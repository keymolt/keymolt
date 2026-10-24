package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Provider templates are data, not code: each is a keymolt recipe (without "store") plus a "detect" block
// that says which keys belong to it. Built-in ones ship in the binary; a user folder overrides and adds to
// them, so supporting a new provider never needs a keymolt release.
//
//go:embed providers/*.json
var builtinProviders embed.FS

var (
	secretName  = regexp.MustCompile(`(?i)KEY|SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL`)
	placeholder = regexp.MustCompile(`\{\{(\w+)\}\}`)
	railwayAuth = map[string]any{"Authorization": "Bearer {{cred:railway}}", "Content-Type": "application/json", "User-Agent": "keymolt"}
)

func railwayAPI() string {
	if u := os.Getenv("KEYMOLT_RAILWAY_API"); u != "" {
		return u
	}
	return "https://backboard.railway.com/graphql/v2"
}

// tmpl is a loaded provider template. rotatable is false for a detect-only template (one with no create step).
// trusted is true only for the built-in templates embedded in the binary.
type tmpl struct {
	raw         []byte
	label       string
	trusted     bool
	rotatable   bool
	name, value *regexp.Regexp // detection from the template's "detect" block; either may be nil
}

func templateDir() string {
	if dir := os.Getenv("KEYMOLT_PROVIDERS"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	d := filepath.Join(home, ".keymolt", "templates")
	if st, err := os.Stat(d); err == nil && st.IsDir() {
		return d
	}
	return ""
}

// loadTemplates reads every provider template: the built-in ones, then a user folder that overrides and
// extends them. A folder entry is untrusted, since keymolt did not ship it.
func loadTemplates() (map[string]tmpl, error) {
	out := map[string]tmpl{}
	add := func(kind string, raw []byte, label string, trusted bool) error {
		m, ok := decode(raw).(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not valid JSON", label)
		}
		t := tmpl{raw: raw, label: label, trusted: trusted, rotatable: asMap(m["create"]) != nil}
		d := asMap(m["detect"])
		var err error
		if s := str(d["name"]); s != "" {
			if t.name, err = regexp.Compile("(?i)" + s); err != nil {
				return fmt.Errorf("%s detect.name: %v", label, err)
			}
		}
		if s := str(d["value"]); s != "" {
			if t.value, err = regexp.Compile(s); err != nil {
				return fmt.Errorf("%s detect.value: %v", label, err)
			}
		}
		out[kind] = t
		return nil
	}
	entries, _ := builtinProviders.ReadDir("providers")
	for _, e := range entries {
		kind := strings.TrimSuffix(e.Name(), ".json")
		b, _ := builtinProviders.ReadFile("providers/" + e.Name())
		if err := add(kind, b, "the built-in "+kind+" template", true); err != nil {
			return nil, err
		}
	}
	if dir := templateDir(); dir != "" {
		des, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range des {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, err
			}
			if err := add(strings.TrimSuffix(e.Name(), ".json"), b, filepath.Join(dir, e.Name()), false); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// classify names the provider of a key. A distinctive value prefix is authoritative; when a prefix is
// shared by several providers, or there is none, the variable name decides. "" means we could not tell.
func classify(name, value string, templates map[string]tmpl) string {
	bestLen, best, tie := -1, "", false
	for kind, t := range templates {
		if t.value == nil {
			continue
		}
		if m := t.value.FindString(value); m != "" {
			switch {
			case len(m) > bestLen:
				bestLen, best, tie = len(m), kind, false
			case len(m) == bestLen:
				tie = true
			}
		}
	}
	if best != "" && !tie {
		return best // one authoritative prefix
	}
	nameLen, nameBest := -1, ""
	for kind, t := range templates {
		if t.name == nil {
			continue
		}
		if tie { // only the providers that share the winning prefix are still candidates
			if t.value == nil || len(t.value.FindString(value)) != bestLen {
				continue
			}
		}
		if m := t.name.FindString(name); m != "" && len(m) > nameLen {
			nameLen, nameBest = len(m), kind
		}
	}
	return nameBest // "" when an ambiguous prefix gets no help from the name, or nothing matched
}

func gql(query string, vars map[string]any) (map[string]any, error) {
	ok, data, detail, err := call(map[string]any{"method": "POST", "url": railwayAPI(), "headers": railwayAuth,
		"body": map[string]any{"query": query, "variables": vars}}, nil, "")
	if err != nil {
		return nil, err
	}
	d := asMap(data)
	if !ok || d == nil || d["errors"] != nil || asMap(d["data"]) == nil {
		return nil, fmt.Errorf("railway query failed (%s)", detail)
	}
	return asMap(d["data"]), nil
}

func nodes(conn any) []map[string]any {
	var out []map[string]any
	for _, e := range asList(asMap(conn)["edges"]) {
		out = append(out, asMap(asMap(e)["node"]))
	}
	return out
}

type location struct{ where, variable, kind, envID, serviceID string }

// group is every place that holds the same key value.
type group struct {
	value string
	locs  []location
}

func scan(projectID string, templates map[string]tmpl) (string, []*group, error) {
	d, err := gql(`query($id: String!) { project(id: $id) { name services { edges { node { id name } } } `+
		`environments { edges { node { id name } } } } }`, map[string]any{"id": projectID})
	if err != nil {
		return "", nil, err
	}
	p := asMap(d["project"])
	var groups []*group
	byValue := map[string]*group{}
	// the last entry has no id: for it Railway returns the environment's shared variables
	targets := append(nodes(p["services"]), map[string]any{"name": "shared"})
	for _, env := range nodes(p["environments"]) {
		for _, svc := range targets {
			// unrendered: a reference such as ${{shared.KEY}} comes back as itself, so we skip it and rotate only its source
			v, err := gql(`query($p: String!, $e: String!, $s: String) { variables(projectId: $p, environmentId: $e, serviceId: $s, unrendered: true) }`,
				map[string]any{"p": projectID, "e": env["id"], "s": svc["id"]})
			if err != nil {
				return "", nil, err
			}
			vars := asMap(v["variables"])
			names := make([]string, 0, len(vars))
			for n := range vars {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				value := str(vars[n])
				if strings.Contains(value, "${{") { // follows its source, which the scan finds on its own
					continue
				}
				kind := classify(n, value, templates)
				if kind == "" && secretName.MatchString(n) && !strings.HasPrefix(n, "RAILWAY_") && len(value) >= 8 {
					kind = "unknown" // looks like a secret, but we can't name its provider
				}
				if kind == "" {
					continue
				}
				addSecret(value)
				g := byValue[value]
				if g == nil {
					g = &group{value: value}
					byValue[value] = g
					groups = append(groups, g)
				}
				g.locs = append(g.locs, location{str(svc["name"]) + "/" + str(env["name"]), n, kind, str(env["id"]), str(svc["id"])})
			}
		}
	}
	return str(p["name"]), groups, nil
}

// last4 shows the end of a key, which provider dashboards also show, so the user can find it there.
func last4(v string) string {
	if len(v) < 16 {
		return ""
	}
	return "..." + v[len(v)-4:]
}

func report(w io.Writer, name string, groups []*group, templates map[string]tmpl) {
	rows := [][]string{{"WHERE", "VARIABLE", "PROVIDER", "KEY", "ACTION"}}
	auto := 0
	for _, g := range groups {
		action := "by hand"
		if templates[g.locs[0].kind].rotatable {
			action = "auto"
			auto++
		}
		for i, l := range g.locs {
			a := action
			if i > 0 {
				a += fmt.Sprintf(", same key as %s %s", g.locs[0].where, g.locs[0].variable)
			}
			rows = append(rows, []string{l.where, l.variable, l.kind, last4(g.value), a})
		}
	}
	widths := make([]int, 4)
	for _, r := range rows {
		for c := range 4 {
			widths[c] = max(widths[c], len(r[c]))
		}
	}
	fmt.Fprintln(w, scrub("Railway project "+name))
	for _, r := range rows {
		line := ""
		for c := range 4 {
			line += fmt.Sprintf("%-*s  ", widths[c], r[c])
		}
		fmt.Fprintln(w, scrub(line+r[4]))
	}
	fmt.Fprintf(w, "%d distinct keys in %d variables. %d can rotate automatically.\n\n", len(groups), len(rows)-1, auto)
}

// uniqueName adds -2, -3, ... when two keys slug to the same recipe name, so they never share state.
// The suffix follows scan order, which is stable, so a rerun finds the same state entry.
func uniqueName(used map[string]bool, name string) string {
	out := name
	for n := 2; used[out]; n++ {
		out = fmt.Sprintf("%s-%d", name, n)
	}
	used[out] = true
	return out
}

func rescueScan(projectID string, w io.Writer) error {
	templates, err := loadTemplates()
	if err != nil {
		return err
	}
	name, groups, err := scan(projectID, templates)
	if err != nil {
		return err
	}
	report(w, name, groups, templates)
	return nil
}

func rescueRotate(projectID string, params map[string]string, w io.Writer) error {
	templates, err := loadTemplates()
	if err != nil {
		return err
	}
	name, groups, err := scan(projectID, templates)
	if err != nil {
		return err
	}
	report(w, name, groups, templates)
	type plan struct {
		g       *group
		recipe  map[string]any
		trusted bool
	}
	var plans []plan
	var byHand []*group
	usedNames := map[string]bool{}
	for _, g := range groups { // build every recipe before rotating anything, so a missing k=v stops the run cleanly
		first := g.locs[0]
		tpl, ok := templates[first.kind]
		if !ok || !tpl.rotatable { // detect-only or unknown: the user rotates it by hand
			byHand = append(byHand, g)
			continue
		}
		label, trusted := tpl.label, tpl.trusted
		t := string(tpl.raw)
		for k, v := range params {
			t = strings.ReplaceAll(t, "{{"+k+"}}", v)
		}
		var missing []string
		for _, m := range placeholder.FindAllStringSubmatch(t, -1) {
			if !slices.Contains([]string{"new", "new_id", "old_id", "ts"}, m[1]) && !slices.Contains(missing, m[1]+"=...") {
				missing = append(missing, m[1]+"=...")
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return fmt.Errorf("%s needs %s", label, strings.Join(missing, " "))
		}
		recipe, ok := decode([]byte(t)).(map[string]any)
		if !ok {
			return fmt.Errorf("%s is not valid JSON", label)
		}
		// named after where the key lives, so a rerun finds keymolt's state and revokes the key it made last time
		recipe["name"] = uniqueName(usedNames, slug(first.where+"-"+first.variable))
		var store []any
		for _, l := range g.locs {
			input := map[string]any{"projectId": projectID, "environmentId": l.envID, "name": l.variable, "value": "{{new}}"}
			if l.serviceID != "" { // no serviceId writes the shared variable
				input["serviceId"] = l.serviceID
			}
			store = append(store, map[string]any{"label": l.where + " " + l.variable, "method": "POST", "url": railwayAPI(),
				"headers": railwayAuth, "ok_path": "data.variableUpsert",
				"body": map[string]any{"query": "mutation($i: VariableUpsertInput!) { variableUpsert(input: $i) }",
					"variables": map[string]any{"i": input}}})
		}
		recipe["store"] = store
		plans = append(plans, plan{g, recipe, trusted})
	}

	if err := os.MkdirAll("rescued", 0o700); err != nil {
		return err
	}
	type result struct {
		g   *group
		r   *receipt
		err error
	}
	var done, failed []result
	for _, p := range plans {
		path := filepath.Join("rescued", str(p.recipe["name"])+".json")
		b, _ := json.MarshalIndent(p.recipe, "", "  ")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return err
		}
		if p.trusted { // keymolt built this recipe from a built-in template and its own Railway store, so trust it
			_ = approveRecipeFile(path)
		}
		if r, err := rotate(path); err != nil {
			failed = append(failed, result{p.g, nil, err})
		} else {
			done = append(done, result{p.g, r, nil})
		}
	}

	for _, d := range done {
		fmt.Fprintln(w, scrub(fmt.Sprintf("Rotated %s key %s: new key %s saved to %s.", d.g.locs[0].kind, last4(d.g.value), d.r.NewID, strings.Join(d.r.Stored, ", "))))
	}
	for _, f := range failed {
		fmt.Fprintln(w, scrub(fmt.Sprintf("FAILED %s key %s: %v. The old key is still in place.", f.g.locs[0].kind, last4(f.g.value), f.err)))
	}
	if len(done) > 0 {
		fmt.Fprintln(w, "\nRevoke these exposed keys in the provider's dashboard now. Each still works until you do:")
		for _, d := range done {
			fmt.Fprintln(w, scrub(fmt.Sprintf("  %s %s", d.g.locs[0].kind, last4(d.g.value))))
		}
	}
	if len(byHand) > 0 {
		fmt.Fprintln(w, "\nRotate these by hand. keymolt has no rotation recipe for them yet:")
		for _, g := range byHand {
			var where []string
			for _, l := range g.locs {
				where = append(where, l.where+" "+l.variable)
			}
			fmt.Fprintln(w, scrub(fmt.Sprintf("  %s %s in %s", g.locs[0].kind, last4(g.value), strings.Join(where, ", "))))
		}
	}
	if len(failed) > 0 {
		return errReported
	}
	return nil
}
