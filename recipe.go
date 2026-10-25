package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	// Go drops the Authorization header on a cross-host redirect, but it resends the body on a 307/308,
	// and the body can hold a key. So refuse any redirect to another host, or from https down to http.
	httpClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme {
			return errors.New("refusing redirect to another host")
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}}
	verifyWait = 2 * time.Second // new keys can take a few seconds to become valid
)

// loadedFlow is where readRecipe puts a browser step's parsed flow, so a run uses the flow bytes approval hashed.
const loadedFlow = "\x00flow"

// stepKind says what a step does. call and recipeDestinations both use it, so approve shows what really runs.
func stepKind(step map[string]any) (string, error) {
	var kinds []string
	for _, k := range []string{"url", "cmd", "browser", "vault"} {
		if step[k] != nil {
			kinds = append(kinds, k)
		}
	}
	if len(kinds) != 1 {
		return "", fmt.Errorf("a step needs exactly one of url, cmd, browser or vault, not %d", len(kinds))
	}
	return kinds[0], nil
}

// checkSteps refuses steps that approve would show wrongly, or that would leak the new key on the way.
func checkSteps(recipe map[string]any) error {
	var errs []error
	eachStep(recipe, func(label string, step map[string]any) {
		if step == nil { // a missing create or store is reported by the command that needs it
			return
		}
		kind, err := stepKind(step)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", label, err))
			return
		}
		b, _ := json.Marshal(step)
		switch {
		case kind == "cmd" && strings.Contains(string(b), "{{new}}"):
			errs = append(errs, fmt.Errorf("%s: {{new}} can't go into a command line, which other programs can read; the command gets the key on stdin", label))
		case kind == "url" && strings.Contains(string(b), "{{new}}") && destHost(str(step["url"])) == "":
			errs = append(errs, fmt.Errorf("%s: the new key only goes over https", label))
		}
	})
	return errors.Join(errs...)
}

// recipeDestinations lists, in plain words, every place a recipe sends keys. Used by `keymolt approve`.
func recipeDestinations(recipe map[string]any) []string {
	var out []string
	eachStep(recipe, func(label string, step map[string]any) {
		kind, _ := stepKind(step)
		switch kind {
		case "url":
			out = append(out, label+" -> "+str(step["url"]))
		case "cmd":
			out = append(out, label+" -> runs "+strings.Join(toStrings(step["cmd"]), " "))
		case "browser":
			line := label + " -> browser flow " + str(step["browser"])
			var sites []string
			for _, s := range asList(asMap(step[loadedFlow])["steps"]) {
				if u := asMap(s)["goto"]; u != nil {
					sites = append(sites, str(u))
				}
			}
			if len(sites) > 0 { // only the goto steps: a click can still lead somewhere else
				line += ", starts at " + strings.Join(sites, ", ")
			}
			out = append(out, line)
		case "vault":
			out = append(out, label+" -> keymolt vault ("+str(step["vault"])+")")
		}
	})
	return out
}

// eachStep calls add for every step of a recipe, always in the same order.
func eachStep(recipe map[string]any, add func(label string, step map[string]any)) {
	if c := asMap(recipe["current"]); c != nil {
		add("current", c)
	}
	if f := asMap(recipe["find"]); f != nil {
		add("find", f)
		if r := asMap(f["revoke"]); r != nil {
			add("find revoke", r)
		}
	}
	add("create", asMap(recipe["create"]))
	if v := asMap(recipe["verify"]); v != nil {
		add("verify", v)
	}
	for i, d := range asList(recipe["store"]) {
		add(fmt.Sprintf("store #%d", i), asMap(d))
	}
	if r := asMap(recipe["revoke"]); r != nil {
		add("revoke", r)
	}
}

// flowPath is where a browser step's flow file is: relative paths start at the recipe's folder.
func flowPath(step map[string]any, dir string) string {
	flow := str(step["browser"])
	if filepath.IsAbs(flow) {
		return flow
	}
	return filepath.Join(dir, flow)
}

// render fills placeholders. {{cred:X}} only resolves when host is one of X's hosts; host "" means nowhere.
func render(v any, ctx map[string]string, host string) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			r, err := render(x, ctx, host)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			r, err := render(x, ctx, host)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case string:
		return renderString(t, ctx, host)
	}
	return v, nil
}

func renderString(s string, ctx map[string]string, host string) (string, error) {
	for {
		i := strings.Index(s, "{{cred:")
		j := strings.Index(s[max(i, 0):], "}}")
		if i < 0 || j < 0 {
			break
		}
		name := s[i+len("{{cred:") : i+j]
		v, err := credGet(name, host)
		if err != nil {
			return "", err
		}
		s = strings.ReplaceAll(s, "{{cred:"+name+"}}", v)
	}
	for k, v := range ctx {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s, nil
}

func pick(data any, path string) (any, error) {
	for _, part := range strings.Split(path, ".") {
		switch t := data.(type) {
		case map[string]any:
			v, ok := t[part]
			if !ok {
				return nil, fmt.Errorf("response has no %s", path)
			}
			data = v
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(t) {
				return nil, fmt.Errorf("response has no %s", path)
			}
			data = t[i]
		default:
			return nil, fmt.Errorf("response has no %s", path)
		}
	}
	return data, nil
}

// call runs one step. ok reports whether the step worked; err is for problems that must stop the rotation,
// such as a credential sent to the wrong host. dir is the recipe's folder, for relative browser flow paths.
func call(step map[string]any, ctx map[string]string, dir string) (ok bool, data any, detail string, err error) {
	var raw []byte
	kind, err := stepKind(step)
	if err != nil {
		return false, nil, "", err
	}
	switch kind {
	case "vault":
		if ok, detail, err = vaultReplace(str(step["vault"]), ctx["new"]); err != nil {
			return false, nil, "", err
		}
	case "browser":
		vars, err := render(step["vars"], ctx, "") // flow vars can't carry credentials
		if err != nil {
			return false, nil, "", err
		}
		flow := asMap(step[loadedFlow])
		if flow == nil {
			return false, nil, "", errors.New("browser flow not loaded") // only readRecipe loads flows, after hashing them
		}
		raw, err = runFlow(flow, toStrMap(vars))
		ok, detail = err == nil, "browser"
		if err != nil {
			detail = "browser: " + err.Error()
		}
	case "cmd":
		s, err := render(step["cmd"], ctx, "") // credentials can't go into a command line at all
		if err != nil {
			return false, nil, "", err
		}
		argv := toStrings(s)
		if len(argv) == 0 {
			return false, nil, "", errors.New("empty cmd")
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		// like browser flows: a recipe works the same from any folder, and from a scheduler
		cmd.Dir = dir
		cmd.Env = childEnv()
		cmd.Stdin = strings.NewReader(ctx["new"]) // the new key goes over stdin, never into argv
		var out bytes.Buffer
		cmd.Stdout = &out
		runErr := cmd.Run()
		ok, raw, detail = runErr == nil, out.Bytes(), fmt.Sprintf("exit %d", cmd.ProcessState.ExitCode())
		if cmd.ProcessState == nil {
			detail = "command not found"
		}
	case "url":
		u, err := renderString(str(step["url"]), ctx, "")
		if err != nil {
			return false, nil, "", err
		}
		r, err := render(step, ctx, destHost(u))
		if err != nil {
			return false, nil, "", err
		}
		ok, raw, detail = httpDo(asMap(r))
	}
	data = decode(raw)
	if s := strings.TrimSpace(string(raw)); data == nil && s != "" { // plain text, such as a CLI printing a key
		data = s
	}
	if ok && step["ok_path"] != nil { // GraphQL APIs return 200 even when the mutation failed
		v, err := pick(data, str(step["ok_path"]))
		ok = err == nil && truthy(v)
	}
	return ok, data, detail, nil
}

func httpDo(s map[string]any) (bool, []byte, string) {
	var body io.Reader
	if b := s["body"]; b != nil {
		j, _ := json.Marshal(b)
		body = bytes.NewReader(j)
	}
	method := str(s["method"])
	if method == "" {
		method = "GET"
	}
	req, err := http.NewRequest(method, str(s["url"]), body)
	if err != nil {
		return false, nil, "bad request"
	}
	for k, v := range asMap(s["headers"]) {
		req.Header.Set(k, str(v))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, "http: no response" // the error text can quote the URL
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return false, nil, fmt.Sprintf("http %d", resp.StatusCode) // error bodies are never read: they may echo secrets
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	return true, raw, fmt.Sprintf("http %d", resp.StatusCode)
}

func toStrings(v any) []string {
	var out []string
	for _, x := range asList(v) {
		out = append(out, str(x))
	}
	return out
}

func toStrMap(v any) map[string]string {
	out := map[string]string{}
	for k, x := range asMap(v) {
		out[k] = str(x)
	}
	return out
}

// --- rotate ---------------------------------------------------------------------------------

type receipt struct {
	OK           bool     `json:"ok"`
	Name         string   `json:"name"`
	NewID        string   `json:"new_id"`
	Length       int      `json:"length"`
	SHA256       string   `json:"sha256"`
	Stored       []string `json:"stored"`
	Revoked      []string `json:"revoked"`
	RevokeFailed []string `json:"revoke_failed"`
	Verify       string   `json:"verify,omitempty"`
	RevokeByHand string   `json:"revoke_by_hand,omitempty"`
	Found        string   `json:"found,omitempty"`
}

type stateEntry struct {
	ID    string   `json:"id"`
	Stale []string `json:"stale"`
	Found []string `json:"found,omitempty"` // keys made before keymolt and linked to it, revoked with find's own revoke
}

func rotate(recipePath string) (*receipt, error) { return runRecipe(recipePath, false) }

// runRecipe makes a new key and stores it, then revokes the old one. createOnly refuses to run when the
// folder's state already records a key for this recipe. It can't see keys set by hand or tracked in another folder.
func runRecipe(recipePath string, createOnly bool) (*receipt, error) {
	recipe, err := loadApproved(recipePath)
	if err != nil {
		return nil, err
	}
	name := str(recipe["name"])
	if name == "" {
		return nil, errors.New("recipe has no name")
	}
	if asMap(recipe["create"]) == nil {
		return nil, errors.New("recipe has no create step")
	}
	if len(asList(recipe["store"])) == 0 { // without this, a store typo would delete the old key and store nothing
		return nil, errors.New("recipe has no store step; the new key would have nowhere to go")
	}
	if err := checkFind(recipe); err != nil {
		return nil, err
	}
	fs, err := openState(recipePath)
	if err != nil {
		return nil, err
	}
	defer fs.unlock()
	dir, state, stateKey, saveState := fs.dir, fs.state, fs.key, fs.save
	entry := state[stateKey]
	if createOnly && (entry.ID != "" || len(entry.Stale) > 0) {
		return nil, fmt.Errorf("keymolt already made a key for this recipe; run `keymolt rotate %s` to replace it", recipePath)
	}
	unknownOld := entry.ID == "" && len(entry.Stale) == 0 // nothing tracked: a key set by hand may be in use
	before := ""                                          // the key a destination held that keymolt doesn't track: reported, never revoked
	if unknownOld && recipe["current"] != nil {
		value, read, err := currentKey(asMap(recipe["current"]), dir)
		if err != nil {
			return nil, err
		}
		switch {
		case read && value == "":
			unknownOld = false // the destination holds no key yet
		case read && createOnly:
			return nil, fmt.Errorf("the destination already holds a key; run `keymolt rotate %s` to replace it", recipePath)
		case read:
			if before, err = findKeyID(asMap(recipe["find"]), value, dir); err != nil {
				return nil, err
			}
		}
	}
	ctx := map[string]string{"ts": time.Now().Format("20060102-150405"), "old_id": entry.ID}
	// track records the new key and the old keys still live, remembering which of them were linked
	track := func(stale []string) stateEntry {
		var f []string
		for _, id := range entry.Found {
			if slices.Contains(stale, id) {
				f = append(f, id)
			}
		}
		return stateEntry{ctx["new_id"], stale, f}
	}

	create := asMap(recipe["create"])
	ok, resp, detail, err := call(create, ctx, dir)
	if err != nil {
		return nil, err
	}
	if !ok || resp == nil {
		return nil, fmt.Errorf("create failed (%s)", detail)
	}
	newValue, err1 := pick(resp, str(create["value"]))
	newID, err2 := pick(resp, str(create["id"]))
	if err := errors.Join(err1, err2); err != nil {
		return nil, fmt.Errorf("create worked but %v; check the provider for an orphaned key", err)
	}
	ctx["new"], ctx["new_id"] = str(newValue), str(newID)
	addSecret(ctx["new"])
	if ctx["new_id"] != "" && !keyID.MatchString(ctx["new_id"]) {
		return nil, fmt.Errorf("create returned an id keymolt can't put in a URL safely; check the provider for an orphaned key")
	}
	// track the new key before anything else can fail, so a crash or a failed cleanup never leaves it live and unknown
	if ctx["new_id"] != "" {
		state[stateKey] = stateEntry{entry.ID, append(slices.Clone(entry.Stale), ctx["new_id"]), entry.Found}
		if err := saveState(); err != nil {
			return nil, fmt.Errorf("create worked but state save failed (%v); check the provider for an orphaned key", err)
		}
	}
	sum := sha256.Sum256([]byte(ctx["new"]))
	out := &receipt{Name: name, NewID: ctx["new_id"], Length: len(ctx["new"]), SHA256: hex.EncodeToString(sum[:])[:12],
		Stored: []string{}, Revoked: []string{}, RevokeFailed: []string{}}
	out.Found = before
	if unknownOld && recipe["revoke"] != nil { // keymolt only revokes keys it created or was linked to
		out.RevokeByHand = "if a key was in use before keymolt's first run, it may still be live: revoke it by hand"
		if before != "" {
			out.RevokeByHand = fmt.Sprintf("%s, the key in use before keymolt, is still live. Once nothing else uses it, "+
				"or now if it may be leaked, run `keymolt revoke %s %s`", before, recipePath, before)
		}
	}

	revoke := func(id string) bool {
		step := asMap(recipe["revoke"])
		if r := asMap(asMap(recipe["find"])["revoke"]); r != nil && slices.Contains(entry.Found, id) {
			step = r // a key made by hand can be a different kind, with its own delete endpoint
		}
		if id == "" || step == nil { // locally generated secrets die when overwritten
			return id == ""
		}
		c := map[string]string{}
		for k, v := range ctx {
			c[k] = v
		}
		c["old_id"] = id
		ok, _, _, err := call(step, c, dir)
		if ok && err == nil {
			out.Revoked = append(out.Revoked, id)
		}
		return ok && err == nil
	}

	// discard revokes the new key after a failed run. If that fails, the key stays in state, so the next run retries.
	discard := func(why string) error {
		if !revoke(ctx["new_id"]) {
			return fmt.Errorf("%s; new key %s could not be revoked, the next rotate retries; old key untouched", why, ctx["new_id"])
		}
		state[stateKey] = entry
		_ = saveState() // best effort: worst case is a later run retries a delete that already happened
		return fmt.Errorf("%s; new key revoked, old key untouched", why)
	}

	if ctx["new"] == "" { // a provider that returns an empty key would otherwise get stored over the live one
		return nil, discard("create returned an empty key")
	}

	if v := asMap(recipe["verify"]); v != nil {
		for range 5 {
			if ok, _, out.Verify, err = call(v, ctx, dir); err != nil || ok {
				break
			}
			time.Sleep(verifyWait)
		}
		if err != nil {
			return nil, discard(err.Error())
		}
		if !ok {
			return nil, discard(fmt.Sprintf("new key failed verify (%s)", out.Verify))
		}
	}

	// every old key that is still live, before we delete any of them
	oldLive := slices.Clone(entry.Stale)
	if entry.ID != "" {
		oldLive = append(oldLive, entry.ID)
	}

	for i, d := range asList(recipe["store"]) {
		dest := asMap(d)
		ok, _, detail, err := call(dest, ctx, dir)
		if err != nil && len(out.Stored) == 0 { // failed before sending anything, so no destination uses the new key
			return nil, discard(fmt.Sprintf("store #%d failed (%v)", i, err))
		}
		if err != nil {
			ok, detail = false, err.Error()
		}
		if !ok {
			// the store may have landed even though it failed, such as a timeout after the write, and other
			// destinations may hold the new key already: keep every key live, and revoke the old ones next run
			state[stateKey] = track(oldLive)
			if e := saveState(); e != nil {
				return nil, fmt.Errorf("store #%d failed and state save failed (%v); keys may be untracked, check the provider", i, e)
			}
			return nil, fmt.Errorf("store #%d failed (%s), and it may hold the new key; old and new keys both live, rerun", i, detail)
		}
		label := str(dest["label"])
		if label == "" {
			label = strconv.Itoa(i)
		}
		out.Stored = append(out.Stored, label)
	}

	// record the new key and every old key as live BEFORE deleting any, so a crash or a bad write never loses track
	state[stateKey] = track(oldLive)
	if err := saveState(); err != nil {
		return nil, fmt.Errorf("new key stored but state save failed (%v); old keys left live, fix the folder and rerun", err)
	}

	// keep_previous: apps that read keys only at deploy time need the old key until they redeploy
	keep := ""
	if entry.ID != "" && truthy(recipe["keep_previous"]) {
		keep = entry.ID
	}
	stale := []string{}
	for _, k := range oldLive {
		if k != keep && !revoke(k) {
			stale = append(stale, k)
		}
	}
	if keep != "" {
		stale = append(stale, keep)
	}
	state[stateKey] = track(stale)
	_ = saveState() // best effort: worst case is a later run retries a delete that already happened
	out.OK, out.RevokeFailed = true, stale
	return out, nil
}

// checkFind rejects a "find" step that can't match a key.
func checkFind(recipe map[string]any) error {
	if f := asMap(recipe["find"]); f != nil && (asMap(recipe["current"]) == nil || str(f["id"]) == "" || str(f["hint"]) == "") {
		return errors.New(`a "find" step needs a "current" step and "id" and "hint" paths`)
	}
	return nil
}

// folderState is the state file in a recipe's folder, locked while one command uses it.
type folderState struct {
	dir, path string
	key       string // the recipe's file name, so two recipes that share a "name" field don't delete each other's keys
	state     map[string]stateEntry
	unlock    func()
}

func openState(recipePath string) (*folderState, error) {
	abs, _ := filepath.Abs(recipePath)
	fs := &folderState{dir: filepath.Dir(abs), key: filepath.Base(abs), state: map[string]stateEntry{}}
	fs.path = filepath.Join(fs.dir, ".keymolt-state.json")
	unlock, err := lockDir(fs.dir)
	if err != nil {
		return nil, err
	}
	fs.unlock = unlock
	if b, err := os.ReadFile(fs.path); err == nil {
		if err := json.Unmarshal(b, &fs.state); err != nil {
			unlock()
			return nil, errors.New(".keymolt-state.json is unreadable")
		}
	}
	for _, e := range fs.state { // ids go into URLs and commands, and the file may have been edited
		for _, id := range append(append([]string{e.ID}, e.Stale...), e.Found...) {
			if id != "" && !keyID.MatchString(id) {
				unlock()
				return nil, fmt.Errorf("%s holds %q, which is not a key id; fix or delete it", fs.path, id)
			}
		}
	}
	return fs, nil
}

func (fs *folderState) save() error {
	b, _ := json.MarshalIndent(fs.state, "", "  ")
	tmp := fs.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, fs.path) // atomic: a crash can't leave a half-written state file
}

// currentKey reads the key in use now from the destination, with the recipe's "current" step. read is false
// when the answer is unknown, such as a failed step.
func currentKey(step map[string]any, dir string) (value string, read bool, err error) {
	ok, data, _, err := call(step, map[string]string{}, dir)
	if err != nil || !ok {
		return "", false, err
	}
	if p := str(step["value"]); p != "" {
		if data, err = pick(data, p); err != nil {
			return "", false, nil
		}
	}
	switch data.(type) {
	case nil, string, json.Number:
		value = str(data)
	default:
		return "", false, nil // an object where a key should be
	}
	addSecret(value)
	return value, true, nil
}

// findKeyID asks the provider for its keys with the recipe's "find" step and returns the id of the one whose
// masked form, such as "sk-ab...xY7q", fits value. It returns "" unless exactly one key fits: a guess could
// revoke a key that is in use.
func findKeyID(step map[string]any, value, dir string) (string, error) {
	if step == nil {
		return "", nil
	}
	req := map[string]any{}
	for k, v := range step {
		if k != "revoke" { // find's own revoke step runs later, with an id
			req[k] = v
		}
	}
	ok, data, _, err := call(req, map[string]string{}, dir)
	if err != nil || !ok {
		return "", err
	}
	list := data
	if p := str(step["list"]); p != "" {
		if list, err = pick(data, p); err != nil {
			return "", nil
		}
	}
	var ids []string
	for _, item := range asList(list) {
		hint, _ := pick(item, str(step["hint"]))
		id, _ := pick(item, str(step["id"]))
		if str(id) != "" && matchesHint(value, str(hint)) {
			ids = append(ids, str(id))
		}
	}
	if len(ids) != 1 {
		return "", nil
	}
	return ids[0], nil
}

var maskRun = regexp.MustCompile(`\.{3}|…|\*+`)

// matchesHint reports whether key fits a masked hint such as "sk-ab...xY7q" or "****xY7q". It needs at least 4
// visible characters, so a hint that hides everything can't match every key.
func matchesHint(key, hint string) bool {
	parts := maskRun.Split(hint, 2)
	if len(parts) == 1 {
		return hint != "" && hint == key
	}
	pre, suf := parts[0], parts[1]
	return len(pre)+len(suf) >= 4 && len(key) >= len(pre)+len(suf) && strings.HasPrefix(key, pre) && strings.HasSuffix(key, suf)
}

// lockDir stops two keymolt runs in one folder from overwriting each other's state file.
// shortcut: a lock older than an hour counts as left by a crashed run; use an OS file lock if runs ever take longer.
func lockDir(dir string) (func(), error) {
	p := filepath.Join(dir, ".keymolt.lock")
	if st, err := os.Stat(p); err == nil && time.Since(st.ModTime()) > time.Hour {
		_ = os.Remove(p)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("another keymolt run is using this folder; if none is, delete %s", p)
	}
	f.Close()
	return func() { os.Remove(p) }, nil
}

// findRecipes returns the recipes in folder, and in every .keymolt folder below it, one list per folder.
func findRecipes(folder string) [][]string {
	dirs := []string{folder}
	_ = filepath.WalkDir(folder, func(p string, d os.DirEntry, err error) error {
		switch {
		case err != nil || !d.IsDir() || p == folder:
		case d.Name() == ".keymolt":
			dirs = append(dirs, p)
			return filepath.SkipDir // recipes sit directly inside; ~/.keymolt's subfolders hold browser profiles
		case d.Name() == "node_modules" || strings.HasPrefix(d.Name(), "."):
			return filepath.SkipDir // large, and never hold recipes
		}
		return nil
	})
	var out [][]string
	for _, dir := range dirs {
		paths, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		paths = slices.DeleteFunc(paths, func(p string) bool {
			if b := filepath.Base(p); strings.HasPrefix(b, ".") || strings.HasSuffix(b, ".example.json") {
				return true // .keymolt-state.json, and templates to copy
			}
			m, err := readJSONFile(p)
			return err == nil && m["create"] == nil // browser flows and other JSON; a broken recipe still runs and fails
		})
		if len(paths) > 0 {
			out = append(out, paths)
		}
	}
	return out
}

// rotateAll rotates each recipe findRecipes finds, so one run covers many projects. Each folder that holds recipes
// gets a log of one receipt line per recipe. Receipts hold no secrets.
func rotateAll(folder string, w io.Writer) error {
	if st, err := os.Stat(folder); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a folder", folder)
	}
	failed, logs := 0, []string{}
	for _, paths := range findRecipes(folder) {
		logPath := filepath.Join(filepath.Dir(paths[0]), "keymolt.log")
		logf, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		for _, p := range paths {
			var line string
			if r, err := rotate(p); err != nil {
				failed++
				line = failJSON(err)
			} else {
				b, _ := json.Marshal(r)
				line = string(b)
			}
			fmt.Fprintf(logf, "%s %s %s\n", time.Now().Format("2006-01-02 15:04:05"), filepath.Base(p), scrub(line))
		}
		logf.Close()
		logs = append(logs, logPath)
	}
	printJSON(w, map[string]any{"ok": failed == 0, "failed": failed, "logs": logs})
	if failed > 0 {
		return errReported
	}
	return nil
}
