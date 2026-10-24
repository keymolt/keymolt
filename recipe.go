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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	// Go drops the Authorization header on a cross-host redirect, but it resends the body on a 307/308,
	// and the body can hold a key. So refuse any redirect to another host.
	httpClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != via[0].URL.Host {
			return errors.New("refusing redirect to another host")
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}}
	verifyWait = 2 * time.Second // new keys can take a few seconds to become valid
)

// recipeDestinations lists, in plain words, every place a recipe sends keys. Used by `keymolt approve`.
func recipeDestinations(recipe map[string]any) []string {
	var out []string
	add := func(label string, step map[string]any) {
		switch {
		case step["url"] != nil:
			out = append(out, label+" -> "+str(step["url"]))
		case step["cmd"] != nil:
			if c := asList(step["cmd"]); len(c) > 0 {
				out = append(out, label+" -> runs "+str(c[0]))
			}
		case step["browser"] != nil:
			out = append(out, label+" -> browser flow "+str(step["browser"]))
		case step["vault"] != nil:
			out = append(out, label+" -> keymolt vault ("+str(step["vault"])+")")
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
	return out
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
	switch {
	case step["vault"] != nil:
		ok, detail = vaultReplace(str(step["vault"]), ctx["new"])
	case step["browser"] != nil:
		vars, err := render(step["vars"], ctx, "") // flow vars can't carry credentials
		if err != nil {
			return false, nil, "", err
		}
		flow := str(step["browser"])
		if !filepath.IsAbs(flow) {
			flow = filepath.Join(dir, flow)
		}
		raw, err = runFlow(flow, toStrMap(vars))
		ok, detail = err == nil, "browser"
		if err != nil {
			detail = "browser: " + err.Error()
		}
	case step["cmd"] != nil:
		s, err := render(step["cmd"], ctx, "") // credentials can't go into a command line at all
		if err != nil {
			return false, nil, "", err
		}
		argv := toStrings(s)
		if len(argv) == 0 {
			return false, nil, "", errors.New("empty cmd")
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdin = strings.NewReader(ctx["new"]) // the new key goes over stdin, never into argv
		var out bytes.Buffer
		cmd.Stdout = &out
		runErr := cmd.Run()
		ok, raw, detail = runErr == nil, out.Bytes(), fmt.Sprintf("exit %d", cmd.ProcessState.ExitCode())
		if cmd.ProcessState == nil {
			detail = "command not found"
		}
	case step["url"] != nil:
		u, err := renderString(str(step["url"]), ctx, "")
		if err != nil {
			return false, nil, "", err
		}
		r, err := render(step, ctx, destHost(u))
		if err != nil {
			return false, nil, "", err
		}
		ok, raw, detail = httpDo(asMap(r))
	default:
		return false, nil, "", errors.New("step has no url, cmd, browser or vault")
	}
	data = decode(raw)
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
}

type stateEntry struct {
	ID    string   `json:"id"`
	Stale []string `json:"stale"`
}

func rotate(recipePath string) (*receipt, error) {
	recipe, err := readJSONFile(recipePath)
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
	if !isApproved(recipePath) {
		return nil, fmt.Errorf("recipe not approved: run `keymolt approve %s` in a terminal first", recipePath)
	}
	abs, _ := filepath.Abs(recipePath)
	dir := filepath.Dir(abs)
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	stateKey := filepath.Base(abs) // keyed by file, so two recipes that share a "name" field don't delete each other's keys
	statePath := filepath.Join(dir, ".keymolt-state.json")
	state := map[string]stateEntry{}
	if b, err := os.ReadFile(statePath); err == nil {
		if err := json.Unmarshal(b, &state); err != nil {
			return nil, errors.New(".keymolt-state.json is unreadable")
		}
	}
	saveState := func() error {
		b, _ := json.MarshalIndent(state, "", "  ")
		tmp := statePath + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return err
		}
		return os.Rename(tmp, statePath) // atomic: a crash can't leave a half-written state file
	}
	entry := state[stateKey]
	ctx := map[string]string{"ts": time.Now().Format("20060102-150405"), "old_id": entry.ID}

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
	sum := sha256.Sum256([]byte(ctx["new"]))
	out := &receipt{Name: name, NewID: ctx["new_id"], Length: len(ctx["new"]), SHA256: hex.EncodeToString(sum[:])[:12],
		Stored: []string{}, Revoked: []string{}, RevokeFailed: []string{}}
	if entry.ID == "" && recipe["revoke"] != nil { // keymolt only revokes keys it created
		out.RevokeByHand = "the key that was in use before keymolt's first rotation"
	}

	revoke := func(id string) bool {
		if id == "" || recipe["revoke"] == nil { // locally generated secrets die when overwritten
			return id == ""
		}
		c := map[string]string{}
		for k, v := range ctx {
			c[k] = v
		}
		c["old_id"] = id
		ok, _, _, err := call(asMap(recipe["revoke"]), c, dir)
		if ok && err == nil {
			out.Revoked = append(out.Revoked, id)
		}
		return ok && err == nil
	}

	if ctx["new"] == "" { // a provider that returns an empty key would otherwise get stored over the live one
		revoke(ctx["new_id"])
		return nil, errors.New("create returned an empty key; new key revoked, old key untouched")
	}

	if v := asMap(recipe["verify"]); v != nil {
		for range 5 {
			if ok, _, out.Verify, err = call(v, ctx, dir); err != nil || ok {
				break
			}
			time.Sleep(verifyWait)
		}
		if err != nil || !ok {
			revoke(ctx["new_id"])
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("new key failed verify (%s); new key revoked, old key untouched", out.Verify)
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
		if err != nil {
			ok, detail = false, err.Error()
		}
		if !ok {
			if len(out.Stored) == 0 { // nothing uses the new key yet, so remove it
				revoke(ctx["new_id"])
				return nil, fmt.Errorf("store #%d failed (%s); new key revoked, old key untouched", i, detail)
			}
			// some destinations now hold the new key: keep every key live, revoke the old ones next run
			state[stateKey] = stateEntry{ctx["new_id"], oldLive}
			if e := saveState(); e != nil {
				return nil, fmt.Errorf("store #%d failed and state save failed (%v); keys may be untracked, check the provider", i, e)
			}
			return nil, fmt.Errorf("store #%d failed (%s) after storing to %v; old and new keys both live, rerun", i, detail, out.Stored)
		}
		label := str(dest["label"])
		if label == "" {
			label = strconv.Itoa(i)
		}
		out.Stored = append(out.Stored, label)
	}

	// record the new key and every old key as live BEFORE deleting any, so a crash or a bad write never loses track
	state[stateKey] = stateEntry{ctx["new_id"], oldLive}
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
	state[stateKey] = stateEntry{ctx["new_id"], stale}
	_ = saveState() // best effort: worst case is a later run retries a delete that already happened
	out.OK, out.RevokeFailed = true, stale
	return out, nil
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

// rotateAll rotates each recipe in a folder and logs one receipt line per recipe. Receipts hold no secrets.
func rotateAll(folder string, w io.Writer) error {
	logPath := filepath.Join(folder, "keymolt.log")
	logf, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	paths, _ := filepath.Glob(filepath.Join(folder, "*.json"))
	sort.Strings(paths)
	failed := 0
	for _, p := range paths {
		if strings.HasPrefix(filepath.Base(p), ".") { // .keymolt-state.json is not a recipe
			continue
		}
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
	printJSON(w, map[string]any{"ok": failed == 0, "failed": failed, "log": logPath})
	if failed > 0 {
		return errReported
	}
	return nil
}
