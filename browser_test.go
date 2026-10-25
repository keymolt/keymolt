package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const createPage = `<input id=name><input id=pw type=password>
<button id=create onclick="fetch('/api/keys',{method:'POST',body:document.getElementById('name').value})
.then(r=>r.json()).then(j=>{document.getElementById('shown').value=j.key})">Create key</button>
<p>Old key: dash-SECRET-****</p><input id=shown readonly>`

// fakeDashboard is a provider with no API for keys: create and delete happen in its web pages.
type fakeDashboard struct {
	mu      sync.Mutex
	keys    map[string]string
	order   []string
	revoked []string
}

func (d *fakeDashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w.Header().Set("Content-Type", "text/html") // the pages start with <input>, which Go would sniff as plain text
	switch {
	case r.URL.Path == "/keys":
		var rows strings.Builder
		for _, n := range d.order {
			if !slices.Contains(d.revoked, n) {
				fmt.Fprintf(&rows, `<li>%s <button onclick="fetch('/api/del?name=%s',{method:'POST'}).then(()=>location.reload())">Delete</button></li>`, n, n)
			}
		}
		fmt.Fprintf(w, "<ul>%s</ul>", rows.String())
	case r.URL.Path == "/api/del":
		d.revoked = append(d.revoked, r.URL.Query().Get("name"))
		fmt.Fprint(w, "{}")
	case r.URL.Path == "/api/keys":
		body, _ := io.ReadAll(r.Body)
		name := string(body)
		key := make([]byte, 16)
		_, _ = rand.Read(key)
		d.keys[name] = "dash-SECRET-" + hex.EncodeToString(key)
		d.order = append(d.order, name)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"key": d.keys[name]})
	default:
		fmt.Fprint(w, createPage)
	}
}

func TestBrowserFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("starts Chrome")
	}
	d := &fakeDashboard{keys: map[string]string{}}
	srv := httptest.NewServer(d)
	defer srv.Close()
	tmp := t.TempDir()
	profile := filepath.Join(tmp, "profile")
	createFlow, revokeFlow := filepath.Join(tmp, "create.json"), filepath.Join(tmp, "revoke.json")
	writeJSON(t, createFlow, map[string]any{"profile": profile, "id": "{{name}}", "steps": []any{
		map[string]any{"goto": srv.URL + "/"}, map[string]any{"fill": "#name", "value": "{{name}}"},
		map[string]any{"fill": "#pw", "value": "{{cred:dashpw}}"},
		map[string]any{"capture": `dash-SECRET-[0-9a-f]{32}`}, map[string]any{"click": "#create"}}})
	writeJSON(t, revokeFlow, map[string]any{"profile": profile, "steps": []any{
		map[string]any{"goto": srv.URL + "/keys"}, map[string]any{"click": "//li[contains(., '{{old_id}}')]//button"}}})
	dest := filepath.Join(tmp, "dest.txt")
	recipe := filepath.Join(tmp, "recipe.json")
	writeJSON(t, recipe, map[string]any{"name": "dash",
		"create": map[string]any{"browser": "create.json", "vars": map[string]any{"name": "keymolt-{{ts}}"}, "value": "value", "id": "id"},
		"store":  []any{map[string]any{"label": "file", "cmd": helper("store", dest)}},
		"revoke": map[string]any{"browser": "revoke.json", "vars": map[string]any{"old_id": "{{old_id}}"}}})
	t.Setenv("KEYMOLT_HELPER", "1")
	t.Setenv("KEYMOLT_CRED_DASHPW", "pw-SECRET")
	skipApproval(t)

	// host lock: a password locked to another site is never filled on this page
	t.Setenv("KEYMOLT_HOSTS_DASHPW", "example.com")
	flow, _ := readJSONFile(createFlow)
	if _, err := runFlow(flow, map[string]string{"name": "x"}); err == nil ||
		!strings.Contains(err.Error(), "may only go to https://example.com") || len(d.keys) != 0 {
		if errors.Is(err, errNoBrowser) {
			t.Skip("no Chromium-based browser here")
		}
		t.Fatal("password filled on the wrong host:", err)
	}
	t.Setenv("KEYMOLT_HOSTS_DASHPW", "127.0.0.1")

	code, out, raw := cli(t, "SECRET", "rotate", recipe)
	first := str(out["new_id"])
	if got, _ := os.ReadFile(dest); code != 0 || string(got) != d.keys[first] {
		t.Fatal("first browser rotation:", raw)
	}
	time.Sleep(1100 * time.Millisecond) // key names use a 1-second timestamp
	code, out, raw = cli(t, "SECRET", "rotate", recipe)
	if got, _ := os.ReadFile(dest); code != 0 || !slices.Equal(list(out["revoked"]), []string{first}) ||
		!slices.Equal(d.revoked, []string{first}) || string(got) != d.keys[str(out["new_id"])] {
		t.Fatal("second browser rotation should delete the first key on the page:", raw, d.revoked)
	}
}

func TestBrowserPath(t *testing.T) {
	only := func(paths ...string) func(string) (string, error) {
		return func(p string) (string, error) {
			if slices.Contains(paths, p) {
				return "/found/" + filepath.Base(p), nil
			}
			return "", errors.New("not found")
		}
	}
	edge := "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
	cases := []struct {
		goos, want string
		look       func(string) (string, error)
	}{
		{"darwin", "", only("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", edge)}, // Chrome wins
		{"darwin", "/found/Microsoft Edge", only(edge)},
		{"linux", "/found/brave-browser", only("brave-browser")},
		{"linux", "", only("chromium", "brave-browser")},
		{"linux", "", only()}, // nothing installed: chromedp reports the error
		{"windows", "", only()},
	}
	for _, c := range cases {
		if got := browserPath(c.goos, c.look); got != c.want {
			t.Errorf("%s: got %q, want %q", c.goos, got, c.want)
		}
	}
	t.Setenv("KEYMOLT_BROWSER", "/opt/vivaldi")
	if got := browserPath("linux", only("chromium")); got != "/opt/vivaldi" {
		t.Error("KEYMOLT_BROWSER must win:", got)
	}
}

func TestBrowserKeyOnlyOnHTTPS(t *testing.T) {
	addSecret("sk-new-SECRET-fill")
	flow := map[string]any{"profile": t.TempDir(), "steps": []any{ // a throwaway browser profile
		map[string]any{"goto": "data:text/html,<input id=k>"}, // not https and not localhost
		map[string]any{"fill": "#k", "value": "{{key}}"}}}
	_, err := runFlow(flow, map[string]string{"key": "sk-new-SECRET-fill"})
	if errors.Is(err, errNoBrowser) {
		t.Skip("no Chromium-based browser here")
	}
	if err == nil || !strings.Contains(err.Error(), "isn't https") {
		t.Fatal("a flow must not type the new key into a page that isn't https:", err)
	}
	flow["steps"] = []any{map[string]any{"goto": "http://example.com/?k={{key}}"}}
	if _, err := runFlow(flow, map[string]string{"key": "sk-new-SECRET-fill"}); err == nil || !strings.Contains(err.Error(), "isn't https") {
		t.Fatal("a flow must not open a plain-http URL with the new key in it:", err)
	}
}

func TestSweepDownloads(t *testing.T) {
	old, err := os.MkdirTemp("", "keymolt-dl-")
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := os.MkdirTemp("", "keymolt-dl-")
	defer os.RemoveAll(fresh)
	long := time.Now().Add(-2 * time.Hour) // left by a run that was killed
	_ = os.Chtimes(old, long, long)
	sweepDownloads()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("an old download folder must be removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("a folder another run may still use must stay")
	}
}
