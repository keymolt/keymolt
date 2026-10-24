package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestMatchesHint(t *testing.T) {
	key := "sk-proj-SECRET-abcdxY7q"
	for hint, want := range map[string]bool{
		"sk-pro...xY7q": true, "****xY7q": true, "sk-proj…xY7q": true, key: true,
		"sk-pro...zzzz": false, // wrong end
		"pk-...xY7q":    false, // wrong start
		"sk...":         false, // fewer than 4 visible characters
		"...":           false,
		"":              false,
	} {
		if got := matchesHint(key, hint); got != want {
			t.Errorf("matchesHint(%q) = %v, want %v", hint, got, want)
		}
	}
}

// fakeKeyAPI is a provider whose keys can be listed in masked form. keymolt's own keys are deleted under
// /keys; keys made by hand only under /api_keys, like OpenAI's service-account and project keys.
type fakeKeyAPI struct {
	mu      sync.Mutex
	keys    map[string]string // id -> value
	n       int
	deleted []string // "keys/ID" or "api_keys/ID"
}

func (f *fakeKeyAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer find-SECRET-admin" && r.URL.Path != "/verify" {
		w.WriteHeader(403)
		return
	}
	switch {
	case r.Method == "POST":
		f.n++
		id := fmt.Sprintf("k%d", f.n)
		f.keys[id] = fmt.Sprintf("sk-new-SECRET-%d-tail%d", f.n, f.n)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "value": f.keys[id]})
	case r.URL.Path == "/list":
		var data []any
		for id, v := range f.keys {
			data = append(data, map[string]any{"id": id, "redacted_value": v[:6] + "..." + v[len(v)-4:]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	case r.URL.Path == "/verify":
		w.WriteHeader(200)
	case r.Method == "DELETE":
		kind, id := filepath.Base(filepath.Dir(r.URL.Path)), filepath.Base(r.URL.Path)
		if (kind == "keys") != strings.HasPrefix(id, "k") { // each kind of key has its own delete endpoint
			w.WriteHeader(404)
			return
		}
		f.deleted = append(f.deleted, kind+"/"+id)
		delete(f.keys, id)
		w.WriteHeader(204)
	}
}

func TestFindKeyMadeByHand(t *testing.T) {
	f := &fakeKeyAPI{keys: map[string]string{"hand1": "sk-hand-SECRET-1234"}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	t.Setenv("KEYMOLT_CRED_FINDADM", "find-SECRET-admin")
	t.Setenv("KEYMOLT_HOSTS_FINDADM", "127.0.0.1")
	t.Setenv("KEYMOLT_HELPER", "1")
	skipApproval(t)
	auth := map[string]any{"Authorization": "Bearer {{cred:findadm}}"}
	recipeFor := func(dest string) map[string]any {
		return map[string]any{"name": "found",
			"current": map[string]any{"cmd": helper("print", dest)},
			"find": map[string]any{"url": srv.URL + "/list", "headers": auth, "list": "data", "id": "id", "hint": "redacted_value",
				"revoke": map[string]any{"method": "DELETE", "url": srv.URL + "/api_keys/{{old_id}}", "headers": auth}},
			"create": map[string]any{"method": "POST", "url": srv.URL + "/create", "headers": auth, "value": "value", "id": "id"},
			"verify": map[string]any{"url": srv.URL + "/verify"},
			"store":  []any{map[string]any{"label": "file", "cmd": helper("store", dest)}},
			"revoke": map[string]any{"method": "DELETE", "url": srv.URL + "/keys/{{old_id}}", "headers": auth}}
	}
	setup := func(held string) (string, string) {
		dir := t.TempDir() // its own folder, so state starts fresh
		dest, p := filepath.Join(dir, "dest.txt"), filepath.Join(dir, "r.json")
		if err := os.WriteFile(dest, []byte(held+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeJSON(t, p, recipeFor(dest))
		return dest, p
	}

	t.Run("a key made by hand is found and revoked with find's own revoke", func(t *testing.T) {
		dest, p := setup("sk-hand-SECRET-1234")
		code, out, _ := cli(t, "SECRET", "rotate", p)
		got, _ := os.ReadFile(dest)
		if code != 0 || out["found"] != "hand1" || out["revoke_by_hand"] != nil || !slices.Contains(f.deleted, "api_keys/hand1") ||
			string(got) != f.keys["k1"] {
			t.Fatal("first rotate should replace and revoke the hand-made key:", out, f.deleted)
		}
		if code, out, _ = cli(t, "SECRET", "rotate", p); code != 0 || !slices.Equal(list(out["revoked"]), []string{"k1"}) ||
			!slices.Contains(f.deleted, "keys/k1") {
			t.Fatal("later rotations revoke keymolt's own key with the recipe's revoke:", out, f.deleted)
		}
	})

	t.Run("two keys that fit the hint: revoke nothing, ask the user", func(t *testing.T) {
		f.keys["hand2"], f.keys["hand3"] = "sk-twin-SECRET-a-9999", "sk-twin-SECRET-b-9999"
		_, p := setup("sk-twin-SECRET-a-9999")
		before := len(f.deleted)
		code, out, _ := cli(t, "SECRET", "rotate", p)
		if code != 0 || out["found"] != nil || out["revoke_by_hand"] == nil || len(f.deleted) != before {
			t.Fatal("an ambiguous match must not revoke anything:", out, f.deleted)
		}
	})

	t.Run("an empty destination: nothing to revoke by hand", func(t *testing.T) {
		_, p := setup("")
		code, out, _ := cli(t, "SECRET", "create", p)
		if code != 0 || out["revoke_by_hand"] != nil || out["found"] != nil {
			t.Fatal("create into an empty destination:", out)
		}
	})

	t.Run("create refuses when the destination already holds a key", func(t *testing.T) {
		_, p := setup("sk-hand-SECRET-5678")
		made := f.n
		code, out, _ := cli(t, "SECRET", "create", p)
		if code != 1 || !strings.Contains(str(out["error"]), "already holds a key") || f.n != made {
			t.Fatal("create must stop before making a key:", out)
		}
	})
}
