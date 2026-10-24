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
	"testing"
)

// fakeElevenLabs issues service-account API keys and disables them via PATCH, authenticating with the xi-api-key header.
// It proves the shape of elevenlabs-to-convex.example.json: a url create + a cmd store that reads the key on stdin.
type fakeElevenLabs struct {
	admin    string
	keys     map[string]string // key_id -> secret value
	disabled []string
	n        int
}

func (f *fakeElevenLabs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("xi-api-key")
	reply := func(code int, body any) {
		w.WriteHeader(code)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	switch {
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/api-keys"):
		if key != f.admin {
			reply(401, nil)
			return
		}
		f.n++
		id := fmt.Sprintf("ek%d", f.n)
		f.keys[id] = "xi-SECRET-" + id
		reply(200, map[string]any{"xi-api-key": f.keys[id], "key_id": id})
	case r.Method == "GET" && r.URL.Path == "/v1/user": // verify: the new key must work and not be disabled
		for id, v := range f.keys {
			if v == key && !slices.Contains(f.disabled, id) {
				reply(200, map[string]any{})
				return
			}
		}
		reply(401, nil)
	case r.Method == "PATCH": // revoke = disable the old key
		if key != f.admin {
			reply(401, nil)
			return
		}
		f.disabled = append(f.disabled, filepath.Base(r.URL.Path))
		reply(200, map[string]any{})
	default:
		reply(404, nil)
	}
}

func TestElevenLabsToConvex(t *testing.T) {
	f := &fakeElevenLabs{admin: "xi-admin-SECRET", keys: map[string]string{}}
	srv := httptest.NewServer(f)
	defer srv.Close()

	t.Setenv("KEYMOLT_CRED_ELEVENLABS_ADMIN", f.admin)
	t.Setenv("KEYMOLT_HOSTS_ELEVENLABS_ADMIN", "127.0.0.1")
	t.Setenv("KEYMOLT_HELPER", "1") // the convex store step is stood in for by the test helper binary
	skipApproval(t)

	tmp := t.TempDir()
	convexFile := filepath.Join(tmp, "convex_env.txt") // stands in for `npx convex env set` reading the key on stdin
	auth := map[string]any{"xi-api-key": "{{cred:elevenlabs_admin}}", "Content-Type": "application/json"}
	recipe := map[string]any{
		"name": "elevenlabs_prod",
		"create": map[string]any{"method": "POST", "url": srv.URL + "/v1/service-accounts/sa_1/api-keys",
			"headers": auth, "body": map[string]any{"name": "keymolt-{{ts}}", "permissions": []any{"text_to_speech"}},
			"value": "xi-api-key", "id": "key_id"},
		"verify": map[string]any{"url": srv.URL + "/v1/user", "headers": map[string]any{"xi-api-key": "{{new}}"}},
		"store":  []any{map[string]any{"label": "convex", "cmd": helper("store", convexFile)}},
		"revoke": map[string]any{"method": "PATCH", "url": srv.URL + "/v1/service-accounts/sa_1/api-keys/{{old_id}}",
			"headers": auth, "body": map[string]any{"is_enabled": false}},
	}
	path := filepath.Join(tmp, "elevenlabs.json")
	writeJSON(t, path, recipe)

	// first run: create a key and place it; there is no old key to disable
	code, out, _ := cli(t, "SECRET", "rotate", path)
	stored, _ := os.ReadFile(convexFile)
	if code != 0 || out["new_id"] != "ek1" || !slices.Equal(list(out["stored"]), []string{"convex"}) ||
		string(stored) != f.keys["ek1"] || len(list(out["revoked"])) != 0 {
		t.Fatal("first run should create ek1 and place it on convex:", out, string(stored))
	}

	// second run: place the new key, then disable the previous one
	code, out, _ = cli(t, "SECRET", "rotate", path)
	stored, _ = os.ReadFile(convexFile)
	if code != 0 || out["new_id"] != "ek2" || string(stored) != f.keys["ek2"] ||
		!slices.Equal(list(out["revoked"]), []string{"ek1"}) || !slices.Equal(f.disabled, []string{"ek1"}) {
		t.Fatal("second run should rotate to ek2 and disable ek1:", out, f.disabled)
	}
}
