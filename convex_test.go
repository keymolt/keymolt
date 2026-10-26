package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeConvex makes deploy keys and deletes them by name. Its create response has no id, like Convex's management API.
type fakeConvex struct {
	keys map[string]string // name -> secret value
}

func (f *fakeConvex) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch {
	case r.Header.Get("Authorization") != "Bearer team-SECRET":
		w.WriteHeader(401)
	case strings.HasSuffix(r.URL.Path, "/create_deploy_key"):
		f.keys[body["name"]] = "prod:x|SECRET-" + body["name"]
		_ = json.NewEncoder(w).Encode(map[string]any{"deployKey": f.keys[body["name"]]})
	case strings.HasSuffix(r.URL.Path, "/delete_deploy_key") && f.keys[body["id"]] != "":
		delete(f.keys, body["id"])
		_ = json.NewEncoder(w).Encode(map[string]any{})
	default:
		w.WriteHeader(404)
	}
}

func TestConvexDeployKeyRevokedByName(t *testing.T) {
	f := &fakeConvex{keys: map[string]string{}}
	srv := httptest.NewServer(f)
	defer srv.Close()

	t.Setenv("KEYMOLT_CRED_CONVEX_TEAM", "team-SECRET")
	t.Setenv("KEYMOLT_HOSTS_CONVEX_TEAM", "127.0.0.1")
	t.Setenv("KEYMOLT_HELPER", "1")
	skipApproval(t)

	tmp := t.TempDir()
	vercelFile := filepath.Join(tmp, "vercel_env.txt")
	auth := map[string]any{"Authorization": "Bearer {{cred:convex_team}}"}
	recipe := map[string]any{
		"name": "convex_deploy_key",
		"create": map[string]any{"method": "POST", "url": srv.URL + "/v1/deployments/d/create_deploy_key", "headers": auth,
			"body": map[string]any{"name": "build-{{ts}}"}, "value": "deployKey", "id": "build-{{ts}}"},
		"store": []any{map[string]any{"label": "vercel", "cmd": helper("store", vercelFile)}},
		"revoke": map[string]any{"method": "POST", "url": srv.URL + "/v1/deployments/d/delete_deploy_key", "headers": auth,
			"body": map[string]any{"id": "{{old_id}}"}},
	}
	// a placeholder url steps don't fill stays literal: refuse before create, or the key is live and untracked
	create := recipe["create"].(map[string]any)
	create["id"] = "{{name}}"
	bad := filepath.Join(tmp, "bad.json")
	writeJSON(t, bad, recipe)
	if code, out, _ := cli(t, "SECRET", "rotate", bad); code == 0 || len(f.keys) != 0 {
		t.Fatal("an id that isn't URL-safe should be refused before create:", out, f.keys)
	}
	create["id"] = "build-{{ts}}"
	path := filepath.Join(tmp, "convex.json")
	writeJSON(t, path, recipe)

	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second))) // start of a second, so the next two runs share {{ts}}
	code, out, _ := cli(t, "SECRET", "rotate", path)
	first, _ := out["new_id"].(string)
	stored, _ := os.ReadFile(vercelFile)
	if code != 0 || !strings.HasPrefix(first, "build-") || string(stored) != f.keys[first] {
		t.Fatal("first run should track the key by the name it sent:", out, f.keys)
	}

	// the same second gives the same name: refuse before making a key, or revoke would delete the new one
	code, out, _ = cli(t, "SECRET", "rotate", path)
	if code == 0 || !strings.Contains(str(out["error"]), "already tracks") || len(f.keys) != 1 {
		t.Fatal("a rotation that reuses a tracked name should be refused before create:", out, f.keys)
	}

	time.Sleep(1100 * time.Millisecond)
	code, out, _ = cli(t, "SECRET", "rotate", path)
	second, _ := out["new_id"].(string)
	if code != 0 || second == first || !slices.Equal(list(out["revoked"]), []string{first}) || f.keys[first] != "" || f.keys[second] == "" {
		t.Fatal("a later run should rotate and delete the old key by name:", out, f.keys)
	}
}
