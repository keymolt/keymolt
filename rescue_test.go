package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

var sharedRef = regexp.MustCompile(`\$\{\{shared\.(\w+)\}\}`)

// fakeRailway serves Railway's GraphQL API and an OpenAI-like provider from one server.
type fakeRailway struct {
	mu      sync.Mutex
	vars    map[string]map[string]string // "service/env" -> variables
	keys    map[string]string
	revoked []string
	upserts []string
}

func (f *fakeRailway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, body any) {
		w.WriteHeader(code)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch {
	case r.URL.Path == "/graphql":
		if bearer != "rw-LEAK" {
			reply(401, nil)
			return
		}
		var body struct {
			Query     string
			Variables map[string]any
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		v := body.Variables
		switch {
		case strings.Contains(body.Query, "project("):
			reply(200, map[string]any{"data": map[string]any{"project": map[string]any{"name": "shop",
				"services": map[string]any{"edges": []any{
					map[string]any{"node": map[string]any{"id": "s1", "name": "api"}},
					map[string]any{"node": map[string]any{"id": "s2", "name": "worker"}}}},
				"environments": map[string]any{"edges": []any{map[string]any{"node": map[string]any{"id": "e1", "name": "production"}}}}}}})
		case strings.Contains(body.Query, "variables("):
			out := map[string]string{}
			for n, val := range f.vars[str(v["s"])+"/"+str(v["e"])] {
				if !strings.Contains(body.Query, "unrendered: true") { // like Railway, resolve ${{shared.X}} by default
					val = sharedRef.ReplaceAllStringFunc(val, func(m string) string {
						return f.vars["/"+str(v["e"])][sharedRef.FindStringSubmatch(m)[1]]
					})
				}
				out[n] = val
			}
			reply(200, map[string]any{"data": map[string]any{"variables": out}})
		default:
			i := asMap(v["i"])
			if s, has := i["serviceId"]; has && str(s) == "" { // a shared variable is written by leaving serviceId out
				reply(200, map[string]any{"errors": []any{"bad serviceId"}})
				return
			}
			f.vars[str(i["serviceId"])+"/"+str(i["environmentId"])][str(i["name"])] = str(i["value"])
			f.upserts = append(f.upserts, str(i["value"]))
			reply(200, map[string]any{"data": map[string]any{"variableUpsert": true}})
		}
	case r.Method == "POST": // create a service account key
		if r.URL.Path != "/projects/proj_1/service_accounts" || bearer != "admin-LEAK" {
			reply(403, nil)
			return
		}
		kid := fmt.Sprintf("sa_%d", len(f.keys)+1)
		f.keys[kid] = "sk-proj-LEAK-new-" + kid
		reply(200, map[string]any{"id": kid, "api_key": map[string]any{"value": f.keys[kid]}})
	case r.Method == "GET": // verify
		for k, v := range f.keys {
			if v == bearer && !slices.Contains(f.revoked, k) {
				reply(200, map[string]any{})
				return
			}
		}
		reply(401, nil)
	case r.Method == "DELETE":
		f.revoked = append(f.revoked, filepath.Base(r.URL.Path))
		reply(204, nil)
	}
}

func TestRescue(t *testing.T) {
	old := "sk-proj-LEAK-old-aaaa1111"
	f := &fakeRailway{keys: map[string]string{}, vars: map[string]map[string]string{
		"s1/e1": {"OPENAI_API_KEY": old, "STRIPE_SECRET_KEY": "sk_live_LEAK-zzzz9999", "PORT": "8080",
			"DATABASE_URL": "postgresql://u:LEAKpw@db.internal:5432/app"},
		"s2/e1": {"OPENAI_API_KEY": "${{shared.OPENAI_API_KEY}}", "NODE_ENV": "production"}, // a reference
		"/e1":   {"OPENAI_API_KEY": old},                                                    // a shared variable: no service id
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	tmp := t.TempDir()
	providers := filepath.Join(tmp, "providers")
	_ = os.Mkdir(providers, 0o700)
	auth := map[string]any{"Authorization": "Bearer {{cred:openai_admin}}"}
	writeJSON(t, filepath.Join(providers, "openai.json"), map[string]any{
		"detect": map[string]any{"name": "OPENAI|OAI", "value": "^sk-"},
		"create": map[string]any{"method": "POST", "url": srv.URL + "/projects/{{openai_project}}/service_accounts",
			"headers": auth, "body": map[string]any{"name": "keymolt-{{ts}}"}, "value": "api_key.value", "id": "id"},
		"verify": map[string]any{"url": srv.URL + "/v1/models", "headers": map[string]any{"Authorization": "Bearer {{new}}"}},
		"revoke": map[string]any{"method": "DELETE", "url": srv.URL + "/projects/{{openai_project}}/service_accounts/{{old_id}}", "headers": auth},
	})
	for k, v := range map[string]string{"KEYMOLT_RAILWAY_API": srv.URL + "/graphql", "KEYMOLT_PROVIDERS": providers,
		"KEYMOLT_CRED_RAILWAY": "rw-LEAK", "KEYMOLT_HOSTS_RAILWAY": "127.0.0.1",
		"KEYMOLT_CRED_OPENAI_ADMIN": "admin-LEAK", "KEYMOLT_HOSTS_OPENAI_ADMIN": "127.0.0.1"} {
		t.Setenv(k, v)
	}
	skipApproval(t) // the openai template comes from a user folder, so it is untrusted
	t.Chdir(tmp)

	code, _, out := cli(t, "LEAK", "rescue", "scan", "proj_rw")
	for _, want := range []string{"3 distinct keys in 4 variables. 1 can rotate automatically.", "...1111",
		"same key as api/production OPENAI_API_KEY", "shared/production", "database"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("scan output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PORT") || strings.Contains(out, "worker/") || len(f.upserts) != 0 || len(f.keys) != 0 {
		t.Fatal("scan must only report, and skip non-secrets and references")
	}

	code, last, _ := cli(t, "LEAK", "rescue", "rotate", "proj_rw")
	if code != 1 || !strings.Contains(str(last["error"]), "openai_project=...") || len(f.keys) != 0 {
		t.Fatal("a missing k=v must stop before any rotation:", last)
	}

	code, _, out = cli(t, "LEAK", "rescue", "rotate", "proj_rw", "openai_project=proj_1")
	if code != 0 || len(f.keys) != 1 || !slices.Equal(f.upserts, []string{f.keys["sa_1"], f.keys["sa_1"]}) ||
		f.vars["/e1"]["OPENAI_API_KEY"] != f.keys["sa_1"] || f.vars["s2/e1"]["OPENAI_API_KEY"] != "${{shared.OPENAI_API_KEY}}" {
		t.Fatal("the new key should reach the service and the shared variable, and the reference must stay a reference:", out, f.upserts)
	}
	for _, want := range []string{"Revoke these exposed keys", "openai ...1111", "stripe ...9999"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rotate output is missing %q:\n%s", want, out)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(tmp, "rescued", "api-production-openai-api-key.json")); strings.Contains(string(b), "LEAK") || len(b) == 0 {
		t.Fatal("rescued recipe is missing or holds a secret")
	}

	code, _, _ = cli(t, "LEAK", "rescue", "rotate", "proj_rw", "openai_project=proj_1") // a rerun is a normal rotation
	if code != 0 || len(f.keys) != 2 || !slices.Equal(f.revoked, []string{"sa_1"}) {
		t.Fatal("rerun should revoke the key keymolt made last time:", f.revoked)
	}
}

func TestUniqueName(t *testing.T) {
	used := map[string]bool{}
	if got := []string{uniqueName(used, "a"), uniqueName(used, "a"), uniqueName(used, "a"), uniqueName(used, "b")}; !slices.Equal(got, []string{"a", "a-2", "a-3", "b"}) {
		t.Fatal(got)
	}
}

func TestClassify(t *testing.T) {
	tpl, err := loadTemplates() // the built-in templates
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, value, want string }{
		{"OPENAI_API_KEY", "sk-proj-abc", "openai"},
		{"ANTHROPIC_KEY", "sk-ant-abc", "anthropic"}, // longer prefix beats sk-
		{"MY_LLM_KEY", "sk-ant-abc", "anthropic"},    // value alone is enough
		{"GITHUB_TOKEN", "ghp_abcdef", "github"},
		{"DATABASE_URL", "postgres://u:p@host:5432/d", "database"},
		{"ACCESS", "AKIAABCDEFGHIJKLMNOP", "aws"}, // name tells us nothing; value does
		{"STRIPE_SECRET_KEY", "sk_live_abc", "stripe"},
		{"WEIRD", "opaque-no-prefix", ""}, // nothing matches
	}
	for _, c := range cases {
		if got := classify(c.name, c.value, tpl); got != c.want {
			t.Errorf("classify(%q, %q) = %q, want %q", c.name, c.value, got, c.want)
		}
	}
	// a shared prefix is broken by the variable name
	shared := map[string]tmpl{
		"openai":   {value: regexp.MustCompile("^sk-"), name: regexp.MustCompile("(?i)OPENAI")},
		"deepseek": {value: regexp.MustCompile("^sk-"), name: regexp.MustCompile("(?i)DEEPSEEK")},
	}
	if got := classify("DEEPSEEK_API_KEY", "sk-abc", shared); got != "deepseek" {
		t.Errorf("a shared prefix should be decided by the name, got %q", got)
	}
	if got := classify("MYSTERY", "sk-abc", shared); got != "" {
		t.Errorf("a shared prefix with no name help should be unknown, got %q", got)
	}
}
