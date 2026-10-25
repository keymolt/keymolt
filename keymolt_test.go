package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	verifyWait = 10 * time.Millisecond
	os.Exit(m.Run())
}

// TestHelperProcess stands in for CLI tools in recipes: "store" saves stdin to a file, "print" prints a file,
// "gen" prints a new secret.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("KEYMOLT_HELPER") != "1" {
		return
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	switch args[0] {
	case "store":
		b, _ := io.ReadAll(os.Stdin)
		_ = os.WriteFile(args[1], b, 0o600)
	case "print": // stands in for a CLI that prints the key a destination holds, like `convex env get`
		b, _ := os.ReadFile(args[1])
		os.Stdout.Write(b)
	case "gen":
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		fmt.Printf(`{"id": "%x", "v": "gen-SECRET-%x"}`, b[:4], b)
	}
	os.Exit(0)
}

func helper(mode, arg string) []any {
	return []any{os.Args[0], "-test.run=^TestHelperProcess$", "--", mode, arg}
}

// cli runs keymolt in-process, fails the test if marker reaches the output, and returns the last JSON line.
func cli(t *testing.T, marker string, args ...string) (int, map[string]any, string) {
	t.Helper()
	var b bytes.Buffer
	code := run(args, &b)
	out := b.String()
	if strings.Contains(out, marker) {
		t.Fatalf("secret leaked into output: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	last, _ := decode([]byte(lines[len(lines)-1])).(map[string]any)
	return code, last, out
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func list(v any) []string { return toStrings(v) }

// fakeProvider issues app keys with a fixed admin key, and admin keys that manage themselves under /admin.
type fakeProvider struct {
	mu              sync.Mutex
	admin           string
	keys, admins    map[string]string
	n, adminN       int
	revoked, stored []string
	failVerify      bool
}

func (f *fakeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	reply := func(code int, body any) {
		w.WriteHeader(code)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
	if strings.HasPrefix(r.URL.Path, "/admin") { // every admin call needs a live admin key
		if !slices.Contains(mapValues(f.admins), bearer) {
			reply(401, map[string]any{})
			return
		}
		switch r.Method {
		case "POST":
			f.adminN++
			kid := fmt.Sprintf("a%d", f.adminN)
			f.admins[kid] = "adm-SECRET-" + kid
			reply(200, map[string]any{"id": kid, "value": f.admins[kid]})
		case "DELETE":
			delete(f.admins, filepath.Base(r.URL.Path))
			reply(204, nil)
		default:
			reply(200, map[string]any{})
		}
		return
	}
	switch r.Method {
	case "POST":
		if bearer != f.admin {
			reply(403, nil)
			return
		}
		f.n++
		kid := fmt.Sprintf("k%d", f.n)
		if r.URL.Path == "/keys-empty" { // a provider that hands back an id but no key value
			reply(200, map[string]any{"id": kid, "api_key": map[string]any{"value": ""}})
			return
		}
		f.keys[kid] = "sk-live-SECRET-" + kid + "-xyz"
		reply(200, map[string]any{"id": kid, "api_key": map[string]any{"value": f.keys[kid]}})
	case "GET": // verify
		live := false
		for k, v := range f.keys {
			live = live || (v == bearer && !slices.Contains(f.revoked, k))
		}
		if f.failVerify || !live {
			reply(401, map[string]any{})
			return
		}
		reply(200, map[string]any{})
	case "PUT": // an HTTP store destination
		var body struct{ Value string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.stored = append(f.stored, body.Value)
		reply(200, map[string]any{"data": map[string]any{"ok": true}})
	case "DELETE":
		f.revoked = append(f.revoked, filepath.Base(r.URL.Path))
		reply(204, nil)
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// skipApproval lets a test run recipes it builds itself. TestApproval covers the approval gate.
func skipApproval(t *testing.T) {
	approveAll = true
	t.Cleanup(func() { approveAll = false })
}

func vaultAvailable(t *testing.T) {
	if err := keyring.Set(vaultService, "probe", "x"); err != nil {
		t.Skip("no OS vault here:", err)
	}
	_ = keyring.Delete(vaultService, "probe")
}

func TestRotate(t *testing.T) {
	f := &fakeProvider{admin: "admin-SECRET-0001", keys: map[string]string{}, admins: map[string]string{"a0": "adm-SECRET-a0"}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	base := srv.URL
	t.Setenv("KEYMOLT_CRED_ADMIN", f.admin)
	t.Setenv("KEYMOLT_HOSTS_ADMIN", "127.0.0.1")
	t.Setenv("KEYMOLT_HELPER", "1")
	skipApproval(t)
	tmp := t.TempDir()
	path, cmdOut := filepath.Join(tmp, "recipe.json"), filepath.Join(tmp, "cmd_dest.txt")
	auth := map[string]any{"Authorization": "Bearer {{cred:admin}}"}
	recipe := map[string]any{
		"name": "fake",
		"create": map[string]any{"method": "POST", "url": base + "/keys", "headers": auth, "body": map[string]any{"n": "{{ts}}"},
			"value": "api_key.value", "id": "id"},
		"verify": map[string]any{"url": base + "/verify", "headers": map[string]any{"Authorization": "Bearer {{new}}"}},
		"store": []any{
			map[string]any{"label": "http", "method": "PUT", "url": base + "/store", "body": map[string]any{"value": "{{new}}"}, "ok_path": "data.ok"},
			map[string]any{"label": "cmd", "cmd": helper("store", cmdOut)},
		},
		"revoke": map[string]any{"method": "DELETE", "url": base + "/keys/{{old_id}}", "headers": auth},
	}
	writeJSON(t, path, recipe)
	rot := func() (int, map[string]any) {
		t.Helper()
		code, out, _ := cli(t, "SECRET", "rotate", path)
		return code, out
	}

	code, out := rot()
	if code != 0 || out["new_id"] != "k1" || !slices.Equal(list(out["stored"]), []string{"http", "cmd"}) {
		t.Fatal("first rotation:", out)
	}
	if got, _ := os.ReadFile(cmdOut); !slices.Equal(f.stored, []string{f.keys["k1"]}) || string(got) != f.keys["k1"] {
		t.Fatal("new key not stored in both destinations")
	}

	code, out = rot()
	if code != 0 || out["new_id"] != "k2" || !slices.Equal(list(out["revoked"]), []string{"k1"}) {
		t.Fatal("second rotation should revoke k1:", out)
	}

	f.failVerify = true
	code, out = rot()
	if code != 1 || !strings.Contains(str(out["error"]), "verify") || !slices.Equal(f.revoked, []string{"k1", "k3"}) {
		t.Fatal("failed verify should revoke only the new key:", out, f.revoked)
	}
	if f.stored[len(f.stored)-1] != f.keys["k2"] {
		t.Fatal("failed rotation must leave the live key in place")
	}
	f.failVerify = false

	t.Run("generated secret with a CLI store and no revoke", func(t *testing.T) {
		gen := filepath.Join(tmp, "gen.json")
		dest := filepath.Join(tmp, "gen_dest.txt")
		writeJSON(t, gen, map[string]any{"name": "webhook", "create": map[string]any{"cmd": helper("gen", ""), "value": "v", "id": "id"},
			"store": []any{map[string]any{"label": "file", "cmd": helper("store", dest)}}})
		code1, _, _ := cli(t, "SECRET", "rotate", gen)
		first, _ := os.ReadFile(dest)
		code2, _, _ := cli(t, "SECRET", "rotate", gen)
		second, _ := os.ReadFile(dest)
		if code1 != 0 || code2 != 0 || !strings.HasPrefix(string(first), "gen-SECRET-") || string(first) == string(second) {
			t.Fatal("generated secret did not rotate")
		}
		os.Remove(gen)
	})

	t.Run("commands run in the recipe's folder, not the caller's", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "rel.json")
		writeJSON(t, p, map[string]any{"name": "rel", "create": map[string]any{"cmd": helper("gen", ""), "value": "v", "id": "id"},
			"store": []any{map[string]any{"label": "file", "cmd": helper("store", "rel_dest.txt")}}})
		t.Chdir(t.TempDir()) // like a scheduler, which starts keymolt in its own folder
		if code, out, _ := cli(t, "SECRET", "rotate", p); code != 0 {
			t.Fatal(out)
		}
		if _, err := os.Stat(filepath.Join(dir, "rel_dest.txt")); err != nil {
			t.Fatal("a relative path in a command must resolve against the recipe's folder:", err)
		}
	})

	t.Run("empty key from the provider is revoked, old key untouched", func(t *testing.T) {
		bad := maps(recipe, "name", "fake_empty", "create", maps(asMap(recipe["create"]), "url", base+"/keys-empty"))
		p := filepath.Join(t.TempDir(), "empty.json")
		writeJSON(t, p, bad)
		before := slices.Clone(f.revoked)
		code, out, _ := cli(t, "SECRET", "rotate", p)
		if code != 1 || !strings.Contains(str(out["error"]), "empty key") || len(f.revoked) != len(before)+1 {
			t.Fatal("empty key should fail and revoke the new key:", out, f.revoked)
		}
	})

	t.Run("keep_previous keeps the old key for one run", func(t *testing.T) {
		kpath := filepath.Join(t.TempDir(), "keep.json") // its own folder, so state starts fresh
		writeJSON(t, kpath, maps(recipe, "name", "fake_keep", "keep_previous", true))
		var outs []map[string]any
		for range 3 {
			_, o, _ := cli(t, "SECRET", "rotate", kpath)
			outs = append(outs, o)
		}
		first := str(outs[0]["new_id"])
		if len(list(outs[0]["revoked"])) != 0 || len(list(outs[1]["revoked"])) != 0 || !slices.Equal(list(outs[2]["revoked"]), []string{first}) {
			t.Fatal("keep_previous revoked at the wrong time:", outs)
		}
		if !slices.Equal(list(outs[1]["revoke_failed"]), []string{first}) { // reported as still live, by design
			t.Fatal(outs[1])
		}
	})

	t.Run("a store fails after another worked: both keys stay live, a rerun finishes", func(t *testing.T) {
		dir := t.TempDir() // its own folder, so state starts fresh
		p := filepath.Join(dir, "partial.json")
		writeJSON(t, p, maps(recipe, "name", "fake_partial"))
		_, first, _ := cli(t, "SECRET", "rotate", p)
		oldID := str(first["new_id"])
		broken := append(slices.Clone(asList(recipe["store"])), map[string]any{"label": "broken", "cmd": []any{"keymolt-no-such-command"}})
		writeJSON(t, p, maps(recipe, "name", "fake_partial", "store", broken))
		before := len(f.revoked)
		code, out, _ := cli(t, "SECRET", "rotate", p)
		var state map[string]stateEntry
		b, _ := os.ReadFile(filepath.Join(dir, ".keymolt-state.json"))
		_ = json.Unmarshal(b, &state)
		e := state["partial.json"]
		if code != 1 || !strings.Contains(str(out["error"]), "both live, rerun") || len(f.revoked) != before ||
			e.ID == "" || e.ID == oldID || !slices.Equal(e.Stale, []string{oldID}) {
			t.Fatal("a partial store must revoke nothing and track both keys:", out, e)
		}
		writeJSON(t, p, maps(recipe, "name", "fake_partial"))
		code, out, _ = cli(t, "SECRET", "rotate", p)
		if code != 0 || !slices.Equal(list(out["revoked"]), []string{oldID, e.ID}) {
			t.Fatal("the rerun must revoke both older keys:", out)
		}
	})

	t.Run("create makes the first key and refuses when one is tracked", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "new.json") // its own folder, so state starts fresh
		writeJSON(t, p, maps(recipe, "name", "fake_create"))
		code, out, _ := cli(t, "SECRET", "create", p)
		if code != 0 || out["ok"] != true || len(list(out["revoked"])) != 0 {
			t.Fatal("create on a new recipe:", out)
		}
		created := f.n
		code, out, _ = cli(t, "SECRET", "create", p)
		if code != 1 || !strings.Contains(str(out["error"]), "already made a key") || f.n != created {
			t.Fatal("a second create must stop before making a key:", out)
		}
		if code, out, _ = cli(t, "SECRET", "rotate", p); code != 0 || len(list(out["revoked"])) != 1 {
			t.Fatal("rotate after create:", out)
		}
	})

	t.Run("folder lock", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "locked.json")
		writeJSON(t, p, maps(recipe, "name", "fake_lock"))
		lock := filepath.Join(dir, ".keymolt.lock")
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		created := f.n
		if code, out, _ := cli(t, "SECRET", "rotate", p); code != 1 || !strings.Contains(str(out["error"]), "another keymolt run") || f.n != created {
			t.Fatal("a held lock must stop the run before create:", out)
		}
		old := time.Now().Add(-2 * time.Hour) // left by a crashed run
		_ = os.Chtimes(lock, old, old)
		if code, out, _ := cli(t, "SECRET", "rotate", p); code != 0 {
			t.Fatal("a stale lock must not block forever:", out)
		}
		if _, err := os.Stat(lock); !os.IsNotExist(err) {
			t.Fatal("the lock must be removed after the run")
		}
	})

	t.Run("rotate-all writes one receipt line per recipe", func(t *testing.T) {
		rdir := t.TempDir() // its own folder with exactly one recipe
		writeJSON(t, filepath.Join(rdir, "one.json"), recipe)
		code, out, _ := cli(t, "SECRET", "rotate-all", rdir)
		log, _ := os.ReadFile(filepath.Join(rdir, "keymolt.log"))
		if code != 0 || out["ok"] != true || strings.Count(string(log), "\n") != 1 || !strings.Contains(string(log), `"ok":true`) ||
			strings.Contains(string(log), "SECRET") {
			t.Fatal("rotate-all:", out, string(log))
		}
	})

	t.Run("host lock", func(t *testing.T) {
		created := f.n
		for _, u := range []string{"http://localhost:1/keys", "http://example.com/keys"} {
			bad := maps(recipe, "create", maps(asMap(recipe["create"]), "url", u))
			writeJSON(t, path, bad)
			code, out := rot()
			if code != 1 || !strings.Contains(str(out["error"]), "may only go to https://127.0.0.1") || f.n != created {
				t.Fatal("admin key went to the wrong host:", u, out)
			}
		}
	})

	t.Run("OS vault", func(t *testing.T) {
		vaultAvailable(t)
		if err := credSet("selftest", "vault-SECRET", []string{"example.com"}); err != nil {
			t.Fatal(err)
		}
		defer keyring.Delete(vaultService, "selftest")
		if v, err := credGet("selftest", "example.com"); err != nil || v != "vault-SECRET" {
			t.Fatal("vault round trip failed", err)
		}
	})

	t.Run("admin key rotates itself", func(t *testing.T) {
		vaultAvailable(t)
		apath := filepath.Join(t.TempDir(), "admin.json") // its own folder, so state starts fresh
		adminAuth := map[string]any{"Authorization": "Bearer {{cred:selftest_admin}}"}
		writeJSON(t, apath, map[string]any{"name": "selftest_admin",
			"create": map[string]any{"method": "POST", "url": base + "/admin", "headers": adminAuth, "value": "value", "id": "id"},
			"verify": map[string]any{"url": base + "/admin", "headers": map[string]any{"Authorization": "Bearer {{new}}"}},
			"store":  []any{map[string]any{"label": "vault", "vault": "selftest_admin"}},
			"revoke": map[string]any{"method": "DELETE", "url": base + "/admin/{{old_id}}", "headers": adminAuth}})
		if err := credSet("selftest_admin", f.admins["a0"], []string{"127.0.0.1"}); err != nil {
			t.Fatal(err)
		}
		defer keyring.Delete(vaultService, "selftest_admin")
		current := func() string { v, _ := credGet("selftest_admin", "127.0.0.1"); return v }
		arot := func() (int, map[string]any) { c, o, _ := cli(t, "SECRET", "rotate", apath); return c, o }

		code, out := arot()
		if code != 0 || !slices.Equal(list(out["stored"]), []string{"vault"}) || out["revoke_by_hand"] == nil || current() != f.admins["a1"] {
			t.Fatal("first admin rotation:", out) // a0 was made by hand, so keymolt leaves it for the user
		}
		code, out = arot()
		if code != 0 || !slices.Equal(list(out["revoked"]), []string{"a1"}) || current() != f.admins["a2"] || len(f.admins) != 2 {
			t.Fatal("second admin rotation:", out, f.admins)
		}
		// an env-var credential can't be rewritten: the new key is revoked and the old one keeps working
		t.Setenv("KEYMOLT_CRED_SELFTEST_ADMIN", f.admins["a2"])
		t.Setenv("KEYMOLT_HOSTS_SELFTEST_ADMIN", "127.0.0.1")
		code, out = arot()
		if code != 1 || !strings.Contains(str(out["error"]), "env var") || len(f.admins) != 2 {
			t.Fatal("env-var admin key:", out, f.admins)
		}
	})
}

// maps returns a copy of m with the given key, value pairs set.
func maps(m map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func TestSchedulePlan(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Weekly Keys")
	name, files, cmds := schedulePlan(dir, "weekly", "windows", `C:\tools\keymolt.exe`, `C:\Users\me`)
	if name != "keymolt-weekly-keys" || files != nil || !strings.Contains(cmds[0][3], "-StartWhenAvailable") ||
		!strings.Contains(cmds[0][3], `'"rotate-all" "`) {
		t.Fatal("windows plan:", name, cmds)
	}
	_, files, cmds = schedulePlan(dir, "monthly", "darwin", "/usr/local/bin/keymolt", "/Users/me")
	for _, plist := range files {
		if !strings.Contains(plist, "<key>Day</key><integer>1</integer>") {
			t.Fatal("monthly plist should run on day 1")
		}
		for d := xml.NewDecoder(strings.NewReader(plist)); ; {
			if _, err := d.Token(); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal("plist is not valid XML:", err)
			}
		}
	}
	if cmds[1][1] != "load" {
		t.Fatal("darwin plan:", cmds)
	}
	name, files, cmds = schedulePlan(dir, "weekly", "linux", "/opt/key%molt", "/home/me")
	timer := files[filepath.Join("/home/me", ".config", "systemd", "user", name)+".timer"]
	service := files[filepath.Join("/home/me", ".config", "systemd", "user", name)+".service"]
	if !strings.Contains(timer, "OnCalendar=Sun *-*-* 03:00") || !strings.Contains(timer, "Persistent=true") ||
		!strings.Contains(service, `"/opt/key%%molt"`) || cmds[1][4] != name+".timer" {
		t.Fatal("linux plan:", files, cmds)
	}
}

func TestTOTP(t *testing.T) {
	if code, err := totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0)); err != nil || code != "287082" {
		t.Fatal("RFC 6238 test vector:", code, err)
	}
}

func TestValidation(t *testing.T) {
	skipApproval(t)
	dir := t.TempDir()
	noStore := filepath.Join(dir, "a.json")
	writeJSON(t, noStore, map[string]any{"name": "x", "create": map[string]any{"cmd": helper("gen", ""), "value": "v", "id": "id"}})
	if _, err := rotate(noStore); err == nil || !strings.Contains(err.Error(), "no store step") {
		t.Fatal("a recipe with no store must be refused:", err)
	}
	noCreate := filepath.Join(dir, "b.json")
	writeJSON(t, noCreate, map[string]any{"name": "x", "store": []any{map[string]any{"cmd": helper("gen", "")}}})
	if _, err := rotate(noCreate); err == nil || !strings.Contains(err.Error(), "no create step") {
		t.Fatal("a recipe with no create must be refused:", err)
	}
}

func TestApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	writeJSON(t, path, map[string]any{"name": "x", "create": map[string]any{"url": "https://api.example.com"},
		"store": []any{map[string]any{"url": "https://api.example.com"}}})
	if isApproved(path) {
		t.Fatal("a new recipe must not be approved")
	}
	if _, err := rotate(path); err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatal("rotate must refuse an unapproved recipe:", err)
	}
	h, _ := recipeHash(path)
	t.Setenv("KEYMOLT_APPROVED", "deadbeef, "+h) // CI: a human lists the exact hashes they trust
	if !isApproved(path) {
		t.Fatal("a hash in KEYMOLT_APPROVED must approve its recipe")
	}
	t.Setenv("KEYMOLT_APPROVED", "")

	vaultAvailable(t)
	if err := approveRecipeFile(path); err != nil {
		t.Fatal(err)
	}
	defer keyring.Delete(vaultService, "approval:"+h)
	if !isApproved(path) {
		t.Fatal("approval did not take")
	}
	if err := os.WriteFile(path, []byte(" "), 0o600); err != nil { // editing the file revokes approval
		t.Fatal(err)
	}
	if isApproved(path) {
		t.Fatal("an edited recipe must lose approval")
	}
}

func TestNormalizeHost(t *testing.T) {
	ok := map[string]string{"api.openai.com": "api.openai.com", "https://api.openai.com": "api.openai.com",
		"https://api.openai.com/": "api.openai.com", " api.openai.com ": "api.openai.com"}
	for in, want := range ok {
		if got, err := normalizeHost(in); err != nil || got != want {
			t.Errorf("normalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"https://api.openai.com/v1/keys", "api.openai.com/v1", ""} {
		if _, err := normalizeHost(bad); err == nil {
			t.Errorf("normalizeHost(%q) should fail", bad)
		}
	}
}

func TestRedirectBlocked(t *testing.T) {
	var hits int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer evil.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/keys", 308) // 308 resends the body, which could hold a key
	}))
	defer front.Close()
	ok, _, _ := httpDo(map[string]any{"method": "POST", "url": front.URL + "/keys", "body": map[string]any{"k": "secret"}})
	if ok || atomic.LoadInt32(&hits) != 0 {
		t.Fatal("a redirect to another host must be refused")
	}
}
