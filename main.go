// Command keymolt creates, stores, verifies and revokes API keys without printing them.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const usage = `keymolt: create, store, verify and revoke API keys without printing them.

  keymolt cred-set NAME HOST [HOST ...]              human, once: hidden prompt, saves a credential locked to these hosts
  keymolt approve RECIPE                             human, once: shows where a recipe sends keys, then trusts it
  keymolt create RECIPE                              first key: new key -> verify -> store. Refuses if keymolt already made one.
  keymolt rotate RECIPE                              new key -> verify -> store -> revoke old. Prints metadata only.
  keymolt find RECIPE                                print the id of the key the recipe's destination holds now
  keymolt link RECIPE ID                             human: track key ID, so the next rotate replaces it, then revokes it
  keymolt revoke RECIPE ID                           revoke key ID now, without a new one. Human, for a key keymolt doesn't track.
  keymolt rotate-all FOLDER                          rotate every recipe in FOLDER and in each keymolt folder below it; logs to keymolt.log
  keymolt schedule FOLDER weekly|monthly             run rotate-all on a schedule (Task Scheduler, launchd or systemd)
  keymolt rescue scan RAILWAY_PROJECT_ID             after a breach: list every key in a Railway project
  keymolt rescue rotate RAILWAY_PROJECT_ID [k=v ...] ...and rotate each key that has a provider template
  keymolt browser login PROFILE URL                  human, once: log in by hand in a visible browser

Recipe strings may use {{cred:NAME}}, {{new}}, {{new_id}}, {{old_id}}, {{ts}}.
Step kinds: HTTP ("url"), command ("cmd", the new key arrives on stdin), browser flow ("browser"),
and vault ("vault": NAME, which saves the new key as credential NAME so an admin key can rotate itself).
Credentials live in the OS vault (Keychain, Credential Manager, Secret Service). In CI, set KEYMOLT_CRED_<NAME>
and KEYMOLT_HOSTS_<NAME> (comma-separated) instead. A credential only goes to its hosts, over https.
In CI, approve recipes by listing their SHA-256 hashes in KEYMOLT_APPROVED (comma-separated).
`

// errReported means the command already printed its own result and only needs a failing exit code.
var errReported = errors.New("reported")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, w io.Writer) (code int) {
	defer func() {
		if recover() != nil { // never print a stack trace: it can hold secrets
			printFail(w, errors.New("internal error"))
			code = 1
		}
	}()
	var err error
	switch {
	case len(args) >= 3 && args[0] == "cred-set":
		err = credSetPrompt(args[1], args[2:], w)
	case len(args) == 2 && args[0] == "approve":
		err = approveCommand(args[1], w)
	case len(args) == 2 && (args[0] == "create" || args[0] == "rotate"):
		var r *receipt
		if r, err = runRecipe(args[1], args[0] == "create"); err == nil {
			printJSON(w, r)
		}
	case len(args) == 2 && args[0] == "find":
		var id string
		if id, err = findCommand(args[1]); err == nil {
			printJSON(w, map[string]any{"ok": true, "id": id})
		}
	case len(args) == 3 && args[0] == "link":
		if err = linkCommand(args[1], args[2]); err == nil {
			printJSON(w, map[string]any{"ok": true, "linked": args[2]})
		}
	case len(args) == 3 && args[0] == "revoke":
		var note string
		if note, err = revokeCommand(args[1], args[2]); err == nil {
			printJSON(w, struct {
				OK      bool   `json:"ok"`
				Revoked string `json:"revoked"`
				Note    string `json:"note,omitempty"`
			}{true, args[2], note})
		}
	case len(args) == 2 && args[0] == "rotate-all":
		err = rotateAll(args[1], w)
	case len(args) == 3 && args[0] == "schedule":
		err = schedule(args[1], args[2], w)
	case len(args) == 3 && args[0] == "rescue" && args[1] == "scan":
		err = rescueScan(args[2], w)
	case len(args) >= 3 && args[0] == "rescue" && args[1] == "rotate":
		err = rescueRotate(args[2], kvArgs(args[3:]), w)
	case len(args) == 4 && args[0] == "browser" && args[1] == "login":
		err = browserLogin(args[2], args[3])
	default:
		fmt.Fprint(w, usage)
		return 2
	}
	if errors.Is(err, errReported) {
		return 1
	}
	if err != nil {
		printFail(w, err)
		return 1
	}
	return 0
}

func kvArgs(args []string) map[string]string {
	m := map[string]string{}
	for _, a := range args {
		if k, v, ok := strings.Cut(a, "="); ok {
			m[k] = v
		}
	}
	return m
}

// --- output: everything printed goes through scrub ------------------------------------------

func printJSON(w io.Writer, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintln(w, scrub(string(b)))
}

func failJSON(err error) string {
	b, _ := json.Marshal(struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}{false, scrub(err.Error())})
	return string(b)
}

func printFail(w io.Writer, err error) {
	fmt.Fprintln(w, failJSON(err))
}

// --- JSON helpers: recipes and API responses are loosely typed ------------------------------

func decode(b []byte) any {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber() // keeps numeric key IDs exact
	var v any
	if d.Decode(&v) != nil {
		return nil
	}
	return v
}

func readJSONFile(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, ok := decode(b).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", path)
	}
	return m, nil
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func asList(v any) []any         { l, _ := v.([]any); return l }

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		return t.String() != "0"
	}
	return true
}
