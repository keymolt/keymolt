package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

// Every secret value seen this run. scrub replaces them in anything we print.
var (
	secretsMu sync.Mutex
	secrets   = map[string]bool{}
)

func addSecret(s string) {
	if s != "" {
		secretsMu.Lock()
		secrets[s] = true
		secretsMu.Unlock()
	}
}

func scrub(text string) string {
	secretsMu.Lock()
	list := make([]string, 0, len(secrets))
	for s := range secrets {
		list = append(list, s)
	}
	secretsMu.Unlock()
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) }) // longest first, so no partial leftovers
	for _, s := range list {
		text = strings.ReplaceAll(text, s, "[redacted]")
	}
	return text
}

// --- credential store -----------------------------------------------------------------------

const vaultService = "keymolt"

type storedCred struct {
	Value string   `json:"value"`
	Hosts []string `json:"hosts"`
}

func credSet(name, value string, hosts []string) error {
	b, _ := json.Marshal(storedCred{value, hosts})
	return keyring.Set(vaultService, name, string(b))
}

// normalizeHost accepts "api.openai.com" or "https://api.openai.com" and returns the bare host name,
// because the host lock compares bare host names. A host with a path is a mistake, so reject it.
func normalizeHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", errors.New("empty host")
	}
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("bad host %q", h)
		}
		if u.Path != "" && u.Path != "/" {
			return "", fmt.Errorf("host %q must be a host name, not a URL with a path", h)
		}
		return u.Hostname(), nil
	}
	if strings.ContainsAny(h, "/?") {
		return "", fmt.Errorf("host %q must be a host name, not a path", h)
	}
	return h, nil
}

func credSetPrompt(name string, hosts []string, w io.Writer) error {
	clean := make([]string, len(hosts))
	for i, h := range hosts {
		n, err := normalizeHost(h)
		if err != nil {
			return err
		}
		clean[i] = n
	}
	fmt.Fprintf(os.Stderr, "Value for %s (hidden): ", name)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("could not read a hidden value: run this in a terminal")
	}
	if err := credSet(name, strings.TrimSpace(string(b)), clean); err != nil {
		return fmt.Errorf("vault write failed: %v", err)
	}
	fmt.Fprintf(w, "saved %s, locked to %s\n", name, strings.Join(clean, ", "))
	return nil
}

// --- recipe approval --------------------------------------------------------------------------
// A recipe says where keys go. A prompt-injected agent could add an exfiltration destination.
// So a human approves a recipe once, by its exact bytes. Editing the file revokes approval.

// lfSum hashes a file with CRLF read as LF, so git's line-ending conversion on Windows doesn't revoke approval.
// JSON can't hold a raw CR inside a string, so two files that differ only in line endings parse to the same recipe.
func lfSum(b []byte) [32]byte {
	return sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
}

// readRecipe reads a recipe and each browser flow it uses, once, and checks its steps. It returns the recipe, with
// each flow attached to its step, and the hash approval covers: the recipe file's SHA-256, or with flows, the
// SHA-256 of the recipe's and each flow's SHA-256. Runs use what it returns, so they run the bytes that were approved.
func readRecipe(path string) (map[string]any, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	recipe, ok := decode(b).(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("%s is not a JSON object", path)
	}
	sum := lfSum(b)
	h, flows := sha256.New(), 0
	h.Write(sum[:])
	eachStep(recipe, func(_ string, step map[string]any) {
		if step["browser"] == nil || err != nil {
			return
		}
		var fb []byte
		if fb, err = os.ReadFile(flowPath(step, filepath.Dir(path))); err != nil {
			return
		}
		fsum := lfSum(fb)
		h.Write(fsum[:])
		flows++
		flow, ok := decode(fb).(map[string]any)
		if !ok {
			err = fmt.Errorf("%s is not a JSON object", str(step["browser"]))
			return
		}
		step[loadedFlow] = flow
	})
	if err == nil {
		err = checkSteps(recipe)
	}
	if err != nil {
		return nil, "", err
	}
	if flows == 0 { // the plain file hash, so `sha256sum recipe.json` gives it too for a file with LF line endings
		return recipe, hex.EncodeToString(sum[:]), nil
	}
	return recipe, hex.EncodeToString(h.Sum(nil)), nil
}

// visible shows recipe text as plain ASCII. A terminal would act on characters such as \r or a text-direction mark,
// so a recipe could draw a fake destination over the real one, and a lookalike letter, such as a Cyrillic а in a
// host name, would pass for the real one. Both show as escapes, such as \r and \u0430.
func visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r <= unicode.MaxASCII && unicode.IsGraphic(r) {
			b.WriteRune(r)
		} else {
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		}
	}
	return b.String()
}

// childEnv is the environment for commands and the browser: keymolt's own, minus the credentials CI passes in
// KEYMOLT_CRED_*, which would otherwise reach every program a recipe runs, on any host.
func childEnv() []string {
	return slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(strings.ToUpper(kv), "KEYMOLT_CRED_") })
}

// approveAll lets tests run the recipes they build. Only test code can set it.
var approveAll bool

// approved reports whether a human approved this recipe hash, in the vault or, for CI where there is no vault,
// in KEYMOLT_APPROVED (comma-separated hashes). There is no switch that approves everything.
func approved(h string) bool {
	if approveAll || slices.ContainsFunc(strings.Split(os.Getenv("KEYMOLT_APPROVED"), ","),
		func(s string) bool { return strings.TrimSpace(s) == h }) {
		return true
	}
	_, err := keyring.Get(vaultService, "approval:"+h)
	return err == nil
}

// loadApproved reads a recipe for a run, and refuses it unless a human approved these exact bytes.
func loadApproved(path string) (map[string]any, error) {
	recipe, h, err := readRecipe(path)
	if err != nil {
		return nil, err
	}
	if !approved(h) {
		return nil, fmt.Errorf("recipe not approved: run `keymolt approve %s` in a terminal first", path)
	}
	return recipe, nil
}

// atTerminal reports whether a person is likely at the keyboard: an agent's shell has no terminal on stdin.
// Tests replace it, and stdin.
var (
	atTerminal           = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	stdin      io.Reader = os.Stdin
)

// approveCommand shows where each new or changed recipe sends keys, then approves them all if the person says yes.
// target is a recipe, or a folder: then every recipe rotate-all would run.
func approveCommand(target string, w io.Writer) error {
	if !atTerminal() {
		return errors.New("run `keymolt approve` in a real terminal: it confirms you trust where these recipes send keys")
	}
	paths := []string{target}
	if st, err := os.Stat(target); err == nil && st.IsDir() {
		paths = nil
		for _, group := range findRecipes(target) {
			paths = append(paths, group...)
		}
	}
	var hashes []string
	for _, p := range paths {
		recipe, h, err := readRecipe(p)
		if err != nil {
			if len(paths) == 1 {
				return err
			}
			fmt.Fprintf(w, "skipping %s\n", visible(fmt.Sprintf("%s: %v", p, err))) // one broken recipe shouldn't block the others
			continue
		}
		if approved(h) {
			if len(paths) == 1 { // CI needs the hash in KEYMOLT_APPROVED
				fmt.Fprintf(w, "%s is already approved (sha256 %s)\n", visible(p), h)
			}
			continue
		}
		fmt.Fprintf(w, "%s (sha256 %s) sends keys to:\n", visible(p), h)
		for _, d := range recipeDestinations(recipe) {
			fmt.Fprintf(w, "  %s\n", visible(d))
		}
		hashes = append(hashes, h)
	}
	if len(hashes) == 0 {
		if len(paths) > 1 {
			fmt.Fprintln(w, "nothing to approve: every recipe here is already approved")
		}
		return nil
	}
	fmt.Fprintf(w, "Approve %d recipe(s)? [y/N] ", len(hashes))
	answer, _ := bufio.NewReader(stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		return errors.New("not approved")
	}
	for _, h := range hashes {
		if err := keyring.Set(vaultService, "approval:"+h, "1"); err != nil {
			return fmt.Errorf("could not save approval: %v", err)
		}
	}
	fmt.Fprintf(w, "approved %d recipe(s). keymolt runs each one until its file, or a flow it uses, changes.\n", len(hashes))
	return nil
}

func envName(prefix, name string) string { return prefix + strings.ToUpper(name) }

func credLoad(name string) (storedCred, error) {
	if v := os.Getenv(envName("KEYMOLT_CRED_", name)); v != "" {
		var hosts []string
		for _, h := range strings.Split(os.Getenv(envName("KEYMOLT_HOSTS_", name)), ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
		return storedCred{v, hosts}, nil
	}
	raw, err := keyring.Get(vaultService, name)
	if err != nil {
		return storedCred{}, fmt.Errorf("credential %s missing: run `keymolt cred-set %s HOST`", name, name)
	}
	var c storedCred
	if json.Unmarshal([]byte(raw), &c) != nil {
		return c, fmt.Errorf("credential %s is unreadable: run `keymolt cred-set %s HOST` again", name, name)
	}
	return c, nil
}

// credGet returns the credential's value, only if host is one of the hosts it was locked to.
// host "" means "not a request to a host", such as a command line, and always fails.
func credGet(name, host string) (string, error) {
	c, err := credLoad(name)
	if err != nil {
		return "", err
	}
	addSecret(c.Value)
	if host == "" || !slices.Contains(c.Hosts, host) { // a bad recipe or template could otherwise send an admin key anywhere
		return "", fmt.Errorf("credential %s may only go to %s", name, httpsList(c.Hosts))
	}
	return c.Value, nil
}

func httpsList(hosts []string) string {
	if len(hosts) == 0 {
		return "(no hosts set)"
	}
	return "https://" + strings.Join(hosts, " or https://")
}

// vaultReplace is the store step for admin keys: the new key replaces credential name and keeps its host lock.
// err means it stopped before writing anything.
func vaultReplace(name, value string) (bool, string, error) {
	if os.Getenv(envName("KEYMOLT_CRED_", name)) != "" {
		return false, "", errors.New("vault: credential comes from an env var; store it with a cmd step such as gh secret set")
	}
	c, err := credLoad(name)
	if err != nil {
		return false, "", errors.New("vault: no credential " + name)
	}
	if err := credSet(name, value, c.Hosts); err != nil {
		return false, "vault: write failed", nil
	}
	// read back before anything revokes the old key: a bad write here would lock the user out
	back, err := credLoad(name)
	return err == nil && back.Value == value, "vault", nil
}

// destHost is the host a credential would go to. "" for plain http, so credentials never travel unencrypted.
func destHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := u.Hostname()
	if u.Scheme == "https" || h == "127.0.0.1" || h == "localhost" {
		return h
	}
	return ""
}
