package main

import (
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
	"strings"
	"sync"

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

// recipeHash is the SHA-256 of the recipe file. With browser flows, it also covers each flow file, since a flow
// decides which pages see the new key.
func recipeHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	var flows [][32]byte
	recipe, _ := decode(b).(map[string]any)
	eachStep(recipe, func(_ string, step map[string]any) {
		if step["browser"] != nil && err == nil {
			var fb []byte
			fb, err = os.ReadFile(flowPath(step, filepath.Dir(path)))
			flows = append(flows, sha256.Sum256(fb))
		}
	})
	if err != nil {
		return "", err
	}
	if len(flows) == 0 { // the plain file hash, so `sha256sum recipe.json` gives it too
		return hex.EncodeToString(sum[:]), nil
	}
	h := sha256.New()
	h.Write(sum[:])
	for _, f := range flows {
		h.Write(f[:])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func approveRecipeFile(path string) error {
	h, err := recipeHash(path)
	if err != nil {
		return err
	}
	return keyring.Set(vaultService, "approval:"+h, "1")
}

// approveAll lets tests run the recipes they build. Only test code can set it.
var approveAll bool

// isApproved reports whether this exact recipe file was approved, in the vault or, for CI where there is no
// vault, in KEYMOLT_APPROVED (comma-separated SHA-256 hashes). There is no switch that approves everything.
func isApproved(path string) bool {
	h, err := recipeHash(path)
	if err != nil {
		return false
	}
	if approveAll || slices.ContainsFunc(strings.Split(os.Getenv("KEYMOLT_APPROVED"), ","),
		func(s string) bool { return strings.TrimSpace(s) == h }) {
		return true
	}
	_, err = keyring.Get(vaultService, "approval:"+h)
	return err == nil
}

// atTerminal reports whether a person is likely at the keyboard: an agent's shell has no terminal on stdin.
// Tests replace it.
var atTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func approveCommand(path string, w io.Writer) error {
	if !atTerminal() {
		return errors.New("run `keymolt approve` in a real terminal: it confirms you trust where this recipe sends keys")
	}
	recipe, err := readJSONFile(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Recipe %s sends keys to:\n", path)
	for _, d := range recipeDestinations(recipe, filepath.Dir(path)) {
		fmt.Fprintf(w, "  %s\n", d)
	}
	if err := approveRecipeFile(path); err != nil {
		return fmt.Errorf("could not save approval: %v", err)
	}
	h, _ := recipeHash(path)
	fmt.Fprintf(w, "approved (sha256 %s). `keymolt rotate` will run this recipe until its file changes.\n", h)
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
func vaultReplace(name, value string) (bool, string) {
	if os.Getenv(envName("KEYMOLT_CRED_", name)) != "" {
		return false, "vault: credential comes from an env var; store it with a cmd step such as gh secret set"
	}
	c, err := credLoad(name)
	if err != nil {
		return false, "vault: no credential " + name
	}
	if err := credSet(name, value, c.Hosts); err != nil {
		return false, "vault: write failed"
	}
	// read back before anything revokes the old key: a bad write here would lock the user out
	back, err := credLoad(name)
	return err == nil && back.Value == value, "vault"
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
