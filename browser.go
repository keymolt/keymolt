package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Browser flows rotate keys on providers that only have a web dashboard.
// Flow file: {"profile": NAME, "id": ..., "timeout": seconds, "steps": [...]}.
// Steps: {"goto": url}, {"click": selector}, {"fill": selector, "value": text}, {"capture": regex}.
// Selectors starting with "/" or "(" are XPath, the rest CSS. After "capture", new strings matching the regex
// in page text, input values, network responses or downloads are the key.
// Fill values may use {{cred:NAME}} and {{totp:NAME}}; these only fill when the page is on one of NAME's hosts.

// shortcut: reads document.body text and input values only, misses iframes and shadow DOM; extend if a site needs it
const domText = `document.body.innerText + '\n' + [...document.querySelectorAll('input,textarea')].map(e => e.value).join('\n')`

// only visible dialogs: innerText of a hidden one, such as a closed modal kept in the page, still returns its text
const dialogText = `[...document.querySelectorAll('[role=dialog],[role=alertdialog],dialog[open]')]
	.filter(e => e.checkVisibility()).map(e => e.innerText.trim()).filter(Boolean).join(' | ')`

var totpRe = regexp.MustCompile(`\{\{totp:(\w+)\}\}`)

func totp(secret string, t time.Time) (string, error) {
	s := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New("TOTP secret is not base32")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	h := hmac.New(sha1.New, key)
	h.Write(msg[:])
	sum := h.Sum(nil)
	o := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[o:o+4])&0x7fffffff)%1000000), nil
}

func profileDir(profile string) string {
	if filepath.IsAbs(profile) {
		return profile
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".keymolt", "profiles", profile)
}

var errNoBrowser = errors.New("browser flows need a Chromium-based browser (Chrome, Edge, Brave or Chromium): " +
	"install one, or set KEYMOLT_BROWSER to its path")

// browserPath picks the browser: KEYMOLT_BROWSER, else the first match in chromedp's own search order, else a
// Chromium-based browser that chromedp doesn't look for. "" means none was found.
func browserPath(goos string, lookPath func(string) (string, error)) string {
	if p := os.Getenv("KEYMOLT_BROWSER"); p != "" {
		return p
	}
	var paths []string
	switch goos {
	case "darwin":
		paths = []string{"/Applications/Chromium.app/Contents/MacOS/Chromium", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"}
	case "windows":
		local := filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
		paths = []string{"chrome", "chrome.exe", `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`, filepath.Join(local, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(local, `Chromium\Application\chrome.exe`), "msedge", "msedge.exe",
			`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, `C:\Program Files\Microsoft\Edge\Application\msedge.exe`}
	default:
		paths = []string{"headless_shell", "headless-shell", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
			"google-chrome-beta", "google-chrome-unstable", "/usr/bin/google-chrome", "/usr/local/bin/chrome", "/snap/bin/chromium", "chrome",
			"microsoft-edge", "microsoft-edge-stable", "brave-browser"}
	}
	for _, p := range paths {
		if found, err := lookPath(p); err == nil {
			return found
		}
	}
	return ""
}

func newBrowser(profile string) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.UserDataDir(profileDir(profile)),
		chromedp.NoInheritEnv, chromedp.Env(childEnv()...))
	if p := browserPath(runtime.GOOS, exec.LookPath); p != "" {
		opts = append(opts, chromedp.ExecPath(p))
	}
	actx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancelCtx := chromedp.NewContext(actx)
	return ctx, func() { cancelCtx(); cancelAlloc() }
}

// Selectors starting with "/" or "(" are XPath, found through DOM search. The rest are CSS.
func isXPath(sel string) bool { return strings.HasPrefix(sel, "/") || strings.HasPrefix(sel, "(") }

func clickAction(sel string) chromedp.Action[chromedp.Void] {
	if isXPath(sel) {
		return chromedp.Click(chromedp.Search(sel))
	}
	return chromedp.Click(chromedp.CSS(sel))
}

func fillAction(sel, value string) chromedp.Action[chromedp.Void] {
	if isXPath(sel) {
		return chromedp.Steps(chromedp.Clear(chromedp.Search(sel)), chromedp.SendKeys(chromedp.Search(sel), value))
	}
	return chromedp.Steps(chromedp.Clear(chromedp.CSS(sel)), chromedp.SendKeys(chromedp.CSS(sel), value))
}

// sweepDownloads removes download folders that killed runs left behind: they may hold a downloaded key.
// An hour is far longer than any flow runs, so a folder another run still uses is never removed.
func sweepDownloads() {
	dirs, _ := filepath.Glob(filepath.Join(os.TempDir(), "keymolt-dl-*"))
	for _, d := range dirs {
		if st, err := os.Stat(d); err == nil && time.Since(st.ModTime()) > time.Hour {
			_ = os.RemoveAll(d)
		}
	}
}

// runFlow runs a browser flow and returns {"id": ..., "value": key} as JSON, or {} when the flow has no capture.
func runFlow(flow map[string]any, vars map[string]string) ([]byte, error) {
	profile, err := renderString(str(flow["profile"]), vars, "")
	if err != nil {
		return nil, err
	}
	id, err := renderString(str(flow["id"]), vars, "")
	if err != nil {
		return nil, err
	}
	timeout := 20 * time.Second
	if t, err := json.Number(str(flow["timeout"])).Float64(); err == nil && t > 0 {
		timeout = time.Duration(t * float64(time.Second))
	}
	sweepDownloads()
	downloads, err := os.MkdirTemp("", "keymolt-dl-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(downloads)

	ctx, cancel := newBrowser(profile)
	defer cancel()
	if err := chromedp.Do(ctx); err != nil {
		return nil, errNoBrowser
	}
	// the event readers only record request IDs: response bodies are read later by the main loop
	var mu sync.Mutex
	armed, inflight, finished := false, map[network.RequestID]bool{}, []network.RequestID{}
	sent := chromedp.Events(ctx, network.RequestWillBeSent)
	loaded := chromedp.Events(ctx, network.LoadingFinished)
	failed := chromedp.Events(ctx, network.LoadingFailed)
	go func() {
		for e, err := range sent {
			if err != nil {
				return
			}
			mu.Lock()
			inflight[e.RequestID] = true
			mu.Unlock()
		}
	}()
	go func() {
		for e, err := range loaded {
			if err != nil {
				return
			}
			mu.Lock()
			delete(inflight, e.RequestID)
			if armed {
				finished = append(finished, e.RequestID)
			}
			mu.Unlock()
		}
	}()
	go func() {
		for e, err := range failed {
			if err != nil {
				return
			}
			mu.Lock()
			delete(inflight, e.RequestID)
			mu.Unlock()
		}
	}()
	if _, err := chromedp.Call(ctx, network.Enable, network.EnableParams{}); err != nil {
		return nil, errNoBrowser
	}
	_, _ = chromedp.CallBrowser(ctx, browser.SetDownloadBehavior,
		browser.SetDownloadBehaviorParams{Behavior: browser.SetDownloadBehaviorBehaviorAllow, DownloadPath: downloads})
	pageText := func() string {
		s, _ := chromedp.Run(ctx, chromedp.Evaluate[string](domText))
		return s
	}

	var pattern *regexp.Regexp
	before := map[string]bool{}
	for i, raw := range asList(flow["steps"]) {
		var host string
		if asMap(raw)["fill"] != nil {
			loc, _ := chromedp.Run(ctx, chromedp.Location())
			host = destHost(loc) // credentials only fill on the site they are locked to, so a lookalike page gets nothing
		}
		r, err := render(raw, vars, host)
		if err != nil {
			return nil, err
		}
		step := asMap(r)
		stepCtx, stepCancel := context.WithTimeout(ctx, 30*time.Second)
		switch {
		case step["goto"] != nil:
			if u := str(step["goto"]); destHost(u) == "" && scrub(u) != u { // a key in a URL goes over https or to localhost only
				stepCancel()
				return nil, errors.New("refusing to open a URL with a key in it that isn't https")
			}
			err = chromedp.Do(stepCtx, chromedp.Navigate(str(step["goto"])))
		case step["click"] != nil:
			err = chromedp.Do(stepCtx, clickAction(str(step["click"])))
		case step["fill"] != nil:
			var credErr error
			value := totpRe.ReplaceAllStringFunc(str(step["value"]), func(m string) string {
				secret, err := credGet(totpRe.FindStringSubmatch(m)[1], host)
				code := ""
				if err == nil {
					code, err = totp(secret, time.Now())
				}
				credErr = errors.Join(credErr, err)
				return code
			})
			if credErr != nil {
				stepCancel()
				return nil, credErr
			}
			if host == "" && scrub(value) != value { // the new key, too, only goes to https pages or localhost
				stepCancel()
				return nil, errors.New("refusing to type a key into a page that isn't https")
			}
			err = chromedp.Do(stepCtx, fillAction(str(step["fill"]), value))
		case step["capture"] != nil:
			if pattern, err = regexp.Compile(str(step["capture"])); err == nil {
				for _, m := range pattern.FindAllString(pageText(), -1) {
					before[m] = true // keys shown before Create are not the new key
				}
				mu.Lock()
				armed = true
				mu.Unlock()
			}
		}
		stepCancel()
		if err != nil { // step number only: browser errors can quote page text, including the key
			return nil, fmt.Errorf("step %d failed", i)
		}
	}

	value, bodies, deadline := "", map[network.RequestID]string{}, time.Now().Add(timeout)
	for pattern != nil && value == "" && time.Now().Before(deadline) {
		texts := []string{pageText()}
		mu.Lock()
		ids := slices.Clone(finished)
		mu.Unlock()
		for _, rid := range ids {
			if _, seen := bodies[rid]; !seen {
				res, _ := chromedp.Call(ctx, network.GetResponseBody, network.GetResponseBodyParams{RequestID: rid})
				bodies[rid] = string(res.Body) // redirects and closed responses have no body
			}
			texts = append(texts, bodies[rid])
		}
		files, _ := os.ReadDir(downloads)
		for _, f := range files {
			b, _ := os.ReadFile(filepath.Join(downloads, f.Name()))
			texts = append(texts, string(b))
		}
	search:
		for _, t := range texts {
			for _, m := range pattern.FindAllString(t, -1) {
				if !before[m] {
					value = m
					break search
				}
			}
		}
		if value == "" {
			time.Sleep(250 * time.Millisecond)
		}
	}
	// let a final click's request finish before closing: wait for 500ms with no requests in flight
	for quiet, stop := 0, time.Now().Add(10*time.Second); quiet < 5 && time.Now().Before(stop); {
		mu.Lock()
		idle := len(inflight) == 0
		mu.Unlock()
		if idle {
			quiet++
		} else {
			quiet = 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	where := ""
	if pattern != nil && value == "" { // an open dialog often says why no key came, such as a site asking to sign in again
		loc, _ := chromedp.Run(ctx, chromedp.Location())
		dialogs, _ := chromedp.Run(ctx, chromedp.Evaluate[string](dialogText))
		if l := hint(pattern.ReplaceAllString(loc, "[cut]")); l != "" { // empty when the browser is gone
			where = "; the page was " + l
		}
		if d := hint(pattern.ReplaceAllString(dialogs, "[cut]")); d != "" {
			where += "; it showed: " + d
		}
	}
	_ = chromedp.Cancel(ctx) // closes Chrome cleanly so the profile keeps its login
	if pattern == nil {
		return []byte("{}"), nil
	}
	if value == "" {
		return nil, errors.New("no new key matched the capture regex" + where)
	}
	addSecret(value)
	return json.Marshal(map[string]string{"id": id, "value": value})
}

// browserLogin opens a visible browser so the user can sign in by hand once. It returns when the browser closes.
func browserLogin(profile, url string) error {
	p := browserPath(runtime.GOOS, exec.LookPath)
	if p == "" {
		return errNoBrowser
	}
	cmd := loginCmd(p, profile, url)
	if err := cmd.Start(); err != nil {
		return errNoBrowser
	}
	start := time.Now()
	_ = cmd.Wait() // the exit code of a browser the user closed says nothing about the login
	// a browser already open on this profile takes the URL and this one exits at once; so does one that crashes
	if time.Since(start) < 3*time.Second {
		return errors.New("the browser closed right away; if a keymolt browser for this profile is open, close it and run login again")
	}
	return nil
}

// loginCmd starts the browser as a plain process, not through chromedp: Google and other sign-in pages refuse a
// browser in automation mode or with a debugging port. Its cookie-encryption flags match the ones flows run with,
// or the flows couldn't read the saved session.
func loginCmd(browser, profile, url string) *exec.Cmd {
	cmd := exec.Command(browser, "--user-data-dir="+profileDir(profile), "--no-first-run", "--no-default-browser-check",
		"--password-store=basic", "--use-mock-keychain", url)
	cmd.Env = childEnv()
	return cmd
}
