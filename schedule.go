package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// slug turns a folder or variable name into a safe job or recipe name.
func slug(s string) string {
	return strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// schedulePlan returns the files to write and commands to run so the OS scheduler runs rotate-all.
// It is pure so every OS can be tested from any OS. pathEnv is the PATH to give the job: launchd and systemd start
// jobs with a bare one, where tools such as npx from Homebrew or nvm are missing.
func schedulePlan(folder, cadence, goos, exe, home, pathEnv string) (name string, files map[string]string, cmds [][]string) {
	abs, _ := filepath.Abs(folder)
	// from the whole path, so each project's .keymolt folder gets its own job.
	// shortcut: paths that differ only in case or punctuation share a job, add a hash if that ever bites
	name = "keymolt-" + slug(abs)
	argv := []string{exe, "rotate-all", abs}
	weekly := cadence == "weekly"
	switch goos {
	case "windows": // StartWhenAvailable runs a missed rotation when the PC is next on
		q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
		args := `"rotate-all" "` + abs + `"`
		trigger := "-Weekly -DaysOfWeek Sunday -At 3am"
		if !weekly {
			trigger += " -WeeksInterval 4" // Task Scheduler's PowerShell module has no monthly trigger
		}
		ps := fmt.Sprintf("Register-ScheduledTask -Force -TaskName %s -Action (New-ScheduledTaskAction -Execute %s -Argument %s) "+
			"-Trigger (New-ScheduledTaskTrigger %s) -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable)", q(name), q(exe), q(args), trigger)
		return name, nil, [][]string{{"powershell", "-NoProfile", "-Command", ps}}
	case "darwin": // launchd runs a missed rotation when the Mac wakes
		path := filepath.Join(home, "Library", "LaunchAgents", "com."+name+".plist")
		when := "<key>Weekday</key><integer>0</integer>"
		if !weekly {
			when = "<key>Day</key><integer>1</integer>"
		}
		var progArgs, pathXML strings.Builder
		_ = xml.EscapeText(&pathXML, []byte(pathEnv))
		for _, a := range argv {
			progArgs.WriteString("<string>")
			_ = xml.EscapeText(&progArgs, []byte(a))
			progArgs.WriteString("</string>")
		}
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.` + name + `</string>
<key>ProgramArguments</key><array>` + progArgs.String() + `</array>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>` + pathXML.String() + `</string></dict>
<key>StartCalendarInterval</key><dict>` + when + `<key>Hour</key><integer>3</integer><key>Minute</key><integer>0</integer></dict>
</dict></plist>
`
		return name, map[string]string{path: plist}, [][]string{{"launchctl", "unload", path}, {"launchctl", "load", "-w", path}}
	}
	// Linux: a systemd user timer, not cron, because it catches up missed runs and can reach the desktop keyring
	unit := filepath.Join(home, ".config", "systemd", "user", name)
	quote := func(a string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(a) + `"` // % starts a systemd specifier
	}
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = quote(a)
	}
	calendar := "Sun *-*-* 03:00"
	if !weekly {
		calendar = "*-*-01 03:00"
	}
	files = map[string]string{
		unit + ".service": "[Service]\nType=oneshot\nEnvironment=" + quote("PATH="+pathEnv) + "\nExecStart=" + strings.Join(quoted, " ") + "\n",
		unit + ".timer":   "[Timer]\nOnCalendar=" + calendar + "\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
	}
	return name, files, [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", name + ".timer"}}
}

func schedule(folder, cadence string, w io.Writer) error {
	if st, err := os.Stat(folder); err != nil || !st.IsDir() || (cadence != "weekly" && cadence != "monthly") {
		return errors.New("usage: keymolt schedule FOLDER weekly|monthly")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	name, files, cmds := schedulePlan(folder, cadence, runtime.GOOS, exe, home, os.Getenv("PATH"))
	for path, text := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			return err
		}
	}
	for _, c := range cmds {
		var stderr bytes.Buffer
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil && c[1] != "unload" { // unload fails harmlessly when the job is new
			return fmt.Errorf("%s failed: %s", c[0], strings.TrimSpace(stderr.String()))
		}
	}
	printJSON(w, map[string]any{"ok": true, "job": name, "cadence": cadence, "os": runtime.GOOS})
	return nil
}
