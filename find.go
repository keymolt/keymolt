package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
)

// find, link and revoke are tools for keys keymolt didn't make. keymolt never decides by itself to delete such a
// key: it can't know every place that still uses it.

// keyID is the form an id must have: it goes into URLs and commands, so no paths, queries or flags.
var keyID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)

// findCommand returns the id of the key the recipe's destination holds now.
func findCommand(recipePath string) (string, error) {
	recipe, err := loadApproved(recipePath)
	if err != nil {
		return "", err
	}
	if recipe["find"] == nil {
		return "", errors.New(`recipe has no "find" step`)
	}
	if err := checkFind(recipe); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(recipePath)
	dir := filepath.Dir(abs)
	value, read, err := currentKey(asMap(recipe["current"]), dir)
	switch {
	case err != nil:
		return "", err
	case !read:
		return "", errors.New("could not read the key the destination holds")
	case value == "":
		return "", errors.New("the destination holds no key")
	}
	id, err := findKeyID(asMap(recipe["find"]), value, dir)
	if err == nil && id == "" {
		err = errors.New("the provider lists no key, or more than one, that fits the key the destination holds")
	}
	return id, err
}

// linkCommand makes keymolt track id as the recipe's live key, so the next rotation replaces it, then revokes it.
func linkCommand(recipePath, id string) error {
	if !keyID.MatchString(id) {
		return fmt.Errorf("%q is not a key id", id)
	}
	if !atTerminal() { // a linked key gets deleted on the next rotate, so a person picks it
		return fmt.Errorf("run `keymolt link %s %s` in a real terminal: it confirms nothing else uses this key", recipePath, id)
	}
	if _, err := readJSONFile(recipePath); err != nil {
		return err
	}
	fs, err := openState(recipePath)
	if err != nil {
		return err
	}
	defer fs.unlock()
	e := fs.state[fs.key]
	if e.ID != "" {
		return fmt.Errorf("keymolt already tracks key %s for this recipe", e.ID)
	}
	e.ID, e.Found = id, append(e.Found, id)
	fs.state[fs.key] = e
	return fs.save()
}

// revokeCommand revokes id now, without making a new key. A key keymolt didn't make is revoked with the "find"
// step's own revoke, when the recipe has one. note says what the user still has to do.
func revokeCommand(recipePath, id string) (note string, err error) {
	if !keyID.MatchString(id) {
		return "", fmt.Errorf("%q is not a key id", id)
	}
	recipe, err := loadApproved(recipePath)
	if err != nil {
		return "", err
	}
	fs, err := openState(recipePath)
	if err != nil {
		return "", err
	}
	defer fs.unlock()
	e := fs.state[fs.key]
	tracked := id == e.ID || slices.Contains(e.Stale, id)
	if !tracked && !atTerminal() { // otherwise an agent could delete any key the provider account holds
		return "", fmt.Errorf("keymolt doesn't track key %s: run `keymolt revoke %s %s` in a real terminal", id, recipePath, id)
	}
	made := tracked && !slices.Contains(e.Found, id)
	step := asMap(recipe["revoke"])
	if r := asMap(asMap(recipe["find"])["revoke"]); r != nil && !made {
		step = r
	}
	if step == nil {
		return "", errors.New("recipe has no revoke step")
	}
	ok, _, detail, err := call(step, map[string]string{"old_id": id}, fs.dir)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("revoke failed (%s)", detail)
	}
	if id == e.ID {
		e.ID = ""
		note = fmt.Sprintf("the recipe's destinations still hold this key: run `keymolt rotate %s` to store a new one", recipePath)
	}
	drop := func(s string) bool { return s == id }
	e.Stale, e.Found = slices.DeleteFunc(e.Stale, drop), slices.DeleteFunc(e.Found, drop)
	fs.state[fs.key] = e
	if err := fs.save(); err != nil {
		return "", fmt.Errorf("key %s revoked, but state save failed (%v)", id, err)
	}
	return note, nil
}
