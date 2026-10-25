---
name: keymolt
description: Create, rotate, find and revoke API keys with the keymolt CLI, so the key value never enters your context. Use when a task needs an API key made, set in a deployment (Convex, Railway, GitHub secrets and others), rotated, replaced or deleted, or when a key may be leaked.
---

# keymolt

keymolt makes API keys and stores them where they are used. You run it and read
its JSON receipt. The receipt holds a key id, a length and a SHA-256 prefix. It
never holds the key.

## Rules

1. Never read, print or ask for a key value. Don't ask the user to paste a key
   into the chat. Don't run commands that print one, such as
   `npx convex env get`, `railway variables`, `printenv` or `cat .env`. If a
   task seems to need the value, use keymolt instead.
2. Some steps belong to the user: `keymolt cred-set`, `keymolt approve`,
   `keymolt link`, and `keymolt revoke` for a key keymolt doesn't track. They
   need a real terminal, so they fail from your shell. Give the user the exact
   command to run in their own terminal, then wait until they say it's done.
3. Don't work around approval or the host lock. Don't set `KEYMOLT_APPROVED`
   or `KEYMOLT_CRED_*` yourself. A change to an approved recipe removes its
   approval, and the user must approve it again.
4. Before the user deletes a key that keymolt didn't make, tell them that
   other apps may still use it.
5. Tell the user what the receipt says. If `revoke_by_hand` or `revoke_failed`
   is set, explain it in plain words.

## Check the install

Run `keymolt` with no arguments. It prints its commands. If the command is
missing, ask the user before you install it. This skill's folder has an install
script that downloads the matching release and checks its SHA-256:

| System | Command | Installs to |
|---|---|---|
| macOS, Linux | `sh install.sh` | `~/.local/bin/keymolt` |
| Windows | `powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1` | `%LOCALAPPDATA%\keymolt\keymolt.exe` |

Your shell keeps its old PATH, so call keymolt by the full path above until the
user opens a new terminal. If the script says another keymolt comes first on
the PATH, tell the user which one runs.

## Choose the command

| Situation | What to run |
|---|---|
| The destination has no key yet | `keymolt create RECIPE` |
| keymolt made the key in use | `keymolt rotate RECIPE` |
| A key made by hand is in use | `keymolt find RECIPE` prints its id. Then ask the user to run one of these in their terminal: `keymolt link RECIPE ID`, so your next `keymolt rotate RECIPE` replaces the key and deletes it, or `keymolt revoke RECIPE ID` to delete it now. |
| A key may be leaked | If keymolt made it, `keymolt rotate RECIPE`. If it was made by hand, run `find`, ask the user to run `link`, then run `rotate`. That stores a new key, then deletes the leaked one. If the rotation fails, the user can `revoke` the leaked key anyway, but apps that use it stop working. |
| Every recipe in a folder, and in each `.keymolt` folder below it | `keymolt rotate-all FOLDER`. For example, `keymolt rotate-all C:\P` rotates every project that keeps its recipes in a `.keymolt/` folder. |
| Rotate on a schedule | Ask first, because this adds a task to the OS scheduler. Then run `keymolt schedule FOLDER monthly`. |

For a key made by hand, run `find` before `rotate`: after a rotation, the
destination holds the new key, and `find` names that one. `find` needs a recipe
with `current` and `find` steps, and most examples have neither.

## Write a recipe

A recipe is a JSON file with `create`, `store`, and optional `verify`, `revoke`,
`current` and `find` steps. Start from an example in the repo, such as
https://github.com/keymolt/keymolt/blob/main/openai-to-convex.example.json. The
README section "Writing a recipe" lists every field.

- Put recipes in a `.keymolt/` folder in the project. Some search tools skip
  hidden folders, so look there by name. Add `.keymolt-state.json`,
  `.keymolt.lock` and `keymolt.log` to `.gitignore`. Recipes hold no secrets,
  so they can be committed.
- Name the exact target in every command, such as
  `--deployment TEAM:PROJECT:prod` for Convex. Ask the user for team, project
  and deployment names that you can't find in the project.
- In `cmd` steps, call a published tool, such as `npx convex`. Don't write a
  script for a `cmd` step to run: approval covers the command line, not the
  script's contents. The new key reaches the command on stdin; `{{new}}` on a
  command line is refused. A `url` step sends `{{new}}` only over https.
- Give each step exactly one of `url`, `cmd`, `browser` or `vault`.
- Use credentials only as `{{cred:NAME}}`. If the credential doesn't exist yet,
  ask the user to run `keymolt cred-set NAME HOST`, where HOST is the API host,
  such as `api.openai.com`.
- When the recipe is ready, ask the user to run `keymolt approve RECIPE`, check
  the list of destinations it prints, and answer `y`. For many recipes,
  `keymolt approve FOLDER` lists every new or changed recipe and asks once.

## Read the receipt

`create`, `rotate`, `find`, `link`, `revoke`, `rotate-all` and `schedule` print
one JSON line. On success, `ok` is `true`. On failure, the output is
`{"ok":false,"error":"..."}` and the exit code is 1. The commands for the user,
`cred-set`, `approve` and `browser login`, print plain text.

| Field | Meaning |
|---|---|
| `new_id`, `length`, `sha256` | The new key's id, length and hash prefix |
| `stored` | The `store` steps that now hold the new key |
| `revoked` | Old keys that keymolt deleted |
| `revoke_failed` | Old keys that are still live. The next `rotate` tries again. With `keep_previous`, the key kept on purpose is listed here too. |
| `revoke_by_hand` | A key keymolt can't delete for you. Tell the user. |
| `found` | The id of a key made by hand that the destination held before. It is still live. |

| Error starts with | What to do |
|---|---|
| `recipe not approved` | Ask the user to run `keymolt approve RECIPE` |
| `credential NAME missing` | Ask the user to run `keymolt cred-set NAME HOST` |
| `run ... in a real terminal`, or `keymolt doesn't track key` | Ask the user to run the quoted command in their own terminal |
| `the destination already holds a key` | Use `find`, then the "made by hand" row above |
| `keymolt already made a key for this recipe` | Use `rotate` instead of `create` |
| `store #N failed ...` ending in `both live, rerun` | A destination may hold the new key, so both keys stay live. Fix the cause, then run `rotate` again. |
| `new key ... could not be revoked` | keymolt still tracks it, and the next `rotate` revokes it |
| `the last rotation's store failed, so key ... may be live and unused` | `rotate-all` stops for this recipe. Find out why the store failed, such as an expired login, and tell the user. After the fix, run `keymolt rotate RECIPE`. |
| `another keymolt run is using this folder` | Wait for the other run. If none is running, tell the user the lock file's path. |
