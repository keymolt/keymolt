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
2. Two steps belong to the user: `keymolt cred-set` and `keymolt approve`. Both
   need a real terminal, so they fail from your shell. Give the user the exact
   command to run in their own terminal, then wait until they say it's done.
3. Don't work around approval or the host lock. Don't set `KEYMOLT_APPROVED`
   or `KEYMOLT_CRED_*` yourself. A change to an approved recipe removes its
   approval, and the user must approve it again.
4. Ask the user before you delete a key that keymolt didn't make, with `link`
   or `revoke`. Other apps may still use it.
5. Tell the user what the receipt says. If `revoke_by_hand` or `revoke_failed`
   is set, explain it in plain words.

## Check the install

Run `keymolt` with no arguments. It prints its commands. If the command is
missing, ask the user to install it from
https://github.com/keymolt/keymolt/releases/latest, or with
`go install github.com/keymolt/keymolt@latest`.

## Choose the command

| Situation | What to run |
|---|---|
| The destination has no key yet | `keymolt create RECIPE` |
| keymolt made the key in use | `keymolt rotate RECIPE` |
| A key made by hand is in use | `keymolt find RECIPE` prints its id. Then ask the user which they want: replace it (`keymolt link RECIPE ID`, then `keymolt rotate RECIPE`), or delete it now (`keymolt revoke RECIPE ID`). |
| A key may be leaked | If keymolt made it, `keymolt rotate RECIPE`. If it was made by hand, `find`, then `link`, then `rotate`. That stores a new key, then deletes the leaked one. If the rotation fails, ask the user whether to `revoke` the leaked key anyway, even though apps that use it will stop working. |
| Every recipe in a folder | `keymolt rotate-all FOLDER` |
| Rotate on a schedule | Ask first, because this adds a task to the OS scheduler. Then run `keymolt schedule FOLDER monthly`. |

Run `find` before `rotate`. After a rotation, the destination holds the new
key, and `find` names that one.

## Write a recipe

A recipe is a JSON file with `create`, `store`, and optional `verify`, `revoke`,
`current` and `find` steps. Start from an example in the repo, such as
https://github.com/keymolt/keymolt/blob/main/openai-to-convex.example.json. The
README section "Writing a recipe" lists every field.

- Put recipes in a `keymolt/` folder in the project. Add
  `.keymolt-state.json`, `.keymolt.lock` and `keymolt.log` to `.gitignore`.
  Recipes hold no secrets, so they can be committed.
- Name the exact target in every command, such as
  `--deployment TEAM:PROJECT:prod` for Convex. Ask the user for team, project
  and deployment names that you can't find in the project.
- Use credentials only as `{{cred:NAME}}`. If the credential doesn't exist yet,
  ask the user to run `keymolt cred-set NAME HOST`, where HOST is the API host,
  such as `api.openai.com`.
- When the recipe is ready, ask the user to run `keymolt approve RECIPE` and to
  check the list of destinations it prints.

## Read the receipt

Every command prints one JSON line. On success, `ok` is `true`. On failure, the
output is `{"ok":false,"error":"..."}` and the exit code is 1.

| Field | Meaning |
|---|---|
| `new_id`, `length`, `sha256` | The new key's id, length and hash prefix |
| `stored` | The `store` steps that now hold the new key |
| `revoked` | Old keys that keymolt deleted |
| `revoke_failed` | Old keys that are still live. The next `rotate` tries again. |
| `revoke_by_hand` | A key keymolt can't delete for you. Tell the user. |
| `found` | The id of a key made by hand that the destination held before. It is still live. |

| Error starts with | What to do |
|---|---|
| `recipe not approved` | Ask the user to run `keymolt approve RECIPE` |
| `credential NAME missing` | Ask the user to run `keymolt cred-set NAME HOST` |
| `the destination already holds a key` | Use `find`, then the "made by hand" row above |
| `keymolt already made a key for this recipe` | Use `rotate` instead of `create` |
| `another keymolt run is using this folder` | Wait for the other run. If none is running, tell the user the lock file's path. |
