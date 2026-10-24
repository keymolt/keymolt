# keymolt

Create, store, verify and revoke API keys without ever printing them.

keymolt lets an AI agent (or a cron job) rotate your third-party API keys on a
schedule. The agent triggers the work and reads a receipt — a key id, a length,
a SHA-256 prefix. It never sees the key itself. The secret goes straight from
the provider that made it to the places that need it, over HTTPS, and nowhere
else.

```
$ keymolt rotate openai-to-railway.example.json
{"ok":true,"name":"openai_prod","new_id":"sa_8f2c","length":164,"sha256":"a1b2c3d4e5f6","stored":["railway"],"revoked":["sa_7a1b"],"revoke_failed":[]}
```

## Why

An agent that can rotate keys is useful. An agent that can *read* your keys is a
liability — one prompt injection and the key is in a log, a chat history, or an
attacker's inbox. keymolt splits the two. The agent gets the power to rotate.
The human keeps the power to see secrets and to decide where they may go.

## What it guarantees

- **Secrets never reach the agent.** Not in output, not in logs, not in command
  arguments. Values are redacted from everything printed. Command steps receive
  the key on stdin, never on the command line.
- **A key only goes to hosts you allowed.** Each credential is locked to a list
  of hosts, and only over HTTPS. A recipe that tries to send a key anywhere else
  fails.
- **A recipe can only run after a human approves it.** `approve` prints every
  destination the recipe sends keys to, then records the file's hash. Edit the
  file and approval is gone. `approve` only runs in a real terminal, and
  there is no switch that approves every recipe.
- **A rotation never leaves you without a working key.** keymolt makes the new
  key, tests it, stores it everywhere the old one lived, saves its state, and
  only then deletes the old key. If any step fails, the live key stays live.

### Where the protection ends

keymolt protects secrets from an agent that reaches it only through keymolt's
commands, such as an MCP tool or a fixed command line the agent can't edit. An
agent with a full shell as your OS user can do anything you can. It can read
the OS vault, write approvals into it, and set keymolt's environment variables.
To guard against that agent, run it as a different OS user, or in a sandbox
that has no access to your vault.

## Install

```
go install github.com/keymolt/keymolt@latest
```

Or build from a clone:

```
go build -o keymolt .
```

Credentials live in your OS vault: Keychain on macOS, Credential Manager on
Windows, Secret Service on Linux.

## Quick start

Three steps. The first two are done once, by a human, in a terminal. The third
is what the agent or scheduler runs.

**1. Save the admin credential, locked to its host.**

```
keymolt cred-set openai_admin api.openai.com
```

It prompts for the value with no echo. The value is stored in the vault and may
only ever be sent to `api.openai.com`.

**2. Approve a recipe.**

```
keymolt approve openai-to-railway.example.json
```

It prints where the recipe creates, verifies, stores and revokes keys. Read the
list. If it is correct, confirm, and the exact file is trusted from now on.

**3. Create the first key, then rotate it later.**

```
keymolt create openai-to-railway.example.json
keymolt rotate openai-to-railway.example.json
```

These are the only steps an agent needs to run. `create` makes a key and stores
it, and refuses if keymolt already made a key for this recipe. `rotate` makes a
new key, stores it, and deletes the old one. On a recipe with no key yet,
`rotate` does the same as `create`.

## Writing a recipe

A recipe is a JSON file. It names the credential-making steps and where the new
key goes. The engine has no provider-specific code — any provider and any
destination that speak HTTP or have a CLI will work.

A recipe has these steps:

| Step | Required | What it does |
|------|----------|--------------|
| `create` | yes | Makes the new key. |
| `store` | yes (one or more) | Puts the new key where it is used. |
| `verify` | no | Tests the new key before storing it. |
| `revoke` | no | Deletes the old key. Omit it and keymolt never deletes. |
| `current` | no | Reads the key in use now from the destination. See [Keys made before keymolt](#keys-made-before-keymolt). |
| `find` | no | Finds that key's id at the provider, so the first rotation can delete it. |

Each step is one of four kinds:

- **`url`** — an HTTP request (`method`, `url`, `headers`, `body`). For `create`,
  `value` and `id` are dotted paths into the JSON response.
- **`cmd`** — a command line, as a list. The new key arrives on the command's
  **stdin**, never in the arguments.
- **`browser`** — a saved browser flow, for providers that only make keys in a
  dashboard.
- **`vault`** — saves the new key back into the vault under a name, so an admin
  key can rotate itself.

Strings in a recipe may use these placeholders:

| Placeholder | Becomes |
|-------------|---------|
| `{{cred:NAME}}` | a credential from the vault (checked against its host lock) |
| `{{new}}` | the new key's value |
| `{{new_id}}` | the new key's id |
| `{{old_id}}` | the previous key's id (for `revoke`) |
| `{{ts}}` | a timestamp, handy for naming keys |

### Example: ElevenLabs to Convex

This creates a new ElevenLabs service-account key with a `url` step, tests it,
and stores it on Convex with a `cmd` step. Convex's `env set` reads the value
from stdin, so no wrapper is needed. See
[`elevenlabs-to-convex.example.json`](elevenlabs-to-convex.example.json).

```json
{
  "name": "elevenlabs_prod",
  "create": {
    "method": "POST",
    "url": "https://api.elevenlabs.io/v1/service-accounts/SERVICE_ACCOUNT_USER_ID/api-keys",
    "headers": {"xi-api-key": "{{cred:elevenlabs_admin}}", "Content-Type": "application/json"},
    "body": {"name": "keymolt-{{ts}}", "permissions": ["text_to_speech"]},
    "value": "xi-api-key",
    "id": "key_id"
  },
  "verify": {
    "url": "https://api.elevenlabs.io/v1/user",
    "headers": {"xi-api-key": "{{new}}"}
  },
  "store": [
    {"label": "convex", "cmd": ["npx", "convex", "env", "set", "ELEVENLABS_API_KEY", "--prod", "--force"]}
  ],
  "revoke": {
    "method": "PATCH",
    "url": "https://api.elevenlabs.io/v1/service-accounts/SERVICE_ACCOUNT_USER_ID/api-keys/{{old_id}}",
    "headers": {"xi-api-key": "{{cred:elevenlabs_admin}}", "Content-Type": "application/json"},
    "body": {"is_enabled": false}
  }
}
```

Before it can run, store the admin key and approve the file:

```
keymolt cred-set elevenlabs_admin api.elevenlabs.io
keymolt approve elevenlabs-to-convex.example.json
```

The Convex CLI uses its own auth — the `CONVEX_DEPLOY_KEY` environment variable
or a prior `npx convex login` — because keymolt will not put a credential on a
command line.

### Example: a dashboard with no API (browser flow)

Some providers only let you make keys in a web dashboard. For those, a `create`
or `revoke` step points at a **flow file** that drives a real browser. keymolt
reuses a saved browser profile, so you sign in once by hand and the flow runs
logged in after that.

Sign in once:

```
keymolt browser login acme https://dashboard.acme.com/login
```

This opens a visible browser under the profile `acme`. Log in, then close the
tab. The session is saved.

The recipe ([`browser-dashboard.example.json`](browser-dashboard.example.json))
uses a browser flow for `create` and `revoke`, and still stores the key the
normal way:

```json
{
  "name": "acme_prod",
  "create": {"browser": "acme-create.flow.json", "vars": {"name": "keymolt-{{ts}}"}, "value": "value", "id": "id"},
  "store": [{"label": "convex", "cmd": ["npx", "convex", "env", "set", "ACME_API_KEY", "--prod", "--force"]}],
  "revoke": {"browser": "acme-revoke.flow.json", "vars": {"old_id": "{{old_id}}"}}
}
```

The create flow ([`acme-create.flow.json`](acme-create.flow.json)) navigates,
fills the key's name, arms `capture`, then clicks **Create**. The regex after
`capture` matches the new key when it appears on the page or in a response:

```json
{
  "profile": "acme",
  "id": "{{name}}",
  "timeout": 20,
  "steps": [
    {"goto": "https://dashboard.acme.com/settings/api-keys"},
    {"click": "#new-api-key"},
    {"fill": "#key-name", "value": "{{name}}"},
    {"capture": "sk-[A-Za-z0-9]{32,}"},
    {"click": "#create"}
  ]
}
```

Flow steps are `goto`, `click`, `fill`, and `capture`. A selector that starts
with `/` or `(` is XPath; the rest are CSS. `capture` must come before the click
that reveals the key — it records the keys already on the page first, so only a
new one is taken. `fill` values may use `{{cred:NAME}}` and `{{totp:NAME}}` for
sites that need a login each time; these fill only when the browser is on one of
that credential's hosts, so a lookalike page gets nothing.

The selectors above are placeholders — change them to match your provider's
dashboard.

### Keys made before keymolt

keymolt deletes keys by id, and on its first run it only knows the ids of keys it
made. A key you made by hand would stay live. Two optional steps fix that:

- **`current`** reads the key the destination holds now, such as
  `npx convex env get OPENAI_API_KEY`. keymolt keeps the value in memory and
  never prints it. If the destination is empty, there is nothing to delete.
- **`find`** lists the provider's keys. Providers show each key masked, such as
  `sk-ab...xY7q`. keymolt picks the one key whose visible start and end match
  the current key. `list` is the path to the array, and `id` and `hint` are the
  paths inside each item. An optional `revoke` inside `find` deletes that key,
  for providers where keys made by hand have their own delete endpoint.

If no key matches, or more than one does, keymolt deletes nothing and the
receipt asks you to revoke the old key by hand. A hint must show at least four
characters. With `current`, `keymolt create` also refuses when the destination
already holds a key. See
[`openai-to-convex.example.json`](openai-to-convex.example.json): it finds a
project key you made in the OpenAI dashboard and deletes it after the new key
is stored.

### Options

- `keep_previous: true` — keep the last key alive for one more run before
  deleting it, for callers that cache keys.
- `ok_path` on a step — a dotted path to check in the response, for APIs that
  return HTTP 200 with an error inside the body (such as GraphQL).

## Rotating on a schedule

Rotation should not depend on your agent being awake and well-behaved. Point a
scheduler at `rotate-all` and let it run on its own:

```
keymolt rotate-all ./recipes
```

This rotates every recipe in a folder and appends one receipt line per recipe to
`recipes/keymolt.log`. Trigger it from whatever scheduler you already have — your
agent's runtime, a GitHub Actions cron, a Kubernetes CronJob, Railway cron, or a
plain crontab entry.

If you have no scheduler, `keymolt schedule` is a shortcut that registers
`rotate-all` with your OS — Task Scheduler, launchd, or a systemd user timer:

```
keymolt schedule ./recipes weekly
```

## Breach rescue (Railway)

If a Railway project's keys are exposed, scan it and rotate every key that has a
provider template, in one pass:

```
keymolt rescue scan RAILWAY_PROJECT_ID      # list the keys and their providers; changes nothing
keymolt rescue rotate RAILWAY_PROJECT_ID    # rotate each key with a template, store it back
```

`rescue` reads each service's variables and each environment's shared
variables, names each key's provider, and writes the new keys back where it
found them. It prints only the last four characters of any key.

Variables that reference another variable (`${{shared.NAME}}`,
`${{Postgres.DATABASE_URL}}`) are skipped. `rescue` writes the new key only to
the variable they point to, so every reference still works and picks up the
new key.

## Providers and templates

Provider detection and templates are data files in `providers/`. Each is a
recipe template plus a `detect` block (a variable-name pattern and a key-value
pattern). Adding a provider is a new JSON file, not a new release. Drop your own
templates in `~/.keymolt/templates` (or set `KEYMOLT_PROVIDERS`); templates you
add are untrusted and need `approve`, like any recipe.

## In CI, without an OS vault

Set the credential and its hosts as environment variables instead of using the
vault:

```
KEYMOLT_CRED_OPENAI_ADMIN=sk-admin-...
KEYMOLT_HOSTS_OPENAI_ADMIN=api.openai.com
```

The name after the prefix is the credential name, upper-cased. Hosts are
comma-separated.

CI has no vault for approvals either. List the SHA-256 hash of each recipe you
trust in `KEYMOLT_APPROVED`, comma-separated. `keymolt approve` prints the
hash, or you can run `sha256sum recipe.json`. Store the list as a CI secret, so
a pull request that edits a recipe can't run it until you update the list. The
hash covers the exact bytes, so keep git from changing line endings in recipe
files (add `*.json -text` to `.gitattributes`).

## License

[FSL-1.1-ALv2](LICENSE). Free to use, with a non-compete that expires after two
years, when each release becomes Apache 2.0.
