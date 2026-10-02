# agentic-kdbx

`agentic-kdbx` is a local KeePass (`.kdbx`) autofill broker designed for AI agents. Agents may search login metadata and choose an opaque, short-lived handle. They never receive the password: the broker types it into the focused application and returns only a success receipt.

## Security model

- The unlocked database and plaintext secrets stay in the foreground broker process.
- The API has no reveal, clipboard, export, or arbitrary-field operation.
- Search returns only title, username, URL, group, and a random authenticated handle.
- Handles expire after five minutes and are consumed on the first fill attempt.
- The Unix socket and its directory are mode `0600` and `0700`. The CLI rejects
  symlinked or incorrectly owned runtime paths and verifies the server's Unix
  peer UID before sending a request.
- The broker starts locked. The user enters the master password only on the private Tailscale HTTPS unlock page, never in chat, terminal input, arguments, or environment variables.
- After unlock, an explicit `fill` invokes keyboard delivery immediately, without terminal approval. The caller must verify the destination and focus the intended field first.
- Errors are deliberately generic after the typing boundary.

This prevents accidental disclosure into chat, command output, logs, process arguments, and agent RPC responses. It does **not** protect against a malicious process running as your OS user, a compromised target application, screen/key logging, or an agent that can redirect focus or inspect a filled web page. The broker uses global keyboard input and cannot verify the destination: check focus before every explicit fill and keep it stable until the response arrives. Python cannot guarantee memory zeroization.

## Install and run

Linux desktop (X11 is the most reliable backend):

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/akdbx serve /absolute/path/to/passwords.kdbx --web-unlock
```

Keep the broker process running. Open its private unlock page from your Tailscale-connected device and enter the master password there. The broker needs no terminal input and can run in a persistent agent PTY that the user cannot access. After unlocking, use another shell—or an agent—to search, focus the destination, and explicitly fill:

```bash
.venv/bin/akdbx search github.com
.venv/bin/akdbx fill HANDLE_FROM_SEARCH --mode login
```

Focus the username field before invoking `fill`. `login` types the username, presses Tab, then types the password. `--mode username` and `--mode password` fill one field. Before sending any keys, the broker rejects a requested fill if any field it needs contains a control character, including Tab, carriage return, or newline. The broker sends no submit key of its own, reads nothing back from the destination, and does not use the clipboard.

There are no per-fill approval prompts. `--yes-on-fill` is a deprecated compatibility no-op; existing commands still work and emit a deprecation warning. Remove it from new commands. `--web-unlock` remains accepted for clarity; private web unlock is now the default and only unlock method, even when the flag is omitted. The former hidden terminal master-password prompt has been removed.

### Unlock remotely over Tailscale

On the configured VPS, start the broker without entering the master password locally:

```bash
.venv/bin/akdbx serve /absolute/path/to/passwords.kdbx --web-unlock
```

The broker starts locked. `status` and `search` responses provide a one-time `https://vps-3857965a.tailb80cc4.ts.net:9443` unlock link. Open it from a device signed into the tailnet, enter the KDBX master password, and then use the broker normally. The backend listens only on a Unix-domain socket in the broker's private runtime directory; it does not open a TCP port. Tailscale Serve supplies HTTPS, tailnet access control, and the authenticated identity header. The filesystem boundary prevents another local UID from replacing a stopped backend behind the trusted HTTPS origin. The page and URL are non-cacheable, attempts are rate-limited, request logging is disabled, and the URL token is replaced after a successful unlock.

The CLI independently trusts that HTTPS origin; it rejects broker responses
containing an HTTP, malformed, credential-bearing, or different-origin unlock
link. Custom deployments must configure the client with the intended origin
using global `--unlock-origin HTTPS_ORIGIN` (or `AKDBX_UNLOCK_ORIGIN`) before the
subcommand. A broker running under a separately configured account likewise
requires global `--broker-uid UID` (or `AKDBX_BROKER_UID`).

The master password travels inside the tailnet HTTPS connection directly to the local broker. It is never returned to the CLI or agent. Unlock remains valid for the lifetime of the broker process.

Key-file databases are supported with `serve DB --keyfile KEY`. Stop the broker with Ctrl-C to lock it and remove its socket. Only explicit, confirmed password-write workflows modify the database; ordinary unlock, search and fill remain read-only.

## Password writes (0.2.0)

`akdbx --version` reports the CLI version. Broker `status` reports its own
`version`, `writes_available` and `recovery_required`; require an unlocked,
write-capable 0.2.0 broker before changing a website password.

- `create-entry --title TITLE --username ACCOUNT --url SITE --group GROUP`
- `update-password SEARCH_HANDLE --title TITLE --username ACCOUNT --url SITE --group GROUP`
- `generate-password SEARCH_HANDLE --title TITLE --username ACCOUNT --url SITE --group GROUP [--length 24] [--symbols '!@#$%*-_+=?']`
- `fill-generated SINGLE_USE_FILL_HANDLE --target-url VERIFIED_RESET_URL`
- `commit-password WRITE_HANDLE --site-accepted`
- `write-status WRITE_HANDLE`
- `cancel-write WRITE_HANDLE`

Update/generation requires all exact search metadata and consumes the fresh
search handle. Creation checks the destination group and rejects duplicate
site/accounts. Create/update returns a private confirmation page where the user
reviews metadata and enters/repeats a chosen password; secrets never pass
through the CLI. Generated reset passwords remain in broker memory: two
single-use references fill password and confirmation fields on the verified
broker desktop, then explicit site acceptance permits saving the same secret.
No operation exports, shows, logs or copies passwords.

Writes expire after five minutes and vanish on restart. Site rejection requires
cancellation, not a vault overwrite. Saves serialize against fills/searches,
check on-disk conflicts, preserve history and unrelated vault data, verify the
encrypted candidate, retain mode-0600 encrypted backups and replace atomically.
Failed or uncertain saves never return success. Successful writes become
immediately searchable/fillable and invalidate previous selection handles.
The advisory disk lock does not constrain uncooperative external editors;
arrange exclusive vault editing during saves.

See [password workflows and recovery](skills/agentic-kdbx/references/password-writes.md)
for reset coordination, policy constraints, focus/origin checks, cancellation,
conflicts, backup recovery and activation. Installing new code does not replace
a running broker: coordinate restart and private re-unlock with its owner after
any live interaction ends.

## Agent contract

The installed agent skill is [skills/agentic-kdbx/SKILL.md](skills/agentic-kdbx/SKILL.md), available on this VPS at `/home/ubuntu/.codex/skills/agentic-kdbx`. Agents can invoke it as `$agentic-kdbx`; automatic selection is enabled for saved-login, KeePass, and autofill tasks. New sessions can discover the installed skill. An existing session whose skill catalog has not refreshed can read the file directly.

The skill covers exact CLI commands, remote unlock, account selection, desktop targeting, explicit fills, and recovery from uncertain fills. Its [setup reference](skills/agentic-kdbx/references/vps-setup.md) documents the managed VPS desktop, socket discovery, startup, and Tailscale configuration. The skill directory in the repository is the maintained source; the installed path links to it so updates stay in sync.

An agent should:

1. Run `akdbx search <site-or-app>` and show the user the non-secret choices.
2. Verify the destination and focus the intended field, then use exactly one returned handle with `akdbx fill`. No further user approval is required for the authorized login task.
3. Never ask for the master password or attempt to read, log, copy, or inspect a filled password field.
4. Search again if a handle expires. An `autofill not started` response guarantees that request sent no keys. A timeout or lost connection can still mean typing had already started, so check non-secret target state and never retry automatically.

Existing broker processes retain their loaded code until restarted. The originating login workflow should stop its old broker before starting the command above with the same database, key file, socket, and desktop environment, then request a fresh private web unlock. Old handles cannot be reused after restart. See the [VPS setup reference](skills/agentic-kdbx/references/vps-setup.md) for the deployment command.

Remote unlock requires Tailscale Serve to proxy HTTPS to the broker's Unix socket, not to a persistent loopback TCP port. This mapping must be installed by root with Tailscale 1.98.9 or newer; older versions had a Unix-socket Serve authorization flaw. Merely starting the updated broker does not migrate an existing Serve mapping. Follow the setup reference when deployment changes are authorized.

## Development

```bash
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
```
