# agentic-kdbx

`agentic-kdbx` is a local KeePass (`.kdbx`) autofill broker designed for AI agents. Agents may search login metadata and choose an opaque, short-lived handle. They never receive the password: the broker types it into the focused application and returns only a success receipt.

## Security model

- The unlocked database and plaintext secrets stay in the foreground broker process.
- The API has no reveal, clipboard, export, or arbitrary-field operation.
- Search returns only title, username, URL, group, and a random authenticated handle.
- Handles expire after five minutes and are consumed on the first fill attempt.
- The Unix socket and its directory are mode `0600` and `0700`.
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

Focus the username field before invoking `fill`. `login` types the username, presses Tab, then types the password. `--mode username` and `--mode password` fill one field. The broker never submits the form, reads the destination back, or uses the clipboard.

There are no per-fill approval prompts. `--yes-on-fill` is a deprecated compatibility no-op; existing commands still work and emit a deprecation warning. Remove it from new commands. `--web-unlock` remains accepted for clarity; private web unlock is now the default and only unlock method, even when the flag is omitted. The former hidden terminal master-password prompt has been removed.

### Unlock remotely over Tailscale

On the configured VPS, start the broker without entering the master password locally:

```bash
.venv/bin/akdbx serve /absolute/path/to/passwords.kdbx --web-unlock
```

The broker starts locked. `status` and `search` responses provide a one-time `https://vps-3857965a.tailb80cc4.ts.net:9443` unlock link. Open it from a device signed into the tailnet, enter the KDBX master password, and then use the broker normally. The backend listens only on `127.0.0.1`; Tailscale Serve supplies HTTPS, tailnet access control, and the authenticated identity header. The page and URL are non-cacheable, attempts are rate-limited, request logging is disabled, and the URL token is replaced after a successful unlock.

The master password travels inside the tailnet HTTPS connection directly to the local broker. It is never returned to the CLI or agent. Unlock remains valid for the lifetime of the broker process.

Key-file databases are supported with `serve DB --keyfile KEY`. Stop the broker with Ctrl-C to lock it and remove its socket. The broker never modifies the database.

## Agent contract

The installed agent skill is [skills/agentic-kdbx/SKILL.md](skills/agentic-kdbx/SKILL.md), available on this VPS at `/home/ubuntu/.codex/skills/agentic-kdbx`. Agents can invoke it as `$agentic-kdbx`; automatic selection is enabled for saved-login, KeePass, and autofill tasks. New sessions can discover the installed skill. An existing session whose skill catalog has not refreshed can read the file directly.

The skill covers exact CLI commands, remote unlock, account selection, desktop targeting, explicit fills, and recovery from uncertain fills. Its [setup reference](skills/agentic-kdbx/references/vps-setup.md) documents the managed VPS desktop, socket discovery, startup, and Tailscale configuration. The skill directory in the repository is the maintained source; the installed path links to it so updates stay in sync.

An agent should:

1. Run `akdbx search <site-or-app>` and show the user the non-secret choices.
2. Verify the destination and focus the intended field, then use exactly one returned handle with `akdbx fill`. No further user approval is required for the authorized login task.
3. Never ask for the master password or attempt to read, log, copy, or inspect a filled password field.
4. Search again if a handle expires. After an error or timeout, check non-secret target state before retrying; typing may have partially completed.

Existing broker processes retain their loaded code until restarted. The originating login workflow should stop its old broker before starting the command above with the same database, key file, socket, and desktop environment, then request a fresh private web unlock. Old handles cannot be reused after restart. See the [VPS setup reference](skills/agentic-kdbx/references/vps-setup.md) for the deployment command.

## Development

```bash
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
```
