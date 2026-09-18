# VPS setup and recovery

Read this when ordinary status/search/fill calls cannot proceed or when the user asks to connect a database. These are local deployment details, not a reason to reconfigure a working broker.

## CLI and socket discovery

```bash
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx --help
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx status
```

The CLI chooses `${XDG_RUNTIME_DIR}/agentic-kdbx.sock` when `XDG_RUNTIME_DIR` is set, otherwise `/tmp/akdbx-UID/agentic-kdbx.sock`. On this VPS, the usual runtime location is `/run/user/1000/agentic-kdbx.sock`. If the caller and broker have different environments, pass the broker's known socket explicitly. `--socket` is a global option and must precede the subcommand:

```bash
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx --socket /run/user/1000/agentic-kdbx.sock status
```

Use the same socket on subsequent search/fill commands. Do not unlink a socket or launch a duplicate broker to work around a connection failure: `serve` currently replaces an existing socket pathname. Also, `serve` changes its socket's parent-directory mode to `0700`, so custom sockets should live in a dedicated private directory, not a shared project directory.

This client is a CLI; no MCP server or automatic broker service is supplied. The repository's `.buildtmp` KDBX files were synthetic test fixtures. Do not treat them as the user's database. If the real database path is unknown, ask for its location, never its master password or key-file contents.

If the existing virtual environment is missing and installation is part of the task, the repository's `README.md` describes installation. Avoid dependency reinstalls for an ordinary login.

## Existing managed desktop

The VPS already runs Xvfb `:99` with Openbox. Check it before trying to launch any desktop components:

```bash
systemctl --user is-active vps-desktop.service vps-cua.service
DISPLAY=:99 XAUTHORITY=/home/ubuntu/.local/share/vps-computer/Xauthority xdpyinfo
```

The broker startup environment is:

```bash
export DISPLAY=:99
export XAUTHORITY=/home/ubuntu/.local/share/vps-computer/Xauthority
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
export XDG_SESSION_TYPE=x11
export XDG_CURRENT_DESKTOP=OPENBOX
```

Login shells receive these values from `/etc/profile.d/vps-managed-desktop.sh`. A tool may sanitize its environment; use the explicit values above if needed. Run as `ubuntu`. Keep the Xauthority contents private. Do not start a second Xvfb just because `DISPLAY` is unset.

For actual GUI interaction, use the available GUI skill/tools and verify the exact target. A browser running on another device, another display, or in a separate preview is not a destination the local broker can automatically fill. Remote unlock on a phone only unlocks the VPS broker; it does not type on that phone.

## Start with remote unlock

Reuse an existing broker whenever possible. To start a new one, use the real database path supplied by the user and a persistent process/PTY with the desktop environment above. Keep that session alive after the agent turn; terminating it locks the database. The user does not need access to its terminal: master-password entry is private web-only and fills require no terminal input.

```bash
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx \
  --socket /run/user/1000/agentic-kdbx.sock \
  serve /absolute/path/to/the-users-vault.kdbx --web-unlock
```

For a database requiring a key file, append `--keyfile /absolute/path/to/keyfile`. The key file must already be available on this VPS. Never print its contents. The browser accepts a master password; it does not upload the KDBX or key file, and its current form requires a nonempty password.

Private web unlock is always enabled. `--web-unlock` remains accepted for command compatibility and clarity; omitting it has the same behavior. The former hidden terminal master-password prompt has been removed.

After web unlock, an explicit `fill` with a fresh handle types immediately into the focused target. The user has authorized removal of all per-fill terminal approval. Do not ask for another fill approval. `--yes-on-fill` is a deprecated compatibility no-op that emits a warning; omit it from new commands. Focus and verify the target before invoking `fill`, and keep focus stable through completion. Unlock and search never type on their own. The client still waits five seconds for an RPC response, so treat a timeout as potentially partial input.

For a broker started before this change, the originating login workflow must stop the old process before running the startup command above, preserving its database/key-file paths, socket, and desktop environment. Do not approve an old pending terminal prompt: stopping that broker discards the pending request. Then request a fresh private web unlock and search for a new handle. Updating source or invoking a new CLI does not replace code already loaded by the running broker. A repair thread scoped to source changes must leave the live broker, socket, vault, and desktop alone.

The database is held in memory for that broker process's lifetime. Changes made to the KDBX file after opening are not automatically reloaded. Stopping the broker (Ctrl-C in its own terminal) requires a fresh unlock next time. There is no stored master password or automatic unlock after reboot.

## Tailscale web page

Configured deployment:

- Public-to-the-tailnet HTTPS base: `https://vps-3857965a.tailb80cc4.ts.net:9443`
- Local backend: `http://127.0.0.1:43128`
- Live URL: the base plus `/?token=...`, returned by the running broker.

The backend only runs while a `serve --web-unlock` process is alive. An installed Tailscale proxy alone does not mean a vault is connected or the page is available.

Read-only checks:

```bash
tailscale serve status
ss -ltn 'sport = :43128'
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx status
```

Only if the mapping is missing and setting up remote access is authorized, inspect current mappings first, then configure this port without replacing other services:

```bash
tailscale serve --bg --https=9443 http://127.0.0.1:43128
```

Use Serve, keep the backend on loopback, and do not enable Funnel/public exposure for the unlock page. Ports 443 and 8443 already serve other applications. Do not reset the entire Serve configuration.

The handler requires both the token and a nonempty Tailscale identity header supplied by Serve. It does not contain a per-owner allowlist: reachability is governed by the tailnet's access rules. Do not spoof identity headers or use a direct backend POST to bypass the intended user unlock workflow. Tagged devices may lack the required identity header.

If the page fails:

- `404`: check broker status and the exact current tokenized URL. Successful unlock invalidates the old URL. Missing identity also causes `404`.
- Proxy/backend unavailable: check that the broker and loopback listener are still running and inspect the existing Serve mapping.
- `Unlock failed`: let the user retry on the page. If needed, check only the configured database/key-file paths and file accessibility; do not solicit or test passwords yourself.
- `429`: the current server limits failed attempts to five per minute. Wait before another user attempt.

## Sources for implementation-specific questions

- Usage: `/home/ubuntu/projects/agentic-kdbx/README.md`
- CLI defaults and arguments: `/home/ubuntu/projects/agentic-kdbx/src/agentic_kdbx/cli.py`
- Broker and keyboard delivery: `/home/ubuntu/projects/agentic-kdbx/src/agentic_kdbx/broker.py`
- Unlock page: `/home/ubuntu/projects/agentic-kdbx/src/agentic_kdbx/web_unlock.py`

Consult source when observed behavior differs from this skill. Reading implementation is fine; using it to extract the user's vault secrets is not part of the login workflow.
