# VPS setup and recovery

Read this when ordinary broker calls cannot proceed or when the user asks to connect a database. These are local deployment details, not a reason to reconfigure a working broker.

## CLI and socket discovery

```bash
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx --help
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx status
```

The CLI chooses `${XDG_RUNTIME_DIR}/agentic-kdbx/agentic-kdbx.sock` when `XDG_RUNTIME_DIR` is set, otherwise `/tmp/akdbx-UID/agentic-kdbx.sock`. On this VPS, the usual runtime location is `/run/user/1000/agentic-kdbx/agentic-kdbx.sock`. If the caller and broker have different environments, pass the broker's known socket explicitly. `--socket` is a global option and must precede the subcommand:

```bash
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx --socket /run/user/1000/agentic-kdbx/agentic-kdbx.sock status
```

Use the same socket on subsequent search/fill commands. Do not unlink a socket or launch a duplicate broker to work around a connection failure. `serve` refuses a live endpoint, recovers only an unchanged owned stale socket, and holds a persistent per-socket lifecycle lock across startup and shutdown. It validates the runtime directory without changing its permissions, and anchors socket lifecycle operations to the verified directory. Custom sockets must already live in (or name a new) dedicated private directory below trusted, non-symlinked ancestry, not a shared project directory. Root-owned sticky ancestors such as `/tmp` are allowed for the per-UID fallback; other group- or world-writable ancestors are rejected.

Before connecting, the CLI requires that dedicated directory to be owned by the configured broker UID with mode `0700`, requires the socket to be owned by that UID with mode `0600`, rejects symlinked path components, and verifies the connected process using Unix peer credentials. The expected UID defaults to the caller's UID. If a deployment intentionally runs the broker as another account, configure its numeric identity independently with global `--broker-uid UID` or `AKDBX_BROKER_UID`; do not derive it from a server response.

Broker-provided unlock links are shown only when they use HTTPS and match the independently configured expected origin. The managed default is `https://vps-3857965a.tailb80cc4.ts.net:9443`. For an intentional custom deployment, put global `--unlock-origin https://host[:port]` before the subcommand, or set `AKDBX_UNLOCK_ORIGIN`. The configured value must be an origin only, without credentials, path, query, or fragment.

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
  --socket /run/user/1000/agentic-kdbx/agentic-kdbx.sock \
  serve /absolute/path/to/the-users-vault.kdbx --web-unlock
```

For a database requiring a key file, append `--keyfile /absolute/path/to/keyfile`. The key file must already be available on this VPS. Never print its contents. The browser accepts a master password; it does not upload the KDBX or key file, and its current form requires a nonempty password.

Private web unlock is always enabled. `--web-unlock` remains accepted for command compatibility and clarity; omitting it has the same behavior. The former hidden terminal master-password prompt has been removed.

After web unlock, an explicit `fill` with a fresh handle types immediately into the focused target. The user has authorized removal of all per-fill terminal approval. Do not ask for another fill approval. `--yes-on-fill` is a deprecated compatibility no-op that emits a warning; omit it from new commands. Focus and verify the target before invoking `fill`, and keep focus stable through completion. Unlock and search never type on their own. Each fill has a short start deadline: `autofill not started` guarantees no key was sent, while a timeout or lost connection remains potentially partial and must not be retried automatically.

For a broker started before this change, the originating login workflow must stop the old process before running the startup command above, preserving its database/key-file paths, socket, and desktop environment. Do not approve an old pending terminal prompt: stopping that broker discards the pending request. Then request a fresh private web unlock and search for a new handle. Updating source or invoking a new CLI does not replace code already loaded by the running broker. A repair thread scoped to source changes must leave the live broker, socket, vault, and desktop alone.

The database is held in memory for that broker process's lifetime. Successful broker writes and merges replace it with the verified saved vault. External file changes are not automatically reloaded and cause write conflicts. Password workflows are documented in [password writes](password-writes.md); version 0.5.0 adds explicit equal-time version preservation to external-target reconciliation in [encrypted merges](merge.md). After coordinated activation, require broker status `version: 0.5.0`, `writes_available: true`, `locked: false` and `recovery_required: false`; merges also require `merge_available: true` and `merge_protocol: 1`; external reconciliation also requires `merge_refresh_target_supported: true`; `--preserve-conflicts` requires `merge_preserve_conflicts_supported: true` and exact `merge_preservation_policy: "capsule-v1"`. CLI help alone does not prove activation. Stopping the broker (Ctrl-C in its own terminal) requires a fresh unlock next time. There is no stored master password or automatic unlock after reboot.

## Tailscale web page

Configured deployment:

- Public-to-the-tailnet HTTPS base: `https://vps-3857965a.tailb80cc4.ts.net:9443`
- Local backend: HTTP over `unix:/run/user/1000/agentic-kdbx/agentic-kdbx-unlock.sock`
- Live URL: the base plus `/?token=...`, returned by the running broker.

The backend only runs while a `serve --web-unlock` process is alive. Both sockets live in the dedicated `/run/user/1000/agentic-kdbx` directory, which is owned by `ubuntu` and mode `0700`; the broker also validates its non-symlinked ancestry and rejects replaceable ancestors instead of weakening permissions. This prevents a different local UID from creating a replacement backend while the broker is stopped. An installed Tailscale proxy alone does not mean a vault is connected or the page is available.

Read-only checks:

```bash
tailscale serve status
sudo test -S /run/user/1000/agentic-kdbx/agentic-kdbx-unlock.sock
/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx status
```

Only if migration or setup is authorized, first verify `tailscale version` is **1.98.9 or newer** and inspect the existing mappings. Tailscale requires root to configure filesystem/Unix-socket targets. Then replace only the 9443 mapping with the protected socket backend; do not reset or disturb other services:

```bash
sudo tailscale serve --bg --https=9443 unix:/run/user/1000/agentic-kdbx/agentic-kdbx-unlock.sock
tailscale serve status
```

Use Serve and do not enable Funnel/public exposure for the unlock page. Ports 443 and 8443 already serve other applications. Do not reset the entire Serve configuration. Do not retain or restore the former `http://127.0.0.1:43128` mapping: a persistent mapping to a reclaimable high TCP port does not authenticate the backend while the broker is stopped. Starting new application code cannot change an existing Tailscale configuration, so remote unlock must remain unavailable until this migration is completed.

Tailscale versions before 1.98.9 must not be used for this socket mapping because TS-2026-005 allowed a non-root Tailscale operator to configure privileged Unix-socket proxy targets. Upgrade Tailscale through the host's managed package process before configuring the mapping. The broker's socket mode is `0600`; `tailscaled` normally runs as root and can reach it without making the socket accessible to other users.

The handler requires both the token and a nonempty Tailscale identity header supplied by Serve. It does not contain a per-owner allowlist: reachability is governed by the tailnet's access rules. Do not spoof identity headers or use a direct backend POST to bypass the intended user unlock workflow. Tagged devices may lack the required identity header.

If the page fails:

- `404`: check broker status and the exact current tokenized URL. Successful unlock invalidates the old URL. Missing identity also causes `404`.
- Proxy/backend unavailable: check that the broker and Unix socket are present and inspect the existing Serve mapping.
- `Unlock failed`: let the user retry on the page. If needed, check only the configured database/key-file paths and file accessibility; do not solicit or test passwords yourself.
- `429`: the current server limits failed attempts to five per minute. Wait before another user attempt.

## Sources for implementation-specific questions

- Usage: `/home/ubuntu/projects/agentic-kdbx/README.md`
- CLI defaults and arguments: `/home/ubuntu/projects/agentic-kdbx/src/agentic_kdbx/cli.py`
- Broker and keyboard delivery: `/home/ubuntu/projects/agentic-kdbx/src/agentic_kdbx/broker.py`
- Unlock page: `/home/ubuntu/projects/agentic-kdbx/src/agentic_kdbx/web_unlock.py`

Consult source when observed behavior differs from this skill. Reading implementation is fine; using it to extract the user's vault secrets is not part of the login workflow.
