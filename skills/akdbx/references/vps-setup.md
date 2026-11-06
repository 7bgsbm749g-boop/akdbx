# VPS setup and recovery

Read this when ordinary broker calls cannot proceed or when the user asks to connect a database. This is a portable setup guide, not a record of a particular server. Obtain real CLI paths, HTTPS origins, service names and desktop settings from private local configuration. Do not reconfigure a working broker to match an example.

## CLI and socket discovery

```bash
/absolute/path/to/akdbx/.venv/bin/akdbx --help
/absolute/path/to/akdbx/.venv/bin/akdbx status
```

The CLI chooses `${XDG_RUNTIME_DIR}/akdbx/akdbx.sock` when `XDG_RUNTIME_DIR` is set, otherwise `/tmp/akdbx-UID/akdbx.sock`. For a runtime-based deployment, the unlock backend is `${XDG_RUNTIME_DIR}/akdbx/akdbx-unlock.sock`. If the caller and broker have different environments, pass the broker's known socket explicitly. `--socket` is a global option and must precede the subcommand:

```bash
/absolute/path/to/akdbx/.venv/bin/akdbx --socket ${XDG_RUNTIME_DIR}/akdbx/akdbx.sock status
```

Use the same socket on subsequent search/fill commands. Do not unlink a socket or launch a duplicate broker to work around a connection failure. `serve` refuses a live endpoint, recovers only an unchanged owned stale socket, and holds a persistent per-socket lifecycle lock across startup and shutdown. It validates the runtime directory without changing its permissions, and anchors socket lifecycle operations to the verified directory. Custom sockets must already live in (or name a new) dedicated private directory below trusted, non-symlinked ancestry, not a shared project directory. Root-owned sticky ancestors such as `/tmp` are allowed for the per-UID fallback; other group- or world-writable ancestors are rejected.

During the rebrand, an existing deployment may keep its legacy
`${XDG_RUNTIME_DIR}/agentic-kdbx/agentic-kdbx.sock` endpoint and private vault
path. The CLI automatically uses that legacy endpoint only when the canonical
socket is absent, then applies the same security checks. Use the existing
socket; do not restart an unlocked broker just to rename storage. Existing
vault, admission and recovery paths must stay unchanged so saved receipts
remain valid. Preserve an existing protected Serve backend until a coordinated
migration is authorized.

Before connecting, the CLI requires that dedicated directory to be owned by the configured broker UID with mode `0700`, requires the socket to be owned by that UID with mode `0600`, rejects symlinked path components, and verifies the connected process using Unix peer credentials. The expected UID defaults to the caller's UID. If a deployment intentionally runs the broker as another account, configure its numeric identity independently with global `--broker-uid UID` or `AKDBX_BROKER_UID`; do not derive it from a server response.

Broker-provided unlock links are shown only when they use HTTPS and match the independently configured expected origin. The built-in default, `https://unlock.example.invalid:9443`, is deliberately non-routable. Set `AKDBX_UNLOCK_ORIGIN` in the private environment to the real deployment origin, or put global `--unlock-origin https://host[:port]` before the subcommand. This setting also configures the broker's private-page origin at startup. The legacy `serve --unlock-url` override remains supported; clients must still independently configure the same trusted origin. Existing deployments must configure their current origin before updating the CLI or restarting the broker. The configured value must be an origin only, without credentials, path, query, or fragment.

This client is a CLI; no MCP server or automatic broker service is supplied. The repository's `.buildtmp` KDBX files were synthetic test fixtures. Do not treat them as the user's database. If the real database path is unknown, ask for its location, never its master password or key-file contents.

If the existing virtual environment is missing and installation is part of the task, the repository's `README.md` describes installation. Avoid dependency reinstalls for an ordinary login.

## Existing X11 desktop

Reuse the host's existing X11 desktop and window manager. Read `DISPLAY`,
`XAUTHORITY`, `DBUS_SESSION_BUS_ADDRESS` and other desktop environment settings
from the owning account's private configuration or managed service. Do not
assume a display number, account name, authorization-file path or service name.
Keep the Xauthority contents private. Verify the configured display with
`xdpyinfo` in that environment before starting desktop components; an unset
`DISPLAY` is not evidence that a second Xvfb is needed.

For actual GUI interaction, use the available GUI skill/tools and verify the
exact target. A browser running on another device, another display, or in a
separate preview is not a destination the local broker can automatically fill.
Remote unlock on a phone only unlocks the host's broker; it does not type on
that phone.

## Start with remote unlock

Reuse an existing broker whenever possible. To start a new one, use the real database path supplied by the user and a persistent process/PTY with the configured desktop environment and `AKDBX_UNLOCK_ORIGIN` set. Keep that session alive after the agent turn; terminating it locks the database. The user does not need access to its terminal: master-password entry is private web-only and fills require no terminal input.

```bash
/absolute/path/to/akdbx/.venv/bin/akdbx \
  --socket ${XDG_RUNTIME_DIR}/akdbx/akdbx.sock \
  serve /absolute/path/to/the-users-vault.kdbx --web-unlock
```

For a database requiring a key file, append `--keyfile /absolute/path/to/keyfile`. The key file must already be available on the broker host. Never print its contents. The browser accepts a master password; it does not upload the KDBX or key file, and its current form requires a nonempty password.

Private web unlock is always enabled. `--web-unlock` remains accepted for command compatibility and clarity; omitting it has the same behavior. The former hidden terminal master-password prompt has been removed.

After web unlock, an explicit `fill` with a fresh handle and `--target` pin sends directly to the verified X11 target. Read [target-pinned delivery](target-fill.md); require target protocol 1 and `x11-send-event-v1` in broker status. The user has authorized removal of all per-fill terminal approval. Do not ask for another fill approval. `--yes-on-fill` is a deprecated compatibility no-op that emits a warning; omit it from new commands. Focus and verify the target before invoking `fill`, and keep focus stable through completion. Unlock and search never type on their own. Each fill has a short start deadline: `autofill not started` guarantees no key was sent, while a timeout or lost connection remains potentially partial and must not be retried automatically.

For a broker started before this change, the originating login workflow must stop the old process before running the startup command above, preserving its database/key-file paths, socket, and desktop environment. Do not approve an old pending terminal prompt: stopping that broker discards the pending request. Then request a fresh private web unlock and search for a new handle. Updating source or invoking a new CLI does not replace code already loaded by the running broker. A repair thread scoped to source changes must leave the live broker, socket, vault, and desktop alone.

The database is held in memory for that broker process's lifetime. Successful broker writes and merges replace it with the verified saved vault. External file changes are not automatically reloaded and cause write conflicts. Password workflows are documented in [password writes](password-writes.md); version 0.6.0 adds semantic active verification to explicit equal-time preservation and external-target reconciliation in [encrypted merges](merge.md). After coordinated activation, verify the new process's reviewed build identity through the [activation checklist](merge.md#activation-by-the-originating-workflow). Compare broker status `version` with the deployed CLI invoked by its discovered absolute path (`/absolute/path/to/akdbx/.venv/bin/akdbx --version`), and use that same path for `status` and `serve`; PATH can select another installation. Require `writes_available: true`, `locked: false` and `recovery_required: false`; merges also require `merge_available: true` and `merge_protocol: 1`; external reconciliation also requires `merge_refresh_target_supported: true`; `--preserve-conflicts` requires `merge_preserve_conflicts_supported: true` and exact `merge_preservation_policy: "capsule-v1"`, plus `merge_active_verification: "semantic-v1"` and result `active_verification: "semantic-v1"`. Fixed refusal categories are documented in [active verification](selection-verification.md). CLI help alone does not prove activation. Stopping the broker (Ctrl-C in its own terminal) requires a fresh unlock next time. There is no stored master password or automatic unlock after reboot.

## Tailscale web page

Example runtime-based deployment (substitute your private configuration):

- Public-to-the-tailnet HTTPS base: the HTTPS origin in `AKDBX_UNLOCK_ORIGIN`
- Local backend: HTTP over `unix:${XDG_RUNTIME_DIR}/akdbx/akdbx-unlock.sock`
- Live URL: the base plus `/?token=...`, returned by the running broker.

The backend only runs while a `serve --web-unlock` process is alive. Both sockets live in the dedicated `${XDG_RUNTIME_DIR}/akdbx` directory, which is owned by the configured broker UID and mode `0700`; the broker also validates its non-symlinked ancestry and rejects replaceable ancestors instead of weakening permissions. This prevents a different local UID from creating a replacement backend while the broker is stopped. An installed Tailscale proxy alone does not mean a vault is connected or the page is available.

Read-only checks:

```bash
tailscale serve status
test -S "${XDG_RUNTIME_DIR}/akdbx/akdbx-unlock.sock"
/absolute/path/to/akdbx/.venv/bin/akdbx status
```

Only if migration or setup is authorized, first verify `tailscale version` is **1.98.9 or newer** and inspect the existing mappings. Tailscale requires root to configure filesystem/Unix-socket targets. Then replace only the mapping for the configured unlock port with the protected socket backend (9443 is an example); do not reset or disturb other services:

```bash
sudo tailscale serve --bg --https=9443 "unix:${XDG_RUNTIME_DIR}/akdbx/akdbx-unlock.sock"
tailscale serve status
```

Use Serve and do not enable Funnel/public exposure for the unlock page. Preserve mappings for other applications; do not reset the entire Serve configuration. Do not retain or restore a loopback TCP mapping: a persistent mapping to a reclaimable high TCP port does not authenticate the backend while the broker is stopped. Starting new application code cannot change an existing Tailscale configuration, so remote unlock must remain unavailable until this migration is completed.

Tailscale versions before 1.98.9 must not be used for this socket mapping because TS-2026-005 allowed a non-root Tailscale operator to configure privileged Unix-socket proxy targets. Upgrade Tailscale through the host's managed package process before configuring the mapping. The broker's socket mode is `0600`; `tailscaled` normally runs as root and can reach it without making the socket accessible to other users.

The handler requires both the token and a nonempty Tailscale identity header supplied by Serve. It does not contain a per-owner allowlist: reachability is governed by the tailnet's access rules. Do not spoof identity headers or use a direct backend POST to bypass the intended user unlock workflow. Tagged devices may lack the required identity header.

If the page fails:

- `404`: check broker status and the exact current tokenized URL. Successful unlock invalidates the old URL. Missing identity also causes `404`.
- Proxy/backend unavailable: check that the broker and Unix socket are present and inspect the existing Serve mapping.
- `Unlock failed`: let the user retry on the page. If needed, check only the configured database/key-file paths and file accessibility; do not solicit or test passwords yourself.
- `429`: the current server limits failed attempts to five per minute. Wait before another user attempt.

## Sources for implementation-specific questions

- Usage: [`README.md`](../../../README.md)
- CLI defaults and arguments: [`src/akdbx/cli.py`](../../../src/akdbx/cli.py)
- Broker and keyboard delivery: [`src/akdbx/broker.py`](../../../src/akdbx/broker.py)
- Unlock page: [`src/akdbx/web_unlock.py`](../../../src/akdbx/web_unlock.py)

Consult source when observed behavior differs from this skill. Reading implementation is fine; using it to extract the user's vault secrets is not part of the login workflow.

Version 0.8.1 adds [passwordless SSO identity creation](password-writes.md#passwordless-sso-identity-records-081).
Require the running broker's SSO protocol 1 before dispatch; the originating
workflow owns coordinated restart/private unlock with unchanged configuration.
Version 0.8.0 adds a separately reviewed [snapshot admission prototype](snapshot-admission.md).
Preserve its external recovery locator/storage; do not downgrade to a broker
that cannot scan those receipts.
