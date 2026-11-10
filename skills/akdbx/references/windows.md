# Native Windows operation

Use the installed Windows executable, typically
`CHECKOUT\.venv\Scripts\akdbx.exe`, in the broker's Windows desktop session. Keep
the existing signed-in app when it satisfies the task. This backend is
experimental: use synthetic vaults until the requested real-app validation is
complete. The repository's `docs/windows.md` contains setup and the validation
checklist; this reference covers operation of an already configured broker.

- Use the independently configured `AKDBX_UNLOCK_ORIGIN` (normally
  `https://localhost:9443`), not a hostname learned from a broker response. Run
  `status` and require `target_fill_delivery: "win32-char-v1"`, target protocol 1,
  and an unlocked, non-recovery-blocked broker before filling.
- When locked, give the exact returned private HTTPS link to the user. It opens
  on the **Windows machine**, not a separate Tailscale device. The user enters the
  master password privately. Never bypass a TLS certificate warning, read the
  master password, submit it for the user, or replace HTTPS with HTTP. The broker
  needs a trusted local certificate and private key; do not start a duplicate
  broker or change trust/permissions merely because a command fails.
- The default transport is a local user/session-specific named pipe. `--socket`
  may select another configured local `\\.\pipe\akdbx-NAME` pipe. `--broker-uid`
  is unsupported. Do not substitute TCP, a remote named pipe or WSL.
- Independently verify the application's PID and top-level HWND. Confirm the
  site, tab and field with the authorized browser/GUI tools, then focus the
  intended field. Call `pin-target --pid VERIFIED_PID --window VERIFIED_HWND`.
  HWND values can be decimal or `0x` hex.
- Use a fresh search handle and target pin for each
  `fill HANDLE --mode username --target PIN` or
  `fill HANDLE --mode password --target PIN`. **Do not use `--mode login`** on
  Windows. Focus the next field through the appropriate tool, verify it, then
  search and pin again. TOTP/generated fills use the usual explicit target URL
  and fresh target pin. Do not read back a real secret from the target.
- A success receipt confirms directed message dispatch, not application
  acceptance. Some apps ignore synthetic `WM_CHAR` messages. Stop on uncertain
  or partial delivery; do not retry or fall back to global input/clipboard.
- Private password/TOTP imports and generated saves use the local HTTPS page.
  Shared metadata, site acceptance, exact-receipt and handle-consumption rules
  still apply. Files need restrictive Windows DACLs on a trusted local NTFS
  path. Do not copy a real vault into a test or change file permissions without
  authorization. Keep encrypted recovery files if a save is uncertain.
- `merge_available` and `admission_supported` are false on Windows. Do not try
  merge, refresh-target, preservation merges, admission or merge-status through
  another entry point. Recovery bundles or an admission locator from Linux
  block this backend until their transaction is resolved through its owning
  workflow.

The broker and target must have the same Windows user and desktop session. Do
not elevate the broker to fill UAC, secure-desktop, service-session or other
unsupported targets. Python/Windows cannot protect from a malicious process
running as the same user or an administrator.
