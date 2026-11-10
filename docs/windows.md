# Windows backend (experimental)

Use native 64-bit Python 3.11 or newer on Windows 10/11 with an interactive
desktop. WSL does not supply the native Windows backend. Install the same project;
`pywin32` is installed on Windows and `python-xlib` is installed only on Linux.

This implementation is awaiting tests in real Windows applications. Hosted
Windows CI tests the native pipe, file access checks, encrypted saves and recovery;
it does not prove that a browser accepts directed window messages. Use a synthetic
vault with invented credentials until the desktop checklist below passes.

## Supported operations and limits

- Unlock, metadata search, single-field username/password fills and TOTP fills.
- Private password/TOTP imports, generated passwords, new entries and passwordless
  identity records use the shared vault logic and the Windows save backend.
- Unlock webhook subscriptions use the same one-shot notification protocol.
- `fill --mode login` is refused before any characters are sent. Fill username and
  password separately, with a new search handle and target pin for each field.
- Merge, refresh-target, preservation merges, snapshot admission and merge receipts
  are unavailable. Both CLI capability checks and direct broker requests refuse
  these operations. Use the Linux implementation for them.
- Use a local NTFS volume with restrictive DACLs. UNC paths, junctions, symlinks,
  other reparse points, hard-linked vaults and alternate data streams are refused.
  OneDrive placeholder paths can be reparse points and are not supported.
- Vault reads and saved candidates are limited to 128 MiB; key files to 1 MiB.
  Write artifacts must fit 255 UTF-16 units per filename and the 260-unit Win32
  path budget. Recovery scans stop at 10,000 matching vault artifacts;
  unrelated files do not consume this budget.
- The broker, CLI and target app must run as the same Windows user in the same
  desktop session. Run normally, without elevation. Secure desktop/UAC prompts and
  apps at a higher integrity level are not supported. Services without an
  interactive desktop cannot fill applications.

## Install and prepare private files

From the checkout in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'

$private = Join-Path $env:LOCALAPPDATA 'akdbx'
New-Item -ItemType Directory -Path $private
$account = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $private /inheritance:r /grant:r "${account}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F'
```

Choose a new directory for this setup. Do not replace permissions on an existing
shared directory. Put a **synthetic test KDBX** in this directory as
`synthetic.kdbx`. The vault, optional key file, HTTPS key and HTTPS certificate
must have restrictive access. Inherited permissions from this new private folder
are suitable. The broker checks existing permissions; it does not silently change
permissions on a production vault. Administrators and SYSTEM remain trusted, as
root is trusted on Linux.

## Configure the private HTTPS page

Windows does not expose the Linux Unix-socket Tailscale Serve backend. It serves
HTTPS directly on `127.0.0.1`. Use a certificate trusted by the local browser for
`localhost` (or `127.0.0.1`), plus its unencrypted PEM private key. A local development CA such
as [mkcert](https://github.com/FiloSottile/mkcert) can issue this certificate:

```powershell
mkcert -install
mkcert -cert-file "$private\localhost.pem" -key-file "$private\localhost-key.pem" localhost 127.0.0.1
$env:AKDBX_UNLOCK_ORIGIN = 'https://localhost:9443'
.\.venv\Scripts\akdbx.exe serve "$private\synthetic.kdbx" `
  --tls-cert "$private\localhost.pem" --tls-key "$private\localhost-key.pem"
```

Installing a local CA changes browser trust and is a user setup step. Protect its
CA private key. An existing certificate from your own trusted CA also works; mkcert
is not a runtime dependency. Do not bypass certificate errors or use HTTP. The
server requires a certificate/key, a loopback HTTPS origin, and a port from 1024 to
65535. The certificate must match the configured hostname. No listener binds to
the LAN or tailnet, and remote unlock from another device is not supported by this
backend. TLS handshakes and private requests share bounded worker/deadline limits.

Open the broker-provided one-time HTTPS link in the Windows browser. Enter the
synthetic master password there. The CLI and agent do not receive it. Host and
Origin checks reject cross-origin requests. No Tailscale identity header is trusted
on Windows. The URL token is secret, rate-limited and rotated on successful unlock.
Stopping the broker invalidates its links. TLS protects a stale link if another
local user later takes the port; keep the certificate key private.

## Search and fill

In a second PowerShell window, with the same unlock origin:

```powershell
$env:AKDBX_UNLOCK_ORIGIN = 'https://localhost:9443'
.\.venv\Scripts\akdbx.exe status
.\.venv\Scripts\akdbx.exe search example.test
.\.venv\Scripts\akdbx.exe pin-target --pid VERIFIED_PID --window VERIFIED_TOP_LEVEL_HWND
.\.venv\Scripts\akdbx.exe fill SEARCH_HANDLE --mode username --target TARGET_PIN
```

Focus the intended field before pinning. `--window` takes the independently
verified top-level HWND, in decimal or `0x` notation. Focus must belong to that
window and process. Repeat search and pin after focusing the password field, then
use `--mode password`. TOTP and generated-password fills use the same fresh-pin
contract as Linux. Never inspect a filled real credential to confirm delivery;
check the application's nonsecret outcome.

The default endpoint is `\\.\pipe\akdbx-USER_SID-SESSION_ID`. `--socket` accepts a
custom local `\\.\pipe\akdbx-NAME` endpoint for isolated tests. Remote named pipes
are refused. The pipe DACL restricts access to the user and SYSTEM, remote clients
are disabled, and each peer's user/session is checked from its native PID before
RPC data is sent or dispatched. Clients use identification-level security to avoid
granting a malicious pipe server impersonation rights. A first-instance check and
a continuously retained pipe instance prevent endpoint replacement during a run.
`--broker-uid` applies only to Linux and is rejected by the Windows client.

## Delivery and persistence contract

`status` advertises `target_fill_delivery: "win32-char-v1"` and
`target_fill_modes: ["username", "password"]`. The CLI refuses another delivery
backend. Pins bind the native process creation time, user/session, top-level HWND,
focused HWND, GUI thread and window classes. The backend checks foreground/focus,
held keys/buttons and identity before and through dispatch. Unicode `WM_CHAR`
messages go only to the pinned HWND via bounded `SendMessageTimeoutW`. It never
uses global `SendInput`, clipboard contents, keystroke grabs, or text readback.
It refuses Tab sequences before sending a prefix. A failure after dispatch starts
is uncertain: do not retry automatically.

A receipt proves message dispatch, not application acceptance. Apps may ignore
synthetic messages. Browser DOM fields, tabs and origins are caller checks. A
target application can change its own internal destination; Windows metadata is
not protection from a malicious process running as the same user. Held process
handles prevent PID reuse during a capture/delivery, but no platform backend
provides protection from administrators or same-user compromise.

Saves hold trusted directory handles, reject reparse paths and unsafe DACLs, lock
the vault, recheck encrypted snapshots and optional key-file contents, reopen and
verify the candidate, retain an encrypted backup, and replace using
`MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH)`. Only encrypted KDBX files and
nonsecret recovery receipts are staged. A `prepared` receipt around replacement
blocks use after an uncertain save, including after restart. Preserve the target,
backup and receipt for recovery; do not simply delete a blocking receipt. A Linux
merge recovery bundle or admission locator also blocks Windows use, because this
backend cannot verify those transactions. Unlock's final recovery scan and
readiness checks use the same nonblocking lock as saves. The private folder must
allow the broker's lock file. A busy save makes writes temporarily unavailable
or delays unlocking until a retry, and does not mark recovery as failed.
Malformed or oversized receipts leave the broker in recovery-required state
after a valid unlock; they are not reported as an incorrect master password.
Keep other editors and sync writers away during
the entire save; advisory locks do not control them. The final snapshot check and
replacement are separate operations. An external edit between them can be lost,
and the retained backup may not contain that edit. This is not a claim of
power-loss safety on every storage device.

## Validation before production use

Run the native automated checks on the prepared Windows machine:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_protocol.py tests/test_windows_target.py tests/test_windows_unlock.py tests/test_windows_native.py
```

Then use only synthetic credentials for these desktop checks:

1. Unlock, search and separately fill a native Unicode edit control, then a local
   browser login fixture. Check ASCII, non-ASCII, punctuation and TOTP acceptance.
2. Switch to another app or field before/during dispatch. Check refusal or an
   uncertain result, with no characters sent to the new foreground app.
3. Check expired/reused pins, wrong PID/HWND, held keys, disconnected clients,
   hung windows and elevated/unsupported targets. No automatic retry is allowed.
4. Exercise private imports and generated-password saves through the HTTPS page.
   Reopen the synthetic KDBX independently and check unrelated fields/history.
5. Test with a second standard Windows user: the pipe and private files must be
   inaccessible. Check junctions, unsafe DACLs, external edits, concurrent writers
   and interrupted-save recovery. Native CI does not replace this second-user test.
6. Confirm no secrets in console output, RPC receipts, logs or unencrypted files.

Record the Windows version, Python version and application versions with results.
An automated CI pass does not complete this checklist.

API references: [named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[GetGUIThreadInfo](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getguithreadinfo),
[SendMessageTimeoutW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw),
and [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).
