# Windows backend

Use native 64-bit Python 3.11 or newer on Windows 10/11 with an interactive
desktop. WSL does not supply the native Windows backend. Install the same project;
`pywin32` is installed on Windows and `python-xlib` is installed only on Linux.

From 0.17.0 the Windows backend has the Linux feature set: password, login and
generated-password fills through the Chromium DOM route, the full password-write
workflow, cards, merge, snapshot admission and durable unlock notifications.
The checks that prove each of these are in
[Validation before production use](#validation-before-production-use). Three
checks still need a person or a second account; see [Limits](#limits). From
0.22.0 Windows also supports
[unlock from another device](#unlock-from-another-device) through Tailscale
Serve and the [browser native host for authenticator capture](#authenticator-capture-native-host).

## Supported operations

- Unlock through the local HTTPS page, and metadata search.
- **Password, login and username fills to a verified, retained Chromium DOM
  input.** Windows uses the same `chromium-password-dom-v1` contract as Linux:
  exact HTTPS URL, page ID, main-frame ID (or a same-site child-frame route),
  selector, autocomplete token rules and a single-use 30-second target token.
  The broker must start with `--password-browser-profile`.
- Username and TOTP fills to a pinned window (`win32-char-v1`). A window pin
  never receives a password: a browser's address bar shares its page's
  top-level HWND and focus identity, so an HWND pin cannot prove that a
  password field has focus. `--mode password`, `--mode login` and
  `fill-generated` to a window pin are refused before the broker reads the
  password.
- The password-write workflow: `generate-entry`, `generate-password`,
  `fill-generated`, `commit-password`, `write-status`, `cancel-write`,
  `create-entry`, `update-password`, `setup-totp`, `create-sso-entry` and
  `create-passwordless-entry`, with verified encrypted persistence.
- Cards: `create-card`/`update-card` through the private HTTPS page,
  `search-cards`, `pin-card-target` and `fill-card` through the
  `cdp-card-element-v1` DOM route, and card-save notifications. The broker must
  start with `--card-browser-profile`.
- `merge` (including `--check`, `--refresh-target` and `--preserve-conflicts`),
  `admit` and `merge-status`, with KeePassXC CLI 2.7.10 or newer, below 2.8,
  installed for all users. See [Merge and admission](#merge-and-admission).
- Fills through the paired akdbx browser extension in Helium, Chrome or Edge,
  with no debugging port (`extension-dom-v1`). See
  [Browser extension route](#browser-extension-route).
- Unlock webhook subscriptions that survive a broker restart.
- Private password and authenticator imports through the HTTPS page.
- Unlock and private pages from another tailnet device, through Tailscale Serve
  (`--local-port`). See [Unlock from another device](#unlock-from-another-device).
- Authenticator capture from a website's setup QR through the browser native
  host (`akdbx-browser-import`). See
  [Authenticator capture native host](#authenticator-capture-native-host).

## Limits

- The HTTPS listener binds `127.0.0.1` only. Other devices reach it only
  through Tailscale Serve. The broker does not trust the `Tailscale-User-Login`
  header on the loopback page (Linux or Windows), because any local process can
  send headers to a loopback port; the one-time URL token and tailnet access
  control protect the page. Windows has no Unix-socket route like Linux's:
  Tailscale Serve proxies to Unix sockets only on Linux, macOS and BSD.
- Use a local NTFS volume with restrictive DACLs. UNC paths, junctions, symlinks,
  other reparse points, hard-linked vaults and alternate data streams are refused.
  OneDrive placeholder paths can be reparse points and are not supported.
- Vault reads and saved candidates are limited to 128 MiB; key files to 1 MiB.
  Write artifacts must fit 255 UTF-16 units per filename and the 260-unit Win32
  path budget. Recovery scans stop at 10,000 matching vault artifacts;
  unrelated files do not consume this budget.
- The broker, CLI, browser and target app must run as the same Windows user in
  the same desktop session. Run normally, without elevation. Secure desktop/UAC
  prompts and apps at a higher integrity level are not supported. Services
  without an interactive desktop cannot fill applications.
- Card processor iframes (Adyen, Computop, Stripe) use the same code as Linux,
  where CI tests them. On the CDP route only main-frame card fields have been
  tested on Windows; the extension route is tested with a Stripe frame.
- The extension route cannot attest which `<iframe>` element hosts a child
  frame, has no browser-native hit test, and does not support secret capture.
  Pairing is held in memory only: a browser or broker restart needs a new
  pairing with the master password.

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

A release wheel installs the same way; see [Releasing akdbx](releasing.md).
Choose a new directory for this setup. Do not replace permissions on an existing
shared directory. Put a **synthetic test KDBX** in this directory as
`synthetic.kdbx`. The vault, optional key file, HTTPS key and HTTPS certificate
must have restrictive access. Inherited permissions from this new private folder
are suitable. The broker checks existing permissions; it does not silently change
permissions on a production vault. Administrators and SYSTEM remain trusted, as
root is trusted on Linux.

## Configure the private HTTPS page

The private HTTPS page works the same way on Linux and Windows; the shared
rules are in [Private HTTPS pages](private-pages.md). The broker serves HTTPS
directly on `127.0.0.1`. Use a certificate trusted by the local browser for
`localhost` (or `127.0.0.1`), plus its unencrypted PEM private key. A local development CA such
as [mkcert](https://github.com/FiloSottile/mkcert) can issue this certificate:

```powershell
mkcert -install
mkcert -cert-file "$private\localhost.pem" -key-file "$private\localhost-key.pem" localhost 127.0.0.1
```

Installing a local CA changes browser trust and is a user setup step. Protect its
CA private key. An existing certificate from your own trusted CA also works; mkcert
is not a runtime dependency. Do not bypass certificate errors or use HTTP. The
server requires a certificate/key, a loopback HTTPS origin, and a port from 1024 to
65535. The certificate must match the configured hostname. No listener binds to
the LAN or tailnet. TLS handshakes and private requests share bounded
worker/deadline limits.

## Configure the browser for password and card fills

The DOM routes use the Chrome DevTools Protocol of one browser profile that the
operator selects at broker startup. No RPC or CLI request can select it.

1. Start Chrome, Edge or another Chromium browser with its own user-data
   directory and a local debugging endpoint:

   ```powershell
   $profile = Join-Path $env:LOCALAPPDATA 'akdbx-browser'
   & 'C:\Program Files\Google\Chrome\Application\chrome.exe' `
     "--user-data-dir=$profile" --remote-debugging-port=0
   ```

   Chromium 136 and newer ignore `--remote-debugging-port` for the default
   user-data directory, so the directory must be a non-default one. The browser
   writes `DevToolsActivePort` in that directory. Port `0` lets it choose a free
   loopback port. Do not use `--remote-debugging-address` or
   `--remote-allow-origins`.
2. Start the broker with that directory:

   ```powershell
   $env:AKDBX_UNLOCK_ORIGIN = 'https://localhost:9443'
   .\.venv\Scripts\akdbx.exe serve "$private\synthetic.kdbx" `
     --tls-cert "$private\localhost.pem" --tls-key "$private\localhost-key.pem" `
     --password-browser-profile $profile --card-browser-profile $profile
   ```

   `AKDBX_PASSWORD_BROWSER_PROFILE` and `AKDBX_CARD_BROWSER_PROFILE` set the same
   options. `status` then reports `password_browser_configured: true` and
   `card_browser_configured: true`.

The broker reads the port from `DevToolsActivePort` and refuses a profile it
cannot trust: every ancestor must resist replacement by another user, and the
profile directory and port file must grant no access outside this user, SYSTEM
and administrators. It connects to `127.0.0.1` only. Before it sends any byte,
it finds the process that owns the server side of that exact TCP connection in
the kernel's connection table, and requires this Windows user and desktop
session. It holds a process handle and reads the table a second time, so a
reused PID or a different listener on a stale port receives nothing.

A local debugging endpoint gives full control of that browser profile to every
process of the same Windows user. This is the same boundary as Linux: no
platform backend protects from a malicious process running as the same user or
an administrator. Keep the profile for work that the broker may fill.

Open the broker-provided one-time HTTPS link in a Windows browser. Enter the
synthetic master password there. The CLI and agent do not receive it. Host and
Origin checks reject cross-origin requests. No Tailscale identity header is trusted
on the loopback page. The URL token is secret, rate-limited and rotated on successful unlock.
Stopping the broker invalidates its links. TLS protects a stale link if another
local user later takes the port; keep the certificate key private.

### Unlock from another device

From 0.22.0 the private pages can open on any device in your tailnet. Tailscale
Serve on the Windows computer proxies its HTTPS name to the broker's loopback
listener. The listener still binds `127.0.0.1` only. From 0.23.0 Linux uses the
same steps; see [Private HTTPS pages](private-pages.md#unlock-from-another-device).

1. Install Tailscale on the Windows computer and enable HTTPS certificates for
   the tailnet. Find the computer's name, for example
   `node.tailnet.ts.net`.
2. Make the Tailscale service trust the CA that issued the broker's
   certificate. Tailscale runs as SYSTEM and does not read your user
   certificate store, where `mkcert -install` puts the CA. As the broker's
   user (not elevated), find the CA file:

   ```powershell
   Join-Path (mkcert -CAROOT) 'rootCA.pem'
   ```

   Then, in an elevated PowerShell, add that exact path to the computer's
   trusted roots. Do not run `mkcert -CAROOT` in the elevated shell: with a
   separate administrator account it names that account's CA.

   ```powershell
   certutil -addstore -f Root 'C:\Users\YOU\AppData\Local\mkcert\rootCA.pem'
   ```

   This is a change to the trust of the whole computer. Keep the CA private key
   (`rootCA-key.pem`) private.
3. Pick a free loopback port for the broker, for example `9444`, and proxy a
   tailnet HTTPS port to it with a **verified** `https://` target:

   ```powershell
   tailscale serve --bg --https=9443 https://127.0.0.1:9444
   ```

   Tailscale Serve then checks the broker's certificate for `127.0.0.1` on
   every connection. Never use an `https+insecure://` or `http://` target. The
   Serve proxy stays configured when the broker stops, and another local user
   can then take the free port. With a verified target, Serve refuses that
   listener, because it has no certificate from your CA. With an unverified
   target, Serve would show that user's fake unlock page at your trusted
   tailnet name, and could collect the master password.
4. Start the broker with the Tailscale origin and the loopback port. Use the
   same origin for every CLI command and for `akdbx extension build`:

   ```powershell
   $env:AKDBX_UNLOCK_ORIGIN = 'https://node.tailnet.ts.net:9443'
   .\.venv\Scripts\akdbx.exe serve "$private\synthetic.kdbx" --local-port 9444 `
     --tls-cert "$private\localhost.pem" --tls-key "$private\localhost-key.pem"
   ```

The broker then gives links on the Tailscale origin. Open them on any tailnet
device, including the Windows computer itself. The page accepts a request only
when its `Host` and `Origin` match the configured origin; Tailscale Serve keeps
both. A remote origin must be a DNS name, not an IP address, and needs
`--local-port` from 1024 to 65535. A loopback origin keeps its own port and
needs no `--local-port`. Limit access to the Serve port with tailnet access
controls. Do not use `tailscale funnel`: it publishes the page to the internet.
When you stop using remote unlock, remove the proxy with
`tailscale serve --https=9443 off`.

### Authenticator capture native host

From 0.22.0 the browser native host that captures a website's authenticator
setup QR also runs on Windows. The extension and the review flow are the same
as on Linux; see the skill's
[private import reference](../skills/akdbx/references/private-import.md).

The broker serves a separate capture pipe whose name is its RPC pipe name plus
`-capture` (for example `\\.\pipe\akdbx-SID-SESSION-capture`). The pipe
accepts one message type, which stages one captured setup for private review.
It never returns a key, cannot unlock the vault, and is not part of the agent
RPC. Like the RPC pipe, it accepts only clients of this Windows user and
desktop session, and the host connects only to a pipe server of the same user
and session.

Build the extension, load it unpacked, then register the host for one browser
with its extension ID and the broker's unlock origin:

```powershell
.\.venv\Scripts\akdbx-browser-import.exe build-extension "$private\capture-extension"
.\.venv\Scripts\akdbx-browser-import.exe install-host --browser chrome `
  --extension-id EXTENSION_ID --origin $env:AKDBX_UNLOCK_ORIGIN
```

`--browser` is `chrome`, `edge` or `helium`. Without `--socket` the host uses
the capture pipe of this user's default broker; give `--socket` with the
`-capture` pipe when the broker runs with its own `--socket`. The installer
writes `%LOCALAPPDATA%\akdbx\browser-import.json` (private to this user, SYSTEM
and administrators), a manifest under `%LOCALAPPDATA%\akdbx\browser-import`, and
one `HKEY_CURRENT_USER` registry value. The manifest starts the installed
`akdbx-browser-import.exe` of this environment directly. Without `--socket`
the host finds the default pipe of the current desktop session each time it
starts. It never replaces another registration. A second browser must use the
same extension ID, origin and pipe. `install-host` reads no vault and starts no
browser. `uninstall-host --browser NAME` removes that browser's registry value
and manifest. When it removes the last browser, it also removes the shared
configuration; to change the origin, extension ID or pipe, uninstall every
browser and install again.

## Browser extension route

From 0.21.0 the broker can also fill through the akdbx browser extension in
your everyday Helium, Chrome or Edge, without a remote-debugging port. A
debugging port gives every process of the same user full control of that
profile; the extension route removes that need. Agents use it with
`--route extension`, and you can click the extension yourself to fill a
focused field. See the skill's [extension route](../skills/akdbx/references/extension.md)
for the commands, capabilities and security model.

### Install in Helium

1. Start the broker as described above. The extension route needs no
   `--password-browser-profile` or `--card-browser-profile`. To make it the
   default for pins that name no route, add `--default-fill-route extension`.
2. Register the native-messaging host for this user, in a second PowerShell
   window with the same unlock origin:

   ```powershell
   .\.venv\Scripts\akdbx.exe extension install --browser helium
   ```

   This writes a launcher and a host manifest in
   `%LOCALAPPDATA%\akdbx\extension-host\` and sets
   `HKEY_CURRENT_USER\Software\Chromium\NativeMessagingHosts\org.akdbx.extension`.
   Helium is a Chromium-branded build: it reads Chromium's key, then Google
   Chrome's key, and not `Software\imput\Helium` (Chromium's
   `launch_context_win.cc`; confirmed with Helium 144.0.7559.109). Use
   `--browser chrome` (`Software\Google\Chrome\...`) or `--browser edge`
   (`Software\Microsoft\Edge\...`) for those browsers. Add the global
   `--socket \\.\pipe\akdbx-NAME` before `extension` only for a custom pipe.
3. Write the unpacked extension to the folder you load extensions from:

   ```powershell
   .\.venv\Scripts\akdbx.exe extension build --output "$env:LOCALAPPDATA\HeliumExtensions\akdbx"
   ```

   Run the same command again after an upgrade; it updates only a folder that
   already holds this extension. It prints the `extension_version` it wrote. The build writes the unlock origin
   (`AKDBX_UNLOCK_ORIGIN`, or `--unlock-origin` before `extension`; on Windows
   the default is `https://localhost:9443`) into the extension. The popup opens
   pairing and unlock links only on that origin, so a replaced native host
   cannot send you to a look-alike master-password page. Rebuild after you
   change the origin.
4. In Helium open `chrome://extensions`, turn on **Developer mode**, choose
   **Load unpacked** and select that folder. The extension ID must be
   `jjoamaejjkldcjcpgncoomoaagdfimhg`; its manifest key keeps it fixed.
5. Click the akdbx toolbar button. The popup shows a code. Choose **Open the
   pairing page**, check that the page shows the same code, and enter the
   master password there. If the broker is locked, this also unlocks it.
   Pairing lasts until the browser or the broker restarts. The popup footer
   shows the extension version, for example **akdbx extension 0.1.0**.

### Update the extension

The extension has its own version, separate from the akdbx version. After you
update akdbx:

1. Restart the broker on the new version, as described above.
2. Run the same `extension build --output` command into the same folder.
3. In `chrome://extensions`, click the reload button on the akdbx card. Pair
   again if the popup asks.

`akdbx status` then shows `version_status: "current"` for the browser in
`extension_browsers`, and `version` equal to `extension_version_expected`.
`"outdated"` means the browser still runs the old copy: check that you built
into the folder Helium loads, then reload again.

To fill, click into a login, card or address field, then click the akdbx
button, use **Fill with akdbx…** in the context menu, or press Alt+Shift+K, and
choose an entry. `.\.venv\Scripts\akdbx.exe extension uninstall --browser helium`
removes the host registration, manifest and launcher; remove the extension in
`chrome://extensions`.

Google Chrome 137 and later still load an unpacked extension through
**Load unpacked**, but ignore the `--load-extension` switch. The automated
checks therefore run in Helium and Edge.

## Search and fill

In a second PowerShell window, with the same unlock origin:

```powershell
$env:AKDBX_UNLOCK_ORIGIN = 'https://localhost:9443'
.\.venv\Scripts\akdbx.exe status
.\.venv\Scripts\akdbx.exe search example.test
```

Password, login and username fills to a web page use a DOM pin. Verify the site
and field with the authorized browser tool, focus the field, then:

```powershell
.\.venv\Scripts\akdbx.exe list-password-frames --top-url EXACT_HTTPS_URL
.\.venv\Scripts\akdbx.exe pin-password-target --page-id PAGE_ID --frame-id MAIN_FRAME_ID `
  --top-url EXACT_HTTPS_URL --selector PASSWORD_SELECTOR --mode password
.\.venv\Scripts\akdbx.exe fill SEARCH_HANDLE --mode password --target TARGET_PIN
```

`list-password-frames` returns `page_id` and `main_frame_id`, so no raw CDP call
is needed. Login pins add `--mode login --username-selector USERNAME_SELECTOR`
with the username focused. The skill's
[password field delivery](../skills/akdbx/references/target-fill.md) and
[password writes](../skills/akdbx/references/password-writes.md) references
apply without change. The CLI checks `status` first and refuses a
password-bearing request before dispatch when the broker has no password
browser profile.

Username and TOTP fills to a native application use a window pin:

```powershell
.\.venv\Scripts\akdbx.exe pin-target --pid VERIFIED_PID --window VERIFIED_TOP_LEVEL_HWND
.\.venv\Scripts\akdbx.exe fill SEARCH_HANDLE --mode username --target TARGET_PIN
```

Focus the intended field before pinning. `--window` takes the independently
verified top-level HWND, in decimal or `0x` notation. Focus must belong to that
window and process. TOTP fills use the same fresh-pin contract as Linux. Never
inspect a filled real credential to confirm delivery; check the application's
nonsecret outcome.

The default endpoint is `\\.\pipe\akdbx-USER_SID-SESSION_ID`. `--socket` accepts a
custom local `\\.\pipe\akdbx-NAME` endpoint for isolated tests. Remote named pipes
are refused. The pipe DACL restricts access to the user and SYSTEM, remote clients
are disabled, and each peer's user/session is checked from its native PID before
RPC data is sent or dispatched. Clients use identification-level security to avoid
granting a malicious pipe server impersonation rights. A first-instance check and
a continuously retained pipe instance prevent endpoint replacement during a run.
`--broker-uid` applies only to Linux and is rejected by the Windows client.

## Delivery contract

`status` advertises `password_fill_protocol: 1`, `password_fill_delivery:
"chromium-password-dom-v1"`, `password_browser_configured`, `cards_supported`,
`card_delivery: "cdp-card-element-v1"`, `card_browser_configured`,
`target_fill_delivery: "win32-char-v1"` and `target_fill_modes: ["username"]`.
The last value describes window pins only: they fill usernames and, through
`fill-totp`, authenticator codes.

DOM pins retain the actual elements, the native value setter and the document in
an isolated world. The broker never resolves a replacement by selector at fill
time, never sends a key, Tab or clipboard content, and never reads a value back.
Navigation, a focus change, a hidden page, a moved or removed field and an
expired token refuse delivery.

Window pins bind the native process creation time, user/session, top-level HWND,
focused HWND, GUI thread and window classes. The backend checks foreground/focus,
held keys/buttons and identity before and through dispatch. Unicode `WM_CHAR`
messages go only to the pinned HWND via bounded `SendMessageTimeoutW`. It never
uses global `SendInput`, clipboard contents, keystroke grabs, or text readback.
It refuses Tab sequences before sending a prefix. A failure after dispatch starts
is uncertain: do not retry automatically.

A receipt proves guarded dispatch, not application acceptance. Apps may ignore
synthetic messages, and a page may reject a value. A target application can
change its own internal destination; Windows metadata is not protection from a
malicious process running as the same user. Held process handles prevent PID
reuse during a capture/delivery, but no platform backend provides protection
from administrators or same-user compromise.

## Persistence contract

Saves hold trusted directory handles, reject reparse paths and unsafe DACLs, lock
the vault, recheck encrypted snapshots and optional key-file contents, reopen and
verify the candidate, retain an encrypted backup, and replace using
`MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH)`. Only encrypted KDBX files and
nonsecret recovery receipts are staged. A `prepared` receipt around replacement
blocks use after an uncertain save, including after restart. Preserve the target,
backup and receipt for recovery; do not simply delete a blocking receipt.
Unlock's final recovery scan and readiness checks use the same nonblocking lock
as saves and merges. The private folder must allow the broker's lock file. A
busy save makes writes temporarily unavailable or delays unlocking until a
retry, and does not mark recovery as failed. Malformed or oversized receipts
leave the broker in recovery-required state after a valid unlock; they are not
reported as an incorrect master password.
Keep other editors and sync writers away during
the entire save; advisory locks do not control them. The final snapshot check and
replacement are separate operations. An external edit between them can be lost,
and the retained backup may not contain that edit. This is not a claim of
power-loss safety on every storage device.

Unlock and card-save subscriptions are saved in
`%LOCALAPPDATA%\akdbx\PIPE_NAME.unlock-notifications.json`, or the file named by
`--notification-state`. The broker creates a missing folder for this user and
SYSTEM only, when it saves the first subscription. It refuses an existing
folder or file that another user can access, and it never repairs their
permissions.

## Merge and admission

`merge`, `admit` and `merge-status` follow the Linux contract in the skill's
[merge](../skills/akdbx/references/merge.md) and
[snapshot admission](../skills/akdbx/references/snapshot-admission.md)
references: the same request checks, receipts, verification order and failure
states. Snapshot admission keeps its review status: read that reference before
any use.

- **Engine.** The broker runs only
  `%ProgramFiles%\KeePassXC\keepassxc-cli.exe`, from the known-folder API and
  never from `PATH`. The engine, its folder and every ancestor must be owned by
  SYSTEM, administrators or TrustedInstaller, with no write, delete or
  permission right for another account. A per-user install or a portable copy
  is refused. The version must be 2.7.10 or newer, below 2.8; the extended
  admission group profiles need exactly 2.7.10. `status` reports
  `merge_available` and `merge_engine`.
- **Secrets.** The master password goes to the engine's standard input only.
  The engine's environment holds `SystemRoot` and nothing else, and its output
  is discarded. Windows has no anonymous sealed file, so a key file is passed
  by its own path: the broker first confirms that the file's bytes match the
  key it holds, and denies write and delete sharing for the whole run.
- **Files.** Each operation keeps its encrypted inputs, candidate and receipt
  in a private folder `.NAME.kdbx.akdbx-merge-ID` beside the vault, or in the
  bound snapshot folder for admission. Checked handles and DACLs replace the
  Linux descriptor checks. `MoveFileEx(WRITE_THROUGH)` replaces rename plus
  fsync.
- **Recovery.** An interrupted merge or admission blocks use after restart.
  A merge folder that this backend cannot read and verify, including one whose
  permissions another user could change, also blocks use. The admission
  locator beside the vault binds the snapshot folder; a missing or changed
  folder blocks use.
- **Crashes.** The broker sets the no-fault-dialog error mode, which the engine
  inherits. A dump policy that an administrator configured is outside the
  broker's control.

## Validation before production use

Run the native automated checks on the prepared Windows machine. Use a fresh,
short test path directly under `LOCALAPPDATA`. The broker checks permissions on
every parent directory, and some Windows installations allow other accounts to
modify the default `TEMP` directory. Pytest owns the directory passed to
`--basetemp` and clears it before starting.

```powershell
$testRoot = Join-Path $env:LOCALAPPDATA ('akdbx-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
.\.venv\Scripts\python.exe -m pytest -q -rs tests/test_protocol.py tests/test_windows_target.py `
  tests/test_windows_unlock.py tests/test_windows_native.py tests/test_windows_browser.py `
  tests/test_windows_chromium.py tests/test_windows_merge.py --basetemp "$testRoot"
```

`test_windows_chromium.py` starts Chrome or Edge headless with a new private
profile. It does not take the foreground and does not read an existing profile.
`test_windows_merge.py` uses the installed engine when it passes the production
checks. On a machine without that engine, set `AKDBX_TEST_ENGINE` to a verified
KeePassXC 2.7.10 `keepassxc-cli.exe`; the tests then replace only the install
location check. All values are synthetic, and the pages report only SHA-256
digests.

Recorded result (2026-11-19, Windows 11 Home build 26200, Python 3.11.9, akdbx
0.17.0, Chrome 157.0.8103.80, KeePassXC CLI 2.7.10): 223 of 224 cases passed
and one was skipped. The skipped case runs a separate broker process and needs
the engine installed for all users; hosted Windows CI installs it and runs all
224 cases.

| Area | Covered by the automated checks | Result |
| --- | --- | --- |
| DOM fills | Password, username and login fills to the pinned fields of a real page; untrusted `input` events only; focus unchanged; no key or Tab | Pass |
| DOM refusals | Wrong URL, scheme, fragment, page ID or frame ID; ambiguous, missing or non-password selector; missing or contradicting autocomplete hint; unfocused field; reused or expired token; focus, navigation, removal or type change after the pin; credential of another site | Refused; every field stayed empty |
| Child frames | Same-site iframe listed, pinned by its exact origin and filled; a login frame in a page of another site | Filled; cross-site chain refused |
| Window pins | Password and login fills to a window pin | Refused before the password is read |
| Account creation | `generate-entry`, two `fill-generated` fills, `commit-password --site-accepted`, then a login fill with the saved entry, in-process and through the installed CLI, named pipe and HTTPS unlock | Saved and reopened; digests match; no secret in CLI output or broker log |
| Rejected reset | Cancelled write, wrong target site, reused fill reference, commit without both fills or without site acceptance | Nothing filled; vault bytes unchanged |
| Cards | Private-page save with protected fields, then number, name, expiry and security code fills; non-card and password fields; login fill of a card | Filled only the pinned field; others refused |
| Browser endpoint | Malformed, oversized or missing port file; profile, file or parent that another user can change; hard link, junction, alternate stream, UNC path | Refused |
| Browser peer | Peer found before `accept`, in any table position; missing, duplicate, listener-only, client-only, closing or non-loopback rows; another user or session; reused PID; unavailable, oversized or slow table | Verified, or refused with no byte sent |
| Merge | Preview, save, repeat, receipt reuse, deletions, history, attachments, same-second conflict, `--refresh-target`, `--preserve-conflicts`, key file, races, faults at every stage, lock contention, interruption and restart | Pass; faults never claimed success |
| Admission | Exact-byte preview and save, external snapshots, locator binding, refusals with fixed diagnostics, unsafe or changed snapshot folder, interruption and restart | Pass |
| Notifications | Until-unlock subscription across a restart; public folder or file, malformed and oversized state | Restored and delivered; unsafe state refused, not repaired |
| Saves and pipe | Named pipe, DACL checks, encrypted saves, recovery receipts (unchanged from 0.15.0) | Pass |
| Extension route (0.21.0) | `test_extension_browser.py` in a disposable Helium 144 and Edge profile: host found through the browser's own registry key, agent list/pin/fill of password and login, Stripe processor frame, user-click popup fill; refusals for wrong origin, cross-site frame, hidden field, processor markup on another host, locked broker. `test_extension_route.py`: pairing, policy, framing and size limits | Pass |

Hosted Windows CI runs the same suites on every pull request and release tag.
It does not prove that a native application accepts directed window messages.

### Desktop acceptance check for window pins

The window-pin route did not change in 0.17.0. Its check takes the foreground
for about three minutes and fills a native Win32 window, then Chrome and Edge in
temporary profiles. Run it from an interactive, unlocked desktop; it asks for
OK first. Fixtures report only SHA-256 digests, and the JSON report contains no
credential values. It removes its private test directories when it finishes.

```powershell
.\.venv\Scripts\python.exe tests\windows_desktop_check.py --report evidence\windows-desktop.json
```

Last recorded result (2026-11-18, Windows 11 Home build 26200, Python 3.11.9,
akdbx 0.15.0, Chrome 157.0.8103.80, Edge 157.0.4341.60): 46 of 46 checks
passed. It has not been run again on 0.17.0. One check changed with this
version: a login fill on a broker without a password browser profile is now
refused by the CLI's capability check instead of by a platform rule.

| Checklist item | Covered by the desktop check | Result (0.15.0) |
| --- | --- | --- |
| 1. Fills | Usernames into a Win32 `EDIT` (ASCII, punctuation, non-ASCII), Chrome and Edge DOM fields; TOTP into all three | Pass |
| 1. Password refusal | Password fills to the same HWND pins, including emoji and punctuation values | Refused before any character; fields stayed empty |
| 2. Focus changes | Foreground switch to another app after pinning; focus moved to another field | Refused before any character |
| 3. Pins and targets | Background, wrong-PID and child-HWND pins; reused and expired pins; reused search handle; hung window; target exit | Refused; hung target reported `uncertain` and received no characters |
| 4. Saves | Private HTTPS password import with an independent reopen; generated password staged, its fills to HWND pins refused, commit refused and cancelled | Import saved with history and unrelated entries preserved; vault unchanged by the generated flow |
| 6. Secrecy | CLI output, broker log, receipts and lock file scanned for every synthetic secret | No secret found |

A TOTP fill near the end of a code period is refused with `retry_after` and
sends nothing. The check honours that response once, with a new search handle and
pin.

### Checks that need a person or a second account

These remain pending. Use only synthetic credentials:

1. Hold a key or mouse button during a window-pin dispatch. Check refusal or an
   uncertain result, with no automatic retry.
2. Pin an elevated window or a UAC prompt. Check refusal before any character.
3. Test with a second standard Windows user (checklist item 5): the pipe, the
   private files, the browser profile and the browser's debugging endpoint must
   be inaccessible or refused. Native CI covers unsafe DACLs, junction and
   alternate-stream refusal, external edits, concurrent writers and
   interrupted-save recovery for one user, and simulates a peer of another
   user; it does not replace this second-user test.
4. Fill each additional application or website you plan to use, and check its
   nonsecret outcome. Applications can ignore synthetic window messages, and a
   page can reject a value.
5. Run one DOM fill in the visible browser window that you will use. The
   automated checks use a headless browser, where the page always has focus. A
   visible browser must be the active window when a field is pinned and filled.

Record the Windows version, Python version and application versions with results.

API references: [named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[GetGUIThreadInfo](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getguithreadinfo),
[SendMessageTimeoutW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw),
[GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable),
and [MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).
