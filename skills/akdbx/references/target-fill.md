# Password field delivery

Saved and generated passwords require `chromium-password-dom-v1`. A browser
window pin cannot identify an address bar, DOM field, tab, or origin. The broker
therefore refuses password and login fills through `pin-target`, including old
clients. There is no password keyboard fallback.

## Operator configuration

The operator must explicitly configure `serve --password-browser-profile PATH`
or `AKDBX_PASSWORD_BROWSER_PROFILE`. PATH is the Chrome user data directory of
the intended browser, started with `--user-data-dir=PATH` and
`--remote-debugging-port=0` so it writes `DevToolsActivePort`. A fixed port does
not create that file for this transport. The broker never launches
or changes a browser, discovers profiles, or accepts an endpoint in an RPC.
The profile must be owned by the broker UID, mode 0700, with no symlink components.
Its bounded regular `DevToolsActivePort` must be owned by that UID and not writable
by group/others (launch Chrome with `umask 077`). The broker connects only to the
loopback browser websocket described by that file. Before its handshake, Linux
kernel metadata must identify the broker UID on the actual connected peer;
unverifiable ownership and redirects refuse. Protect this privileged CDP
interface and profile from other local users. Configuration is not proof of
protection against malicious processes running as the broker user.

Do not restart a live broker, alter its browser/profile, or deploy this source
repair without the owning workflow's authorization. Existing processes retain
their old code until an authorized update and restart.

## Caller workflow

1. Check `status` for integer `password_fill_protocol: 1` and
   `password_fill_delivery: "chromium-password-dom-v1"`, plus
   `password_browser_configured: true`.
2. Verify the selected account, exact HTTPS page URL, page ID, main-frame ID,
   and intended field with supported browser tools. Do not read a filled value.
3. Focus the intended password field, then pin it immediately:

   ```sh
   akdbx pin-password-target --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
     --top-url VERIFIED_EXACT_HTTPS_URL --selector '#password' --mode password
   ```

4. Use the returned single-use `target` within 30 seconds:

   ```sh
   akdbx fill --mode password --target TARGET -- FRESH_ENTRY_HANDLE
   ```

5. Require `ok: true`, the expected `filled` mode, and
   `target_delivery: "chromium-password-dom-v1"`. Submit through the authorized
   browser workflow and verify signed-in state. A receipt does not prove login.

`login` mode requires `--selector PASSWORD_SELECTOR --username-selector
USERNAME_SELECTOR --mode login`. Focus the username input first. The username
must be a text/email input with `autocomplete="username"`; the password must be
an editable visible input with type password and autocomplete `current-password`
or `new-password`. Both must belong to the same form
(or both have no form). Native setters fill both retained nodes without Tab,
focus changes, submit keys, or script callbacks between assignments. Input and
change notifications run only after both assignments. Pages that need trusted
keystrokes or a multi-step login must use separate supported fills or refuse.

For a username-only DOM fill, use `--mode username` and select the username
input. It also requires `autocomplete="username"`. Child frames, shadow DOM,
non-HTTPS pages, custom controls, hidden/disabled/read-only/inert fields,
ambiguous selectors, and profiles without the configured CDP interface refuse.
Do not weaken checks to work around refusal.

Each generated password and confirmation reference needs a fresh password-mode
DOM pin for its actual input, then `fill-generated --target-url VERIFIED_URL
--target TARGET -- REF`. The saved/generated entry's HTTPS origin must match the pinned
page. A failed or uncertain fill does not count toward `commit-password`.

## Race checks and limits

Each pin owns one CDP connection, isolated JavaScript world, and retained element
references. There are at most 16 pins, including captures in progress. Browser
pin I/O runs outside the vault lock; a separate lock protects token publication
and consumption. Expired pins are closed on the next pin or
consume; broker shutdown closes all remaining pins. Consumption closes the pin
on every outcome. Fill rechecks the page/frame identity, exact URL, document,
unique selector, same node, field type, visibility/editability, active element,
focus history, secure context, and foreground document. Navigation destroys the
old context; tab changes and field/focus changes invalidate the pin. Validation
and native assignment occur in one synchronous renderer task with no keys or
focus routing. Even a later focus switch cannot redirect a setter to the omnibox.

The page receives its password and may read or misuse it. A hostile target page,
compromised browser/OS, same-user process, or another debugging client is outside
this protection. CDP is privileged; do not log its messages. The broker returns
fixed errors and receipts, never values or native exceptions. `not-started` means
no assignment occurred; `uncertain` means assignment may have occurred. Do not
retry an uncertain fill automatically or read back a real password to check it.

## Remaining X11 operations

`pin-target --pid PID --window XID` remains available for username-only keyboard
fills and TOTP. These paths retain their existing PID/window/focus checks and
`x11-send-event-v1` receipts. They do not attest DOM fields or origins. In
particular, this password repair does not extend field protection to TOTP.
See [TOTP](totp.md). Never use username mode to deliver a password.
