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
not create that file for this transport. For Chrome 136 and later, PATH must be
a non-default user-data root; explicitly naming Chrome's default data directory
is unsupported. A profile named `Default` within a custom root is a separate
concept. The broker never launches
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

## Exact URL privacy limitation

`pin-password-target --top-url` must receive the exact observed page URL;
the broker compares the full URL, including any query and fragment. Supplying
only an origin or sanitized URL cannot authorize that page. The CLI has no
private file/stdin input for this URL. If it contains a reset token, verification
code, or other private value, this CLI pin workflow is unsupported: do not put
that value in command arguments, logs, or notes, or change the live URL to bypass
the check. Continue only if the site's normal authorized flow provides a
verified password page with a secret-free exact URL; otherwise report this
limitation and refuse the fill.

## Caller workflow

1. Check `status` for integer `password_fill_protocol: 1` and
   `password_fill_delivery: "chromium-password-dom-v1"`, plus
   `password_browser_configured: true`.
2. Verify the selected account, exact HTTPS page URL, page ID, main-frame ID,
   and intended field with supported browser tools. Do not read a filled value.
3. For password mode, focus the intended password field, then pin it immediately:

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
must be a text/email input with autocomplete field token `username`; the password
must be an editable visible input with type password and field token
`current-password` or `new-password`. Both must belong to the same form
(or both have no form). Native setters fill both retained nodes without Tab,
focus changes, submit keys, or script callbacks between assignments. Input and
change notifications run only after both assignments. Pages that need trusted
keystrokes or a multi-step login must use separate supported fills or refuse.

Autocomplete uses the [HTML ordered token grammar](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofilling-form-controls:-the-autocomplete-attribute):
an optional `section-*` token, optional `shipping` or `billing`, the required
field token, then an optional final `webauthn`. For example,
`current-password webauthn` and `section-login username webauthn` are supported.
Tokens are ASCII case-insensitive and separated by ASCII whitespace. Unknown,
conflicting, repeated or misordered tokens, `on`/`off`, and lists over 4096
characters refuse. Capture and the final synchronous check parse the raw
attribute with a captured native getter; browser property normalization cannot
hide duplicate tokens.
Delivery does not rewrite attributes; never alter a page to bypass refusal.

For a username-only DOM fill, use `--mode username` and select the username
input. It also requires the `username` field token. Child frames, shadow DOM,
non-HTTPS pages, custom controls, hidden/disabled/read-only/inert fields,
ambiguous selectors, and profiles without the configured CDP interface refuse.
Do not weaken checks to work around refusal.

### Password inputs without semantic autofill hints

Some login forms omit `autocomplete` or set it to `on`. The default still
refuses these fields. With integer `password_purpose_protocol: 1`, a caller who
independently verified the field's purpose can use password-only mode with
`--password-purpose current-password` (sign-in) or `new-password` (an authorized
password creation/change). Verify the exact HTTPS URL, main frame, unique
selector, visible editable `type=password` input and current focus first.
Fill any username separately; this option is refused in username and login modes.

The option accepts only missing/empty hints or the single token `on`, or a valid
semantic token list whose password purpose matches the declaration. It never
overrides `off` on its own, unknown/malformed/duplicate hints, conflicting purposes,
non-password inputs, hidden fields, ambiguous selectors or focus changes.
The raw password hint must remain unchanged between capture and fill. All
normal origin, retained-node, navigation, focus, deadline and single-use checks
remain in force, and delivery still uses the broker's DOM setters. Do not add
or rewrite site attributes. Check the capability before sending this option;
an older broker must be upgraded through its owning deployment workflow.

### Explicitly verified password fields with autocomplete off

Some account forms use `autocomplete="off"` even on standard password inputs.
Require broker 0.14.1 or newer and integer
`password_autocomplete_off_protocol: 1`. After independently verifying the
account, exact secret-free HTTPS main-frame URL, password field purpose,
unique selector and current focus, add `--allow-autocomplete-off` to a
password-only pin with `--password-purpose current-password` or `new-password`.
The CLI refuses an older broker before requesting the pin. The new option is
not valid in username/login modes or without an explicit password purpose.

This accepts only the single `off` token in addition to the hints already
supported by explicit purpose. It does not override malformed/duplicate hints,
a conflicting password purpose, field type, visibility, node identity, focus,
navigation, expiry or single-use checks. Never rewrite page attributes to
make a field eligible. Any raw hint change, including changing it and restoring
it, invalidates the retained pin. Use fresh pins for password and confirmation,
and verify non-secret site acceptance before committing a generated password.

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
