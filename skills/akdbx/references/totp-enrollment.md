# Automatic authenticator enrollment (0.35.0)

Before using CDP, verify [client isolation](target-fill.md#operator-configuration).

Use this when the user authorized adding an authenticator app (TOTP) to a
website account, for example GitHub's **Set up authenticator app**. The broker
reads the setup key from the enrollment page itself, saves it to the correct
vault entry, fills the site's confirmation code, and then makes the key the
entry's authenticator. The user does not open a private page, click the
extension, copy a key or approve again. The agent never sees the key or a code.

This changes the site's security settings. Do it only when the task authorizes
the enrollment for this account. Do not remove another 2FA method, a phone app
or recovery options to finish it.

## Requirements

`akdbx status` must show integer `totp_capture_protocol: 1` (CLI and broker
0.35.0 or newer), `totp_protocol: 1`, and a read-pin route:

- CDP route: `secret_capture_protocol: 1` and `password_browser_configured: true`;
- extension route: `extension_capture_protocol: 1` and a paired extension.
  A setup key printed in space-separated groups needs extension 0.6.0 or newer
  (an older one reads only a key printed as one token).

Use a browser read pin to capture the setup key. A native read pin has only
the caller's `--service-url`. The OS identifies the control but cannot verify
the website origin. The broker consumes the native pin and refuses capture
before reading the control.

Extension read pins require the top document. The extension cannot verify
the text's exact position and visibility through padded or transformed iframe
owners. For a supported same-site child frame, use the CDP read route.

The pending code fill uses the same TOTP pins as a saved code: retained DOM
pins on CDP (Linux/Windows/macOS), the paired extension (Linux/Windows/macOS), native
field pins (Linux X11/Wayland and supported Windows controls), or Current Window
pins on Linux X11/Windows. Browser pins require integer
`browser_totp_protocol: 1`; extension pins also require integer
`extension_totp_protocol: 1` and fill extension 0.10.0 or newer. See
[TOTP delivery](totp.md#capabilities-and-selection) for route-specific checks.

For Current Window on an agent desktop slot (`status` shows `browser_profile_root`), the slot's
Chrome runs on the slot's own X display, not the broker's. Pin its window with
`--browser-slot SLOT` (0.35.3+, `target_slot_protocol: 1`; pass it explicitly,
for example `--browser-slot "$AGENT_DESKTOP_SLOT"`): the broker finds that slot's Chrome from its
profile lock and the X display where that Chrome is connected, and `--pid` must
be that Chrome's browser PID. Without it the pin opens the broker's display and
refuses with `target unavailable`.

## How the key stays safe

- `capture-totp` saves the key as the entry's **pending** authenticator, a
  protected field beside `otp`. The entry's `otp` field does not change. A
  failed enrollment, a second attempt or a wrong element cannot remove the
  authenticator the entry already has.
- The page's origin must be the entry's main URL origin or one of its
  additional URLs, and the four metadata values must match the entry exactly.
- The entry needs a title, a username (the account; it labels a bare key) and
  an HTTPS URL, as for `setup-totp`.
- The value must parse as a supported TOTP setup: a Base32 key (one token or
  groups such as `abcd efgh ijkl mnop`) or an `otpauth://totp/` URI. Other text
  refuses with `nothing saved`.
- `commit-totp --site-accepted` moves the pending key into `otp`. If `otp`
  already holds a key, `--replace` is required; the old key stays in the
  entry's encrypted history.
- Receipts carry no key and no code.

## Never look at the setup key

The rules of [secret capture](secret-capture.md#never-look-at-the-secret)
apply. After the site shows the QR code or the setup key, take no screenshot,
accessibility snapshot, text dump, `innerText`/`value` read, clipboard copy or
recording of that page. Do not click a copy button. Find the element from
structure only (tag, `id`, classes, position next to fixed labels such as
"setup key"); a structural query may return counts, tags, ids, class names and
boxes, never text. Do not select or drag over the text.

## Steps

1. Select the account's existing entry: `akdbx search github.com`. Use the
   entry of this website account (not a Google or SSO identity entry). Note its
   exact title, username, URL and group.
2. On the site, sign in and open the enrollment step (GitHub: **Settings >
   Password and authentication > Two-factor authentication**, then the
   authenticator app setup). Verify the account name from fixed page text
   before the key is shown.
3. Show the key as text. GitHub shows a QR code and a **setup key** link under
   it; click the link. The key then shows in a dialog. Plan the selector before
   this click.
4. Focus the element that shows the key by script (for a non-focusable
   element: `element.tabIndex = -1; element.focus()`, returning nothing), then
   pin it:

   ```bash
   akdbx pin-password-target --mode read --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
     --top-url EXACT_HTTPS_URL --selector 'SELECTOR' [--route extension]
   ```

5. Capture it into the entry, with a fresh search handle and the exact metadata:

   ```bash
   akdbx capture-totp --target TARGET --handle HANDLE \
     --title TITLE --username USERNAME --url URL --group GROUP
   ```

   Receipt: `{"ok": true, "state": "pending", "totp_configured": false,
   "metadata": {...}, "capture_delivery": "chromium-dom-read-v1"}`
   (`"extension-dom-read-v1"` on the extension route). `totp_configured: true`
   means the entry already has an authenticator; it is still unchanged.
   `search` now shows `totp_pending: true`.
6. Close the key dialog if the site needs it, focus the site's code field
   (GitHub: "Verify the code from the app"), and fill a code of the pending key:

   ```bash
   akdbx pin-password-target --route extension --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
     --top-url 'EXACT_HTTPS_URL' --selector '#otp' --mode totp
   akdbx fill-totp FRESH_HANDLE --pending --target-url 'EXACT_HTTPS_URL' --target FRESH_TARGET
   ```

   Use `--route cdp` for a configured CDP browser; add `--browser-slot SLOT`
   when needed. For a child challenge frame, add `--frame-origin ORIGIN` and
   its frame ID; the fill's target URL is that exact child challenge URL.
   Current Window can instead use `pin-target --pid VERIFIED_PID --window
   VERIFIED_WINDOW` (plus `--browser-slot SLOT` for an agent desktop slot).

   On `retry_after`, wait that many seconds, then take a fresh handle and pin.
   Submit if the site needs a click, then check the site's non-secret result
   (GitHub moves to the recovery codes step).
7. When the site accepted the code:

   ```bash
   akdbx commit-totp --handle FRESH_HANDLE --site-accepted \
     --title TITLE --username USERNAME --url URL --group GROUP [--replace]
   ```

   Receipt: `{"ok": true, "state": "saved", "replaced": false, "metadata": {...}}`.
   `search` now shows `totp_configured: true` and no `totp_pending`. Later
   sign-ins use the normal `fill-totp` without `--pending`.

If the site refused the code, do not commit. Check the clock, then try one more
fresh code. If the site starts the enrollment again with a new key, capture
again (steps 3 to 5): the new capture replaces only the pending key. To stop,
remove the pending key with `commit-totp --discard` (same handle and metadata
options); `otp` stays as it was.

Run one enrollment per entry at a time. A commit takes the key that is pending
now, so a second capture for the same entry replaces the key of the first.

If a capture or commit response is lost, search the entry first
(`totp_pending`, `totp_configured`) before any retry. If the site accepted the
code but the commit failed, the key is still pending in the vault: run
`commit-totp --site-accepted` again with fresh handles. Do not restart the
enrollment on the site because of a lost receipt.

## Recovery codes and other steps

Enrollment pages often show recovery codes next. They are secrets: do not read,
copy, screenshot or put them in notes. Leave that step to the user, or use the
site's own download button only when the task authorizes it, and tell the user
the file's location without opening it. Push approvals, SMS, passkeys and
device checks are separate and can still need the user.

## Report

Report the site, the account, and the verified results: the site accepted the
code, and the commit receipt is `state: saved`. Never report the key, a code or
a recovery code.
