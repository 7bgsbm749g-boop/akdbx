# Password and authenticator field delivery

For browser authenticator challenges, use `pin-password-target --mode totp`
with the CDP or extension route, then `fill-totp --target-url EXACT_CHALLENGE_URL`.
Require `browser_totp_protocol: 1`; extension also needs `extension_totp_protocol: 1`
and fill extension 0.10.0+. The same retained-node, focus, expiry, single-use and
same-site child-frame rules apply. Password and TOTP pins cannot cross modes.
Only one whole-code input is supported, with no keyboard/Tab/clipboard fallback.
See [TOTP](totp.md) for exact origin/URL checks, format limits and platform scope.


For contact and address fields, use [identity workflows](identities.md).
Identity pins use the same-origin card DOM transport with focused identity
fields and a separate pin and fill command.

Saved and generated passwords require `chromium-password-dom-v1`. A browser
window pin cannot identify an address bar, DOM field, tab, or origin. The broker
therefore refuses password and login fills through `pin-target`, including old
clients. There is no password keyboard fallback.

## Operator configuration

Before starting Chromium with remote debugging, verify that only trusted clients
can reach its loopback TCP port. On a shared Mac without verified isolation,
use the paired extension. See the [macOS CDP setup](https://github.com/7bgsbm749g-boop/akdbx/blob/main/docs/macos.md#chromium-cdp).

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
loopback browser websocket described by that file. Before its handshake, Linux and macOS kernel metadata must identify the broker
UID on the reciprocal established connection. macOS refuses extended allow
ACLs on profile paths and the port file. Windows verifies private DACLs and
requires the connected peer to share the broker user, desktop session and integrity level;
unverifiable ownership and redirects refuse. Protect this privileged CDP
interface and profile from other local users. Configuration is not proof of
protection against malicious processes running as the broker user.

### Agent desktop slots

On a host with several agent desktops, the operator starts the broker with
`serve --browser-profile-root ROOT` (or `AKDBX_BROWSER_PROFILE_ROOT`) instead of
one profile. Each slot `ROOT/slotN` is the Chrome user data directory of one
desktop, with the same launch rules as above. `status` shows
`browser_profile_root`, `browser_slots` and `browser_slots_live` (slots whose
Chrome publishes a valid `DevToolsActivePort`).

Every CDP pin then names the slot of the desktop you work in:
`--browser-slot SLOT` on `pin-password-target` (including `--mode read`),
`list-password-frames`, `pin-card-target` and `pin-identity-target`. Without
the option the CLI sends `$AGENT_DESKTOP_SLOT` to a broker that reports a root. If that variable is not set,
run `vps-agent-desktop current` to learn your slot. Never pick another slot,
and never guess one from `browser_slots_live`: that is another agent's Chrome.

Refusals name the cause and send nothing to a browser:

| Error | Meaning |
| --- | --- |
| `browser slot required: ... (slots: ...)` | The broker has a root and the request named no slot. Pass yours. |
| `browser slot invalid: ...` | Not a slot name (`slot1` … `slot99`); paths are never accepted. |
| `browser slot unknown: SLOT (slots: ...)` | No such slot folder under the root. |
| `browser slot not supported: ...` | The broker runs with one profile; omit the slot. |
| `browser slot applies only to the cdp route; ...` | The extension route takes no slot. |

A slot that exists but runs no Chrome gives the usual `target unavailable`
refusal. A pin stays in the Chrome it was made in: fill it with the usual
`fill`, `fill-card` or `fill-identity` (these take no slot).

**Window pins in a slot (0.35.3+, `target_slot_protocol: 1`).** A slot's
Chrome runs on the slot's own X display (for example `:101`), and the broker
runs on another one. `pin-target` for a username or TOTP field in that Chrome
takes `--browser-slot SLOT` too. Pass it explicitly (the CLI does not take it
from `$AGENT_DESKTOP_SLOT` for a window pin, because a native app on the
broker's display needs a pin without it):

```bash
akdbx pin-target --pid SLOT_CHROME_PID --window SLOT_CHROME_WINDOW --browser-slot SLOT
akdbx fill-totp HANDLE [--pending] --target-url 'https://example.com/two-factor' --target TARGET
```

The broker takes the slot Chrome's PID from the profile lock (`SingletonLock`)
and checks that this process is ours and runs exactly that profile. It then
finds the one local X display of this user where that PID is a connected
client. It opens that display only as a Unix socket whose peer is an X server
of this user, and sends that server's own `-auth` cookie only after it checks
the peer. `--pid` must be that Chrome's
browser PID, and the window must be its focused, active top-level window on
that display, as for every window pin. The receipt adds `browser_slot`. The
pin and the fill both stay on that display. A slot with no running Chrome
refuses with `browser slot not running: SLOT has no verified Chrome on a local
X display; start the slot and pin again`. A PID, window or focus of anything
else refuses with `target unavailable` and sends no key.

For a reset, each `fill-generated --target-url VERIFIED_URL --target TOKEN -- REF`
needs its own fresh pin after independently focusing that field. A failed or
partial generated fill does not count toward the two successful fills needed
for `commit-password --site-accepted` (one fill for a write staged with
`--single-field`; see [password writes](password-writes.md#form-with-one-new-password-field-0310)).
Do not commit until the site accepts it.

Do not restart a live broker, alter its browser/profile, or deploy this source
repair without the owning workflow's authorization. Existing processes retain
their old code until an authorized update and restart.

## Exact URL with a private token

`--top-url` and `--frame-url` must be the exact observed page URL. The broker
compares the full URL, including any query and fragment. An origin or a
sanitized URL does not authorize the page. Never change the live URL to get
past the check.

If the URL contains a reset token, an activation or verification code, or
another private value, do not put it in a command argument, a log or a note.
Do not ask the user. Use the private file form, which `pin-password-target`,
`list-password-frames`, `pin-identity-target` and `pin-card-target` accept
(akdbx CLI 0.28.4 or newer; the broker needs no change):

1. Write the exact observed URL, on one line, to a new mode-0600 file in a
   private directory. Do not print it. Prefer a direct transfer: redirect
   the browser tool's URL output into the file (`BROWSER_URL_COMMAND >
   FILE`), so the URL is in no tool input and no displayed result. Use a
   file-writing tool only when your browser tool already showed you the URL;
   it is then in your transcript already, and the file tool adds no new copy
   for other processes or logs. Never put the URL in a command argument (for
   example not `echo URL > FILE`), and never repeat it in a reply or note.
2. Pass `--top-url-file FILE` in place of `--top-url`, and
   `--frame-url-file FILE` in place of `--frame-url`. The plain flag and its
   file form are mutually exclusive. The CLI reads the file and sends the URL
   to the broker unchanged. No output or error from the CLI contains the URL.
3. Delete the file after the pin (and after `list-password-frames`).

For the configured password browser profile (with slots:
`ROOT/$AGENT_DESKTOP_SLOT`), Chrome's read-only `/json/list` is a direct transfer. Give only the token-free origin and path. The filter
takes the one page tab whose URL is that path, or that path followed by `?` or
`#`; two or more such tabs refuse. It writes the tab's exact URL to the file
and prints only the page ID:

```sh
umask 077
url_dir=$(mktemp -d)                       # private directory, mode 0700
port=$(head -n 1 "$PASSWORD_BROWSER_PROFILE/DevToolsActivePort")
curl -q -sf "http://127.0.0.1:$port/json/list" | python3 -I -c '
import json, sys
base = sys.argv[1]
tabs = [t for t in json.load(sys.stdin) if t.get("type") == "page"
        and (t.get("url") == base or t.get("url", "").startswith((base + "?", base + "#")))]
if len(tabs) != 1:
    sys.exit("need exactly one tab for this page; no URL written")
sys.stdout.write(tabs[0]["url"])
print("page_id", tabs[0]["id"], file=sys.stderr)
' 'https://site.example/user/activate' > "$url_dir/top-url"
akdbx pin-password-target --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
  --top-url-file "$url_dir/top-url" --selector '#password' --mode password
rm -rf -- "$url_dir"
```

Check that the printed page ID is the tab you verified. If the filter fails,
the file stays empty and akdbx refuses it.

The CLI refuses, before it sends any request, a file that is missing,
unreadable, a symlink, not a regular file, not owned by you, open to other
users (group or other mode bits), empty, larger than 4096 bytes, or not one
URL on one line, or not UTF-8 without a byte order mark. On Windows the file
must be a private file of the current user, as for other akdbx private input
files; Windows PowerShell 5.1 redirects and `-Encoding utf8` add UTF-16 or a
byte order mark, so write it with `[IO.File]::WriteAllText(FILE, URL)` from a
variable, never with the URL in the command text.

`fill-generated --target-url` and `fill-totp --target-url` compare only the
origin. Pass the observed origin there, for example
`https://example.test/`; these commands do not need the token.

## Caller workflow

1. Check `status` for integer `password_fill_protocol: 1` and
   `password_fill_delivery: "chromium-password-dom-v1"`, plus
   `password_browser_configured: true`.
2. Verify the selected account, exact HTTPS page URL, page ID, main-frame ID,
   and intended field with supported browser tools. Do not read a filled value.
   For a form inside an iframe, use the [child-frame route](#child-frames-iframes).
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
input. It also requires the `username` field token. Without the explicit
child-frame route below, child frames refuse. Shadow DOM,
non-HTTPS pages, custom controls, hidden/disabled/read-only/inert fields,
ambiguous selectors, and profiles without the configured CDP interface refuse.
Do not weaken checks to work around refusal.

## Child frames (iframes)

Some sign-in forms are inside an iframe, for example an identity provider's
widget or a `secure.` subdomain. Broker 0.16.0 and newer advertise integer
`password_frame_protocol: 1` and `password_frame_policy: "same-site-chain-v1"`.
Check both in `status`. The CLI refuses an older broker before it sends a
frame request. Password, login and username modes, saved and generated
passwords, `--password-purpose` and `--allow-autocomplete-off` work the same
way in a child frame.

### Get the page and frame IDs from the broker

Browser automation tools do not show CDP IDs. Do not read raw CDP. Ask the
broker for a read-only list of the tab's frames:

```sh
akdbx list-password-frames --top-url VERIFIED_EXACT_HTTPS_URL [--page-id PAGE_ID]
```

`--top-url` is the exact top-level URL that you verified in the address bar.
Without `--page-id`, exactly one open tab must have this exact URL; otherwise
the command refuses. You can then get the page ID from Chrome's read-only
`/json/list` as before, and give it with `--page-id`. The result contains:

- `page_id` and `main_frame_id`;
- `frames`: for each frame, `frame_id`, `parent_frame_id`, `depth`, `origin`,
  `out_of_process`, `eligible` and `visible_fields` (counts of visible password
  and text/email inputs; never values);
- `frame_policy` and `truncated`.

The list never contains frame URLs, paths, queries, page-controlled names or
field values. It does not read the vault, so it works while the vault is
locked. `eligible: true` means only that the frame chain passes the policy
below; it does not prove that the frame is the intended form. Select the frame
whose `origin` matches the saved credential and which has the expected visible
fields. If two eligible frames have that origin and fields, stop: the target is
ambiguous.

### Pin and fill

Focus the intended input inside the frame, then pin it at once:

```sh
akdbx pin-password-target --page-id PAGE_ID --frame-id CHILD_FRAME_ID   --frame-origin https://secure.example.com   --top-url VERIFIED_EXACT_HTTPS_URL --selector '#password' --mode password
akdbx fill --mode password --target TARGET -- FRESH_ENTRY_HANDLE
```

`--frame-origin` is the exact serialized origin from the list:
lowercase `https://host`, with `:port` only for a port other than 443, and no
path or slash. `--top-url` stays the exact top-level page URL, not the frame
URL. The selector applies inside the child frame's document. A main-frame pin
must not use `--frame-origin`; a child frame without `--frame-origin` refuses.

### How the broker verifies the route

The broker reads the tab's frame tree itself, including out-of-process iframe
targets, and requires all of these at pin time and again at fill time:

1. The page target and top frame have the exact `--top-url`.
2. The frame ID exists and is attached below that page, at most 8 levels deep.
3. Each document in the chain, from the top page to the field frame, is an
   HTTPS secure context with a non-opaque origin that matches its URL.
4. All documents in the chain have the same registrable domain, as Chrome
   computes it with the public suffix list (`domainAndRegistry`). If the hosts
   have no registrable domain (for example IP addresses), every document must
   have the same exact origin.
5. The field frame's origin equals `--frame-origin`.
6. Each frame owner is a connected, visible `<iframe>` in its parent document.
   It must not be in a shadow root, use `srcdoc`, or have a `sandbox` attribute
   without both `allow-scripts` and `allow-same-origin`. The broker keeps each
   owner element and refuses if it moves, hides, is removed, or changes its
   `src`, `srcdoc`, `sandbox`, `allow`, `name` or `credentialless` attribute.
   A change refuses also when the old state is restored later. The list marks
   a frame `eligible` only when its owners pass these same checks.
7. The exact frame URLs, frame IDs, parent IDs and hosting targets stay the
   same. Navigation of the page or of any frame in the chain refuses, also when
   the URL is restored later.

At fill time, the saved or generated credential's origin must equal the field
frame's origin. A match with only the top page or only the site is not
sufficient. All main-frame field checks then apply inside the frame: retained
node, exact frame URL and origin, focus and focus history, visibility,
autocomplete rules, 30-second expiry, single use, native setters and no keys.

### Phishing cases

- A legitimate page that embeds a frame from another site (an ad or a
  hostile frame): rule 4 refuses the route, and rule 5 plus the credential
  origin check refuse a frame of another origin.
- A hostile top page that embeds the legitimate login frame: rule 4 refuses,
  because the top page has a different registrable domain. The password
  never goes to a frame that a cross-site page controls.
- A hostile frame between a legitimate top page and the login frame: rule 4
  refuses.
- A sandboxed frame without scripts, or with an opaque origin: rules 3 and 6
  refuse.

A same-site page can still embed or cover a same-site frame. Same-site pages
are inside the trust boundary of the site's own credential. The owner check
compares visibility and attributes before the fill call; the owner is in
another document and maybe another process, so a change in that short time is
not proven. The value can reach only the retained input in the verified frame.

The private exact-URL limit also applies to `--top-url`. The broker keeps the
frame's exact URL internally; the caller does not give it, and the broker does
not show it.

### Additional exact origins (0.18.0)

The field frame's origin must equal the saved credential's main URL origin or
one of its KeePassXC/KeePass2Android additional URLs (custom string fields
`KP2A_URL`, `KP2A_URL_1`, `KP2A_URL_2`, …). Broker 0.18.0 advertises integer
`additional_urls_protocol: 1` and `additional_urls_policy:
"kp2a-exact-origin-v1"`. Search returns the valid ones as `additional_urls`.
Each value counts only as its exact `(https, host, port)` origin; http values,
wildcards, unparsable text and credentials in a URL grant nothing. The same
rule applies to main-frame pins, to `fill-totp --target-url` and, from
0.31.2 (status `generated_additional_urls: true`), to `fill-generated
--target-url` for an existing entry. A `generate-entry` write has only its
main URL.

If the main URL is `https://example.com/` and the login iframe is
`https://secure.example.com`, the fill refuses until the user authorizes
adding that origin:

```bash
akdbx add-url --url https://secure.example.com/ -- FRESH_HANDLE
```

`add-url` and `remove-url` are metadata-only writes (see
[password writes](password-writes.md#additional-urls-0180)). They accept only
an exact HTTPS origin on the saved URL's site (same registrable domain).

Why exact origin is still required: browsers isolate documents by origin, not
by site. Another host or port on the same site can be a separately operated
service, a user-content host or a compromised legacy app. Matching a site or a
suffix would give the password to every such document. An explicit list keeps
each extra origin a deliberate, reviewable decision. Listing an origin does
not relax the frame rules: a cross-site frame chain still refuses, even when
the user has listed a cross-site origin in KeePassXC.

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
account, exact HTTPS main-frame URL (with `--top-url-file` if it holds a token),
password field purpose,
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
--target TARGET -- REF`. The `--target-url` origin must be the entry's main
URL origin or one of its exact additional URL origins, and the pinned field
document must have exactly that origin (for a child-frame pin, pass the
frame's origin). A failed or uncertain fill does not count toward `commit-password`.

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

After 0.47.0, Linux and Windows brokers list the numeric window operations in
`target_fill_modes: ["username", "totp", "sms-code"]`. These correspond to
`fill --mode username`, `fill-totp` and `fill-sms-code`.

On Linux, `pin-target --pid PID --window XID` requires a window on the broker's
X display (or the selected slot's display), X-Resource 1.2 local PID support,
and a window manager that publishes `_NET_ACTIVE_WINDOW`. This includes
XWayland when the compositor provides those checks. A native Wayland surface
has no XID. Virtual keyboards and remote desktop input follow compositor focus
and cannot bind key delivery to that surface. Use a [native field pin](native-fields.md)
for supported native controls. The SMS fallback for split inputs also requires
an X11 or XWayland window on Linux. These paths retain their existing PID/window/focus checks and
`x11-send-event-v1` receipts. They do not attest DOM fields or origins. In
particular, this password repair does not extend field protection to TOTP.
See [TOTP](totp.md). Never use username mode to deliver a password.

## Extension route (0.21.0)

Every DOM pin in this guide can also go through the paired akdbx browser
extension instead of a debugging port: add `--route extension` to
`list-password-frames` and `pin-password-target`. The pin rules are the same;
receipts carry `target_delivery: "extension-dom-v1"`. Read
[the extension route](extension.md) for pairing, capabilities and limits.
