# Browser extension route (0.21.0; origin trust 0.29.0)

The extension route is a second delivery route next to the Chrome DevTools
Protocol (CDP) route. A browser extension in the user's everyday browser
fills the field, reached through a native-messaging host:

```text
CLI/agent -> broker -> native-messaging host -> akdbx extension -> retained DOM element
```

Prefer this route whenever the extension is paired. It needs no
remote-debugging port, which would give every process of the same user full
control of the browser profile. It also runs in the user's real browser, with
its normal history and sessions. Anti-bot and anti-fraud checks often misfire
on a debugging-port browser and refuse genuine use (in practice: Cloudflare's
sign-in check failing, and Stripe returning `generic_decline` for a valid card
before the bank saw it). The same tasks pass in the user's own browser. When a
check like that blocks the CDP route for the user's own account and data, stop
retrying there and use this route.

The extension is the user's browser, not a disguise. Do not use it to
impersonate anyone, to get past a block a site applied to this user or account
on purpose, or with someone else's account or card.

Windows, Linux and macOS support Helium, Google Chrome, Microsoft Edge and
Firefox 153+ (0.47.0+). From 0.49.0, the installer also accepts Chromium and
Brave. See `extension_host_browsers` in broker status. The Chromium family uses the fixed ID `jjoamaejjkldcjcpgncoomoaagdfimhg`;
Firefox uses `akdbx@akdbx.org`. Both use host name `org.akdbx.extension`.
See [Firefox setup and installation limits](../../../docs/firefox.md).

## Capabilities

Require these values in `status` before you use the route:

| Key | Value |
| --- | --- |
| `extension_protocol` | `1` |
| `extension_delivery` | `"extension-dom-v1"` |
| `fill_routes` | contains `"extension"` |
| `extension_connected` | `true`: a host is attached |
| `extension_paired` | `true`: the user approved this browser session |

`default_fill_route` is `"cdp"` unless the operator started the broker with
`serve --default-fill-route extension` (or `AKDBX_DEFAULT_FILL_ROUTE`).
On macOS it defaults to `"extension"`, with CDP available for configured Chromium profiles from 0.50.1.
`extension_browsers` lists attached browsers and whether each is paired.
Each item also has the extension version that browser loaded and how it
compares with this broker (see [Extension version](#extension-version)).
While a browser is not paired, `extension_pairing` gives its code and private
pairing link. The existing `password_fill_delivery`, `card_delivery`,
`identity_delivery` and `code_delivery` values still describe the CDP route;
receipts of this route carry `"extension-dom-v1"` in the same keys.

## Extension version

The extension has its own version (from 0.1.0), separate from the akdbx
package version. `status` shows:

| Key | Value |
| --- | --- |
| `extension_version_expected` | The version this akdbx build writes, for example `"0.7.1.12345"` (0.35.2+; before: `"0.7.0"`) |
| `extension_browsers[].version` | The version the loaded extension reported, or `null` |
| `extension_browsers[].version_status` | `"current"`, `"outdated"` (older, or no version), `"newer"`, or from 0.35.2 `"stale"` (an old worker beside newer files) and `"mismatch"` (another build than this broker's) |

From akdbx 0.35.2 (extension 0.7.1) `akdbx extension build` adds a fourth
version part from the built contents: `MAJOR.MINOR.PATCH.N`, where N is the
first 16 bits of SHA-256 over the built files (config.js excluded). Only
MAJOR.MINOR.PATCH orders versions; N names the contents. `extension build`
and `extension info` print the four-part version, and chrome://extensions
shows it. A broker or host launcher from akdbx 0.35.1 or earlier refuses the
four-part hello (the popup says the broker is not reachable): restart the
broker on the updated akdbx, and run `akdbx extension refresh` (or
`install`) from it.

An extension built by akdbx 0.21.2 or earlier reports no version. It still
attaches and works, with `version: null` and `version_status: "outdated"`.
akdbx 0.21.3 shipped the extension as 1.0.0; from 0.21.4 the numbering starts
again at 0.1.0, so a browser that still runs the 1.0.0 copy shows `"newer"`.
In both cases, build the extension again and reload it. The popup shows the
version in its footer (**akdbx extension 0.1.0**); an extension without that
footer was built by akdbx 0.21.2 or earlier. `akdbx extension build` and
`akdbx extension info` also print `extension_version`.

When a browser shows `outdated`, the unpacked copy in that browser is stale
after an akdbx update. Tell the user; do not reload it for them. The user
rebuilds into the same folder and reloads:

1. `akdbx extension build --output SAME_FOLDER_AS_BEFORE`
2. In `chrome://extensions`, click the reload button on the akdbx card.
3. Pair again from the popup if it asks.

`newer` means the broker is older than the extension: restart the broker on
the updated akdbx.

### Stale service worker (0.35.2+)

Chrome keeps a registered extension service worker, with the scripts it
imported, until the manifest `version` changes or the extension reloads. A
browser restart alone does not replace it. Content scripts and injected
files come from disk. So when a build with other contents but the same
version went into the loaded folder (a development or worktree build), the
browser ran the old worker beside the new content script. Seen on
23 November 2026 with extension 0.5.0 in Chrome 153: `pin-password-target
--route extension` worked, then every `fill` and `fill-generated` returned
`autofill not started: target unavailable, changed or unsupported; pin
again`, while `status` showed `version_status: "current"`.

From 0.35.2:

- The content stamp (fourth version part) changes the version for any other
  contents, so a browser restart loads the new worker.
- The worker reports the version from its own config.js, which Chrome caches
  with it, not the manifest on disk. The broker shows `version_status:
  "mismatch"` when that version has the same MAJOR.MINOR.PATCH as its own
  build but another (or no) fourth part: the browser loads other contents
  than this akdbx builds.
- Before each frame list and pin, the worker reads manifest.json on disk. If
  the folder holds a newer build, it answers `stale` and reloads itself once
  for that build (`chrome.runtime.reload()`). If the worker after that reload
  still runs old code, it does not reload again and tells the broker
  (`stale: true` in its hello).
- A stale or mismatched worker gets no frame list and no pin. A frame list
  without `--page-id` still lists the page in another paired browser when
  only that browser has the URL open; if the refused browser has it open
  too, the list fails with the refusal, never with the other browser's tab.
  A stale worker
  (`version_status: "stale"`) gets `extension route unavailable: the browser
  runs an older akdbx extension service worker than the extension files on
  disk (stale build); restart the browser, or reload akdbx on
  chrome://extensions, then pair it again`. A mismatched one gets `…the
  browser runs akdbx extension X, another build than this broker's Y; rebuild
  the folder the browser loads with this akdbx and the broker's private-page
  origin (the origin of its unlock link): \`akdbx --unlock-origin ORIGIN
  extension build --output FOLDER\`, or restart the broker if akdbx was
  updated; then reload akdbx on chrome://extensions and pair it again`.

Fix: restart the browser, or click reload on the akdbx card in
`chrome://extensions`. Keep Developer mode on there: with it off, Chromium
blocks an unpacked extension when it reloads ("blocked by Chromium"), also
after the worker's own reload. Then pair again: a reload, also the worker's own
reload, ends the pairing, because the pairing key lives in session storage.
Every `extension build` also writes a new random build ID, and a reloaded
worker drops the broker trust saved under another build. So expect a new
pairing after every rebuild that the browser loads. A content-identical
rebuild gets the same version, so a restart keeps the running worker, but a
reload still needs a pairing. Rebuild only when `extension info` shows
another `extension_version` than the folder's manifest.

## Pairing

The extension keeps an ECDH P-256 key pair in browser session memory only and
sends only the public key. The broker keeps only a digest of that public key,
for its own lifetime. A browser restart or a broker restart needs a new
pairing. Pairing is the user's step:

1. The user clicks the akdbx extension button. The popup shows a code such as
   `ABCD-EFGH`, computed from its own public key, and an **Open the pairing
   page** button.
2. The private page (`/extension/pair?token=...` on the unlock origin) shows
   the same code and asks for the master password. When the broker is locked,
   the same entry also unlocks it.

You can give the user the `extension_pairing` link from `status`, as you give
an unlock link. Never ask for the master password, and never open or operate
the pairing page for the user. After a successful pairing the page heading is
**Successfully paired** (0.33.0).

Do not ask the user to say "paired". From 0.33.0, register a one-shot webhook
with `subscribe-pairing --code CODE` (in T3: a webhook task bound to the
current thread) and end the turn. The broker posts `akdbx.extension-paired`
when that browser is paired and connected. Steps:
[pairing notifications](pairing-notifications.md).

### Reconnects and what ends a pairing

The pending link and the pairing belong to the extension's key, not to one
native-host connection. The key stays in browser session memory while the
extension's service worker stops and starts again. So:

| Event | Pending link | Established pairing |
| --- | --- | --- |
| The service worker goes idle and restarts, or the host reconnects | Still works, same code and link | Kept: the next connection is paired |
| The user pairs while the extension is not connected | Works; the extension is paired when it reconnects, and the pairing event comes then | - |
| Ten minutes pass | Expires; the popup gives a new link with the same code | Kept |
| The broker restarts | Ends | Ends; the code stays the same, the user pairs again |
| The browser restarts (or a slot's Chrome stops) | Ends | Ends; the popup shows a new code |
| The unlock link is blocked or replaced | Ends | Kept |

While the native port is open, Chrome keeps the service worker running, so an
idle extension stays connected. When `status` shows
`extension_connected: false`, the browser has no host connection at this
moment: it reconnects by itself (after a broker restart, within about 30
seconds), or when the user clicks the toolbar button. A missing
`extension_pairing` entry during that gap does not mean the link stopped
working. Check whether the broker or the browser restarted before you ask the
user to use a new link. A vault that has only a key file and no master
password cannot be paired from an unlocked broker; restart it locked and pair
with the unlock.

Failed master-password attempts on the pairing page count toward the unlock
link's three (0.25.0+). After the third, the pairing page also refuses
attempts, every pairing link made before stops working, and `status` reports
`unlock_blocked: true`, even when the vault is unlocked. Follow the skill's
"Blocked unlock link" steps; after a new link, open a new pairing page from
the extension.

## Origin trust

From extension 0.3.0 (akdbx 0.29.0) an origin change needs no rebuild, no
reload and no approval. This covers a relay port move, `akdbx relay rotate`,
`relay enable` or `disable`, and another `--unlock-origin`.

- The broker has a persistent ECDSA P-256 identity key, one per broker
  endpoint, in `${XDG_STATE_HOME:-~/.local/state}/akdbx/broker-identity/`
  (Windows: `%LOCALAPPDATA%\akdbx\broker-identity\`), with the relay folder's
  private-file checks. At each start it signs `{"type": "akdbx-origin", "v": 1,
  "origin": ..., "seq": ..., "key_id": ...}`; `seq` goes up by one each time
  the origin changes. It sends the statement in the `identity` field of its
  `attached` and `state` messages. `status` shows `extension_trust`
  (`key_id`, `origin`, `seq`).
- The built origin (`config.js`) is the first trusted origin; later the
  trusted origin is the one stored after a verified binding or a signed
  change. The native host never chooses it, and there is no trust on first
  use. With no stored key, the extension never stores a key that only the
  native host sent: when an `attached` or `state` message brings the
  statement, its service worker reads
  `GET <trusted origin>/.well-known/akdbx-identity` over HTTPS and stores the
  public key, origin and `seq` only when that statement verifies, names the
  trusted origin and has the host's key. A failed read stores nothing; the
  next statement or popup tries again. A broker that names another origin
  before the first key is refused with no reset: the popup says the extension
  was built for another address, and only `akdbx extension build` (then a
  reload) changes the first origin. Each build writes a new random build ID
  into `config.js`, and the stored trust keeps it: after any local build and
  a reload, the extension drops the stored key and origin and binds the key
  again from the built origin's HTTPS page. A reload of the same build keeps
  the stored trust. An extension built with no origin opens no link and asks
  for `akdbx extension build`. The popup shows the origin next to the pairing
  code.
- Later, it accepts a new origin only when the stored key signed it, the key
  id matches, `seq` is higher than the stored one, and the origin is an HTTPS
  origin without path, query or credentials. Otherwise it keeps the stored
  origin and the popup says why. Each statement is checked when it arrives and
  a higher `seq` is saved at once. A replaced host can relay statements but
  cannot sign one.
- Another broker key (a new computer, a deleted identity file) is never
  accepted by itself, and no pairing or unlock link opens while it differs.
  If it names the trusted origin, the popup shows **Reset broker trust…** and
  then **Reset and pair again**. Only the user clicks these; never do it for
  them, and tell the user: if you did not set up this broker again yourself,
  do not reset and do not enter your master password. The reset clears only
  the stored key and `seq` and keeps the trusted origin; the new key is
  accepted only from that origin's HTTPS identity page. Another key with
  another origin gets no reset: the user runs `akdbx extension build` again.

After an origin change, the user does nothing in the browser: at the next
connection the popup says that the broker moved. If it shows a trust warning instead, give
the user its text and the steps above; do not rebuild to get around it.

## Agent workflow

The model is the CDP model. The browser reports tabs, documents and URLs. A
30-second single-use target pin binds the tab, document, origin and retained
element. A fresh search handle authorizes each fill. Receipts never contain a
value.

```bash
akdbx list-password-frames --top-url EXACT_HTTPS_URL --route extension
akdbx pin-password-target --route extension --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
  --top-url EXACT_HTTPS_URL --selector '#password' --mode password
akdbx fill HANDLE_FROM_SEARCH --mode password --target TARGET_FROM_PIN
```

- `page_id` has the form `CHANNEL.TAB` and `frame_id` is the browser's
  document ID, from `list-password-frames --route extension`. The listing has
  the CDP listing's fields (without `out_of_process`) plus `route: "extension"`.
  It never contains frame URLs or values.
- Password, login and username pins keep every CDP rule: exact top URL,
  focused field, autocomplete tokens, `--password-purpose`,
  `--allow-autocomplete-off`, and for child frames `--frame-origin` with the
  same-site chain policy. The field document's origin must equal the
  credential's main URL origin or one of its additional URLs.
- TOTP: `pin-password-target --mode totp --route extension`, then
  `fill-totp HANDLE --target-url EXACT_CHALLENGE_URL --target PIN [--pending]`.
  Require `browser_totp_protocol: 1`, `extension_totp_protocol: 1` and fill
  extension 0.10.0+. One retained whole-code field only; password/TOTP pins
  cannot cross modes. The exact challenge URL and authorized entry origin
  must match the field document before OTP access. Deadlines and format checks
  run in the renderer too; no keyboard fallback. This is the CLI/agent route,
  supported on Linux/Windows/macOS.
  See [TOTP](totp.md), including child frames and pending enrollment.
- `fill-generated` and `commit-password` work unchanged with a password-mode extension pin.
- Cards: `pin-card-target --route extension` takes the same options. `--frame-url`
  is optional on this route: the broker uses the browser's own URL for the
  document. Cards go only to frames of the merchant's top origin, or with
  `--processor adyen|computop|stripe` to that processor's exact frame below
  same-origin merchant frames. `stripe` covers the Payment Element and, with
  fill extension 0.2.0 or newer, the classic Card Element frame. Against a
  broker without `stripe_card_element: true`, give the exact Stripe
  `--frame-url`; without it the CLI refuses a `stripe` pin before it sends it.
- SMS codes (fill extension 0.13.0+): `pin-code-target --route extension`, then
  `fill-sms-code MESSAGE_ID --target PIN`. Require `extension_code_protocol: 1`
  and a paired browser in `extension_browsers` whose version is at least
  `extension_code_min_version`; the CLI refuses before it sends otherwise. The
  pin takes the CDP code pin's options and its DOM checks: one focused,
  visible, enabled `text`, `tel`, `number` or `password` input for
  `--field one-time-code`, or a `text` or `url` input for `--field webhook-url`
  (`sms-add-source NAME --kind KIND --target PIN`). `--frame-url` is required
  and must be the document's exact URL; every document from the top page to
  the field must have the top page's exact origin. The code goes sealed to the
  pinned element, once; it never reaches the agent or the keyboard. Receipts
  carry `code_delivery: "extension-dom-v1"`. The CDP code pin is the other
  page route (on macOS from 0.50.1, with a configured profile). See [SMS](sms.md).
- Identities: `pin-identity-target --route extension`, same rules as the CDP
  route; only frames of the top origin.
- Secret capture (0.32.0+, fill extension 0.4.0): `pin-password-target --mode read
  --route extension`, then `capture-secret` as on the CDP route. The read pin
  has the CDP read pin's rules (structural selector only, focus and no
  selection, one visible single-line text), and it reads only in the top
  document: a frame route (`--frame-origin`) refuses. Use the CDP route for a
  secret shown in a child frame. The broker
  seals the read request with the pin's facts; the extension seals the value
  to the broker under a second key (`akdbx-extension-capture-v1`), bound to
  that pin. The native host relays the broker's per-connection key, so the
  broker signs that key and the extension's key with its identity key
  (`channel_signature`); the extension reads only for a connection that the
  identity key it learned over HTTPS at its first pairing signed. Before that
  first binding, `capture-secret` refuses and saves nothing (the read pin itself
  can still succeed). A connection keeps the broker key of its
  first `attached` message, so a host cannot swap keys during a read. The
  receipt says
  `capture_delivery: "extension-dom-read-v1"`.
  Without `--route`, a read pin takes the broker's default route when the
  broker advertises `extension_capture_protocol: 1`, else the CDP route.
- Authenticator enrollment (0.35.0+): the same read pin feeds `capture-totp`
  ([automatic enrollment](totp-enrollment.md)). Fill extension 0.6.0 also reads
  a setup key printed in space-separated Base32 groups; 0.5.0 and older read
  only a key printed as one token.
- A setup QR code (`pin-password-target --mode read --qr --route extension`,
  then `capture-totp --qr`; broker `totp_qr_capture_protocol: 1`) needs fill
  extension 0.14.0 or newer (`extension_qr_capture_min_version`) in a
  Chromium-family browser (Helium, Chrome, Edge, Chromium or Brave), or 0.14.2
  or newer in Firefox (`extension_qr_capture_firefox_min_version`, after akdbx
  0.51.0). For that pin the service worker injects the bundled jsQR
  (`jsQR.js`, shipped with its licence) into the page's isolated world, and
  the content script decodes the pinned `<img>`, `<canvas>` or inline `<svg>`
  there with the CDP route's checks. An image URL must be on the page's own
  origin or be a `data:` URL, checked before anything is drawn, and from fill
  extension 0.15.1 an image that is not a `data:` URL must load without CORS
  (no `crossorigin` attribute). A CORS-mode image that redirects to another
  origin which allows the read stays origin-clean, so it could show that
  origin's code. The pin also
  decodes only a canvas that passes `convertToBlob`'s origin-clean check. A
  Firefox content script with `<all_urls>` host access (Enhanced security)
  reads another origin's pixels from a tainted canvas, also for an `<img>`
  whose URL on the page's origin redirects to another origin, and that check
  stops it. The decoded value goes to the broker sealed, like a text read; no
  pixel leaves the page. With enhanced security, the pixel challenge hides the
  code's own pixels for a moment (the picture moves out of its clipped box, an
  `<svg>`'s shapes are hidden), so the screenshot must show the challenge
  colour on a grid of points over the whole code. From fill extension 0.14.2,
  the challenge ignores the `::before` content that Firefox reports for every
  `<img>` (its alt text, which a loaded image does not paint). An older
  extension refuses a QR read pin with `target unavailable`; text reads are
  unchanged.
- Identity pins with `--field-purpose` (0.35.1) need fill extension 0.7.0 or
  newer. An older extension gets no such pin: rebuild and reload it
  (`version_status` in `extension_browsers`).
- A card or identity field under an ancestor `clip-path: inset(...)` that holds
  the whole field (a side drawer that trims its shadow) pins from fill
  extension 0.7.2 on Chromium, or 0.11.1 on Firefox: the CDP route’s page script cannot inspect
  closed shadow roots and refuses it. An older extension also refuses it as
  `target unavailable, changed or unsupported`
  ([clipped drawer or modal](identities.md#field-inside-a-clipped-drawer-or-modal-0363)).
- Read pins in the top document and password pins in a child frame need fill
  extension 0.4.0 or newer. Use CDP for supported same-site child-frame reads. Build
  the extension again and reload it. From 0.4.0 both sealing keys bind the
  version the extension reports, so a host that reports another version makes
  every sealed message fail.

## User-click workflow

The user clicks into a field, then opens akdbx with the toolbar button, the
**Fill with akdbx…** context-menu item or the shortcut (default Alt+Shift+K).
The popup asks the broker which entries match the focused field's frame and
shows metadata only (title, username, card brand and last four digits, or an
address label). The fill happens only after a trusted click in the popup.
Logins fill the focused field and its partner field in the same form; cards
and addresses fill the recognised visible fields of the same form. Hidden,
disabled and detached fields never receive a value.

Addresses (fill extension 0.15.0 or later) use the agent identity pin's own
checks on every field the popup fills: the build copies the identity pin
script into the extension, and only its focus check is left out, because the
popup holds the window focus and fills the focused field's partners too. The
focused field itself must stay the page's active element. So, as for
`pin-identity-target`:

- A field needs its autocomplete token in the identity grammar: an optional
  `section-*`, then `shipping` or `billing`, then for `tel` and `email` one of
  `home`, `work`, `mobile`, `fax` or `pager`, then the field
  ([field table](identities.md#fill)). Other token lists refuse. The popup has
  no `--field-purpose`: a field without a matching token stays empty.
- Input types: `text` for every field, `email` only for `email`, `tel` only
  for `tel`; a `<select>` only for `country`, `country-name` and
  `address-level1`; a `<textarea>` only for `street-address`.
- Partners come from the focused field's own form, section and address part:
  a `billing` field never gets a value when you focus a `shipping` field.
- Each field must pass the pin's style guard (no filter, mask, clip or blend
  on it or an ancestor, apart from an accepted `clip-path: inset()`), be
  enabled and editable, and pass the hit test at its centre, through every
  frame up to the top. A field outside the visible part of the page, or under
  a cover, stays empty: scroll to it, focus it and open akdbx again.
- Only documents whose frames up to the top all have the top page's origin.
  The popup keeps each field's element from when it opened. Just before it
  writes a field, it pins that element again with all these checks, and the
  element's type, autocomplete value, ID, name and form must be the same as
  when the popup opened. A field that fails before the first write refuses
  the whole fill; a field that the page changes while the popup fills the
  others makes the result "fill incomplete".
- Values: the saved value as saved. `street-address` gets the address lines
  joined with line breaks, and a single-line input refuses a multi-line
  address. A select needs exactly one enabled option with the saved value; a
  country select also takes the one option whose shown name is the saved
  name. A phone number fills as saved: for a separate country picker, use
  the agent route with `fill-identity --format` and `--calling-code`.
- Events: the popup sends bubbling `input` and `change` events on each field,
  as `fill-identity --notify-page` does, and checks after them that each
  field kept its value; a page that changes one gets "fill incomplete".

Before 0.15.0 the popup took the last autocomplete token only, any text,
email or telephone input for any address field, and had no style guard or
hit test: it could fill a field outside the viewport or under a hidden
ancestor, or mix two address parts. Rebuild and reload an older extension.

In fill extension 0.12.0 or later, the popup can fill a saved authenticator
code on the top HTTPS page. Require `extension_popup_totp_protocol: 1`. Focus
an input marked `autocomplete="one-time-code"` and select the matching account.
The popup closes to return focus to the field before delivery. Framed
challenges use a TOTP pin with retained frame owners. Before fill extension
0.14.1, a chosen code was sometimes refused ("field changed or hidden; nothing
filled") when the code reached the page before the browser gave focus back to
the field. Rebuild and reload an older extension.

For the same focused one-time-code field, fill extension 0.15.0 or later also
lists the texts in the broker's SMS inbox (`extension_popup_sms_protocol: 1`,
`extension_popup_sms_min_version`): the sender, the masked preview, the code
length and the age, never the code. akdbx cannot tell which site sent a text,
so the popup lists every unexpired text, and the user picks the one this site
sent. When the user clicks one, the popup closes and gives the focus back to
the page. Then the agent code pin's checks (`pin-code-target`) pin the field:
one focused, visible, enabled `text`, `tel`, `number` or `password` input that
passes the hit test, in the top document only. With Enhanced security, the
cover check runs on that pin. Only then does the broker spend the text, once,
and seal its code to that pin; if nothing reached the field, the extension
puts the text back with a token sealed inside that release. See
[SMS](sms.md#fill-from-the-toolbar-popup-fill-extension-0150).

Stripe's classic Card Element frame (`elements-inner-card-<hash>.html`) is
pin-route only. Its inputs have no ID, so the popup does not offer or fill a
card there, at any frame depth; the content script and the broker both refuse
it. Use `pin-card-target --processor stripe`, which checks the exact input
type, autocomplete token, unique name, merchant iframe owner and hit test.

## Security model

- Origin and frame identity come from the browser (`tabs`,
  `webNavigation` and injection results), never from page content.
- The host is launched by the browser for the fixed extension ID only. It
  connects to the broker's private socket or named pipe with the CLI's peer
  checks, relays bounded messages (64 KiB) and stores nothing.
- Every value is sealed with AES-256-GCM under a key that the broker's
  per-connection ECDH key and the extension's private key agree, and bound to
  the pin or popup selection it answers. The host, or a process that replaces
  the host registration, relays only ciphertext and never receives a value.
  The sealed payload also carries the tab, document, frame chain and kind the
  broker authorized, and the extension fills only when they equal its own
  browser facts. If someone replaces the host while the user pairs, the page
  shows a different code from the popup's; the user then does not approve. The
  popup opens pairing and unlock links only on the trusted origin (see
  [Origin trust](#origin-trust)), never on an origin the host sends unsigned.
- Values exist only in the broker, the relay, extension memory and the field.
  There is no clipboard and no logging. Extension storage holds only the
  pairing key (session memory) and the broker trust record (public key, origin,
  sequence number); never a value. The content
  script runs in the extension's isolated world; it uses the CDP route's own
  checks, which the build step copies in.
- Frame owners (0.32.0+): the browser names a child frame's parent document
  but not its `<iframe>` element. The parent's isolated world posts a fresh
  nonce into each child window: those `window.frames` lists and those of every
  `iframe`, `frame` and `object` element, also in shadow roots (a document with
  an `embed` refuses). The child's isolated world reports the nonces its parent
  window sent; exactly one names the owner, so a page that forwards another
  frame's nonce makes the child hear two, which refuses. The listener starts at
  `document_start` (`early.js` marks that start; a script injected later
  refuses), also in `about:blank` frames, and stops every probe, so a page
  neither sees nor stops one. In a page that was open before the extension
  loaded, child-frame password pins refuse until the page reloads. That owner
  then gets the CDP route's owner guard (connected, visible, no `srcdoc`, safe
  `sandbox`, no attribute change), checked at pin and again before the fill or
  read.
- Hit tests (default): there is no browser-native hit test. The checks use
  `elementFromPoint` in the isolated world, which skips click-through covers
  (`pointer-events: none`, `inert` content, a popover's `::backdrop`). For card
  and address fields the CDP route also runs `DOM.getNodeForLocation`, which
  sees them (also for code fields); use the CDP route where a page may cover
  such a field, unless the user turned on Enhanced security. Read pins use the same `elementFromPoint`
  check on both routes, and password pins have no hit test on either.
- Covers (Enhanced security: experimental, off by default; 0.34.0+, fill
  extension 0.5.0). The user turns it on in the extension's settings page (the
  cog in the popup, or the browser's extension options); an agent does not.
  The page first asks the browser for the optional `<all_urls>` host access,
  and stores the setting only when the browser grants it. Turning it off keeps
  that access: Chrome's `permissions.remove` of `<all_urls>` also withholds the
  required `https://*/*` access. On, but without that access (not granted, or
  removed later on the browser's extension page), every card, address, code and
  read pin refuses; the settings page shows a warning. The broker does not see the
  setting: a refused pin looks like any other refused pin, so when the pins of
  an ordinary page keep refusing on the extension route, the user can turn the
  setting off or the agent can use the CDP route. With the setting on, a card,
  address, code (fill extension 0.13.0+) or read pin needs proof that nothing is
  painted over the field or the secret. The popup runs this check for a texted
  code (0.15.0+), not for the logins, cards and addresses that it fills. `elementFromPoint` cannot give it (it
  skips click-through and inert covers), and no list of selectors names every
  cover. The extension asks the browser instead, in two steps, at the pin and
  again at the fill or read:
  1. The occlusion test, where the browser provides it. Firefox 161 lacks
     `IntersectionObserverEntry.isVisible` and uses step 2 on its own.
     [Firefox cover checks](../../../docs/firefox.md#enhanced-security) describes the limits.
     In Chromium, `IntersectionObserver` with `trackVisibility` runs the
     browser's own occlusion hit test: the one CDP's `DOM.getNodeForLocation`
     runs (pointer-events and `inert` ignored, visual overflow included), over
     the whole box of the element, through every parent frame. A cross-origin
     parent reports the occlusion of the whole `<iframe>` to its child, so a
     processor frame also sees a cover in the merchant page. A popover, a
     `::backdrop`, an exit transition, any pseudo-element, an inert or
     shadow-root cover: each is a box above the element, so the answer is
     "not visible". Opacity below 1, a filter or a distorting transform on the
     element's chain give the same answer. The fill or read runs in the task
     that delivers a fresh "visible" answer. The test needs a rendered tab.
  2. The pixel challenge, for every card, address, code and read check. Step 1 does
     not count paint that the element's own ancestors draw over it (a
     negative-offset outline, also around a processor iframe), and it is
     all-or-nothing for the whole box: a floating label, an icon in the field,
     an element over another part of a processor frame, or the transparent
     `::backdrop` of a cookie popover elsewhere also fail it.
     The service worker then adds one user-origin rule (it beats every author
     rule) that paints only the pinned element in a random colour, takes a
     screenshot of the tab (`tabs.captureVisibleTab`), removes the rule, and
     checks the colour at the points CDP hit-tests: the centre of a field; for
     a secret, a point every few pixels along the middle of each line of its
     text. An ordinary cover over those points, in any document or frame (a
     dialog, a banner, a popover, an inert or click-through layer), changes
     those pixels, so the pin refuses; a see-through veil also refuses.
     Limit: the check proves those points only, at the moment of the
     screenshot. A page built against it can hide the rest of a secret's line
     (a band above and below its middle), leave gaps at the checked points, or
     remove its cover while the challenge colour is on (a page script can read
     the element's computed style). Enhanced security stops covers that do not
     know about akdbx, not a page that targets it. The field shows the colour for
     about a tenth of a second. The screenshot stays in the service worker and
     is dropped after the check. The element's own outline gets another colour,
     so one drawn over its content refuses; a secret element that draws its own
     `::before`, `::after`, list marker or scroll markers refuses, because that
     content would take the challenge colour. After the screenshot the points are measured
     again; a layout shift refuses.
  Costs and limits: `tabs.captureVisibleTab` needs the `<all_urls>` host
  permission (asked for when the setting is turned on) and allows two
  screenshots each second, so challenges run one at a time, about half a
  second apart: each card or address field costs one challenge at its pin and
  one at its fill. Colours are compared exactly. Chrome returns tab screenshots
  in sRGB also when it renders for a colour-managed display: the tests pass with
  forced Display P3 and scRGB profiles (`--force-color-profile`). A display
  that still changed the colours would refuse, never fill. The tab must be the active tab of a window that renders.
  Only a script that can read the field's own document can copy the colour
  onto a cover in time, and such a script can read the filled value anyway;
  a parent page cannot see the colour in a cross-origin processor frame. A
  cover that comes and goes by itself is seen only if it is there at the pin
  or at the fill.

## Setup

See [docs/windows.md](../../../docs/windows.md#browser-extension-route) and the
README for install commands. In short:

```bash
akdbx extension install --browser helium   # all three desktops: chrome, edge, helium, chromium, brave or firefox
akdbx extension build --output /path/to/akdbx-extension
```

The build writes the configured unlock origin (`AKDBX_UNLOCK_ORIGIN` or the
global `--unlock-origin`) into the extension as the first trusted origin; later
origin changes follow [Origin trust](#origin-trust) without a rebuild. Then
load the folder as an unpacked extension (`chrome://extensions`,
**Developer mode**, **Load unpacked**). Run `akdbx extension uninstall
--browser NAME` to remove the host registration.

### Host launcher (0.31.1+)

`extension install` writes one launcher per browser
(`~/.local/share/akdbx/extension-host/BROWSER.sh` on Linux) and a manifest that
names it. On Linux and macOS the launcher runs
`PYTHON -I -c BOOTSTRAP AKDBX_SOURCE --browser NAME`: it puts the folder of the
akdbx that ran `install` first on `sys.path`, so the host runs that same akdbx
even when the interpreter's own site-packages hold another akdbx (a wrapper
deployment that adds a release folder to `sys.path`). Before it writes
anything, `install` starts the interpreter the same way and refuses one that
cannot import this akdbx's host (`cannot start`, `cannot run the akdbx
extension host`, `runs another akdbx`). The install output shows
`akdbx_source`. On Windows the launcher still runs `python -I -m
akdbx.extension_host`, so the interpreter must have this akdbx installed.

- `--python PATH` chooses the interpreter; the default is the CLI's own
  (`sys.executable`). The check above applies to it.
- `akdbx extension refresh [--python PATH]` rewrites every launcher that akdbx
  wrote for this user so that it runs the akdbx that runs `refresh`. It keeps
  each launcher's socket and never touches manifests or registrations, so it
  also covers every `--manifest-dir` profile. It refuses, and changes nothing,
  when a launcher there was not written by akdbx. Run it after an update moves
  akdbx to another folder (a new release folder).
- `akdbx extension info` shows `launcher_state` per browser: `current`,
  `stale` (another akdbx folder, an older `-m` launcher on Linux, or a missing
  interpreter: run `refresh`), `foreign` (not written by akdbx) or `missing`.

**Windows custom manifest location.** Use `extension install --browser NAME
--manifest-dir DIR` to put the manifest in a chosen directory. The browser
looks up the absolute path in HKCU for all its profiles. Use the same directory
with `uninstall` before moving the registration. Chromium and Helium share a
registration on Windows. Brave uses Chrome’s registration on Windows and macOS.
Install, refresh and uninstall affect the shared host. The `registration_browser`
in the install result identifies the launcher and its label in broker status.
A Chromium-branded browser can prefer an existing Chromium key over Chrome’s key.

**Linux and macOS Chromium profiles.** Each slot's Chrome uses its own user-data folder
`<browser_profile_root>/<slot>`, and Chrome reads native-messaging manifests
from that folder. Install the host once per slot whose Chrome loads the
extension:

```bash
akdbx extension install --browser chrome \
  --manifest-dir "$ROOT/$AGENT_DESKTOP_SLOT/NativeMessagingHosts"
```

`$ROOT` is `browser_profile_root` from `akdbx status`. All slot manifests of one
browser name the same launcher, so one `refresh` updates every slot.
`uninstall --manifest-dir` removes that slot's manifest and also the shared
launcher; reinstall the other slots afterwards.

## Agent desktop slot without DevTools

Use this **from the first load** of a page that has a
[red-flag vendor](#red-flag-vendors) (see
[Known bot-check sites](#known-bot-check-sites) and the probe below), and
before **every** retry after a block. Seen: DataDome on SoundCloud and npm
sign-ups, Cloudflare "Verifying…" that does not finish. A page that loads
once in a Chrome with an open DevTools connection ("use of developer or
inspection tools") flags the profile, and every later attempt starts as a
known bot. Every route that needs that connection fails: the CDP route, the
`browser_*` tools and `browser_prepare`. A home IP alone did not pass.

### Red-flag vendors

A red-flag vendor can refuse a sign-up at the first request, with no
challenge to solve, and remembers the profile, the device and the IP. Use the
whole procedure on this page from the first load.

| Vendor | Signs in the probe | Process |
| --- | --- | --- |
| DataDome | `x-datadome` or `x-dd-b` header, `datadome` cookie, `captcha-delivery.com` or `datadome` in the body | **Red flag.** This whole procedure from the first load. |
| Cloudflare challenge | `cf-mitigated: challenge`, `challenges.cloudflare.com` | Hides the page behind it. Check the table and search the web for a red-flag vendor on the site; doubt is a red flag. Through the home IP tunnel it hung on every setup; it passed at once on the direct IP. |
| Others: HUMAN (PerimeterX), Akamai Bot Manager, Kasada, Imperva, Arkose, reCAPTCHA, hCaptcha, Turnstile | `_px`, `px-captcha`, `_abck`, `bm_sz`, `x-kpsdk`, `incap_ses`, `reese84`, `arkoselabs`, `hcaptcha`, `recaptcha`, `turnstile` | Not a red flag yet. Solve the check ([Website checks](../SKILL.md#website-checks-during-sign-in)). If one refuses with no challenge, add it here as a red flag and report it ([Report blockers](../SKILL.md#report-blockers-and-adversarial-sites-to-akdbx)). |

### Known bot-check sites

| Site | Check | Notes |
| --- | --- | --- |
| `npmjs.com` (sign-up, sign-in) | Cloudflare challenge, then GitHub's DataDome | Hard block, no challenge: "Access is temporarily restricted" with a GitHub logo. Refused on the datacenter IP (also with a new empty Firefox profile) and on the home IP after a first load in a DevTools Chrome. GitHub's DataDome keys sit under both `npmjs.com` and `github.com`. `npm adduser` cannot create accounts ("Account creation via legacy auth is unavailable"). |
| `soundcloud.com` (sign-up) | DataDome | Slider challenge. Passed through the home IP proxy with this whole procedure. |

Add each new site that you meet to this table in the same change as your
task, and report it ([Report blockers](../SKILL.md#report-blockers-and-adversarial-sites-to-akdbx)).

### Probe before the first load

From the host, never from the slot browser:

```bash
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36'
curl -sL -D headers.txt -o body.html -A "$UA" https://SITE/SIGNUP-PAGE
cat headers.txt body.html | tr 'A-Z' 'a-z' | grep -o -E 'x-datadome|x-dd-b|datadome|captcha-delivery|cf-mitigated: *challenge|challenges\.cloudflare\.com|turnstile|_px[a-z0-9]*|perimeterx|px-captcha|_abck|bm_sz|x-kpsdk|kasada|incap_ses|reese84|imperva|arkoselabs|funcaptcha|hcaptcha|recaptcha' | sort -u
```

Probe the sign-up page itself and the site's home page. A red-flag vendor, a
Cloudflare challenge that hides the page, a site in the table, or doubt: use
this whole procedure from the first load.

### Host parts

Two parts depend on the host. Use the host's own tools for them; its agent
guidance names them. Without such tools, use the user's everyday browser.

- **Browser without DevTools (required):** restart only the slot's browser
  without `--remote-debugging-port`, and keep it so until you finish.
- **Home IP proxy (optional, recommended):** send only the slot's browser
  traffic out through the user's home (residential) internet connection, for
  example an SSH SOCKS tunnel (`ssh -N -D 127.0.0.1:PORT HOME_HOST`) and Chrome
  `--proxy-server=socks5://127.0.0.1:PORT` with
  `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`. Make it fail
  closed: if the tunnel stops, the browser must get no connection, never the
  datacenter IP.
- **Slow, hung or refused:** a home connection is often slow (seen: about
  100 KB/s), so pages through the proxy can take 10-60 seconds. Measure it
  before you judge a page. Content that still arrives is slow, not refused.
  *Refused* means an explicit message ("blocked", "failed", "try again",
  "Access is temporarily restricted", an error code): stop; it counts as an
  attempt. *Hung* means a check that still shows "Verifying…" after 90
  seconds with no message. Seen: Cloudflare hung through a home IP proxy in
  every setup and passed at once on the direct IP, while DataDome passed
  through the proxy.

### Remove all traces

Do this before the first attempt on a profile that ever loaded the site,
and before **every** retry. "Most of the data" is not enough: one key that
is left (seen: a DataDome key in storage partitioned under another site)
marks the next attempt. Print only names, domains and counts, never values.

What to remove:

- **The blocked site, everything:** cookies (also partitioned ones and
  cookies that other sites set while it was the top-level site), Local
  Storage, Session Storage, IndexedDB, Cache Storage, service workers and
  their caches, File System, Shared Storage, storage partitioned under the
  site, client hints and other per-site content settings in `Preferences`,
  network state (`Network Persistent State`, `Reporting and NEL`), DIPS
  records, history and the HTTP cache.
- **The bot-check vendor, everywhere in the profile:** its origins (for
  DataDome: `captcha-delivery.com`, `datadome.co`, `datado.me`) under every
  top-level site, cookies and storage keys whose name contains the vendor
  (for example `datadome`, `ddSession_datadome`) on any site, and the same
  check's data under other sites of the same owner (npm's DataDome is
  GitHub's: remove its keys under `github.com` too). Keep the other data of
  those other sites, for example a GitHub sign-in.

How:

1. Stop the browser that uses the profile and make sure that no process has
   it open. Edit nothing while the browser runs: it writes its in-memory
   state back on exit, and a copy taken while it runs can miss keys that it
   has not written yet.
2. SQLite stores (`Cookies`, `History`, `Reporting and NEL`, `DIPS`, `Shared
   Dictionary/db`, `SharedStorage`): delete the matching rows.
3. LevelDB stores (`Local Storage/leveldb`, `Session Storage`, `Service
   Worker/Database`): delete the matching keys (for Session Storage also the
   `map-ID-` entries of a removed `namespace-` key), then compact the whole
   key range so that no old file keeps a value or a deleted-key marker.
4. Folders named for a matching origin (`IndexedDB/https_SITE_0.*`, Cache
   Storage folders whose index names the origin): delete them. Delete the
   HTTP cache and code cache folders.
5. JSON stores (`Preferences` content settings, `Network Persistent State`):
   remove the matching entries.
6. **Prove it:** scan every LevelDB store record by record, including
   deleted records, and every other file in the profile by name and
   content, for the site, the vendor and the vendor's key names. The scan
   must find nothing. A cleanup that you have not proved complete is not
   done: do not retry on it.
7. Start the browser once and check that the stores open (same entry
   counts, less the removed keys). Delete every backup that you made: the
   backups hold the old data.

Other slots seeded from the same master profile can hold the same data.
Clean another slot only if it was part of the attempt and no other agent
uses it.

### Steps

1. **Remove all traces** (above), and prove it.
2. **Restart the browser first, pair after.** Pairing lasts only until the
   browser restarts, and both host changes restart the slot's browser.
   Before you load or pair the extension, restart the slot's browser without
   DevTools and, if available, with the home IP proxy. Check the exit IP
   (for example `https://api.ipify.org`) with desktop input before the real
   page.
3. **Desktop input only.** From now on use only `vps_computer` desktop
   actions on the browser window (`list_windows` for the new pid and window
   id, `get_window_state`, `click`, `type_text`, `press_key`, `hotkey`,
   `drag`), with `delivery_mode: "foreground"`; background input does not
   reach an unfocused Chromium. Never call `browser_*`, `browser_prepare` or
   any CDP script on this slot.
4. **Load the extension once per slot profile.** Build it and register the
   native host for that profile's own folder (a custom `--user-data-dir` reads
   `NativeMessagingHosts` inside it):

   ```bash
   akdbx extension build --output ~/.local/share/akdbx/extension-chrome
   akdbx extension install --browser chrome \
     --manifest-dir ~/.local/share/agent-desktops/profiles/"$SLOT"/NativeMessagingHosts
   ```

   Then, with desktop input: `ctrl+L`, type `chrome://extensions`, Enter;
   switch on **Developer mode**; **Load unpacked**; in the folder dialog
   `ctrl+L`, type the build folder, and select it. The extension stays in the
   slot profile; later runs need only pairing.
5. **Pair.** Click the akdbx toolbar button. `akdbx status` must show
   `extension_connected: true`. If it stays `false`, check which akdbx the
   host launcher (`path` in the profile's `org.akdbx.extension.json`)
   imports: it must be the release the broker runs. A launcher whose Python
   imports an older akdbx (for example an old editable checkout) cannot reach
   the broker. With 0.31.1+, `akdbx extension info` shows
   `launcher_state: "stale"` for it; run `akdbx extension refresh` (see
   [Host launcher](#host-launcher-0311)). With an older akdbx, repair it in
   akdbx ([repair thread](repair-thread.md)), then run the `install` command again. Give the user the `extension_pairing` link and
   the code from the popup, then wait for "paired"
   ([Pairing](#pairing)).
6. **Do the page by hand.** Type names and emails with `type_text`. For a
   slider check, drag it once like a person: a slow movement in several
   uneven steps, then check the result. Fill the password only through the
   extension: `list-password-frames`, `pin-password-target` and
   `fill`/`fill-generated` with `--route extension`. Do not look at the field.
   Dismiss the browser's own "Save password?" prompt; save the entry in akdbx.
7. **If it is refused, change the method.** Remove all traces again and
   prove it, then change one part and try again: the direct IP instead of
   the home IP (or the reverse), Firefox (the extension supports Firefox
   153+), a new empty profile for that browser, another slot. Record what
   each attempt used and its result, and never repeat a refused
   combination. Keep going until it passes or the site states a block on
   this user or account on purpose.
8. **Clean up.** Remove the home IP proxy, restart the slot's browser with
   DevTools again (the pairing ends), delete any temporary profile you made,
   then `end_session`.
9. **Report.** For a new site, a new vendor or a refusal, ask the user, then
   open an akdbx issue
   ([Report blockers](../SKILL.md#report-blockers-and-adversarial-sites-to-akdbx)).
   Do not hand the sign-up to the user while a method is left to try
   ([Automate first](../SKILL.md#automate-first-do-not-give-the-work-back-to-the-user)).

## Errors

| Observed result | Next step |
| --- | --- |
| `frame list unavailable` or `target unavailable` with `extension_connected: false` | The browser is closed, the extension is not loaded, or the host is not installed for that browser. |
| The same with `extension_paired: false` | Give the user the `extension_pairing` link. Wait for the pairing; do not retry in a loop. |
| `autofill outcome uncertain` | The browser did not confirm the fill. Check the page; do not retry automatically. |
| Popup: "This broker signs with another identity key…" | The broker's identity key changed. Ask the user whether they set up the broker again (another computer, deleted state). Only then may the user click **Reset broker trust…** and pair again; otherwise they must not reset or enter the master password. |
| Popup: "…this extension was built for…", "…this extension trusts…" or "no trusted broker address" | The broker names another origin than the trusted one, or the extension has none. No reset is offered: you run `akdbx extension build` again with the broker's current origin and the user reloads the extension. Any local build (also one for the same origin) replaces the saved broker trust; the extension then binds the broker key from the built origin's HTTPS page. A reload without a build changes nothing. |
| Popup: "The broker page at … names another identity than the native host sent" | The native host and the broker's HTTPS page disagree about the broker key, so the extension learned nothing. Tell the user not to enter the master password; check that the broker on that origin and the installed native host (`akdbx extension install`) are the user's own. |
| `version_status: "stale"` in `extension_browsers`, or a pin or frame list fails with `…older akdbx extension service worker…` | The browser runs an old worker beside newer files ([stale service worker](#stale-service-worker-0352)). Restart the browser, or reload akdbx in `chrome://extensions`, then pair again. |
| `version_status: "mismatch"`, or a pin or frame list fails with `…another build than this broker's…` | The loaded folder holds another build than this broker's. Run `akdbx --unlock-origin ORIGIN extension build --output FOLDER` with the broker's akdbx, where ORIGIN is the broker's private-page origin (the origin of its unlock link; the build replaces the saved broker trust), or restart the broker if akdbx was updated in place. Then reload akdbx in `chrome://extensions` and pair again. |
| `version_status: "outdated"` in `extension_browsers` | The loaded extension is older than this akdbx build. Ask the user to rebuild into the same folder and reload it in `chrome://extensions`. |
| `pin-code-target --route extension` refuses with `no paired akdbx fill extension 0.13.0 or newer is connected` | No paired browser runs fill extension 0.13.0 or newer (`extension_code_min_version`). Rebuild the folder the browser loads with `akdbx extension build`, reload it and pair it; or pair the browser first if `extension_paired` is false. |
| `pin-code-target --route extension` refuses with `the paired akdbx extension runs a stale build or another build…` | Every suitable paired browser has `version_status` `"stale"` or `"mismatch"`: follow the `version_status: "stale"` or `"mismatch"` row above, then pin again. |
| Right after an update, the popup says the broker is not reachable and `status` shows `extension_connected: false` | The broker, or the Python that the host launcher runs, is older than the extension and refuses its hello: akdbx 0.21.2 or earlier for any versioned extension, akdbx 0.35.1 or earlier for an extension built by 0.35.2 or later (four-part version). Restart the broker on the new version. If the launcher points to another Python, run `akdbx extension install --browser NAME` again from the updated installation. |
| The popup says the broker is not reachable and the broker is running; `extension info` shows `launcher_state: "stale"`, or the launcher fails with `No module named 'akdbx.extension_host'` | The launcher runs another akdbx than the CLI: an older release folder, or (before 0.31.1) the interpreter's own akdbx. Run `akdbx extension refresh` with the current CLI; with an akdbx before 0.31.1 on Linux, update first. Then reopen the popup. |
