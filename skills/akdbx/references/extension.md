# Browser extension route (0.21.0)

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

Supported browsers: Helium, Google Chrome and Microsoft Edge, on Windows and
Linux. The extension has the fixed ID `jjoamaejjkldcjcpgncoomoaagdfimhg` and
the host name `org.akdbx.extension`.

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
`extension_browsers` lists attached browsers and whether each is paired.
Each item also has the extension version that browser loaded and how it
compares with this broker (see [Extension version](#extension-version)).
While a browser is not paired, `extension_pairing` gives its code and private
pairing link. The existing `password_fill_delivery`, `card_delivery` and
`identity_delivery` values still describe the CDP route; receipts of this
route carry `"extension-dom-v1"` in the same keys.

## Extension version

The extension has its own version (from 0.1.0), separate from the akdbx
package version. `status` shows:

| Key | Value |
| --- | --- |
| `extension_version_expected` | The version this akdbx build ships, for example `"0.1.0"` |
| `extension_browsers[].version` | The version the loaded extension reported, or `null` |
| `extension_browsers[].version_status` | `"current"`, `"outdated"` (older, or no version) or `"newer"` |

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
the pairing page for the user. A vault that has only a key file and no master
password cannot be paired from an unlocked broker; restart it locked and pair
with the unlock.

Failed master-password attempts on the pairing page count toward the unlock
link's three (0.25.0+). After the third, the pairing page also refuses
attempts, every pairing link made before stops working, and `status` reports
`unlock_blocked: true`, even when the vault is unlocked. Follow the skill's
"Blocked unlock link" steps; after a new link, open a new pairing page from
the extension.

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
- `fill-generated` and `commit-password` work unchanged with an extension pin.
- Cards: `pin-card-target --route extension` takes the same options. `--frame-url`
  is optional on this route: the broker uses the browser's own URL for the
  document. Cards go only to frames of the merchant's top origin, or with
  `--processor adyen|computop|stripe` to that processor's exact frame below
  same-origin merchant frames. `stripe` covers the Payment Element and, with
  fill extension 0.2.0 or newer, the classic Card Element frame. Against a
  broker without `stripe_card_element: true`, give the exact Stripe
  `--frame-url`; without it the CLI refuses a `stripe` pin before it sends it.
- Identities: `pin-identity-target --route extension`, same rules as the CDP
  route; only frames of the top origin.
- Secret capture (`--mode read`, `capture-secret`) stays on the CDP route.

## User-click workflow

The user clicks into a field, then opens akdbx with the toolbar button, the
**Fill with akdbx…** context-menu item or the shortcut (default Alt+Shift+K).
The popup asks the broker which entries match the focused field's frame and
shows metadata only (title, username, card brand and last four digits, or an
address label). The fill happens only after a trusted click in the popup.
Logins fill the focused field and its partner field in the same form; cards
and addresses fill the recognised visible fields of the same form. Hidden,
disabled and detached fields never receive a value.

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
  popup opens pairing and unlock links only on the unlock origin written at
  build time, never on an origin the host sends. After `akdbx relay enable` or
  `disable` (0.26.0+) changes that origin, build the extension again.
- Values exist only in the broker, the relay, extension memory and the field.
  There is no clipboard, no extension storage and no logging. The content
  script runs in the extension's isolated world; it uses the CDP route's own
  checks, which the build step copies in.
- Limits compared with the CDP route: the extension cannot attest which
  `<iframe>` element hosts a child frame, so password child frames have no
  owner-element guard (the frame chain, focus and in-frame visibility checks
  remain). Processor card frames keep an owner guard found by the frame's exact
  URL. There is no browser-native hit test; DOM hit tests remain.

## Setup

See [docs/windows.md](../../../docs/windows.md#browser-extension-route) and the
README for install commands. In short:

```bash
akdbx extension install --browser helium   # or chrome, edge
akdbx extension build --output /path/to/akdbx-extension
```

The build writes the configured unlock origin (`AKDBX_UNLOCK_ORIGIN` or the
global `--unlock-origin`) into the extension; the popup opens pairing and unlock
links only there. Then load the folder as an unpacked extension (`chrome://extensions`,
**Developer mode**, **Load unpacked**). Run `akdbx extension uninstall
--browser NAME` to remove the host registration.

## Errors

| Observed result | Next step |
| --- | --- |
| `frame list unavailable` or `target unavailable` with `extension_connected: false` | The browser is closed, the extension is not loaded, or the host is not installed for that browser. |
| The same with `extension_paired: false` | Give the user the `extension_pairing` link. Wait for the pairing; do not retry in a loop. |
| `autofill outcome uncertain` | The browser did not confirm the fill. Check the page; do not retry automatically. |
| `version_status: "outdated"` in `extension_browsers` | The loaded extension is older than this akdbx build. Ask the user to rebuild into the same folder and reload it in `chrome://extensions`. |
| Right after an update, the popup says the broker is not reachable and `status` shows `extension_connected: false` | The broker, or the Python that the host launcher runs, still has akdbx 0.21.2 or earlier, and it refuses the new extension's hello. Restart the broker on the new version. If the launcher points to another Python, run `akdbx extension install --browser NAME` again from the updated installation. |
