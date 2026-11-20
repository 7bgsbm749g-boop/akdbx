# Browser extension route (0.21.0)

The extension route is a second delivery route next to the Chrome DevTools
Protocol (CDP) route. A browser extension in the user's everyday browser
fills the field, reached through a native-messaging host:

```text
CLI/agent -> broker -> native-messaging host -> akdbx extension -> retained DOM element
```

Use it when the browser must not run with a remote-debugging port. The akdbx
docs warn that a debugging port gives every process of the same user full
control of that profile. This route is not a way to hide automation from a
website: do not use it to avoid bot detection or fraud checks.

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
While a browser is not paired, `extension_pairing` gives its code and private
pairing link. The existing `password_fill_delivery`, `card_delivery` and
`identity_delivery` values still describe the CDP route; receipts of this
route carry `"extension-dom-v1"` in the same keys.

## Pairing

The extension keeps a random pairing key in browser session memory only. The
broker keeps only a digest of it, for its own lifetime. A browser restart or a
broker restart needs a new pairing. Pairing is the user's step:

1. The user clicks the akdbx extension button. The popup shows a code such as
   `ABCD-EFGH` and an **Open the pairing page** button.
2. The private page (`/extension/pair?token=...` on the unlock origin) shows
   the same code and asks for the master password. When the broker is locked,
   the same entry also unlocks it.

You can give the user the `extension_pairing` link from `status`, as you give
an unlock link. Never ask for the master password, and never open or operate
the pairing page for the user. A vault that has only a key file and no master
password cannot be paired from an unlocked broker; restart it locked and pair
with the unlock.

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
  same-origin merchant frames.
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

## Security model

- Origin and frame identity come from the browser (`tabs`,
  `webNavigation` and injection results), never from page content.
- The host is launched by the browser for the fixed extension ID only. It
  connects to the broker's private socket or named pipe with the CLI's peer
  checks, relays bounded messages (64 KiB) and stores nothing.
- A host or process that imitates the extension has no approved pairing key, so
  it receives no value.
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

Then load the folder as an unpacked extension (`chrome://extensions`,
**Developer mode**, **Load unpacked**). Run `akdbx extension uninstall
--browser NAME` to remove the host registration.

## Errors

| Observed result | Next step |
| --- | --- |
| `frame list unavailable` or `target unavailable` with `extension_connected: false` | The browser is closed, the extension is not loaded, or the host is not installed for that browser. |
| The same with `extension_paired: false` | Give the user the `extension_pairing` link. Wait for the pairing; do not retry in a loop. |
| `autofill outcome uncertain` | The browser did not confirm the fill. Check the page; do not retry automatically. |
