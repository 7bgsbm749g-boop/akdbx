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
| `extension_version_expected` | The version this akdbx build ships, for example `"0.3.0"` |
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
  popup opens pairing and unlock links only on the trusted origin (see
  [Origin trust](#origin-trust)), never on an origin the host sends unsigned.
- Values exist only in the broker, the relay, extension memory and the field.
  There is no clipboard and no logging. Extension storage holds only the
  pairing key (session memory) and the broker trust record (public key, origin,
  sequence number); never a value. The content
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
global `--unlock-origin`) into the extension as the first trusted origin; later
origin changes follow [Origin trust](#origin-trust) without a rebuild. Then
load the folder as an unpacked extension (`chrome://extensions`,
**Developer mode**, **Load unpacked**). Run `akdbx extension uninstall
--browser NAME` to remove the host registration.

## Agent desktop slot without DevTools

Use this when a bot check (seen: DataDome on a SoundCloud sign-up) refuses an
agent desktop slot even after the CDP route, a clean profile and a residential
IP. The check detects the open DevTools connection ("use of developer or
inspection tools"), so every route that needs it fails: the CDP route, the
`browser_*` tools and `browser_prepare`. Each refused attempt can make the
next one harder, so change the setup before you try again.

The host commands below exist on the operator's VPS (agent desktop slots); on
another host, use its equivalent or the user's everyday browser.

1. **Restart Chrome first, pair after.** Pairing lasts only until the browser
   restarts, and both commands restart the slot's Chrome. Run them before you
   load or pair the extension:

   ```bash
   slot-devtools off "$SLOT"     # Chrome without --remote-debugging-port
   laptop-proxy on "$SLOT"       # optional: the user's home IP, if the IP is also blocked
   ```

   Both last only until the slot stops. `slot-devtools status` and
   `laptop-proxy status` show each slot.
2. **Desktop input only.** From now on use only `vps_computer` desktop
   actions on the Chrome window (`list_windows` for the new pid and window id,
   `get_window_state`, `click`, `type_text`, `press_key`, `hotkey`, `drag`),
   with `delivery_mode: "foreground"`; background input does not reach an
   unfocused Chromium. Never call `browser_*`, `browser_prepare` or any CDP
   script on this slot.
3. **Load the extension once per slot profile.** Build it and register the
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
4. **Pair.** Click the akdbx toolbar button. `akdbx status` must show
   `extension_connected: true`. If it stays `false`, check which akdbx the
   host launcher (`path` in the profile's `org.akdbx.extension.json`)
   imports: it must be the release the broker runs. A launcher whose Python
   imports an older akdbx (for example an old editable checkout) cannot reach
   the broker. Repair it in akdbx ([repair thread](repair-thread.md)), then
   run the `install` command again. Give the user the `extension_pairing` link and
   the code from the popup, then wait for "paired"
   ([Pairing](#pairing)).
5. **Do the page by hand.** Type names and emails with `type_text`. For a
   slider check, drag it once like a person: a slow movement in several
   uneven steps, then check the result. Fill the password only through the
   extension: `list-password-frames`, `pin-password-target` and
   `fill`/`fill-generated` with `--route extension`. Do not look at the field.
   Dismiss Chrome's own "Save password?" prompt; save the entry in akdbx.
6. **Clean up.** `laptop-proxy off "$SLOT"`, `slot-devtools on "$SLOT"`
   (Chrome restarts with DevTools, so the pairing ends), then `end_session`.

## Errors

| Observed result | Next step |
| --- | --- |
| `frame list unavailable` or `target unavailable` with `extension_connected: false` | The browser is closed, the extension is not loaded, or the host is not installed for that browser. |
| The same with `extension_paired: false` | Give the user the `extension_pairing` link. Wait for the pairing; do not retry in a loop. |
| `autofill outcome uncertain` | The browser did not confirm the fill. Check the page; do not retry automatically. |
| Popup: "This broker signs with another identity key…" | The broker's identity key changed. Ask the user whether they set up the broker again (another computer, deleted state). Only then may the user click **Reset broker trust…** and pair again; otherwise they must not reset or enter the master password. |
| Popup: "…this extension was built for…", "…this extension trusts…" or "no trusted broker address" | The broker names another origin than the trusted one, or the extension has none. No reset is offered: you run `akdbx extension build` again with the broker's current origin and the user reloads the extension. Any local build (also one for the same origin) replaces the saved broker trust; the extension then binds the broker key from the built origin's HTTPS page. A reload without a build changes nothing. |
| Popup: "The broker page at … names another identity than the native host sent" | The native host and the broker's HTTPS page disagree about the broker key, so the extension learned nothing. Tell the user not to enter the master password; check that the broker on that origin and the installed native host (`akdbx extension install`) are the user's own. |
| `version_status: "outdated"` in `extension_browsers` | The loaded extension is older than this akdbx build. Ask the user to rebuild into the same folder and reload it in `chrome://extensions`. |
| Right after an update, the popup says the broker is not reachable and `status` shows `extension_connected: false` | The broker, or the Python that the host launcher runs, still has akdbx 0.21.2 or earlier, and it refuses the new extension's hello. Restart the broker on the new version. If the launcher points to another Python, run `akdbx extension install --browser NAME` again from the updated installation. |
