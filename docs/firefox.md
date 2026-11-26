# Firefox extension (0.47.0+)

Firefox 153 or newer uses the same local broker, master-password pairing,
sealed values and retained DOM targets as the Chromium extension. It needs no
debugging port and works with X11 or Wayland. Windows, Linux and macOS use the
broker on the same computer; this adds no remote broker connection.

The fixed Firefox add-on ID is `akdbx@akdbx.org`. The native host allows only
that ID and checks the ID Firefox supplies when it starts the host. Firefox's
native document UUIDs identify pin targets, including child frames. A page
navigation makes an old target unusable.

## Install for local use

Start and configure the broker as usual. For macOS, see
[macOS setup](macos.md). Install the host and build a separate
Firefox extension folder:

```sh
akdbx extension install --browser firefox
akdbx --unlock-origin https://YOUR-BROKER-ORIGIN extension build --browser firefox --output /absolute/path/to/akdbx-firefox
```

Use the broker's configured private-page origin. Open
`about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and
select the built folder's `manifest.json` for a native build. With Snap or
Flatpak, give the file picker one ZIP containing the complete extension. For
example, run `(cd /absolute/path/to/akdbx-firefox && zip -r ../akdbx-firefox.zip .)`
with a new archive name, then select the ZIP. The archive must have
`manifest.json` at its root. Selecting the unpacked manifest can give the
sandbox access to that file alone. Open the akdbx toolbar popup and
pair it on the broker's private page. Agents then use `--route extension`.
Logins, cards, identity fields, TOTP delivery, SMS verification codes (fill
extension 0.13.0+, `pin-code-target --route extension`) and shown-once secret
capture use the existing extension protocol and its field and origin
restrictions.

A temporary add-on is removed when Firefox exits. Load it again at the next
start, then pair again. Permanent installation in standard Firefox requires a
Mozilla-signed XPI. This source release does not publish an AMO listing or
provide a signed XPI. For an unlisted release the publisher needs an AMO
developer account authorized for `akdbx@akdbx.org`, its API key (JWT issuer)
and its API secret. Build the Firefox folder with the intended initial broker
origin, assign an unused, increasing add-on version, and submit that folder
with `web-ext sign --channel=unlisted`. Supply the credentials privately as
`WEB_EXT_API_KEY` and `WEB_EXT_API_SECRET`. Distribute the returned signed
XPI after review. Editing its bundled origin or rebuilding the files requires
a new signature. See Mozilla’s [web-ext signing instructions](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/).

After an update, rebuild with `--browser firefox` into the same Firefox
folder. For an unpacked install, reload the temporary add-on. For a ZIP
install, create a fresh ZIP from the rebuilt folder and select the new archive
with **Load Temporary Add-on**. Pair again. Keep Chromium and
Firefox builds in separate folders; the builder refuses to replace the other
format.

Guided setup with `--browser firefox --extension-dir FOLDER` uses that exact
folder. If Chromium is selected too, Firefox uses `FOLDER-firefox` and Chromium
uses `FOLDER`. The setup JSON's `stages.fill.extension_dirs` reports the folder
for each browser.
Each format's folder is saved separately, so adding another browser later
keeps the existing Firefox folder in place.
An existing akdbx manifest establishes which format owns a saved or default
folder. This also handles unused Chromium paths saved by older setup versions
and Firefox builds made with the standalone command. Path aliases do not make
the two formats share one folder.

## Native host locations

| Platform | Per-user registration |
| --- | --- |
| Linux | `~/.mozilla/native-messaging-hosts/org.akdbx.extension.json` |
| macOS | `~/Library/Application Support/Mozilla/NativeMessagingHosts/org.akdbx.extension.json` |
| Windows | `HKEY_CURRENT_USER\Software\Mozilla\NativeMessagingHosts\org.akdbx.extension`; its default value names the host manifest |

`akdbx extension info` reports the paths and launcher state. Run
`akdbx extension refresh` if an upgrade moves the broker package. For Linux Snap or Flatpak builds, run the host installer outside
the sandbox in the user’s graphical session. From 0.49.0 it recognizes the
usual launchers. Use `--firefox-package snap` or `--firefox-package flatpak`
to select the intended package explicitly, or `native` for an unconfined
build on the same machine. The installer checks the session bus with `gdbus`
before writing the normal Mozilla manifest. The desktop needs the native
messaging proxy or the WebExtensions portal. Firefox and its package must
also allow that service. A portal may ask for permission on first use.
Confirm `extension_connected` in broker status after loading the add-on.
If the bridge is unavailable, use an unconfined Firefox installation.
See [Mozilla’s native messaging design](https://firefox-source-docs.mozilla.org/toolkit/components/extensions/webextensions/native-messaging-portal-design.html).

For a user-started QR import, build the **separate importer** (1.1.0+) with
`akdbx-browser-import build-extension --browser firefox NEW_DIRECTORY` and load
its manifest as a temporary add-on. Register `org.akdbx.private_import` with
`akdbx-browser-import install-host --browser firefox --origin ORIGIN`, adding
`--socket CAPTURE_SOCKET` on Linux and macOS. Its host allows only
`private-import@akdbx.org`. The user confirms the account on the private page
before saving. See [private import](../skills/akdbx/references/private-import.md).

From fill extension 0.11.1, a card or address field inside a clipped drawer
can pass the inset check in Firefox. The extension checks open and closed shadow
roots when it walks the field’s ancestors.

From fill extension 0.14.2 (after akdbx 0.51.0), QR read pins for
`capture-totp --qr` work in Firefox too
(`extension_qr_capture_firefox_min_version`). The content script decodes the
pinned `<img>`, `<canvas>` or inline `<svg>` with the same checks as in
Chromium. Only the top document is read, the image URL must be on the page's
origin (or a `data:` URL), and the page must show exactly one code with an
`otpauth://totp/` URI. If the element changes after the pin, the capture
refuses. The key is saved as pending until `commit-totp`. One Firefox
difference needs an extra check. A content script with `<all_urls>` host
access (Enhanced security asks for it) can read another origin's pixels from
a tainted canvas. This includes an `<img>` whose URL on the page's origin
redirects to another origin. So the extension decodes only a canvas that
passes `convertToBlob`'s origin-clean check, which that access does not skip.
An older Firefox build refuses `pin-password-target --mode read --qr` with
`target unavailable`; text setup keys and shown-once secret reads are not
affected.

## Enhanced security

With **Enhanced security** on, card, address, code and read pins require a pixel check
at the pin and again at delivery. Firefox 161 does not expose
`IntersectionObserverEntry.isVisible`. The extension therefore cannot repeat
a whole-element occlusion check in the JavaScript task that writes or reads the
field. A DOM hit test skips click-through covers. The extension checks a tab screenshot at the field centre or along the secret text,
then rechecks the target and its position. A cover between sampled points is
outside that proof. The ordinary DOM, frame-owner and origin checks still apply.

Firefox can paint a native input over its CSS inset shadow. In that case the
screenshot lacks the expected colour and akdbx refuses even an uncovered
field. An ordinary CSS-styled input can pass. Missing screenshot permission or
an inactive tab also prevents the pixel check from succeeding.

## WebDriver BiDi

Firefox can expose browsing contexts and navigation events over WebDriver BiDi.
A controller could locate an element, keep its node reference, and run DOM checks
in a sandboxed realm. This would require a debugging session for the profile.
BiDi has no command equivalent to the CDP card check that hit-tests a screen
point while ignoring pointer-event exclusions and returns a backend node ID.
A BiDi node reference identifies an element but cannot prove what is painted
over it. akdbx therefore uses the paired extension for Firefox. See the
[WebDriver BiDi specification](https://www.w3.org/TR/webdriver-bidi/) and
[CDP’s DOM domain](https://chromedevtools.github.io/devtools-protocol/tot/DOM/#method-getNodeForLocation).

## Validation

`tests/test_firefox_browser.py` loads the actual built add-on into a fresh
Firefox profile and connects through a unique native host to a synthetic
broker. It exercises main and child documents, a two-field child login, TOTP,
SMS codes in the main and a same-origin child document (with replay, a hidden
field, a wrong frame URL and a reloaded page refused), generated-password delivery, merchant card fields, and Adyen, Computop and both
Stripe frame types. A loopback TLS fixture serves all processor pages. The suite
also checks identity notification events, the toolbar popup's trusted click
on a login, an address (with the identity pin's checks, 0.15.0) and a texted
code (0.15.0); no Firefox test fills a TOTP code or a card from the popup. It
also checks the pixel check on an uncovered and a covered field. For `capture-secret`
and `capture-totp`, it reopens a disposable encrypted vault to verify the
result. CI runs this suite on Linux, macOS and Windows with Firefox 161, and on
Linux with the minimum supported version, Firefox 153. The
[support matrix](support-matrix.md#extension-route-firefox) lists each Firefox
operation and its CI job.

The Firefox integration follows Mozilla's
[native-messaging contract](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging)
and [native document IDs](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webNavigation/getAllFrames).
