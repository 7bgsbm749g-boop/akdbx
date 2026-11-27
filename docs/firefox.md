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
Mozilla-signed XPI. From 0.53.0 the broker gets its own build signed:
see [Permanent install](#permanent-install-a-mozilla-signed-xpi-0530).

After an update, rebuild with `--browser firefox` into the same Firefox
folder (a signed install needs a new signature instead; see
[Updates](#updates)). For an unpacked install, reload the temporary add-on. For a ZIP
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

## Permanent install: a Mozilla-signed XPI (0.53.0)

Release Firefox installs an add-on permanently only when Mozilla signed it.
`akdbx extension sign` gets the broker's own Firefox build signed on
addons.mozilla.org (AMO) through the **unlisted** channel: Mozilla's
self-distribution route, where the add-on is not listed on AMO, Mozilla
reviews and signs every submission, and the developer distributes the file.
Each deployment signs its own file. The build writes the broker's
private-page origin and a new random build ID (the extension's trust anchor,
see [Origin trust](../skills/akdbx/references/extension.md#origin-trust)) into
config.js, so a file that all users shared would share one trust anchor.

The add-on ID is fixed: `akdbx@akdbx.org`, the ID that the native host
allows. On AMO one account owns an add-on ID, so only the AMO account that
owns `akdbx@akdbx.org` (the akdbx owner's account) can sign. Every
deployment of that owner signs with the same key and gets its own file.
Another AMO account gets a clear refusal (HTTP 403 or 409); signing with
your own add-on ID is not built yet.
`status` reports `firefox_signing_protocol: 1` and
`firefox_signing_configured: true` when the running broker can sign.

### One-time setup

1. Create a Mozilla account with two-step authentication, open
   <https://addons.mozilla.org/en-US/developers/addon/api/key/>, accept the
   developer agreement and generate credentials. Do not paste them into a
   terminal or a chat.
2. Save them in the vault as one entry on exactly
   `https://addons.mozilla.org` with two captured protected fields: the
   **JWT issuer** as `jwt_issuer` and the **JWT secret** as `jwt_secret`.
   Pin each value on the key page with `pin-password-target --mode read` and
   save it with `capture-secret --field jwt_issuer` and
   `capture-secret --field jwt_secret` (see
   [secret capture](../skills/akdbx/references/secret-capture.md)).
3. The first signature creates the add-on `akdbx@akdbx.org` in that AMO
   account. Later signatures, from any deployment with that key, add
   versions to it.

### Sign, install and pair

```sh
akdbx search addons.mozilla.org                      # the AMO API key entry's handle
akdbx extension sign --output ~/akdbx-firefox HANDLE
```

The broker builds the Firefox files from its own installed akdbx, never from
files a caller supplies, so nobody can get other code signed under the
owner's account. It picks a new add-on version, uploads the archive, waits
for AMO's validation, and attaches a source archive to the new version:
Mozilla asks for the source of generated code, and content.js is filled in
from akdbx's Python modules. The source archive holds the akdbx package that
built the files (no compiled files, no Android helper binary), a BUILD.md
that explains the generation, and a `rebuild.py` with this version's origin,
build ID and version. `python rebuild.py OUT` rebuilds every submitted file
from the archived package, and the uploaded archive byte for byte. Then the broker waits for the
signature, downloads the signed XPI and checks that it holds exactly the
submitted files plus a complete set of Mozilla's signature files under
`META-INF/` (an unsigned copy is refused). It saves the XPI in its own private folder
(`${XDG_STATE_HOME:-~/.local/state}/akdbx/firefox-signed-KEY/` on Linux and
macOS, `%LOCALAPPDATA%\akdbx\firefox-signed\` on Windows). The CLI then
copies it into `--output` (an existing file with other contents is never
replaced) and prints JSON with `state: "signed"`, `addon_version`, `xpi` (the
copy), `broker_xpi`, `size`, `sha256` and `trusted_origin`.

One call works for at most about 100 seconds. When AMO needs longer, the
result is `state: "pending"` with the `stage` (`validation`, `review`, ...)
and `retry_after` seconds. Run the same command again with a fresh search
handle: it resumes the same job and does not submit again. `--restart` drops a
pending job and submits a new version. The job lives only in broker memory
(no secret in it) for at most 24 hours; after a broker restart the next call
submits a new version.

To install, open `about:addons` in Firefox, choose the gear menu, **Install
Add-on From File…**, and select the XPI (or drop the file on the Firefox
window). Remove a temporary akdbx add-on first in
`about:debugging#/runtime/this-firefox`: both use the ID `akdbx@akdbx.org`.
The installed add-on stays after Firefox restarts, uses the same native host
(`akdbx extension install --browser firefox`) and pairs as usual: open the
toolbar popup and approve the code on the broker's private page. The pairing
key lives in session storage, so pair again after each Firefox start.

### Updates

Mozilla signs the exact files, and Firefox refuses a signed add-on whose
files changed. So every rebuild needs a new signature: after an akdbx update
that changes the extension, `status` shows the installed add-on as
`version_status: "outdated"` or `"mismatch"`. Run `akdbx extension sign`
again and install the new XPI over the old one. Each new XPI also has a new
build ID, so the extension trusts the built origin again from the start and
asks for a new pairing. Origin changes that the broker's identity key signs
need no new file.

### Versions

AMO accepts every version string only once per add-on, deleted versions
included. A signed build's version is `MAJOR.MINOR.PATCH.N`, where
N = 100000000 + 1000 × (the content part of the unsigned build version) + a
sequence number from 1 to 999, for example `0.15.1.111058001`. Firefox and
AMO allow up to nine digits in a part. The broker reads all of the add-on's
versions on AMO (pages of 50 from the API's own origin; a long list
continues at the next call, and more than 200 pages refuse) and takes the
next sequence number; when another deployment of the same account took
one (AMO answers HTTP 409), it builds the next one. From the version alone
the broker knows that a signed add-on runs its own contents, so `status`
shows it as `version_status: "current"`. A broker from 0.52.0 or earlier
refuses the nine-digit version. The toolbar popup shows it from fill
extension 0.17.0.

### How the API key is protected

- The caller passes only the entry's search handle. The broker reads the two
  protected fields itself and never returns, logs or prints them.
- For each AMO request the broker signs a JSON Web Token (HS256, a unique
  `jti`, valid for 60 seconds; AMO allows at most 300). A child process
  (`akdbx/amo_https.py`, standard library only) sends that one request and is
  stopped at a fixed deadline. The child gets the token on standard input,
  never the secret, and nothing goes into argv or the environment.
- The child ignores proxy variables and follows no redirect. The broker sends
  a token only to the API's own origin; a download redirect to another origin
  gets no token.
- AMO's own error text is shortened to one line without control characters,
  and any copy of the key in it is withheld.

akdbx calls the AMO v5 API from Python rather than running `web-ext sign`:
that needs Node.js and the secret in its environment or command line, and a
signing child that holds only one-minute tokens keeps the secret inside the
broker.

### Refusals

| Result | Meaning |
| --- | --- |
| `the entry is not on https://addons.mozilla.org` | Select the AMO API key entry. Look-alike hosts and AMO's staging site are refused. |
| `the entry has no captured protected jwt_issuer and jwt_secret fields` | Capture both values with `capture-secret`. A value typed into another field, or an unprotected field, does not count. |
| `vault locked` | Unlock first; the result includes the private unlock link. |
| `this broker serves no private HTTPS page` | The add-on would trust no origin. Start the broker with its private page (relay, loopback HTTPS or Tailscale Serve). |
| `AMO refused the API key (HTTP 401)` | Wrong issuer or secret, or this computer's clock is wrong. The job is kept. |
| `AMO refused add-on ID akdbx@akdbx.org (HTTP 403 or 409)` | Another AMO account owns the ID (or a deleted add-on used it), or the key cannot manage it. Only the account that owns the ID can sign. Nothing is signed. |
| `AMO refused the source archive of VERSION` | AMO did not take the source archive. The job is kept: run the command again. |
| `AMO lists more than 10000 versions…`, `AMO named a version list page on another origin` | The next free version cannot be known safely. Nothing is submitted. |
| `AMO validation failed for VERSION: …` | AMO's validator refused the archive; its first errors follow. Nothing is signed. |
| `Mozilla did not sign VERSION` | AMO rejected or disabled the version; see the AMO developer hub. |
| `AMO could not be reached`, `AMO is busy or failed (HTTP 5xx or 429)` | Network failure or an AMO outage. The job is kept: run the command again later. |
| `the signed add-on from AMO does not match the submitted build` | The download is not the submitted build plus signatures. Nothing is saved. |

Guided setup (`akdbx setup --browser firefox`) still loads the temporary
add-on and names this command; it does not sign by itself yet.

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
origin (or be a `data:` URL). From fill extension 0.15.1, an image that is
not a `data:` URL must also load without CORS (no `crossorigin` attribute).
The page must show exactly one code with an
`otpauth://totp/` URI. If the element changes after the pin, the capture
refuses. The key is saved as pending until `commit-totp`. One Firefox
difference needs an extra check. A content script with `<all_urls>` host
access can read another origin's pixels from a tainted canvas. Fill extension
0.5.0 to 0.15.x could ask for that access, and Firefox keeps the grant through
an update to a build that no longer asks for it (see [Covers](#covers)). This includes an `<img>` whose URL on the page's origin
redirects to another origin. So the extension decodes only a canvas that
passes `convertToBlob`'s origin-clean check, which that access does not skip.
An older Firefox build refuses `pin-password-target --mode read --qr` with
`target unavailable`; text setup keys and shown-once secret reads are not
affected.

## Covers

In Firefox the extension runs the same DOM checks as in Chromium: hidden,
transparent, zero-size, off-screen and inert targets refuse. Card, address and
code fields also refuse a clip and a cover that takes pointer events at the
field centre, and a read pin refuses a cover over its text; password pins have
no hit test. The DOM hit test
(`elementFromPoint`) skips a click-through cover (`pointer-events: none`,
`inert`, a popover `::backdrop`). Firefox has no browser-native hit test for
an extension (see WebDriver BiDi below), so no Firefox route refuses such a
cover. See [Visibility checks](../README.md#visibility-checks-what-they-stop).

Fill extension 0.5.0 to 0.15.x had an experimental Enhanced security pixel
check with tab screenshots. Fill extension 0.16.0 (after akdbx 0.52.0) removes
it, with its settings page and its `<all_urls>` request
([why](../skills/akdbx/references/extension.md#removed-enhanced-security)). A
temporary add-on that was granted `<all_urls>` keeps the grant after a reload
with the new build, until Firefox exits (tested with Firefox 161). 0.16.0 never
uses it, and the QR check above still refuses a tainted canvas.

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
code (0.15.0); no Firefox test fills a TOTP code or a card from the popup. The
QR tests also run with `<all_urls>` host access. For `capture-secret`
and `capture-totp`, it reopens a disposable encrypted vault to verify the
result. From 0.53.0 it also loads the exact archive that
`akdbx extension sign` uploads, with its nine-digit signed-build version, and
fills a password through it (the broker reports it `current`).
`tests/test_firefox_signing.py` runs the whole signing flow against a fake
AMO over loopback TLS (the real child process, AMO's status codes and
messages, no request to Mozilla). In the Linux Firefox job, Mozilla's
`addons-linter` 10.16.0 (the validator AMO runs on uploads) checks that
archive and must find no error. The first real signature happens on the
owner's own account. CI runs this suite on Linux, macOS and Windows with Firefox 161, and on
Linux with the minimum supported version, Firefox 153. The
[support matrix](support-matrix.md#extension-route-firefox) lists each Firefox
operation and its CI job.

The Firefox integration follows Mozilla's
[native-messaging contract](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging)
and [native document IDs](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webNavigation/getAllFrames).
