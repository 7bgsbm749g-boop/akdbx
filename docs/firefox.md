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
akdbx extension build --browser firefox --output /absolute/path/to/akdbx-firefox
```

From fill extension 0.19.0 the build is generic: the same files for every
user, with no broker address (the release attaches them as
`akdbx-extension-firefox-VERSION.zip`). Open
`about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and
select the built folder's `manifest.json` for a native build. With Snap or
Flatpak, give the file picker one ZIP containing the complete extension:
`akdbx extension pack --browser firefox --output /absolute/path/to/akdbx-firefox.zip`
writes it (the release's ZIP, `manifest.json` at its root), or use the
release's unsigned Firefox ZIP. Selecting the unpacked manifest can give the
sandbox access to that file alone. Open the akdbx toolbar popup: on first use
it shows the broker address that the native host names; check it against
`akdbx status` (`extension_trust.origin`) and click **Trust this address**
([Browser extension trust](private-pages.md#browser-extension-trust)). Then
pair it on the broker's private page. Agents then use `--route extension`.
Logins, cards, identity fields, TOTP delivery, SMS verification codes (fill
extension 0.13.0+, `pin-code-target --route extension`) and shown-once secret
capture use the existing extension protocol and its field and origin
restrictions.

A temporary add-on is removed when Firefox exits, with its storage. Load it
again at the next start, confirm the broker address again and pair again.
Permanent installation in standard Firefox requires a Mozilla-signed XPI:
every release attaches one (see
[Permanent install](#permanent-install-the-releases-mozilla-signed-xpi-0190)).

After an update, rebuild with `--browser firefox` into the same Firefox
folder (a signed install takes the new release's XPI instead; see
[Updates](#updates)). For an unpacked install, reload the temporary add-on. For a ZIP
install, pack a new ZIP and select it with **Load Temporary Add-on**. Pair
again. Keep Chromium and
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

## Permanent install: the release's Mozilla-signed XPI (0.19.0)

Release Firefox installs an add-on permanently only when Mozilla signed it.
From fill extension 0.19.0 (akdbx 0.55.0) the add-on is one generic
build for every user, so Mozilla signs it once per release: the GitHub
release attaches `akdbx-extension-firefox-VERSION.xpi`, listed in
`SHA256SUMS` and covered by a build-provenance attestation like the wheel.
Mozilla signs it on addons.mozilla.org (AMO) through the **unlisted**
channel: Mozilla's self-distribution route, where the add-on is not listed on
AMO, Mozilla reviews and signs every submission, and the developer
distributes the file.

```sh
gh release download vX.Y.Z --repo 7bgsbm749g-boop/akdbx --pattern 'akdbx-extension-firefox-*' --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify akdbx-extension-firefox-*.xpi --repo 7bgsbm749g-boop/akdbx
```

To install, open `about:addons` in Firefox, choose the gear menu, **Install
Add-on From File…**, and select the XPI (or drop the file on the Firefox
window). Remove a temporary akdbx add-on first in
`about:debugging#/runtime/this-firefox`: both use the ID `akdbx@akdbx.org`.
The installed add-on stays after Firefox restarts, uses the same native host
(`akdbx extension install --browser firefox`), asks once to confirm the
broker address ([first use](private-pages.md#browser-extension-trust)) and
pairs as usual: open the toolbar popup and approve the code on the broker's
private page. The pairing key lives in session storage, so pair again after
each Firefox start; the confirmed address stays.

`akdbx extension sign` (0.53.0 to 0.54.x) had each broker sign its own
per-deployment build with an AMO key from the vault. It is removed: the
release signs the one generic build, so no broker needs an AMO key. When the
release's XPI replaces an add-on that it signed (same ID, higher version),
the popup asks once to confirm the broker address
([update from a per-deployment build](private-pages.md#browser-extension-trust)).

### How the release signs

The Release workflow's `extension` job installs the released wheel, writes
the Chrome and Firefox archives with `akdbx extension pack`, and runs
`python -m akdbx.firefox_signing --output ext --timeout 1200` with the AMO
API key in the GitHub Actions secrets `AMO_JWT_ISSUER` and `AMO_JWT_SECRET`
(only this step sees them). The step:

- looks the version up on AMO (by its version string, then in the author's
  list of all versions);
- uploads exactly the release's unsigned Firefox ZIP, at the build's own
  version (`MAJOR.MINOR.PATCH.N`, N from the contents; the version `status`
  calls current);
- waits for AMO's validation, creates the version on the add-on
  `akdbx@akdbx.org` (the first upload created it) and attaches a source
  archive: Mozilla asks for the source of generated code, and content.js is
  filled in from akdbx's Python modules. The source archive holds the akdbx
  package that built the files (no compiled files, no Android helper binary),
  a BUILD.md that explains the generation and a `rebuild.py`;
  `python rebuild.py OUT` rebuilds every submitted file and the uploaded
  archive byte for byte;
- waits for the signature, downloads the signed XPI and checks that it holds
  exactly the submitted files plus a complete set of Mozilla's signature
  files under `META-INF/` (an unsigned copy is refused).

AMO accepts every version string only once per add-on. A re-run of the same
tag, or a later release with the same extension contents, finds that version
on AMO and resumes it (source archive if missing, review, download); nothing
is uploaded twice. AMO review can take minutes: the whole step is bounded
(20 minutes in the workflow) and then fails with the stage it reached and
"re-run the failed release jobs to resume this version"; nothing is
published until it passes. When the secrets are not set, the step prints
`state: "unsigned"` and exits 3, and the release still publishes the wheel,
the sdist and both ZIPs, with a release-notes line that it has no signed
Firefox add-on. A version that AMO disabled, rejected or deleted can never be
used again: bump the fill extension version
([Extension version](releasing.md#extension-version)).

The add-on ID is fixed: `akdbx@akdbx.org`, the ID that the native host
allows. On AMO one account owns an add-on ID, so only the akdbx owner's AMO
account can sign it. A fork's own AMO account gets a clear refusal (HTTP 403
or 409); signing under another add-on ID is not supported, because the native
host allows only this one.

### Updates

Mozilla signs the exact files, and Firefox refuses a signed add-on whose
files changed. After an akdbx update that changes the extension, `status`
shows the installed add-on as `version_status: "outdated"`: install the XPI of
the broker's release over the old one. Its stored broker trust stays (same
add-on ID), so it asks for no new confirmation, only the usual new pairing.
Origin changes that the broker's identity key signs need no new file.

### How the API key is protected

- The key lives only in the two GitHub Actions secrets and reaches only the
  signing step's environment. No broker holds it.
- For each AMO request the step signs a JSON Web Token (HS256, a unique
  `jti`, valid for 60 seconds; AMO allows at most 300). A child process
  (`akdbx/amo_https.py`, standard library only) sends that one request and is
  stopped at a fixed deadline. The child gets the token on standard input,
  never the secret: its environment has no `AMO_JWT_ISSUER` or
  `AMO_JWT_SECRET`, and nothing goes into argv.
- The child ignores proxy variables and follows no redirect. The step sends
  a token only to the API's own origin; a download redirect to another origin
  gets no token.
- AMO's own error text is shortened to one line without control characters,
  and any copy of the key in it is withheld. The step prints only the file
  name, version, size and SHA-256.

akdbx calls the AMO v5 API from Python rather than running `web-ext sign`:
that needs Node.js and the secret in its environment or command line, and a
signing child that holds only one-minute tokens keeps the secret in one
process.

### Refusals

| Result | Meaning |
| --- | --- |
| `state: "unsigned"` (exit 3) | `AMO_JWT_ISSUER` and `AMO_JWT_SECRET` are not both set. The release ships without a signed add-on and says so. |
| `AMO refused the API key (HTTP 401)` | Wrong issuer or secret, or the runner's clock is wrong. Nothing is signed. |
| `AMO refused add-on ID akdbx@akdbx.org (HTTP 403 or 409)` | Another AMO account owns the ID, or the key cannot manage it. Nothing is signed. |
| `AMO validation failed for VERSION: …` | AMO's validator refused the archive; its first errors follow. Nothing is signed. |
| `AMO has not signed VERSION within N seconds (stage …)` | Review, validation or a slow AMO answer outlasted the step; every request and its child process end by the deadline. Once the version is on AMO, the message says so and a re-run of the failed release jobs resumes it; before that (lookup, upload or validation) it says that AMO has no version from this run. |
| `Mozilla did not sign VERSION`, `AMO had version VERSION before and deleted it` | That version string is spent. Bump the fill extension version and release again. |
| `AMO refused the source archive of VERSION` | AMO did not take the source archive. Re-run: the next run attaches it. |
| `AMO could not be reached`, `AMO is busy or failed (HTTP 5xx or 429)` | Network failure or an AMO outage, after four retries. Re-run later. |
| `the signed add-on from AMO does not match the VERSION build` | The download is not the submitted build plus signatures. Nothing is saved. |

Guided setup (`akdbx setup --browser firefox`) loads the temporary add-on and
names the release's signed XPI for a permanent install.

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
result. From fill extension 0.19.0 every session confirms the broker
address with a trusted click in the toolbar popup before it pairs, and the
suite checks that the generic build opens no page before that click and binds
the key after it, on a broker at a fresh loopback origin (not the default),
and that the users of two brokers (own origins, keys and vaults) load the same
archive and each fill from their own broker. It also loads the release's
Firefox archive (the one AMO signs) and fills a password through it (the
broker reports it `current`). `tests/test_firefox_signing.py` runs the
release's signing step against a fake AMO over loopback TLS (the real child
process, AMO's status codes and messages, a re-run of the same tag, no
request to Mozilla). In the Linux Firefox job, Mozilla's `addons-linter`
10.16.0 (the validator AMO runs on uploads) checks that archive and must find
no error. CI runs this suite on Linux, macOS and Windows with Firefox 161, and on
Linux with the minimum supported version, Firefox 153. The
[support matrix](support-matrix.md#extension-route-firefox) lists each Firefox
operation and its CI job.

The Firefox integration follows Mozilla's
[native-messaging contract](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging)
and [native document IDs](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webNavigation/getAllFrames).
