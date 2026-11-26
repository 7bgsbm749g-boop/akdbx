# Private authenticator transfer (0.12.0)

This copies TOTP setup data into an existing KDBX entry. It does not remove a
phone's account, reset a website, configure a push approval, or prove that a
website accepted enrollment. The agent never reads keys, QR pixels or codes.
Require broker `totp_import_supported: true` and integer `totp_import_protocol: 1`.
Updating source does not replace a running broker. Installation/restart of the
live deployment is separate work; keep its current vault and credentials intact.

## Private phone import

1. Select the exact existing vault entry with a fresh search. Start the usual
   `setup-totp HANDLE --title ... --username ... --url ... --group ...` request.
2. Give the user its private URL. They open it where the unlock link opens (the
   broker's computer for a loopback origin, any tailnet device for a Tailscale
   origin) and select
   **Import QR images / Google export, or review a browser capture**.
3. The user can enter a Base32 setup key / standard `otpauth://totp/` URI, select
   QR images, or take a QR photo. The images stay in the browser and are decoded
   with bundled jsQR; only decoded setup data is posted to the broker. There is
   no third-party decoder, CDN, local-storage cache or image-upload endpoint.
   Do not put QR images in agent tools, screenshots, chat, notes or evidence.
4. For Google Authenticator, use **Transfer accounts > Export accounts**. This
   imports a copy, not a site reset. Include every image of one multi-part batch.
   The current limits are 8 QR images, 4 MiB each, at most 4096 pixels per side,
   32 accounts and 32 KiB of decoded transfer URI text. Accepted image formats
   are PNG, JPEG and WebP. The camera option depends on the browser producing
   one of those formats; unsupported formats fail without upload.
5. The private review shows the chosen vault destination and imported account
   labels, never keys/codes. The user must select exactly one imported account
   and confirm the destination. Labels come from the QR and are not proof of
   the account or website. Other accounts are discarded, not silently added.
   To import another account, start a fresh request and reuse the original QR
   images privately; a successful save invalidates other pending requests.
6. Check `write-status WRITE_HANDLE` for `state: saved`. Use a fresh normal
   `fill-totp` request to verify sign-in when authorized. The save receipt alone
   does not certify site acceptance or that the phone is still configured.

The request expires after five minutes and is consumed on a save attempt.
Missing parts, mixed batches, duplicate account labels, HOTP, Steam, unsupported
algorithm/digit enums, malformed or oversized payloads are rejected as a whole.
Only SHA1/SHA256/SHA512 TOTP with six/eight digits is imported. Google migration
records use their format's fixed 30-second period. Existing ordinary URI/key
validation and encrypted save/reopen checks remain authoritative.

Authy does not expose a supported consumer token export. Microsoft Authenticator
backup is not a general raw-key export. Neither is bypassed here. Use an
independently available original setup key or an explicit additional website
authenticator. Never reset/remove a phone method to work around an import limit.
An image already saved in Photos/Files remains there under user control; this
workflow cannot delete source copies or prevent their cloud backup. Avoid making
unnecessary screenshots. JavaScript/Python memory is not guaranteed zeroized;
the design avoids intentionally persisting raw imports or returning them to the
model, not compromise by a process sharing the broker's OS account.

## Private browser capture

Importer 1.1.0 supports Chromium browsers and Firefox 153+ on Linux, macOS
and Windows. Use the browser on the same machine as the broker. The importer
stays separate from the fill extension so the browser enforces its temporary
`activeTab` permission. The user invokes it on one tab. Closing that tab or
navigating to another origin revokes access. The fill extension's persistent
HTTPS permissions would remove this browser-enforced limit.
It is not an iOS app, a Windows-to-VPS tunnel, or an agent screenshot reader.
It captures one standard TOTP QR or `otpauth://totp/` link/code from the selected
HTTPS top-level document. It does not extract arbitrary Base32-looking page text,
read other frames, export an app's internal database, or use a screenshot fallback.
Cross-origin and tainted images are skipped. Images loaded with CORS enabled
are also skipped because a redirect can make foreign pixels readable.

Build an unpacked extension after installing this version of akdbx:

```bash
/absolute/path/to/.venv/bin/akdbx-browser-import build-extension /private/new-extension-directory
```

For Firefox, add `--browser firefox` to the build command. Load its
`manifest.json` through **about:debugging > This Firefox > Load Temporary
Add-on**. Repeat after Firefox restarts. Permanent installation in standard
Firefox requires a Mozilla-signed XPI (`akdbx extension sign` signs only the
fill extension, not this importer). Register with `install-host --browser
firefox` and the origin and socket options below. Its fixed ID is
`private-import@akdbx.org`. Omit `--extension-id` for Firefox. Use separate
build directories when installing both formats.

For Chromium, load that directory through **chrome://extensions > Developer mode > Load
unpacked** in the established main profile. Do not create a new profile to
work around an error. Copy Chrome's extension ID, then explicitly register the
native host using the current independently configured unlock origin and the
broker's **HTTP unlock socket**, not its agent RPC socket. On Linux this
socket (`akdbx-unlock.sock` beside the broker socket, `agentic-kdbx-unlock.sock`
beside a legacy `agentic-kdbx.sock`, or `--unlock-socket`)
exists on both private-page routes: with `--tls-cert` and `--tls-key` (0.23.0+)
it serves only this capture request, as the capture pipe does on Windows.

```bash
/absolute/path/to/.venv/bin/akdbx-browser-import install-host \
  --extension-id EXTENSION_ID \
  --origin https://PRIVATE_HOST:9443 \
  --socket /private/runtime/akdbx-unlock.sock \
  --browser chrome
```

On Linux and macOS, `--browser chrome|edge|helium|firefox` selects the
browser's per-user native host directory. From 0.49.0, `--browser
chromium|brave` is also accepted. The importer uses the fill extension host's
directory for each browser, with its own host name `org.akdbx.private_import`.
On Linux, Chrome, Chromium and Helium honor `CHROME_CONFIG_HOME` before
`XDG_CONFIG_HOME`. On macOS, Brave reads Chrome's directory. One registration
serves both browsers, and the installer refuses to write a second one there.
A second Chromium browser can
reuse the same extension ID, private origin and capture socket. For a custom Chromium user-data
root, pass `--manifest-dir /existing/chrome-user-data/NativeMessagingHosts`.
Use a user-owned manifest directory under trusted, non-symlinked parents.
On macOS pass `--socket "$HOME/Library/Application Support/akdbx/run/u"` for
the default broker. For a custom broker use its `--unlock-socket` or the
sibling socket named `u` (`s` if the RPC socket itself is named `u`).
The host and broker both verify Darwin peer credentials.
Run the installed console script from the intended environment as shown above.
The installer records that exact script, even when its directory is not on `PATH`.
The installer creates mode-0600 configuration at
`${XDG_CONFIG_HOME:-~/.config}/akdbx/browser-import.json` (Firefox uses `browser-import-firefox.json`) and one native-host
manifest. It refuses to overwrite existing files. Use the same config environment
when the browser starts the host. No database/password/key is stored in this config.
Neither build nor install reads the vault or restarts the browser/broker.

On macOS, guided setup from 0.49.0 (`--capture-host --capture-browser
chrome|edge|helium|chromium|brave`) runs this installer with `--browser BROWSER`
and the default capture socket. The installer uses that browser's
`NativeMessagingHosts` folder and creates it when it is missing. A browser started from Finder
does not get `XDG_CONFIG_HOME`. With a configuration folder other than
`~/.config/akdbx`, the macOS manifest therefore names a mode-0700 launcher,
`browser-import-host.sh`, in that folder. The launcher sets `XDG_CONFIG_HOME` and
starts the recorded script. A second registration reuses it only if it is identical.

On Windows (0.22.0+) use `akdbx-browser-import.exe install-host --browser
chrome|edge|helium --extension-id EXTENSION_ID --origin ORIGIN`. From 0.49.0,
`--browser brave` uses Chrome's registry key and `--browser chromium` uses
Helium's key, as for the fill extension host. One registration serves both
browsers of a pair. A second install for the pair is refused, and
`uninstall-host` for either browser removes the shared registration. It registers
the host under `HKEY_CURRENT_USER` and, without `--socket`, uses the default
broker's capture pipe (the RPC pipe name plus `-capture`), never the agent RPC
pipe. For Firefox use `--browser firefox` without an extension ID. The
manifest registers under Mozilla's per-user native messaging key.
`uninstall-host --browser NAME` removes one registration. See
`docs/windows.md`.

For capture, prepare the normal private `setup-totp` URL, verify the website and
account without reading the setup key, then open the extension on the enrollment
tab. The user supplies that private URL and clicks **Capture this tab's setup QR**.
The extension requests temporary `activeTab` access, not blanket site permission.
It sends data through a browser native-messaging host restricted to that extension
ID. The host validates the configured private origin, protected Unix socket and
broker UID (on Windows: the capture named pipe and its same-user, same-session
server). The broker separately checks the actual captured source origin
against the selected entry, and rejects duplicate captures. The local capture
route requires a same-UID Unix peer, rejects Tailscale identity/Origin headers,
and cannot be used to unlock the vault. Agent RPC never accepts the secret data.

Capture returns only `ok: true, state: awaiting-private-confirmation`. Nothing
has been saved yet. Open the original private URL, follow its import/review link,
confirm the source and account, and save. Wrong-site capture, navigation, stale
requests, missing native hosts and ambiguous QR results refuse capture. Do not
automatically retry an unconfirmed receipt; inspect the private page and normal
write status first. Keep private URLs/handles out of durable notes and PRs.

## Future enrollment and replacement

The importer is deliberately not an autonomous website-2FA reset. A new,
authorized enrollment can skip this importer: [automatic enrollment](totp-enrollment.md)
(0.35.0+) reads the setup key from the site's page and needs no user step. A new website
authenticator must use an explicitly authorized additive route. Verify site
acceptance and the retained phone method independently; keep recovery available.
The existing `--replace` flag only permits replacing the KDBX field and preserves
its old encrypted history. It cannot make a website's replacement route additive.

## Validation

Synthetic tests cover complete/mixed/malformed migration batches, parser bounds,
private account selection, consent, CSRF origin checks, protected encrypted saves,
native-message framing, wrong-site capture, replay, cancellation, expiry, socket
trust and memory cleanup. Node tests decode a synthetic QR and exercise extension
navigation/receipt checks. Linux integration tests invoke the toolbar action in real
Chromium and Firefox profiles, decode a synthetic canvas QR through the
installed native host, verify the vault is unchanged, submit the private
confirmation and reopen the encrypted entry. Windows and macOS runner suites
exercise host registration and their native capture channels.

The decoder is vendored unmodified from jsQR 1.4.0 with its Apache-2.0 license
and npm tarball integrity recorded in `import_assets/VENDOR.txt`. No runtime
package/CDN downloads occur. All test vaults use synthetic data.
