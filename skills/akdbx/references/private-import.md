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
2. Give the user its private URL. On their Tailscale-connected device, they open
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

This optional Chrome extension runs on **Linux on the same machine as the broker**.
It is not an iOS app, a Windows-to-VPS tunnel, or an agent screenshot reader.
It captures one standard TOTP QR or `otpauth://totp/` link/code from the selected
HTTPS top-level document. It does not extract arbitrary Base32-looking page text,
read other frames, export an app's internal database, or use a screenshot fallback.
Cross-origin/tainted images and unsupported pages fail closed.

Build an unpacked extension after installing this version of akdbx:

```bash
/absolute/path/to/.venv/bin/akdbx-browser-import build-extension /private/new-extension-directory
```

Load that directory through **chrome://extensions > Developer mode > Load
unpacked** in the established main profile. Do not create a new profile to
work around an error. Copy Chrome's extension ID, then explicitly register the
native host using the current independently configured unlock origin and the
broker's **HTTP unlock socket**, not its agent RPC socket:

```bash
/absolute/path/to/.venv/bin/akdbx-browser-import install-host \
  --extension-id EXTENSION_ID \
  --origin https://PRIVATE_HOST:9443 \
  --socket /private/runtime/akdbx-unlock.sock \
  --manifest-dir /existing/chrome-user-data/NativeMessagingHosts
```

The manifest directory belongs to the user-data root (the parent of `Default`),
not the `Default` profile directory. It must already have an existing parent.
Run the installed console script from the intended environment as shown above.
The installer records that exact script, even when its directory is not on `PATH`.
The installer creates mode-0600 configuration at
`${XDG_CONFIG_HOME:-~/.config}/akdbx/browser-import.json` and one native-host
manifest. It refuses to overwrite existing files. Use the same config environment
when Chrome starts the host. No database/password/key is stored in this config.
Neither build nor install reads the vault or restarts the browser/broker.

For capture, prepare the normal private `setup-totp` URL, verify the website and
account without reading the setup key, then open the extension on the enrollment
tab. The user supplies that private URL and clicks **Capture this tab's setup QR**.
The extension requests temporary `activeTab` access, not blanket site permission.
It sends data through a Chrome native-messaging host restricted to that extension
ID. The host validates the configured private origin, protected Unix socket and
broker UID. The broker separately checks the actual captured source origin
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

The importer is deliberately not an autonomous website-2FA reset. A new website
authenticator must use an explicitly authorized additive route. Verify site
acceptance and the retained phone method independently; keep recovery available.
The existing `--replace` flag only permits replacing the KDBX field and preserves
its old encrypted history. It cannot make a website's replacement route additive.

## Validation

Synthetic tests cover complete/mixed/malformed migration batches, parser bounds,
private account selection, consent, CSRF origin checks, protected encrypted saves,
native-message framing, wrong-site capture, replay, cancellation, expiry, socket
trust and memory cleanup. Node tests decode a synthetic QR and exercise extension
navigation/receipt checks. The optional real Chromium test uses a new isolated
Xvfb/profile and synthetic image only. It does not prove native iPhone behavior,
real Authy/Microsoft export, or a loaded Chrome extension/native-host deployment.

The decoder is vendored unmodified from jsQR 1.4.0 with its Apache-2.0 license
and npm tarball integrity recorded in `import_assets/VENDOR.txt`. No runtime
package/CDN downloads occur. All test vaults use synthetic data.
