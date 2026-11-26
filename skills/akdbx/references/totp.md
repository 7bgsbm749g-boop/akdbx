# TOTP authenticators

Use the broker to generate and enter authenticator codes for an authorized
sign-in or access-confirmation challenge. This does not authorize changing a
site's security settings. Reuse the shared browser session and verify the
account, origin and focused field before filling.

## Capabilities and selection

Require `status` fields `totp_supported: true`, integer `totp_protocol: 1`,
`target_fill_required: true` and integer `target_fill_protocol: 1`.
Then check the selected route:

- CDP: integer `browser_totp_protocol: 1` and a configured CDP profile.
- Extension: integer `browser_totp_protocol: 1`, integer
  `extension_totp_protocol: 1` and a paired extension **0.10.0** or newer.
- Native desktop fields: `native_field_supported: true`, integer
  `native_field_protocol: 1` and `native_field_delivery: native-field-v1`.
  Linux X11/Wayland and supported Windows controls use the
  [native field workflow](native-fields.md) with `--mode totp`.
- Current Window: `target_fill_delivery: x11-send-event-v1` on Linux (X11 or XWayland windows) or
  `win32-char-v1` on Windows. This method is unavailable on macOS; its
  `target_fill_delivery: unavailable` does not block the paired extension.

The CLI checks capabilities before sending TOTP requests. Updating installed
source does not change an old running process; coordinate its normal restart
and private unlock, without disrupting another live workflow.

Search the exact service and account. An entry with `totp_configured: true`
has an OTP field, which can still be malformed or unsupported. Select the
provider's entry for a provider challenge; a destination site's entry is not
the provider's authenticator. A passwordless identity can have an authenticator
without gaining password fill or password generation privileges.

## Fill a saved code

Verify the exact challenge page and account, then focus one visible editable
whole-code input. For Chromium browser delivery, require integer
`browser_totp_protocol: 1`. Use CDP on Linux/Windows or the paired extension on
Linux/Windows/macOS (including the native macOS broker). Extension TOTP requires
integer `extension_totp_protocol: 1` and fill extension **0.10.0** or newer; an
older loaded extension is refused before pinning. These are agent/CLI routes;
the extension's manual popup keeps its existing login/card/address workflow.

```bash
akdbx list-password-frames --route extension --top-url 'https://example.com/challenge'
akdbx pin-password-target --route extension --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
  --top-url 'https://example.com/challenge' --selector '#otp' --mode totp
akdbx search example.com
akdbx fill-totp HANDLE --target-url 'https://example.com/challenge' --target PIN
```

Use `--route cdp` for the configured CDP profile, with its page/frame IDs. In
an agent desktop slot, add `--browser-slot "$AGENT_DESKTOP_SLOT"` to CDP discovery
and pinning; see [agent desktop slots](target-fill.md#agent-desktop-slots).
For a same-site child frame, use its frame ID and add `--frame-origin
https://auth.example.com` to the pin command. `--top-url` remains the top page's
exact URL; `fill-totp --target-url` must be the **exact child challenge URL**, not
the top URL. The asserted origin must match both the entry's authorized origins
and the pinned frame origin before any OTP configuration is read. URLs must use
ASCII HTTPS spelling, including punycode. An exact `KP2A_URL*` origin can also
authorize an entry.

Only one input of type `text`, `tel`, `number` or `password` is supported.
Split-digit fields, textareas, hidden/disabled/read-only fields, conflicting
password/card hints and unsupported format constraints refuse. Metadata, URL,
focus and the retained element must remain stable through assignment. The site
may then consume the code and advance its form during notification. Leading
zeros stay intact;
`maxlength` must admit all six/eight digits. Supported patterns are `\d+`,
`[0-9]+`, or those digit classes with `{6}`, `{8}` or `{6,8}`. Explicit `min`,
`max` or `step` constraints and an empty `pattern` refuse. A public digit-count
preflight checks field format before dispatch; the renderer repeats the checks
at the setter.
Password pins cannot accept TOTP, and TOTP pins cannot accept saved/generated
passwords, login fills or username fills. SMS/webhook code pins are separate.
There is no keyboard, Tab or clipboard fallback on these browser routes.

Current Window still uses `pin-target --pid VERIFIED_PID --window VERIFIED_WINDOW`
with the same `fill-totp` command. Its target URL is a caller assertion and does
not attest a browser field or origin. Android keeps `akdbx android pin` and
`akdbx android fill-totp`; see [Android](android.md). Use `--pending` on the
standard `fill-totp` command to confirm an authorized pending enrollment through
CDP, extension, native desktop fields or Current Window. Native field pins use
`pin-native-target --mode totp` with an independently verified app and asserted
service URL; that URL must match `fill-totp --target-url` at the origin level.

All handles and pins are single-use, including failures. A success receipt
contains only `ok: true`, `filled: totp` and `target_delivery`: browser CDP uses
`chromium-password-dom-v1`, extension uses `extension-dom-v1`, and Current Window
uses `x11-send-event-v1` on Linux or `win32-char-v1` on Windows. Native desktop
fields use `native-field-v1`.
The broker sends no submit key. Submit through the
verified application and check its non-secret result. Never inspect or return
the filled code, or put it in chat, logs, screenshots or notes.

A code with less than eight seconds remaining is refused before dispatch.
Wait at least the returned `retry_after` seconds, then obtain a new search
handle and pin. Do not keep retrying the same code. If the site rejects two
fresh codes, stop and report the clock/configuration or site blocker; do not
guess, try other accounts, change 2FA or use recovery codes as routine MFA.
After timeout, disconnect or uncertain/partial delivery, inspect the site's
non-secret state before deciding whether any deliberate retry is appropriate.
The machine clock must be synchronized; expiry uses wall time while handles
and delivery deadlines use monotonic time. Browser dispatch is also bounded in
the renderer/extension by the remaining code lifetime. An expiry, clock change
or lost response after dispatch is uncertain; do not retry automatically.

## One-time private import

For an authorized authenticator save, select an existing entry with a fresh
search handle and supply all four exact returned metadata fields:

```bash
akdbx setup-totp HANDLE --title 'Example' --username 'alice@example.com' \
  --url 'https://example.com/login' --group 'Web'
```

The command returns `write_handle`, `private_url` and `state: pending`.
The user opens that private HTTPS page, confirms the displayed destination,
and enters the Base32 setup key or otpauth TOTP URI there. Never ask for the key
in chat, pass it through RPC/CLI arguments/environment variables, read a live
QR/setup key with GUI/browser tools (screenshots, page text, image data), or
extract a vault field; the broker's own `capture-totp --qr` is the only QR read. Do not observe
the page while the user enters a key. No secret is returned or shown after
submission. This initial private import is separate from later automatic fills.

Check `write-status -- WRITE_HANDLE` for `state: saved`. `cancel-write -- WRITE_HANDLE` cancels an
unused request. The private link expires after five minutes and is invalid
after a save attempt, cancellation, restart or conflicting vault change.
Input validation errors permit correcting the same private form without
reflecting its values. If a save response is lost, check write status and
search before starting another import. If the broker restarted, search for
the saved marker; a dispatch receipt alone is not proof of a durable save.

An existing OTP field requires explicit `setup-totp ... --replace`, which is
only appropriate for an authorized key replacement. Old keys remain in
encrypted entry history and existing encrypted backups. There is no key-reveal,
export, delete-TOTP or history-restore command in this version.

This saves an authenticator to KeePass only. It does not enable or reconfigure
2FA on the site. To add an authenticator app to a website account without a
private page (0.35.0+), use [automatic enrollment](totp-enrollment.md): the
broker reads the setup key through a CDP or extension read pin. Native controls
cannot verify the enrollment site's origin. When the page shows only a QR code,
the broker decodes that QR code in the browser instead (`--qr`,
`totp_qr_capture_protocol: 1`); the agent still never sees the key. A pending site enrollment can be checked after import with a
normal code fill, but the agent must separately verify site acceptance and
report failed enrollment accurately. Do not remove recovery methods. This
version attaches TOTP to existing entries, including managed SSO/email-code
identities; it does not create dummy-password or standalone TOTP-only records.

The standard protected KDBX `otp` field stores a normalized otpauth URI.
The broker verifies the exact protected field by reopening the encrypted
candidate before vault replacement; passwords and unrelated entry data are
preserved. Stale/external edits and recovery-required state refuse writes.
Imports also refuse a current entry or history version dated after the host's
clock. Ordinary same-second saves wait up to 1.25 seconds for a newer real
second; a frozen or backward clock refuses the save. Synchronize the clock
before a new private import. Do not rewrite history or backdate records to
force a save. The broker never invents a future modification time.

Supported: RFC 6238 SHA1/SHA256/SHA512, six/eight digits, 15..120-second periods.
A bare Base32 key defaults to SHA1, six digits, 30 seconds. A URI carries other
settings. Unsupported formats and duplicate/unknown URI parameters are
rejected; HOTP and Steam are unsupported. The ordinary manual-setup path rejects
authenticator migration payloads; the separate private importer below accepts
supported Google export batches.
No legacy KeePass OTP custom-field formats are automatically migrated.

Version 0.12.0 adds a separate [private QR/Google export importer and browser
capture workflow](private-import.md). The ordinary `parse_setup`/RPC path still
rejects migration payloads; only the private importer accepts them. Require its
own advertised protocol, keep the user's private import page outside agent
observation, and never use a website reset as a transfer shortcut.

This replaces routine code entry only. Push approvals, SMS, passkeys, device
requirements, account recovery and organization policies remain separate.
Passwords and authenticator keys available to one host are not independent
factors against compromise of that host. Keep recovery outside the agent's
control; the broker's same-OS-user security limits still apply.
