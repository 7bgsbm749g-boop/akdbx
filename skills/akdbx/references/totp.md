# TOTP authenticators (0.10.0)

Use the broker to generate and enter authenticator codes for an authorized
sign-in or access-confirmation challenge. This does not authorize changing a
site's security settings. Reuse the shared browser session and verify the
account, origin and focused field before filling.

## Capabilities and selection

Require CLI/broker 0.10.0 or newer and `status` fields `totp_supported: true`,
integer `totp_protocol: 1`, `target_fill_required: true`, integer
`target_fill_protocol: 1`, and `target_fill_delivery: x11-send-event-v1`.
The CLI checks capabilities before sending TOTP requests. Updating installed
source does not change an old running process; coordinate its normal restart
and private unlock, without disrupting another live workflow.

Search the exact service and account. An entry with `totp_configured: true`
has an OTP field, which can still be malformed or unsupported. Select the
provider's entry for a provider challenge; a destination site's entry is not
the provider's authenticator. A passwordless identity can have an authenticator
without gaining password fill or password generation privileges.

## Fill a saved code

1. Independently verify the site, account, Chrome process/profile and X11
   client window. Focus the code field and keep the foreground stable.
2. Search for a fresh single-use account handle, then obtain a fresh
   `pin-target --pid VERIFIED_PID --window VERIFIED_X11_CLIENT_WINDOW` token.
3. Fill the current code directly:

   ```bash
   akdbx fill-totp HANDLE --target-url 'https://example.com/challenge' --target TARGET
   ```

4. Submit through the verified application and check its non-secret result.
   The broker sends no submit key. Never inspect the filled code to confirm
   typing or put the code into chat, logs, screenshots or notes.

The target URL is required, must be HTTPS, and must match the entry's origin.
Both URLs must use ASCII spelling, including punycode for internationalized
hostnames; Unicode URLs are refused to avoid ambiguous IDNA normalization.
This is a caller assertion: pinned X11 delivery does not verify a DOM field,
tab, origin or site acceptance. All search handles and target pins are
single-use, including on failure. Success returns only a dispatch receipt:
`ok: true`, `filled: totp`, `target_delivery: x11-send-event-v1`.

A code with less than eight seconds remaining is refused before dispatch.
Wait at least the returned `retry_after` seconds, then obtain a new search
handle and pin. Do not keep retrying the same code. If the site rejects two
fresh codes, stop and report the clock/configuration or site blocker; do not
guess, try other accounts, change 2FA or use recovery codes as routine MFA.
After timeout, disconnect or uncertain/partial delivery, inspect the site's
non-secret state before deciding whether any deliberate retry is appropriate.
The machine clock must be synchronized; expiry uses wall time while handles
and delivery deadlines use monotonic time.

## One-time private import

For an authorized authenticator save, select an existing entry with a fresh
search handle and supply all four exact returned metadata fields:

```bash
akdbx setup-totp HANDLE --title 'Example' --username 'alice@example.com' \
  --url 'https://example.com/login' --group 'Web'
```

The command returns `write_handle`, `private_url` and `state: pending`.
The user opens that private Tailscale page, confirms the displayed destination,
and enters the Base32 setup key or otpauth TOTP URI there. Never ask for the key
in chat, pass it through RPC/CLI arguments/environment variables, read a live
QR/setup key with GUI/browser tools, or extract a vault field. Do not observe
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
2FA on the site. A pending site enrollment can be checked after import with a
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
rejected; HOTP, Steam and authenticator migration payloads are unsupported.
No legacy KeePass OTP custom-field formats are automatically migrated.

This replaces routine code entry only. Push approvals, SMS, passkeys, device
requirements, account recovery and organization policies remain separate.
Passwords and authenticator keys available to one host are not independent
factors against compromise of that host. Keep recovery outside the agent's
control; the broker's same-OS-user security limits still apply.
