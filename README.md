# akdbx

`akdbx` is a local KeePass (`.kdbx`) autofill broker designed for AI agents. Agents may search login metadata and choose an opaque, short-lived handle. They never receive the password: the broker sends it to a retained Chromium DOM password input and returns only a success receipt.

Source and issue tracker: [7bgsbm749g-boop/akdbx](https://github.com/7bgsbm749g-boop/akdbx).

## akdbx rebrand (0.9.2)

The project, Python distribution, Python package and agent skill are named
`akdbx`. The command remains `akdbx`; new integrations import `akdbx` and invoke
`$akdbx`. The old `agentic_kdbx` import remains a compatibility alias.

New brokers use `akdbx/akdbx.sock` under `XDG_RUNTIME_DIR`, or
`/tmp/akdbx-UID/akdbx.sock` without it. When the new socket is absent, the CLI
can connect to an existing `agentic-kdbx.sock` using the same path, ownership
and peer checks. This lets an unlocked broker finish its session without a
restart. Explicit `--socket` remains supported. Existing encrypted vaults,
recovery directories, admission locators and receipts must retain their paths;
the rebrand does not migrate or rewrite private vault data.

## Security model

- The unlocked database and plaintext secrets stay in the foreground broker process.
- The API has no reveal, clipboard, export, or arbitrary-field operation.
- Search returns only title, username, URL, group, a random authenticated handle,
  auth-method/passwordless flags, and TOTP-presence flags.
- Handles expire after five minutes and are consumed on the first fill attempt.
- The Unix socket and its directory are mode `0600` and `0700`. The CLI rejects
  symlinked or incorrectly owned runtime paths and verifies the server's Unix
  peer UID before sending a request.
- The broker starts locked. The user enters the master password only on the private Tailscale HTTPS unlock page, never in chat, terminal input, arguments, or environment variables.
- After unlock, password fills use an explicitly configured Chromium CDP connection and a retained DOM password input. They never send password keys or Tab. Unsupported targets refuse delivery without terminal approval.
- Errors are deliberately generic after the typing boundary.

This prevents accidental disclosure into chat, command output, logs, process arguments, and agent RPC responses. It does **not** protect against a malicious process running as your OS user, a compromised target application, screen/key logging, or an agent that can redirect focus or inspect a filled web page. Password fills require a short-lived DOM target pin; see [the target contract](skills/akdbx/references/target-fill.md). The broker verifies the exact HTTPS page, main frame and retained editable password input. X11 window pins refuse password/login delivery. Application acceptance remains a caller check; malicious pages and compromised local processes are outside this boundary. Python cannot guarantee memory zeroization.

## Install and run

Linux desktop with X11, X-Resource 1.2 local PID support and EWMH window-manager metadata. Set `AKDBX_UNLOCK_ORIGIN` in your private local environment to the HTTPS origin configured in Tailscale Serve before starting the broker or using the CLI. For example, `https://node.example:9443` is an illustrative origin, not a deployment address:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/akdbx --unlock-origin "$AKDBX_UNLOCK_ORIGIN" \
  serve /absolute/path/to/passwords.kdbx --web-unlock \
  --password-browser-profile /absolute/path/to/chrome-user-data
```

Keep the broker process running. Open its private unlock page from your Tailscale-connected device and enter the master password there. The broker needs no terminal input and can run in a persistent agent PTY that the user cannot access. After unlocking, use another shell—or an agent—to search, focus the destination, and explicitly fill:

```bash
.venv/bin/akdbx search github.com
.venv/bin/akdbx pin-password-target --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
  --top-url VERIFIED_EXACT_HTTPS_URL --selector '#password' --mode password
.venv/bin/akdbx fill HANDLE_FROM_SEARCH --mode password --target TARGET_FROM_PIN
```

Before starting the broker, choose the private Chrome user data directory shown above (or set `AKDBX_PASSWORD_BROWSER_PROFILE`). Configure that browser's startup with `--user-data-dir=/absolute/path/to/chrome-user-data --remote-debugging-port=0` so Chrome writes its selected port and browser endpoint to `DevToolsActivePort`. [Chrome 136 and later require a non-default user data directory](https://developer.chrome.com/blog/remote-debugging-port); explicitly naming Chrome's default directory with `--user-data-dir` does not enable remote debugging there. This concerns the user-data root, not a profile name such as `Default`. A fixed debugging port does not provide `DevToolsActivePort` for this transport. The broker does not start or change Chrome. The profile must be owned, mode 0700, without symlink components; launch Chrome with `umask 077` so `DevToolsActivePort` is not writable by other users. On Linux, the broker also verifies the kernel UID of the connected TCP peer before the WebSocket handshake. An unavailable or ambiguous ownership check refuses; redirects and reconnection are forbidden. No profile means password fills refuse. Treat CDP as a privileged local interface.

Focus the password input before pinning. For `login`, pin with `--mode login --selector PASSWORD_SELECTOR --username-selector USERNAME_SELECTOR` and focus the username first. Username inputs require autocomplete field token `username`; password inputs require `current-password` or `new-password`. Valid ordered lists such as `current-password webauthn` and optional section/address prefixes are supported; malformed or conflicting tokens refuse. Delivery never rewrites the page's autocomplete attributes. Login fills both retained nodes with native DOM setters, without Tab or focus changes. Both saved and generated passwords require this path; a legacy X11 pin refuses them. HTTPS main-frame standard inputs are supported; child frames, shadow DOM, custom controls, and ambiguous or changed fields refuse. The broker sends no submit key and does not use the clipboard.

Some login forms omit semantic autofill hints or use `autocomplete="on"`.
When `status` advertises integer `password_purpose_protocol: 1`, callers who
independently verified a password-only field can pin it with
`--password-purpose current-password` (or `new-password` for an authorized
creation/change). The default remains strict. The option does not support
username/login modes or override `off`, malformed hints or a conflicting
password purpose; exact page, origin, retained input, focus and expiry checks
remain mandatory. It never edits site attributes or enables keyboard passwords.
See [the field-purpose contract](skills/akdbx/references/target-fill.md#password-inputs-without-semantic-autofill-hints).

There are no per-fill approval prompts. `--yes-on-fill` is a deprecated compatibility no-op; it emits a deprecation warning. All fill commands now require `--target`. Remove it from new commands. `--web-unlock` remains accepted for clarity; private web unlock is now the default and only unlock method, even when the flag is omitted. The former hidden terminal master-password prompt has been removed.

### Unlock remotely over Tailscale

On your host, set the private deployment origin as described above, then start the broker without entering the master password locally:

```bash
.venv/bin/akdbx --unlock-origin "$AKDBX_UNLOCK_ORIGIN" \
  serve /absolute/path/to/passwords.kdbx --web-unlock \
  --password-browser-profile /absolute/path/to/chrome-user-data
```

The broker starts locked. `status` and `search` responses provide a one-time unlock link under your configured HTTPS origin. Open it from a device signed into the tailnet, enter the KDBX master password, and then use the broker normally. The backend listens only on a Unix-domain socket in the broker's private runtime directory; it does not open a TCP port. Tailscale Serve supplies HTTPS, tailnet access control, and the authenticated identity header. The filesystem boundary prevents another local UID from replacing a stopped backend behind the trusted HTTPS origin. The page and URL are non-cacheable, attempts are rate-limited, request logging is disabled, and the URL token is replaced after a successful unlock.

The CLI independently trusts that HTTPS origin; it rejects broker responses
containing an HTTP, malformed, credential-bearing, or different-origin unlock
link. Every deployment must configure the client with the intended origin
using global `--unlock-origin HTTPS_ORIGIN` (or `AKDBX_UNLOCK_ORIGIN`) before the
subcommand. The same setting configures the broker's private-page origin at startup; the built-in default is a non-routable example. Existing deployments must set their current trusted origin before updating the CLI or restarting the broker. Keep real hostnames and deployment paths in private configuration, outside Git. A broker running under a separately configured account likewise
requires global `--broker-uid UID` (or `AKDBX_BROKER_UID`).

The master password travels inside the tailnet HTTPS connection directly to the local broker. It is never returned to the CLI or agent. Unlock remains valid for the lifetime of the broker process.

Key-file databases are supported with `serve DB --keyfile KEY`. Stop the broker with Ctrl-C to lock it and remove its socket. Explicit password writes and merges can modify the database; ordinary unlock, search and fill remain read-only.

### Payment cards (0.14.0)

Cards use ordinary KDBX entries with custom fields; no format extension is
needed. `akdbx.card=v1` identifies a card. Cardholder name, number, expiry month,
expiry year and optional security code use protected custom strings named
`akdbx.card.name`, `.number`, `.month`, `.year` and `.csc`. These field names are
akdbx conventions; other clients can display them as custom fields.

`create-card --title LABEL --group EXISTING_GROUP` opens a private card-save
workflow. Enter card values only on the returned private HTTPS page. Never
put them in command arguments, agent messages or notes. `update-card HANDLE
--title EXACT_TITLE --group EXACT_GROUP` prepares an update. Updates preserve
the previous entry in KDBX History. `write-status` and `cancel-write` apply to
these saves. Persistence reopens and verifies every protected field before
replacing the encrypted vault. A private page expires after five minutes.

`search-cards QUERY` returns only title, group, brand, last four digits and a
single-use handle. Ordinary login search excludes card entries; password
operations refuse card records. Expired cards cannot be filled.

Card delivery uses a retained DOM element in a private isolated JavaScript world
through Chrome DevTools Protocol. It never sends keyboard events, Tab or submit,
and cannot direct input into the browser address bar through keyboard focus.
The broker checks the exact HTTPS page/frame URLs, unique selector, matching
`autocomplete` card token, element identity, editability, visibility and
occlusion. It repeats input checks in the same JavaScript task as the native value
setter. A focus change cannot select a different destination. Replacement,
navigation, expiry or unsupported markup refuses the fill. An interrupted
delivery is reported as uncertain and must not be retried automatically.

Configure the broker with `serve DB --card-browser-profile /absolute/USER_DATA_DIR`
or `AKDBX_CARD_BROWSER_PROFILE`. This must be the existing, owned, mode-0700
Chrome **user-data directory**, containing an owned, non-symlink,
non-group/world-writable `DevToolsActivePort` file from a loopback debugging
port. The broker does not launch/restart Chrome, enable debugging, change
profiles or fall back to X11. Keep this directory and the debugging connection
private. An unconfigured/unsupported browser refuses fills; storage and search
remain available.

Before sending any WebSocket bytes, the broker verifies that its UID owns the
server side of the connected loopback TCP socket using Linux's bounded
/proc/self/net/tcp table. It keeps that exact socket and refuses redirects.
Missing or ambiguous ownership data refuses the connection, including stale
port files that point to another user's listener.

Chrome's debugging port grants browser control. Loopback binding alone does
not restrict it to one OS user. Use a host environment that restricts access
to trusted clients; the private profile-directory checks do not provide network
authentication for CDP. Do not enable a debugging port as an automatic workaround
for a refused fill.

After independently verifying the merchant and payment form, obtain the page
and frame IDs through your browser's DOM inspection tools, bring the intended
field into view, and pin its exact selector and autocomplete field type:

```bash
akdbx search-cards 'Personal Visa'
akdbx pin-card-target --page-id PAGE_ID --frame-id FRAME_ID \
  --top-url https://merchant.example/checkout \
  --frame-url https://merchant.example/checkout \
  --selector '#card-number' --field cc-number
akdbx fill-card CARD_HANDLE --target CARD_TARGET --field cc-number
```

Pins have a maximum lifetime of 30 seconds and are consumed on the first fill attempt. Use a fresh
search handle and pin for each field. Supported types are `cc-name`, `cc-number`,
`cc-exp-month`, `cc-exp-year`, `cc-exp` and `cc-csc`. Combined expiry requires
`--format MM/YY` or `MM/YYYY`; expiry year requires `--format YY` or `YYYY`.
Month/year selects are supported when the value matches an unambiguous option.
Main frames and same-origin iframes are supported. Version 0.14.0 adds the
explicit `--processor adyen` pin option, gated by integer
`card_processor_frames_protocol: 1` and `adyen` in `card_processors`.
Only production HTTPS `checkoutshopper-live.adyen.com` secured-field iframes
attested by Chrome to the selected merchant tab are accepted. All intermediate
merchant frames must be same-origin with the top page. The broker retains
the input and iframe-owner elements in isolated worlds, refuses unsupported CSS
transforms, motion paths, filters and masks, and checks exact URLs,
frame ancestry, identity and occlusion before and after dispatch, and preserves
the single-use pin, deadline and receipt-only contract. Child input checks run
in the write task; cross-process ancestor checks run separately. A changed or
lost post-dispatch guard is uncertain and must not be retried automatically.
Other cross-origin frames, shadow DOM, unannotated fields and native
applications remain unsupported. Merchant verification uses part of the pin's
lifetime, while the four-second fill deadline starts with the fill request.
An already expired pin is not issued. See the skill's card guide for the exact
processor pin command and independent merchant verification requirements.

The success receipt contains only the field type and transport, never a card
value. It confirms the element accepted the value at dispatch; it does not
prove merchant acceptance or authorize a purchase. The intended page receives
the card values. A malicious page, compromised browser or process with the same
OS-user privileges remains outside this boundary. Do not read filled card values
back through browser tools or capture unmasked fields in screenshots.

### Card-save notifications

Private card forms can resume the same agent task through a one-shot HTTPS
webhook, with the same bounded sender and private persistent storage used by
unlock notifications. Register before sharing the form; no completion message
or polling schedule is needed:

```bash
.venv/bin/akdbx subscribe-card-save WRITE_HANDLE --webhook-url-file /private/url-file
.venv/bin/akdbx card-save-subscription-status SUBSCRIPTION_ID
.venv/bin/akdbx unsubscribe-card-save SUBSCRIPTION_ID
```

Require `card_save_notifications_protocol: 1` and
`card_save_notifications_until_result: true` from the running broker. Waits have
no subscription TTL. The existing form deadline emits `expired`; cancellation,
invalidation and persistence failure also emit terminal results. A validation
typo leaves the form pending. Callbacks contain only `akdbx.card-save`, a result
state and opaque event/subscription IDs. Card values, metadata, form tokens and
write handles are excluded. Pending callbacks survive restart in the configured
notification-state file plus `.card-saves`; an unfinished form reports
`interrupted` because private form contents are never restored. See the
[card-save notification workflow](skills/akdbx/references/card-save-notifications.md)
for host registration, verification, duplicate handling and cleanup.

### Unlock notifications (0.11.0)

Agents can subscribe to a one-shot unlock webhook and end their turn. In T3,
create a webhook task bound to the current thread, register its returned URL,
and let T3 resume the thread when the broker posts the unlock event. No “unlocked”
chat reply, active agent wait or polling schedule is needed. Other agent hosts
can use their own incoming webhook/event adapters.

```bash
.venv/bin/akdbx subscribe-unlock --webhook-url-file /private/url-file
.venv/bin/akdbx unlock-subscription-status SUBSCRIPTION_ID
.venv/bin/akdbx unsubscribe-unlock SUBSCRIPTION_ID
```

The URL file must be an owned mode-0600 regular file. The URL is private and is
never echoed in receipts. Events contain only `event: "akdbx.unlocked"`,
`locked: false` and opaque subscription/event IDs. Registration cannot miss a
racing unlock; an already-unlocked broker queues the event immediately. Delivery
runs outside the unlock request, uses verified HTTPS without redirects, and
retries at most three times with the same event ID. Subscriptions wait until
unlock or explicit cancellation by default. Pending
callbacks survive restarts through the configured private notification-state
file; choose persistent storage outside `/run` for host reboot survival. Only an
explicitly requested time-limited wait uses `--ttl 60..3600`. Delivery attempts
and the number of stored subscriptions remain bounded. The agent must remove
the host trigger and recheck broker readiness before continuing.

Require the running broker's `unlock_notifications_supported: true` and integer
`unlock_notifications_protocol: 1`; source/CLI updates alone do not activate a
running broker. See [the notification workflow](skills/akdbx/references/unlock-notifications.md)
for exact T3 registration, cleanup and recovery.

## Authenticator codes (0.10.0)

`akdbx` can import TOTP authenticator keys and directly fill the current code
without returning the key or code to the agent. It supports RFC 6238 SHA-1,
SHA-256 and SHA-512, six or eight digits, and periods from 15 to 120 seconds.
The default for a manual Base32 key is SHA-1, six digits and 30 seconds.
Other settings require an `otpauth://totp/` URI. HOTP and Steam codes are not
supported. There is no code-reveal or key-export command.

Version 0.12.0 adds [private QR/Google transfer import and Chrome native capture](skills/akdbx/references/private-import.md).
The private setup page can decode QR images on the user's device, review a
complete Google export batch, and save one explicitly selected account to an
existing entry. It copies the existing key without removing phone accounts or
changing website 2FA. An optional Linux Chrome extension sends one selected
site's setup QR directly to a local native host/broker; private confirmation is
still required before any save. The agent receives only receipts, never keys,
codes or QR images. Authy/Microsoft export restrictions are not bypassed.
Require `totp_import_supported: true` and integer `totp_import_protocol: 1` in
the running broker. Installation does not activate an already-running broker.

Check that `status` advertises `totp_supported: true`, integer `totp_protocol: 1`,
and the existing target-fill protocol. New CLI commands refuse old brokers.
Updating source or pushing a commit does not update a running broker: install
the tested version and coordinate its normal restart/private unlock first.

For one-time import, select an existing account entry with `search`, then pass
its fresh handle and all four exact metadata fields:

```bash
akdbx setup-totp HANDLE --title 'Example' --username 'alice@example.com' \
  --url 'https://example.com/login' --group 'Web'
```

This returns a private `/totp?token=...` page. The user enters the site's setup
key or otpauth URI there and confirms the displayed account. Never put keys,
URIs or generated codes in CLI arguments, environment variables, chat, logs,
screenshots or notes. The page uses the existing Tailscale private-write
transport; it accepts no secrets through agent RPC. Check
`write-status WRITE_HANDLE` for `state: saved`. A cancelled, expired or stale request cannot
save; an existing OTP field requires explicit `setup-totp ... --replace`.
Private imports save to KeePass only: they do not enable or change site 2FA.
This version attaches authenticators to existing entries, including managed
passwordless identities; it does not create standalone TOTP-only records.

The key is stored in the standard protected KDBX `otp` field. The broker
reopens the encrypted candidate and verifies the exact protected field before
replacing the vault. Existing passwords, notes and other fields are preserved;
replacing a key keeps the previous entry in encrypted history. No existing key
is exposed on the import page. Keep recovery methods under your own control.
Storing passwords and TOTP keys on the same host reduces their independence;
the broker does not protect against a malicious process sharing its OS account.

After import, search returns `totp_configured: true` for that entry. Confirm the
site and account, focus the code field in the verified foreground window, then
pin and fill using fresh single-use references:

```bash
akdbx search example.com
akdbx pin-target --pid VERIFIED_PID --window VERIFIED_X11_CLIENT_WINDOW
akdbx fill-totp FRESH_SEARCH_HANDLE --target-url 'https://example.com/challenge' \
  --target FRESH_TARGET_PIN
```

The asserted target URL and the entry URL must use ASCII HTTPS spelling
(punycode for internationalized hosts) and match in origin; X11 does
not attest the DOM field, browser tab or origin. The caller must verify them.
The receipt contains only `ok`, `filled: totp` and `target_delivery`.
The broker refuses a code with less than eight seconds remaining, returning
a non-secret `retry_after` delay. Wait for the next period, then search and pin
again. Keep the host clock synchronized. Never retry an uncertain/partial
dispatch automatically or read back a filled code; verify the site's outcome.
This handles standard authenticator challenges, not push approvals, SMS,
passkeys, recovery checks or organization-specific device requirements.

Algorithm references: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) and
[Google's Key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

## Encrypted vault merge (0.8.0)

```bash
akdbx status
akdbx merge /absolute/path/to/other.kdbx --check
akdbx merge /absolute/path/to/other.kdbx
akdbx merge /absolute/path/to/other.kdbx --refresh-target
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts --check
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts
akdbx merge-status OPERATION_ID
```

Require broker 0.8.0, `merge_protocol: 1`, `merge_available: true` and no recovery
block. The broker privately reuses its held password and key file. Locked
operation returns the existing private HTTPS unlock link and a clear command
continuation. Different source credentials are not supported in this release.

The native dependency is root-owned `/usr/bin/keepassxc-cli` >=2.7.10,<2.8
(tested: 2.7.10). Its UUID-aware merge keeps newer entry versions and combines
history. A broker deletion pass applies timestamped UUID tombstones; newer edits
survive. Default mode refuses genuine equal-second conflicts and loss of surviving
history/fields. Explicit `--preserve-conflicts` retains every distinct original
active/history entry version in opaque preservation attachments inside the encrypted
KDBX, including original timestamps, fields, attachment bytes and referenced icons.
Newest active values win; equal-time active ties prefer the current disk target,
then broker image, then source. No original timestamp is changed. Native History
can still collapse or prune versions; the verified preservation records retain
them across repeats, reconciliation and history limits. These managed records are
excluded from broker search/fill and password destinations. There is no capsule
restore/view/export command in this release. See the workflow for the documented
format and limits. Destination database settings remain authoritative;
source custom icons/CustomData follow native engine rules. See the workflow for
metadata conflict details and unsupported credential types.

The default still refuses externally changed targets. Explicit
`--refresh-target` requires `merge_refresh_target_supported: true` and combines
the last verified encrypted broker image, the current disk target and the
incoming source. It privately reuses held credentials, retains all three inputs,
checks both native merge stages, then applies all deletion records. Broker-only,
external-only and incoming-only entries survive according to the conflict and
deletion rules. `--check` also works with this option and adopts no state.
Successful reconciliation refreshes the broker and invalidates handles even if
the disk file already held the full result. Bad current keys, incomplete receipts
and races remain failures. This is not a plain reload or a security override.
For the preservation option require `merge_preserve_conflicts_supported: true`
and `merge_preservation_policy: "capsule-v1"`. Use both options for explicit authorized
reconciliation. A transformed merge does not satisfy an unmodified KeePassium
consecutive-save byte contract. The CLI checks the exact policy before sending
the request; raw RPC integrations must do the same. Version 0.6.0 also requires
`merge_active_verification: "semantic-v1"`. It verifies active values separately
from native serialization and independent entry location changes, while keeping
the capsule-v1 format and exact original payloads unchanged. Standard/custom
values, protection against downgrade, attachments, active times/expiry and
native location selection remain checked. Known tag/default/protection/settings
and CustomData clock transformations are documented in the workflow. Refusals
add only fixed aggregate `verification_diagnostics` categories; they expose no
record identities, field names/values or secret digests. Status advertises
`merge_diagnostics: "categories-v1"`. Raw callers must require these capabilities
and verify `active_verification: "semantic-v1"` in saved/check receipts.
PyKeePass is pinned to the
tested 4.2.0; another version disables this policy. `--check` supports both options.
The basic command remains compatible with 0.3.0; the new CLI rejects unsupported
brokers before sending an opt-in. Activating 0.8.0 in place of an older running
process still requires a coordinated restart/private unlock with its latest
encrypted state retained; future external saves need no additional unlock.

Both encrypted originals and a reopened encrypted candidate are retained in a
private recovery directory beside the target. The source stays unchanged.
Replacement uses the existing advisory lock, change checks, restrictive
permissions, fsync and atomic rename. Success refreshes the active broker and
invalidates old selection/write handles. Responses contain only status, counts,
encrypted checksums and durable receipt paths. No plaintext password or raw engine output
is returned or written to disk. A lost response must be resolved with
`merge-status`, not an automatic retry. Incomplete receipts block use after
restart until authorized recovery. Keep competing editors/sync writers away
from the inputs during merge; filesystem advisory locks cannot constrain them.

Read [the supported merge workflow](skills/akdbx/references/merge.md)
for the normal command path, exact semantics, recovery and activation. A source
update does not replace a running broker. Development uses synthetic vaults and
isolated sockets only; it does not access or restart the production broker.

## Passwordless email-code identity records (0.9.1)

`create-passwordless-entry --title TITLE --username ACCOUNT --url SITE --group GROUP
--auth-method email_code` saves an authorized account verified through the site's
native emailed-code sign-in. It saves an empty Password field, not the one-time
code. It neither labels the account as SSO nor creates/copies a password.
Require CLI/broker 0.9.1 or newer, `passwordless_identity_supported: true`, integer
`passwordless_identity_protocol: 1`, and `email_code` in
`passwordless_auth_methods`. The CLI checks these capabilities before dispatch;
an older running broker is refused even if new CLI help is present.

This separate action reuses SSO's metadata validation, duplicate checks,
verified encrypted persistence, backups and recovery rules. The entry has
`akdbx.passwordless: "v1"` and `akdbx.auth-method: "email_code"`; search returns
`passwordless: true` and `auth_method: "email_code"`. Password/login fills and
password updates/generation refuse it. Username-only fill still requires the
existing fresh target pin. Empty or incomplete managed markers fail closed.
Google/GitHub remain on the unchanged SSO protocol 1 and `create-sso-entry`.
See [email-code save and parent activation](skills/akdbx/references/password-writes.md#passwordless-email-code-identity-records-091).

## Passwordless SSO identity records (0.8.1)

`create-sso-entry --title TITLE --username ACCOUNT --url SITE --group GROUP
--auth-method google` saves an explicitly authorized Google SSO account with
an empty Password field and clear provider/no-separate-password markers.
`--auth-method github` is also supported. It never generates, copies, accepts
or exports a password, opens a password form, or types credentials. Require
CLI/broker 0.8.1 or newer, `sso_identity_supported: true`, integer
`sso_identity_protocol: 1` and the selected provider in `sso_auth_methods`.
The CLI checks the running broker before dispatch. Existing group selection,
same-origin/account duplicate checks, write safety, conflicts, recovery refusal,
verified encrypted persistence and backups are reused. Search reports provider
and passwordless flags; login/password fills and password writes refuse these
records, while username-only fill remains available. The ordinary chosen-
password workflow below still requires private confirmation and a nonempty
password. Read [the exact SSO workflow and activation requirements](skills/akdbx/references/password-writes.md#passwordless-sso-identity-records-081).

## Password writes (0.2.0)

`akdbx --version` reports the CLI version. Broker `status` reports its own
`version`, `writes_available` and `recovery_required`; require an unlocked,
write-capable broker version 0.12.0 or newer before changing a website password.
Password fills also require integer `password_fill_protocol: 1`,
`password_fill_delivery: "chromium-password-dom-v1"`, and
`password_browser_configured: true` in the running broker's status.

- `create-entry --title TITLE --username ACCOUNT --url SITE --group GROUP`
- `update-password SEARCH_HANDLE --title TITLE --username ACCOUNT --url SITE --group GROUP`
- `generate-password SEARCH_HANDLE --title TITLE --username ACCOUNT --url SITE --group GROUP [--length 24] [--symbols '!@#$%*-_+=?']`
- `fill-generated --target-url VERIFIED_RESET_URL --target TARGET_FROM_FRESH_PIN -- SINGLE_USE_FILL_HANDLE`
- `commit-password --site-accepted -- WRITE_HANDLE`
- `write-status -- WRITE_HANDLE`
- `cancel-write -- WRITE_HANDLE`

Update/generation requires all exact search metadata and consumes the fresh
search handle. Creation checks the destination group and rejects duplicate
site/accounts. Create/update returns a private confirmation page where the user
reviews metadata and enters/repeats a chosen password; secrets never pass
through the CLI. Generated reset passwords remain in broker memory: two
single-use references fill password and confirmation fields on the verified
broker desktop, then explicit site acceptance permits saving the same secret.
Generated resets require the entry and asserted target URLs to use ASCII HTTPS
spelling (punycode for internationalized hosts) and to match in origin.
No operation exports, shows, logs or copies passwords.

Writes expire after five minutes and vanish on restart. Site rejection requires
cancellation, not a vault overwrite. Saves serialize against fills/searches,
check on-disk conflicts, preserve history and unrelated vault data, verify the
encrypted candidate, retain mode-0600 encrypted backups and replace atomically.
Failed or uncertain saves never return success. Successful writes become
immediately searchable/fillable and invalidate previous selection handles.
The advisory disk lock does not constrain uncooperative external editors;
arrange exclusive vault editing during saves.

See [password workflows and recovery](skills/akdbx/references/password-writes.md)
for reset coordination, policy constraints, focus/origin checks, cancellation,
conflicts, backup recovery and activation. Installing new code does not replace
a running broker: coordinate restart and private re-unlock with its owner after
any live interaction ends.

## Agent contract

The installed agent skill is [skills/akdbx/SKILL.md](skills/akdbx/SKILL.md), which can be installed under your agent's local skills directory. Agents can invoke it as `$akdbx`; automatic selection is enabled for saved-login, KeePass, and autofill tasks. New sessions can discover the installed skill. An existing session whose skill catalog has not refreshed can read the file directly.

The skill covers exact CLI commands, remote unlock, account selection, desktop targeting, explicit fills, and recovery from uncertain fills. Its [setup reference](skills/akdbx/references/vps-setup.md) documents X11 desktop requirements, socket discovery, startup, and Tailscale configuration using portable examples. The skill directory in the repository is the maintained source; a local installation can link to it so updates stay in sync.

An agent should:

1. Run `akdbx search <site-or-app>` and show the user the non-secret choices.
2. Verify the destination and focus the intended field, then use exactly one returned handle with `akdbx fill`. No further user approval is required for the authorized login task.
3. Never ask for the master password or attempt to read, log, copy, or inspect a filled password field.
4. Search again if a handle expires. An `autofill not started` response guarantees that request sent no keys. A timeout or lost connection can still mean typing had already started, so check non-secret target state and never retry automatically.

Existing broker processes retain their loaded code until restarted. The originating login workflow should stop its old broker before starting the command above with the same database, key file, socket, and desktop environment, then request a fresh private web unlock. Old handles cannot be reused after restart. See the [VPS setup reference](skills/akdbx/references/vps-setup.md) for the deployment command.

Remote unlock requires Tailscale Serve to proxy HTTPS to the broker's Unix socket, not to a persistent loopback TCP port. This mapping must be installed by root with Tailscale 1.98.9 or newer; older versions had a Unix-socket Serve authorization flaw. Merely starting the updated broker does not migrate an existing Serve mapping. Follow the setup reference when deployment changes are authorized.

## Development

```bash
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
```

Card browser tests skip locally if Chrome/Chromium, Xvfb or openssl is missing.
The foreign-UID listener test requires an explicit opt-in and passwordless
`sudo -n -u nobody`. To require both native checks locally, install those
dependencies and run:

```bash
AKDBX_REQUIRE_CARD_CHROMIUM=1 AKDBX_TEST_FOREIGN_UID=1 \
  .venv/bin/pytest tests/test_cards.py tests/test_card_target.py tests/test_card_chromium.py -q
```

Card CI enables both requirements and rejects any skipped case.

Merge integration tests require the native KeePassXC CLI dependency above.
Tests generate synthetic KDBXs under pytest's temporary directory, with isolated
RPC and HTTP Unix sockets. Keep temporary fixtures outside every synced vault;
store retained evidence in the project's gitignored `evidence/` directory, outside
synced vaults.
Most fixtures use a reduced KDF cost. `test_full_argon2d_41_profile` separately
uses KDBX 4.1/AES-256/Argon2d with I=119, M=67108864, P=2, V=19. The suite
includes the installed CLI, broker, native engine, encrypted replacement, reopen,
private HTTP form handling, restart receipts and regression boundaries. Its
test-only identity headers do not test the deployed Tailscale HTTPS proxy,
native browser input, real vaults, synchronization services, or mobile editors.

## Exact-byte snapshot admission (0.8.0 review prototype)

**NEEDS PARENT POLICY REVIEW before activation.** Existing capsule-v1 merge
defaults remain unchanged. The separate `admit` operation saves exact incoming
encrypted bytes only after proving the required active state and existing
capsules survive. Complete encrypted originals are retained outside canonical;
new per-upload capsules are not required. Ordinary-history versions can remain
only in those encrypted backups. Conservative group/settings conflicts refuse.

```bash
akdbx admit /absolute/private-staging/upload.kdbx --policy snapshot-admission-v1 \
  --snapshot-dir /absolute/private-backups/one-vault-admission --check
```

Read the [full admission contract](skills/akdbx/references/snapshot-admission.md)
before use, including capability/result checks, retention differences, real
conflict recovery, deadline limits, and coordinated restart/private unlock.
Synthetic transport evidence does not establish native iPhone compatibility.
Version 0.8.0 adds explicit `--group-verification group-tag-sequence-v1` and
`--group-verification native-group-selection-v1` profiles. Read the
[group contract and remaining limits](skills/akdbx/references/group-selection.md)
before selecting either. The old default `group-semantic-v1` remains narrower.
New CLI requires group protocol 2 and checks the exact requested profile in
capabilities and durable results; old 0.7.0/0.7.1 processes are rejected before
dispatch. Recovery locators/old receipts need no migration and gain no new
certification. Noncanonical tag separators can be admitted when the ordered
case-sensitive sequence, including duplicates, is unchanged. Native group
selection admits only already-complete selected properties/locations. Pure
entry moves/recycle deletes and root modification propagation remain conflicts;
this patch does not prove unrestricted native phone sync. No production or
native iPhone test is claimed.


## Password destination regression checks

`tests/test_browser_password.py` uses synthetic credentials, temporary Chrome
profiles, loopback HTTPS pages and separate Xvfb desktops (never the shared
desktop). It reproduces the former X11 omnibox delivery and checks direct DOM
saved/generated fills, login without Tab, wrong-field/selector/type changes,
replacement, focus restoration, tab changes, navigation and commit refusal.
`tests/test_password_endpoint.py` checks endpoint configuration and pin cleanup.
Existing native X11 tests cover the remaining username/TOTP transport.
Optional browser tests require Xvfb, Chromium, OpenSSL, xdotool and ImageMagick;
record skips explicitly. Store test output and temporary files outside project
checkouts, for example with pytest `--basetemp` in a private evidence directory.
Run heavy batches through the configured resource-manager queue.
