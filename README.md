# akdbx

`akdbx` is a local KeePass (`.kdbx`) autofill broker designed for AI agents. Agents may search login metadata and choose an opaque, short-lived handle. They never receive the password: the broker sends it to a verified, pinned X11 application window and returns only a success receipt.

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
  and auth-method/passwordless flags for managed SSO and email-code identities.
- Handles expire after five minutes and are consumed on the first fill attempt.
- The Unix socket and its directory are mode `0600` and `0700`. The CLI rejects
  symlinked or incorrectly owned runtime paths and verifies the server's Unix
  peer UID before sending a request.
- The broker starts locked. The user enters the master password only on the private Tailscale HTTPS unlock page, never in chat, terminal input, arguments, or environment variables.
- After unlock, an explicit `fill` invokes keyboard delivery immediately, without terminal approval. The caller must verify the destination and focus the intended field first.
- Errors are deliberately generic after the typing boundary.

This prevents accidental disclosure into chat, command output, logs, process arguments, and agent RPC responses. It does **not** protect against a malicious process running as your OS user, a compromised target application, screen/key logging, or an agent that can redirect focus or inspect a filled web page. Version 0.9.0 requires a short-lived target pin and directed X11 delivery; see [the target contract](skills/akdbx/references/target-fill.md). It verifies the local process, foreground window and X input focus through dispatch. Browser field/tab/origin and application acceptance remain caller checks; X11 metadata is not a hostile-process security boundary. Python cannot guarantee memory zeroization.

## Install and run

Linux desktop with X11, X-Resource 1.2 local PID support and EWMH window-manager metadata:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/akdbx serve /absolute/path/to/passwords.kdbx --web-unlock
```

Keep the broker process running. Open its private unlock page from your Tailscale-connected device and enter the master password there. The broker needs no terminal input and can run in a persistent agent PTY that the user cannot access. After unlocking, use another shell—or an agent—to search, focus the destination, and explicitly fill:

```bash
.venv/bin/akdbx search github.com
.venv/bin/akdbx pin-target --pid VERIFIED_PID --window VERIFIED_X11_CLIENT_WINDOW
.venv/bin/akdbx fill HANDLE_FROM_SEARCH --mode login --target TARGET_FROM_PIN
```

Focus the username field before invoking `fill`. `login` types the username, presses Tab, then types the password. `--mode username` and `--mode password` fill one field. Before sending any keys, the broker rejects a requested fill if any field it needs contains a control character, including Tab, carriage return, or newline. The broker sends no submit key of its own, reads nothing back from the destination, and does not use the clipboard.

There are no per-fill approval prompts. `--yes-on-fill` is a deprecated compatibility no-op; it emits a deprecation warning. All fill commands now require `--target`. Remove it from new commands. `--web-unlock` remains accepted for clarity; private web unlock is now the default and only unlock method, even when the flag is omitted. The former hidden terminal master-password prompt has been removed.

### Unlock remotely over Tailscale

On the configured VPS, start the broker without entering the master password locally:

```bash
.venv/bin/akdbx serve /absolute/path/to/passwords.kdbx --web-unlock
```

The broker starts locked. `status` and `search` responses provide a one-time `https://vps-3857965a.tailb80cc4.ts.net:9443` unlock link. Open it from a device signed into the tailnet, enter the KDBX master password, and then use the broker normally. The backend listens only on a Unix-domain socket in the broker's private runtime directory; it does not open a TCP port. Tailscale Serve supplies HTTPS, tailnet access control, and the authenticated identity header. The filesystem boundary prevents another local UID from replacing a stopped backend behind the trusted HTTPS origin. The page and URL are non-cacheable, attempts are rate-limited, request logging is disabled, and the URL token is replaced after a successful unlock.

The CLI independently trusts that HTTPS origin; it rejects broker responses
containing an HTTP, malformed, credential-bearing, or different-origin unlock
link. Custom deployments must configure the client with the intended origin
using global `--unlock-origin HTTPS_ORIGIN` (or `AKDBX_UNLOCK_ORIGIN`) before the
subcommand. A broker running under a separately configured account likewise
requires global `--broker-uid UID` (or `AKDBX_BROKER_UID`).

The master password travels inside the tailnet HTTPS connection directly to the local broker. It is never returned to the CLI or agent. Unlock remains valid for the lifetime of the broker process.

Key-file databases are supported with `serve DB --keyfile KEY`. Stop the broker with Ctrl-C to lock it and remove its socket. Explicit password writes and merges can modify the database; ordinary unlock, search and fill remain read-only.

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
write-capable broker version 0.2.0 or newer before changing a website password.

- `create-entry --title TITLE --username ACCOUNT --url SITE --group GROUP`
- `update-password SEARCH_HANDLE --title TITLE --username ACCOUNT --url SITE --group GROUP`
- `generate-password SEARCH_HANDLE --title TITLE --username ACCOUNT --url SITE --group GROUP [--length 24] [--symbols '!@#$%*-_+=?']`
- `fill-generated SINGLE_USE_FILL_HANDLE --target-url VERIFIED_RESET_URL --target TARGET_FROM_FRESH_PIN`
- `commit-password WRITE_HANDLE --site-accepted`
- `write-status WRITE_HANDLE`
- `cancel-write WRITE_HANDLE`

Update/generation requires all exact search metadata and consumes the fresh
search handle. Creation checks the destination group and rejects duplicate
site/accounts. Create/update returns a private confirmation page where the user
reviews metadata and enters/repeats a chosen password; secrets never pass
through the CLI. Generated reset passwords remain in broker memory: two
single-use references fill password and confirmation fields on the verified
broker desktop, then explicit site acceptance permits saving the same secret.
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

The installed agent skill is [skills/akdbx/SKILL.md](skills/akdbx/SKILL.md), available on this VPS at `/home/ubuntu/.codex/skills/akdbx`. Agents can invoke it as `$akdbx`; automatic selection is enabled for saved-login, KeePass, and autofill tasks. New sessions can discover the installed skill. An existing session whose skill catalog has not refreshed can read the file directly.

The skill covers exact CLI commands, remote unlock, account selection, desktop targeting, explicit fills, and recovery from uncertain fills. Its [setup reference](skills/akdbx/references/vps-setup.md) documents the managed VPS desktop, socket discovery, startup, and Tailscale configuration. The skill directory in the repository is the maintained source; the installed path links to it so updates stay in sync.

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

Merge integration tests require the native KeePassXC CLI dependency above.
Tests generate synthetic KDBXs under pytest's temporary directory, with isolated
RPC and HTTP Unix sockets. Keep temporary fixtures outside every synced vault;
store retained evidence under `/home/ubuntu/backups/send-to-t3-code`, never QLO2.
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


## Target-window regression checks (0.9.0)

`tests/test_target*.py` covers required pins, legacy broker downgrade refusal,
PID/window/focus switches, partial delivery and generated-password commit
refusal. Native widget/browser checks launch a fresh Xvfb display (never :99).
The Chromium test uses a new temporary profile and synthetic HTML fields; CDP
only prepares/observes them, while production X11Typer sends all nonempty input.
It passed six separate username/password fills and a username–Tab–password fill
on Chrome 153.0.8010.47. Optional native checks skip when Xvfb/Chromium is absent;
record those skips explicitly. No real vault, canonical browser/profile or live
broker is used. Run heavy batches through the configured resource-manager queue.
