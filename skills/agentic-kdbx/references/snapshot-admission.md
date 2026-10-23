# Exact-byte snapshot admission (0.7.1 prototype)

**NEEDS PARENT POLICY REVIEW before activation.** This is a separately named
opt-in policy, not a native merge or capsule-v1 capture. Existing merge defaults
and capsule-v1 identities, payloads and retention semantics remain unchanged.

## Contract and commands

KeePassium's public [DatabaseSaver](https://github.com/keepassium/KeePassium/blob/master/KeePassiumLib/KeePassiumLib/DatabaseSaver.swift)
checks remote SHA512 before saving, then caches the local uploaded bytes after a
successful PUT without rereading the server. Its
[WebDAVUploadRequest](https://github.com/keepassium/KeePassium/blob/master/KeePassiumLib/KeePassiumLib/files/data-source/remote/webdav/WebDAVUploadRequest.swift)
sends whole-file PUT without If-Match. A transformed native merge followed by
204 causes a false conflict on the next save. Raising timeouts cannot fix that.

After policy review and coordinated activation:

```bash
akdbx --version
akdbx status
install -d -m 0700 /absolute/private-backups/one-vault-admission
akdbx admit /absolute/private-staging/upload.kdbx \
  --policy snapshot-admission-v1 \
  --snapshot-dir /absolute/private-backups/one-vault-admission --check
akdbx admit /absolute/private-staging/upload.kdbx \
  --policy snapshot-admission-v1 \
  --snapshot-dir /absolute/private-backups/one-vault-admission \
  --operation-id OPERATION_ID
akdbx merge-status OPERATION_ID
```

Use a dedicated existing mode-0700 directory outside the canonical file's parent
and **all synced vaults**. It is permanently bound by a small nonsecret mode-0600
`.TARGET.akdbx-admission.json` locator beside the target. Preserve this locator
and external storage through restarts/migrations. Keep the locator local to this
broker host; exclude it from cross-device file sync with the owning workflow.
It contains a host-specific absolute recovery path. Do not delete it to bypass
recovery or copy it to another host as a portable configuration. Missing or unsafe storage
fails closed. No snapshot pruning, rebind, reset or downgrade command is added.
`--check` retains encrypted snapshots/receipt and binds the recovery directory,
but does not replace the vault, refresh the broker or invalidate handles. It is
not a reservation against later races.

Require CLI/broker 0.7.1, unlocked, no recovery block, `merge_available:true`, and
all exact capabilities before dispatch:

```json
{"admission_supported":true,"admission_protocol":1,
 "admission_policy":"snapshot-admission-v1",
 "admission_verification":"native-containment-v1",
 "admission_group_verification":"group-semantic-v1"}
```

RPC action `admit` requires `source`, `snapshot_directory`, `operation_id`,
`policy`, `verification`, `group_verification:"group-semantic-v1"`, and optional boolean `check`.
Older raw callers may omit the additive group-verifier request; the new broker
still applies it. Unsupported explicit group verifiers are refused before intent.
The 0.7.1 CLI requires the capability, sends the request and checks the result.
Merge options are refused.
Optional CLI `--if-match SHA256` / RPC `if_match` is an unquoted lowercase SHA256
of the current **encrypted** target. Adapters must map an HTTP ETag explicitly;
stale supplied preconditions must never be ignored. No wildcard is supported.
Without If-Match, the active-state containment checks still prevent branch loss.

A synchronous adapter may acknowledge only a durable result with `ok:true`,
`state:saved|unchanged`, `check:false`, `mode:admission`, requested operation ID,
`policy:snapshot-admission-v1`, `verification:native-containment-v1`,
`group_verification:group-semantic-v1` and `exact_bytes:true`. The CLI checks
these result fields as well as capabilities.
Raw callers must do the same. `source_sha256` and `candidate_sha256` identify the
same encrypted bytes. GET/HEAD must serve those exact canonical bytes, with
correct ETag and length. No transform-and-ack, asynchronous success, automatic
slow-merge fallback, or acknowledgement of `checked` is supported.

## Proof and deliberately conservative limits

Each incoming file is freshly decrypted/authenticated at its full KDF cost using
credentials held inside the existing broker. A matching current encrypted image
reuses that broker's previously verified state; an external replacement is
freshly opened too. Exact unchanged capsule payloads may reuse private completed
validation, while wrapper checks still run and changed payloads are fully
validated. No plaintext/key export, secondary unlock, reduced KDF or password
change is involved. A locked command returns the existing private HTTPS unlock
link; repeat the same command, policy and ID after private unlock.

Current disk is base, held broker state second, incoming last. Native semantic-v1
active selection is checked: newest active second wins, ties retain the base;
history/capsules cannot excuse wrong or missing active data. Exact standard and
custom values, attachment bytes, protection, essential times, metadata and
independently selected entry locations must agree. All required UUIDs must
survive or have valid union tombstones; newer edits survive older deletion.
Earliest tombstones, including obsolete and group deletions, must remain.
Existing capsule payloads must be intact and byte-identical. New groups/icons
are permitted; removal of an existing empty group needs a valid tombstone.

The prototype refuses existing group property/parent/essential-time differences
across inputs, including group rename/move combinations, rather than guess a
partial native result. Expansion, last-visible-entry, display order and access/usage statistics
may differ. Database settings must agree, including name/description/default
user, history limits, recycle bin/templates, key settings and memory protection.
Known singleton database/group field order (including nonempty Tags) and
memory-protection flag order are normalized; duplicate settings are refused.

### Group representation equivalence in 0.7.1

`group-semantic-v1` corrects demonstrable serialization refusals without changing
`snapshot-admission-v1`, `native-containment-v1`, capsule identities or retention.
The public [KeePassium 2.5.171 Group2 reader/writer](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassiumLib/KeePassiumLib/db/kp2/Group2.swift)
reorders group Tags and writes tristates as `True`/`False`/`null`.
[KeePassXC 2.7.10 writer](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/KdbxXmlWriter.cpp)
writes Tags earlier and tristates lowercase; its
[reader](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/KdbxXmlReader.cpp)
reads those tristates case-insensitively. These are equal representations.
The former raw check falsely refused them, including disabled searching/AutoType
in the managed archive group. Synthetic reproduction does not identify any
particular real client's trigger.

Only documented defaults are supplied for absent fields: empty Name/Notes/
DefaultAutoTypeSequence, built-in IconID 48 and inherited searching/AutoType.
Absent/zero optional CustomIconUUID and PreviousParentGroup are equal. Empty
CustomData is equal to absent; CustomData item order is insignificant, but every
key, value and optional modification clock remains significant. Valid group
timestamps use UTC instants independent of binary/ISO representation.
Fractional group instants remain significant; timezone equivalence does not
bucket them into entry-version seconds. Unsupported precision beyond six
fractional digits refuses rather than silently rounding metadata.

Inheritance remains distinct from explicit enabled/disabled. Nonempty Tags,
name/notes, icon/custom icon, AutoType sequence, previous parent, actual parent,
creation/modification/location times, Expires and ExpiryTime (even while disabled)
remain checked. No group edit or competing metadata is automatically selected.
Unknown metadata stays conservative. Duplicate fields, invalid tristates and
malformed Times/CustomData fail closed. Exact original metadata remains in the
complete encrypted snapshots; no input/capsule bytes are normalized on disk.

Group Tags *text* is still checked exactly. Public KeePassium
[TagHelper](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassiumLib/KeePassiumLib/db/kp2/Taggable.swift)
can change semicolon separators/whitespace to comma syntax without an explicit
tag edit; native Group stores and compares the original string directly. This
patch does not extend policy to accept those value changes. They still return
a retained-upload conflict. A future group tag equivalence policy would need
separate native reference proof and review. Group2 projection tests model this
rewrite and verify both the accepted canonical syntax and this remaining limit.
The native reference retains the target's original Tags string on an existing
group. A new client read can therefore repeat the rewrite/refusal; explicit
merge is not a lasting cure for that particular structural shape. Do not
repeat private unlocks or claim universal compatibility to work around it.

Generator and selected/top-visible
UI state may differ. Database CustomData may
change only its dictionary clock; existing icons must remain intact. Current
protected fields cannot be downgraded to unprotected. Ordinary client edits can
therefore produce a genuine refusal; universal client compatibility is not
claimed. Entry metadata follows the documented semantic-v1 normalizations.

KDBX4 is required. Cipher, inner protected stream, KDF UUID and every KDF parameter
except random salt must match all inputs; unknown header policy changes are
refused too. Seeds, IVs, stream keys and salts may rotate; compression and format
serialization may vary. Same master password and key file are required. No
incidental destination encryption weakening or settings change is accepted.

All four encrypted images (target, incoming, held broker, candidate) are written,
fsynced and read back in the external bundle, including identical inputs. The
source stays unchanged. The authenticated incoming ciphertext is staged and
checked for exact equality; decrypting identical bytes a second time adds no
proof. Before atomic replacement, source/target identities/digests, trusted
paths/ownership/symlinks/hardlinks, key file and external directory are checked.
Target file/directory fsync, exact encrypted readback, broker refresh, stale-handle
and pending-write invalidation, and final durable receipt precede success.

## Retention and conflicts

| Property | Native merge with capsule-v1 | Snapshot admission |
| --- | --- | --- |
| Canonical bytes | Transformed merge | Exact incoming file |
| Active branches | Reconciles branches | Refuses unless incoming already contains required result |
| Original logical versions | New capsules inside canonical | Complete encrypted original databases outside canonical |
| Existing capsules | Restored/unioned | Must already survive byte-for-byte |
| Ordinary history pruning | Capsules retain versions | Retained full encrypted input databases retain versions |
| Different active equal-time value | Base wins; capsules retain all | Refusal if incoming selects another value |
| Genuine conflict | Explicit merge | Refusal, explicit merge, then fresh client read |

No snapshot, capsule or history pruning is implemented. Every successful
admission retains `target.kdbx`, `source.kdbx`, `broker.kdbx`, `candidate.kdbx` and
receipt, mode 0600 under 0700. Early failures may not create every snapshot.
Versions omitted from canonical History remain only in retained encrypted input
databases; this is a policy change requiring review. No individual-version
backup/capsule restore, view or export command is added. Do not use ad hoc
secret-reading scripts. An authorized private client can open an intact retained
database with existing credentials; canonical reconciliation uses supported merge.

On a refusal, retain the upload and return an honest conflict (for example 409).
Outside the timed PUT, explicitly run:

```bash
akdbx merge /absolute/retained/upload.kdbx --refresh-target --preserve-conflicts
```

After durable merge success the client must read the new canonical bytes before
resolving/reapplying its edit. Do not silently merge and204 the old upload bytes.
The native merge may itself refuse unsupported data; report that refusal.

Timeout/disconnect can occur before or after a durable save. Keep the same
transport intent and operation ID, query `merge-status`, block uncertain saves,
and require a fresh read as appropriate. Never retry blindly with a new ID.
Reusing an ID retrieves its receipt, including after restart/while locked.
Re-encrypted retries with new IDs receive fresh decrypt and state checks.
Preparing/prepared/uncertain receipts in external storage block recovery after
restart. No automatic reset/security override is provided. Error diagnostics
contain fixed category counts only, never UUIDs/titles/field names/values,
secret digests or raw engine output.

## Deadlines and activation

[URLReference](https://github.com/keepassium/KeePassium/blob/master/KeePassiumLib/KeePassiumLib/files/URLReference.swift)
defaults to 10 seconds, also in metadata/reference refresh default arguments.
DatabaseSaver has separate configured phase deadlines. Metadata queued behind a
long PUT can exhaust a different deadline; idle HEAD timings cannot establish
behavior during a save. The synthetic tests cover separate metadata delays and
queues; they do not identify a particular installed client's early failure.

The full-cost synthetic test uses 300 active/900 History/1200 capsules, 30 16KiB
attachments, protected fields, KDBX4.1/AES256/Argon2d I119/M67108864/P2/V19. It
measures real CLI/RPC through two local HTTP hops with body staging and 50 ms
proxy delay, plus actual 10/30-second client deadlines and a separate native
baseline. Receipt monotonic timings stop before final receipt fsync; client
measurements include it and CLI/HTTP overhead. Client encryption is separate.
Host/load timings do not guarantee arbitrary load or network latency; a changed
external target adds another full decrypt. TLS/Tailscale, production adapter,
Windows/iPhone UI and native KeePassium remain outside this verification.

After parent policy review, retain the current broker's latest durable encrypted
state and resolve pending receipts. Install the final tested wheel/commit, then
perform one coordinated normal restart/private HTTPS unlock. An unlocked older process, including 0.7.0,
cannot acquire new code. No hotpatch, key extraction or second unlock
service is supported. No new serve argument is required: the first explicit
admission binds external recovery. Require exact capabilities/results before
adapter integration. Do not downgrade a bound vault to 0.6 or older: old brokers
do not scan external admission receipts. Preserve the locator and snapshots;
there is no downgrade/reset/prune command. Parent owns activation and native
client acceptance; this prototype is **not native iPhone verified**.

The runtime wheel does not install these skill documents. When using a wheel,
advance the maintained source/skill checkout to the same tested commit through
the existing checkout workflow, preserving unrelated local work.

0.7.1 keeps the 0.7.0 external locator, snapshot directory, operation IDs and
receipt recovery format. Preserve them in place; no rebind or migration is
required. Historical 0.7.0 receipts remain queryable with `merge-status` and
do not retroactively prove `group-semantic-v1`. New admissions report the group
verifier. New CLI refuses an old running 0.7.0 broker before dispatch. Do not
repeat a historical operation ID to obtain a new verifier: inspect its original
receipt and retain uncertainty rules. A downgrade loses the group fix; never
downgrade below 0.7.0 on a bound vault because external recovery is unsupported.

The reported installed client is KeePassium 2.5.171. Public tag `2.5.171` maps
to commit `4dc000da761217d1f8fab7ac40c4195d7b2ff37b`; its Xcode project sets
`MARKETING_VERSION=2.5` and `CURRENT_PROJECT_VERSION=171`. The test projection
is pinned to this source, not an assumption about current master. This source
mapping does not verify a device binary or identify the real refusal.

In that release, [Group.touch](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassiumLib/KeePassiumLib/db/Group.swift)
updates access time for `.accessed`, modification time for `.modified`, and
propagates the mode to parents; Group2 also increments usage. Access/usage-only
touches are admitted. Real group modification clocks remain significant.
The [AutoFill remembered-URL operation](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassiumLib/KeePassiumLib/db/transactions/AddEntryURLOperation.swift)
backs up the entry, sets its modification clock and changes its URL/extra field;
it does not directly touch parent clocks. Do not infer which operation or
metadata occurred on a user's device from these possible paths.
The AutoFill [background saver](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassium%20AutoFill/AutoFillCoordinator%2BdbSaving.swift)
has a fixed 10-second timeout in this public release. That is a separate path
from main-app save settings, not a diagnosis of a particular failed request.
