# Exact-byte snapshot admission (0.7.0 prototype)

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

Require CLI/broker 0.7.0, unlocked, no recovery block, `merge_available:true`, and
all exact capabilities before dispatch:

```json
{"admission_supported":true,"admission_protocol":1,
 "admission_policy":"snapshot-admission-v1",
 "admission_verification":"native-containment-v1"}
```

RPC action `admit` requires `source`, `snapshot_directory`, `operation_id`,
`policy`, `verification`, and optional boolean `check`. Merge options are refused.
Optional CLI `--if-match SHA256` / RPC `if_match` is an unquoted lowercase SHA256
of the current **encrypted** target. Adapters must map an HTTP ETag explicitly;
stale supplied preconditions must never be ignored. No wildcard is supported.
Without If-Match, the active-state containment checks still prevent branch loss.

A synchronous adapter may acknowledge only a durable result with `ok:true`,
`state:saved|unchanged`, `check:false`, `mode:admission`, requested operation ID,
`policy:snapshot-admission-v1`, `verification:native-containment-v1`, and
`exact_bytes:true`. The CLI checks these result fields as well as capabilities.
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
Known singleton database/group field order and memory-protection flag order
are normalized; duplicate settings are refused. Generator and selected/top-visible
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
perform one coordinated normal restart/private HTTPS unlock. An unlocked 0.6
process cannot acquire new code. No hotpatch, key extraction or second unlock
service is supported. No new serve argument is required: the first explicit
admission binds external recovery. Require exact capabilities/results before
adapter integration. Do not downgrade a bound vault to 0.6 or older: old brokers
do not scan external admission receipts. Preserve the locator and snapshots;
there is no downgrade/reset/prune command. Parent owns activation and native
client acceptance; this prototype is **not native iPhone verified**.
