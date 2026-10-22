# Merge encrypted KeePass databases (0.5.0)

Use the broker that owns the destination vault. The command is authorization
for this scoped merge. No GUI, second unlock service, key export, or per-step
approval is needed. Never use a real vault for development tests.

## Normal path

Use the installed CLI's absolute path (on this VPS,
`/home/ubuntu/projects/agentic-kdbx/.venv/bin/akdbx`). Global socket and trusted
unlock-origin options go before the subcommand.

```bash
akdbx --version
akdbx status
akdbx merge /absolute/path/to/other.kdbx
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts
```

Require CLI and broker version `0.5.0`, `merge_protocol: 1`,
`merge_available: true`, `locked: false`, and `recovery_required: false`.
`merge_engine` reports the detected engine. An older broker's missing capability
is not permission to extract its held key or patch its memory. Coordinate
activation with its owner after any pending login/reset has ended.

The basic merge remains compatible with 0.3.0. External-change reconciliation
requires 0.4.0 and `merge_refresh_target_supported: true`; the new CLI checks
that capability before sending an opt-in request to a broker. The protocol
version stays 1 because the options are additive. Version 0.5.0 adds
`--preserve-conflicts`; require `merge_preserve_conflicts_supported: true` and
exact `merge_preservation_policy: "capsule-v1"`. The CLI checks both before
sending the request. A raw RPC integration must perform the same check before
using boolean `preserve_conflicts: true`; an old broker can ignore unknown fields.

The already-unlocked broker reuses its password and key-file bytes privately.
The agent receives status, counts, encrypted-file SHA-256 hashes, an operation ID,
and a receipt path. Entry titles, passwords, plaintext XML, and native engine
output are never merge responses. Search remains a separate authorized metadata
operation. The source file is unchanged.

If locked, the command returns the existing private HTTPS `unlock_url` and a
continuation. Give that exact link to the user. After private unlock, repeat the
same command with the reported ID:

```bash
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts --operation-id OPERATION_ID
```

Keep the original command's options when continuing. The ID is 32 lowercase
hexadecimal characters. The CLI prints it to stderr
before sending the request. Keep it to recover from a lost connection. No work
is queued behind a locked response. Unlock alone does not authorize a later
automatic merge without the repeated explicit command.

Both databases must use the same master password and, if configured, the same
key file. Different source credentials, key-file-only databases, hardware keys,
and master passwords containing CR, LF or NUL are unsupported. Spaces,
punctuation, Unicode and emoji are preserved without trimming or normalization.
An unreadable source does not establish that the user's password is wrong.
Do not troubleshoot by requesting secrets in chat, arguments, or environment
variables. This release does not add a separate source-password form.

## Preview and receipts

```bash
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts --check
akdbx merge-status OPERATION_ID
```

`--check` performs the full encrypted staging, engine merge and reopen checks;
it does not replace the destination or refresh/invalidate broker state. It
retains encrypted evidence and a `checked` receipt. A later real merge performs
fresh checks and needs a new ID. A check is not a reservation against external
changes. A merge with no native/deletion changes returns `unchanged` without
replacing the target. A source that still contains tombstoned entries can cause
native add/delete work again; the logical records remain unchanged but
the encrypted candidate can be saved again. Reuse of an existing ID retrieves
the prior receipt; never reuse an ID
for a different source, mode, or intended operation.

Each accepted operation creates a mode-0700 directory beside the target:
`.TARGET.kdbx.akdbx-merge-ID/`. It retains `target.kdbx`, `source.kdbx`, and the
verified `candidate.kdbx` (all encrypted, mode 0600) plus a nonsecret
`receipt.json` (0600). Some early failures cannot create every snapshot. Files
are not automatically pruned. Exclude these hidden recovery directories from
cross-device synchronization if the vault directory is synced. Account for disk
space for both originals, the candidate and the replacement staging file.

Receipts survive broker restart and can be queried while locked. `saved` means
replacement, target-directory fsync, encrypted readback, in-memory refresh, and
receipt fsync completed. Previous selection handles are cleared; pending
password writes fail as stale and generated secrets/references are discarded.
Get fresh search handles after a saved merge.

## Reconcile an externally replaced target

An external editor or sync writer can replace the target with an older branch
that lacks entries previously saved by this broker. The default command still
refuses a stale target. Do not restart/reload simply to discard that broker
state. Explicitly authorize reconciliation with:

```bash
akdbx status
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts --check
akdbx merge /absolute/path/to/other.kdbx --refresh-target --preserve-conflicts
```

Require `merge_refresh_target_supported: true`, `merge_available: true`,
`locked: false` and no recovery block. A compatible unlocked broker needs no
additional private unlock for this operation. The option is authorization to
reconcile these inputs; it does not weaken the path, key-file, race or recovery
checks. An older broker cannot provide this behavior merely because a new CLI
is installed. Raw RPC callers must also check the capability before sending
boolean `refresh_target: true`; an older broker may ignore unknown fields.

The broker retains its last verified encrypted image on unlock and after every
durable password save or merge. Under the target lock, reconciliation snapshots
all three encrypted inputs: `broker.kdbx` is that verified broker image,
`target.kdbx` is the current disk file, and `source.kdbx` is the requested input.
It privately opens the current target with held credentials, merges the broker
image into the current target with the native engine, reopens/checks that stage,
then merges the requested source and reopens/checks again. `reconciled.kdbx`
retains the first native stage when distinct. Destination settings come from the
current disk target. No stage is a plain reload that discards broker-only data.

Deletion records from all three inputs are applied only after both native
merges. Newer surviving edits can therefore keep history from the earlier
stages. Without preservation, equal-second conflicts and history/field/entry
loss fail closed. With preservation, all original entry versions are verified
in encrypted capsules, including records removed by valid live deletions. All
three snapshots are retained before private target/source open or native merge.
The existing deletion and metadata policies below still apply.

The receipt adds `refresh_target`, `target_refreshed`, `broker_sha256` and
`disk_before` counts. `target_refreshed` means the target identity differed from
the broker's last verified revision. `--check` leaves the broker vault, verified
image, expected file identity, pending writes and handles unchanged. A real
successful reconciliation updates them and invalidates old handles/pending
writes. If the current target already contains all inputs, `unchanged` can still
mean the broker adopted a new external revision after file/directory fsync and
race checks. Get new handles after this result too. A final receipt failure
after adoption is uncertain and blocks further vault use.

Wrong current-file credentials, missing/inconsistent verified broker images,
changed key files, concurrent file changes, or incomplete prior receipts never
cause an automatic reset. The held broker state stays available after an
ordinary pre-save failure; an uncertain/interrupted operation remains blocked.
Use `merge-status` and the retained encrypted files for recovery. There is no
security override flag.

For a private WebDAV merge-on-write integration, explicitly use both
`--refresh-target --preserve-conflicts` for the
authorized incoming upload, require the capability at activation, and wait for
the truthful durable result before returning success. Do not replace merge with
an unconditional file PUT or a plain reload. The integration must keep its
existing transport, concurrency and upload checks; this option does not supply
WebDAV or synchronization control itself.

## Preserve equal-second versions

Same-second differences can occur in active entries, histories, or both. They
do not prove separate live edits. The default now normalizes benign indentation,
known field order, empty defaults and equivalent boolean representations, while
keeping password whitespace, custom fields, unknown ordered metadata and
attachment bytes distinct. It still refuses genuine collisions.

`--preserve-conflicts` authorizes a different, explicit preservation policy:

- Keep the native UUID-based merge and its newest-active-value rule. Active
  ties prefer the current disk target, then the verified broker image, then the
  incoming source. A two-input merge prefers the target. Verify this selection
  after reopening. No original record timestamp is changed to invent an order.
- Before native merging, collect every distinct original active/history entry
  version from all inputs and all existing preservation records. Retain original
  UUIDs, all original times, fields/flags, custom metadata, original grouping
  context, attachment bytes and referenced custom icon data in structured
  capsules. These are opaque binary attachments **inside the encrypted KDBX**,
  with deterministic container UUIDs in a reserved managed group. They do not
  require another password or unlock service. No plaintext file is exported.
- Restore and verify every capsule byte after each encrypted native stage and
  after final encrypted save/reopen. Timestamp-keyed native History and history
  limits may collapse/prune versions; complete originals remain in capsules.
  The generic container records have fixed bookkeeping times; embedded original
  times remain exact. Native active records are never replaced by title matches.
- Live deletions still apply. Capsules deliberately retain original versions of
  deleted entries, without reviving them as active logins. They are excluded from
  broker search/fill, duplicate checks and password-write destinations, and marked
  nonsearchable/non-autotypable for native clients. Subsequent supported writes,
  repeated merges and reconciliation validate and retain them. Identical logical
  versions deduplicate; new versions consume additional encrypted space/memory.

Receipts identify `preserve_conflicts`, `preservation_policy: "capsule-v1"` and
`preserved_versions`. Counts separate active `entries` from `archived_versions`.
The full policy composes with `--check` and `--refresh-target`; previews retain
their staged capsules but adopt no broker state. Reuse an operation ID only for
that same request. Uncertain/incomplete receipt rules remain unchanged.

There is no capsule restore/view/export or purge command in this release. Native
History alone must not be treated as the complete preservation ledger. Do not
edit the managed group or extract capsule contents with an ad hoc agent script.
The [capsule format](preservation-format.md) documents the internal recovery
representation and checks. Capsule corruption, reserved UUID collisions,
unreadable protected fields or an unverified active selection fail closed. This
policy preserves original entry records; it does not independently reconcile
all competing database/group settings, which still follow native semantics.

## Semantics and dependencies

Linux with `/proc/self/fd`, sealed `memfd`, Unix sockets, fsync and atomic rename
is required. Install root-owned `/usr/bin/keepassxc-cli` from KeePassXC
`>=2.7.10,<2.8`. Version 2.7.10 is the tested native engine. The Python package
dependencies are installed by `pip install .`. PyKeePass is pinned to **4.2.0**:
the capsule reader/writer and protected-field checks are verified for that
version. A different installed version disables the preservation capability.
An unavailable, unsafe or
unsupported native executable makes merge unavailable; ordinary login behavior
continues. No engine path or password override is accepted through RPC.

KeePassXC's database-aware `KeepNewer` merge matches entry/group UUIDs. It
preserves the newer entry's value, fields and modification time, and merges
older values into history. Group moves use `LocationChanged`; newer group
properties follow the native engine's rules. Without `--preserve-conflicts`,
equal-second conflicting entry or history values are refused before the engine
can discard one. A post-merge
check refuses loss of any surviving entry version, history, field or attachment
content, including native history-limit pruning. Such a failure leaves the
target unchanged. Use the explicit preservation policy when complete original
versions must survive native history limits or timestamp collisions. Its
capsule verification replaces the default history-membership check; active
selection and deletion checks still apply.

The CLI's native mode omits deletion synchronization. The broker therefore
applies a separate database-object deletion pass to the encrypted candidate:
union deletion UUIDs, use the earliest deletion time per UUID (KeePassXC
Synchronize convention), delete entries whose modification time is not later
than that time, and delete old empty groups from the bottom up. Newer edits and
groups with surviving children remain. All consolidated deletion records are
retained, including obsolete records, to avoid silently dropping tombstones.
There is no title matching, plaintext export, or entry-XML concatenation.

Destination database identity, name, settings and encryption credentials remain
authoritative. Missing source custom icons and database CustomData use native
KeePassXC rules; that engine can replace/remove CustomData keys according to its
dictionary modification time. Database setting changes on the source are not
independently combined. Review application-specific metadata conflicts before
merging. The original encrypted metadata always remains in both snapshots.
KeePassXC can select KDBX 4.0 when no data requires 4.1; KDBX 4.1 input and
Argon2d/AES-256 are supported. This does not change the password.

The broker passes the held master password through stdin to a private native
child. Key-file material uses a sealed, inherited anonymous memory file, never a
disk file. Native stdout/stderr are discarded. Native core dumps are disabled
for the broker process and its children once merge runs. Python cannot promise
memory zeroization; a malicious process with the same OS identity remains
outside the isolation boundary.

Engine references: [CLI merge](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/cli/Merge.cpp),
[UUID, history and deletion rules](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/core/Merger.cpp).

## Failures and recovery

- `vault locked`: share the returned private link, then repeat the scoped merge.
- `merge unavailable`: inspect version/capabilities, dependency and target path
  safety. Installing new source does not update a running broker.
- Source cannot open: retain both inputs, confirm which encrypted source was
  selected and whether its credential/key-file requirements match. This is not
  proof of an incorrect password. Different-source-key merges are unsupported.
- Stale target: the default refuses it. Use the explicit `--refresh-target`
  path above to combine the verified broker image, current target and incoming
  file without another unlock on 0.4.0. Do not discard broker-only data by reload.
- Conflicting same-second records or native history pruning: retain inputs and
  use a new operation ID with `--preserve-conflicts` on verified 0.5.0/capsule-v1.
  Include `--refresh-target` when reconciling external changes. This authorizes
  encrypted capsule preservation and the documented active tie preference.
- Changed key file or wrong current-file key: retain all inputs and reconcile
  the cause privately. The option does not reset the broker or bypass key checks.
- Stale source: preserve its latest bytes. Review the retained input snapshot,
  select a stable source, and start a new operation.
- Busy: the operation did not start. Check the known ID first. Let the active
  save finish before a deliberate new request.
- Failure before replacement: the receipt says `failed`; the original target
  remains. Fix the reported cause and use a new ID.
- Timeout/disconnect: do not repeat blindly. Use `merge-status ID`. `checked`,
  `unchanged`, or `saved` describe that operation only. A missing receipt is not
  proof that the request never ran; wait for broker health and inspect again.
- `uncertain`, `preparing`, `prepared`, missing/corrupt receipt in an existing
  bundle, or failed durability: stop writes and automatic retries. The target
  may already have changed. Compare encrypted target/candidate hashes and the
  retained originals. Do not infer success from file presence. The current
  broker blocks vault use after an uncertain replacement; a fresh unlock also
  blocks if incomplete merge bundles remain. After an authorized recovery has
  established the intended encrypted target, archive the entire uncertain
  bundle outside the target directory, then restart and privately unlock.
  No automatic rollback or recovery override is exposed.

The existing advisory `.TARGET.akdbx.lock` serializes cooperative broker saves.
Source/target inode, timestamps and checksums are checked before replacement;
target-directory identity and key-file digest are checked too. Symlinked source
files/ancestry, wrong owners, multiple hard links, nonregular files and unsafe
directory ancestry are rejected. Do not edit or sync-replace either input while
merging: an advisory lock cannot constrain an uncooperative external editor or
eliminate the final check-to-rename race. Pause competing editing/sync through
its authorized owner when needed; merge itself does not alter sync services.

## Activation by the originating workflow

Do this only after the source repair thread has finished and its exact tested
commit/report has been reviewed. The development thread does not activate code
or merge real vaults.

1. Install the tested 0.5.0 package/commit into the broker's environment. For a
   source checkout, select the tested commit and run `.venv/bin/pip install -e .`.
   Keep the native dependency above available. Preserve existing uncommitted
   work; do not reset a checkout or force-push.
2. End pending fills/resets with the broker's owner. Before stopping an older
   broker, preserve its latest durable encrypted state and receipt. If external
   replacement has removed it from disk, identify its retained encrypted saved
   candidate before proceeding. Do not stop a broker whose latest state exists
   only in memory. This option preserves state within a compatible running
   broker; it does not transfer an older process's memory to 0.5.0.
   Coordinate a normal restart and private re-unlock for version activation.
   Never extract a key, hot-patch memory, or start a second unlock service.
3. Start the installed CLI with the intended target, original socket, key-file
   option (if any), desktop environment and existing private HTTPS mapping:
   `akdbx --socket /KNOWN/PRIVATE/broker.sock serve /INTENDED/base.kdbx`.
   No additional unlock service is required.
4. Give the returned private unlock link to the user. Check CLI/broker 0.5.0
   and merge capabilities, including `merge_refresh_target_supported: true`,
   `merge_preserve_conflicts_supported: true` and exact policy `capsule-v1`.
   Run the authorized merge command above; keep its receipt. Later compatible
   external replacements can be reconciled without a new unlock or restart.
5. Verify `saved`/`unchanged`, checksums and expected nonsecret results before
   resuming the separate synchronization workflow. Synthetic tests do not
   establish real-vault behavior or iPhone/Android editor adoption.
