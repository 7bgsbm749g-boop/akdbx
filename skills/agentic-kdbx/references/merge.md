# Merge encrypted KeePass databases (0.3.0)

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
```

Require CLI and broker version `0.3.0`, `merge_protocol: 1`,
`merge_available: true`, `locked: false`, and `recovery_required: false`.
`merge_engine` reports the detected engine. An older broker's missing capability
is not permission to extract its held key or patch its memory. Coordinate
activation with its owner after any pending login/reset has ended.

The already-unlocked broker reuses its password and key-file bytes privately.
The agent receives status, counts, encrypted-file SHA-256 hashes, an operation ID,
and a receipt path. Entry titles, passwords, plaintext XML, and native engine
output are never merge responses. Search remains a separate authorized metadata
operation. The source file is unchanged.

If locked, the command returns the existing private HTTPS `unlock_url` and a
continuation. Give that exact link to the user. After private unlock, repeat the
same command with the reported ID:

```bash
akdbx merge /absolute/path/to/other.kdbx --operation-id OPERATION_ID
```

The ID is 32 lowercase hexadecimal characters. The CLI prints it to stderr
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
akdbx merge /absolute/path/to/other.kdbx --check
akdbx merge-status OPERATION_ID
```

`--check` performs the full encrypted staging, engine merge and reopen checks;
it does not replace the destination or refresh/invalidate broker state. It
retains encrypted evidence and a `checked` receipt. A later real merge performs
fresh checks and needs a new ID. A check is not a reservation against external
changes. An identical/repeated merge returns `unchanged` without replacing the
target. Reuse of an existing ID retrieves the prior receipt; never reuse an ID
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

## Semantics and dependencies

Linux with `/proc/self/fd`, sealed `memfd`, Unix sockets, fsync and atomic rename
is required. Install root-owned `/usr/bin/keepassxc-cli` from KeePassXC
`>=2.7.10,<2.8`. Version 2.7.10 is the tested native engine. The Python package
dependencies are installed by `pip install .`. An unavailable, unsafe or
unsupported native executable makes merge unavailable; ordinary login behavior
continues. No engine path or password override is accepted through RPC.

KeePassXC's database-aware `KeepNewer` merge matches entry/group UUIDs. It
preserves the newer entry's value, fields and modification time, and merges
older values into history. Group moves use `LocationChanged`; newer group
properties follow the native engine's rules. Equal-second conflicting entry or
history values are refused before the engine can discard one. A post-merge
check refuses loss of any surviving entry version, history, field or attachment
content, including native history-limit pruning. Such a failure leaves the
target unchanged. It requires review of the vault's history policy or records
in a trusted KeePass application, then a fresh private unlock/operation.

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
- Stale target/key file: do not overwrite it. Reconcile the external change,
  coordinate a broker restart and privately unlock the intended target again.
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

1. Install the tested 0.3.0 package/commit into the broker's environment. For a
   source checkout, select the tested commit and run `.venv/bin/pip install -e .`.
   Keep the native dependency above available. Preserve existing uncommitted
   work; do not reset a checkout or force-push.
2. End pending fills/resets with the broker's owner. Stop that specific old
   broker normally. Do not extract its master key or modify its memory.
3. Start the installed CLI with the intended target, original socket, key-file
   option (if any), desktop environment and existing private HTTPS mapping:
   `akdbx --socket /KNOWN/PRIVATE/broker.sock serve /INTENDED/base.kdbx`.
   No additional unlock service is required.
4. Give the returned private unlock link to the user. Check CLI/broker 0.3.0
   and merge capabilities. Run the merge command above; keep its receipt.
5. Verify `saved`/`unchanged`, checksums and expected nonsecret results before
   resuming the separate synchronization workflow. Synthetic tests do not
   establish real-vault behavior or iPhone/Android editor adoption.
