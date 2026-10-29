# Explicit group admission profiles (0.8.0 review prototype)

**NEEDS PARENT POLICY REVIEW. Do not activate automatically.** This extension
adds two named verifiers to `snapshot-admission-v1`. It neither changes
`group-semantic-v1` nor converts admission into a native merge. All input
ciphertexts remain in complete encrypted external snapshots. Existing capsule
payloads remain intact in the canonical upload. A refusal retains the upload;
it is not a saved edit.

## Commands and exact detection

After review and one coordinated activation, select one profile explicitly:

```bash
akdbx admit /absolute/private-staging/upload.kdbx \
  --policy snapshot-admission-v1 \
  --snapshot-dir /absolute/private-backups/one-vault-admission \
  --group-verification group-tag-sequence-v1 --check
akdbx admit /absolute/private-staging/upload.kdbx \
  --policy snapshot-admission-v1 \
  --snapshot-dir /absolute/private-backups/one-vault-admission \
  --group-verification native-group-selection-v1 \
  --operation-id OPERATION_ID
akdbx merge-status OPERATION_ID
```

Both profiles compose with `--check`, `--if-match` and same-ID status recovery.
Admission always reconciles current/held state privately; it does not accept
merge's `--refresh-target` or `--preserve-conflicts` flags. No native merge runs
on PUT. Successful admission means the **exact uploaded ciphertext** is durable,
read back, canonical and served by GET/HEAD. The broker refreshes and invalidates
old handles. The existing snapshot locator, crypto policy, capsule, branch,
advisory lock, ownership, keyfile, race and uncertainty checks still apply.

Require CLI/broker **0.8.0** and exact KeePassXC CLI **2.7.10** for the two new
profiles. Also require all admission capabilities in the
[snapshot contract](snapshot-admission.md), unlocked/writable/no recovery block,
and these additional exact capabilities:

```json
{"admission_group_protocol":2,
 "admission_group_verification":"group-semantic-v1",
 "admission_group_verifiers":["group-semantic-v1","group-tag-sequence-v1","native-group-selection-v1"],
 "admission_group_tags":"keepassium-2.5.171-sequence-v1",
 "admission_group_selection":"keepassxc-2.7.10-selection-v1",
 "admission_group_diagnostics":"group-categories-v1"}
```

The old singular capability remains the narrower contract. Do not use it as
proof of a new profile. A different native version exposes only the old profile.
New CLI checks protocol 2 and the requested profile before dispatch, including
when its default profile is selected; actual 0.7.0/0.7.1 processes are rejected.
RPC requests specify `group_protocol:2` and the chosen `group_verification`.
Omission by an old raw caller continues to apply the old strict profile only.
Unknown profiles, invalid protocol values and unsupported engines fail before
creating an intent.

A transport must require durable `ok:true`, `state:saved|unchanged`,
`check:false`, the same operation ID, all snapshot policy/result fields and:

| Requested profile | `group_protocol` | `group_verification` | `group_tag_verification` | `group_selection` |
|---|---|---|---|---|
| old/default | 2 | `group-semantic-v1` | `raw-v1` | `strict-v1` |
| tags only | 2 | `group-tag-sequence-v1` | `keepassium-2.5.171-sequence-v1` | `strict-v1` |
| native group selection | 2 | `native-group-selection-v1` | `keepassium-2.5.171-sequence-v1` | `keepassxc-2.7.10-selection-v1` |

CLI validates these fields too. A failed receipt describes the requested profile;
`ok:false` is never certification. `checked` is never a PUT acknowledgement.
Historical receipts keep their original fields and cannot acquire a new
certification by reusing their IDs. `merge-status` reads them unchanged.

## Tag text: proved useful common equivalence

Public KeePassium tag **2.5.171**, commit
`4dc000da761217d1f8fab7ac40c4195d7b2ff37b`, matches marketing version 2.5/build
171 in its Xcode project. This is a public source mapping, not verification of
a device binary. Its [TagHelper](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassiumLib/KeePassiumLib/db/kp2/Taggable.swift)
splits group tag text at comma or semicolon, trims Foundation `whitespaces`,
filters empty tokens and writes comma separators. It preserves sequence,
duplicates and case. Quotes and backslashes have no escaping role. XML entities
are decoded as ordinary XML text before this operation.

[DatabaseItem.resolvingTags](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassiumLib/KeePassiumLib/db/DatabaseItem.swift)
starts with the item's ordered tags, including duplicates, and appends ancestor
tags only when not already present. Entry field presentation and the tag
selector consume those arrays. Reordering, deduplicating or case-folding group
tags is therefore not generally equivalent. Swift's Unicode string equality
must not be replaced by an unproved broad Python normalization.

KeePassXC 2.7.10 [Group](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/core/Group.cpp)
stores a raw scalar string. Its XML reader/writer retain that string and its
native group merge retains the existing target string even when other newer
properties are selected. Full source inspection found no group tag editor or
group-tag use in its GUI/search: [Database.updateTagList](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/core/Database.cpp)
iterates entry tag lists; [EntrySearcher](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/core/EntrySearcher.cpp)
searches entry tags without inheriting group tags. Real CLI tests independently
verify group-only tags do not match tag search, entry tags do match, and native
merge keeps the raw target group tag text. No GUI or iPhone runtime was tested.

The new profiles permit only equal ordered sequences after splitting on
`,`/`;`, trimming **ASCII space/tab only** and removing empty tokens. This is
a conservative subset of the Swift equivalence, with no native group-tag UI
semantic difference. It is explicitly **not native raw scalar identity**.
Examples: ` a ; b,a ` and `a,b,a` are equivalent; `a,b` and `b,a`, `a,a` and
`a`, `A` and `a` remain distinct. Quotes, backslashes, line breaks, Unicode
normalization and unproved Unicode whitespace distinctions remain significant.
Absent/empty/separator-only text is an empty sequence. This is not the entry-tag
set normalizer; entry semantics are unchanged. Full original raw group text is
retained in encrypted input snapshots, not necessarily in canonical metadata.

## Explicit native group selection

`group-tag-sequence-v1` changes only tag representation equivalence. Other
existing group properties, essential times and parents must still agree.
`native-group-selection-v1` additionally verifies a selected group state. It
models [Merger](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/core/Merger.cpp)
in **current disk -> held broker -> incoming** order. It does not call that
engine, produce a transformed candidate, promote History to active, or accept
clocks alone as proof of active containment. Entry `semantic-v1` verification
and the database/encryption checks remain independently required.

For existing non-root groups:

- A strictly newer `LocationChanged` and different parent select a move.
  `PreviousParentGroup` becomes the previous selected parent. A newer clock at
  the same parent does not replace the selected location clock.
- A strictly newer modification time selects Name, Notes, icon, ExpiryTime and
  that modification time. Ties keep the established base properties.
- Native custom icons select their UUID and built-in number zero. Built-in
  zero with a null custom UUID calls the native null-UUID no-op; it does not
  erase a current icon. Nonzero built-ins replace the icon and clear custom UUID.
- Creation time, expiry-enabled flag, default AutoType, search/AutoType tristates,
  CustomData and Tags stay from the established state. The explicit tag
  equivalence above is the only tag-text exception. Essential clocks and all
  CustomData keys/values/clocks remain significant, including disabled expiry.
- Native does **not** resolve root properties. The root remains the current
  target's base. A propagated root modification clock is not accepted.

A new group copies its complete supported metadata, UUID and parent. All selected
UUID membership and parent topology must exist in the incoming file. Missing
remote/held groups, an entry/group UUID collision, cycles, unknown group schema,
duplicate singleton fields, unsupported icons or uncertain selection refuse.
Existing empty/default equivalences and ignored access/usage/viewport state
remain the old documented ones; no protection or custom metadata is waived.

Deletion verification uses the existing earliest-tombstone union and removes
only old empty groups after selected entry occupancy/child retention. Newer
edits and occupied groups survive. The root and managed archive cannot be
tombstoned. This models the repository's explicit deletion synchronization after
native KeepNewer (the CLI alone does not synchronize deletions).

Native binary time writing cannot preserve arbitrary ISO fractions. The new
selection profile refuses fractional **essential group clocks and tombstones**
with a fixed unsupported-metadata category; it never erases or invents their
order. The old/tag-only profiles continue exact fractional comparisons. Group
CustomData clocks, including the raw `_LAST_MODIFIED` dictionary value and
fractional item clocks, are retained exactly. The native reader can regenerate
the dictionary clock and the writer can omit item clocks. This is an explicit
stronger input-preservation floor, not permission to ignore a changed clock.
Native reference tests assert every other key/value independently and restore
only this floor in the in-memory test oracle before checking selected groups. Independent tests compare ordinary native whole-
second reference results and enforce this additional data-preservation floor.

The uploaded file must already contain this complete selected result, including
independently selected location and properties. A version hidden in History,
capsules or external backups cannot excuse wrong/missing active values. If not,
return a retained-upload conflict. Explicit supported merge outside PUT followed
by a fresh client read remains the recovery path. Do not transform and 204.

## Ordinary release paths and remaining compatibility limits

The exact-release [entry editor](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassium/database/entry-editor/EntryFieldEditorCoordinator.swift)
backs up/changes the entry with `updateParents:false`. Create/Edit transaction
operations do not modify parent group clocks. Adding/removing children marks
child state without changing parent modification clocks. Synthetic sequential
add, field edit and permanent deletion pass the new profile, including a normal
public group writer rewrite of noncanonical tag text, actual CLI/broker, exact
ciphertext, GET/HEAD and the client's SHA512 cache sequence.

The exact-release [relocation coordinator](https://github.com/keepassium/KeePassium/blob/2.5.171/KeePassium/database/relocation/ItemRelocationCoordinator.swift)
touches access state after a move. Entry2.move updates previous parent and
location time without advancing entry modification time. Native 2.7.10 can
select the new parent while retaining base active entry times. The incoming
phone location clock then differs from current `semantic-v1`; pure entry moves
and recycle-bin deletes **still refuse** in the synthetic tests. No entry-policy
change is hidden in this group extension. Permanent tombstone deletion is a
different, supported case. Group moves use the separately modeled group rules.

Some EntryViewer property actions call `touch(.modified)` with parent
propagation. The root clock changes and remains a retained conflict because
native root selection retains the base. Newer non-root clocks/properties that
already contain the full selected result can pass; newer clocks alone cannot
bypass the other checks. This patch therefore **does not establish unrestricted
ordinary native sync** or identify a real rejected upload's trigger.

Diagnostics contain only fixed aggregate categories: `group_membership`,
`group_properties`, `group_times`, `group_location`, `group_custom_data`,
`group_tags`, `unsupported_group_metadata`, plus existing admission/entry
categories. No UUIDs, titles, field names, values, secret hashes or native output.

## Migration, performance and activation

Old 0.7.0/0.7.1 locators, external roots, operation IDs and receipts remain
readable without reset, rebind or migration. Preserve all snapshots and recovery
blocks. Never downgrade below 0.7.0 on a bound vault; 0.6 cannot scan external
receipts. Older CLIs do not certify new profiles. A rollback loses new profile
support; do not silently fall back in a transport.

Full-cost tests retain KDBX4.1/AES256/Argon2d I119/M67108864/P2/V19 and the
300 active/900 History/1200 capsule fixture. They use the new native-group
profile and noncanonical tags through two HTTP hops, body staging, actual CLI/
RPC, full fresh decrypt, validation, atomic/fsync/readback and final receipt.
10/30-second measurements are host evidence, not a deadline guarantee under
arbitrary load. An external replacement adds a fresh current-file decrypt.
Separate fixed metadata deadlines and queued requests remain independent
failure shapes. No TLS/Tailscale, production adapter, real vault or device test.

Parent must review these differences and remaining conflicts **before activation**.
Only then retain the current latest durable broker image and resolve uncertainty,
install the exact tested wheel, advance maintained source/skill to its commit,
and use one normal coordinated restart/private HTTPS unlock. A running 0.7.0
process cannot acquire these checks. No hotpatch, export or second unlock service.
Parent owns the private adapter's explicit profile request and durable result
checks. No production action or new user unlock was requested by this thread.
