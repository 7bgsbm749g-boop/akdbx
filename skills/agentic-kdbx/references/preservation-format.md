# Internal version capsule format (capsule-v1, 0.5.0)

This is an internal preservation format, not an agent export or restoration
workflow. No public command returns its contents. It is entirely inside the
ordinary authenticated/encrypted KDBX and uses that database's credentials.
There is no second unlock service or individually encrypted sidecar.

The managed group has UUID `f889158f-848d-5932-9887-364d8b37cb83` and CustomData
`akdbx.version-capsules=capsule-v1`. Its entries use generic labels and disabled
group search/autotype. Each has exactly one protected binary attachment named
`original-record.akdbx` and protected custom property `akdbx.capsule-sha256`.
The latter is a SHA-256 of the attachment bytes; it is a consistency check, not
an independent signature. KDBX authentication protects the database.

The attachment is canonical UTF-8 JSON with these keys:

| Key | Preserved value |
| --- | --- |
| `schema` | `capsule-v1` |
| `uuid`, `group_uuid` | Original entry and observed parent UUIDs |
| `group_path`, `group_record` | Original grouping context; group record excludes child groups/entries |
| `format` | Original KDBX major/minor version for timestamp decoding |
| `record` | Original active or history entry node without its nested History |
| `attachments` | Every original Binary reference with its exact bytes encoded as base64 |
| `custom_icons` | Original referenced custom icon records, including exact image data |

A packed node is `[tag, attributes, text, children, tail]`. Attributes are an
object; text/tail are strings or null; children are packed nodes. Comments use
`#comment`; processing instructions use `#pi` with their `target` attribute.
Original protected field values are inside this encrypted attachment, never in
the CLI, receipt, engine arguments, logs or a plaintext file. History records
are captured separately so duplicate original times remain representable.

The logical identity is a private SHA-256 of original UUID, parent UUID,
normalized entry content including all original times and attachment byte
hashes, and referenced icon content. Benign formatting/default differences
deduplicate; unknown metadata order, significant whitespace, protection flags,
custom fields and distinct bytes remain significant. The first input's exact
representation is retained when logical identities match. This is set retention
of logical versions, not a count of identical copies across histories.

Container entry UUIDs are UUIDv5 of that identity under namespace
`f5ba0e04-3220-5403-88af-8780ec6da434`. Containers have fixed epoch bookkeeping
times, no native History and no login values. This does not change original
times or invent an ordering for original versions. Native history limits cannot
prune opaque attachment contents. The broker validates the group marker,
container UUID, record UUID, schema, payload checksum and attachment structure,
then verifies every expected payload byte after encrypted save/reopen.

The complete input ledger is unioned on every preservation merge, restored if a
native stage omits it, and checked across later supported saves. Capsules remain
when their original active entry is validly deleted. They are not automatically
pruned. Corrupt capsules or reserved UUID collisions refuse the operation;
incomplete receipts never trigger an automatic repair/reset.

Recovery of individual fields/versions is not exposed in 0.5.0. Native History
is still useful but is not a complete ledger of duplicate-time or pruned records.
Keep the encrypted originals and truthful operation receipt as well. Database
and group setting conflicts remain subject to the documented native merge
policy; capsules do not claim a separate settings reconciliation algorithm.
