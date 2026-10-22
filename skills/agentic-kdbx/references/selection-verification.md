# Active verification and safe diagnostics (0.6.0, semantic-v1)

Native serialization is not byte-for-byte entry selection. Version 0.5.0 used
one broad entry signature for both and could refuse correct native results.
Synthetic native tests reproduce protection-flag upgrades under destination
MemoryProtection, tag normalization, omitted defaults, CustomData clocks and
previous-parent changes. This does not establish the cause of any real-vault
failure; no real contents are needed to interpret supported diagnostics.

The verifier does not modify native results or choose a password from history.
It simulates the two native stages: newest **active** modification time at stored
second precision, current-target preference on active ties, location resolved
before whole active-record replacement at each stage. The active value and its
actual group can come from different inputs. A newer history item never becomes
active. Source-root entries map to the destination root while retaining entry
UUIDs. Previous-parent changes from native moves are checked.

After encrypted reopen, verify:

- Exact standard field values, including password whitespace and Unicode.
  Missing standard fields equal empty defaults; an empty custom field remains
  distinct from a missing field. Custom field names/values and attachment names
  and bytes must match the selected original, not merely an archived version.
- Original protected fields cannot become unprotected. Standard fields may gain
  protection under destination MemoryProtection. ProtectInMemory and Protected
  represent the same protection intent. Standard policies do not permit
  arbitrary protection changes on custom fields.
- Modification and creation instants, expiry-enabled state, effective expiry
  when enabled, selected location timestamp, actual group and previous parent.
  ISO UTC/offset timestamps and binary KDBX times are compared at serialized
  seconds. Unused expiry timestamps, access times and usage statistics do not
  choose active credentials. Every exact original time remains in its capsule.
- AutoType settings/association order, override URL, colors, icon choice, report
  quality flag, and CustomData values. Tags use native split/trim/deduplicate
  semantics. Numeric/default/null representations are normalized. The legacy
  CustomData KnownBad report flag maps to QualityCheck with the native literal
  semantics. Native dictionary `_LAST_MODIFIED` and omitted per-item CustomData
  clocks do not select active values; ordinary String custom fields with these
  names are still exact. Referenced icon bytes and original metadata remain in
  capsules; shared database icon/settings conflicts follow native rules.

Missing/unexpected/duplicate active entries, wrong selected values, altered
attachments, protection downgrade, incorrect expiry/time/location or unsupported
metadata transformations refuse replacement. Unknown selected extensions that
the engine discards are refused, not silently exempted. Missing essential
creation/location/modification times or invalid timestamps produce a structural
refusal rather than an invented time. Nonselected original extensions still
remain in capsules.

Require status `merge_active_verification: "semantic-v1"` and
`merge_diagnostics: "categories-v1"`, in addition to the existing merge and exact
capsule-v1 capabilities. The current CLI preflights semantic-v1 and sends
`active_verification: "semantic-v1"`. The broker rejects unsupported requested
verifiers. An older raw request without that new field remains supported on
0.6.0 with semantic verification enabled; check the active verifier in the
durable result before integration success. An old 0.5.0 process cannot gain this
code without one coordinated normal restart/private unlock after final package
installation. Preserve its latest encrypted durable state and receipts first.

A failed verification includes `verification_diagnostics`, a nonempty object of
fixed aggregate **entry-category counts**:

| Categories | Meaning / next step |
| --- | --- |
| `missing_entry`, `unexpected_entry`, `duplicate_entry`, `deletion` | Active UUID membership/deletion check failed. Retain encrypted inputs; do not override. |
| `modification_time`, `standard_fields`, `custom_fields`, `field_protection`, `attachments` | Selected active data or protection differs. Do not accept a candidate just because its capsules retained originals. |
| `times_metadata`, `location`, `entry_metadata`, `custom_data` | Active metadata differs from documented native semantics. Keep the receipt for a synthetic client repair. |
| `unsupported_structure`, `unsupported_times`, `unsupported_metadata` | A structure/time or discarded selected extension cannot be safely verified. This is a supported-client limit; do not read decrypted records or export them to diagnose. |

Only nonzero counts are returned. One entry can count in several categories.
No UUID, title, username, URL, field name/value, secret signature/hash or raw
native output is included. There is no standalone arbitrary-value comparison
API. Diagnostics belong to an authorized merge of trusted owned inputs; they
do not authorize probing secrets. Lost/uncertain receipt rules still apply: a
failure to save a receipt cannot establish a durable result. Use merge-status.

Capsule-v1 identities and immutable original payloads remain compatible with
0.5.0. Semantic verification does not change the retention policy. Native
History is still not the full duplicate-time ledger, and no capsule restore,
view, export or purge command exists. Repeated merges retain existing capsules.
Native-generated clock changes can create additional exact original metadata
versions and increase the ledger; capsule-v1 retains them even when login values
match. There is no pruning, repair override or timestamp rewrite.

Native references: [UUID/value and location merge](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/core/Merger.cpp),
[reader normalization](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/KdbxXmlReader.cpp),
[writer serialization](https://github.com/keepassxreboot/keepassxc/blob/2.7.10/src/format/KdbxXmlWriter.cpp).
