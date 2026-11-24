# Save and fill identity details (0.18.2)

Require `identity_protocol: 1` and `identity_delivery: "cdp-identity-element-v1"`
from `akdbx status`. Delivery also requires `identity_browser_configured: true`.
The broker uses its configured password browser profile, or the card browser
profile if there is no password profile. A source or CLI update alone does not
activate an existing broker. Follow the skill's private unlock workflow if
the broker is locked.

## Save

First look for the user's existing identities:

```bash
akdbx search-identities ''
```

- One identity fits the task (for example the user's only personal record):
  add or change the missing field on it with `update-identity` (below).
  Do not create a duplicate.
- None fits: create a new one.
- Several could fit: ask the user which one to use, or whether to create a
  new one. Give only the titles and groups.

Search leaves out identities that share the same title and group. If the user
says a matching identity exists but search does not return it, ask the user
which title to use; do not create another one.

```bash
akdbx create-identity --title 'Home shipping' --group 'Personal' --fields tel
akdbx write-status -- WRITE_HANDLE
akdbx cancel-write -- WRITE_HANDLE
```

Ask only for the fields the task needs. Pass them with `--fields`, a
comma-separated list of the field keys in the fill table below (for example
`--fields tel` or `--fields tel,email`; `street-address` is a fill token, not a
saved field, so use `address-line1` and the other lines). The private page then
shows only those fields, and the broker accepts and stores only those fields.
Without `--fields`, the page shows all fields. `--fields` needs
`identity_fields_protocol: 1` from `akdbx status` (0.28.2); the CLI refuses
before sending the request otherwise.

Supply a short non-secret label and an existing group path. Keep personal
details out of labels, arguments, notes and agent responses. Give the user the
returned `private_url` within the private task. The user enters and confirms
the details on that page. The form accepts trimmed, single-line values and
requires at least one value. Country code uses two letters (for example `DE`).
The save button shows a busy bar while saving, then `Saved` or an error state
(`Page expired`, `Not confirmed`); a correctable form error keeps the page
open with the message under the button. The page expires after five minutes.
Only `state: "saved"` from `write-status` confirms persistence.
Use `cancel-write` to cancel a pending page. The broker refuses a duplicate
identity label in the same group.

## Update an existing identity (0.28.3)

```bash
akdbx search-identities 'Home shipping' --exact --group 'Personal'
akdbx update-identity --title 'Home shipping' --group 'Personal' --fields tel -- HANDLE_FROM_SEARCH
akdbx write-status -- WRITE_HANDLE
```

Requires `identity_update_protocol: 1` from `akdbx status`. Pass a fresh
search handle and the exact title and group the search returned, and
`--fields` with only the fields to add or change. The broker refuses a used
or expired handle, a title or group that does not match, and a title and group
that more than one identity shares. The private page shows only those fields,
with empty inputs; it never shows the saved values. A field the user leaves
empty keeps its saved value, and at least one field must be filled in. Saving
changes only the filled-in fields, keeps the `akdbx.identity=v1` marker and the
protection on every field, and keeps the previous version in the entry
history. The receipt, `write-status` states, `cancel-write`, five-minute
expiry and save button are the same as for `create-identity`.

## Fill

Verify the exact HTTPS site and select the correct account or form. Inspect
the label, field type, selector and autocomplete token without reading input
values. For the configured password browser profile, `list-password-frames
--top-url EXACT_HTTPS_URL` provides tab and frame IDs. See [target discovery](target-fill.md)
for the retained browser target. The field frame must have the top page's
exact HTTPS origin. Supply the exact URL of each, including its path and any
query or fragment. The two URLs are identical for a main-frame field. If either
URL contains personal data or a private token, do not put it on the command
line and do not ask the user: write it to a mode-0600 file without printing
it, pass `--top-url-file FILE` or `--frame-url-file FILE` in place of the
plain flag, and delete the file after the pin. See
[exact URL with a private token](target-fill.md#exact-url-with-a-private-token).

Focus the intended field and use one fresh pin and search handle per field.

```bash
akdbx pin-identity-target --page-id PAGE_ID --frame-id FRAME_ID \
  --top-url EXACT_HTTPS_URL --frame-url EXACT_HTTPS_FIELD_DOCUMENT_URL \
  --selector '#postal-code' --field postal-code
akdbx search-identities 'Home shipping' --exact
akdbx fill-identity --field postal-code --target TARGET_FROM_PIN -- HANDLE_FROM_SEARCH
```

Search returns the title, group path and handle for up to 20 case-insensitive
label matches, subject to the response size limit. Use `--exact` for the full
case-sensitive label and `--group EXACT_GROUP_PATH` for the group. These filters run before
the limits. Select the exact label and group. If more than one entry has the
same label and group path, the broker omits those entries. Search does not
inspect address, phone, name or email values. A pin lasts 30 seconds. A search handle
lasts up to five minutes. Each is consumed on the first fill attempt.

Use the matching HTML autocomplete field token:

| Token | Saved detail |
| --- | --- |
| `name`, `given-name`, `additional-name`, `family-name` | Full name or the separately saved name part |
| `address-line1`, `address-line2`, `address-line3` | Individual postal address lines |
| `street-address` | Saved address lines joined with line breaks. Use a textarea for multiple lines. |
| `address-level2`, `address-level1` | City or locality and state, province or region |
| `postal-code` | Postcode |
| `country`, `country-name` | Two-letter code or separately saved name |
| `tel`, `email` | Phone number and email address |

Text inputs, compatible email and telephone inputs, and a street-address
textarea can receive values. Single-select country and region controls
require a unique enabled option whose value matches the stored text exactly.
An absent saved value or missing or conflicting autocomplete token refuses,
unless you give an explicit field purpose (below).
The broker also refuses a hidden, unfocused, covered, ambiguous, or changed
field. It uses the retained DOM element and sends no keys, focus changes,
clipboard data or form submission. Identity fills do not dispatch input or
change events. A site that requires those events can need manual entry.

### Field without an autocomplete hint (0.35.1)

Many sites have phone, name and address inputs with no autocomplete token.
Require `identity_field_purpose_protocol: 1` from `akdbx status`. First verify
from the page itself that the field takes this detail: its label, placeholder,
`name`, `type` and the form around it. Then add `--field-purpose FIELD` with
the same value as `--field`:

```bash
akdbx pin-identity-target --route extension --page-id PAGE_ID --frame-id FRAME_ID \
  --top-url EXACT_HTTPS_URL --selector 'input[name="phoneNumber"]' \
  --field tel --field-purpose tel
```

- With the purpose, the broker also accepts a field with no autocomplete
  attribute, an empty one, or only `on`.
- `autocomplete="off"` needs `--allow-autocomplete-off` as well (only
  together with `--field-purpose`).
- A token for another detail still refuses, for example `email` when you
  pin `tel`, and so does a sub-token such as `tel-national`. A purpose that
  differs from `--field` refuses before the request is sent.
- Every other guard stays: exact URL, same origin, unique selector, visible
  and uncovered field, focus, compatible input type, 30-second single-use
  pin, and no value in any output. A hint that changes after the pin refuses
  the fill. Never add or rewrite page attributes to make a field eligible.
- The CDP and extension routes apply the same rules. The extension route
  needs fill extension 0.7.0 or newer (`extension_browsers` in `status`
  shows `version_status: "current"`); the broker refuses a purpose pin to an
  older extension.

### Phone number next to a country picker (0.35.1)

When the page has a separate country-code dropdown and the phone input wants
only the national number, fill with `--format national`. Require
`identity_tel_formats` to contain `"national"` in `status`:

```bash
akdbx fill-identity --field tel --format national --calling-code 44 \
  --target TARGET_FROM_PIN -- HANDLE_FROM_SEARCH
```

- The broker removes the leading `+` (or `00`) and the country calling code,
  a `(0)` trunk marker, and spaces, hyphens, dots, slashes and brackets. The
  field receives only the digits of the national number. The saved value does
  not change.
- `--calling-code DIGITS` (no `+`) refuses unless the saved number has that
  country calling code. Give the code the page's picker shows, so a number of
  another country never goes next to it. Check the picker shows the right
  country before you fill.
- A saved number without `+` or `00`, or with letters or an extension,
  refuses: the broker cannot split it safely. Ask the user to update the
  identity's phone number in international form with `update-identity
  --fields tel`.
- `--format` applies only to `--field tel`.

A receipt reports the field token and delivery outcome. Check the site's
non-secret state without reading the filled value. On an uncertain response
or timeout, check the destination before taking any further action. Use
fresh references for a deliberate retry.

## Extension route (0.21.0)

`pin-identity-target --route extension` pins the field through the paired akdbx
browser extension. Only frames of the top origin are accepted, and receipts
carry `identity_delivery: "extension-dom-v1"`. Read
[the extension route](extension.md).
