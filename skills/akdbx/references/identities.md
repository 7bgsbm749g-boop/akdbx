# Save and fill identity details (0.18.1)

Require `identity_protocol: 1` and `identity_delivery: "cdp-identity-element-v1"`
from `akdbx status`. Delivery also requires `identity_browser_configured: true`.
The broker uses its configured password browser profile, or the card browser
profile if there is no password profile. A source or CLI update alone does not
activate an existing broker. Follow the skill's private unlock workflow if
the broker is locked.

## Save

```bash
akdbx create-identity --title 'Home shipping' --group 'Personal'
akdbx write-status -- WRITE_HANDLE
akdbx cancel-write -- WRITE_HANDLE
```

Supply a short non-secret label and an existing group path. Keep personal
details out of labels, arguments, notes and agent responses. Give the user the
returned `private_url` within the private task. The user enters and confirms
the details on that page. The form accepts trimmed, single-line values and
requires at least one value. Country code uses two letters (for example `DE`).
The page expires after five minutes. Only `state: "saved"` confirms persistence.
Use `cancel-write` to cancel a pending page. The broker refuses a duplicate
identity label in the same group. To change an existing record, use KeePass
and keep the `akdbx.identity=v1` marker and the protection on each
`akdbx.identity.FIELD` custom string. Coordinate external editing as for any
vault write.

## Fill

Verify the exact HTTPS site and select the correct account or form. Inspect
the label, field type, selector and autocomplete token without reading input
values. For the configured password browser profile, `list-password-frames
--top-url EXACT_HTTPS_URL` provides tab and frame IDs. See [target discovery](target-fill.md)
for the retained browser target. The field frame must have the top page's
exact HTTPS origin. Supply the exact URL of each, including its path and any
query or fragment. The two URLs are identical for a main-frame field. If either
URL contains personal data or a private token, stop before passing it to the
CLI.

Focus the intended field and use one fresh pin and search handle per field.

```bash
akdbx pin-identity-target --page-id PAGE_ID --frame-id FRAME_ID \
  --top-url EXACT_HTTPS_URL --frame-url EXACT_HTTPS_FIELD_DOCUMENT_URL \
  --selector '#postal-code' --field postal-code
akdbx search-identities 'Home shipping'
akdbx fill-identity --field postal-code --target TARGET_FROM_PIN -- HANDLE_FROM_SEARCH
```

Search returns the title, group path and handle for up to 20 case-insensitive
label matches. Use `search-identities LABEL --group EXACT_GROUP_PATH` to narrow
matches before the limit. Select the exact label and group. Search does not
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
An absent saved value or missing or conflicting autocomplete token refuses.
The broker also refuses a hidden, unfocused, covered, ambiguous, or changed
field. It uses the retained DOM element and sends no keys, focus changes,
clipboard data or form submission. Identity fills do not dispatch input or
change events. A site that requires those events can need manual entry.

A receipt reports the field token and delivery outcome. Check the site's
non-secret state without reading the filled value. On an uncertain response
or timeout, check the destination before taking any further action. Use
fresh references for a deliberate retry.
