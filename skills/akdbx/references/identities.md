# Save and fill identity details (0.18.2)

For identity field operations on Android, see [Android pins and commands](android.md#additional-android-operations-0501).

Require `identity_protocol: 1` from `akdbx status`. On the CDP route,
delivery also requires `identity_delivery: "cdp-identity-element-v1"` and
`identity_browser_configured: true`; the broker uses its configured password
browser profile, or the card browser profile if there is no password profile.
The extension route needs a paired extension, and native field and Android
pins need their own capabilities (see the
[support matrix](../../../docs/support-matrix.md)). A source or CLI update alone does not
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
The save button shows a busy bar while saving. A save then ends on a small
`Success` screen (`Identity saved to vault`, and the title and group it was
saved as), the same as a card page; an error keeps the form with an error
state on the button (`Page expired`, `Not confirmed`). A correctable form
error keeps the page open with the message under the button. The page expires
after five minutes unless you ask for a longer lifetime (below).
Only `state: "saved"` from `write-status` confirms persistence.
Use `cancel-write` to cancel a pending page. The broker refuses a duplicate
identity label in the same group.

### The user may rename the identity on the page (0.52.1)

The page shows the title in a text field that the user may change. A new
title is saved in the same write as the fields. An unchanged or empty title
field keeps the title you gave. The page applies the `--title` rules (up to
4096 bytes, no line breaks or control characters) and refuses a title that
another identity in the same group already has; the form stays open with the
message. The group cannot be changed on the page. After the save,
`write-status` returns the saved `title` and `group` with `state: "saved"`.
Use that title, not the one you gave, to search for the identity again.

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
history. The receipt, `write-status` states, `cancel-write`, page lifetime,
title field and save button are the same as for `create-identity`. A new title
replaces the old one in the same write; the entry history keeps the old title.

## Page lifetime (0.51.0)

```bash
akdbx create-identity --title 'Home shipping' --group 'Personal' --fields tel --valid-minutes 25
```

`create-identity` and `update-identity` take `--valid-minutes N`: the private
page stays valid for N whole minutes, from 1 to 30. Without it the page stays
valid for 5 minutes. Use a longer lifetime when the user cannot enter the
details at once, for example when the user asked for it or a page already
expired unsaved. The receipt reports `expires_in` (seconds) and `expires_at`
(UTC, for example `2026-11-26T12:30:00Z`), and the page shows the expiry time
in the viewer's time zone. Tell the user the expiry time with the link. A
longer lifetime changes nothing else: the page is still single use, still
needs its token, and still becomes invalid when the vault changes. A vault
lock (idle timeout, screen lock or `lock`) also ends the page, and opening
the page does not keep the vault open, so a lifetime cannot be longer than the
broker's `lock_timeout_seconds`; the default page is cut to it. The CLI
refuses a value outside 1 to 30 or longer than the lock timeout before
sending, and refuses `--valid-minutes` unless `akdbx status` shows
`save_page_lifetime_protocol: 1`; the broker refuses such a value too.

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
clipboard data or form submission. By default the fill sends no events.
For a form that tracks edits, use
`fill-identity --notify-page` to send bubbling `input` and `change` events
on the pinned field after setting its value. The page can validate, advance,
or submit the form in response. Check its non-secret state before continuing.
This option requires fill extension 0.9.0 or newer on the extension route.
It also works on Android Chrome pages; native controls and Android app fields
refuse it, because they have no page to notify.

### Field inside a clipped drawer or modal (0.36.3)

Card and identity pins refuse a field when the field or an ancestor has CSS
that can hide part of it: `clip`, masks, filters, `backdrop-filter`, a blend
mode, and `clip-path`. From 0.36.3, the extension route (fill extension 0.7.2)
accepts one `clip-path`: `inset(...)` with only `px` or `%` lengths, on an HTML
block or atomic inline element with one box, when the field's whole border box
lies inside the inset rectangle of that element's border box (each inset
widened by a 0.1% rounding margin). Side drawers and modals often use a
negative inset such as `inset(-32px 0px -32px -32px)` only to trim their own
shadow; it hides nothing inside the drawer, so the field pins. The pin checks
it again at the fill. This requires fill extension 0.11.1 or newer on Firefox.

The CDP route still refuses every `clip-path`: its in-page JavaScript cannot inspect
closed shadow roots. CDP itself can traverse shadow roots with
`DOM.getDocument` and `pierce: true`. The in-page check must refuse the inset
because it cannot exclude a hidden transform. A closed shadow wrapper that mirrors the drawer keeps
its size but swaps the edges the inset clips. For a field in such a drawer,
pin with `--route extension`:

```bash
akdbx pin-identity-target --route extension --page-id PAGE_ID --frame-id FRAME_ID \
  --top-url EXACT_HTTPS_URL --selector '#recipient-add-input' \
  --field tel --field-purpose tel
```

The extension route still refuses:

- an inset that cuts any part of the field, before the pin or after it;
- `round` corners, `calc()`, a reference box keyword (`padding-box`), and every
  other shape (`polygon()`, `circle()`, `ellipse()`, `path()`, `url()`);
- an inset on an element that is not HTML, has more than one box, or is
  inline, a table or a list item;
- a scale, rotation, perspective, motion path or `zoom` on the clipping
  element or any element above it (a pure translation is accepted), an SVG
  element above it (a `foreignObject` viewport scales it), a rendered size
  that differs from its layout size, or the clipping element or an element
  above it slotted into an open or closed shadow tree.

A refusal is the usual `target unavailable, changed or unsupported`. Password
pins do not use this style check.

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

### Phone number next to a country picker

When the page has a separate country-code dropdown, the phone input wants the
number without the country code, or the full number with it. Fill with
`--format national` or (from 0.36.1) `--format international`. Require
`identity_tel_formats` in `status` to contain the format you use:

```bash
akdbx fill-identity --field tel --format national --calling-code 44 \
  --target TARGET_FROM_PIN -- HANDLE_FROM_SEARCH
akdbx fill-identity --field tel --format international --calling-code 44 \
  --target TARGET_FROM_PIN -- HANDLE_FROM_SEARCH
```

- `national` fills the national significant number, digits only: no `+`,
  `00`, country calling code or trunk `0`. Spaces, hyphens, dots, slashes and
  brackets are dropped. `international` fills `+`, the calling code and that
  number (`+447...`). The saved value does not change.
- `--calling-code DIGITS` (no `+`) is the code the page's picker shows. A saved
  `+...` or `00...` number refuses unless it has that code, so a number of
  another country never goes next to the picker (for a `0...` number, see
  below). Check the picker shows the
  right country before you fill.
- A saved number in national form with one trunk `0` (`07...`, 0.36.1) works
  only with `--calling-code`, which tells the broker the country. The broker
  drops the `0` only for countries where the `0` is never part of the number
  (for example 44 UK, 49 Germany, 33 France, 61 Australia; the full list is
  `TRUNK_ZERO` in `src/akdbx/identities.py`, from Google libphonenumber), and
  only for a number of a length that country uses. Other countries refuse: in
  Italy (39) the `0` is part of the number, Russia (7) uses `8`, Hungary (36)
  uses `06`, Argentina (54) and Brazil (55) put other digits next to it.
  Without `--calling-code` it refuses: the country is unknown. A bracketed
  area code (`(020) 7946 ...`) works too.
- For a `0...` number the broker cannot check the country: it takes
  `--calling-code` as the number's country, and a wrong code fills a wrong
  number. Give it only when the user told you the phone number's country, and
  set the picker to it. The identity's address `country` is not the phone's
  country (a French address can go with an Australian mobile); if you do not
  know, ask the user.
- For those trunk-0 countries a `0` after the calling code (`+44 07...`)
  refuses: it is the wrong number a page made from `07...` and a +44 picker.
- A `(0)` marker, letters or an extension refuse: the broker cannot split
  the number safely. If a fill refuses, ask the user to update the identity's
  phone number in international form with `update-identity --fields tel`.
- A refusal never shows the number. `--format` applies only to `--field tel`.

A receipt reports the field token and delivery outcome. Check the site's
non-secret state without reading the filled value. On an uncertain response
or timeout, check the destination before taking any further action. Use
fresh references for a deliberate retry.

## Extension route (0.21.0)

`pin-identity-target --route extension` pins the field through the paired akdbx
browser extension. Only frames of the top origin are accepted, and receipts
carry `identity_delivery: "extension-dom-v1"`. Read
[the extension route](extension.md).

## Toolbar popup (fill extension 0.15.0)

The user can fill an address with a click: focus an address field, open the
akdbx popup and choose the identity. From fill extension 0.15.0, the popup
applies the identity pin's own checks to the focused field and to each
partner field of the same form, section and address part (`shipping` or
`billing`): the autocomplete grammar and field table above, the input types,
the select rules, the style guard, the hit test, exact page URLs and only
frames of the top origin. It sends the `input` and `change` events of
`--notify-page`. It has no `--field-purpose` and no `--format`: a field
without a matching token stays empty, and a phone number fills as saved.
A field outside the visible part of the page stays empty. Details:
[user-click workflow](extension.md#user-click-workflow).
