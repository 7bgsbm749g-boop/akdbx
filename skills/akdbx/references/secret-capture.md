# Capture a shown-once secret and deliver it (0.20.0)

Use this when a website shows a new secret once (an OAuth client secret, an API
key, a webhook signing secret) and the task needs it stored and later written
to a service configuration. The broker reads the page element itself, saves
the value as a protected KeePass field and writes it only to a sink that the
operator configured at broker start. The value never enters a tool response,
chat, argv, screenshot, log or evidence file.

Require from `akdbx status`: integer `secret_capture_protocol: 1`,
`secret_capture_delivery: "chromium-dom-read-v1"`, `password_browser_configured:
true` for capture, and integer `secret_sink_protocol: 1` with the sink name in
`secret_sinks` for delivery. The CLI refuses an older broker before it sends
anything. A source or CLI update does not activate a running broker.

## Never look at the secret

After the site shows the secret, do not take a screenshot, accessibility
snapshot, page text dump, `innerText`/`value` read, clipboard copy or video of
that page. The secret stays visible until you navigate away, so plan the
selector before you generate it, then capture, then leave or reload the page.
Do not click the site's copy button: that puts the value on the clipboard.

Find the selector from structure only: the element's tag, `id`, classes,
attributes and position relative to fixed page text. A structural query may
return counts, tags, ids, class names, lengths and bounding boxes; it must not
return text content or values. If no selector without page text identifies one
element, stop and report that blocker.

## 1. Point at the element and pin it

Focus the element that shows the secret: a read-only text input, or an element
with `tabindex`. For an element that cannot take focus, a structural script may
set `element.tabIndex = -1` and call `element.focus()`, returning nothing. Do not
select, double-click or drag over the text: on X11, Chromium publishes any
selected text (also a scripted selection) to the PRIMARY selection, where other
programs can read it. Pins accept focus only and refuse while any text is selected, also inside the
focused input; focus by script rather than with Tab, which can select an input's
text. Then pin it, like a password
field, with the new read mode:

```bash
akdbx pin-password-target --mode read --page-id PAGE_ID --frame-id MAIN_FRAME_ID \
  --top-url EXACT_HTTPS_URL --selector '#new-client-secret'
```

The receipt is `{"ok": true, "target": "...", "expires_in": 30, "target_delivery": "chromium-password-dom-v1"}`.
The pin is single use and expires after 30 seconds. It refuses unless:

- the page has the exact HTTPS top URL, page ID and frame ID (a same-site child
  frame needs `--frame-origin` as described in the target-fill guide; a
  cross-site frame chain refuses);
- the selector uses only tag names, `#id`, `.class`, `:nth-of-type(n)` or
  `:nth-child(n)`, joined by spaces or `>` (attribute selectors and other
  pseudo-classes refuse, so a pin result cannot test the secret's value);
- the selector matches exactly one visible element in the viewport (not
  `visibility: hidden`, `opacity: 0`, `display: none`, `inert` or zero size);
- the page has focus and the element itself is focused;
- the element is a read-only text input or a leaf element that holds only text
  (no child elements), and not a password, textarea, select or editable element;
- its rendered text, trimmed of surrounding blanks, is one non-empty token of at
  most 4096 characters with no space, line break, control or invisible character.

## 2. Capture into an explicit entry

New record (choose verified title, account, HTTPS URL and an existing group):

```bash
akdbx capture-secret --target TARGET --field client_secret --new \
  --title 'Example OAuth app' --username 'CLIENT_ID' \
  --url 'https://github.com/settings/applications/1234' --group 'Web'
```

Existing entry (fresh `search` handle and all four exact metadata values;
`--replace` is required if the field already exists):

```bash
akdbx capture-secret --target TARGET --field client_secret --handle HANDLE \
  --title TITLE --username USERNAME --url URL --group GROUP [--replace]
```

The page's (or child frame's) exact origin must equal the entry's main URL
origin or one of its additional URLs. The broker re-verifies the page, frame,
element, focus and value before it reads, then rereads the
encrypted file after the save. Any mutation of the element, navigation, focus
change, blur or value change after the pin refuses with
`nothing saved`. The receipt is only:

```json
{"ok": true, "state": "saved", "created": true, "field": "client_secret",
 "length": 40, "metadata": {...}, "capture_delivery": "chromium-dom-read-v1"}
```

The field is a protected custom string. The entry records its name in
`akdbx.captured-fields`; `search` shows `captured_fields` and, for new records,
`secret_record: true`. A new secret record has no site password, so login and
password fills refuse it. Field names are letters, digits and underscores;
standard KeePass fields, `otp`, `TOTP*`, `KP2A_URL*` and `akdbx*` names refuse.

If capture refuses after the site showed the secret, do not read the page to
find out why. Fix the selector or pointing and pin again while the secret is
still shown. If the page has changed, generate a new secret on the site only if
the task authorizes it, and revoke the unused one.

## 3. Deliver to a configured sink

```bash
akdbx deliver-secret --sink repus-env --field client_secret -- HANDLE
```

Use a fresh `search` handle for the entry. The sink, not the caller, fixes the
file path, the `KEY` in its `KEY=VALUE` file, the owner, group, mode, the field
name, the required entry origin and an optional fixed restart command. The
agent cannot pass a path, key or command. The receipt is only:

```json
{"ok": true, "state": "delivered", "sink": "repus-env", "field": "client_secret",
 "restarted": true}
```

The receipt does not say whether the file already had this value. `restarted` is `true`
when the configured restart command succeeded, `false` when it failed and `null`
when the sink has none. Verify the service's non-secret outcome (for example a
health or status endpoint), never the file content.

Refusals write nothing: an unknown sink, a field other than the sink's field,
an entry not on the sink's origin, a field that capture did not save or that is
not protected, a value that an environment file cannot hold unquoted (only
`A-Z a-z 0-9 . _ + / = : @ % , ^ -`; a shell would expand `~`), a duplicated key, any quote or backslash
in the file, or a symlinked, hard-linked or
foreign-owned path. The handle is consumed either way.

Operators define sinks in a JSON file passed as `serve --secret-sinks PATH`
(or `AKDBX_SECRET_SINKS`). Sinks owned by another account use the root-owned,
socket-activated helper described in the repository's `docs/secret-sinks.md`.
Adding or changing a sink needs the operator and a broker restart; an agent
must not edit the sink file or helper to reach a new destination.
