# Card storage and field-bound delivery (0.14.2)

Require CLI/broker card protocol 1: `cards_supported: true`, integer
`card_protocol: 1`, `card_delivery: "cdp-card-element-v1"`. `card_browser_configured`
must be true for filling. The CLI checks protocol capabilities before dispatch.
An edited checkout does not update the running broker. Do not restart or
reconfigure a shared browser or broker to work around a refused fill.

## Save or update

For an authorized save, run `create-card --title LABEL --group EXISTING_GROUP`.
For an authorized update, use `search-cards`, then `update-card HANDLE --title
EXACT_TITLE --group EXACT_GROUP`. Give the returned private URL to the user.
The user enters name, card number, two-digit expiry month, four-digit year and
optional security code directly into that page. Do not observe the form or put
card values in tool arguments, chat, files or screenshots.

The page prefills the title and group. The user can change the title. On a new
card, the user can choose another existing group (the KeePass folder the entry
is saved in; the page calls it the vault folder) from a list; the page does not create groups. An update keeps the
card's group. The page and the broker check the card number (Luhn checksum and
length for the detected brand), the expiry (01 to 12, not in the past) and the
security-code length; the broker refuses a bad form even if the page is
bypassed, and keeps the form open for correction. Do not tell the user a card
number is valid or invalid yourself; the page shows that.

The fields are protected custom strings in the encrypted KDBX entry, identified
by `akdbx.card=v1`. Existing cards in other clients need these explicit field
conventions; do not guess from arbitrary notes or extract the vault to import
them. `write-status WRITE_HANDLE` confirms `state: saved` and reports the final
non-secret `title` and `group` the user chose (0.28.1 and later); use those, not the values you
prepared, for later `search-cards` and `update-card`. `cancel-write`
cancels a pending page. A save page expires after five minutes; a vault revision
change invalidates it. A save receipt confirms vault persistence only.

Before giving the user a private save page, register the event-driven
[card-save notification](card-save-notifications.md) so the authorized task can
resume without asking the user to report completion. Require the advertised
card-save notification protocol; installing a CLI alone does not update a running
broker. Do not create a polling schedule or give the subscription a waiting TTL.

## Choose a card and destination

`search-cards QUERY` returns title, group, brand, last four digits and a
single-use, five-minute handle. Choose from these safe labels; resolve ambiguity
with the user instead of trying multiple cards. Login search excludes cards.

Verify the actual merchant, full HTTPS checkout URL, intended frame URL and
payment field through the browser's DOM tools. Get page/frame IDs and a unique
CSS selector without reading any filled values. Do not infer these identifiers
from an X11 window ID. Bring the actual field into view. Main frames and
same-origin iframes with matching `autocomplete="cc-…"` fields use the default
route. For Adyen, Computop or Stripe card iframes, use the explicit processor
routes below.
Other cross-origin frames, shadow DOM and unannotated fields must be refused.

```bash
akdbx pin-card-target --page-id PAGE_ID --frame-id FRAME_ID \
  --top-url https://merchant.example/checkout \
  --frame-url https://merchant.example/checkout \
  --selector '#card-number' --field cc-number
akdbx fill-card SEARCH_HANDLE --target CARD_TARGET --field cc-number
```

If the checkout or frame URL contains a private token, do not put it on the
command line and do not ask the user. Write it to a mode-0600 file without
printing it, pass `--top-url-file FILE` or `--frame-url-file FILE` in place of
the plain flag, and delete the file after the pin. See
[exact URL with a private token](target-fill.md#exact-url-with-a-private-token).

### Adyen processor frames

Require broker 0.14.0 or newer, integer `card_processor_frames_protocol: 1`
and `adyen` in `card_processors`. A new CLI refuses an older broker before
sending the processor pin. Base card protocol and receipts remain compatible.
Use `--processor adyen` only after independently verifying the merchant's
checkout and the actual processor field. The broker accepts only HTTPS
`checkoutshopper-live.adyen.com` production secured-field endpoints. It proves
that Chrome's out-of-process iframe belongs to the selected merchant tab,
through same-origin merchant ancestors. Missing browser ancestry metadata,
other processor origins, transformed/hidden/covered frames, CSS filters/masks
and ambiguous ownership refuse. This option does not allow arbitrary cross-origin frames.
Keep the full browser URL, including any `#/…` route; the broker joins CDP's
separate URL-fragment metadata and verifies the complete URL.

```bash
akdbx pin-card-target --page-id MERCHANT_PAGE_ID --frame-id ADYEN_FRAME_ID \
  --top-url EXACT_MERCHANT_HTTPS_URL --frame-url EXACT_ADYEN_HTTPS_URL \
  --selector 'input[autocomplete="cc-number"]' --field cc-number --processor adyen
akdbx fill-card SEARCH_HANDLE --target CARD_TARGET --field cc-number
```

### Computop hosted card forms

Require broker 0.14.2 or newer, integer `card_processor_frames_protocol: 1`,
and `computop` in `card_processors`. After verifying the actual merchant and
payment purpose, use `--processor computop` only for the production HTTPS
`www.computop-paygate.com/payssl.aspx` OOPIF, with no query or fragment.
The normal same-origin merchant ancestor, retained owner/input, visibility,
native hit-test, deadline and single-use guards apply before and after dispatch.
For a POST-loaded blank iframe, the broker also retains the unique merchant
POST form with the exact processor action and matching iframe target name.
Changes to that form or its action/method/target refuse delivery.

This page uses `autocomplete=off`. Only these exact input id AND name pairs
are supported, each visible editable type=text in a form: `creditCardHolder`
for cc-name, `_KKnr` for cc-number, `expiry_date` for cc-exp, and `cccvc` for
cc-csc. Other fields and off hints on other routes still refuse. Do not edit
attributes. Use a unique selector and fresh search handle/pin for each field,
with the exact observed page/frame IDs and complete URLs. Verify the visible
expiry label is MM/YY, then use `--format MM/YY`; four-digit years refuse.
No card value is returned, typed as keys, or placed on the clipboard. Submit
through the merchant's normal controls only within the user's authorization,
and verify the actual merchant acceptance, never just the fill receipt.

Pins have a maximum lifetime of 30 seconds; merchant verification uses part of
that lifetime. The fill deadline starts with the later fill request, so slow
verification does not consume its four-second dispatch budget. A pin that
expires during verification is refused instead of issued. Fill promptly.

### Stripe Payment Element

Require broker 0.18.1 or newer, integer `card_processor_frames_protocol: 1`
and `stripe` in `card_processors`. Use `--processor stripe` after verifying
the merchant and payment form. This route accepts the HTTPS
`js.stripe.com/v3/elements-inner-accessory-target-<hash>.html` iframe used by
Cloudflare. For the classic `elements-inner-card-<hash>.html` iframe, see
[Stripe Card Element](#stripe-card-element). Keep the complete observed frame URL, including its fragment.
Only the inputs with these exact IDs, names and autocomplete tokens are supported:

| Input ID | Name | Field |
| --- | --- | --- |
| `payment-numberInput` | `number` | `cc-number` |
| `payment-expiryInput` | `expiry` | `cc-exp` |
| `payment-cvcInput` | `cvc` | `cc-csc` |

Cloudflare dialogs that translate the iframe in two dimensions require 0.18.3
or newer. The broker checks the translated position and rejects covered inputs.

Use `--format MM/YY` for the expiry field. Pin the exact iframe and one unique
input for each fill, using a fresh card search handle each time.

### Stripe Card Element

Require broker 0.24.0 or newer with `stripe_card_element: true` in `status`,
as well as the Payment Element requirements above. Use the same
`--processor stripe`. The Card Element is pin-route only: use
`pin-card-target --processor stripe` (CDP or extension route). The extension
popup (user-click route) never offers or fills a card in this frame.

A new CLI refuses an older broker (no `stripe_card_element: true`) before it
sends the pin. On the extension route `--frame-url` is optional, so without it
the CLI cannot tell the two Stripe frames apart: against an older broker it
then refuses every `--processor stripe` pin and asks for the exact frame URL.
Give `--frame-url` with the complete observed Stripe frame URL.
The broker tells the two Stripe frames apart by the exact frame path only:
`elements-inner-accessory-target-<hash>.html` is the Payment Element and
`elements-inner-card-<hash>.html` is the classic Card Element. Each path accepts
only its own inputs, never the inputs of the other frame.

This route accepts the HTTPS
`js.stripe.com/v3/elements-inner-card-<32 hex>.html` iframe (title "Secure card
payment input frame"), with no query. Keep the complete observed frame URL,
including its `#__shared_params__…` fragment. Its inputs have no ID. Only a
visible editable type=text input with no `id` attribute, a name that is unique
in the frame, and the matching autocomplete token is supported:

| Name | Autocomplete | Field |
| --- | --- | --- |
| `cardnumber` | `cc-number` | `cc-number` |
| `exp-date` | `cc-exp` | `cc-exp` |
| `cvc` | `cc-csc` | `cc-csc` |

The frame also holds decoy inputs (`name="hidden" autocomplete="fake"`). The
broker refuses them, and every other input. Use a selector such as
`input[name="cardnumber"]`. Use `--format MM/YY` for `exp-date`; other formats
refuse. All the processor frame checks below apply.

```bash
akdbx pin-card-target --page-id MERCHANT_PAGE_ID --frame-id STRIPE_FRAME_ID \
  --top-url EXACT_MERCHANT_HTTPS_URL --frame-url EXACT_STRIPE_CARD_FRAME_URL \
  --selector 'input[name="exp-date"]' --field cc-exp --processor stripe
akdbx fill-card SEARCH_HANDLE --target CARD_TARGET --field cc-exp --format MM/YY
```

### Processor frame checks

The broker retains the actual input and the merchant's iframe owner in separate
isolated worlds. It checks the processor input in the write's JavaScript task,
and checks the exact merchant URLs, browser ancestry, retained iframe identity
and browser-native hit testing before and after dispatch. The native hit tests
include covers with `pointer-events:none` and require the retained input and
iframe-owner nodes. Even a transparent overlay can cause a conservative refusal.
Mask-box images and other unsupported CSS effects are refused. From 0.36.2 the
extension route accepts an ancestor `clip-path: inset(...)` that holds the whole
input ([clipped drawer or modal](identities.md#field-inside-a-clipped-drawer-or-modal-0362));
the CDP route, other clip shapes and an inset on the merchant's iframe owner
still refuse. Cross-process parent and child
checks are separate operations; an interrupted or changed post-dispatch guard
returns an uncertain receipt, never proof that nothing was written. Do not
retry it automatically. No submit, keyboard, clipboard or agent-visible card
value is used. Use a fresh search handle and pin for every field.

Allowed field types: `cc-name`, `cc-number`, `cc-exp-month`, `cc-exp-year`,
`cc-exp`, `cc-csc`. For `cc-exp`, explicitly select `--format MM/YY` or
`--format MM/YYYY`; for `cc-exp-year`, select `--format YY` or `--format YYYY`
from the observed form. Do not guess the expiry format. Each field requires a
fresh search handle and fresh 30-second pin. The broker fills the retained DOM
element directly, regardless of keyboard focus. It sends no Tab or submit.

Never substitute `fill --mode password`, `pin-target`, X11 typing, clipboard or
agent-visible JavaScript values if the card transport is unavailable. Report
the unsupported field/frame or missing browser configuration instead. The
operator configures the existing browser's private local CDP connection through
`serve --card-browser-profile USER_DATA_DIR` or `AKDBX_CARD_BROWSER_PROFILE`,
or with one Chrome per agent desktop through `serve --browser-profile-root ROOT`;
this is deployment configuration, not an agent-selected endpoint or new profile.
With a root, `pin-card-target` names the desktop's slot with `--browser-slot SLOT`
(default `$AGENT_DESKTOP_SLOT`; see [agent desktop slots](target-fill.md#agent-desktop-slots)).
Before the WebSocket handshake, the broker checks the connected peer's reciprocal
TCP tuple and UID in bounded Linux kernel metadata. Missing or ambiguous proof
refuses the connection. The verified socket is retained and redirects are refused.
Chrome's debugging port is a browser-control interface. Loopback alone does not
isolate it from other local users. The operator must provide host access controls
for trusted clients; profile ownership checks do not authenticate CDP clients.

## Verify without reading secrets

Only `ok`, the filled field type and transport enter a success receipt. Verify
non-secret UI validation or form progression; do not read the filled card value
back or capture it unmasked. A fill receipt does not prove merchant acceptance.
Refusals consume authorizations. After an uncertain response or connection
loss, stop and inspect non-secret form state; do not retry automatically.
Complete only the authorized task. Card fill alone never authorizes payment.

## Extension route (0.21.0)

`pin-card-target --route extension` pins the field through the paired akdbx
browser extension instead of a debugging port. `--frame-url` is optional on
this route; the broker uses the browser's own document URL (but see
[Stripe Card Element](#stripe-card-element) for an older broker). The merchant-frame
and processor rules are the same, and receipts carry `card_delivery:
"extension-dom-v1"`. Read [the extension route](extension.md).
