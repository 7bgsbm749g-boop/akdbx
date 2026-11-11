# Card storage and field-bound delivery (0.13.0)

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

The fields are protected custom strings in the encrypted KDBX entry, identified
by `akdbx.card=v1`. Existing cards in other clients need these explicit field
conventions; do not guess from arbitrary notes or extract the vault to import
them. `write-status WRITE_HANDLE` confirms `state: saved`. `cancel-write`
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
from an X11 window ID. Bring the actual field into view. Only main frames and
same-origin iframes with matching `autocomplete="cc-…"` fields are supported;
cross-origin processor frames, shadow DOM and unannotated fields must be refused.

```bash
akdbx pin-card-target --page-id PAGE_ID --frame-id FRAME_ID \
  --top-url https://merchant.example/checkout \
  --frame-url https://merchant.example/checkout \
  --selector '#card-number' --field cc-number
akdbx fill-card SEARCH_HANDLE --target CARD_TARGET --field cc-number
```

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
`serve --card-browser-profile USER_DATA_DIR` or `AKDBX_CARD_BROWSER_PROFILE`;
this is deployment configuration, not an agent-selected endpoint or new profile.
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
