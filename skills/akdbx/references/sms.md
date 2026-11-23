# Phone verification texts (SMS) (0.34.0)

akdbx can receive the verification texts that sites send to a phone number and
fill the code straight into the challenge field. You see only a masked preview
(no digits, no links), the sender and the code length. You never see the code,
the webhook token or the text itself.

Require broker 0.34.0 or newer and `status` field `sms_protocol: 1`.
`sms_sources_configured` tells you how many phone numbers forward texts.

## Two kinds of phone number

| Source kind | What it is | Works with |
| --- | --- | --- |
| `shortcut` (**recommended**) | The user's real iPhone number. An iOS Shortcuts automation forwards each verification text. | Every site, because it is a real carrier number. |
| `twilio` | A virtual Twilio number. Twilio posts each text to akdbx. | Only sites that accept VoIP numbers. |
| `webhook` | Any other service that can POST each text. | Depends on the number. |

**Use the real number by default.** Google, many banks, WhatsApp and some other
sites reject VoIP numbers, so a virtual number does not always work. Use a
virtual number only for a site that accepts it, or when the user wants a number
that is not their own. Never use public "free SMS" websites: anyone can read
their codes.

## Add a source (one time)

```bash
akdbx sms-add-source iphone --kind shortcut
```

The receipt has a `private_url` setup page (one hour). Send it to the user
privately (`send_to_user`); they open it on the iPhone and follow its steps.
The page shows the webhook URL (tap to copy) and how to create the automation
in the Shortcuts app: a new shortcut whose trigger is **Automation > Message**
(When I receive a message where Message contains `code`), Confirm Before Run
off, then **Get Contents of URL** with Method POST and a JSON body `text` = the
message (Content), `from` = the message (Sender). Older iOS versions use the
**Automation** tab and **Run Immediately** instead. The user must do this step
on the phone; you cannot.

For a virtual number, type the webhook URL straight into the provider's
console field instead, so the URL never reaches your output:

```bash
akdbx pin-code-target --page-id PAGE --frame-id FRAME --top-url-file TOP \
  --frame-url-file TOP --selector '#sms-url' --field webhook-url --browser-slot slotN
akdbx sms-add-source twilio-us --kind twilio --target FRESH_PIN
```

In the Twilio Console the field is **Phone Numbers > Active numbers > (number)
> Messaging Configuration > A message comes in** (Webhook, HTTP POST). Save the
configuration and check that Twilio shows it saved. If the fill does not
finish, the receipt has a `private_url` fallback page.

`akdbx sms-sources` lists sources (never tokens). `sms-add-source NAME --kind
KIND --replace` issues a new URL (the old one stops working at once);
`sms-remove-source NAME` removes it. Replace a source if its URL may have leaked.

## Complete a phone challenge

1. Note the time, then let the site send the text (the user's standing
   authorization for sign-in codes covers this; do not resend more than
   needed).
2. Wait for it. This is an event wait on the broker's inbox, not polling:

   ```bash
   akdbx sms-wait --recent 120 --timeout 120
   ```

   Each row has `id`, `source`, `sender`, `preview` (digits shown as `•`),
   `code_length`, `received_at` and `age_seconds`. Pick the newest row whose
   sender and preview match this site and this attempt. If none match, the
   text has not arrived or was not forwarded; do not guess.
3. Focus the code field, pin it and fill once:

   ```bash
   akdbx pin-code-target --page-id PAGE --frame-id FRAME --top-url-file TOP \
     --frame-url-file TOP --selector '#code' --browser-slot slotN
   akdbx fill-sms-code MESSAGE_ID --target FRESH_PIN
   ```

   The DOM pin accepts one focused, visible, enabled `text`, `tel`, `number`
   or `password` input on an exact HTTPS page. For six one-digit boxes, use
   X11 keyboard delivery instead: `pin-target --pid ... --window ...`, then
   `fill-sms-code MESSAGE_ID --target X11_PIN --target-url VERIFIED_URL`.
4. Check the site's result (signed-in page, next step), not the field.

Each code is filled once. A fill that never started (expired or refused pin)
puts the text back, so pin again and retry. After an uncertain fill, do not
retry automatically; check the page. Texts expire after 10 minutes. If the
site rejects the code, request one new text; stop after two rejected fresh codes.

## Rules

- Never print, log, screenshot or save a code, webhook URL or setup link.
  Never paste a webhook URL yourself.
- The webhook token in the URL is the only credential. akdbx stores only its
  SHA-256 hash, in a private file (`--sms-sources`, default beside
  `--notification-state` or in the per-user state folder).
- The broker keeps only texts with exactly one verification code, in memory.
  It drops all other texts at once and never stores message bodies.
- Inbound texts need an HTTPS origin that the phone or provider can reach:
  the akdbx relay (or another public origin). Tailscale-only origins work
  only for a phone on the tailnet.
- After a broker restart, codes are gone, but sources keep working.
