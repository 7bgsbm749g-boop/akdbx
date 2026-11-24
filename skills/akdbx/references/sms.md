# Phone verification texts (SMS) (0.39.0)

akdbx can receive the verification texts that sites send to a phone number and
fill the code straight into the challenge field. You see only a masked preview
(plain words only: no digits, no links), the sender and the code length. You
never see the code, the webhook token or the text itself.

Require broker 0.39.0 or newer and `status` field `sms_protocol: 1`.
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
The page shows the webhook URL (tap to copy) and the Shortcuts steps for the
iPhone's iOS version: it detects the version from the browser and offers the
other versions (iOS 27 and later, iOS 17 to 26, iOS 16 and earlier) in a list.
The automation is a **Message** trigger (Message contains `code`) that runs
without confirmation and calls **Get Contents of URL** with Method POST and a
JSON body: `text` = the message, `from` = its Sender (optional). The user must
do this step on the phone; you cannot.

The filter forwards only texts that contain the word `code`. A site whose text
says only `OTP`, `PIN` or `passcode` (common for banks) is not forwarded, and
`sms-wait` stays empty. Then ask the user to add a second automation with the
same steps and that word instead of `code` (iOS allows one word per
automation); the same webhook URL works for both.

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

A free Twilio trial is only for tests. It accepts texts only from its verified
phone numbers, never from site short codes, so it cannot take real
verification texts. A "Limited trial" (no card) has no Active numbers: its
webhook field is **Try out SMS > Receive an SMS > Custom**, and its trial
number can differ for each verified number. Add a verified number with
`fill-identity --field tel --format national --calling-code CC` (0.36.1+)
when the console has a country picker; a saved `0…` value without the
format becomes a wrong `+CC0…` number, and Twilio then drops that phone's
texts without a log entry.

`akdbx sms-sources` lists sources (never tokens), with `last_received` and
`last_result` (why the last text was kept or dropped: `code`, `no-code-word`,
`no-code`, `several-codes` or `empty`). `sms-add-source NAME --kind
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

   If the text can take longer, or the user must act first, register a
   one-shot webhook instead and end the turn:
   [SMS notifications](sms-notifications.md) (`subscribe-sms`).

   Each row has `id`, `source`, `sender`, `preview`, `code_length`,
   `received_at` and `age_seconds`. The preview shows only plain words.
   `[code]` stands in the place of the code that akdbx will fill. Each digit
   of any other number is `•`. `[link]` and `[hidden]` stand for links, for
   words that are not only letters, and for a word in the place of a code
   that akdbx does not know as an ordinary word.

   Pick the newest row whose sender and preview match this site and this
   attempt. Then make these two checks before you fill:
   - `[code]` stands in the place of the verification code, not in the place
     of a card number, an amount or a reference;
   - `code_length` is the number of digits that the page asks for.

   If a check fails, do not fill that row. If no row matches, the text has
   not arrived, was not forwarded, or was dropped; do not guess. `sms-sources`
   shows why the last text was dropped: `several-codes` (more than one
   possible code) or `no-code` (no code of 4 to 8 digits; this includes a
   code in letters, which akdbx cannot type: ask the user for that code).
3. Focus the code field, pin it and fill once:

   ```bash
   akdbx pin-code-target --page-id PAGE --frame-id FRAME --top-url-file TOP \
     --frame-url-file TOP --selector '#code' --browser-slot slotN
   akdbx fill-sms-code MESSAGE_ID --target FRESH_PIN
   ```

   The DOM pin accepts one focused, visible, enabled `text`, `tel`, `number`
   or `password` input on an exact HTTPS page. For six one-digit boxes, use
   X11 keyboard delivery instead: `pin-target --pid ... --window ...`, then
   `fill-sms-code MESSAGE_ID --target X11_PIN --target-url-file URL_FILE`
   (a mode-0600 file with the verified challenge URL; use `--target-url URL`
   only for a URL that holds no token).
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
  When two numbers can be the code, it does not choose: it drops the text.
  It also drops a text that gives its code in letters or in a form other
  than 4 to 8 digits, even when the text has another number.
  It drops all other texts at once and never stores message bodies.
- Inbound texts need an HTTPS origin that the phone or provider can reach:
  the akdbx relay (or another public origin). Tailscale-only origins work
  only for a phone on the tailnet.
- After a broker restart, codes are gone, but sources keep working.
