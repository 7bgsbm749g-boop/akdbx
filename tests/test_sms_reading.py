"""The SMS reader: code choice and preview from one allow-list reading of the text.

Odd characters are written with ``chr()`` so that this source holds no invisible character.
"""
import itertools
import json
import random
import string
import unicodedata

import pytest

from akdbx import sms

NBSP, NNBSP, ZWSP, SHY, RLO, LRM, BOM = (chr(c) for c in (0xA0, 0x202F, 0x200B, 0xAD, 0x202E, 0x200E, 0xFEFF))
IDEOGRAPHIC_SPACE, UNIT_SEPARATOR, VERTICAL_TAB, GRIN, KEYCAP = chr(0x3000), chr(0x1F), chr(0x0B), chr(0x1F600), chr(0xFE0F) + chr(0x20E3)
TAB, LOCK, KEY = chr(0x09), chr(0x1F512), chr(0x1F511)
ARABIC_482913 = ''.join(chr(0x660 + int(d)) for d in '482913')
FULLWIDTH_482913 = ''.join(chr(0xFF10 + int(d)) for d in '482913')

# Code choice -----------------------------------------------------------------

# The formats the brief names, and other real-world shapes: (text, its code).
COMMON = [
    ('G-482913 is your Google verification code.', '482913'),
    ('Your Twilio verification code is: 771204', '771204'),
    ('Your code is 123 456.', '123456'),
    ('Use 4821 to sign in to Example.', '4821'),
    ('Your Example login code: 5512-9983', '55129983'),
    ('Verification code 991122. Not you? Call +447700900123.', '991122'),
    ('Your code is 482913. (c) 2026 Example Ltd', '482913'),
    ('Ihr Bestätigungscode lautet 664422', '664422'),
    ('Tu código de verificación es 908172', '908172'),
    # A link and a code.
    ('Verify at https://x.test/v/123456 with code 778899', '778899'),
    ('Verify at example.test/v/123456 with code 778899', '778899'),
    ('Your Example code is 482913. Or sign in: https://example.test/l?t=a1B2c3D4e5&u=77', '482913'),
    # Bank 3-D Secure texts with a card ending and an amount.
    ('Your OTP for card ending 4321 is 482913', '482913'),
    ('Card ending 4321: OTP is 482913.', '482913'),
    ('Your verification code for account ending 1234 is 567890.', '567890'),
    ('Confirm transfer of 2500 EUR to account 7788 with code 482913', '482913'),
    ('Your code is 2048 for card ending 7654.', '2048'),
    ('482913 is your One Time Passcode (OTP) for payment of GBP 12.34 at EXAMPLE with card ending 1234. '
     'Never share it.', '482913'),
    ('Example Bank: your one-time passcode is 123456 to verify a payment of £45.99 to Shop with card ending 1234.',
     '123456'),
    ('Use code 123456 to approve the payment of 45,99 EUR at Example with card **** 1234.', '123456'),
    ('OTP 482913 for txn of INR 2,500.00 at EXAMPLE on card XX4321. Valid till 10:35. Do not share OTP.', '482913'),
    ('Your OTP for txn of INR 2500 on card ending 4321 is 482913. Valid for 10 mins.', '482913'),
    ('Ihre TAN für die Zahlung 45,99 EUR mit Karte 1234 lautet: 482913. Ihr Bestätigungscode.', '482913'),
    ('Example Bank OTP: 482913. Amount £1250 to J SMITH, account ending 7788. Never share this code.', '482913'),
    ('Your 3-D Secure code is 482913 for EUR 2500 at Example, card 1234', '482913'),
    # Other common shapes.
    ('482913 is your Example verification code. Do not share it.', '482913'),
    ('[Example] 482913 is your verification code, valid for 5 minutes.', '482913'),
    ('Example: Your security code is 482913. It expires in 10 minutes. Please do not reply.', '482913'),
    ('Your Example verification code is: 123-456. Do not share this code with anyone.', '123456'),
    ('<#> Your Example code is 482913 FA+9qCX9VSu', '482913'),
    ('Your Example code: 4821\nDo not share this code\n4sgLq1p5sV6', '4821'),
    ('482913 is your Example authentication code.\n\n@example.test #482913', '482913'),
    ('Your code is:\n\n482913\n\nIt expires in 10 minutes.', '482913'),
    ('Example code 12345', '12345'),
    ('Use verification code 482913 for Example authentication.', '482913'),
    ('Code:482913', '482913'),
    ('OTP482913', '482913'),
    ('Your OTP is 482913.Do not share it with anyone.', '482913'),
    ('PIN 2048', '2048'),
    ('Sign in 2048 is your code', '2048'),
    ('Code valid until 2025-11-24: 482913', '482913'),
    ('Use these numbers 482913 as your verification code.', '482913'),
    ('Reference 123456. Your code is 123456.', '123456'),
    ('Votre code de vérification est 482913. Ne le partagez pas.', '482913'),
    (f'Votre code de vérification est{NNBSP}: 482913', '482913'),
    ('Il tuo codice di verifica è 482913', '482913'),
    ('Seu código de verificação é 482913', '482913'),
    ('Uw verificatiecode is 482913', '482913'),
    ('Dein Anmeldecode: 482913', '482913'),
    (f'Your code is {FULLWIDTH_482913}', '482913'),
    (f'Your code is {LRM}482913{LRM}', '482913'),
    (f'{BOM}482913 is your code', '482913'),
    (f'code{NBSP}482913', '482913'),
    (f'Your code is 482{NBSP}913 ref 4821', '482913'),
    (f'{GRIN}482913 is your Example code', '482913'),
    ('Your one-time password is 482913. Valid for 5 minutes. Call 0800 123 4567 if this was not you.', '482913'),
    ('Your code is 482913. Call 1234 5678 if this was not you.', '482913'),
    ('Example security code: 482913. Reply STOP to 22395 to opt out.', '482913'),
    ('Your code is 482913. Sent Nov 24, 2026.', '482913'),
    ('Your verification code is 2017. Request reference 456789.', '2017'),
    ('Your code is 482913\nRef: 1234', '482913'),
    # A service name with the code noun, and a number in a known place that is not a code's place.
    ('Your Uber code is 4829. Never share this code. Reply STOP ALL to 89203 to unsubscribe.', '4829'),
    ('482913 is your Instagram code. Reply STOP to 32665 to opt out.', '482913'),
    ('Code: 482913. Text HELP to 22395 for help.', '482913'),
    ('Your Lyft code is 482913. (c) 2026 Lyft', '482913'),
    ('Your Lyft code is 482913. © 2026 Lyft', '482913'),
    ('Your Example code is 482913. Expires at 1845.', '482913'),
    ('Ihre mTAN lautet 482913 für die Überweisung von 250,00 EUR', '482913'),
    ('Ihre TAN lautet 482913', '482913'),
    ('Votre code Example est 482913', '482913'),
    ('Tu código Example: 482913', '482913'),
    # What a text says about its code, in words and in small numbers, does not hide the code.
    ('Your Uber code is 4829. Sharing this code compromises your account.', '4829'),
    ('Your OTP is 482913. OTP is strictly confidential. Do not share it with anyone.', '482913'),
    ('Your OTP is 482913. This OTP is SECRET. DO NOT disclose it.', '482913'),
    ('YOUR OTP IS 482913. DO NOT SHARE THIS OTP WITH ANYONE. OTP IS VALID FOR 10 MINS.', '482913'),
    ('Ihr Bestätigungscode lautet 664422. Der Code ist 10 Minuten gültig.', '664422'),
    ('Deze code is 10 minuten geldig: 482913', '482913'),
    ('Your code is 482913. This code is valid for 10 minutes. Enter 1 to confirm.', '482913'),
    ('Your Example code is 482913. The code is case sensitive.', '482913'),
    ('Your PIN is 4821. PIN is valid for one login only.', '4821'),
    ('Your code is 482913. Your password was changed on 12 May.', '482913'),
    ('Tu código es 482913. Úsalo tan pronto como puedas.', '482913'),
    ('This is Example. Your code is 482913', '482913'),
    ('Use Example to sign in. Your code is 482913', '482913'),
    ('The following number is your code: 482913', '482913'),
    # The app hash of the SMS Retriever format, and a signature after a line that is only a label.
    ('123456 is your Facebook code H29Q+Fsn4Sr', '123456'),
    ('<#> 123456 is your Example code AbCdEfGhIjk', '123456'),
    ('482913 is your Example verification code AbCdEfGhIjk', '482913'),
    ('Your Example code is 482913.\nEnter this code\nExample', '482913'),
    ('Your Uber code is 4829.\nUber verification code\nUber Technologies', '4829'),
    ('482913 is your Bank of Example verification code. Ref 1234', '482913'),
    ('TAN:482913', '482913'),
    # More forms of a strict label.
    ('Your code is as follows: 482913. Ref 1234', '482913'),
    ('Enter the code below: 48613. Ref 1234', '48613'),
    ('Your verification code\n482913\nRef 1234', '482913'),
    ('Your code is in this message: 482913. Ref 1234', '482913'),
    ('The code you requested is 482913. Ref 1234', '482913'),
    ('Your OTP HDFC 482913', '482913'),
    ('OTP SBI: 482913. Do NOT share.', '482913'),
    ('Votre code est prêt : 482913', '482913'),
    ('Dein Code ist da: 482913', '482913'),
    ('Enter the code or tap here: https://example.test/a1b2. Your code is 482913', '482913'),
    ('482913 - your Example verification code. Ref 1234', '482913'),
    ('Example: your code is 482913', '482913'),
    ('EXAMPLE - your verification code\n482913', '482913'),
    ('Note: your code is 482913. Do not share it.', '482913'),
    ('Your code is valid for 10 minutes: 482913', '482913'),
    ('YOUR OTP IS VALID FOR 10 MINS. OTP 482913. DO NOT SHARE', '482913'),
]

# Texts from the five review rounds, and variants on the same themes: line
# breaks, semicolons, linking verbs, brands, masks, repeated codes,
# currencies, years, ZIP and postal codes, device, request and order numbers.
# (text, the code the text really holds, what the broker gives: that code or None.)
REVIEW = [
    ('Your OTP for card ending 4321 is 482913', '482913', '482913'),                 # rounds 0 and 1
    ('Your code is 2048 for card ending 7654.', '2048', '2048'),
    ('Confirm transfer of 2500 EUR to account 7788 with code 482913', '482913', '482913'),
    ('PIN 2048', '2048', '2048'),                                                     # round 2
    ('Your code for 123 456 EUR is 482913.', '482913', '482913'),
    ('Reference 123456. Your code is 123456.', '123456', '123456'),
    ('Use these numbers 482913 as your verification code.', '482913', '482913'),
    ('Use 482913 to approve the payment to Mastercard 1234. Verification code required.', '482913', '482913'),  # 3
    ('OTP for card VisaXXXX1234 is 482913', '482913', '482913'),
    ('Type 482913 to continue. Secure authentication since 2025.', '482913', '482913'),
    ('482913\nYour request ID is 7950. Your verification code is 482 913.', '482913', '482913'),
    ('123456 is for your current request. For device 7890 use code 123456.', '123456', '123456'),
    ('1234 is your request ID. Enter 482913 to verify.', '482913', '482913'),         # round 4
    ('Device 1234 is requesting access. Enter 482913 to confirm.', '482913', '482913'),
    ('Use 482913 to confirm delivery to ZIP code 90210.', '482913', None),
    ('Device 1234 is active\nVerify with 482913.', '482913', '482913'),               # round 5
    ('Device 1234 is active; verify with 482913.', '482913', '482913'),
    ('Your ZIP code is 90210. Use 482913 to verify.', '482913', None),
    ('Your postal code is 90210; your code is 482913', '482913', None),
    ('postal code is 90210\nVerification code 482913', '482913', None),
    # Variants.
    ('Your ZIP code is 90210. Type 482913 to continue.', '482913', None),
    ('Your ZIP code is 90210. Please key in 482913', '482913', None),
    ('ZIP code: 90210. Enter 482913', '482913', None),
    ('Your postcode is 90210, verification code 482913', '482913', '482913'),
    ('Area code 0207. OTP 482913', '482913', None),
    ('Device 1234 was added.\nYour code was 482913', '482913', '482913'),
    ('Device 1234 is\nyour new device. Code 482913', '482913', '482913'),
    ('Device 1234 is active. 482913', '482913', None),
    ('1234 is the last four of your card; 482913 is your code', '482913', '482913'),
    ('Request 7950 is pending - code 482913', '482913', None),
    ('Order 12345678 needs confirmation: 482913 is your code', '482913', '482913'),
    ('Card Mastercard 1234, Visa 5678: code 482913', '482913', None),
    ('Mastercard ****1234 OTP 482913', '482913', '482913'),
    ('Acct XXXX1234: your OTP is 482913', '482913', '482913'),
    ('Since 2025 we protect you. Your code is 482913', '482913', '482913'),
    ('In 2025 sign in with code 482913', '482913', '482913'),
    ('May 2025: your Example code is 482913', '482913', None),
    ('Year 2026 login code 482913', '482913', '482913'),
    ('Your code is 2026. (c) 2025 Example', '2026', '2026'),
    ('Pay 123 456 EUR? Code 482913', '482913', '482913'),
    ('Amount 2500 EUR. Use code 482913 to approve.', '482913', '482913'),
    ('Rs 2500 debited. OTP is 482913', '482913', '482913'),
    ('482913 is your code. 482913 was requested by device 7950.', '482913', '482913'),
    ('Ref 482913. Device 7950. Your code is 482913.', '482913', '482913'),
    ('Use code 4321 at checkout. Verify with 482913.', '482913', None),
    ('Use code 4321 at checkout.OTP 482913', '482913', None),
    ('Enter 4321 to opt out.Use 482913 to verify', '482913', None),
    ('Your booking code is 483920. Your verification code is 771204.', '771204', None),
    ('Your PIN is 4321. Enter 482913 to continue.', '482913', None),
    ('Promo code 2024: enter 482913 to verify', '482913', None),
    ('Error code 4012. Use 482913 to sign in.', '482913', None),
    ('Your code is 482913. Login attempt from device 1234.', '482913', '482913'),
    ('Your old code 123456 expired. Your new code is 482913.', '482913', None),
    ('Do not share your code 482913 with 0800 callers', '482913', '482913'),
    ('Your security code is 4321 - 482913', '482913', None),
    ('Your code is 482913\n1234', '482913', None),
    ('Card 4321. Ltd.G-482913 is your code', '482913', None),
    ('Your code is:\n1234 Main Street\n482913', '482913', None),
]

# No verification code the broker can type, or no single one: (text, reason).
NOTHING = [
    ('See you at 1830 tomorrow', 'no-code-word'),
    ('Your parcel 12345678 arrives today', 'no-code-word'),
    ('code', 'no-code'),
    ('', 'empty'),
    (None, 'empty'),
    ('Your code is 12.50 GBP', 'no-code'),
    ('code ' + '1' * 3000, 'empty'),
    ('Your code is ready', 'no-code'),
    ('Sign in: https://x.test/c/482913', 'no-code'),
    ('Code 123456 or code 654321', 'several-codes'),
    ('Code 482913 or 771204', 'several-codes'),
    ('Code 482913, 771204', 'several-codes'),
    ('Use 4821 or 9934 to sign in', 'several-codes'),
    ('Your code is 4821 9934', 'several-codes'),                 # one code of 8 digits or two numbers
    ('Your code is 1234 567', 'several-codes'),
    ('Your code is AB12CD. Ref 4821', 'no-code'),                # the code is not a number
    ('Your code is HXKQWP. Order 483920', 'no-code'),            # a code in capital letters: never kept or shown
    ('Your verification code: HXKQ-WPZR (order 483920)', 'no-code'),
    ('Your code is 12 34 56. Ref 4821', 'no-code'),
    ('12 34 56 is your verification code. Ref 4821', 'no-code'),
    ('Your code is 123456789. Ref 4821', 'no-code'),
    ('Your code: 482913/771204', 'no-code'),
    (f'Code {ARABIC_482913} ref 4821', 'several-codes'),         # numerals the broker does not type
    (f'Your code is 4{KEYCAP}8{KEYCAP}2{KEYCAP}1{KEYCAP} ref 4821', 'several-codes'),
    (f'Your code is 482{ZWSP}913', 'no-code'),                   # an invisible character inside the number
    (f'Your code is {RLO}319284', 'no-code'),                    # shown reversed on a screen
]


# Round 6: (text, what the broker gives, words that the preview must not show).
ROUND6 = [
    # A code in letters under any label: before, after, on the next line, with a service name, in capitals.
    ('Your Lyft code is ABCD. Order 5555', None, ['ABCD']),
    ('YOUR CODE IS HXKQWP. ORDER 483920', None, ['HXKQWP']),
    ('Your verification code is hxkqwp. Order 483920', None, ['hxkqwp']),
    ('Your code is Kxqrpt. Order 12345', None, ['Kxqrpt']),
    ('HXKQWPZR is your Yahoo verification code. Msg 20481', None, ['HXKQWPZR']),
    ('Your verification code is:\nHXKQWP\nOrder 483920', None, ['HXKQWP']),
    ('Your temporary password is MapleRiver. Your user ID is 641892', None, ['MapleRiver']),
    ('Your Example code is HXKQWP. Reply STOP to 89203 to unsubscribe.', None, ['HXKQWP']),
    ('Code HXKQWP. Order 483920', None, ['HXKQWP']),
    ('Your code HXKQWP expires soon. Order 483920', None, ['HXKQWP']),
    ('Your code hxkqwp expires soon. Order 483920', None, ['hxkqwp']),
    ('Use HXKQWP to verify. Ref 482913', None, ['HXKQWP']),
    ('Enter hxkqwp to verify. Ref 482913', None, ['hxkqwp']),
    ('Your code is as follows: HXKQWP. Order 483920', None, ['HXKQWP']),
    ('Your Example verification code\nHXKQWP\nOrder 483920', None, ['HXKQWP']),
    ('hxkqwp is your Example code. Ref 4821', None, ['hxkqwp']),
    ('Ihr Code lautet HXKQWP. Bestellung 483920', None, ['HXKQWP']),
    ('Tu código es hxkqwp. Pedido 483920', None, ['hxkqwp']),
    ('Your verification code is tiger. Order 483920', None, ['tiger']),
    ('Your passphrase is correct horse battery staple. ID 641892', None, ['correct', 'horse', 'battery', 'staple']),
    ('Your password is the quick brown fox. ID 641892', None, ['quick', 'brown', 'fox']),
    ('You requested a code. It is HXKQWP. Order 483920', None, ['HXKQWP']),
    ('Use 4321 to open the locker. Your verification code is HXKQWP', None, ['HXKQWP']),
    ('Your code is in this message: HXKQWP. Order 483920', None, ['HXKQWP']),
    ('The code you requested is HXKQWP. Order 483920', None, ['HXKQWP']),
    ('Your code will be hxkqwp. Order 483920', None, ['hxkqwp']),
    ('Your code is https://example.test/c/SyntheticToken. Order 483920', None, ['Synthetic']),
    ('Your verification code: example.test/c/482913. Order 483920', None, []),
    ('Verification: HXKQWP. Order 483920', None, ['HXKQWP']),
    ('HXKQWP - your Example verification code. Order 483920', None, ['HXKQWP']),
    ('hxkqwp: your code. Order 483920', None, ['hxkqwp']),
    ('You requested a code. It is AB12CD. Order 483920', None, ['AB12CD']),
    ('Your OTP is 482913. Your passphrase is correct horse battery staple', '482913', ['correct', 'horse', 'staple']),
    # A labelled code that is not a number the broker types, under any label or an order.
    ('Your Example code is AB12CD. Ref 20481', None, ['AB12CD']),
    ('Your Steam code is K7XQ2P. Ref 55551', None, ['K7XQ2P']),
    ('Your Example PIN is 123. Order 20481', None, []),
    ('Use AB12CD to verify. Ref 482913', None, ['AB12CD']),
    ('Your code is ABCD-482913', None, ['ABCD']),
    ('Your code is 48-29-13. Ref 20481', None, []),
    ('Your code is 482.913. Ref 20481', None, []),
    ('Your OTP: 12 34 56. Ref 20481', None, []),
    ('Use 12 34 56 to verify. Ref 20481', None, []),
    # A link cut by a pictograph, a tab or a line break.
    ('OTP 482913 //' + LOCK + '/' + KEY + 'SyntheticToken', '482913', ['Synthetic', 'Token']),
    ('Verification code: 482913. Or sign in at //example.test/' + TAB + 'SyntheticToken', '482913', ['Synthetic']),
    ('Verification code: 482913. Or sign in at //example.test/\nSyntheticToken', '482913', ['Synthetic']),
    ('Code 482913 https://example.test/t/\nSynthetic\nToken', '482913', ['Synthetic', 'Token']),
    # "Your code for ... is N" does not reach into a new clause.
    ('Your code for this transaction expires in five minutes and your reference is 1234. Please key in 482913.',
     None, []),
    ('Your verification code for this delivery is shown below and your ZIP is 90210. Enter the code below: 48613.',
     None, []),
    ('Your code for today and your ZIP is 90210. Enter 482913', None, []),
    # A line break is layout: "postal" still modifies "code".
    ('Your postal\ncode is 90210. Please key in 482913.', None, []),
    ('Your postal\ncode: 90210. Use 482913 to verify', None, []),
    # A number in a known place is not a competitor, but it is not a code either.
    ('Example 482913. Reply STOP to 89203', None, []),
]


# Texts in the shapes that services send, with what often stands around the code: (text, its code).
REAL_WORLD = [
    ("Your Apple ID Code is: 482913. Don't share it with anyone.", '482913'),
    ('Use OTP 482913 for transaction of INR 2,500.00 at AMAZON PAY. Valid for 10 mins. Do not share with anyone.', '482913'),
    ('Dear Customer, 482913 is the OTP for your transaction of Rs.2500.00 at EXAMPLE on card ending 4321. OTP is valid for 10 minutes. Do not share it.', '482913'),
    ('482913 is your Example verification code. This code will expire in 10 minutes. Do not share it with anyone, including Example staff.', '482913'),
    ('Example: Use code 482913 to log in. We will never ask you for this code. If you did not request it, reply STOP.', '482913'),
    ('Your Example code is 482913. It is valid for 5 minutes. @example.test #482913', '482913'),
    ('Microsoft access code: 4821', '4821'),
    ('Use 482913 as Microsoft account security code. Go passwordless with Microsoft Authenticator https://example.test/ms', '482913'),
    ("Your WhatsApp code: 482-913\n\nYou can also tap on this link to verify your phone: v.example.test/482913\n\nDon't share this code with others", '482913'),
    ("<#> Your Example code is 482913\nDon't share this code with anyone\nFA+9qCX9VSu", '482913'),
    ('Telegram code: 48291\n\nYou can also tap on this link to log in:\nhttps://t.example/login/48291\n\nO2P2z+/jBpJ', '48291'),
    ('Your Signal verification code: 482-913\n\ndoDiFGKPO1r', '482913'),
    ('[Example] Verification code: 482913. Valid for 5 minutes. Do not share with others.', '482913'),
    ('Example verification code is 482913. Please do not share this code with anyone. Team Example', '482913'),
    ('OTP for login is 482913. Do not share this OTP with anyone. Bank never asks for OTP.', '482913'),
    ('Your one time password (OTP) for Example is 482913. Valid for 15 mins. Do not disclose OTP to anyone.', '482913'),
    ('Your OTP HDFC 482913', '482913'),
    ('OTP SBI: 482913. Do NOT share.', '482913'),
    ('Hi! Your Example code is 482913. Please enter this code within the next 10 minutes to continue. Thank you!', '482913'),
    ("Your Example security code is 482913. If you didn't request this code, someone may be trying to access your account.", '482913'),
    ('Your Example code is 482913. Never share this code with anyone. Example will NEVER call to ask for it.', '482913'),
    ('Your UBER code is 4829. UBER will never ask for this code.', '4829'),
    ('482913 is the OTP for your HDFC Bank card. HDFC Bank never asks for OTP.', '482913'),
    ('Example: 482913 is your code. Reply HELP for help.', '482913'),
    ('Ihr Example Sicherheitscode lautet: 482913. Geben Sie diesen Code niemals an Dritte weiter.', '482913'),
    ('Dein Code ist da: 482913', '482913'),
    ('Votre code est prêt : 482913', '482913'),
    ('Votre code de sécurité Example est 482913. Ne le partagez jamais.', '482913'),
    ('Su código de seguridad de Example es 482913. No lo comparta con nadie.', '482913'),
    ('482913 es tu código de Example. No lo compartas.', '482913'),
    ('Il tuo codice di sicurezza Example è 482913. Non condividerlo con nessuno.', '482913'),
    ('Seu código de verificação é 482913. Não o compartilhe.', '482913'),
    ('Je verificatiecode is 482913. Deel deze code met niemand.', '482913'),
    ('Password: ******** Code: 482913', '482913'),
    ('Your verification code is 482913. Your booking reference is HXKQWP.', '482913'),
    ('Your verification code is 482913. Your order reference is AB12CD.', '482913'),
    ('Example: your login code is 482913. Your username is jsmith.', '482913'),
    ('Code: 482913\nValid: 10 min\nService: Example', '482913'),
    ("Your Example code is: 482913\n\nIf you didn't request this, ignore this message.", '482913'),
    ('Enter 482913 on the Example sign-in page to verify your identity. This code expires in 10 minutes.', '482913'),
    ('To verify your phone number, enter the code 482913 in the Example app.', '482913'),
    ('Your code to access Example is 482913', '482913'),
    ('Hello, your Example verification code is 482913. Have a nice day!', '482913'),
    ('Example Bank: NEVER share this code. Your one-time passcode is 482913 for the payment of £45.99 to SHOP LTD.', '482913'),
    ('482913 Use this code for Example verification', '482913'),
    ('482913 - Example verification code', '482913'),
    ('Example verification code: 482913', '482913'),
    ('Example code 482913', '482913'),
    ('Your code - 482913', '482913'),
    ('482913 (Example verification code)', '482913'),
    ('Example 482913 is your verification code', '482913'),
    ('Use the code 482913 to verify your Example account', '482913'),
    ('Your Example verification PIN is 4821', '4821'),
    ('Hi John, 482913 is your code for Example', '482913'),
    ('Uber code: 4829. Reply STOP ALL to 89203 to unsubscribe.', '4829'),
    ('Your Lyft code is 482913. If you did not request this code, contact LYFT immediately.', '482913'),
    ('Your Example code is 482913. This code grants access to your account, so keep it secret.', '482913'),
    ('Your Example code is 482913. Never share your code with SBI staff or anyone else.', '482913'),
    ('Your verification code is 482913. If you did not request this code, contact UBER immediately.', '482913'),
    ('Your Example PIN is 4821. Your code will expire on 24.11.26.', '4821'),
    ('Your Example code is 482913. Your code is valid for 1 use only.', '482913'),
    ('Your Uber code is 4829.\nEnter this code\nUBER', '4829'),
]


@pytest.mark.parametrize('text,code', REAL_WORLD)
def test_real_world_shapes_give_their_code(text, code):
    reading = sms.read(text)
    assert (reading.code, reading.result) == (code, 'code')
    assert '[code]' in reading.preview


# Round 7: (text, what the broker gives, words that the preview must not show).
ROUND7 = [
    # A prefix before "X is your code".
    ('<#> HXKQWP IS YOUR EXAMPLE CODE. REF 20481', None, ['HXKQWP']),
    ('[Example] Hxkqwp is your verification code. Ref 20481', None, ['Hxkqwp']),
    ('<#> kqmuhpxr is your Yahoo verification code. Ref 20481', None, ['kqmuhpxr']),
    ('EXAMPLE BANK HXKQWP IS YOUR OTP. REF 20481', None, ['HXKQWP']),
    ('DEAR CUSTOMER HXKQWP IS YOUR OTP FOR TXN 20481', None, ['HXKQWP']),
    # The value in apposition, or far from the noun.
    ('HXKQWP, your verification code. Ref 20481', None, ['HXKQWP']),
    ('HXKQWP (your Example verification code). Ref 20481', None, ['HXKQWP']),
    ('Use the following code to complete your registration on Example: HXKQWP. Ref 20481', None, ['HXKQWP']),
    # A service name of several words.
    ('HXKQWP is your Bank of Example verification code. Ref 20481', None, ['HXKQWP']),
    ('AB12CD is your Bank of Example verification code. Ref 20481', None, ['AB12CD']),
    ('K7 is your Bank of Example verification code. Ref 20481', None, []),
    # A colon in place of "is", after a phrase with a number.
    ('Your verification code for account ending 4839: HXKQWP', None, ['HXKQWP']),
    ('Your OTP for txn 483920: HXKQWP', None, ['HXKQWP']),
    ('Your code for order 483920: hxkqwp', None, ['hxkqwp']),
    # A password: no word after "password" shows but a function word.
    ('Your code is 482913. Your password is secure blue tiger.', '482913', ['secure', 'blue', 'tiger']),
    ('Your code is 482913. Your password is private river stone.', '482913', ['private', 'river', 'stone']),
    ('Votre mot de passe temporaire est Soleil. Votre code de vérification est 482913', '482913', ['Soleil']),
    ('A sua palavra-passe é Soleil. O seu código de verificação é 482913', '482913', ['Soleil']),
    ('Your password was reset to MapleRiver. Your verification code is 482913', '482913', ['MapleRiver']),
    ('Your password was changed to sunshine. Your verification code is 482913', '482913', ['sunshine']),
    ('MapleRiver is your new password. Your verification code is 482913', '482913', ['MapleRiver']),
    # A label glued to its value.
    ('Your verification code:AB12CD, valid for 5 minutes. Order 20481', None, ['AB12CD']),
    ('PIN:AB12. Ref 20481 login', None, ['AB12']),
    ('Code:HXKQWP. Login ref 20481', None, ['HXKQWP']),
    ('code(AB12CD) order 48213 login', None, ['AB12CD']),
    ('Verification code【AB12CD】Order 20481', None, ['AB12CD']),
    # Words or a note between the label and the value.
    ('Your code is now AB12CD. Ref 20481', None, ['AB12CD']),
    ('Login code for Example\nAB12CD\nOrder 20481', None, ['AB12CD']),
    ('Your code (valid 10 min) is HXKQWP. Order 483920', None, ['HXKQWP']),
    ('Your code, valid for 10 minutes, is HXKQWP. Order 483920', None, ['HXKQWP']),
    ('Your code (expires in 10 minutes): hxkqwp. Order 483920', None, ['hxkqwp']),
    ('Your code (valid 10 min): AB12CD. Ref 483920', None, ['AB12CD']),
    ('Your verification code - valid 10 min - HXKQWP. Order 483920', None, ['HXKQWP']),
    # A code in digit names.
    ('Your Lyft code is FOUR TWO ONE SIX. Order 483920', None, ['FOUR', 'TWO', 'ONE', 'SIX']),
    ('Your code: four eight two nine one three. Order 483920', None, ['four', 'eight', 'nine', 'three']),
    # A link next to a sign or a line break.
    ('Your code is 482913. Sign in at https://example.test/t/©SyntheticToken', '482913', ['Synthetic']),
    ('Code 482913 //example.test/\nSynthetic' + TAB + 'Token', '482913', ['Synthetic', 'Token']),
    # A label does not reach into a new clause.
    ('Your code expired and your order is: 90210. Please key in 482913.', None, []),
    ('Your code expires at noon reference 1234. Please key in 482913.', None, []),
    ('Your code for this transaction expires shortly (reference is 1234). Please key in 482913.', None, []),
    ('Your code for this transaction expires soon reference is 1234. Please key in 482913.', None, []),
    # A code noun with a modifier: before it across layout, or after it ("código de cliente").
    ('Your postal,\ncode is 90210. Please key in 482913.', None, []),
    ('Postal:\nCode 90210. Please key in 482913.', None, []),
    ('Su código de cliente es 483920. Por favor teclee 771204.', None, []),
    ('Tu código de área es 0212. Por favor teclee 482913', None, []),
    ('Votre code de réduction est 2024. Veuillez taper 482913', None, []),
    ('Il tuo codice di prenotazione è 483920. Mostra 7712 al corriere', None, []),
    ('Seu código de cliente é 483920. Por favor digite depois 771204', None, []),
    # A number with its own label does not excuse a code in letters that another label gives directly.
    ('Your PIN is 4821. Your verification code is HXKQWP.', None, ['HXKQWP']),
    ('Your PIN is 4821. HXKQWP is your verification code.', None, ['HXKQWP']),
    ('Your PIN is 4821 and your verification code is HXKQWP.', None, ['HXKQWP']),
    ('Enter 20481 to track your parcel. Your code is hxkqwp', None, ['hxkqwp']),
    ('HXKQWP: your code\nYour PIN is 4821', None, ['HXKQWP']),
    # A sentence names a code, gives no number for it and holds a word written as a value: a number whose own
    # label is not strict ("Your PIN is", "Your ZIP code is") is not given.
    ('Use the HXKQWP code to sign in. Your PIN is 4821', None, ['HXKQWP']),
    ('Your code is now HXKQWP. Your PIN is 4821', None, ['HXKQWP']),
    ('Your code (valid 10 min) is AB12CD. Your ZIP code is 90210', None, ['AB12CD']),
    ('Code\nHXKQWP\nYour order code is 483920', None, ['HXKQWP']),
    # The same word in a sentence that names no code is hidden; the number with its own label is given.
    ('Please type in HXKQWP. Your PIN is 4821', '4821', ['HXKQWP']),
    # A value written like a name of the code, or like a thing, is no name and no ordinary word.
    ('Your HXKQWP code expires soon. Your PIN is 4821', None, ['HXKQWP']),
    ('Your HXKQWP verification code expires in 5 minutes. Ref 20481', None, ['HXKQWP']),
    ('HXKQWP-Code. Ref 20481', None, ['HXKQWP']),
    ('HXKQWP will expire soon. Ref 20481 login', None, ['HXKQWP']),
    ('Your code is ACCESS. Ref 20481', None, []),
    ('Your code is account. Your PIN is 4821', None, []),
]


@pytest.mark.parametrize('text,given,unseen', ROUND7)
def test_round_seven_an_unknown_word_is_never_shown_and_never_passed_over(text, given, unseen):
    reading = sms.read(text)
    assert reading.code == given
    assert not [word for word in unseen if word in reading.preview]


# Wherever a text puts a code that is not typed digits, a number without a label of its own is not given.
PLACES = [
    '<#> {V} IS YOUR EXAMPLE CODE', '[Example] {V} is your verification code', 'EXAMPLE BANK {V} IS YOUR OTP',
    'Dear customer {V} is your OTP', '{V}, your verification code', '{V} (your Example verification code)',
    'Use the following code to complete your registration on Example: {V}',
    '{V} is your Bank of Example verification code', 'Your verification code for account ending in May: {V}',
    'Your code is now {V}', 'Login code for Example\n{V}', 'Your code (valid 10 min) is {V}',
    'Your code, valid for 10 minutes, is {V}', 'Your code (expires in 10 minutes): {V}',
    'Your verification code - valid 10 min - {V}', 'Your verification code:{V}', 'PIN:{V}', 'code({V})',
    'Verification code【{V}】', 'Your code will arrive as {V}', 'The code we sent you reads {V}',
    'Here you go: {V} (verification code)', 'Code\n{V}', '{V}\nis your code', 'Your code today: {V}',
    'Example code {V}', 'We texted you the code {V} a moment ago', 'Verification code, as requested, {V}',
    'Kindly note your one-time code {V}', 'Type {V} when the app asks for the code',
]
PLACE_VALUES = ['HXKQWP', 'hxkqwp', 'Kxqrpt', 'MapleRiver', 'AB12CD', 'K7XQ2P', 'tiger', 'FOUR TWO ONE SIX',
                'vier acht zwei neun']
UNLABELLED = ['Order 483920', 'Ref 20481', 'Msg 20481', 'Your user ID is 641892', 'Call 55512', 'Ticket #55551',
              'Parcel 5512 7788', 'Txn 483920 on 24 Nov']


def place_texts():
    for place, value, other in itertools.product(PLACES, PLACE_VALUES, UNLABELLED):
        for separator in ('. ', '\n'):
            yield place.format(V=value) + separator + other, value
            yield other + separator + place.format(V=value), value


def test_generated_a_code_in_any_place_stops_a_number_without_a_label():
    count = 0
    for text, value in place_texts():
        reading = sms.read(text)
        assert reading.code is None, text
        assert not [word for word in value.split() if word in reading.preview], (text, reading.preview)
        count += 1
    assert count == 4 * len(PLACES) * len(PLACE_VALUES) * len(UNLABELLED)


# The same, when the other number has a label of its own. The code in letters never shows. And when that label
# is not strict, a value that is written as a value (capitals, digits, digit names) stops the number.
LOOSELY_LABELLED = ['Your PIN is 4821', 'Your order code is 483920', 'Your ZIP code is 90210', 'Your Example PIN: 4821']
STRICTLY_LABELLED = ['Enter 20481 to track your parcel', 'Use 4821 to open the locker']
WRITTEN_VALUES = ['HXKQWP', 'MapleRiver', 'AB12CD', 'K7XQ2P', 'FOUR TWO ONE SIX', 'vier acht zwei neun']


def labelled_texts(others, values=PLACE_VALUES, places=PLACES):
    for place, value, other in itertools.product(places, values, others):
        for separator in ('. ', '\n'):
            yield place.format(V=value) + separator + other, value
            yield other + separator + place.format(V=value), value


def test_generated_a_code_in_any_place_never_shows_beside_a_labelled_number():
    for text, value in labelled_texts(LOOSELY_LABELLED + STRICTLY_LABELLED):
        reading = sms.read(text)
        assert reading.code is None or not [word for word in value.split() if word in reading.preview], text
    # "PIN:HXKQWP" beside "Your PIN is 4821" is left out: a PIN in letters is another secret, hidden and no more.
    for text, value in labelled_texts(LOOSELY_LABELLED, WRITTEN_VALUES, [p for p in PLACES if p != 'PIN:{V}']):
        assert sms.read(text).code is None, text


# The app hash of the SMS Retriever format, on the line of the code or on a line of its own.
HASHES = ['H29Q+Fsn4Sr', 'AbCdEfGhIjk', 'FA+9qCX9VSu', 'O2P2z+/jBpJ', '4sgLq1p5sV6']


def hash_texts():
    for statement, prefix, app_hash, separator in itertools.product(STATEMENTS, ('', '<#> '), HASHES, (' ', '\n')):
        text = statement.format(C='482913')
        yield prefix + text + separator + app_hash, app_hash
        yield prefix + text.rstrip('.') + separator + app_hash, app_hash  # "123456 is your Example code H29Q+Fsn4Sr"


def test_generated_an_app_hash_does_not_stop_the_code():
    for text, app_hash in hash_texts():
        reading = sms.read(text)
        assert reading.code == '482913', text
        assert app_hash not in reading.preview, reading.preview


@pytest.mark.parametrize('text,given,unseen', ROUND6)
def test_round_six_no_letter_code_is_shown_and_no_other_number_is_given(text, given, unseen):
    reading = sms.read(text)
    assert reading.code == given
    assert not [word for word in unseen if word in reading.preview]


# A label with a value that is not a code in digits, and another number in the text: never that number.
VALUE_LABELS = [
    'Your code is {V}', 'Your Example code is {V}', 'Your verification code is {V}', 'Your code: {V}', 'Code {V}',
    'OTP {V}', 'Your OTP is: {V}', '{V} is your Example verification code', '{V} is your code', 'Use {V} to verify',
    'Enter {V} to sign in', 'Verify with {V}', 'Your verification code is:\n{V}', 'Your Example verification code\n{V}',
    'Your code is as follows: {V}', 'Your temporary password is {V}', 'Your Example PIN is {V}', 'Ihr Code lautet {V}',
    'Tu código es {V}', 'Votre code est {V}', 'Passcode: {V}', 'Your one-time passcode is {V}', 'YOUR CODE IS {V}',
    'Your code {V} expires soon', 'Use code {V} to sign in',
]
VALUES = ['HXKQWP', 'hxkqwp', 'Kxqrpt', 'MapleRiver', 'ABCD', 'AB12CD', 'K7XQ2P', 'tiger', '123', '12 34 56',
          '48-29-13', '482.913', '123456789', 'XK-48', 'abc123']
OTHER_NUMBERS = ['Order 483920', 'Ref 20481', 'Msg 20481', 'Your user ID is 641892',
                 'Reply STOP to 89203 to unsubscribe', '(c) 2026 Example', 'Call 55512', 'ID 641892', 'Ticket #55551']


def value_texts():
    for label, value, other in itertools.product(VALUE_LABELS, VALUES, OTHER_NUMBERS):
        for separator in ('. ', '\n'):
            yield label.format(V=value) + separator + other, value
            yield other + separator + label.format(V=value), value


def test_generated_a_label_that_gives_no_typed_code_stops_every_other_number():
    count = 0
    for text, value in value_texts():
        reading = sms.read(text)
        assert reading.code is None, text
        letters = ''.join(ch for ch in value if ch.isalpha())
        assert not letters or letters not in reading.preview, (text, reading.preview)
        count += 1
    assert count == 4 * len(VALUE_LABELS) * len(VALUES) * len(OTHER_NUMBERS)


# The same in more written forms: label nouns x sentence forms x wrappings x values x another number.
LABEL_NOUNS = ['code', 'security code', 'login code', 'access code', 'sign-in code', 'confirmation code',
               'one-time code', 'OTP', 'OTP code', 'passcode', 'verification code', 'Example code',
               'Example verification code', 'verification PIN', 'one-time password', 'temporary password', 'password',
               'PIN', 'activation code', 'Bestätigungscode', 'Einmalpasswort', 'código de verificación',
               'code de vérification', 'codice di verifica', 'TAN', 'SMS-Code', 'auth code', 'secret code']
LABEL_FORMS = ['Your {N} is {V}', 'Your {N}: {V}', 'Your {N} is: {V}', '{N} {V}', '{N} - {V}', '{N} = {V}',
               'Your {N} was {V}', 'Your {N}\n{V}', 'Your {N} is\n{V}', 'Your {N}:\n{V}',
               'Your {N} is as follows: {V}', 'Your {N} is in this message: {V}', 'Your {N} is below:\n{V}',
               'Your {N} ({V})', '{V} is your {N}', '{V} - your {N}', '{V}: your {N}',
               'The {N} for your account is {V}', 'Use {N} {V} to sign in', 'Here is your {N}: {V}',
               'Your {N} for Example is {V}', 'YOUR {N} IS {V}', 'The {N} you requested is {V}',
               'Your {N} will be {V}']
WRAPPINGS = ['{V}', "'{V}'", '"{V}"', '({V})', '[{V}]', '<{V}>', '*{V}*', '{V}.', '{V},', '{V}!']
LABEL_VALUES = ['HXKQWP', 'hxkqwp', 'Kxqrpt', 'MapleRiver', 'ABCD', 'AB12CD', 'K7XQ2P', 'tiger', '123', '12 34 56',
                '48-29-13', '123456789', 'XK-48']
NUMBERS_NEAR = ['Order 483920', 'Your user ID is 641892', 'Reply STOP to 89203', 'Ref 20481']


def label_texts(nouns=LABEL_NOUNS, forms=LABEL_FORMS, wrappings=WRAPPINGS, values=LABEL_VALUES, near=NUMBERS_NEAR):
    for noun, form, wrapping, value, other in itertools.product(nouns, forms, wrappings, values, near):
        if ' ' in value and wrapping != '{V}' or wrapping[-1] in '.,!' and not form.endswith('{V}'):
            continue  # "12 34 56" is not wrapped; a full stop after the value only where the value ends the form
        label = form.format(N=noun, V=wrapping.format(V=value))
        yield label + '. ' + other, value
        yield other + '. ' + label, value


def unsafe(texts, reader=None):
    """How many texts give a number, and how many show the letters of the value."""
    picked = shown = 0
    for text, value in texts:
        reading = (reader or sms).read(text)
        letters = ''.join(ch for ch in value if ch.isalpha())
        picked += reading.code is not None
        shown += bool(letters) and letters in reading.preview
    return picked, shown


def test_generated_label_forms_never_give_a_number_or_show_the_value():
    # A fast slice here; evidence.py runs the whole product (more than half a million texts).
    assert unsafe(label_texts(nouns=LABEL_NOUNS[::4], wrappings=WRAPPINGS[::3], near=NUMBERS_NEAR[:2])) == (0, 0)
    assert unsafe(label_texts(forms=LABEL_FORMS[::4], values=LABEL_VALUES[::3], near=NUMBERS_NEAR[2:])) == (0, 0)


def test_reading_time_stays_small_for_a_hostile_text():
    import time
    started = time.perf_counter()
    for text in (('is ' * 680) + ' code', 'code code is ' * 150, '4821 9934 ' * 200, 'it is x ' * 250):
        sms.read(text[:sms.MAX_TEXT])
    assert time.perf_counter() - started < 5  # about 0.1 s; a quadratic reader needs minutes


# What real texts say after the code: a statement of the code, then a common second sentence.
STATEMENTS = [
    'Your Example verification code is {C}.', 'Your Example code is {C}.', '{C} is your Example verification code.',
    '{C} is your Example code.', 'Example: {C} is your security code.', 'Your verification code is {C}.',
    'Your code is {C}.', 'Use {C} to verify your Example account.', 'Example code: {C}.', 'Your OTP is {C}.',
    '{C} is your OTP for Example.', 'PIN {C}.', 'Your Example PIN is {C}.', 'G-{C} is your Google verification code.',
    'Your one-time password is {C}.', 'Ihr Example-Code lautet {C}.', 'Ihr Bestätigungscode lautet {C}.',
    'Dein Code: {C}.', 'Tu código de Example es {C}.', 'Su código de verificación es {C}.',
    'Votre code Example est {C}.', 'Votre code de vérification est {C}.', 'Il tuo codice Example è {C}.',
    'Seu código Example é {C}.', 'Uw Example-code is {C}.', 'Your Example security code is: {C}',
    '[Example] Your code is {C}', 'Example verification code: {C}', 'Your Example sign-in code is {C}.',
    'Hi Sam, your code is {C}.', 'Code {C}', 'Example OTP: {C}',
]
SECOND_SENTENCES = [
    'Do not share this code with anyone.', 'Never share this code.', "Don't share it.",
    'This code expires in 10 minutes.', 'This code will expire in 5 minutes.', 'It expires in 10 minutes.',
    'Valid for 10 minutes.', 'The code is valid for 10 minutes.', 'This code is valid for 5 min.',
    'Code valid for 10 mins.', "If you didn't request this code, you can safely ignore this message.",
    'If you did not request this, please ignore.', 'Enter this code to verify your phone number.',
    'Use this code to sign in.', 'Please enter it on the verification page.',
    'We will never call you to ask for this code.', 'Our employees will never ask for the code.',
    "Don't share this code with anyone; our employees will never ask for the code.", 'Do not disclose OTP to anyone.',
    'OTP is confidential.', 'Do not share your OTP or PIN with anyone.', 'Never share your code, even with staff.',
    'Never give this code to anyone, even if they claim to be from Example.',
    'For your security, do not share this code.', 'This code can only be used once.', 'This is a one-time code.',
    'Keep this code private.', 'Code expires in 15 minutes.',
    'Sharing this code could give someone access to your account.', 'Anyone with this code can access your account.',
    'Example will never ask you for this code.', 'Not you? Secure your account now.',
    "Didn't request this code? Call us.", 'Reply STOP to opt out.', 'Msg & data rates may apply.',
    'Thanks, The Example Team', 'This code is only valid for the next 10 minutes.', 'Type the code into the app.',
    'Enter the code in the box.', 'Please use this code within 10 minutes.',
    'The code remains valid for 30 minutes.', 'Treat this code like a password.', 'Do not forward this code.',
    'This code lets you sign in to Example.', 'This code was requested from a device near London.',
    'Use the code only on example.com.', 'This code is for one-time use only.', 'Your code is unique to you.',
    'Never share your password or code.', 'This OTP is valid for 10 mins and can be used only once.',
    'Please do not reply to this message.', 'Do not share this code. Example Support',
    'This code is confidential and should not be shared.', 'The code is time-sensitive.',
    'The code is single-use.', 'This passcode is valid for one login only.',
    'Der Code ist 10 Minuten gültig.', 'Dieser Code ist 5 Minuten lang gültig.',
    'Geben Sie diesen Code niemals weiter.', 'Bitte geben Sie den Code nicht an Dritte weiter.',
    'Teilen Sie diesen Code mit niemandem.', 'Der Code läuft in 10 Minuten ab.', 'Gib diesen Code niemals weiter.',
    'Dieser Code ist nur einmal gültig.', 'No compartas este código con nadie.',
    'Este código caduca en 10 minutos.', 'El código es válido por 10 minutos.', 'No lo compartas.',
    'Ne partagez ce code avec personne.', 'Ce code est valable 10 minutes.', 'Ce code expire dans 10 minutes.',
    'Ne le communiquez à personne.', 'Non condividere questo codice con nessuno.',
    'Il codice è valido per 10 minuti.', 'Il codice scade tra 10 minuti.',
    'Não compartilhe este código com ninguém.', 'O código é válido por 10 minutos.',
    'Este código expira em 10 minutos.', 'Deel deze code met niemand.', 'Deze code is 10 minuten geldig.',
    'De code verloopt over 10 minuten.',
]


def test_common_second_sentences_do_not_stop_the_code():
    for statement, sentence in itertools.product(STATEMENTS, SECOND_SENTENCES):
        for separator in (' ', '\n'):
            reading = sms.read(statement.format(C='482913') + separator + sentence)
            assert reading.code == '482913', (statement, sentence, reading)
            assert '[code]' in reading.preview and 'code' in reading.preview.replace('[code]', '').casefold() + 'code'


@pytest.mark.parametrize('text,code', COMMON)
def test_common_formats_give_their_code(text, code):
    reading = sms.read(text)
    assert (reading.code, reading.result) == (code, 'code')
    assert '[code]' in reading.preview and not set(code) & set(reading.preview)


@pytest.mark.parametrize('text,truth,given', REVIEW)
def test_review_texts_give_the_code_or_nothing_never_another_number(text, truth, given):
    assert given in (truth, None)
    assert sms.extract_code(text) == given


@pytest.mark.parametrize('text,reason', NOTHING)
def test_texts_without_one_code_are_dropped_with_a_reason(text, reason):
    assert sms.extract(text) == (None, reason)
    assert reason in sms.RESULTS


def test_one_candidate_needs_no_label_and_several_need_exactly_one_strict_label():
    assert sms.extract_code('Your Example code is 482913') == '482913'             # one number: no label needed
    assert sms.extract_code('Your Example code is 482913. Ref 1234') is None       # a name before "code": loose
    assert sms.extract_code('Your verification code is 482913. Ref 1234') == '482913'
    assert sms.extract_code('Your ZIP code is 90210. Ref 1234') is None            # "ZIP code" selects nothing
    assert sms.extract_code('Your postcode is 90210. Your code is 482913') == '482913'  # "postcode" is no code noun
    assert sms.extract_code('Your code is 482913. Your ZIP code is 90210') is None  # and it stops the other choice


# Generated texts: a decoy phrase and a code phrase in both orders, with every separator.
DECOYS = [
    'card ending {D}', 'Card ending in {D}', 'account ending {D}', 'acct {D}', 'Ref: {D}', 'Ref {D}', 'reference {D}',
    'order {D}', 'Order #{D}', 'booking {D}', 'invoice {D}', 'ticket {D}', 'ZIP code {D}', 'Your ZIP code is {D}',
    'postal code is {D}', 'postcode {D}', 'area code {D}', 'Device {D} is active', '{D} is your request ID',
    'Device {D} is requesting access', 'request ID is {D}', 'since {D}', '(c) {D} Example Ltd', '© {D}', '{D} EUR',
    'EUR {D}', 'amount {D}', 'transfer of {D} EUR', 'Mastercard {D}', 'Visa {D}', 'payment of {D} USD',
    'valid until {D}', 'in {D}', 'year {D}', 'May {D}', 'promo code {D}', 'error code {D}', 'sort code {D}',
    'country code {D}', 'booking code is {D}', 'tracking number {D}', 'PIN attempts {D}',
    'Your customer number is {D}', '{D} is your customer number', 'Store {D}', 'Flight {D}', 'Room {D}',
    'at {D} Main St', 'Reply STOP to {D}', 'Text HELP to {D}', 'Call {D}', 'extension {D}', 'ID: {D}', 'ID {D}',
    'No. {D}', '#{D}', 'Terminal {D}', 'session {D}', 'limit is {D}', 'balance is {D}', 'Your member ID is {D}',
    'Your PIN was changed on {D}', 'Sent to phone ending {D}', 'Mobile ending {D}', 'for {D} points',
    '{D} is your table number', 'Gate {D}', 'Txn {D}', 'txn of INR {D}', 'Rs {D}', 'Rs. {D}', 'USD {D}',
    'Your discount code is SAVE{D}', 'the QR code {D}', 'code word {D}', 'Bestellung {D}', 'Konto {D}',
    'PLZ {D}', 'tarjeta {D}', 'pedido {D}', 'Your password expires in {D} days', 'Version {D}', 'Build {D}',
    'the {D} to', 'your {D}', ': {D}', '- {D}', '{D}:', 'code area {D}', 'Enter {D} to opt out',
    'Use {D} to unsubscribe', 'Your PIN is {D}', '{D} is your booking code', 'Your old code {D} is no longer valid',
    'Your previous code was {D}', 'Your card PIN is {D}', 'door code {D}', 'Your pickup code is {D}',
    'Pickup code: {D}', 'Your voucher code: {D}', 'Coupon code {D}', 'Reference code {D}',
    'Your referral code is {D}', 'Your tracking code is {D}', 'Team code {D}', 'Your password is {D}',
    'Your customer code {D}', 'Sort code {D}',
]
# In these the other number carries a true, unmodified code label.
CODE_DECOYS = [
    'Use code {D} at checkout', 'Your security code is {D}', 'Your booking confirmation code is {D}',
    'Your access code for the gate is {D}', 'The code {D} has expired', 'Code {D} expired', 'temporary password {D}',
]
PHRASES = [
    'Your code is {C}', 'Your verification code is {C}', 'code: {C}', 'OTP {C}', '{C} is your verification code',
    '{C} is your Example code', 'Use code {C}', 'Your Example code is {C}', 'Use {C} to verify',
    'Enter {C} to continue', 'Type {C} to sign in', 'Verify with {C}', 'Your one-time password is {C}',
    'Passcode: {C}', 'Security code {C}', 'Ihr Code lautet {C}', 'Tu código es {C}', 'Sign in with {C}',
    'Your login code: {C}', 'Confirm with {C}', '{C} is your OTP', 'Authentication code {C}',
    'G-{C} is your Google verification code', 'Your code is:\n{C}', 'Your OTP for this is {C}', 'Verification: {C}',
    'Your Example PIN is {C}', 'Login {C}', 'Use {C}', 'Code {C}', 'Use {C} as your code',
]
# The verification code with no code word near it at all.
BARE_PHRASES = ['{C}', 'To continue type in {C} now', 'Please key in {C}', 'It is {C}', 'Here it is: {C}',
                'Example: {C}', '{C} (do not share)']
SEPARATORS = ['. ', '\n', '; ', ', ', ' - ', ': ', ' ', ' and ', ' | ', '.\n', ' (', '! ', '? ', '\n\n', ' / ', '.',
              ' — ']
NUMBERS = [('4321', '482913'), ('2025', '482913'), ('90210', '482913'), ('123456', '482913'), ('4321', '2048'),
           ('2025', '2048'), ('654321', '2048'), ('12345678', '482913'), ('4321', '55129983')]


def generated(decoys, phrases, separators=SEPARATORS, numbers=NUMBERS):
    for decoy, phrase, separator, (d, c) in itertools.product(decoys, phrases, separators, numbers):
        first, second = decoy.format(D=d), phrase.format(C=c)
        yield first + separator + second, c
        yield second + separator + first, c


def outcomes(texts, reader=None):
    code = wrong = 0
    for text, truth in texts:
        given = (reader or sms).extract_code(text)
        code += given == truth
        wrong += given not in (truth, None)
    return code, wrong


def test_generated_texts_never_give_a_number_that_is_not_the_code():
    # A fast slice here; evidence.py runs the whole product (more than 1.3 million texts).
    slice_ = dict(separators=SEPARATORS[:4], numbers=NUMBERS[::4])
    picked, wrong = outcomes(generated(DECOYS, PHRASES + BARE_PHRASES, **slice_))
    assert wrong == 0 and picked > 10_000
    # Another number that is itself called "the code": still no wrong pick while the real code has any label.
    picked, wrong = outcomes(generated(CODE_DECOYS, PHRASES, **slice_))
    assert wrong == 0


def test_the_known_limit_is_a_text_that_calls_another_number_the_code():
    """The one way to a wrong pick, kept here so that it stays known and narrow.

    The text must label another number with a real code noun, and give the
    verification code with no code word at all. The preview then shows the
    pick, so the agent can refuse it.
    """
    reading = sms.read('Use code 4321 at checkout. Please key in 482913')
    assert reading.code == '4321'
    assert reading.preview == 'Use code [code] at checkout. Please [hidden] in ••••••'


# Preview -----------------------------------------------------------------------

TOKEN = 'SyntheticToken'
LINKS = [
    'https://example.test/t/' + TOKEN, 'http://example.test/t/' + TOKEN, 'www.example.test/' + TOKEN,
    'example.test/t/' + TOKEN, 'example.test?token=' + TOKEN, 'example.test:8443/t/' + TOKEN,
    'example.xn--p1ai/t/' + TOKEN, '192.0.2.4/t/' + TOKEN, 'münchen.de/t/' + TOKEN, '[2001:db8::1]/t/' + TOKEN,
    '//example.test/t/' + TOKEN, '//x/' + TOKEN, 'x.y?' + TOKEN, 'x.y#' + TOKEN, TOKEN + '.example.test',
    'example.test/' + TOKEN + '.', '(example.test/' + TOKEN + ')', 'user:' + TOKEN + '@example.test',
    TOKEN + '@example.test', 'mailto:' + TOKEN + '@example.test', 'app://open?t=' + TOKEN, 'example://' + TOKEN,
    'intent:#' + TOKEN, '/t/' + TOKEN, '?t=' + TOKEN, '#' + TOKEN, '&' + TOKEN, 't=' + TOKEN,
    'example.test/'.translate({ord(c): ord(c) + 0xFEE0 for c in 'example.test/'}) + TOKEN,   # full-width letters
    'example' + chr(0x3002) + 'test/' + TOKEN, 'example.test\\' + TOKEN, 'example' + chr(0x2024) + 'test/' + TOKEN,
    'xn--mnchen-3ya.de/' + TOKEN, 'ex-ample.test/a/b/c?d=e&f=' + TOKEN + '#g', 'tel:' + TOKEN, TOKEN + ':8443',
    TOKEN + '_abc', 'Synthetic.Token', 'Synthetic/Token', TOKEN + '1', '1' + TOKEN, 'Synthetic=Token',
    # A link cut by a character that is no ordinary space: nothing after the cut shows.
    'example.test/t/Synthetic' + ZWSP + 'Token', 'example.test/t/Synthetic' + NBSP + 'Token',
    'example.test/t/Synthetic' + RLO + 'Token', 'example.test/t/Synthetic' + SHY + 'Token',
    'example.test/t/Synthetic' + GRIN + 'Token', 'example.test/t/Synthetic' + UNIT_SEPARATOR + 'Token',
    'example.test/t/Synthetic' + VERTICAL_TAB + 'Token', 'example.test/t/Synthetic' + IDEOGRAPHIC_SPACE + 'Token',
    '192.0.2.4/' + NBSP + TOKEN,
    # The parts of a cut link can each look plain: the decision is on the whole spaced word.
    '//' + LOCK + '/' + KEY + TOKEN, '//example.test/' + TAB + TOKEN, 'example.test/t/Synthetic' + TAB + 'Token',
    '//example.test/\n' + TOKEN, 'https://example.test/t/Synthetic\nToken', 'example.test?t=\n' + TOKEN,
    '/' + LOCK + TOKEN, TOKEN + KEY + '=', ':' + TAB + TOKEN + TAB + '/', '//\n' + TOKEN, 'x.y?\n' + TOKEN,
]


@pytest.mark.parametrize('link', LINKS)
def test_no_link_form_reaches_the_preview_or_the_sender(link):
    preview = sms.mask('OTP 482913 ' + link + ' end')
    assert preview.startswith('OTP [code] ') and preview.endswith(' end')
    assert sms.extract_code('OTP 482913 ' + link + ' end') == '482913'
    for shown in (preview, sms.clean_sender('Example ' + link, '482913')):
        assert 'ynthetic' not in shown and 'oken' not in shown and 'xample.t' not in shown


@pytest.mark.parametrize('text,preview', [
    ('G-482913 is your code. https://g.co/x/123 www.example.test/9 ' + RLO + 'end',
     '[code] is your code. [link] [link] end'),
    ('Code 482913, or sign in at example.test/t/' + TOKEN, 'Code [code], or sign in at [link]'),
    ('Your OTP for card ending 4321 is 482913', 'Your OTP for card ending •••• is [code]'),
    ('Your code is 123 456. Call +447700900123 by 2025-11-24, 18:30 (fee €12.50).',
     'Your code is [code]. Call +•••••••••••• by ••••-••-••, ••:•• (fee €••.••).'),
    # Words outside the vocabulary show only where a name stands: before the code noun, after "for", "at", "to".
    ('G-482913 is your Google verification code.', '[code] is your Google verification code.'),
    ('482913 is your Bank of Example verification code. Ref 1234',
     '[code] is your Bank of Example verification code. Ref ••••'),
    ('Use 4821 to sign in to Example.', 'Use [code] to sign in to Example.'),
    ('Example Bank: your one-time passcode is 123456 to verify a payment of £45.99 to Shop with card ending 1234.',
     'Example Bank: your one-time passcode is [code] to verify a payment of £••.•• to [hidden] with card ending ••••.'),
    ('Votre code Example est 482913', 'Votre code Example est [code]'),
    ('Your Uber code is 4829. Sharing this code compromises your account.',
     'Your Uber code is [code]. Sharing this code [hidden] your account.'),
    ('Your Example code is 482913. (c) 2026 Example Ltd', 'Your Example code is [code]. (c) •••• Example Ltd'),
    ('Your UBER code is 4829. UBER will never ask for this code. Contact UBER support.',
     'Your UBER code is [code]. UBER will never ask for this code. Contact UBER support.'),
    ('123456 is your Facebook code H29Q+Fsn4Sr', '[code] is your Facebook code [hidden]'),
    # After "password" only function words show.
    ('Your code is 482913. Your password is secure blue tiger.', 'Your code is [code]. Your password is [hidden]'),
    ('Use the HXKQWP code to sign in. Your PIN is 4821', 'Use the [hidden] code to sign in. Your PIN is ••••'),
    ('Code 482913 for card VisaXXXX1234, user a.b@example.test, valid 10min',
     'Code [code] for card [hidden] user [link] valid [hidden]'),               # a placeholder stands for the whole word
    ('Use 4821 or 9934 to sign in', 'Use •••• or •••• to sign in'),                  # no code chosen: bullets only
    (GRIN * 400 + ' code 482913', 'code [code]'),
    ('Your' + NBSP + 'code is 482913', 'Your code is [code]'),
    ('code' + NBSP + '482913', '[hidden] [code]'),                                    # glued to a number: not shown
    ('Go' + ZWSP + 'ogle code 482913', 'Google code [code]'),
])
def test_preview_shows_plain_words_bullets_and_the_place_of_the_code(text, preview):
    assert sms.mask(text) == preview


def test_a_long_text_keeps_the_chosen_code_in_view():
    preview = sms.mask('the ' * 120 + 'your code is 482913 ' + 'now ' * 60)
    assert len(preview) <= sms.MAX_PREVIEW and preview.startswith('…') and 'your code is [code] now' in preview
    assert sms.mask('word ' * 120 + 'your code is 482913 ' + 'tail ' * 60) == '[hidden] your code is [code] [hidden]'


OPEN, CLOSE, JOIN = (set('([{<"\'“‘«¿¡【（「『《〈'), set('.,;:!?)]}>"\'”’»。，！？：；、】）」』》〉'),
                     set("-‐'’&"))
GLUE = [chr(c) for c in range(0x21, 0x7F) if not chr(c).isalpha()] + [chr(c) for c in (
    0xA0, 0xAD, 0xB7, 0x200B, 0x200C, 0x200D, 0x2011, 0x2024, 0x2028, 0x2029, 0x202E, 0x202F, 0x2060, 0x2215, 0x3002,
    0x3000, 0xFEFF, 0xFF0E, 0xFF0F, 0xFF1A, 0xFF1F, 0x1F600, 0x0B, 0x0C, 0x1C, 0x1F, 0x85, 0x7F, 0x0301, 0x20E3,
    0x0660, 0x0966, 0x2460, 0xE000, 0xE0041, 0x2044, 0x00B2, 0x00BD, 0x09, 0x1F512)]
WORDS = ['Your', 'code', 'is', 'Example', 'verification', 'sign', 'in', 'at', 'OTP', 'Use', 'to', 'card', 'ending']


def may_show(raw):
    """The preview rule, stated a second time without the module.

    The spaced word is cut at tabs, odd spaces and pictographs. Every part must be letters with ordinary
    punctuation at its ends; a cut word must have no other kind of part at all.
    """
    parts, part = [], ''
    for ch in unicodedata.normalize('NFKC', raw):
        category = unicodedata.category(ch)
        if category[0] == 'Z' or category in {'So', 'Sk'} or ch in '\t\x0b\x0c\x1c\x1d\x1e\x1f\x85':
            parts.append(part)
            part = ''
        elif category[0] != 'C':
            part += ch
    parts = [part for part in parts + [part] if part]
    for part in parts:
        part = part.lstrip(''.join(OPEN)).rstrip(''.join(CLOSE))
        runs = ''.join('\0' if ch in JOIN else ch for ch in part).split('\0')
        if any(not run or unicodedata.category(run[0])[0] != 'L'
               or any(unicodedata.category(ch)[0] not in 'LM' for ch in run) for run in runs):
            return False
    return True


def fuzz_preview(rounds, seed=20261124):
    """A random secret glued to random characters. Returns how often it was shown; fails on any leak."""
    rng = random.Random(seed)
    shown = 0
    for _ in range(rounds):
        secret = ''.join(rng.choice(string.ascii_letters) for _ in range(rng.randint(9, 16)))
        left, right = (''.join(rng.choice(GLUE + list('abcDEF')) for _ in range(rng.randint(0, 6))) for _ in 'lr')
        words = [rng.choice(WORDS) for _ in range(rng.randint(0, 5))]
        words.insert(rng.randint(0, len(words)), left + secret + right)
        words.insert(rng.randint(0, len(words)), str(rng.randint(1000, 99999999)))
        text = ' '.join(words)
        reading = sms._read(text)  # the inner reader: a fault must fail the test, not be swallowed
        sender = sms.clean_sender(text, '0000')
        for output in (reading.preview, sender):
            assert not any(unicodedata.category(ch)[0] == 'N' for ch in output), (text, output)
            assert secret not in output or may_show(left + secret + right), (text, output)
        shown += secret in reading.preview
    return shown


def fuzz_any_text(rounds, seed=7):
    """Any text at all is read without a fault; a chosen code is 4 to 8 digits and its place is in the preview."""
    rng = random.Random(seed)
    pool = GLUE + list('abcXYZ 0123456789 \n\t') + ['code', ' is ', 'OTP', ' 482913 ', ' 4321 ', 'Use ', ' to ']
    for _ in range(rounds):
        text = ''.join(rng.choice(pool) for _ in range(rng.randint(1, 40)))
        if text.strip():
            reading = sms._read(text)
            assert reading.code is None or reading.code.isascii() and reading.code.isdigit() and 4 <= len(reading.code) <= 8
            assert not any(unicodedata.category(ch)[0] == 'N' for ch in reading.preview), (text, reading.preview)
            assert reading.code is None or '[code]' in reading.preview, (text, reading)
    return rounds


def test_fuzz_a_secret_glued_to_anything_but_letters_never_shows():
    assert 0 < fuzz_preview(20_000) < 20_000


def test_fuzz_any_text_is_read_without_a_fault():
    assert fuzz_any_text(20_000) == 20_000


def test_a_reader_fault_drops_the_text_and_shows_nothing(monkeypatch):
    monkeypatch.setattr(sms, '_words', lambda text: 1 / 0)
    assert sms.read('Your code is 482913') == sms.Reading(None, 'no-code', '')
    assert sms.clean_sender('Example') == ''


# Sender and inbox ----------------------------------------------------------------


@pytest.mark.parametrize('sender,shown', [
    ('Google', 'Google'), ('+15550100', '+15550100'), ('22395', '22395'), ('AX-EXMPLB', 'AX-EXMPLB'),
    ('Example Bank', 'Example Bank'), ('+1 (555) 010-0199', '+1 (555) 010-0199'),
    ('+15554829130', '+•••••••••••'),                                        # a number that holds the code
    ('Your code is 482913 example.test/t/' + TOKEN, 'Your code is •••••• [link]'),   # "from" set to the message
    ('Example 12345', 'Example •••••'), ('example.test', '[link]'), (None, ''), (482913, ''),
    # A longer sender is the message itself: it is shown as a preview is, so a code in letters stays hidden.
    ('Your Example code is HXKQWP', 'Your [hidden] code is [hidden]'),
    ('HXKQWP is your Example verification code', '[hidden] is your [hidden] verification code'),
])
def test_sender_is_a_number_or_a_short_name(sender, shown):
    assert sms.clean_sender(sender, '482913') == shown


def test_inbox_keeps_the_preview_of_the_one_reading_and_rows_fit_the_rpc_limit(tmp_path):
    inbox = sms.SmsInbox(tmp_path / 'sms.json')
    tokens = [inbox.add_source(f'source-{i}', 'webhook') for i in range(sms.MAX_SOURCES)]
    for i in range(sms.MAX_MESSAGES):
        assert inbox.receive(tokens[i % len(tokens)], GRIN * 64 + 'Example', GRIN * 400 + f' code 48291{i % 10}') == 'kept'
    rows = inbox.wait()
    assert len(rows) == sms.MAX_MESSAGES and all(row['preview'] == 'code [code]' for row in rows)
    assert len(json.dumps(dict(ok=True, messages=rows), separators=(',', ':')).encode()) < 64 * 1024
    inbox.messages.clear()
    assert inbox.receive(tokens[0], 'x' * 60 + ' 482913', 'Your OTP for card ending 4321 is 482913') == 'kept'
    [row] = inbox.wait()
    assert row['preview'] == 'Your OTP for card ending •••• is [code]' and row['code_length'] == 6
    assert not any(ch.isdigit() for ch in row['preview'] + row['sender'])
    assert inbox.take(row['id']).code == '482913'
    assert inbox.receive(tokens[0], 'Example', 'Your ZIP code is 90210. Use 482913 to verify.') == 'dropped'
    assert inbox.list_sources()[0]['last_result'] == 'several-codes' and inbox.wait() == []
