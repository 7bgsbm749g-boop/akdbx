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
    ('Request 7950 is pending - code 482913', '482913', '482913'),
    ('Order 12345678 needs confirmation: 482913 is your code', '482913', '482913'),
    ('Card Mastercard 1234, Visa 5678: code 482913', '482913', '482913'),
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
    slice_ = dict(separators=SEPARATORS[:8], numbers=NUMBERS[::4])
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
    assert reading.preview == 'Use code [code] at checkout. Please key in ••••••'


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
]


@pytest.mark.parametrize('link', LINKS)
def test_no_link_form_reaches_the_preview_or_the_sender(link):
    preview = sms.mask('OTP 482913 ' + link + ' end')
    assert preview.startswith('OTP [code] ') and preview.endswith(' end')
    for shown in (preview, sms.clean_sender('Example ' + link, '482913')):
        assert 'ynthetic' not in shown and 'oken' not in shown and 'xample.t' not in shown


@pytest.mark.parametrize('text,preview', [
    ('G-482913 is your code. https://g.co/x/123 www.example.test/9 ' + RLO + 'end',
     '[code] is your code. [link] [link] end'),
    ('Code 482913, or sign in at example.test/t/' + TOKEN, 'Code [code], or sign in at [link]'),
    ('Your OTP for card ending 4321 is 482913', 'Your OTP for card ending •••• is [code]'),
    ('Your code is 123 456. Call +447700900123 by 2025-11-24, 18:30 (fee €12.50).',
     'Your code is [code]. Call +•••••••••••• by ••••-••-••, ••:•• (fee €••.••).'),
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
    preview = sms.mask('word ' * 120 + 'your code is 482913 ' + 'tail ' * 60)
    assert len(preview) <= sms.MAX_PREVIEW and preview.startswith('…') and 'your code is [code] tail' in preview


OPEN, CLOSE, JOIN = (set('([{<"\'“‘«¿¡【（「『《〈'), set('.,;:!?)]}>"\'”’»。，！？：；、】）」』》〉'),
                     set("-‐'’&"))
GLUE = [chr(c) for c in range(0x21, 0x7F) if not chr(c).isalpha()] + [chr(c) for c in (
    0xA0, 0xAD, 0xB7, 0x200B, 0x200C, 0x200D, 0x2011, 0x2024, 0x2028, 0x2029, 0x202E, 0x202F, 0x2060, 0x2215, 0x3002,
    0x3000, 0xFEFF, 0xFF0E, 0xFF0F, 0xFF1A, 0xFF1F, 0x1F600, 0x0B, 0x0C, 0x1C, 0x1F, 0x85, 0x7F, 0x0301, 0x20E3,
    0x0660, 0x0966, 0x2460, 0xE000, 0xE0041, 0x2044, 0x00B2, 0x00BD)]
WORDS = ['Your', 'code', 'is', 'Example', 'verification', 'sign', 'in', 'at', 'OTP', 'Use', 'to', 'card', 'ending']


def may_show(raw):
    """The preview rule, stated a second time without the module: every part of the spaced word is plain."""
    parts, part = [], ''
    for ch in unicodedata.normalize('NFKC', raw):
        category = unicodedata.category(ch)
        if category[0] == 'Z' or category in {'So', 'Sk'} or ch in '\x0b\x0c\x1c\x1d\x1e\x1f\x85':
            parts.append(part)
            part = ''
        elif category[0] != 'C':
            part += ch
    for part in parts + [part]:
        if not any(unicodedata.category(ch)[0] in 'LMN' for ch in part):
            continue  # nothing, or punctuation only
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
])
def test_sender_is_a_number_or_plain_words(sender, shown):
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
