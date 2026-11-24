"""Real-world verification texts (service wordings, synthetic codes): every one must give its code.

A reader change that drops or misreads one of these is a regression, however safe the drop.
"""
import pytest

from akdbx import sms

REAL = [
("Google", "G-482913 is your Google verification code.", "482913"),
("Google 2", "Your Google verification code is 482913", "482913"),
("Google voice", "Your Google Voice verification code is 482913. Don't share this code with anyone.", "482913"),
("Microsoft", "Use 4829 as Microsoft account security code", "4829"),
("Microsoft 2", "Microsoft account security code: 482913", "482913"),
("Microsoft 3", "Your Microsoft account verification code is 482913", "482913"),
("Apple", "Your Apple ID Code is: 482913. Don't share it with anyone.", "482913"),
("Apple 2", "Your Apple Account code is: 482913. Do not share it with anyone.\n\n@apple.com #482913 %apple.com", "482913"),
("Amazon", "482913 is your Amazon OTP. Do not share it with anyone.", "482913"),
("Amazon 2", "Your Amazon one-time password is 482913. Don't share it with anyone.", "482913"),
("AWS", "Your Amazon Web Services verification code is: 482913", "482913"),
("PayPal", "PayPal: Your security code is: 482913. Your code expires in 10 minutes. Please don't reply.", "482913"),
("PayPal 2", "PayPal: 482913 is your security code. Don't share your code.", "482913"),
("Facebook", "482913 is your Facebook confirmation code", "482913"),
("Facebook 2", "123456 is your Facebook code H29Q+Fsn4Sr", "123456"),
("Facebook reset", "482913 is your Facebook password reset code", "482913"),
("Facebook reset 2", "482913 is your Facebook password reset code or reset your password here: https://fb.com/l/abc", "482913"),
("Instagram", "482 913 is your Instagram code. Don't share it.", "482913"),
("Instagram 2", "Use 482913 to verify your Instagram account.", "482913"),
("WhatsApp", "Your WhatsApp code: 482-913\n\nDon't share this code with others", "482913"),
("WhatsApp 2", "Your WhatsApp code is 482-913\nYou can also tap on this link to verify your phone: v.whatsapp.com/482913\nDon't share this code with others", "482913"),
("WhatsApp PT", "Seu código do WhatsApp: 482-913\n\nNão compartilhe este código", "482913"),
("WhatsApp ES", "Tu código de WhatsApp: 482-913\n\nNo compartas este código", "482913"),
("WhatsApp DE", "Dein WhatsApp-Code: 482-913\n\nTeile diesen Code nicht", "482913"),
("Telegram", "Telegram code: 48291\n\nYou can also tap on this link to log in:\nhttps://t.me/login/48291", "48291"),
("Telegram 2", "Telegram code 48291", "48291"),
("Signal", "Your Signal code: 482913\n\nDo not share this code\n\ndoDiFGKPO1r", "482913"),
("Signal 2", "Your Signal verification code: 482-913", "482913"),
("Uber", "Your Uber code is 4829. Never share this code. Reply STOP ALL to 89203 to unsubscribe.", "4829"),
("Uber 2", "Your Uber code: 4829. Never share this code.", "4829"),
("Lyft", "Your Lyft code is 482913", "482913"),
("Twitter", "Your Twitter confirmation code is 482913.", "482913"),
("X", "Your X verification code is 482913.", "482913"),
("TikTok", "[TikTok] 4829 is your verification code, valid for 5 minutes. To keep your account safe, never forward this code.", "4829"),
("Snapchat", "Snapchat code: 482913. Happy Snapping!", "482913"),
("Discord", "Your Discord security code is: 482913", "482913"),
("LinkedIn", "Your LinkedIn verification code is 482913.", "482913"),
("GitHub", "482913 is your GitHub authentication code. @github.com #482913", "482913"),
("Steam", "Your Steam verification code is: 48291", "48291"),
("Netflix", "Your Netflix verification code is 4829.", "4829"),
("Spotify", "Your Spotify code is 482913", "482913"),
("Airbnb", "Your Airbnb verification code is: 482913. Don't share this code with anyone; our employees will never ask for the code.", "482913"),
("Booking", "482913 is your Booking.com verification code.", "482913"),
("Tinder", "Your Tinder code is 482913", "482913"),
("Tinder PT", "Seu código do Tinder é 482913", "482913"),
("Bumble", "482913 is your Bumble verification code", "482913"),
("Coinbase", "Your Coinbase verification code is: 4829135. Don't share this code with anyone; our employees will never ask for the code.", "4829135"),
("Binance", "[Binance] Your verification code is 482913. The code is valid for 30 minutes. Do not share this code with anyone.", "482913"),
("Revolut", "Your Revolut verification code is 482-913. Don't share this code with anyone.", "482913"),
("Monzo", "Your Monzo verification code is 482913. Never share this code with anyone, even Monzo.", "482913"),
("Starling", "Your Starling verification code is 482913. Do not share this code with anyone.", "482913"),
("Wise", "Your Wise code is 482913. Never share this code.", "482913"),
("Venmo", "Venmo here! NEVER share this code via call/text. ONLY YOU should enter the code. BEWARE: If someone asks for the code, it's a scam. Code: 482913", "482913"),
("Cash App", "Cash App: 482-913 is your sign-in code. Do not share this code. Cash App will never call you for this code.", "482913"),
("Chase", "Chase: DON'T share. Use 48291354 to confirm it's you. We'll NEVER call to ask for this code. Call us if you didn't request it.", "48291354"),
("BofA", "BofA: DO NOT share this Sign In code. We will NEVER call you or text you for it. Code 482913", "482913"),
("Wells Fargo", "Wells Fargo: Your access code is 482913. We will never call or text you for this code. Don't share it with anyone.", "482913"),
("Barclays", "Your Barclays passcode is 482913. We'll never ask for this. If you didn't request it, call us.", "482913"),
("HSBC", "Your HSBC security code is 482913. Never share this code with anyone. HSBC will never call to ask for it.", "482913"),
("HSBC payment", "HSBC: Your code to approve the payment of GBP 25.00 to EXAMPLE LTD is 482913. Never share this code.", "482913"),
("Lloyds", "Lloyds: Your one-time passcode is 482913 for your online payment of £25.00 to EXAMPLE LTD with your card ending 1234. Never share this code.", "482913"),
("NatWest", "NatWest: 482913 is your one time passcode to confirm your online card payment of GBP 25.00 at EXAMPLE. Don't share it.", "482913"),
("Santander UK", "Santander: Your OTP is 48291354 for a payment of £25.00 to EXAMPLE on card ending 1234. Never share this code.", "48291354"),
("Amex", "American Express: Your one-time verification code is 482913. Do not share this code with anyone.", "482913"),
("SBI", "OTP for online purchase of Rs. 2500.00 at AMAZON thru State Bank Debit Card 6220XXXX1234 is 482913. Do not share this with anyone.", "482913"),
("HDFC", "482913 is OTP for txn of INR 2500.00 at AMAZON on HDFC Bank card ending 1234. Valid till 10:25. Do not share OTP for security reasons.", "482913"),
("ICICI", "Dear Customer, 482913 is the OTP for transaction of INR 2500.00 on your ICICI Bank Card XX1234 at AMAZON. OTPs are SECRET. DO NOT share OTP with anyone", "482913"),
("Axis", "482913 is your OTP for txn of INR 2500.00 on Axis Bank card XX1234. OTP valid for 5 mins. Do not share it with anyone.", "482913"),
("Kotak", "OTP is 482913 for txn of INR 2500.00 on Kotak Bank card ending 1234. Do not share OTP with anyone.", "482913"),
("Aadhaar", "OTP for Aadhaar (XX1234) is 482913 (valid for 10 mins). To update Aadhaar, upload documents on myAadhaar portal. Call 1947 for info.", "482913"),
("Paytm", "482913 is your Paytm OTP. Do not share it with anyone. Paytm never calls to ask for OTP.", "482913"),
("PhonePe", "482913 is your OTP for PhonePe. Do not share it with anyone.", "482913"),
("Flipkart", "482913 is the OTP for your Flipkart account. Do not share it with anyone.", "482913"),
("Swiggy", "482913 is your OTP for Swiggy. Do not share it with anyone.", "482913"),
("Zomato", "482913 is your Zomato OTP. Do not share it with anyone.", "482913"),
("One Time Password", "482913 is your One Time Password (OTP) for login. Do not share it with anyone.", "482913"),
("OTP generic", "Your OTP is 482913. It is valid for 10 minutes.", "482913"),
("Sparkasse", "Ihre TAN für die Überweisung an EXAMPLE GMBH über 25,00 EUR lautet 482913.", "482913"),
("mTAN", "Ihre mTAN lautet 482913 für die Überweisung von 250,00 EUR", "482913"),
("N26", "Dein N26 Bestätigungscode lautet 482913. Teile diesen Code mit niemandem.", "482913"),
("ING", "Ihr ING Bestätigungscode: 482913", "482913"),
("FR bank", "Votre code de confirmation est 482913. Ne le communiquez à personne.", "482913"),
("FR 2", "Votre code de sécurité Example : 482913. Il expire dans 10 minutes.", "482913"),
("ES", "Tu código de verificación es 908172", "908172"),
("ES 2", "Tu código de seguridad de Example es 482913. No lo compartas con nadie.", "482913"),
("IT", "Il tuo codice di verifica è 482913", "482913"),
("BR Nubank", "Nubank: seu código de verificação é 482913. Não compartilhe com ninguém.", "482913"),
("BR iFood", "Seu código de acesso iFood é 482913", "482913"),
("BR Mercado Livre", "482913 é seu código de verificação do Mercado Livre. Não compartilhe.", "482913"),
("Yahoo", "482913 is your Yahoo verification code", "482913"),
("Proton", "Your Proton verification code is: 482913", "482913"),
("Okta", "Your verification code is 482913", "482913"),
("Duo", "SMS passcodes: 4829135", "4829135"),
("Twilio", "Your Twilio verification code is: 771204", "771204"),
("Twilio Verify", "Your Example verification code is: 482913", "482913"),
("Shopify", "482913 is your Shopify verification code.", "482913"),
("eBay", "Your eBay security code is 482913. It expires in 10 minutes.", "482913"),
("Etsy", "Your Etsy verification code is 482913", "482913"),
("Deliveroo", "Your Deliveroo code is 4829", "4829"),
("DoorDash", "Your DoorDash verification code is: 482913", "482913"),
("HMRC", "Your HMRC access code is 482913. Do not share this code with anyone.", "482913"),
("GOV.UK", "Your GOV.UK One Login security code is 482913. Do not share this code with anyone.", "482913"),
("NHS", "Your NHS login security code is 482913", "482913"),
("Samsung", "[Samsung account] Your verification code is 482913.", "482913"),
("Xiaomi", "[Xiaomi] Your verification code is 482913. It is valid for 10 minutes.", "482913"),
("WeChat", "[WeChat] Your verification code is 482913. Don't share it with others.", "482913"),
("LINE", "LINE verification code: 4829", "4829"),
("Viber", "Your Viber code: 482913", "482913"),
("Robinhood", "Your Robinhood code is 482913. Don't share it with anyone, even Robinhood.", "482913"),
("Stripe", "Your Stripe verification code is 482913", "482913"),
("Wise 2", "482913 is your Wise verification code. Never share it with anyone.", "482913"),
("Klarna", "Your Klarna code is 482913. Never share it with anyone.", "482913"),
("Vinted", "Your Vinted verification code is 4829", "4829"),
]


@pytest.mark.parametrize('service,text,code', REAL, ids=[row[0] for row in REAL])
def test_real_format_gives_its_code(service, text, code):
    reading = sms.read(text)
    assert reading.code == code
    assert reading.result == 'code' and '[code]' in reading.preview


@pytest.mark.parametrize('text', [
    '<#> 123456 is your Example code AbCdEfGhIjk',            # app hash after the noun
    '482913 is your Example verification code AbCdEfGhIjk',
    'Your Example code is 482913.\nEnter this code\nExample',  # label-only line before a signature
    'Your Uber code is 4829.\nUber verification code\nUber Technologies',
])
def test_app_hash_and_signature_do_not_drop_a_labelled_code(text):
    assert sms.read(text).result == 'code'


@pytest.mark.parametrize('text', [
    'Your verification code:\nHXKQWP\nOrder 483920',           # a value after a colon line is still graded
    'Your verification code is:\nHXKQWP\nOrder 483920',
])
def test_a_letter_code_after_a_label_line_still_drops(text):
    reading = sms.read(text)
    assert reading.code is None and 'HXKQWP' not in reading.preview
