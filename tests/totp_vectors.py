"""Public RFC test values, with no platform-specific test dependencies."""
import base64


KEY = base64.b32encode(b'12345678901234567890').decode('ascii')
URI = 'otpauth://totp/Example:synthetic-account?secret=' + KEY + '&issuer=Example'
