"""A synthetic address form and identity for the toolbar popup tests in Chromium and Firefox.

The popup fills the focused address field and its partners with the agent
identity pin's own rules. The form holds partners that those rules accept and
decoys that they refuse: another address part, a field outside the viewport,
a wrong input type, a wrong autocomplete grammar and a hidden ancestor style.
Only synthetic values.
"""
from akdbx.identities import MARKER, property_key

from test_broker import Entry

ADDRESS = {
    'given-name': 'Synthetic',
    'family-name': 'Person',
    'additional-name': 'Middle',
    'address-line1': '1 Synthetic Street',
    'address-line2': 'Flat 2',
    'address-level2': 'Testville',
    'address-level1': 'Test Region',
    'postal-code': '12345',
    'country-name': 'Germany',
    'tel': '+49 30 0000000',
    'email': 'address-only@example.test',
}
ADDRESS_TITLE = 'Synthetic address'
STREET = ADDRESS['address-line1'] + '\n' + ADDRESS['address-line2']


class AddressEntry(Entry):
    def get_custom_property(self, key):
        return {MARKER: 'v1', **{property_key(field): value for field, value in ADDRESS.items()}}.get(key)


SCOPE = 'section-home shipping '
# Filled: field id -> the value it gets. The country select shows "Germany" for the value DE.
FILLED = {'given': ADDRESS['given-name'], 'family': ADDRESS['family-name'], 'street': STREET,
          'postal': ADDRESS['postal-code'], 'country': 'DE', 'phone': ADDRESS['tel'], 'mail': ADDRESS['email']}
# Left empty: another address part, outside the viewport, a wrong type, a wrong token list, a hidden ancestor.
DECOYS = ('bill-postal', 'far-city', 'wrong-type', 'extra-token', 'faded')
ADDRESS_FORM = (
    '<style>input,select,textarea{display:block;margin:3px;width:220px;height:22px}textarea{height:40px}</style><form>'
    f'<input id="given" autocomplete="{SCOPE}given-name">'
    f'<input id="family" autocomplete="{SCOPE}family-name">'
    f'<textarea id="street" autocomplete="{SCOPE}street-address"></textarea>'
    # Before the shipping postcode: a popup that took the first field of each kind would fill this one.
    '<input id="bill-postal" autocomplete="section-home billing postal-code">'
    f'<input id="postal" autocomplete="{SCOPE}postal-code">'
    f'<select id="country" autocomplete="{SCOPE}country-name"><option value="">Choose</option>'
    '<option value="FR">France</option><option value="DE">Germany</option></select>'
    f'<input id="phone" type="tel" autocomplete="{SCOPE}mobile tel">'
    f'<input id="mail" type="email" autocomplete="{SCOPE}email">'
    f'<input id="far-city" autocomplete="{SCOPE}address-level2" style="position:absolute;left:-9999px">'
    f'<input id="wrong-type" type="email" autocomplete="{SCOPE}address-level1">'
    f'<input id="extra-token" autocomplete="{SCOPE}home address-line2">'
    f'<div style="filter:opacity(0)"><input id="faded" autocomplete="{SCOPE}additional-name"></div>'
    '</form><script>window.addressEvents = [];'
    "for (const type of ['input', 'change']) document.addEventListener(type, e => addressEvents.push(type + ':' + e.target.id));"
    '</script>')
