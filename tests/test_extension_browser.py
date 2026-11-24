"""The extension route in a real browser on native Windows or Linux; synthetic values only.

A disposable headless profile loads the built extension. A uniquely named test
host is registered for the duration of the test, then removed: on Windows under
the browser's own native-messaging registry key (for Helium that is Chromium's
key, so the test also proves where Helium looks), on Linux in the profile's
NativeMessagingHosts folder. The broker runs on a test pipe or Unix socket with
a synthetic vault. Values reach pages only through the extension route; the
pages report SHA-256 digests, so no test reads back a field value. The test
observer uses the disposable profile's debugging port only to prepare pages.

On Linux, set AKDBX_TEST_EXTENSION_BROWSER to a Chromium that still loads an
unpacked extension (Chromium or Chrome for Testing; Google Chrome 137+ does
not), and AKDBX_TEST_BROWSER_NO_SANDBOX=1 on a host without user namespaces.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import uuid

import pytest

if sys.platform != 'win32' and not sys.platform.startswith('linux'):
    pytest.skip('native Windows or Linux required', allow_module_level=True)

from akdbx import broker_identity, extension_host, extension_route as route
from akdbx.broker import Broker, serve
from akdbx.local_https import start_local_unlock_server
from akdbx.browser_card import failure as card_failure
from akdbx.cards import FIELDS, MARKER
from akdbx.identities import MARKER as IDENTITY_MARKER, property_key as identity_property
from akdbx.target import failure
from test_broker import Entry, Vault
from test_windows_unlock import certificates  # noqa: F401
from windows_chromium_lab import FORM, ORIGIN, chromium_lab

CARD = dict(name='Synthetic Cardholder', number='4111111111111111', month='09', year='2031', csc='123')


class NoKeys:
    """A window backend that fails the test if any keyboard delivery starts."""

    def capture(self, pid, window):
        return ('synthetic-window', pid, window)

    def deliver(self, *args, **kwargs):
        pytest.fail('a DOM-only credential reached the keyboard backend')


class CardEntry(Entry):
    def get_custom_property(self, key):
        return {MARKER: 'v1', **{field: CARD[k] for k, field in FIELDS.items()}}.get(key)


PHONE = '+44 7000-000000'  # Synthetic only.
PHONE_NATIONAL = '7000000000'


class IdentityEntry(Entry):
    def get_custom_property(self, key):
        return {IDENTITY_MARKER: 'v1', identity_property('tel'): PHONE,
                identity_property('email'): 'synthetic-only@example.test'}.get(key)


if sys.platform == 'win32':
    from test_windows_native import private_dir  # noqa: F401
else:
    @pytest.fixture
    def private_dir(tmp_path):
        path = tmp_path / 'private'
        path.mkdir(mode=0o700)
        return path

USERNAME = 'Synthetic.User+42@example.test'
PASSWORD = 'Synthetic-ONLY!$`\\Aa19 Ω'
EMPTY = hashlib.sha256(b'').hexdigest()
STRIPE_PATH = '/v3/elements-inner-accessory-target-' + 'b' * 32 + '.html'
STRIPE = 'https://js.stripe.com' + STRIPE_PATH
CARD_ELEMENT_PATH = '/v3/elements-inner-card-' + 'd' * 32 + '.html'
CARD_ELEMENT = 'https://js.stripe.com' + CARD_ELEMENT_PATH + '#__shared_params__[version]=v3&componentName=card'
DIGEST = '''<script>
window.syntheticEvents = [];
document.addEventListener('input', e => syntheticEvents.push({field: e.target.id, trusted: e.isTrusted}));
async function digest(id) {
  const data = new TextEncoder().encode(document.getElementById(id).value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}
</script>'''
SECRET = 'SynthCapture-0123456789abcdefOnly'
GROUPED_KEY = 'jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp'  # A synthetic Base32 setup key.
SECRET_STYLE = '<style>body{margin:0}code,input{display:block;margin:4px;font:16px monospace}</style>'
COVER = 'position:fixed;left:0;top:0;width:900px;height:300px;background:#fff;pointer-events:none'
FULL = 'position:fixed;inset:0;margin:0;width:100vw;height:100vh;border:0;background:#fff'
LOGIN_FRAME = ('<!doctype html><meta charset="utf-8"><h1>Outer page</h1>'
               '<iframe id="login-frame" src="https://auth.example.com/login" style="width:600px;height:300px;border:0;{}">'
               '</iframe><iframe id="decoy" src="https://auth.example.com/decoy" style="width:200px;height:100px;border:0">'
               '</iframe>')
PAGES = {
    '/secret': f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<p>Copy it now.</p><code id="secret" tabindex="0">{SECRET}</code>',
    # An authenticator setup key printed in groups, and prose that has only Base32 letters.
    '/totp-grouped': f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{GROUPED_KEY}</code>',
    '/totp-prose': f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">you will not see this again</code>',
    # A click-through cover: elementFromPoint ignores it, CDP's hit test does not.
    # An opaque cover that takes pointer events: the DOM hit test refuses it, with enhanced security off too.
    '/secret-opaque-cover': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                             f'<div style="{COVER.replace(";pointer-events:none", "")}"></div>'),
    '/secret-covered': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                        f'<div style="{COVER}"></div>'),
    '/secret-covered-important': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}'
                                  f'<code id="secret" tabindex="0">{SECRET}</code>'
                                  f'<div style="{COVER} !important"></div>'),
    # The same cover inside a closed shadow root: the user style sheet does not reach it.
    '/secret-shadow-cover': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                             '<div id="host"></div><script>host.attachShadow({mode: "closed"}).innerHTML = '
                             f'`<div style="{COVER}"></div>`;</script>'),
    '/secret-shadow-important': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                                 '<div id="host"></div><script>host.attachShadow({mode: "closed"}).innerHTML = '
                                 f'`<div style="{COVER} !important"></div>`;</script>'),
    '/card-covered': ('<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number" '
                      f'style="width:200px;height:30px"></form><div style="{COVER}"></div>' + DIGEST),
    # A floating label above, not over, the field centre: benign, both routes fill it.
    '/card-label': ('<!doctype html><meta charset="utf-8"><form><div style="position:relative">'
                    '<input id="number" autocomplete="cc-number" style="width:220px;height:44px">'
                    '<label for="number" style="position:absolute;left:8px;top:2px;font-size:10px;pointer-events:none">'
                    'Card number</label></div></form>' + DIGEST),
    # A phone input with no autocomplete hint next to a separate country picker, as many sign-up pages have.
    '/phone': ('<!doctype html><meta charset="utf-8"><form><select id="country"><option value="+44">+44</option>'
               '</select><input id="phone" type="tel" name="phoneNumber" style="width:200px;height:30px">'
               '<input id="phone-on" type="tel" autocomplete="on"><input id="phone-off" type="tel" autocomplete="off">'
               '<input id="phone-email" type="text" autocomplete="email"><input id="phone-national" type="tel" '
               'autocomplete="tel-national"></form>' + DIGEST),
    '/framed-visible': LOGIN_FRAME.format(''),
    '/framed-hidden': LOGIN_FRAME.format('opacity:0'),
    '/decoy': '<!doctype html><meta charset="utf-8"><p>decoy</p>',
    # Covers that elementFromPoint skips even with pointer-events on: the inert attribute, CSS
    # interactivity, and a pseudo-element in a closed shadow root with a more specific !important rule.
    '/secret-inert': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                      f'<div inert style="{COVER.replace(";pointer-events:none", "")}"></div>'),
    '/secret-interactivity': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                              f'<div style="{COVER.replace("pointer-events:none", "interactivity:inert !important")}"></div>'),
    '/secret-shadow-pseudo': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                              '<div id="host"></div><script>host.attachShadow({mode: "closed"}).innerHTML = '
                              '`<style>#c::before{content:"";position:fixed;left:0;top:0;width:900px;height:300px;'
                              'background:#fff;pointer-events:none !important}</style><div id="c"></div>`;</script>'),
    '/card-inert': ('<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number" '
                    f'style="width:200px;height:30px"></form><div inert style="{COVER.replace(";pointer-events:none", "")}"></div>'
                    + DIGEST),
    # Inert covers: one styled only while inert, one in the top layer above a modal dialog (inert
    # because the dialog is modal), and the same dialog without a cover, which reads.
    '/secret-inert-styled': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>.c{{display:none}}'
                             f'.c[inert]{{display:block;{COVER.replace(";pointer-events:none", "")}}}</style>'
                             f'<code id="secret" tabindex="0">{SECRET}</code><div class="c" inert></div>'),
    '/secret-modal': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<dialog id="d"><code id="secret" tabindex="0">'
                      f'{SECRET}</code></dialog><script>d.showModal()</script>'),
    '/secret-modal-cover': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<dialog id="d"><code id="secret" tabindex="0">'
                            f'{SECRET}</code></dialog><div id="p" popover style="position:fixed;inset:0;margin:0;width:100vw;'
                            'height:100vh;border:0;background:#fff"></div><script>d.showModal(); p.showPopover()</script>'),
    # Covers that paint outside the inert element's own box, and a popover's opaque ::backdrop.
    '/secret-inert-text': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                           '<div inert style="position:fixed;left:0;top:0;width:0;height:0;font:600px/1 monospace;'
                           'color:#fff">\u2588\u2588</div>'),
    '/secret-inert-pseudo': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#c{{position:fixed;left:0;top:0;'
                             'width:0;height:0}#c::before{content:"";display:block;width:900px;height:300px;'
                             f'background:#fff}}</style><code id="secret" tabindex="0">{SECRET}</code><div id="c" inert></div>'),
    '/secret-inert-slot': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                           f'<div id="host"><div style="{COVER.replace(";pointer-events:none", "")}"></div></div>'
                           '<script>host.attachShadow({mode: "closed"}).innerHTML = '
                           "'<div inert style=\"display:contents\"><slot></slot></div>'</script>"),
    '/secret-popover-backdrop': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#p::backdrop{{background:#fff}}'
                                 f'</style><code id="secret" tabindex="0">{SECRET}</code><div id="p" popover="manual" '
                                 'style="position:fixed;width:0;height:0;border:0;padding:0"></div>'
                                 '<script>p.showPopover()</script>'),
    # Covers that no selector list names. A popover in its exit transition: painted in the top
    # layer, no longer :popover-open.
    '/secret-popover-exit': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#p{{{FULL};transition:overlay 60s '
                             f'allow-discrete,display 60s allow-discrete}}</style><code id="secret" tabindex="0">{SECRET}</code>'
                             '<div id="p" popover="manual"></div><script>p.showPopover(); requestAnimationFrame(() => '
                             'requestAnimationFrame(() => { p.hidePopover(); window.ready = true; }));</script>'),
    # A popover that holds the secret's modal dialog and opens after it: it paints over the dialog and is inert.
    '/secret-popover-holds-modal': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<div id="p" popover="manual" '
                                    f'style="{FULL}"><dialog id="d"><code id="secret" tabindex="0">{SECRET}</code></dialog></div>'
                                    '<script>d.showModal(); p.showPopover();</script>'),
    '/secret-details-content': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>details::details-content{{display:block;'
                                f'{COVER}}}</style><code id="secret" tabindex="0">{SECRET}</code>'
                                '<details open><summary>More</summary><p>text</p></details>'),
    '/secret-scroll-button': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#s{{overflow:auto;width:60px;height:60px}}'
                              f'#s::scroll-button(down){{content:"";border:0;{COVER}}}</style>'
                              f'<code id="secret" tabindex="0">{SECRET}</code><div id="s"><div style="height:500px"></div></div>'),
    '/secret-scroll-marker-group': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#s{{overflow:auto;width:60px;'
                                    f'height:60px;scroll-marker-group:after}}#s::scroll-marker-group{{{COVER}}}</style>'
                                    f'<code id="secret" tabindex="0">{SECRET}</code><div id="s"><div style="height:500px"></div></div>'),
    # A view transition that never ends, with a white click-through root and no snapshot images.
    '/secret-view-transition': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>@keyframes hold{{from{{opacity:1}}'
                                'to{opacity:1}}::view-transition{background:#fff;pointer-events:none}::view-transition-group(root)'
                                '{animation:hold 60s;pointer-events:none}::view-transition-image-pair(root){display:none}'
                                f'</style><code id="secret" tabindex="0">{SECRET}</code><script>secret.focus(); '
                                'document.startViewTransition(() => {}).ready.then(() => { window.ready = true; });</script>'),
    # A user-agent pseudo-element (the bar of a meter) as the cover.
    '/secret-meter-bar': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>meter{{appearance:none}}'
                          f'meter::-webkit-meter-bar{{{COVER}}}</style><code id="secret" tabindex="0">{SECRET}</code>'
                          '<meter value="0.5"></meter>'),
    # A cover that lets most of the secret show through: the pixels are not the secret's own.
    '/secret-veil': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                     f'<div style="{COVER.replace("#fff", "rgba(255,255,255,.6)")}"></div>'),
    # The secret hidden under its own ::after. A hit test (CDP's too) returns the element itself, and the
    # occlusion test does not count an element's own parts; only the pixel challenge sees it.
    '/secret-own-pseudo': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#secret{{position:relative}}'
                           '#secret::after{content:"";position:absolute;inset:0;background:#fff}</style>'
                           f'<code id="secret" tabindex="0">{SECRET}</code>'),
    # Paint that a hit test does not see as a cover: the secret element's own ::after painted in
    # currentColor (it would take the challenge colour), and its own outline drawn over its text.
    '/secret-own-pseudo-currentcolor': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#secret{{position:relative}}'
                                        '#secret::after{content:"";position:absolute;inset:0;background:currentColor}</style>'
                                        f'<code id="secret" tabindex="0">{SECRET}</code>'),
    '/secret-own-outline': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#secret{{outline:40px solid '
                            f'currentColor;outline-offset:-40px}}</style><code id="secret" tabindex="0">{SECRET}</code>'),
    # The secret's own scroll markers in currentColor, over its text.
    '/secret-own-scroll-markers': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#secret{{overflow:auto;'
                                   'scroll-marker-group:after}#secret::scroll-marker-group{position:fixed;left:0;top:0;'
                                   f'width:900px;height:300px;background:currentColor}}</style>'
                                   f'<code id="secret" tabindex="0">{SECRET}</code>'),
    # Generated content that draws nothing: a hidden ::after and a list item without a marker. Both read.
    '/secret-hidden-pseudo': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#secret::after{{content:"x";'
                              f'display:none}}</style><code id="secret" tabindex="0">{SECRET}</code>'),
    '/secret-list-item': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<ul style="list-style:none;padding:0;margin:0">'
                          f'<li id="secret" tabindex="0" style="font:16px monospace">{SECRET}</li></ul>'),
    '/secret-list-item-no-marker': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#secret::marker{{content:none}}'
                                    '</style><ul style="padding:0;margin:0"><li id="secret" tabindex="0" '
                                    f'style="font:16px monospace">{SECRET}</li></ul>'),
    '/secret-hidden-scroll-markers': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<style>#secret{{overflow:auto;'
                                      'scroll-marker-group:after}#secret::scroll-marker-group{display:none}</style>'
                                      f'<code id="secret" tabindex="0">{SECRET}</code>'),
    # A long token that wraps over many lines in a narrow box: visible, so it reads.
    '/secret-wrapped': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0" '
                        'style="width:190px;overflow-wrap:anywhere">' + 'Synth' + 'abcdefghij' * 40 + '</code>'),
    # An ancestor's negative-offset outline over the field, and over the whole Stripe frame.
    '/card-outline': ('<!doctype html><meta charset="utf-8"><div style="width:240px;height:60px;outline:60px solid #fff;'
                      'outline-offset:-60px"><form><input id="number" autocomplete="cc-number" '
                      'style="width:200px;height:30px"></form></div>' + DIGEST),
    # Benign pages that the selector rules refused: a cookie popover elsewhere on the page (its
    # transparent ::backdrop spans the viewport), an inert background behind a dialog that holds the
    # secret or the field, a copy button over a corner of the secret's box, and a transparent
    # click-through layer over the field (it hides nothing).
    '/secret-cookie-popover': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<code id="secret" tabindex="0">{SECRET}</code>'
                               '<div id="p" popover="manual" style="position:fixed;inset:auto 0 0 0;margin:0;width:auto;'
                               'height:80px;border:0;background:#eee">We use cookies.</div><script>p.showPopover();</script>'),
    '/secret-inert-background': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<main inert style="height:600px;'
                                 'background:#ddd"><p>Page content</p></main><div role="dialog" style="position:fixed;left:100px;'
                                 f'top:100px;width:500px;height:200px;background:#fff"><code id="secret" tabindex="0">{SECRET}</code>'
                                 '</div>'),
    '/secret-copy-button': (f'<!doctype html><meta charset="utf-8">{SECRET_STYLE}<div style="position:relative;width:700px">'
                            f'<code id="secret" tabindex="0">{SECRET}</code><button style="position:absolute;right:4px;top:0;'
                            'height:19px">Copy</button></div>'),
    '/card-cookie-popover': ('<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number" '
                             'style="width:200px;height:30px"></form><div id="p" popover="manual" style="position:fixed;'
                             'inset:auto 0 0 0;margin:0;width:auto;height:80px;border:0;background:#eee">We use cookies.</div>'
                             '<script>p.showPopover();</script>' + DIGEST),
    '/card-inert-background': ('<!doctype html><meta charset="utf-8"><main inert style="height:600px;background:#ddd">'
                               '<p>Page content</p></main><dialog id="d"><form><input id="number" autocomplete="cc-number" '
                               'style="width:200px;height:30px"></form></dialog><script>d.showModal();</script>' + DIGEST),
    '/card-clear-layer': ('<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number" '
                          'style="width:200px;height:30px"></form>'
                          f'<div style="{COVER.replace("background:#fff", "background:transparent")}"></div>' + DIGEST),
    # The Stripe frame with a merchant element over one corner of the frame, away from the inputs.
    '/checkout-corner': f'''<!doctype html><meta charset="utf-8"><h1>Merchant</h1>
<iframe id="stripe" src="{STRIPE}" style="width:400px;height:200px;border:0"></iframe>
<div id="chip" style="position:absolute;width:40px;height:20px;background:#ccc;pointer-events:none"></div>
<script>const box = stripe.getBoundingClientRect(); chip.style.left = (box.right - 50) + 'px';
chip.style.top = (box.bottom + scrollY - 30) + 'px';</script>''',
    # A card field in a same-origin child frame, with covers in the top page that only the
    # top page's own checks can see: a click-through cover in a closed shadow root, and an inert one.
    '/card-field': ('<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number" '
                    'style="width:200px;height:30px"></form>' + DIGEST),
    '/card-frame': ('<!doctype html><meta charset="utf-8"><iframe id="pay" src="/card-field" '
                    'style="width:400px;height:200px;border:0"></iframe>'),
    '/card-frame-shadow': ('<!doctype html><meta charset="utf-8"><iframe id="pay" src="/card-field" '
                           'style="width:400px;height:200px;border:0"></iframe><div id="host"></div>'
                           '<script>host.attachShadow({mode: "closed"}).innerHTML = '
                           f'`<div style="{COVER}"></div>`;</script>'),
    '/card-frame-inert': ('<!doctype html><meta charset="utf-8"><iframe id="pay" src="/card-field" '
                          'style="width:400px;height:200px;border:0"></iframe>'
                          f'<div inert style="{COVER.replace(";pointer-events:none", "")}"></div>'),
    # The Stripe frame with an inert cover in the merchant page over only the number input. (At 20px
    # high it ended above the input's centre, the one point that CDP tests; it now covers that point.)
    '/checkout-inert': f'''<!doctype html><meta charset="utf-8"><h1>Merchant</h1>
<iframe id="stripe" src="{STRIPE}" style="width:400px;height:200px;border:0"></iframe>
<div inert id="cover" style="position:absolute;width:150px;height:30px;background:#fff"></div>
<script>const box = stripe.getBoundingClientRect(); cover.style.left = (box.left + 2) + 'px';
cover.style.top = (box.top + scrollY + 2) + 'px';</script>''',
    '/checkout-outline': f'''<!doctype html><meta charset="utf-8"><h1>Merchant</h1>
<div style="width:400px;height:200px;outline:200px solid #f00;outline-offset:-200px">
<iframe id="stripe" src="{STRIPE}" style="width:400px;height:200px;border:0"></iframe></div>''',
    # A hidden middle frame in a closed shadow root (window.frames leaves it out) and a visible
    # about:blank decoy whose owner probe the page reads and forwards to the hidden frame.
    '/framed-shadow-decoy': '''<!doctype html><meta charset="utf-8"><h1>Outer page</h1>
<iframe id="decoy" style="width:600px;height:300px;border:0"></iframe><div id="host"></div>
<script>
const root = host.attachShadow({mode: 'closed'});
root.innerHTML = '<iframe src="/middle" style="width:600px;height:300px;border:0;opacity:0"></iframe>';
const hidden = root.querySelector('iframe');
decoy.contentWindow.addEventListener('message', event => {
  if (event.data && event.data.akdbx_owner) hidden.contentWindow.postMessage(event.data, location.origin);
}, true);
</script>''',
    '/middle': ('<!doctype html><meta charset="utf-8"><iframe src="https://auth.example.com/login" '
                'style="width:580px;height:280px;border:0"></iframe>'),
    # A secret in a same-site child frame: the extension reads only in the top document.
    '/framed-secret': ('<!doctype html><meta charset="utf-8"><iframe id="keys" src="https://auth.example.com/secret" '
                       'style="width:700px;height:200px;border:0"></iframe>'),
    # An attacker with pages on the login origin: the login page stops the first (genuine) owner
    # probe, and a visible decoy on the same origin relays its own probe through the top page.
    '/login-suppress': FORM + '''<script>let first = true;
addEventListener('message', event => {
  if (event.data && event.data.akdbx_owner && first) {
    first = false;
    event.stopImmediatePropagation();
  }
}, true);</script>''',
    '/decoy-relay': '''<!doctype html><meta charset="utf-8"><p>decoy</p><script>
addEventListener('message', event => {
  if (event.data && event.data.akdbx_owner) parent.postMessage({relay: event.data.akdbx_owner}, '*');
}, true);</script>''',
    '/framed-suppress': '''<!doctype html><meta charset="utf-8"><h1>Outer page</h1>
<iframe id="decoy" src="https://auth.example.com/decoy-relay" style="width:600px;height:300px;border:0"></iframe>
<iframe id="login" src="https://auth.example.com/login-suppress" style="width:600px;height:300px;border:0;opacity:0"></iframe>
<script>
addEventListener('message', event => {
  if (event.data && event.data.relay) login.contentWindow.postMessage({akdbx_owner: event.data.relay}, 'https://auth.example.com');
});
</script>''',
    # A hostile page: the real login frame is transparent inside a closed shadow root, and the page
    # forwards the nonce that its own visible decoy frame receives to the login frame.
    '/framed-forward': '''<!doctype html><meta charset="utf-8"><h1>Outer page</h1>
<iframe id="decoy" src="/decoy" style="width:600px;height:300px;border:0"></iframe><div id="host"></div>
<script>
const root = host.attachShadow({mode: 'closed'});
root.innerHTML = '<iframe src="https://auth.example.com/login" style="width:600px;height:300px;border:0;opacity:0"></iframe>';
const login = root.querySelector('iframe');
decoy.addEventListener('load', () => decoy.contentWindow.addEventListener('message', event => {
  if (event.data && event.data.akdbx_owner) login.contentWindow.postMessage(event.data, 'https://auth.example.com');
}, true));
</script>''',
    '/replacing': '''<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number">
<input id="expiry" autocomplete="cc-exp" maxlength="5"></form>
<script>number.addEventListener('input', () => { const fresh = expiry.cloneNode(); expiry.replaceWith(fresh); });</script>''' + DIGEST,
    '/clearing': '''<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number">
<input id="expiry" autocomplete="cc-exp" maxlength="5"></form>
<script>number.addEventListener('input', () => { expiry.value = ''; });</script>''' + DIGEST,
    '/masked': '''<!doctype html><meta charset="utf-8"><form><input id="number" autocomplete="cc-number">
<input id="csc" type="password" autocomplete="cc-csc"></form>''' + DIGEST,
    '/hidden': '''<!doctype html><meta charset="utf-8"><form><input id="username" autocomplete="username">
<input id="password" type="password" autocomplete="current-password" style="opacity:0"></form>''' + DIGEST,
    '/checkout': f'''<!doctype html><meta charset="utf-8"><h1>Merchant</h1>
<iframe id="stripe" src="{STRIPE}" style="width:400px;height:200px;border:0"></iframe>
<iframe id="fake" src="https://evil.example.net{STRIPE_PATH}" style="width:400px;height:200px;border:0"></iframe>''',
    STRIPE_PATH: '''<!doctype html><meta charset="utf-8"><style>input{display:block;width:200px;height:24px}</style>
<input id="payment-numberInput" name="number" autocomplete="cc-number">
<input id="payment-expiryInput" name="expiry" autocomplete="cc-exp">''' + DIGEST,
    '/card-element': f'''<!doctype html><meta charset="utf-8"><h1>Merchant</h1>
<iframe name="__privateStripeFrame5551" title="Secure card payment input frame" src="{CARD_ELEMENT}"
 style="width:400px;height:240px;border:0"></iframe>''',
    # Synthetic classic Card Element: no ids, two decoys named "hidden".
    CARD_ELEMENT_PATH: '''<!doctype html><meta charset="utf-8"><style>input{display:block;width:200px;height:24px}</style>
<form><input name="hidden" autocomplete="fake">
<input type="text" name="cardnumber" autocomplete="cc-number" placeholder="Card number">
<input type="text" name="exp-date" autocomplete="cc-exp" placeholder="MM / YY">
<input type="text" name="cvc" autocomplete="cc-csc" placeholder="CVC">
<input name="hidden" autocomplete="fake"></form>
<script>
async function digestName(name, index = 0) {
  const data = new TextEncoder().encode(document.getElementsByName(name)[index].value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}
</script>''',
}


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def extension_browser():
    """The browser to test: AKDBX_TEST_EXTENSION_BROWSER, else Helium, Edge or Chrome.

    Google Chrome 137 and later ignore --load-extension, so a disposable Chrome
    profile cannot load the unpacked extension; Helium and Edge still can.
    """
    override = os.environ.get('AKDBX_TEST_EXTENSION_BROWSER')
    if override:
        return Path(override)
    if sys.platform != 'win32':
        return None
    local, programs = os.environ.get('LOCALAPPDATA', ''), os.environ.get('ProgramFiles', '')
    for candidate in (Path(local) / r'imput\Helium\Application\chrome.exe',
                      Path(os.environ.get('ProgramFiles(x86)', '')) / r'Microsoft\Edge\Application\msedge.exe',
                      Path(programs) / r'Google\Chrome\Application\chrome.exe'):
        if candidate.is_file():
            return candidate
    return None


def browser_kind(binary):
    text = str(binary).lower()
    return 'helium' if 'helium' in text else 'edge' if 'msedge' in text else 'chrome'


class Harness:
    def __init__(self, lab, broker, kind, unlock_origin=None, identity=None):
        self.lab, self.broker, self.kind = lab, broker, kind
        self.unlock_origin, self.identity = unlock_origin, identity

    @property
    def hub(self):
        return self.broker.extension

    def frames(self, url):
        return self.broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1,
                                         top_url=url, route='extension'))

    def focus(self, field):
        self.lab.evaluate(f'document.getElementById({json.dumps(field)}).focus()')
        self.lab.wait(f'document.activeElement.id === {json.dumps(field)}')

    def service_worker(self):
        observer = self.lab.observer
        targets = observer.call('Target.getTargets')['targetInfos']
        worker = next(t for t in targets if t['type'] == 'service_worker'
                      and t['url'].startswith(route.EXTENSION_ORIGIN))
        return observer.call('Target.attachToTarget', dict(targetId=worker['targetId'], flatten=True))['sessionId']

    def worker_call(self, expression):
        session = self.service_worker()
        return self.lab.observer.evaluate(expression, session, await_promise=True)

    def frame_session(self, url):
        observer = self.lab.observer
        for _ in range(100):
            frames = [t for t in observer.call('Target.getTargets')['targetInfos'] if t['type'] == 'iframe' and t['url'] == url]
            if frames:
                return observer.call('Target.attachToTarget', dict(targetId=frames[0]['targetId'], flatten=True))['sessionId']
            time.sleep(.05)
        raise AssertionError('processor frame target missing')


def grant_screenshots(extension):
    """The access that the options page asks for when the user turns enhanced security on.

    A headless browser cannot click its permission prompt, so a test that needs the
    access (the `enhanced` fixture or the screenshot_access marker) gets a build that
    lists <all_urls> as granted at install. Every other test runs the shipped manifest.
    """
    path = Path(extension) / 'manifest.json'
    manifest = json.loads(path.read_text(encoding='utf-8'))
    assert manifest['optional_host_permissions'] == ['<all_urls>'] and manifest['host_permissions'] == ['https://*/*']
    manifest['host_permissions'] = ['<all_urls>']
    path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')


@pytest.fixture
def harness(private_dir, certificates, monkeypatch, request):
    if sys.platform != 'win32':
        certificates[1].chmod(0o600)  # The Linux page refuses a key other users could read.
    binary = extension_browser()
    if binary is None:
        if os.environ.get('AKDBX_REQUIRE_EXTENSION_BROWSER') == '1':
            pytest.fail('the extension route tests require Helium, Chrome or Edge')
        pytest.skip('the extension route tests require Helium, Chrome or Edge')
    kind = browser_kind(binary)
    suffix = uuid.uuid4().hex[:10]
    host_name = 'org.akdbx.test_' + suffix
    pipe = (Path(r'\\.\pipe\akdbx-test-extension-' + suffix) if sys.platform == 'win32'
            else Path(private_dir) / 'run' / 'broker.sock')
    # The broker's own HTTPS page on loopback, as `akdbx serve --tls-cert` runs it: the built origin.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        unlock_port = probe.getsockname()[1]
    unlock_origin = f'https://localhost:{unlock_port}'
    extension = extension_host.build(Path(private_dir) / 'extension', host_name=host_name, unlock_origin=unlock_origin)
    if 'enhanced' in request.fixturenames or request.node.get_closest_marker('screenshot_access') is not None:
        grant_screenshots(extension)
    launcher = Path(private_dir) / ('host.cmd' if sys.platform == 'win32' else 'host.sh')
    launcher.write_text(extension_host._launcher_text(kind, sys.executable, str(pipe)), encoding='utf-8', newline='')
    native_hosts = None
    if sys.platform == 'win32':
        import winreg
        manifest = Path(private_dir) / (host_name + '.json')
        manifest.write_text(json.dumps(extension_host._manifest(launcher, host_name)), encoding='utf-8')
        key = extension_host.WINDOWS_KEYS[kind] + '\\' + host_name
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
            winreg.SetValueEx(handle, '', 0, winreg.REG_SZ, str(manifest))
    else:
        launcher.chmod(0o700)
        native_hosts = {host_name: extension_host._manifest(launcher, host_name)}
    entries = [Entry(username=USERNAME, password=PASSWORD, url=ORIGIN + '/login'), CardEntry(title='Synthetic card'),
               IdentityEntry(uuid='identity', title='Synthetic phone', path=('Root', 'Web', 'Synthetic phone')),
               Entry(title='Other', username='other@example.test', password=PASSWORD, url='https://other.example.org/'),
               Entry(title='Auth', username=USERNAME, password=PASSWORD, url='https://auth.example.com/login')]
    broker = Broker(Vault(entries), NoKeys())
    unlock, _ = start_local_unlock_server(broker, Path(private_dir) / 'vault.kdbx', None, unlock_origin, *certificates)
    identity = broker_identity.IdentityStore(Path(private_dir) / 'identity').announce(unlock_origin)
    broker.extension.set_identity(identity)
    stop = threading.Event()
    server = threading.Thread(target=serve, args=(pipe, broker, stop), daemon=True)
    server.start()
    try:
        with chromium_lab(private_dir, *certificates, pages=PAGES, binary=binary, extension=extension,
                          hosts=('js.stripe.com',), native_hosts=native_hosts) as lab:
            deadline = time.monotonic() + 60
            while not broker.extension.channels:
                assert time.monotonic() < deadline, 'the extension host did not attach to the broker'
                time.sleep(.1)
            [channel] = broker.extension.channels.values()
            assert channel.browser == kind
            # The loaded extension reports the version of its own build (with the content stamp) to the broker.
            assert channel.version == extension_host.built_version() and channel.stale is False
            assert broker.dispatch(dict(action='ping'))['extension_browsers'] == [
                dict(browser=kind, paired=False, version=extension_host.built_version(), version_status='current')]
            # The popup shows a code computed from its own key; it must equal
            # the code the broker's pairing page shows for the key it received.
            workers = [t for t in lab.observer.call('Target.getTargets')['targetInfos']
                       if t['type'] == 'service_worker' and t['url'].startswith(route.EXTENSION_ORIGIN)]
            worker = lab.observer.call('Target.attachToTarget', dict(targetId=workers[0]['targetId'], flatten=True))
            state = lab.observer.evaluate('popupState()', worker['sessionId'], await_promise=True)
            assert state['paired'] is False and state['code'] == route.pairing_code(channel.digest)
            # Pair through the hub; the private page itself has its own tests.
            token = next(t for t, (digest, _) in broker.extension.pairings.items() if digest == channel.digest)
            assert broker.extension.approve(token)
            # Reload so the declared content script runs in the test page.
            lab.navigate('/login')
            harness = Harness(lab, broker, kind, unlock_origin, identity)
            harness.extension, harness.host_name = extension, host_name  # For a rebuild in the same folder.
            yield harness
    finally:
        stop.set()
        server.join(5)
        unlock.shutdown()
        unlock.server_close()
        broker.unlock_notifications.close()
        if sys.platform == 'win32':
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)
            except OSError:
                pass


SETTINGS = "chrome.storage.local.get('settings').then(found => found.settings ?? null)"


def set_enhanced(harness, on):
    harness.worker_call(f"chrome.storage.local.set({{settings: {{enhanced_security: {json.dumps(on)}}}}})")


@pytest.fixture
def enhanced(harness):
    """Enhanced security on, as the options page leaves it after the browser granted the screenshots."""
    set_enhanced(harness, True)
    return harness


def test_the_service_worker_binds_the_first_broker_key_from_the_https_identity_page(harness):
    """The MV3 worker itself reads /.well-known/akdbx-identity: CSP connect-src, host permission and the
    page's Origin allowlist all let it through, and the key is stored only after that read verifies."""
    statement = harness.identity.message()['statement']
    read = "chrome.storage.local.get('broker_trust').then(found => found.broker_trust ?? null)"
    deadline = time.monotonic() + 30
    record = harness.worker_call(read)
    while record is None and time.monotonic() < deadline:
        time.sleep(.2)
        record = harness.worker_call(read)
    build = harness.worker_call('globalThis.AKDBX_BUILD_ID')  # The ID that config.js of this build holds.
    assert isinstance(build, str) and len(build) == 22
    assert record == {'v': 1, 'public_key': harness.identity.message()['public_key'], 'key_id': statement['key_id'],
                      'origin': harness.unlock_origin, 'seq': statement['seq'], 'build': build}
    state = harness.worker_call('popupState()')
    assert state['origin'] == harness.unlock_origin and state['trust_error'] is None and state['trust_reset'] is False


def search(broker):
    return broker.dispatch(dict(action='search', query='signup.example.com'))['entries'][0]['handle']


def test_agent_route_fills_the_pinned_password_through_the_extension(harness):
    lab, broker = harness.lab, harness.broker
    url = lab.evaluate('location.href')
    listing = harness.frames(url)
    assert listing['ok'] and listing['route'] == 'extension', listing
    harness.focus('password')
    pin = broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                               frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='password',
                               route='extension'))
    assert pin['ok'] and pin['target_delivery'] == route.DELIVERY, pin
    receipt = broker.dispatch(dict(action='fill', handle=search(broker), mode='password', target=pin['target'],
                                   target_protocol=1))
    assert receipt == dict(ok=True, filled='password', target_delivery=route.DELIVERY)
    assert lab.digest('password') == sha(PASSWORD) and lab.digest('username') == EMPTY
    assert not any(e['trusted'] for e in lab.evaluate('syntheticEvents'))
    # Login mode fills both retained fields without Tab or focus changes.
    harness.focus('username')
    pin = broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                               frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='login',
                               username_selector='#username', route='extension'))
    assert broker.dispatch(dict(action='fill', handle=search(broker), mode='login', target=pin['target'],
                                target_protocol=1))['ok']
    assert lab.digest('username') == sha(USERNAME) and lab.evaluate('document.activeElement.id') == 'username'
    print(json.dumps(dict(browser=lab.version, kind=harness.kind, route='extension', exact_values=True)))


def test_agent_route_refuses_wrong_origin_wrong_frame_and_hidden_fields(harness):
    lab, broker = harness.lab, harness.broker
    # Wrong origin: a credential of another site never fills this page.
    url = lab.navigate('/signup')
    listing = harness.frames(url)
    harness.focus('password')
    pin = broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                               frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='password',
                               route='extension'))
    assert pin['ok'], pin
    other = broker.dispatch(dict(action='search', query='other.example.org'))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill', handle=other, mode='password', target=pin['target'],
                                target_protocol=1)) == failure()
    assert lab.untouched()
    # Wrong frame: a login frame of another site inside this page.
    url = lab.navigate('/hostile')
    listing = harness.frames(url)
    child = next(f for f in listing['frames'] if f['depth'] == 1)
    assert child['origin'] == 'https://evil.example.net' and child['eligible'] is False
    assert broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                frame_id=child['frame_id'], top_url=url, selector='#password', mode='password',
                                frame_protocol=1, frame_origin='https://evil.example.net', route='extension')) == failure()
    # Hidden field: a transparent password input is never pinned.
    url = lab.navigate('/hidden')
    listing = harness.frames(url)
    harness.focus('password')
    assert broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='password',
                                route='extension')) == failure()
    assert lab.digest('password') == EMPTY


def test_cards_go_only_to_the_supported_processor_frame_below_the_merchant(harness):
    lab, broker = harness.lab, harness.broker
    url = lab.navigate('/checkout')
    lab.wait("document.readyState === 'complete'")
    session = harness.frame_session(STRIPE)
    lab.observer.evaluate("document.getElementById('payment-numberInput').focus()", session)
    frames = harness.frames(url)
    by_origin = {f['origin']: f for f in frames['frames']}
    stripe = by_origin['https://js.stripe.com']
    fake = by_origin['https://evil.example.net']

    def pin(frame, **extra):
        return broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=frames['page_id'],
                                    frame_id=frame['frame_id'], top_url=url, selector='#payment-numberInput',
                                    field='cc-number', route='extension', **extra))
    stripe_route = dict(processor='stripe', processor_protocol=1)
    assert pin(fake, **stripe_route) == card_failure()   # Same markup, wrong host.
    assert pin(stripe) == card_failure()                 # Cross-origin without the processor route.
    target = pin(stripe, **stripe_route)
    assert target['ok'] and target['card_delivery'] == route.DELIVERY, target
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                   field='cc-number'))
    assert receipt == dict(ok=True, filled='cc-number', card_delivery=route.DELIVERY)
    assert lab.observer.evaluate("digest('payment-numberInput')", session, await_promise=True) == sha(CARD['number'])


def test_card_element_fills_its_three_inputs_and_never_a_decoy(harness):
    lab, broker = harness.lab, harness.broker
    url = lab.navigate('/card-element')
    lab.wait("document.readyState === 'complete'")
    session = harness.frame_session(CARD_ELEMENT)
    frames = harness.frames(url)
    frame = {f['origin']: f for f in frames['frames']}['https://js.stripe.com']
    stripe_route = dict(processor='stripe', processor_protocol=1)

    def pin(selector, field):
        return broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=frames['page_id'],
                                    frame_id=frame['frame_id'], top_url=url, selector=selector, field=field,
                                    route='extension', **stripe_route))
    assert pin('form > input:first-child', 'cc-number') == card_failure()   # Decoy.
    assert pin('input[name="cardnumber"]', 'cc-exp') == card_failure()      # Wrong field.
    for name, field, options, expected in (('cardnumber', 'cc-number', {}, CARD['number']),
                                           ('exp-date', 'cc-exp', {'format': 'MM/YY'}, '09/31'),
                                           ('cvc', 'cc-csc', {}, CARD['csc'])):
        target = pin(f'input[name="{name}"]', field)
        assert target['ok'] and target['card_delivery'] == route.DELIVERY, target
        handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
        receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                       field=field, **options))
        assert receipt == dict(ok=True, filled=field, card_delivery=route.DELIVERY)
        assert lab.observer.evaluate(f"digestName('{name}')", session, await_promise=True) == sha(expected)
    for index in (0, 1):
        assert lab.observer.evaluate(f"digestName('hidden', {index})", session, await_promise=True) == EMPTY


def test_user_click_route_fills_the_focused_login_and_skips_hidden_fields(harness):
    lab, broker = harness.lab, harness.broker
    lab.navigate('/login')
    harness.focus('username')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'] and found['kind'] == 'login', found
    assert [set(e) for e in found['entries']] == [{'index', 'title', 'username'}]
    assert PASSWORD not in json.dumps(found)
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result == {'ok': True}
    assert lab.digest('username') == sha(USERNAME) and lab.digest('password') == sha(PASSWORD)
    # A reused selection fills nothing.
    again = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert again['ok'] is False
    # Hidden focused field: no match is offered and nothing is filled.
    lab.navigate('/hidden')
    harness.focus('password')
    hidden = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert hidden['ok'] is False and lab.digest('password') == EMPTY


def test_user_click_route_reports_a_locked_broker(harness):
    lab, broker = harness.lab, harness.broker
    vault, broker.vault = broker.vault, None
    try:
        lab.navigate('/login')
        harness.focus('password')
        state = harness.worker_call('popupState()')
        assert state['connected'] and state['paired'] and state['locked'] is True
        tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
        found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
        assert found['ok'] is False and found['error'] == 'vault locked'
    finally:
        broker.vault = vault


def test_user_click_route_fills_a_masked_security_code_as_a_card(harness):
    lab = harness.lab
    lab.navigate('/masked')
    harness.focus('csc')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'] and found['kind'] == 'card', found
    assert set(found['entries'][0]) == {'index', 'title', 'brand', 'last_four'}
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result == {'ok': True}
    assert lab.digest('csc') == sha(CARD['csc']) and lab.digest('number') == sha(CARD['number'])


def test_user_click_route_refuses_a_field_changed_after_the_probe(harness):
    lab = harness.lab
    lab.navigate('/login')
    harness.focus('username')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'], found
    lab.evaluate("document.getElementById('password').type = 'text'")
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result['ok'] is False
    assert lab.digest('username') == EMPTY and lab.digest('password') == EMPTY


def test_user_click_route_reports_a_page_that_clears_a_filled_field(harness):
    lab = harness.lab
    lab.navigate('/clearing')
    harness.focus('number')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'] and found['kind'] == 'card', found
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result['ok'] is False and 'incomplete' in result['error']


def test_user_click_route_reports_a_page_that_replaces_a_filled_field(harness):
    lab = harness.lab
    lab.navigate('/replacing')
    harness.focus('number')
    tab = "(await chrome.tabs.query({url: 'https://signup.example.com/*'}))[0].id"
    found = harness.worker_call(f'(async () => popupProbe({{tab_id: {tab}}}))()')
    assert found['ok'] and found['kind'] == 'card', found
    result = harness.worker_call(f'popupFill({{session: {json.dumps(found["session"])}, index: 0}})')
    assert result['ok'] is False and 'incomplete' in result['error']


@pytest.fixture
def pairing_page(harness, certificates):
    """The broker's real Windows loopback HTTPS handler, for a browser form submit."""
    import ssl
    from akdbx.web_unlock import UnlockState, handler_for
    from akdbx.windows_unlock import WindowsHTTPServer
    broker = harness.broker
    state = UnlockState(broker, None, None, lambda *_: pytest.fail('the broker is already unlocked'))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*certificates)
    server = WindowsHTTPServer(('127.0.0.1', 0), handler_for(state), context, '')
    server.local_origin = f'https://127.0.0.1:{server.server_port}'
    server.write_manager = broker.writes
    previous = broker.writes.public_base
    broker.writes.public_base = server.local_origin
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.local_origin
    finally:
        broker.writes.public_base = previous
        server.shutdown()
        server.server_close()
        thread.join(3)


def test_pairing_page_form_submit_pairs_the_extension_in_a_real_browser(harness, pairing_page):
    """Regression: the page's referrer policy made the browser send Origin: null on POST."""
    lab, broker = harness.lab, harness.broker
    master = 'Synthetic master Ω 42'
    broker.vault.password = master
    broker.extension.approved.clear()
    [channel] = broker.extension.channels.values()
    url = broker.extension._pairing_info(channel.digest)['url']
    assert url.startswith(pairing_page + '/extension/pair?token=')
    lab.observer.call('Page.navigate', {'url': url}, lab.session)
    lab.wait("document.readyState === 'complete' && !!document.querySelector('form')")
    assert lab.evaluate('document.body.innerText').count(route.pairing_code(channel.digest)) == 1
    lab.evaluate(f"""document.getElementById('password').value = {json.dumps(master)};
        document.querySelector('input[name=confirmed]').checked = true;
        document.querySelector('form button:not([type=button])').click();""")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if lab.evaluate("document.readyState === 'complete' && !document.querySelector('form')"):
                break
        except AssertionError:
            pass  # The page is navigating.
        time.sleep(.1)
    text = lab.evaluate('document.body.innerText')
    assert 'paired with akdbx' in text, text
    assert broker.extension.approved == [channel.digest]


# ----- secret capture, frame owners and cover checks (0.32.0) ---------------------------
def read_pin(harness, url, **extra):
    listing = harness.frames(url)
    request = dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                   frame_id=listing['main_frame_id'], top_url=url, selector='#secret', mode='read', capture_protocol=1,
                   route='extension')
    request.update(extra)
    return harness.broker.dispatch(request)


def trusted(harness):
    """The worker binds the broker identity key over HTTPS; reads need it for the signed connection."""
    deadline = time.monotonic() + 30
    read = "chrome.storage.local.get('broker_trust').then(found => found.broker_trust ?? null)"
    while harness.worker_call(read) is None:
        assert time.monotonic() < deadline, 'the extension did not bind the broker identity key'
        time.sleep(.2)


def read_value(harness, pin, origin=ORIGIN):
    """Run the broker's own extension read for a pin token; the test compares digests only."""
    from akdbx.totp import https_origin
    trusted(harness)
    broker = harness.broker
    target = broker.extension.take(pin['target'], 'read')
    assert target is not None
    try:
        value = broker.extension.read(target, {https_origin(origin)}, lambda: True, broker.clock() + 4)
    except Exception:
        return None
    finally:
        target.close()
    return sha(value)


def test_secret_capture_reads_the_focused_secret_through_the_extension(harness):
    lab = harness.lab
    url = lab.navigate('/secret')
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert pin['ok'] and pin['target_delivery'] == route.DELIVERY, pin
    assert read_value(harness, pin) == sha(SECRET)
    # A read pin is single-use, and a fill command cannot take it.
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert harness.broker.dispatch(dict(action='fill', handle=search(harness.broker), mode='password',
                                        target=pin['target'], target_protocol=1))['ok'] is False
    assert harness.broker.extension.take(pin['target'], 'read') is None


def test_secret_capture_refuses_unfocused_selected_and_changed_secrets(harness):
    lab = harness.lab
    url = lab.navigate('/secret')
    assert read_pin(harness, url) == failure()  # Not focused.
    harness.focus('secret')
    lab.evaluate("getSelection().selectAllChildren(document.getElementById('secret'))")
    assert read_pin(harness, url) == failure()  # A selection would reach PRIMARY on X11.
    lab.evaluate('getSelection().removeAllRanges()')
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert pin['ok'], pin
    lab.evaluate("document.getElementById('secret').textContent = 'SynthOther-replaced'")
    assert read_value(harness, pin) is None


COVERED_SECRETS = ['/secret-covered', '/secret-covered-important', '/secret-shadow-cover', '/secret-shadow-important',
                   '/secret-inert', '/secret-interactivity', '/secret-shadow-pseudo', '/secret-inert-styled',
                   '/secret-modal-cover', '/secret-inert-text', '/secret-inert-pseudo', '/secret-inert-slot',
                   '/secret-popover-backdrop', '/secret-popover-exit', '/secret-popover-holds-modal',
                   '/secret-details-content', '/secret-scroll-button', '/secret-scroll-marker-group',
                   '/secret-view-transition', '/secret-meter-bar', '/secret-veil', '/secret-own-pseudo',
                   '/secret-own-pseudo-currentcolor', '/secret-own-outline', '/secret-own-scroll-markers']
CHALLENGE_GONE = "getComputedStyle(document.getElementById('secret')).boxShadow === 'none'"


def open_page(harness, page):
    lab = harness.lab
    url = lab.navigate(page)
    if 'window.ready' in PAGES[page]:
        lab.wait('window.ready === true')
    return url


@pytest.mark.usefixtures('enhanced')
@pytest.mark.parametrize('page', COVERED_SECRETS)
def test_secret_capture_refuses_a_cover(harness, page):
    lab = harness.lab
    url = open_page(harness, page)
    harness.focus('secret')
    assert read_pin(harness, url) == failure()
    # The challenge colour ends with the check, and the page's DOM got no marker.
    assert lab.evaluate(CHALLENGE_GONE)
    assert lab.evaluate("[...document.getElementById('secret').attributes].map(a => a.name).sort().join() === 'id,tabindex'")


@pytest.mark.usefixtures('enhanced')
@pytest.mark.parametrize('page', ['/secret-modal', '/secret-cookie-popover', '/secret-inert-background',
                                  '/secret-copy-button'])
def test_a_secret_on_an_ordinary_page_reads(harness, page):
    lab = harness.lab
    url = open_page(harness, page)
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert pin['ok'], pin
    assert read_value(harness, pin) == sha(SECRET)
    assert lab.evaluate(CHALLENGE_GONE)


@pytest.mark.usefixtures('enhanced')
def test_a_cover_added_after_the_pin_refuses_the_read(harness):
    lab = harness.lab
    for cover in (f'<div style="{COVER}"></div>', f'<div inert style="{COVER.replace(";pointer-events:none", "")}"></div>'):
        url = lab.navigate('/secret-cookie-popover')
        harness.focus('secret')
        pin = read_pin(harness, url)
        assert pin['ok'], pin
        lab.evaluate(f"document.body.insertAdjacentHTML('beforeend', {json.dumps(cover)})")
        assert read_value(harness, pin) is None


def test_with_enhanced_security_off_no_screenshot_is_taken_and_the_dom_hit_test_still_runs(harness):
    """The default. Fills and reads work as in fill extension 0.4.0: the DOM hit test refuses an
    ordinary cover, and a click-through cover passes it, as it passes the CDP route's read pin."""
    lab, broker = harness.lab, harness.broker
    assert harness.worker_call(SETTINGS) is None
    url = lab.navigate('/secret-opaque-cover')
    harness.focus('secret')
    assert read_pin(harness, url) == failure()
    url = lab.navigate('/secret-covered')
    harness.focus('secret')
    # With enhanced security on, this click-through cover refuses (test_secret_capture_refuses_a_cover).
    pin = read_pin(harness, url)
    assert pin['ok'], pin
    assert read_value(harness, pin) == sha(SECRET)
    target = card_pin(harness, lab.navigate('/card-covered'))
    assert target['ok'], target
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                field='cc-number'))['ok']
    assert lab.digest('number') == sha(CARD['number'])


def test_enhanced_security_without_the_screenshot_access_refuses_every_checked_pin(harness):
    """On, but the browser holds no <all_urls> (not granted, or removed later): nothing is checked, so nothing fills."""
    lab = harness.lab
    set_enhanced(harness, True)
    url = lab.navigate('/secret')
    harness.focus('secret')
    assert read_pin(harness, url) == failure()
    assert card_pin(harness, lab.navigate('/card-label')) == card_failure()
    # Logins keep their own checks only, as before.
    url = lab.navigate('/login')
    listing = harness.frames(url)
    harness.focus('password')
    assert harness.broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                        frame_id=listing['main_frame_id'], top_url=url, selector='#password',
                                        mode='password', route='extension'))['ok']
    set_enhanced(harness, False)
    url = lab.navigate('/secret')
    harness.focus('secret')
    assert read_pin(harness, url)['ok']


def extension_page(harness, path):
    """A session in the extension page at `path`, opened by the browser or by the test."""
    observer = harness.lab.observer
    url = route.EXTENSION_ORIGIN.rstrip('/') + '/' + path
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        found = [t for t in observer.call('Target.getTargets')['targetInfos'] if t['type'] == 'page' and t['url'] == url]
        if found:
            session = observer.call('Target.attachToTarget', dict(targetId=found[0]['targetId'], flatten=True))['sessionId']
            # The new tab's first document is about:blank: wait for the extension page itself.
            if observer.evaluate(f"location.href === {json.dumps(url)} && document.readyState === 'complete'", session):
                return session
        time.sleep(.05)
    raise AssertionError(path + ' did not open')


def click(harness, session, selector):
    """A trusted mouse click at the centre of an element, as a user's click."""
    observer = harness.lab.observer
    observer.call('Page.bringToFront', session=session)
    x, y = observer.evaluate(f"(r => [r.x + r.width / 2, r.y + r.height / 2])"
                             f"(document.querySelector({json.dumps(selector)}).getBoundingClientRect())", session)
    for kind in ('mousePressed', 'mouseReleased'):
        observer.call('Input.dispatchMouseEvent', dict(type=kind, x=x, y=y, button='left', clickCount=1), session=session)


@pytest.mark.screenshot_access
def test_the_cog_opens_the_settings_and_the_switch_turns_enhanced_security_on_and_off(harness):
    lab, observer = harness.lab, harness.lab.observer
    observer.call('Target.createTarget', dict(url=route.EXTENSION_ORIGIN.rstrip('/') + '/popup.html'))
    click(harness, extension_page(harness, 'popup.html'), '#settings')
    options = extension_page(harness, 'options.html')
    state = "(() => { const t = document.getElementById('enhanced'), s = document.getElementById('enhanced-status');" \
            " return {disabled: t.disabled, checked: t.checked, status: s.hidden ? '' : s.textContent}; })()"
    deadline = time.monotonic() + 5
    while observer.evaluate(state, options)['disabled']:
        assert time.monotonic() < deadline
        time.sleep(.05)
    # Off by default. This test build already holds the access, so the page says that it stays.
    off = observer.evaluate(state, options)
    assert off['checked'] is False and off['status'].startswith('Off: akdbx takes no screenshots'), off
    assert 'Enhanced security' in observer.evaluate("document.querySelector('label[for=enhanced]').textContent", options)
    click(harness, options, '#enhanced')
    deadline = time.monotonic() + 5
    while harness.worker_call(SETTINGS) != dict(enhanced_security=True):
        assert time.monotonic() < deadline, harness.worker_call(SETTINGS)
        time.sleep(.05)
    assert observer.evaluate(state, options) == dict(disabled=False, checked=True, status='')
    # The service worker reads the setting: a click-through cover now refuses.
    observer.call('Page.bringToFront', session=lab.session)
    url = lab.navigate('/secret-covered')
    harness.focus('secret')
    assert read_pin(harness, url) == failure()
    click(harness, options, '#enhanced')
    deadline = time.monotonic() + 5
    while harness.worker_call(SETTINGS) != dict(enhanced_security=False):
        assert time.monotonic() < deadline
        time.sleep(.05)
    found = observer.evaluate(state, options)
    assert found['checked'] is False and found['status'].startswith('Off: akdbx takes no screenshots'), found


ORACLES = """(async () => {
  const [tab] = await chrome.tabs.query({url: URL_});
  const frames = await chrome.webNavigation.getAllFrames({tabId: tab.id});
  const documentId = frames.find(f => f.frameId === 0).documentId;
  const chain = await chainFor(tab.id, documentId);
  await inject(tab.id, documentId);
  const pinId = await run(tab.id, documentId, (kind, spec, url) => globalThis.__akdbxContent.pin(kind, spec, url, url),
    [KIND, SPEC, URL_]);
  if (typeof pinId !== 'string') return null;
  try {
    let start = performance.now();
    const occlusion = await run(tab.id, documentId, id => globalThis.__akdbxContent.clear(id), [pinId]);
    const occlusionMs = Math.round(performance.now() - start);
    await new Promise(resolve => setTimeout(resolve, 600));  // The screenshot quota of the test before.
    start = performance.now();
    const pixels = await challenge(tab.id, chain, pinId, null);
    return {occlusion, pixels, occlusionMs, pixelsMs: Math.round(performance.now() - start)};
  } finally {
    await run(tab.id, documentId, id => globalThis.__akdbxContent.release(id), [pinId]);
  }
})()"""


def oracles(harness, page):
    """Each of the two cover checks alone, on a content-script pin that skips the worker's own decision."""
    url = open_page(harness, page)
    card = page.startswith('/card')
    harness.focus('number' if card else 'secret')
    spec = dict(selector='#number', field='cc-number') if card else dict(selector='#secret', frame_origin=None)
    return harness.worker_call(ORACLES.replace('URL_', json.dumps(url)).replace('KIND', json.dumps('card' if card else 'read'))
                               .replace('SPEC', json.dumps(spec)))


@pytest.mark.screenshot_access
def test_each_cover_check_alone_refuses_every_cover_and_one_of_them_passes_every_ordinary_page(harness):
    """The occlusion test and the pixel challenge are independent: every cover fails both. An ordinary
    page passes the occlusion test, or, when something harmless overlaps the box, the pixel challenge."""
    report = {}
    for page in [*COVERED_SECRETS, '/card-covered', '/card-inert']:
        found = report[page] = oracles(harness, page)
        # During a view transition the pin's own DOM checks already refuse: no pin to test.
        # The secret's own ::after is no occluder for a hit test: only the pixel challenge refuses it.
        assert found is None and page == '/secret-view-transition' or (
            found and found['occlusion'] is (page in ('/secret-own-pseudo', '/secret-own-pseudo-currentcolor',
                                                      '/secret-own-outline', '/secret-own-scroll-markers'))
            and found['pixels'] is False), (page, found)
    for page, occlusion in {'/secret': True, '/secret-modal': True, '/secret-inert-background': True,
                            '/card-inert-background': True, '/secret-cookie-popover': False, '/secret-copy-button': False,
                            '/card-label': False, '/card-cookie-popover': False, '/card-clear-layer': False}.items():
        found = report[page] = oracles(harness, page)
        assert found and found['occlusion'] is occlusion and found['pixels'] is True, (page, found)
    print(json.dumps(report, indent=1))


def card_pin(harness, url):
    listing = harness.frames(url)
    return harness.broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=listing['page_id'],
                                        frame_id=listing['main_frame_id'], top_url=url, selector='#number',
                                        field='cc-number', route='extension'))


@pytest.mark.usefixtures('enhanced')
@pytest.mark.parametrize('page', ['/card-label', '/card-cookie-popover', '/card-inert-background', '/card-clear-layer'])
def test_a_card_field_on_an_ordinary_page_fills(harness, page):
    lab, broker = harness.lab, harness.broker
    target = card_pin(harness, lab.navigate(page))
    assert target['ok'], target
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                   field='cc-number'))
    assert receipt == dict(ok=True, filled='cc-number', card_delivery=route.DELIVERY)
    assert lab.digest('number') == sha(CARD['number'])
    assert lab.evaluate("getComputedStyle(document.getElementById('number')).boxShadow === 'none'")


@pytest.mark.usefixtures('enhanced')
def test_card_pins_refuse_a_click_through_cover_and_keep_a_floating_label(harness):
    lab, broker = harness.lab, harness.broker
    assert card_pin(harness, lab.navigate('/card-covered')) == card_failure()
    assert card_pin(harness, lab.navigate('/card-inert')) == card_failure()
    # A cover added after the pin refuses the fill.
    target = card_pin(harness, lab.navigate('/card-label'))
    lab.evaluate(f"document.body.insertAdjacentHTML('beforeend', '<div style=\"{COVER}\"></div>')")
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                field='cc-number')) == card_failure()
    assert lab.digest('number') == EMPTY


def identity_pin(harness, url, selector, field='tel', **extra):
    listing = harness.frames(url)
    harness.focus(selector.lstrip('#'))
    return harness.broker.dispatch(dict(action='pin-identity-target', identity_protocol=1, page_id=listing['page_id'],
                                        frame_id=listing['main_frame_id'], top_url=url, selector=selector,
                                        field=field, route='extension', **extra))


def identity_fill(broker, target, field='tel', **extra):
    handle = broker.dispatch(dict(action='search-identities', identity_protocol=1, query='Synthetic phone',
                                  exact=True))['entries'][0]['handle']
    return broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=handle, target=target,
                                field=field, start_deadline=broker.clock() + 4, **extra))


def test_an_identity_field_without_an_autocomplete_hint_fills_with_an_explicit_purpose(harness):
    """The agent attests the field's purpose; the national format drops the country code for a separate picker."""
    lab, broker = harness.lab, harness.broker
    url = lab.navigate('/phone')
    purpose = dict(field_purpose='tel')
    # Without the attestation, no hint, "on", "off", another detail and a sub-token all refuse, as before.
    for selector in ('#phone', '#phone-on', '#phone-off', '#phone-email', '#phone-national'):
        assert identity_pin(harness, url, selector) == card_failure(kind='identity'), selector
    # With it, a conflicting hint and "off" (without its own flag) still refuse; a purpose for another field refuses.
    for selector in ('#phone-email', '#phone-national', '#phone-off'):
        assert identity_pin(harness, url, selector, **purpose) == card_failure(kind='identity'), selector
    assert identity_pin(harness, url, '#phone-email', field='email', **purpose) == card_failure(kind='identity')
    assert identity_pin(harness, url, '#phone', allow_autocomplete_off=True) == card_failure(kind='identity')
    assert lab.untouched()
    # No hint: the saved number goes in without + and country code; the stored value is unchanged.
    target = identity_pin(harness, url, '#phone', **purpose)
    assert target['ok'] and target['identity_delivery'] == route.DELIVERY, target
    # A calling code that differs from the saved number's refuses and uses up the pin.
    assert identity_fill(broker, target['target'], format='national', calling_code='49') == card_failure(kind='identity')
    assert lab.digest('phone') == EMPTY
    target = identity_pin(harness, url, '#phone', **purpose)
    receipt = identity_fill(broker, target['target'], format='national', calling_code='44')
    assert receipt == dict(ok=True, filled='tel', identity_delivery=route.DELIVERY)
    assert lab.digest('phone') == sha(PHONE_NATIONAL)
    assert lab.evaluate("document.getElementById('country').value") == '+44'
    # "on" with the purpose fills the saved value as it is.
    target = identity_pin(harness, url, '#phone-on', **purpose)
    assert identity_fill(broker, target['target'])['ok']
    assert lab.digest('phone-on') == sha(PHONE)
    # "off" needs its own flag as well.
    target = identity_pin(harness, url, '#phone-off', allow_autocomplete_off=True, **purpose)
    assert target['ok'], target
    assert identity_fill(broker, target['target'], format='national')['ok']
    assert lab.digest('phone-off') == sha(PHONE_NATIONAL)
    # A hint that changes after the pin refuses the fill.
    lab.evaluate("document.getElementById('phone').value = ''")
    target = identity_pin(harness, url, '#phone', **purpose)
    lab.evaluate("document.getElementById('phone').setAttribute('autocomplete', 'email')")
    assert identity_fill(broker, target['target']) == card_failure(kind='identity')
    assert lab.digest('phone') == EMPTY
    assert lab.digest('phone-email') == EMPTY and lab.digest('phone-national') == EMPTY
    assert not any(e['trusted'] for e in lab.evaluate('syntheticEvents'))


def test_an_older_extension_never_gets_an_identity_purpose_pin(harness):
    """Fill extension 0.6.0 ignores the purpose; the broker refuses before it asks such a browser."""
    lab, broker = harness.lab, harness.broker
    url = lab.navigate('/phone')
    [channel] = broker.extension.channels.values()
    reported = channel.version
    channel.version = '0.6.0'
    try:
        assert identity_pin(harness, url, '#phone', field_purpose='tel') == card_failure(kind='identity')
    finally:
        channel.version = reported
    assert identity_pin(harness, url, '#phone', field_purpose='tel')['ok']


def same_site_frame(harness, url, ready='password'):
    """An isolated world in the same-site login frame (same process as the top, so no own target)."""
    lab = harness.lab
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        pending, found = [lab.observer.call('Page.getFrameTree', session=lab.session)['frameTree']], []
        while pending:
            node = pending.pop()
            pending.extend(node.get('childFrames', []))
            if node['frame']['url'] == url:
                found.append(node['frame']['id'])
        if found:
            world = lab.observer.call('Page.createIsolatedWorld', dict(frameId=found[0], worldName='akdbx-test-observer'),
                                      lab.session)['executionContextId']

            def evaluate(expression, await_promise=False):
                response = lab.observer.call('Runtime.evaluate', dict(expression=expression, contextId=world,
                                                                      returnByValue=True, awaitPromise=await_promise),
                                             lab.session)
                assert 'exceptionDetails' not in response, response['exceptionDetails'].get('text')
                return response['result'].get('value')
            if evaluate(f"document.readyState === 'complete' && (!{json.dumps(ready)} || !!document.getElementById({json.dumps(ready)}))"):
                return evaluate
        time.sleep(.05)
    raise AssertionError('same-site login frame missing')


FRAME_DIGEST = ("crypto.subtle.digest('SHA-256', new TextEncoder().encode(document.getElementById('password').value))"
                ".then(h => Array.from(new Uint8Array(h), b => b.toString(16).padStart(2, '0')).join(''))")


def frame_password_pin(harness, url):
    lab, broker = harness.lab, harness.broker
    lab.wait("document.readyState === 'complete'")
    frame = same_site_frame(harness, 'https://auth.example.com/login')
    frame("window.focus(); document.getElementById('password').focus()")
    listing = harness.frames(url)
    login = next(f for f in listing['frames'] if f['origin'] == 'https://auth.example.com' and f['visible_fields']
                 and f['visible_fields']['password'])
    return frame, broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                         frame_id=login['frame_id'], top_url=url, selector='#password', mode='password',
                                         frame_protocol=1, frame_origin='https://auth.example.com', route='extension'))


def auth_handle(broker):
    return broker.dispatch(dict(action='search', query='auth.example.com'))['entries'][0]['handle']


def test_a_child_frame_login_needs_a_visible_iframe_owner(harness):
    lab, broker = harness.lab, harness.broker
    session, pin = frame_password_pin(harness, lab.navigate('/framed-visible'))
    assert pin['ok'], pin
    receipt = broker.dispatch(dict(action='fill', handle=auth_handle(broker), mode='password', target=pin['target'],
                                   target_protocol=1))
    assert receipt == dict(ok=True, filled='password', target_delivery=route.DELIVERY)
    assert session(FRAME_DIGEST, True) == sha(PASSWORD)
    # The owner <iframe> is transparent: the field inside looks visible to its own document only.
    session, pin = frame_password_pin(harness, lab.navigate('/framed-hidden'))
    assert pin == failure()
    assert session(FRAME_DIGEST, True) == EMPTY
    # The owner is hidden after the pin: the fill refuses.
    session, pin = frame_password_pin(harness, lab.navigate('/framed-visible'))
    assert pin['ok'], pin
    lab.evaluate("document.getElementById('login-frame').style.opacity = '0'")
    assert broker.dispatch(dict(action='fill', handle=auth_handle(broker), mode='password', target=pin['target'],
                                target_protocol=1)) == failure()
    assert session(FRAME_DIGEST, True) == EMPTY


def test_a_page_cannot_lend_a_decoy_iframe_to_a_hidden_login_frame(harness):
    lab = harness.lab
    url = lab.navigate('/framed-forward')
    lab.wait("document.getElementById('decoy').contentDocument?.readyState === 'complete'")
    frame, pin = frame_password_pin(harness, url)
    assert pin == failure()
    assert frame(FRAME_DIGEST, True) == EMPTY


def test_a_read_pin_never_takes_a_selector_that_could_test_the_secret(harness):
    """The pin call comes through the host unsealed: the extension itself refuses attribute selectors."""
    lab = harness.lab
    url = lab.navigate('/secret')
    harness.focus('secret')
    listing = harness.frames(url)
    tab = int(listing['page_id'].split('.')[1])
    for selector in ('#secret', '#secret:not([id=x])', 'code[id^="se"]', 'body:has(code) #secret'):
        call = json.dumps(dict(tab_id=tab, document_id=listing['main_frame_id'], top_url=url, frame_url=None,
                               kind='read', spec=dict(selector=selector, frame_origin=None)))
        result = harness.worker_call(f'pin({call}).then(r => (r.ok && release({{tab_id: {tab}, document_id: '
                                     f'{json.dumps(listing["main_frame_id"])}, pin_id: r.pin_id}}), r.ok))')
        assert result is (selector == '#secret'), selector


def test_the_extension_reads_secrets_only_in_the_top_document(harness):
    lab = harness.lab
    url = lab.navigate('/framed-secret')
    lab.wait("document.readyState === 'complete'")
    frame = same_site_frame(harness, 'https://auth.example.com/secret', ready='secret')
    frame("window.focus(); document.getElementById('secret').focus()")
    listing = harness.frames(url)
    keys = next(f for f in listing['frames'] if f['origin'] == 'https://auth.example.com')
    assert read_pin(harness, url, frame_id=keys['frame_id'], frame_protocol=1,
                    frame_origin='https://auth.example.com') == failure()
    assert read_pin(harness, url, frame_id=keys['frame_id']) == failure()


def test_a_hidden_frame_in_a_shadow_root_cannot_borrow_a_decoy_owner(harness):
    lab = harness.lab
    url = lab.navigate('/framed-shadow-decoy')
    frame = same_site_frame(harness, 'https://auth.example.com/login')
    frame("window.focus(); document.getElementById('password').focus()")
    listing = harness.frames(url)
    login = next(f for f in listing['frames'] if f['origin'] == 'https://auth.example.com' and f['visible_fields']
                 and f['visible_fields']['password'])
    pin = harness.broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                       frame_id=login['frame_id'], top_url=url, selector='#password', mode='password',
                                       frame_protocol=1, frame_origin='https://auth.example.com', route='extension'))
    assert pin == failure()
    assert frame(FRAME_DIGEST, True) == EMPTY


def test_a_page_cannot_stop_an_owner_probe_to_lend_a_decoy(harness):
    lab = harness.lab
    url = lab.navigate('/framed-suppress')
    same_site_frame(harness, 'https://auth.example.com/decoy-relay', ready='')  # Both frames loaded.
    frame = same_site_frame(harness, 'https://auth.example.com/login-suppress')
    frame("window.focus(); document.getElementById('password').focus()")
    listing = harness.frames(url)
    login = next(f for f in listing['frames'] if f['origin'] == 'https://auth.example.com' and f['visible_fields']
                 and f['visible_fields']['password'])
    pin = harness.broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
                                       frame_id=login['frame_id'], top_url=url, selector='#password', mode='password',
                                       frame_protocol=1, frame_origin='https://auth.example.com', route='extension'))
    assert pin == failure()


def framed_card_pin(harness, page):
    lab, broker = harness.lab, harness.broker
    url = lab.navigate(page)
    lab.wait("document.getElementById('pay').contentDocument?.readyState === 'complete'")
    listing = harness.frames(url)
    child = next(f for f in listing['frames'] if f['depth'] == 1)
    return url, broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=listing['page_id'],
                                     frame_id=child['frame_id'], top_url=url, selector='#number', field='cc-number',
                                     route='extension'))


@pytest.mark.usefixtures('enhanced')
def test_a_card_in_a_same_origin_child_frame_needs_every_parent_clear(harness):
    lab, broker = harness.lab, harness.broker
    url, target = framed_card_pin(harness, '/card-frame')
    assert target['ok'], target
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                field='cc-number'))['ok']
    assert lab.evaluate("document.getElementById('pay').contentWindow.digest('number')", await_promise=True) == sha(CARD['number'])
    for page in ('/card-frame-shadow', '/card-frame-inert'):
        assert framed_card_pin(harness, page)[1] == card_failure(), page


def processor_pin(harness, page):
    lab, broker = harness.lab, harness.broker
    url = lab.navigate(page)
    lab.wait("document.readyState === 'complete'")
    session = harness.frame_session(STRIPE)
    lab.observer.evaluate("document.getElementById('payment-numberInput').focus()", session)
    frames = harness.frames(url)
    stripe = {f['origin']: f for f in frames['frames']}['https://js.stripe.com']
    return session, broker.dispatch(dict(action='pin-card-target', card_protocol=1, page_id=frames['page_id'],
                                         frame_id=stripe['frame_id'], top_url=url, selector='#payment-numberInput',
                                         field='cc-number', route='extension', processor='stripe', processor_protocol=1))


@pytest.mark.usefixtures('enhanced')
def test_a_processor_field_refuses_an_inert_cover_in_the_merchant_page(harness):
    assert processor_pin(harness, '/checkout-inert')[1] == card_failure()


@pytest.mark.usefixtures('enhanced')
def test_an_ancestor_outline_over_a_field_or_a_processor_frame_refuses(harness):
    """The occlusion test does not count an ancestor's own paint; the pixel challenge sees it."""
    lab = harness.lab
    assert card_pin(harness, lab.navigate('/card-outline')) == card_failure()
    assert lab.digest('number') == EMPTY
    assert processor_pin(harness, '/checkout-outline')[1] == card_failure()


@pytest.mark.usefixtures('enhanced')
@pytest.mark.parametrize('page', ['/secret-hidden-pseudo', '/secret-list-item', '/secret-list-item-no-marker',
                                  '/secret-hidden-scroll-markers'])
def test_generated_content_that_draws_nothing_does_not_refuse(harness, page):
    lab = harness.lab
    url = lab.navigate(page)
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert pin['ok'], pin
    assert read_value(harness, pin) == sha(SECRET)


@pytest.mark.usefixtures('enhanced')
def test_a_long_token_wrapped_over_many_lines_reads(harness):
    lab = harness.lab
    url = lab.navigate('/secret-wrapped')
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert pin['ok'], pin
    assert read_value(harness, pin) == sha('Synth' + 'abcdefghij' * 40)


@pytest.mark.usefixtures('enhanced')
def test_a_processor_field_fills_when_a_merchant_element_overlaps_another_part_of_the_frame(harness):
    """The browser reports the whole frame as possibly covered; the pixel challenge shows the field itself."""
    lab, broker = harness.lab, harness.broker
    session, target = processor_pin(harness, '/checkout-corner')
    assert target['ok'], target
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    receipt = broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                   field='cc-number'))
    assert receipt == dict(ok=True, filled='cc-number', card_delivery=route.DELIVERY)
    assert lab.observer.evaluate("digest('payment-numberInput')", session, await_promise=True) == sha(CARD['number'])
    # A cover in the merchant page after the pin refuses the fill.
    session, target = processor_pin(harness, '/checkout-corner')
    assert target['ok'], target
    lab.evaluate(f"document.body.insertAdjacentHTML('beforeend', '<div style=\"{COVER}\"></div>')")
    assert broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=target['target'],
                                field='cc-number')) == card_failure()
    assert lab.observer.evaluate("digest('payment-numberInput')", session, await_promise=True) == EMPTY


def test_a_grouped_authenticator_setup_key_reads_and_prose_refuses(harness):
    """capture-totp reads a setup key printed in groups; other spaced text still refuses at the pin."""
    lab = harness.lab
    url = lab.navigate('/totp-grouped')
    harness.focus('secret')
    pin = read_pin(harness, url)
    assert pin['ok'], pin
    assert read_value(harness, pin) == sha(GROUPED_KEY)
    url = lab.navigate('/totp-prose')
    harness.focus('secret')
    assert read_pin(harness, url) == failure()


# ----- a rebuild in the same folder ------------------------------------------------
REBUILT = b'\nglobalThis.AKDBX_TEST_REBUILT = true;\n'


def rebuild(monkeypatch, folder, *, keep_version=False, **options):
    """`akdbx extension build` into the same folder from other contents (one more line in background.js).

    ``keep_version``: write the old version, as two builds with other contents and one
    version did before the content stamp. Returns the version written.
    """
    old = extension_host.built_version()
    source = extension_host._source_files
    monkeypatch.setattr(extension_host, '_source_files', lambda host_name=route.HOST_NAME: {
        **source(host_name), 'background.js': source(host_name)['background.js'] + REBUILT})
    extension_host.built_version.cache_clear()
    if keep_version:
        monkeypatch.setattr(extension_host, 'built_version', lambda: old)
    try:
        extension_host.build(folder, **options)
        return extension_host.built_version()
    finally:
        monkeypatch.undo()
        extension_host.built_version.cache_clear()


def worker_value(lab, expression, timeout=30):
    """Evaluate in the extension's running service worker once its script has run; wait for one."""
    deadline = time.monotonic() + timeout
    while True:
        workers = [t for t in lab.observer.call('Target.getTargets')['targetInfos']
                   if t['type'] == 'service_worker' and t['url'].startswith(route.EXTENSION_ORIGIN)]
        try:
            if workers:
                session = lab.observer.call('Target.attachToTarget',
                                            dict(targetId=workers[0]['targetId'], flatten=True))['sessionId']
                # A worker target can appear before its script ran.
                if lab.observer.evaluate("typeof connect === 'function'", session):
                    return lab.observer.evaluate(expression, session, await_promise=True)
        except Exception:
            if time.monotonic() > deadline:
                raise
        assert time.monotonic() < deadline, 'no extension service worker runs'
        time.sleep(.2)


RUNS = '[globalThis.AKDBX_EXTENSION_VERSION, globalThis.AKDBX_TEST_REBUILT === true, typeof staleBuild]'


def test_a_rebuild_with_other_contents_runs_the_new_worker_after_a_browser_restart(private_dir, certificates,
                                                                                   monkeypatch):
    """Chrome keeps a registered worker until the manifest version changes; the content stamp changes it.

    The first rebuild keeps the version, as builds did before the stamp: the restarted
    browser usually still runs the old worker beside the new files on disk (in 3 of 4
    local Chromium 153 runs). The stamped rebuild gives another version, and after the
    next restart the new worker runs.
    """
    binary = extension_browser()
    if binary is None:
        pytest.skip('the extension route tests require Helium, Chrome or Edge')
    if sys.platform != 'win32':
        certificates[1].chmod(0o600)
    folder = Path(private_dir) / 'extension'
    origin = 'https://localhost:9443'
    extension_host.build(folder, unlock_origin=origin)
    first = extension_host.built_version()
    run = dict(binary=binary, extension=folder)
    with chromium_lab(private_dir, *certificates, **run) as lab:
        assert worker_value(lab, RUNS) == [first, False, 'function']
    same = rebuild(monkeypatch, folder, keep_version=True, unlock_origin=origin)
    assert same == first and REBUILT in (folder / 'background.js').read_bytes()
    with chromium_lab(private_dir, *certificates, restart=True, **run) as lab:
        # Usually the cached old worker beside the new files (the defect); Chromium does not always keep it.
        assert worker_value(lab, RUNS) in ([first, False, 'function'], [first, True, 'function'])
    stamped = rebuild(monkeypatch, folder, unlock_origin=origin)
    assert stamped != first and json.loads((folder / 'manifest.json').read_text())['version'] == stamped
    with chromium_lab(private_dir, *certificates, restart=True, **run) as lab:
        # Chromium registers the new worker at startup. Edge on Windows can first start the registered old
        # worker, which then finds the newer build on disk and reloads into it.
        deadline = time.monotonic() + 30
        while (runs := worker_value(lab, RUNS)) != [stamped, True, 'function']:
            assert runs == [first, False, 'function'] and time.monotonic() < deadline, runs
            time.sleep(.2)


def test_a_worker_that_finds_a_newer_build_on_disk_refuses_the_pin_and_reloads_into_it(harness, monkeypatch):
    """A rebuild under a running browser: the next pin names the fix and the worker reloads itself.

    The reload ends the pairing (the worker's key lives in session storage), so the new
    worker attaches unpaired, with the new version, and needs a new pairing.
    """
    [old] = harness.hub.channels.values()
    assert harness.hub._paired_channel() == [old]
    url = harness.lab.evaluate('location.href')
    listing = harness.frames(url)
    harness.focus('password')
    pin = dict(action='pin-password-target', password_protocol=1, page_id=listing['page_id'],
               frame_id=listing['main_frame_id'], top_url=url, selector='#password', mode='password', route='extension')
    assert harness.broker.dispatch(pin)['ok'] is True
    newer = rebuild(monkeypatch, harness.extension, host_name=harness.host_name, unlock_origin=harness.unlock_origin)
    assert newer != old.version
    assert harness.broker.dispatch(pin) == dict(ok=False, error=route.STALE)
    assert old.stale is True and harness.frames(url) == dict(ok=False, error=route.STALE)
    assert harness.broker.dispatch(dict(action='ping'))['extension_browsers'][0]['version_status'] == 'stale'
    deadline = time.monotonic() + 60
    while True:  # One snapshot: the old host may be gone before the new one attaches.
        channels = list(harness.hub.channels.values())
        if len(channels) == 1 and channels[0] is not old:
            break
        assert time.monotonic() < deadline, 'the extension did not reload into the new build'
        time.sleep(.2)
    [new] = channels
    assert new.version == newer and new.stale is False and new.digest != old.digest
    assert harness.hub._paired_channel() == [] and harness.broker.dispatch(dict(action='ping'))['extension_paired'] is False
    assert worker_value(harness.lab, RUNS) == [newer, True, 'function']
