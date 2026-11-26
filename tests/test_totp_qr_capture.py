"""Authenticator enrollment from a setup QR code, in real Chromium, on the CDP and extension routes.

A synthetic enrollment page on https://signup.example.com shows only a QR code
(a PNG <img>, a <canvas> or an inline <svg>) and a "verify the code from the
app" field, the way a site's "Set up authenticator app" step does when it
prints no text key. The broker decodes the code inside the browser
(`pin-password-target --mode read --qr`, `capture-totp --qr`), saves the key as
the entry's pending authenticator in an encrypted synthetic test vault, fills a
code of it into the verify field (`fill-totp --pending`) and, after the page
accepted the code, moves it into `otp` (`commit-totp --site-accepted`).

A cross-origin image (with or without CORS), two codes in one image, a code
that is not an otpauth TOTP URI, an image that is not a code and an element
that changes after the pin all refuse with nothing saved. A fresh synthetic key
is made on every run; no receipt, CLI output or log may contain it or a code.
"""
import base64
import io
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
import time
from types import SimpleNamespace

import pytest
from pykeepass import PyKeePass, create_database

if sys.platform not in ('win32', 'darwin') and not sys.platform.startswith('linux'):
    pytest.skip('native Windows, Linux or macOS required', allow_module_level=True)

import qr_fixture
import test_extension_browser as extension_lab
from akdbx import cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.browser_password import DELIVERY as CDP_PIN_DELIVERY
from akdbx.extension_route import CAPTURE_DELIVERY as EXTENSION_CAPTURE, DELIVERY as EXTENSION_PIN_DELIVERY
from akdbx.local_https import start_local_unlock_server
from akdbx.secrets_capture import CAPTURE_DELIVERY as CDP_CAPTURE
from akdbx.target import failure
from akdbx.totp_capture import OLD_BROKER, PENDING_FIELD, QR_REFUSED, REFUSED
from test_broker import Vault
from test_extension_browser import NoKeys, certificates, enhanced, harness, private_dir, trusted  # noqa: F401
from windows_chromium_lab import ORIGIN, browser_binary, chromium_lab


def b32(raw):
    return base64.b32encode(raw).decode('ascii').rstrip('=')


KEY = b32(secrets.token_bytes(20))
OTHER_KEY = b32(secrets.token_bytes(20))
NEXT_KEY = b32(secrets.token_bytes(20))


def uri(key, kind='totp'):
    return f'otpauth://{kind}/Synthetic:synthetic-octocat?secret={key}&issuer=Synthetic'


URI = uri(KEY)
SECRETS = (KEY, OTHER_KEY, NEXT_KEY, KEY.lower())
VALUES = dict(title='Synthetic QR site', username='synthetic-octocat', url=ORIGIN + '/login', group='Web')
ROWS = qr_fixture.rows(URI)
NEXT_ROWS = qr_fixture.rows(uri(NEXT_KEY))
OTHER_ROWS = qr_fixture.rows(uri(OTHER_KEY))
assert len(ROWS) == len(OTHER_ROWS) == len(NEXT_ROWS)
TWO_ROWS = [a + b for a, b in zip(ROWS, OTHER_ROWS)]
# Two codes of different sizes: jsQR alone then decodes one of them (here the small one), so only the
# broker's second look, after it blanks the first code, refuses the image.
TWO_SIZES = qr_fixture.compose([(ROWS, 5, 0, 0), (OTHER_ROWS, 3, 250, 250)], 400, 400)
PNG = ('image/png', {})
PATH_SVG = qr_fixture.svg(ROWS, kind='path').replace('<svg ', '<svg id="qr" ', 1)
DARK_PATH = re.search(r'<path fill="#000000" d="([^"]*)"/>', PATH_SVG)[1]


def enrollment(body, script=''):
    """The enrollment step: the QR code, the code field, and the site's own check of a code."""
    return f'''<!doctype html><meta charset="utf-8"><title>Synthetic authenticator setup</title>
<style>body{{margin:0;font:14px sans-serif}}img,canvas,svg{{display:block;margin:8px}}</style>
<p>Scan this QR code with your authenticator app.</p>
{body}
<label>Verify the code from the app <input id=otp autocomplete=one-time-code inputmode=numeric></label>
<script>
const KEY = {json.dumps(KEY)};
function unb32(s) {{
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of s) bits += a.indexOf(c).toString(2).padStart(5, '0');
  return new Uint8Array(bits.match(/.{{8}}/g).map(b => parseInt(b, 2)));
}}
async function code(step) {{
  const key = await crypto.subtle.importKey('raw', unb32(KEY), {{name: 'HMAC', hash: 'SHA-1'}}, false, ['sign']);
  const counter = new DataView(new ArrayBuffer(8)); counter.setUint32(4, step);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter.buffer));
  const o = h[19] & 15, n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}}
document.getElementById('otp').addEventListener('input', async e => {{
  const value = e.target.value;
  if (value.length !== 6) return;
  const step = Math.floor(Date.now() / 30000);
  const ok = value === await code(step) || value === await code(step - 1);
  document.body.dataset.result = ok ? 'accepted' : 'rejected';
}});
{script}
window.ready = true;
</script>'''


CANVAS = '''
function draw(rows) {
  const canvas = document.getElementById('qr'), scale = 4, context = canvas.getContext('2d');
  canvas.width = canvas.height = rows.length * scale;
  for (let y = 0; y < rows.length; y++) for (let x = 0; x < rows.length; x++) {
    context.fillStyle = rows[y][x] === '1' ? '#000' : '#fff';
    context.fillRect(x * scale, y * scale, scale, scale);
  }
}
draw(ROWS);
'''
PAGES = {
    '/qr/key.png': (qr_fixture.png(ROWS), *PNG),
    '/qr/key-cors.png': (qr_fixture.png(ROWS), 'image/png', {'Access-Control-Allow-Origin': '*'}),
    '/qr/inverted.png': (qr_fixture.png(ROWS, invert=True), *PNG),
    '/qr/next.png': (qr_fixture.png(NEXT_ROWS), *PNG),
    '/qr/two.png': (qr_fixture.png(TWO_ROWS), *PNG),
    '/qr/two-sizes.png': (qr_fixture.png(TWO_SIZES, 1), *PNG),
    '/qr/hotp.png': (qr_fixture.png(qr_fixture.rows(uri(KEY, 'hotp'))), *PNG),
    '/qr/bare.png': (qr_fixture.png(qr_fixture.rows(KEY)), *PNG),
    '/qr/link.png': (qr_fixture.png(qr_fixture.rows('https://signup.example.com/help/two-factor')), *PNG),
    '/qr/blank.png': (qr_fixture.png(['0' * 40] * 40), *PNG),
    '/qr-img': enrollment('<img id=qr src="/qr/key.png" alt="QR code">'),
    '/qr-inverted': enrollment('<img id=qr src="/qr/inverted.png" alt="QR code">'),
    '/qr-rounded': enrollment('<img id=qr src="/qr/key.png" alt="QR code" style="border-radius:24px">'),
    '/qr-data-url': enrollment('<img id=qr alt="QR code" src="data:image/png;base64,'
                               + base64.b64encode(qr_fixture.png(ROWS)).decode() + '">'),
    '/qr-canvas': enrollment('<canvas id=qr></canvas>', 'const ROWS = ' + json.dumps(ROWS) + ';\n'
                             + 'const NEXT_ROWS = ' + json.dumps(NEXT_ROWS) + ';\n' + CANVAS),
    '/qr-svg': enrollment(qr_fixture.svg(ROWS).replace('<svg ', '<svg id="qr" ', 1)),
    '/qr-svg-path': enrollment(PATH_SVG),
    '/qr-svg-transform': enrollment(qr_fixture.svg(ROWS, kind='transform').replace('<svg ', '<svg id="qr" ', 1)),
    # The code's path data comes from a style sheet (d: path(...)); the attribute holds a decoy dot.
    '/qr-svg-css-d': enrollment('<style>#qr .code{d:path("' + DARK_PATH + '")}</style>'
                                + PATH_SVG.replace('<path fill="#000000" d="' + DARK_PATH + '"/>',
                                                   '<path class="code" fill="#000000" d="M0 0h1v1h-1z"/>')),
    '/qr-svg-stroke': enrollment(qr_fixture.svg(ROWS, kind='stroke').replace('<svg ', '<svg id="qr" ', 1)),
    '/qr-svg-styled': enrollment('<style>#qr .light{fill:#fff} #qr .dark{fill:#111}</style>'
                                 + qr_fixture.svg(ROWS, kind='styled').replace('<svg ', '<svg id="qr" ', 1)),
    # An <svg> with text over the code: not a plain shape, so it refuses rather than draw something else.
    '/qr-svg-text': enrollment(qr_fixture.svg(ROWS).replace('<svg ', '<svg id="qr" ', 1)
                               .replace('</svg>', '<text x="10" y="20">Scan me</text></svg>')),
    # A strict image policy: only the page's own origin, no data: images.
    '/qr-svg-csp': (enrollment(qr_fixture.svg(ROWS).replace('<svg ', '<svg id="qr" ', 1)), 'text/html; charset=utf-8',
                    {'Content-Security-Policy': "img-src 'self'"}),
    '/qr-img-csp': (enrollment('<img id=qr src="/qr/key.png" alt="QR code">'), 'text/html; charset=utf-8',
                    {'Content-Security-Policy': "img-src 'self'"}),
    '/qr-cross-origin': enrollment('<img id=qr src="https://evil.example.net/qr/key.png" alt="QR code">'),
    '/qr-cross-origin-cors': enrollment('<img id=qr crossorigin=anonymous src="https://evil.example.net/qr/key-cors.png" '
                                        'alt="QR code">'),
    # The page draws a cross-origin image (no CORS) into its own canvas: the canvas is tainted.
    '/qr-canvas-tainted': enrollment('<canvas id=qr></canvas>').replace('window.ready = true;', '''
const picture = new Image();
picture.onload = () => {
  const canvas = document.getElementById('qr');
  canvas.width = picture.naturalWidth; canvas.height = picture.naturalHeight;
  canvas.getContext('2d').drawImage(picture, 0, 0);
  window.ready = true;
};
picture.src = 'https://evil.example.net/qr/key.png';'''),
    '/qr-two': enrollment('<img id=qr src="/qr/two.png" alt="QR codes">'),
    '/qr-two-sizes': enrollment('<img id=qr src="/qr/two-sizes.png" alt="QR codes">'),
    '/qr-hotp': enrollment('<img id=qr src="/qr/hotp.png" alt="QR code">'),
    '/qr-bare': enrollment('<img id=qr src="/qr/bare.png" alt="QR code">'),
    '/qr-link': enrollment('<img id=qr src="/qr/link.png" alt="QR code">'),
    '/qr-blank': enrollment('<img id=qr src="/qr/blank.png" alt="QR code">'),
    '/qr-covered': enrollment('<img id=qr src="/qr/key.png" alt="QR code"><div style="position:absolute;left:40px;top:60px;'
                              'width:60px;height:60px;background:#fff"></div>'),
    '/qr-text': enrollment('<code id=qr>' + KEY + '</code>'),
    # An inline setup key whose text box ends below a half pixel: Chromium hit-tests the box only up to
    # round(right) - 1, so a check point at right - 1 misses it. The page tunes the font size to get there.
    # The same at a fractional device scale (Windows 125 %): Chromium snaps boxes in device pixels. The page looks
    # for a font size where an end point of round(right) - 1.5 CSS pixels would fall outside the snapped box.
    '/text-inline-scaled': enrollment('<code id=qr>' + KEY + '</code>', '''
const key = document.getElementById('qr'), z = devicePixelRatio;
for (let size = 10; size < 24 && window.found === undefined; size += 1 / 32) {
  key.style.fontSize = size + 'px';
  const range = document.createRange(); range.selectNodeContents(key);
  const right = range.getClientRects()[0].right, old = Math.round(right) - 1.5;
  if (Math.ceil(old * z) > Math.round(right * z) - 1) window.found = {size, right, z};
}'''),
    '/text-inline-fraction': enrollment('<code id=qr>' + KEY + '</code>', '''
const key = document.getElementById('qr');
for (let size = 13; size < 19 && window.fraction === undefined; size += 1 / 16) {
  key.style.fontSize = size + 'px';
  const range = document.createRange(); range.selectNodeContents(key);
  const right = range.getClientRects()[0].right;
  if (right - Math.floor(right) > 0.05 && right - Math.floor(right) < 0.45) window.fraction = right - Math.floor(right);
}'''),
    # The enrollment step inside a same-origin child frame (CDP route only; the extension reads the top document).
    '/qr-framed': '<!doctype html><meta charset="utf-8"><title>Synthetic settings</title><h1>Security</h1>'
                  '<iframe id=setup src="/qr-img" style="width:520px;height:420px;border:0"></iframe>'
                  '<script>window.ready = true;</script>',
}
extension_lab.PAGES.update(PAGES)  # The extension harness serves its module's pages.


def cdp_binary():
    """The CDP route's browser: AKDBX_TEST_BROWSER or an installed Chrome or Edge, else Chrome or Chromium on Linux."""
    found = browser_binary()
    if found is None and sys.platform != 'win32':
        name = shutil.which('google-chrome') or shutil.which('chromium')
        found = Path(name) if name else None
    return found


MASTER = 'synthetic-qr-master-only'


@pytest.fixture(scope='module')
def template(tmp_path_factory):
    """A synthetic KDBX with a cheap KDF and a 'Web' group; never a real vault."""
    path = tmp_path_factory.mktemp('qr-template') / 'synthetic.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value, params['M'].value = 1, 1024 * 1024
    vault.add_group(vault.root_group, 'Web')
    buffer = io.BytesIO()
    vault.save(buffer)
    path.write_bytes(buffer.getvalue())
    return path


def kdbx(tmp_path, template):
    path = tmp_path / 'synthetic-qr.kdbx'
    shutil.copyfile(template, path)
    vault = PyKeePass(str(path), password=MASTER)
    vault.add_entry(vault.find_groups(name='Web', first=True), VALUES['title'], VALUES['username'],
                    'synthetic-qr-site-password', url=VALUES['url'])
    vault.save()
    return path


@pytest.fixture(params=['cdp', 'extension'])
def qr(request, tmp_path, template, private_dir, certificates):  # noqa: F811
    path = kdbx(tmp_path, template)
    if request.param == 'extension':
        h = request.getfixturevalue('harness')
        broker, lab = h.broker, h.lab
        broker.vault = open_vault_with_password(path, MASTER)  # A real encrypted vault in place of the fake one.
        trusted(h)

        def where(url):
            listing = h.frames(url)
            return dict(page_id=listing['page_id'], frame_id=listing['main_frame_id'], route='extension')

        yield SimpleNamespace(route='extension', broker=broker, lab=lab, where=where, path=path,
                              pin_delivery=EXTENSION_PIN_DELIVERY, capture_delivery=EXTENSION_CAPTURE)
        return
    binary = cdp_binary()
    if binary is None:
        if os.environ.get('AKDBX_REQUIRE_QR_CHROMIUM') == '1':
            pytest.fail('the CDP QR capture tests require Chrome, Chromium or Edge')
        pytest.skip('the CDP QR capture tests require Chrome, Chromium or Edge')
    if sys.platform != 'win32':
        certificates[1].chmod(0o600)
    with chromium_lab(private_dir, *certificates, pages=PAGES, binary=binary) as lab:
        broker = Broker(open_vault_with_password(path, MASTER), NoKeys(), password_browser_profile=lab.profile)
        # The broker's private HTTPS page on loopback, as `akdbx serve` runs it: it activates private writes.
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        unlock, _ = start_local_unlock_server(broker, path, None, f'https://localhost:{port}', *certificates)
        try:
            yield SimpleNamespace(route='cdp', broker=broker, lab=lab, path=path,
                                  where=lambda url: dict(page_id=lab.page_id, frame_id=lab.main_frame),
                                  pin_delivery=CDP_PIN_DELIVERY, capture_delivery=CDP_CAPTURE)
        finally:
            broker.passwords.close()
            unlock.shutdown()
            unlock.server_close()
            broker.unlock_notifications.close()


def open_page(q, page):
    url = q.lab.navigate(page)
    q.lab.wait('window.ready === true')
    return url


def focus(q, selector):
    """Focus the element by script, as the skill says (a picture is not focusable on its own)."""
    q.lab.evaluate(f'(e => {{ e.tabIndex = -1; e.focus(); }})(document.querySelector({json.dumps(selector)}))')
    q.lab.wait(f'document.hasFocus() && document.activeElement === document.querySelector({json.dumps(selector)})')


def pin(q, url, selector='#qr', **extra):
    focus(q, selector)
    request = dict(action='pin-password-target', password_protocol=1, top_url=url, selector=selector, mode='read',
                   capture_protocol=1, read_kind='qr', **q.where(url))
    request.update(extra)
    return q.broker.dispatch({k: v for k, v in request.items() if v is not None})


def handle(q):
    found = [e for e in q.broker.dispatch(dict(action='search', query=VALUES['title']))['entries']
             if e['title'] == VALUES['title']]
    assert len(found) == 1
    return found[0]


def capture(q, target, **extra):
    request = dict(action='capture-totp', totp_capture_protocol=1, target=target, handle=handle(q)['handle'],
                   metadata=dict(VALUES), read_kind='qr')
    request.update(extra)
    return q.broker.dispatch({k: v for k, v in request.items() if v is not None})


def commit(q):
    return q.broker.dispatch(dict(action='commit-totp', totp_capture_protocol=1, handle=handle(q)['handle'],
                                  metadata=dict(VALUES), decision='site-accepted'))


def fill_pending(q, url):
    """Fill a fresh code of the pending key into the page's verify field over the same route."""
    for _ in range(2):
        q.lab.evaluate("otp.value = ''; delete document.body.dataset.result")
        focus(q, '#otp')
        target = q.broker.dispatch(dict(action='pin-password-target', password_protocol=1, top_url=url, selector='#otp',
                                        mode='totp', **q.where(url)))
        assert target['ok'], target
        response = q.broker.dispatch(dict(action='fill-totp', handle=handle(q)['handle'], target=target['target'],
                                          target_protocol=1, target_url=url, pending=True))
        if 'retry_after' not in response:
            return response
        time.sleep(response['retry_after'] + .2)
    raise AssertionError('authenticator code stayed near expiry')


def page_result(q):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = q.lab.evaluate('document.body.dataset.result || null')
        if result:
            return result
        time.sleep(.05)
    return None


def stored(q):
    entry = PyKeePass(str(q.path), password=MASTER).find_entries(title=VALUES['title'], first=True)
    props = entry.custom_properties
    return entry.otp, props.get(PENDING_FIELD), (entry.is_custom_property_protected(PENDING_FIELD)
                                                 if PENDING_FIELD in props else None)


def nothing_saved(q):
    assert stored(q) == (None, None, None)
    assert 'totp_pending' not in handle(q)
    return True


def clean(*items):
    text = json.dumps(items, default=str)
    for value in SECRETS:
        assert value not in text
    return True


def receipt(q):
    return dict(ok=True, state='pending', totp_configured=False, metadata=VALUES, capture_delivery=q.capture_delivery)


@pytest.mark.parametrize('page', ['/qr-img', '/qr-canvas', '/qr-svg'])
def test_a_qr_code_on_the_entry_origin_saves_a_pending_key_that_commit_promotes(qr, page, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    url = open_page(qr, page)
    pinned = pin(qr, url)
    assert pinned == dict(ok=True, target=pinned.get('target'), expires_in=30, target_delivery=qr.pin_delivery), pinned
    captured = capture(qr, pinned['target'])
    assert captured == receipt(qr), captured
    otp, pending, protected = stored(qr)
    assert otp is None and pending.startswith('otpauth://totp/') and 'secret=' + KEY in pending and protected is True
    assert handle(qr).get('totp_pending') is True
    assert capture(qr, pinned['target'])['ok'] is False  # The pin was single use.
    filled = fill_pending(qr, url)
    assert filled['ok'] is True and filled['filled'] == 'totp', filled
    assert page_result(qr) == 'accepted'
    saved = commit(qr)
    assert saved == dict(ok=True, state='saved', replaced=False, metadata=VALUES), saved
    otp, pending, _ = stored(qr)
    assert pending is None and 'secret=' + KEY in otp
    listed = handle(qr)
    assert listed['totp_configured'] is True and 'totp_pending' not in listed
    out = capsys.readouterr()
    assert clean(pinned, captured, filled, saved, listed, out.out, out.err, caplog.text)


@pytest.mark.parametrize('page', ['/qr-inverted', '/qr-data-url', '/qr-svg-csp', '/qr-img-csp', '/qr-svg-path',
                                  '/qr-svg-stroke', '/qr-svg-styled', '/qr-svg-transform', '/qr-svg-css-d'])
def test_other_code_forms_and_a_strict_image_policy_capture(qr, page):
    url = open_page(qr, page)
    pinned = pin(qr, url)
    assert pinned['ok'], pinned
    assert capture(qr, pinned['target']) == receipt(qr)
    assert 'secret=' + KEY in stored(qr)[1]


@pytest.mark.parametrize('page', ['/qr-cross-origin', '/qr-cross-origin-cors', '/qr-canvas-tainted', '/qr-two',
                                  '/qr-two-sizes', '/qr-blank', '/qr-covered', '/qr-text', '/qr-svg-text'])
def test_a_cross_origin_image_two_codes_no_code_a_cover_or_text_refuse_the_pin(qr, page):
    url = open_page(qr, page)
    if page.startswith('/qr-cross-origin'):
        qr.lab.wait("document.getElementById('qr').complete && document.getElementById('qr').naturalWidth > 0")
    refused = pin(qr, url)
    assert refused == failure(), refused
    assert nothing_saved(qr) and clean(refused)


@pytest.mark.parametrize('page', ['/qr-hotp', '/qr-bare', '/qr-link'])
def test_a_code_that_is_not_an_otpauth_totp_uri_saves_nothing(qr, page):
    url = open_page(qr, page)
    pinned = pin(qr, url)
    assert pinned['ok'], pinned  # One readable code: the broker, not the page, decides what it holds.
    refused = capture(qr, pinned['target'])
    assert refused == dict(ok=False, error=QR_REFUSED), refused
    assert nothing_saved(qr) and clean(refused)


def test_an_element_changed_after_the_pin_saves_nothing(qr):
    # The page draws another code into the same canvas: no DOM change, other pixels.
    url = open_page(qr, '/qr-canvas')
    pinned = pin(qr, url)
    assert pinned['ok'], pinned
    qr.lab.evaluate('draw(NEXT_ROWS)')
    assert capture(qr, pinned['target']) == dict(ok=False, error=QR_REFUSED)
    # The page points the image at another code.
    url = open_page(qr, '/qr-img')
    pinned = pin(qr, url)
    assert pinned['ok'], pinned
    qr.lab.evaluate("document.getElementById('qr').src = '/qr/next.png'")
    qr.lab.wait("document.getElementById('qr').complete")
    assert capture(qr, pinned['target']) == dict(ok=False, error=QR_REFUSED)
    # An inline SVG whose shapes change.
    url = open_page(qr, '/qr-svg')
    pinned = pin(qr, url)
    assert pinned['ok'], pinned
    qr.lab.evaluate("document.querySelector('#qr g').setAttribute('fill', '#333')")
    assert capture(qr, pinned['target']) == dict(ok=False, error=QR_REFUSED)
    assert nothing_saved(qr)


def test_a_qr_pin_only_with_qr_capture_and_never_for_secret_capture(qr):
    url = open_page(qr, '/qr-img')
    # A QR pin without --qr, and capture-secret with a QR pin: refused, and the pin is used up.
    pinned = pin(qr, url)
    assert pinned['ok'], pinned
    assert capture(qr, pinned['target'], read_kind=None) == dict(ok=False, error=REFUSED)
    assert capture(qr, pinned['target'])['ok'] is False
    pinned = pin(qr, url)
    assert pinned['ok'], pinned
    secret = qr.broker.dispatch(dict(action='capture-secret', capture_protocol=1, target=pinned['target'],
                                     field='client_secret', metadata=dict(VALUES), handle=handle(qr)['handle']))
    assert secret['ok'] is False and 'refused' in secret['error'], secret
    # --qr with a text pin refuses too.
    url = open_page(qr, '/qr-text')
    text = pin(qr, url, read_kind=None)
    assert text['ok'], text
    assert capture(qr, text['target']) == dict(ok=False, error=QR_REFUSED)
    # read_kind is only "qr", and only on a read pin.
    focus(qr, '#qr')
    for change in (dict(read_kind='text'), dict(read_kind='QR'), dict(mode='totp', selector='#otp', capture_protocol=None)):
        assert pin(qr, url, **change) == failure(), change
    entry = PyKeePass(str(qr.path), password=MASTER).find_entries(title=VALUES['title'], first=True)
    assert entry.otp is None and PENDING_FIELD not in entry.custom_properties and 'client_secret' not in entry.custom_properties


def test_an_inline_text_key_at_a_fractional_device_scale_captures_as_text(qr):
    lab = qr.lab
    lab.observer.call('Emulation.setDeviceMetricsOverride', dict(width=1200, height=900, deviceScaleFactor=1.25,
                                                                 mobile=False), lab.session)
    try:
        url = open_page(qr, '/text-inline-scaled')
        found = lab.evaluate('window.found || null')
        assert found and found['z'] == 1.25, found
        text = pin(qr, url, read_kind=None)
        assert text['ok'], (text, found)
        assert capture(qr, text['target'], read_kind=None) == receipt(qr)
    finally:
        lab.observer.call('Emulation.clearDeviceMetricsOverride', {}, lab.session)


def test_an_inline_text_key_that_ends_below_a_half_pixel_captures_as_text(qr):
    # Not a QR case: the text read pin's own end-of-text hit test, which capture-totp without --qr uses.
    url = open_page(qr, '/text-inline-fraction')
    assert 0 < qr.lab.evaluate('window.fraction') < .5
    text = pin(qr, url, read_kind=None)
    assert text['ok'], text
    assert capture(qr, text['target'], read_kind=None) == receipt(qr)
    assert 'secret=' + KEY in stored(qr)[1]


@pytest.mark.parametrize('qr', ['cdp'], indirect=True)  # The extension reads only in the top document, by design.
def test_a_qr_code_in_a_same_origin_child_frame_captures_on_the_cdp_route(qr):
    url = open_page(qr, '/qr-framed')
    qr.lab.wait("document.getElementById('setup').contentWindow.ready === true")
    listing = qr.broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=url,
                                      page_id=qr.lab.page_id))
    [child] = [f for f in listing['frames'] if f['depth'] == 1]
    assert child['eligible'] and child['origin'] == ORIGIN, child
    qr.lab.evaluate("(e => { e.tabIndex = -1; e.focus(); })(document.getElementById('setup').contentDocument"
                    ".getElementById('qr'))")
    qr.lab.wait("document.getElementById('setup').contentDocument.activeElement.id === 'qr'")
    request = dict(action='pin-password-target', password_protocol=1, page_id=qr.lab.page_id, frame_id=child['frame_id'],
                   top_url=url, selector='#qr', mode='read', capture_protocol=1, read_kind='qr', frame_protocol=1,
                   frame_origin=ORIGIN)
    pinned = qr.broker.dispatch(request)
    assert pinned['ok'], pinned
    assert capture(qr, pinned['target']) == receipt(qr)
    assert 'secret=' + KEY in stored(qr)[1]


def test_cli_pins_and_captures_a_qr_code(qr, monkeypatch, capsys):
    monkeypatch.setattr(cli, 'request', lambda socket, payload, **kwargs: qr.broker.dispatch(payload))
    url = open_page(qr, '/qr-canvas')
    focus(qr, '#qr')
    where = qr.where(url)
    route = ['--route', 'extension'] if qr.route == 'extension' else []
    assert cli.main(['pin-password-target', '--mode', 'read', '--qr', '--page-id', where['page_id'],
                     '--frame-id', where['frame_id'], '--top-url', url, '--selector', '#qr', *route]) == 0
    target = json.loads(capsys.readouterr().out)['target']
    meta = [a for k, v in VALUES.items() for a in ('--' + k, v)]
    assert cli.main(['capture-totp', '--qr', '--target', target, '--handle', handle(qr)['handle'], *meta]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == receipt(qr) and clean(out.out, out.err)
    assert 'secret=' + KEY in stored(qr)[1]


def test_cli_sends_no_qr_request_to_a_broker_without_qr_capture(monkeypatch, capsys, tmp_path):
    status = Broker(Vault([]), NoKeys(), password_browser_profile=tmp_path).dispatch(dict(action='ping'))
    assert status['totp_qr_capture_protocol'] == 1
    old = {k: v for k, v in status.items() if k != 'totp_qr_capture_protocol'}
    sent = []

    def request(socket, payload, **kwargs):
        if payload['action'] == 'ping':
            return old
        sent.append(payload)
        return dict(ok=False, error='synthetic refusal')

    monkeypatch.setattr(cli, 'request', request)
    pin = ['pin-password-target', '--mode', 'read', '--qr', '--page-id', 'PAGE', '--frame-id', 'FRAME',
           '--top-url', ORIGIN + '/qr', '--selector', '#qr', '--route', 'cdp']
    meta = [a for k, v in VALUES.items() for a in ('--' + k, v)]
    assert cli.main(pin) == 1
    assert json.loads(capsys.readouterr().out) == dict(ok=False, error=OLD_BROKER + '; target request not sent')
    assert cli.main(['capture-totp', '--qr', '--target', 'a' * 64, '--handle', 'HANDLE', *meta]) == 1
    assert json.loads(capsys.readouterr().out) == dict(ok=False, error=OLD_BROKER + '; request not sent')
    assert cli.main(['pin-password-target', '--mode', 'totp', '--qr', '--page-id', 'PAGE', '--frame-id', 'FRAME',
                     '--top-url', ORIGIN + '/qr', '--selector', '#otp']) == 2
    assert '--qr requires --mode read' in capsys.readouterr().err
    assert sent == []
    # A broker with QR capture gets read_kind on both requests; without --qr nothing changes.
    old['totp_qr_capture_protocol'] = 1
    cli.main(pin)
    cli.main(['capture-totp', '--qr', '--target', 'a' * 64, '--handle', 'HANDLE', *meta])
    cli.main(['capture-totp', '--target', 'a' * 64, '--handle', 'HANDLE', *meta])
    assert [p.get('read_kind') for p in sent] == ['qr', 'qr', None]
    capsys.readouterr()


# ----- extension only: enhanced security's pixel challenge -----------------------------------
@pytest.fixture
def qr_extension(tmp_path, template, harness):  # noqa: F811
    path = kdbx(tmp_path, template)
    harness.broker.vault = open_vault_with_password(path, MASTER)
    trusted(harness)

    def where(url):
        listing = harness.frames(url)
        return dict(page_id=listing['page_id'], frame_id=listing['main_frame_id'], route='extension')

    return SimpleNamespace(route='extension', broker=harness.broker, lab=harness.lab, where=where, path=path,
                           pin_delivery=EXTENSION_PIN_DELIVERY, capture_delivery=EXTENSION_CAPTURE)


CHALLENGE_GONE = "getComputedStyle(document.getElementById('qr')).boxShadow === 'none'"


@pytest.mark.usefixtures('enhanced')
@pytest.mark.parametrize('page', ['/qr-img', '/qr-canvas', '/qr-svg', '/qr-rounded'])
def test_with_enhanced_security_a_shown_code_passes_the_pixel_challenge(qr_extension, page):
    q = qr_extension
    url = open_page(q, page)
    pinned = pin(q, url)
    assert pinned['ok'], pinned
    assert capture(q, pinned['target']) == receipt(q)
    assert q.lab.evaluate(CHALLENGE_GONE)


@pytest.mark.usefixtures('enhanced')
def test_with_enhanced_security_a_click_through_cover_over_the_code_refuses(qr_extension):
    q = qr_extension
    url = open_page(q, '/qr-img')
    # pointer-events: none passes the DOM hit test; the screenshot still shows the cover.
    q.lab.evaluate("document.body.insertAdjacentHTML('beforeend', '<div style=\"position:absolute;left:40px;top:60px;"
                   "width:60px;height:60px;background:#fff;pointer-events:none\"></div>')")
    assert pin(q, url) == failure()
    assert q.lab.evaluate(CHALLENGE_GONE) and nothing_saved(q)
