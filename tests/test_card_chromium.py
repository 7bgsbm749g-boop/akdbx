"""Real card transport in an isolated Chrome, TLS site, profile and X desktop.

Only public payment test numbers are used. Never attaches to a user browser.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import ssl
import sys
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from akdbx.broker import Broker
from akdbx.browser_card import BrowserCards, CDP, CardTargetError, browser_endpoint, failure, TTL, MAX_PINS
from akdbx.cards import FIELDS, MARKER
from test_broker import Entry, Vault, RecordingTyper, running_broker
from akdbx import cli
from test_cards import CARD
from test_writes import deployed, template
from test_target import isolated_x11
from card_form_fixtures import HINTLESS

HTML = b'''<!doctype html><title>Synthetic card destination test</title>
<style>input,select{display:block;width:230px;height:25px;margin:5px}</style>
<input id="address" autocomplete="street-address"><input id="number" autocomplete="cc-number">
<input id="name" autocomplete="cc-name"><input id="month" autocomplete="cc-exp-month">
<input id="year" autocomplete="cc-exp-year"><input id="expiry" autocomplete="cc-exp">
<input id="csc" autocomplete="cc-csc"><input id="password" type="password" autocomplete="current-password">
<select id="months" autocomplete="cc-exp-month"><option value=""></option><option value="9">September</option></select>
<select id="years" autocomplete="cc-exp-year"><option value=""></option><option value="2031">2031</option></select>
<script>window.events=[];document.addEventListener('input', e=>events.push(e.target.id));</script>'''


class CardEntry(Entry):
    def get_custom_property(self, key):
        return {MARKER: 'v1', **{field: CARD[k] for k, field in FIELDS.items()}}.get(key)


def wait_for_browser_endpoint(profile, process, deadline):
    # Chrome creates this file before publishing the complete header. Existence
    # alone is not readiness. Reuse the production validator without weakening
    # it, and retry only this non-secret test-browser startup phase.
    while time.monotonic() < deadline:
        assert process.poll() is None, 'isolated Chrome exited'
        try:
            return browser_endpoint(profile)
        except (FileNotFoundError, CardTargetError):
            time.sleep(.05)
    raise AssertionError('isolated Chrome did not publish a valid debugging header')


def connect_test_browser(profile, process, deadline):
    import websocket
    # The published port file can precede a responsive WebSocket server. Retry
    # only preparation of this owned synthetic browser, before pinning any DOM
    # target. Peer ownership/permission/protocol errors still fail immediately.
    while time.monotonic() < deadline:
        wait_for_browser_endpoint(profile, process, deadline)
        try:
            return CDP(profile)
        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, TimeoutError,
                websocket.WebSocketTimeoutException, websocket.WebSocketConnectionClosedException):
            time.sleep(.05)
    raise AssertionError('isolated Chrome did not accept a verified debugging connection')


def card_browser_binary():
    """Require all native dependencies in card CI; allow optional local runs."""
    if sys.platform == 'darwin':
        binary = Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
        assert binary.is_file(), 'macOS CDP tests require Google Chrome'
        return str(binary)
    binary = shutil.which('google-chrome') or shutil.which('chromium')
    if not binary or not shutil.which('openssl') or not shutil.which('Xvfb'):
        message = 'Card safety tests require Chrome/Chromium, Xvfb and openssl'
        if os.environ.get('AKDBX_REQUIRE_CARD_CHROMIUM') == '1':
            pytest.fail(message)
        pytest.skip(message + '; set AKDBX_REQUIRE_CARD_CHROMIUM=1 to require them')
    return binary


STRIPE_CARD_FRAME = (
    'https://js.stripe.com/v3/elements-inner-accessory-target-'
    '0123456789abcdef0123456789abcdef.html#merchant=synthetic'
)
# Stripe's classic Card Element frame, with the fragment shape a live page uses.
STRIPE_CARD_ELEMENT_FRAME = (
    'https://js.stripe.com/v3/elements-inner-card-'
    'fedcba9876543210fedcba9876543210.html'
    '#__shared_params__[version]=v3&wait=false&rtl=false&componentName=card'
)


@pytest.fixture
def chrome(tmp_path, request):
    windows = os.name == 'nt'
    if windows:
        from windows_chromium_lab import browser_binary
        binary = browser_binary()
        assert binary is not None, 'Windows CDP tests require an installed browser'
        desktop = None
    else:
        binary = card_browser_binary()
        desktop = None if sys.platform == 'darwin' else request.getfixturevalue('isolated_x11')
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=127.0.0.1', '-keyout', str(key), '-out', str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            requests.append(self.path)
            body = HTML
            if self.path == '/hintless':
                body = HINTLESS.encode()
            elif self.path == '/framed':
                body = b'<!doctype html><iframe src="/frame" style="width:600px;height:600px"></iframe>'
            elif self.path == '/computop':
                body = b'<!doctype html><iframe id=merchant src=/computop-merchant style="width:650px;height:500px"></iframe>'
            elif self.path == '/computop-merchant':
                body = b'''<!doctype html><iframe id=processor name=PGForm style="width:550px;height:350px"></iframe>
                  <form id=processorPost method=post target=PGForm action="https://www.computop-paygate.com/payssl.aspx"></form>
                  <script>processorPost.submit()</script>'''
            elif self.path == '/payssl.aspx':
                body = b'''<!doctype html><style>input{display:block;width:230px;height:25px;margin:5px}</style>
                  <form><input id=creditCardHolder name=creditCardHolder autocomplete=off maxlength=40>
                  <input id=_KKnr name=_KKnr autocomplete=off maxlength=30>
                  <input id=expiry_date name=expiry_date autocomplete=off>
                  <input id=cccvc name=cccvc autocomplete=off maxlength=4>
                  <input id=unrelated autocomplete=off></form>'''
            elif self.path == '/processor':
                body = b'<!doctype html><iframe id="merchant" src="/merchant-frame" style="width:650px;height:500px"></iframe>'
            elif self.path == '/merchant-frame':
                body = b'''<!doctype html><iframe id="processor"
                  src="https://checkoutshopper-live.adyen.com/checkoutshopper/securedfields/live_test/6.3.0/securedFields.html"
                  style="width:550px;height:300px"></iframe>'''
            elif self.path == '/stripe-unrecognized':
                body = (b'<!doctype html><iframe src="https://js.stripe.com/v3/unrecognized-element.html" '
                        b'style="width:550px;height:300px"></iframe>')
            elif self.path == '/stripe':
                body = (f'<!doctype html><iframe src="{STRIPE_CARD_FRAME}" '
                        'style="width:550px;height:300px"></iframe>').encode()
            elif self.path in (urlsplit(STRIPE_CARD_FRAME).path, '/v3/unrecognized-element.html'):
                body = b'''<!doctype html><style>input{display:block;margin:10px}</style>
                  <input id=payment-numberInput name=number autocomplete=cc-number>
                  <input id=payment-expiryInput name=expiry autocomplete=cc-exp placeholder="MM / YY">
                  <input id=payment-cvcInput name=cvc autocomplete=cc-csc>
                  <input id=other-number name=other autocomplete=cc-number>
                  <input name=cardnumber autocomplete=cc-number>
                  <script>
                  document.querySelector('#payment-expiryInput').addEventListener('input', e => {
                      e.target.value = e.target.value.replace('/', ' / ');
                  });
                  </script>'''
            elif self.path == '/stripe-card':
                body = (f'<!doctype html><iframe name="__privateStripeFrame5551" '
                        f'title="Secure card payment input frame" src="{STRIPE_CARD_ELEMENT_FRAME}" '
                        'style="width:550px;height:300px"></iframe>').encode()
            elif self.path == urlsplit(STRIPE_CARD_ELEMENT_FRAME).path:
                # Synthetic Card Element: inputs without ids, decoys named
                # "hidden", and a Payment Element binding that must not apply.
                body = b'''<!doctype html><style>input{display:block;margin:10px}</style>
                  <form novalidate>
                  <input class=decoy name=hidden autocomplete=fake tabindex=-1>
                  <input type=text name=cardnumber autocomplete=cc-number placeholder="Card number" inputmode=numeric>
                  <input type=text name=exp-date autocomplete=cc-exp placeholder="MM / YY" inputmode=numeric>
                  <input type=text name=cvc autocomplete=cc-csc placeholder="CVC" inputmode=numeric>
                  <input class=decoy name=hidden autocomplete=fake tabindex=-1>
                  <input id=payment-numberInput name=number autocomplete=cc-number>
                  </form>
                  <script>
                  const n = document.querySelector('[name=cardnumber]');
                  n.addEventListener('input', () => { n.value = n.value.replace(/([0-9]{4})(?=[0-9])/g, '$1 '); });
                  const e = document.querySelector('[name=exp-date]');
                  e.addEventListener('input', () => { e.value = e.value.replace('/', ' / '); });
                  </script>'''
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_POST(self):
            # The synthetic form has no secrets or fields. A POST-navigation
            # keeps the iframe owner's src empty, matching hosted checkout.
            assert self.path == '/payssl.aspx'
            self.do_GET()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    class TLSServer(ThreadingHTTPServer):
        def get_request(self):
            client, address = self.socket.accept()
            client.settimeout(2)
            try:
                return tls.wrap_socket(client, server_side=True), address
            except BaseException:
                client.close()
                raise
    server = TLSServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    url = 'https://127.0.0.1:' + str(server.server_port) + '/payment'
    profile = tmp_path / 'slot1'
    if windows:
        from akdbx.windows_security import ensure_private_directory
        ensure_private_directory(profile)
    else:
        profile.mkdir(mode=0o700)
    log = (tmp_path / 'chrome.log').open('wb')
    environment = {**os.environ, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/nonexistent/akdbx-card-test', 'NO_AT_BRIDGE': '1'}
    launch = {} if windows else dict(start_new_session=True, umask=0o077)
    process = subprocess.Popen([binary, '--user-data-dir=' + str(profile), '--no-first-run',
        '--no-default-browser-check', '--disable-background-networking', '--disable-component-update',
        '--disable-sync', '--disable-extensions', '--disable-gpu', '--disable-dev-shm-usage',
        '--renderer-process-limit=2', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
        '--site-per-process', '--no-proxy-server',
        '--host-resolver-rules=MAP checkoutshopper-live.adyen.com 127.0.0.1:' + str(server.server_port) +
        ',MAP www.computop-paygate.com 127.0.0.1:' + str(server.server_port) +
        ',MAP js.stripe.com 127.0.0.1:' + str(server.server_port) +
        ',MAP login.example.test 127.0.0.1:' + str(server.server_port),
        '--ignore-certificate-errors', '--window-size=1000,1000', '--headless=new' if desktop is None else '--ozone-platform=x11', url],
        env=environment, stdout=subprocess.DEVNULL, stderr=log, **launch)
    cdp = None
    try:
        # Cold CI Chrome preparation gets a separate bounded budget. Production
        # connection/fill deadlines and every post-pin assertion are unchanged.
        deadline = time.monotonic() + 60
        cdp = connect_test_browser(profile, process, deadline)
        page, session = None, None
        while time.monotonic() < deadline:
            pages = [t for t in cdp.call('Target.getTargets')['targetInfos'] if t['type'] == 'page' and t['url'] == url]
            if pages:
                page = pages[0]['targetId']
                session = cdp.call('Target.attachToTarget', dict(targetId=page, flatten=True))['sessionId']
                if cdp.call('Runtime.evaluate', dict(expression="!!document.getElementById('number')", returnByValue=True), session)['result'].get('value'):
                    break
            time.sleep(.05)
        assert page and session
        frame = cdp.call('Page.getFrameTree', session=session)['frameTree']['frame']['id']
        broker = Broker(Vault([CardEntry()]), RecordingTyper(), card_browser_profile=profile, default_fill_route='cdp')
        yield SimpleNamespace(broker=broker, cdp=cdp, session=session, page=page, frame=frame,
            url=url, profile=profile, process=process, lab=desktop, requests=requests)
    finally:
        if 'broker' in locals():
            broker.card_targets.close()
        if cdp:
            try:
                cdp.call('Browser.close')
            except Exception:
                pass
            cdp.close()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            if windows:
                process.kill()
                process.wait(timeout=5)
            else:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        # This group was created by this fixture with its own
                        # browser profile and start_new_session=True.
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                except ProcessLookupError:
                    process.wait(timeout=5)
        log.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        # Each function owns a fresh profile. Keep its bounded Chrome log for
        # CI evidence, not hundreds of stopped-browser caches across the suite.
        # Never remove a profile while its exact owned process is still alive.
        if process.poll() is not None:
            shutil.rmtree(profile, ignore_errors=windows)


def evaluate(chrome, expression):
    result = chrome.cdp.call('Runtime.evaluate', dict(expression=expression, returnByValue=True), chrome.session)
    assert 'exceptionDetails' not in result
    return result['result'].get('value')


def pin(chrome, field='cc-number', selector='#number', **changes):
    request = dict(action='pin-card-target', card_protocol=1, page_id=chrome.page, frame_id=chrome.frame,
                   top_url=chrome.url, frame_url=chrome.url, field=field, selector=selector)
    request.update(changes)
    return chrome.broker.dispatch(request)


def handle(chrome):
    return chrome.broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']


def fill(chrome, target, field='cc-number', **changes):
    request = dict(action='fill-card', card_protocol=1, handle=handle(chrome), target=target['target'], field=field)
    request.update(changes)
    return chrome.broker.dispatch(request)


@pytest.mark.parametrize('field,selector,formatting,expected', [
    ('cc-number', '#number', None, CARD['number']), ('cc-name', '#name', None, CARD['name']),
    ('cc-exp-month', '#month', None, '09'), ('cc-exp-year', '#year', 'YY', '31'),
    ('cc-exp-year', '#year', 'YYYY', '2031'), ('cc-exp', '#expiry', 'MM/YY', '09/31'),
    ('cc-exp', '#expiry', 'MM/YYYY', '09/2031'), ('cc-csc', '#csc', None, '123'),
    ('cc-exp-month', '#months', None, '9'), ('cc-exp-year', '#years', 'YYYY', '2031')])
def test_real_transport_fills_only_pinned_field_and_reports_no_values(chrome, field, selector, formatting, expected):
    evaluate(chrome, "document.getElementById('address').focus()")
    evaluate(chrome, f'document.querySelector({json.dumps(selector)}).scrollIntoView({{block:"center"}})')
    target = pin(chrome, field, selector)
    assert target['ok'], evaluate(chrome, '''(()=>{const e=document.querySelector(''' + json.dumps(selector) + '''); const r=e.getBoundingClientRect(); return {rect:r.toJSON(),hit:document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)?.id,visible:document.visibilityState,secure:isSecureContext,type:e.type,autocomplete:e.autocomplete,viewport:[innerWidth,innerHeight]};})()''')
    result = fill(chrome, target, field, **({'format': formatting} if formatting else {}))
    assert result == dict(ok=True, filled=field, card_delivery='cdp-card-element-v1')
    assert evaluate(chrome, f'document.querySelector({json.dumps(selector)}).value') == expected
    assert evaluate(chrome, "address.value === '' && password.value === '' && document.activeElement.id === 'address'")
    assert evaluate(chrome, 'events') == [selector[1:]]
    assert chrome.broker.typer.events == []
    assert 'number' not in result and 'value' not in result


@pytest.mark.parametrize('mutation', [
    "number.outerHTML='<input id=number autocomplete=cc-number>'",
    "number.setAttribute('autocomplete','street-address')", "number.type='email'",
    "number.disabled=true", "number.readOnly=true", "number.style.display='none'",
    "number.parentElement.style.opacity='0'",
    "number.parentElement.style.filter='opacity(0)'",
    "number.parentElement.style.maskImage='linear-gradient(transparent,transparent)'",
    "number.style.setProperty('-webkit-mask-box-image-source','linear-gradient(transparent,transparent)')",
    "document.body.insertAdjacentHTML('beforeend','<div style=\"position:fixed;inset:0;background:white;z-index:2147483647;pointer-events:none\"></div>')",
    "number.remove()", "number.setAttribute('maxlength','2')",
    "number.insertAdjacentHTML('afterend','<form id=newForm></form>');newForm.append(number)",
    "number.insertAdjacentHTML('afterend','<input id=number autocomplete=cc-number>')",
    "history.pushState({},'', '/changed')",
    "number.insertAdjacentHTML('afterend','<div style=\"position:fixed;inset:0;background:white\"></div>')"])
def test_changed_or_wrong_field_refuses_without_writing_anywhere(chrome, mutation):
    target = pin(chrome)
    assert target['ok']
    evaluate(chrome, mutation)
    assert fill(chrome, target)['ok'] is False
    assert evaluate(chrome, "Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")
    assert not fill(chrome, target)['ok']
    assert chrome.broker.typer.events == []


DRAWER = ("const d=document.createElement('div');d.id='drawer';number.before(d);d.append(number);"
          "d.style.padding='16px';d.style.boxShadow='0 0 16px #000';")


@pytest.mark.parametrize('style', [
    # A side drawer that trims only its own shadow (Twilio console). The CDP isolated world cannot see
    # closed shadow roots, and a closed wrapper that mirrors the drawer swaps the edges an inset clips,
    # so this route refuses every clip-path; the extension route accepts this one (issue #69).
    "d.style.clipPath='inset(-32px 0px -32px -32px)'", "d.style.clipPath='inset(0px)'",
    "d.style.clipPath='inset(0px 0px 0px 40px)'", "d.style.clipPath='inset(-32px round 8px)'",
    "d.style.clipPath='polygon(0 0,100% 0,100% 100%,0 100%)'", "d.style.clipPath='circle(100%)'",
    "d.style.clipPath='url(#none)'", "d.style.clip='rect(0px,999px,999px,0px)';d.style.position='absolute'"])
def test_the_cdp_route_refuses_any_ancestor_clip(chrome, style):
    evaluate(chrome, DRAWER + style)
    assert pin(chrome)['ok'] is False
    assert chrome.broker.card_targets.pins == {}
    assert evaluate(chrome, "Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")


def test_a_clip_added_after_the_cdp_pin_refuses_the_fill(chrome):
    evaluate(chrome, DRAWER)
    target = pin(chrome)
    assert target['ok']
    evaluate(chrome, "drawer.style.clipPath='inset(-32px 0px -32px -32px)'")
    assert fill(chrome, target)['ok'] is False
    assert evaluate(chrome, "Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")


@pytest.mark.parametrize('changes', [dict(selector='#address'), dict(selector='#password'), dict(selector='input'),
    dict(selector='#missing'), dict(field='cc-csc'), dict(top_url='https://wrong.test/'),
    dict(frame_url='https://wrong.test/'), dict(frame_id='wrong-frame'), dict(page_id='wrong-page'),
    dict(card_protocol=True), dict(selector='[')])
def test_ambiguous_non_card_and_wrong_origin_pins_refused(chrome, changes):
    assert not pin(chrome, **changes)['ok']
    assert chrome.broker.card_targets.pins == {}
    assert evaluate(chrome, "Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")


def test_reused_expired_mismatched_and_disconnected_authorizations_never_write(chrome):
    target = pin(chrome)
    assert not fill(chrome, target, 'cc-csc')['ok']
    assert not fill(chrome, target)['ok']
    target = pin(chrome)
    chrome.broker.card_targets.pins[target['target']]['expires'] = chrome.broker.clock() - 1
    assert not fill(chrome, target)['ok']
    target = pin(chrome)
    assert not chrome.broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle(chrome),
        field='cc-number', target=target['target'], start_deadline=chrome.broker.clock() + 3), delivery_ready=lambda: False)['ok']
    assert evaluate(chrome, "number.value === ''")


@pytest.mark.skipif(sys.platform != 'linux', reason='requires an interactive X11 browser and XTest')
def test_real_omnibox_focus_cannot_receive_card_value(chrome):
    from Xlib import X, Xatom, XK
    from Xlib.ext import xtest
    root, d = chrome.lab.display.screen().root, chrome.lab.display
    atom = d.intern_atom('_NET_WM_PID')
    windows = [w for w in root.query_tree().children
        if (p := w.get_full_property(atom, Xatom.CARDINAL)) is not None and list(p.value) == [chrome.process.pid]
        and w.get_wm_class() and w.get_attributes().map_state == X.IsViewable]
    assert len(windows) == 1
    chrome.lab.activate(windows[0])
    evaluate(chrome, 'number.focus()')
    target = pin(chrome)
    assert target['ok']
    def key(name, down=True):
        xtest.fake_input(d, X.KeyPress if down else X.KeyRelease, d.keysym_to_keycode(XK.string_to_keysym(name)))
        d.sync()
    key('Control_L'); key('l'); key('l', False); key('Control_L', False)
    # This actual browser shortcut removes focus from the page.
    deadline = time.monotonic() + 2
    while evaluate(chrome, 'document.hasFocus()') and time.monotonic() < deadline:
        time.sleep(.01)
    assert evaluate(chrome, 'document.hasFocus()') is False
    canary = chrome.url.replace('/payment', '/omnibox-canary')
    # All characters are public synthetic test data; no vault value is typed.
    for char in canary:
        sym = ord(char)
        code = d.keysym_to_keycode(sym)
        row = d.get_keyboard_mapping(code, 1)[0]
        shift = row[0] != sym
        if shift: key('Shift_L')
        xtest.fake_input(d, X.KeyPress, code); xtest.fake_input(d, X.KeyRelease, code)
        if shift: key('Shift_L', False)
    d.sync()
    result = fill(chrome, target)
    assert result['ok']
    assert evaluate(chrome, 'number.value') == CARD['number']
    assert evaluate(chrome, 'document.hasFocus()') is False
    key('Return'); key('Return', False)
    deadline = time.monotonic() + 3
    while '/omnibox-canary' not in chrome.requests and time.monotonic() < deadline:
        time.sleep(.01)
    assert '/omnibox-canary' in chrome.requests
    assert not any(CARD['number'] in request for request in chrome.requests)
    assert chrome.broker.typer.events == []


def test_navigation_destroys_pin_and_cannot_fill_new_document(chrome):
    target = pin(chrome)
    assert target['ok']
    chrome.cdp.call('Page.navigate', dict(url=chrome.url.replace('/payment', '/other-page')), chrome.session)
    deadline = time.monotonic() + 3
    while evaluate(chrome, 'location.href') == chrome.url and time.monotonic() < deadline:
        time.sleep(.01)
    assert not fill(chrome, target)['ok']
    assert evaluate(chrome, "Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")


def test_isolated_world_ignores_page_setter_overrides_and_does_not_submit(chrome):
    evaluate(chrome, '''window.leaked=false;window.submitted=false;
        Object.defineProperty(HTMLInputElement.prototype,'value',{set(v){window.leaked=true;},get(){return 'bad';}});
        document.querySelectorAll=()=>[];window.Event=()=>{throw Error('page Event override');};
        document.addEventListener('submit',()=>{window.submitted=true;});''')
    target = pin(chrome)
    assert target['ok']
    assert fill(chrome, target)['ok']
    assert evaluate(chrome, '!window.leaked && !window.submitted')
    # Observe the synthetic value through a second isolated world, whose
    # builtins were not replaced by the deliberately hostile page fixture.
    context = chrome.cdp.call('Page.createIsolatedWorld', dict(frameId=chrome.frame, worldName='synthetic-inspection'), chrome.session)['executionContextId']
    assert chrome.cdp.call('Runtime.evaluate', dict(expression='number.value', returnByValue=True, contextId=context), chrome.session)['result']['value'] == CARD['number']


def test_receipt_is_uncertain_when_page_rejects_value_and_never_echoes_it(chrome):
    evaluate(chrome, "number.addEventListener('input',()=>{number.value='';})")
    target = pin(chrome)
    result = fill(chrome, target)
    assert result == failure(True)
    assert CARD['number'] not in str(result)
    assert evaluate(chrome, "number.value === '' && address.value === ''")


@pytest.mark.parametrize('location',['number','document.body'])
@pytest.mark.parametrize('after_dispatch',[False,True])
def test_blended_same_origin_input_or_ancestor_refuses_pin_fill_and_success(chrome,location,after_dispatch):
    mutation='''const e=ELEMENT;
      e.parentElement.style.background='black';e.style.mixBlendMode='multiply';'''.replace('ELEMENT',location)
    if after_dispatch:
        evaluate(chrome,"number.addEventListener('input',()=>{"+mutation+"})")
    target=pin(chrome);assert target['ok']
    if not after_dispatch:
        evaluate(chrome,mutation)
        assert not pin(chrome)['ok']
    result=fill(chrome,target)
    assert not result['ok'] and result['delivery']==('uncertain' if after_dispatch else 'not-started')
    assert evaluate(chrome,'number.value')==(CARD['number'] if after_dispatch else '')
    assert CARD['number'] not in str(result) and chrome.broker.typer.events==[]
    assert not fill(chrome,target)['ok']
    assert not chrome.broker.card_targets.pins


def test_same_origin_frame_is_bound_and_hidden_parent_is_refused(chrome):
    framed = chrome.url.replace('/payment', '/framed')
    chrome.cdp.call('Page.navigate', dict(url=framed), chrome.session)
    deadline = time.monotonic() + 3
    frames = None
    while time.monotonic() < deadline:
        tree = chrome.cdp.call('Page.getFrameTree', session=chrome.session)['frameTree']
        if tree.get('childFrames') and tree['childFrames'][0]['frame']['url'].endswith('/frame'):
            frames = tree['childFrames'][0]['frame']
            if evaluate(chrome, "!!document.querySelector('iframe')?.contentDocument?.getElementById('number')"):
                break
        time.sleep(.01)
    assert frames
    # Keep the whole iframe centre visible on the deliberately small X screen.
    evaluate(chrome, "document.querySelector('iframe').style.height='250px';")
    request = dict(top_url=framed, frame_url=frames['url'], frame_id=frames['id'])
    target = pin(chrome, **request)
    assert target['ok']
    assert fill(chrome, target)['ok']
    assert evaluate(chrome, "document.querySelector('iframe').contentDocument.getElementById('number').value") == CARD['number']
    evaluate(chrome, "document.querySelector('iframe').contentDocument.getElementById('number').value='';")
    target = pin(chrome, **request)
    assert target['ok']
    evaluate(chrome, "document.querySelector('iframe').style.display='none'")
    assert not fill(chrome, target)['ok']
    assert evaluate(chrome, "document.querySelector('iframe').contentDocument.getElementById('number').value") == ''


def test_pointer_transparent_cover_blocks_fresh_main_frame_pin(chrome):
    evaluate(chrome,"document.body.insertAdjacentHTML('beforeend','<div style=\"position:fixed;inset:0;background:white;z-index:2147483647;pointer-events:none\"></div>')")
    assert not pin(chrome)['ok']
    assert evaluate(chrome,"number.value === ''")


def test_native_input_hit_handles_scrolled_main_document(chrome):
    evaluate(chrome,"document.body.style.minHeight='3000px';number.style.marginTop='450px';scrollTo(0,400)")
    assert evaluate(chrome,'scrollY')==400
    target=pin(chrome);assert target['ok']
    assert fill(chrome,target)['ok']
    assert evaluate(chrome,'number.value')==CARD['number']


def test_native_input_hit_handles_scrolled_same_origin_frame_and_top(chrome):
    framed=chrome.url.replace('/payment','/framed')
    chrome.cdp.call('Page.navigate',dict(url=framed),chrome.session)
    deadline=time.monotonic()+3
    frame=None
    while time.monotonic()<deadline:
        tree=chrome.cdp.call('Page.getFrameTree',session=chrome.session)['frameTree']
        if tree.get('childFrames') and tree['childFrames'][0]['frame']['url'].endswith('/frame'):
            frame=tree['childFrames'][0]['frame']
            if evaluate(chrome,"!!document.querySelector('iframe')?.contentDocument?.getElementById('number')"):break
        time.sleep(.01)
    assert frame
    evaluate(chrome,"""document.body.style.minHeight='3000px';
      const f=document.querySelector('iframe');f.style.height='250px';f.style.marginTop='400px';
      f.contentDocument.getElementById('number').style.marginTop='300px';
      f.contentWindow.scrollTo(0,250);scrollTo(0,300);""")
    assert evaluate(chrome,'scrollY')==300
    target=pin(chrome,top_url=framed,frame_url=frame['url'],frame_id=frame['id'])
    assert target['ok'] and fill(chrome,target)['ok']
    assert evaluate(chrome,"document.querySelector('iframe').contentDocument.getElementById('number').value")==CARD['number']


def test_cross_origin_frame_is_explicitly_unsupported(chrome):
    assert not pin(chrome, frame_url=chrome.url.replace('127.0.0.1', 'localhost'))['ok']


def test_hash_routed_main_frame_pin_keeps_exact_navigation_checks(chrome):
    evaluate(chrome,"location.hash='/checkout'")
    url=chrome.url+'#/checkout'
    target=pin(chrome,top_url=url,frame_url=url)
    assert target['ok'] and fill(chrome,target)['ok']
    evaluate(chrome,"number.value=''")
    target=pin(chrome,top_url=url,frame_url=url)
    assert target['ok']
    evaluate(chrome,"location.hash='/changed'")
    assert not fill(chrome,target)['ok']
    assert evaluate(chrome,"number.value === ''")


def test_cli_rpc_real_browser_fill_is_receipt_only(chrome, tmp_path, capsys):
    socket = tmp_path / 'r' / 's'
    prefix = ['--socket', str(socket)]
    with running_broker(socket, chrome.broker):
        assert cli.main([*prefix, 'search-cards', 'Example']) == 0
        selected = json.loads(capsys.readouterr().out)['entries'][0]
        assert cli.main([*prefix, 'pin-card-target', '--page-id', chrome.page,
            '--frame-id', chrome.frame, '--top-url', chrome.url, '--frame-url', chrome.url,
            '--selector', '#number', '--field', 'cc-number']) == 0
        target = json.loads(capsys.readouterr().out)
        assert cli.main([*prefix, 'fill-card', selected['handle'], '--target', target['target'], '--field', 'cc-number']) == 0
        output = capsys.readouterr()
        assert json.loads(output.out) == dict(ok=True, filled='cc-number', card_delivery='cdp-card-element-v1')
        assert CARD['number'] not in output.out + output.err
        assert evaluate(chrome, 'number.value') == CARD['number']


@pytest.mark.parametrize('mutation', ["number.outerHTML='<input id=number autocomplete=cc-number>'",
                                    "history.pushState({},'', '/last-moment-change')"])
def test_last_check_to_write_race_still_refuses_changed_destination(chrome, mutation, monkeypatch):
    target = pin(chrome)
    assert target['ok']
    transport = chrome.broker.card_targets.pins[target['target']]['cdp']
    original = transport.call
    def race(method, params=None, session=None):
        if method == 'Runtime.callFunctionOn' and 'this.fill(value' in params.get('functionDeclaration',''):
            evaluate(chrome, mutation)
        return original(method, params, session)
    monkeypatch.setattr(transport, 'call', race)
    assert not fill(chrome, target)['ok']
    assert evaluate(chrome, "Array.from(document.querySelectorAll('input')).every(e=>e.value==='')")


def test_tab_switch_after_pin_refuses_hidden_page(chrome):
    target = pin(chrome)
    page = chrome.cdp.call('Target.createTarget', dict(url='about:blank'))['targetId']
    session = chrome.cdp.call('Target.attachToTarget', dict(targetId=page, flatten=True))['sessionId']
    try:
        chrome.cdp.call('Page.bringToFront', session=session)
        deadline = time.monotonic() + 2
        while evaluate(chrome, "document.visibilityState === 'visible'") and time.monotonic() < deadline:
            time.sleep(.01)
        assert not fill(chrome, target)['ok']
        assert evaluate(chrome, "number.value === ''")
    finally:
        chrome.cdp.call('Target.closeTarget', dict(targetId=page))


def test_blocked_renderer_cannot_apply_a_delayed_fill_after_authorization_expiry(chrome, monkeypatch):
    target = pin(chrome)
    transport = chrome.broker.card_targets.pins[target['target']]['cdp']
    original = transport.call
    def block_before_write(method, params=None, session=None):
        if method == 'Runtime.callFunctionOn' and 'this.fill(value' in params.get('functionDeclaration',''):
            # Bound the synthetic renderer stall to five seconds, beyond the
            # four-second authorization. Only this test browser is affected.
            evaluate(chrome, 'setTimeout(()=>{const end=performance.now()+5000;while(performance.now()<end){}},20)')
            time.sleep(.05)
        return original(method, params, session)
    monkeypatch.setattr(transport, 'call', block_before_write)
    assert fill(chrome, target) == failure(True)
    time.sleep(3.2)  # allow the explicitly bounded renderer stall to end
    assert evaluate(chrome, "number.value === '' && address.value === ''")


def test_private_identity_save_and_cli_fill_on_real_loopback_https(chrome, deployed, tmp_path, capsys):
    from test_identities import IDENTITY, LABEL, post
    from test_writes import reopened

    broker, _, path, web = deployed
    broker.identity_targets.profile = chrome.profile
    rpc = tmp_path / 'private' / 'identity-rpc.sock'

    def command(*args, code=0):
        assert cli.main(['--socket', str(rpc), '--unlock-origin', 'https://node.example:9443', *args]) == code
        captured = capsys.readouterr()
        for value in (v for v in IDENTITY.values() if len(v) > 2):
            assert value not in captured.out + captured.err
        return json.loads(captured.out)

    def target(field, selector, code=0, url=None):
        return command('pin-identity-target', '--route', 'cdp', '--page-id', chrome.page, '--frame-id', chrome.frame,
                       '--top-url', url or chrome.url, '--frame-url', url or chrome.url, '--selector', selector,
                       '--field', field, code=code)

    with running_broker(rpc, broker):
        pending = command('create-identity', '--title', LABEL, '--group', 'Web')
        assert post(web, pending)[0] == 200
        broker.vault = reopened(path)
        # The lab fails if a fill triggers a handler that would submit the form.
        evaluate(chrome, '''document.body.insertAdjacentHTML("beforeend", '<form id="identity-checkout"></form>');
          const checkout = document.getElementById("identity-checkout");
          window.submitAttempts = 0;
          window.identityKeyEvents = 0;
          for (const event of ["keydown", "keypress", "keyup"]) {
            document.addEventListener(event, () => { window.identityKeyEvents++; }, true);
          }
          checkout.addEventListener("submit", e => { e.preventDefault(); window.submitAttempts++; });
          for (const event of ["input", "change"]) checkout.addEventListener(event, () => checkout.requestSubmit());''')
        tags = {
            'name': '<input autocomplete="name">',
            'address-line1': '<input autocomplete="SECTION-livraison-é SHIPPING address-line1">',
            'address-line2': '<input autocomplete="shipping address-line2">',
            'street-address': '<textarea autocomplete="street-address"></textarea>',
            'address-level2': '<input autocomplete="address-level2">',
            'postal-code': '<input autocomplete="postal-code">',
            'country': '<select autocomplete="country"><option value=""></option><option value="NZ" disabled>Unavailable</option><option value="NZ">New Zealand</option></select>',
            'tel': '<input type="tel" autocomplete="shipping mobile tel">',
            'email': '<input type="email" autocomplete="email" multiple>',
        }
        for field, tag in tags.items():
            selector = '#identity-' + field
            element = f'<div id="identity-{field}">{tag}</div>'
            evaluate(chrome, f'document.getElementById("identity-checkout").insertAdjacentHTML("beforeend", {json.dumps(element)})')
            selector += ' > *'
            get = f'document.querySelector({json.dumps(selector)})'
            evaluate(chrome, f'{get}.focus()')
            pin = target(field, selector)
            handle = command('search-identities', LABEL)['entries'][0]['handle']
            result = command('fill-identity', '--field', field, '--target', pin['target'], '--', handle)
            assert result == dict(ok=True, filled=field, identity_delivery='cdp-identity-element-v1')
            expected = IDENTITY.get(field, IDENTITY['address-line1'] + '\n' + IDENTITY['address-line2'])
            assert evaluate(chrome, f'{get}.value === {json.dumps(expected)} && document.activeElement === {get}')
            if field == 'country':
                assert evaluate(chrome, f'{get}.selectedIndex === 2')
            evaluate(chrome, f'{get}.parentElement.remove()')

        evaluate(chrome, "document.body.insertAdjacentHTML('beforeend','<input id=phone autocomplete=tel>'); phone.focus()")
        assert target('email', '#phone', code=1)['delivery'] == 'not-started'
        evaluate(chrome, "phone.autocomplete = 'worK email'")
        assert target('email', '#phone', code=1)['delivery'] == 'not-started'
        evaluate(chrome, "phone.autocomplete = 'tel'")
        assert target('tel', '#phone', code=1, url=chrome.url.replace('https:', 'http:'))['delivery'] == 'not-started'
        pin = target('tel', '#phone')
        evaluate(chrome, 'password.focus()')
        handle = command('search-identities', LABEL)['entries'][0]['handle']
        assert command('fill-identity', '--field', 'tel', '--target', pin['target'], '--', handle,
                       code=1)['delivery'] == 'not-started'
        evaluate(chrome, 'phone.focus()')
        fresh_pin = target('tel', '#phone')
        assert command('fill-identity', '--field', 'tel', '--target', fresh_pin['target'], '--', handle,
                       code=1)['delivery'] == 'not-started'
        fresh_handle = command('search-identities', LABEL)['entries'][0]['handle']
        assert command('fill-identity', '--field', 'tel', '--target', pin['target'], '--', fresh_handle,
                       code=1)['delivery'] == 'not-started'
        assert evaluate(chrome, "phone.value === '' && password.value === '' && submitAttempts === 0 && identityKeyEvents === 0")

        # A form that listens on an ancestor must receive both events on the pinned field.
        evaluate(chrome, """window.phoneEvents = [];
          for (const type of ['input', 'change']) document.addEventListener(type, e => {
            if (e.target === phone) phoneEvents.push([type, phone.value.length > 0]);
          });""")
        def notify_phone(code=0):
            pin = target('tel', '#phone')
            handle = command('search-identities', LABEL)['entries'][0]['handle']
            return command('fill-identity', '--notify-page', '--field', 'tel', '--target', pin['target'],
                           '--', handle, code=code)

        assert notify_phone()['ok']
        assert evaluate(chrome, 'JSON.stringify(phoneEvents)') == '[["input",true],["change",true]]'
        evaluate(chrome, "phone.addEventListener('change', () => { phone.value = ''; }, {once:true})")
        assert notify_phone(code=1)['delivery'] == 'uncertain'

        evaluate(chrome, """phoneEvents.length = 0;
          phone.addEventListener('input', () => { phone.value = ''; }, {once:true})""")
        assert notify_phone(code=1)['delivery'] == 'uncertain'
        assert evaluate(chrome, 'JSON.stringify(phoneEvents)') == '[["input",false]]'

        evaluate(chrome, """phoneEvents.length = 0;
          phone.addEventListener('input', () => { password.focus(); }, {once:true})""")
        assert notify_phone(code=1)['delivery'] == 'uncertain'
        assert evaluate(chrome, 'JSON.stringify(phoneEvents)') == '[["input",true]]'

        evaluate(chrome, """document.body.insertAdjacentHTML('beforeend',
          '<select id="region" autocomplete="country"><option></option><option>NZ</option></select>');
          window.regionEvents = [];
          for (const type of ['input', 'change']) document.addEventListener(type, e => {
            if (e.target === region) regionEvents.push(type);
          });
          region.focus()""")
        pin = target('country', '#region')
        handle = command('search-identities', LABEL)['entries'][0]['handle']
        assert command('fill-identity', '--notify-page', '--field', 'country', '--target', pin['target'],
                       '--', handle)['ok']
        assert evaluate(chrome, "regionEvents.join() === 'input,change' && region.value === 'NZ'")

        # No autocomplete hint: only an explicit field purpose pins it; "off" needs its own flag.
        evaluate(chrome, "phone.remove(); document.body.insertAdjacentHTML('beforeend', "
                         "'<input id=bare type=tel><input id=hintoff type=tel autocomplete=off>"
                         "<input id=other autocomplete=email>'); bare.focus()")
        assert target('tel', '#bare', code=1)['delivery'] == 'not-started'
        assert command('pin-identity-target', '--page-id', chrome.page, '--frame-id', chrome.frame,
                       '--top-url', chrome.url, '--frame-url', chrome.url, '--selector', '#bare', '--field', 'tel',
                       '--field-purpose', 'email', code=1)['error'].endswith('request not sent')
        purpose = ('--field-purpose', 'tel')

        def purpose_pin(selector, *extra, code=0):
            return command('pin-identity-target', '--route', 'cdp', '--page-id', chrome.page, '--frame-id', chrome.frame,
                           '--top-url', chrome.url, '--frame-url', chrome.url, '--selector', selector,
                           '--field', 'tel', *purpose, *extra, code=code)
        pin = purpose_pin('#bare')
        handle = command('search-identities', LABEL)['entries'][0]['handle']
        assert command('fill-identity', '--field', 'tel', '--format', 'national', '--calling-code', '44',
                       '--target', pin['target'], '--', handle, code=1)['delivery'] == 'not-started'
        pin = purpose_pin('#bare')
        handle = command('search-identities', LABEL)['entries'][0]['handle']
        assert command('fill-identity', '--field', 'tel', '--format', 'national', '--calling-code', '49',
                       '--target', pin['target'], '--', handle) == dict(ok=True, filled='tel',
                                                                          identity_delivery='cdp-identity-element-v1')
        assert evaluate(chrome, "bare.value === '30000000'")
        pin = purpose_pin('#bare')
        handle = command('search-identities', LABEL)['entries'][0]['handle']
        assert command('fill-identity', '--field', 'tel', '--format', 'international',
                       '--target', pin['target'], '--', handle)['ok']
        assert evaluate(chrome, "bare.value === '+4930000000'")
        evaluate(chrome, 'hintoff.focus()')
        assert purpose_pin('#hintoff', code=1)['delivery'] == 'not-started'
        pin = purpose_pin('#hintoff', '--allow-autocomplete-off')
        handle = command('search-identities', LABEL)['entries'][0]['handle']
        assert command('fill-identity', '--field', 'tel', '--target', pin['target'], '--', handle)['ok']
        assert evaluate(chrome, f"hintoff.value === {json.dumps(IDENTITY['tel'])}")
        evaluate(chrome, 'other.focus()')
        assert purpose_pin('#other', '--allow-autocomplete-off', code=1)['delivery'] == 'not-started'
        assert evaluate(chrome, "other.value === '' && submitAttempts === 0 && identityKeyEvents === 0")
    assert broker.typer.events == []


def hintless(chrome):
    url = chrome.url.replace('/payment', '/hintless')
    evaluate(chrome, f'location.href = {json.dumps(url)}')
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if evaluate(chrome, "location.pathname === '/hintless' && document.readyState === 'complete' && "
                                "!!document.getElementById('two-lists')"):
                break
        except AssertionError:
            pass
        time.sleep(.05)
    frame = chrome.cdp.call('Page.getFrameTree', session=chrome.session)['frameTree']['frame']['id']
    return SimpleNamespace(url=url, frame=frame)


def hintless_pin(chrome, page, selector, field, **changes):
    return pin(chrome, field, selector, top_url=page.url, frame_url=page.url, frame_id=page.frame, **changes)


@pytest.mark.parametrize('field,selector,expected', [
    ('cc-number', '#pidlInput_accountToken', CARD['number']), ('cc-csc', '#pidlInput_cvvToken', CARD['csc']),
    ('cc-number', '#hint-on', CARD['number'])])
def test_a_card_field_without_a_hint_fills_only_with_its_purpose(chrome, field, selector, expected):
    page = hintless(chrome)
    assert hintless_pin(chrome, page, selector, field) == failure()
    target = hintless_pin(chrome, page, selector, field, field_purpose=field)
    assert target['ok'], target
    assert fill(chrome, target, field) == dict(ok=True, filled=field, card_delivery='cdp-card-element-v1')
    assert evaluate(chrome, f'document.querySelector({json.dumps(selector)}).value') == expected
    assert evaluate(chrome, 'events') == ['input:' + selector[1:]]
    assert chrome.broker.typer.events == []


def test_a_card_purpose_never_overrides_another_hint_off_or_a_processor(chrome):
    page = hintless(chrome)
    # A hint for another detail, or with a section the card grammar refuses, still refuses.
    assert hintless_pin(chrome, page, '#conflict', 'cc-number', field_purpose='cc-number') == failure()
    assert hintless_pin(chrome, page, '#sub-hint', 'cc-number', field_purpose='cc-number') == failure()
    # A purpose for another field, or a field without its own purpose, refuses.
    assert hintless_pin(chrome, page, '#pidlInput_accountToken', 'cc-number', field_purpose='cc-csc') == failure()
    assert hintless_pin(chrome, page, '#pidlInput_accountToken', 'cc-exp', field_purpose='cc-exp') == failure()
    # autocomplete=off needs its own flag, which needs the purpose.
    assert hintless_pin(chrome, page, '#hint-off', 'cc-number', field_purpose='cc-number') == failure()
    assert hintless_pin(chrome, page, '#hint-off', 'cc-number', allow_autocomplete_off=True) == failure()
    target = hintless_pin(chrome, page, '#hint-off', 'cc-number', field_purpose='cc-number', allow_autocomplete_off=True)
    assert target['ok'], target
    assert fill(chrome, target) == dict(ok=True, filled='cc-number', card_delivery='cdp-card-element-v1')
    assert evaluate(chrome, "events") == ['input:hint-off']
    # A hint added after the pin refuses the fill.
    target = hintless_pin(chrome, page, '#pidlInput_cvvToken', 'cc-csc', field_purpose='cc-csc')
    evaluate(chrome, "pidlInput_cvvToken.setAttribute('autocomplete', 'cc-number')")
    assert fill(chrome, target, 'cc-csc') == failure()
    assert evaluate(chrome, "pidlInput_cvvToken.value") == ''


def dropdown_state(chrome, selector):
    return evaluate(chrome, f"""(() => {{ const b = document.querySelector({json.dumps(selector)});
        return [b.firstElementChild.textContent, b.getAttribute('aria-expanded'),
                document.querySelectorAll('[role=listbox]').length]; }})()""")


@pytest.mark.parametrize('field,selector,formatting,shown', [
    ('cc-exp-month', '#pidlInput_expiryMonth', None, '09'),
    ('cc-exp-year', '#pidlInput_expiryYear', 'YYYY', '2031'),
    ('cc-exp-year', '#pidlInput_expiryYear', 'YY', '2031'),
    ('cc-exp-year', '#short-year', 'YYYY', '31'),
    ('cc-exp-month', '#combo-month', None, '9'),
    # A value attribute counts when the text is that month's name.
    ('cc-exp-month', '#one-based-names', None, 'September')])
def test_an_aria_expiry_dropdown_chooses_the_one_matching_option(chrome, field, selector, formatting, shown):
    page = hintless(chrome)
    # Without the purpose, a dropdown button is not a card field.
    assert hintless_pin(chrome, page, selector, field) == failure()
    target = hintless_pin(chrome, page, selector, field, field_purpose=field)
    assert target['ok'], target
    result = fill(chrome, target, field, **({'format': formatting} if formatting else {}))
    assert result == dict(ok=True, filled=field, card_delivery='cdp-card-element-v1')
    assert dropdown_state(chrome, selector) == [shown, 'false', 0]
    assert evaluate(chrome, 'events') == ['open:' + selector[1:], 'choose:' + selector[1:] + '=' + shown]
    assert chrome.broker.typer.events == []


# '#zero-based-names': names counted from 0, so data-value 9 is October: never chosen.
@pytest.mark.parametrize('selector', ['#ambiguous', '#no-match', '#disabled-match', '#never-opens',
                                      '#zero-based-names'])
def test_an_aria_dropdown_with_no_single_match_refuses_and_keeps_the_selection(chrome, selector):
    page = hintless(chrome)
    target = hintless_pin(chrome, page, selector, 'cc-exp-month', field_purpose='cc-exp-month')
    assert target['ok'], target
    assert fill(chrome, target, 'cc-exp-month') == failure()
    # It closed what it opened, and chose nothing.
    assert dropdown_state(chrome, selector) == ['Month', 'false', 0]
    assert evaluate(chrome, 'events') == ['open:' + selector[1:], 'close:' + selector[1:]]


@pytest.mark.parametrize('selector', ['#plain-button', '#submit-dropdown', '#menu-dropdown', '#two-lists'])
def test_a_button_that_is_not_an_aria_listbox_dropdown_refuses(chrome, selector):
    page = hintless(chrome)
    assert hintless_pin(chrome, page, selector, 'cc-exp-month', field_purpose='cc-exp-month') == failure()
    # A card number never goes to a dropdown, even a well-formed one.
    assert hintless_pin(chrome, page, '#pidlInput_expiryMonth', 'cc-number', field_purpose='cc-number') == failure()
    assert evaluate(chrome, 'events') == []


def test_an_aria_dropdown_whose_list_changes_owner_refuses(chrome):
    page = hintless(chrome)
    target = hintless_pin(chrome, page, '#pidlInput_expiryMonth', 'cc-exp-month', field_purpose='cc-exp-month')
    assert target['ok'], target
    evaluate(chrome, "pidlInput_expiryMonth.setAttribute('aria-controls', 'year-list')")
    assert fill(chrome, target, 'cc-exp-month') == failure()
    assert evaluate(chrome, 'events') == []


def test_an_ignored_dropdown_click_is_uncertain_even_when_the_label_equals_an_option_value(chrome):
    page = hintless(chrome)
    # The button shows 8, the data-value of option 9 (values counted from 0); the page ignores the click.
    target = hintless_pin(chrome, page, '#stale-label', 'cc-exp-month', field_purpose='cc-exp-month')
    assert target['ok'], target
    assert fill(chrome, target, 'cc-exp-month') == failure(True)
    assert evaluate(chrome, "document.querySelector('#stale-label').firstElementChild.textContent") == '8'
