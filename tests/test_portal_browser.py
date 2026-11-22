"""Isolated synthetic Chromium. Never uses a user desktop/profile or real vault."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from pykeepass.exceptions import CredentialsError
from akdbx.broker import Broker
from akdbx.web_unlock import start_unlock_server
from test_broker import Entry, RecordingTyper, Vault
from test_cards import CARD, begin as begin_card, post as post_card
from test_target import isolated_x11
from test_target_chromium import synthetic_chromium, wait_for
from test_web_unlock import call
from test_writes import deployed, template


def start_bridge(socket):
    class Bridge(BaseHTTPRequestHandler):
        # Only this disposable loopback listener adds a synthetic identity.
        def route(self):
            length = int(self.headers.get('Content-Length', 0))
            assert 0 <= length <= 49152
            body = self.rfile.read(length) if length else None
            code, headers, page = call(socket, self.command, self.path, body, timeout=12)
            self.send_response(code)
            for key, value in headers.items():
                if key.lower() not in {'server', 'date'}:
                    self.send_header(key, value)
            self.end_headers()
            if getattr(self.server, 'drop_response', False):
                # Deliver headers but truncate the response after the server
                # acts, so the browser cannot confirm the result or retry POST.
                self.wfile.write(page[:16])
                self.close_connection = True
                return
            self.wfile.write(page)

        do_GET = do_POST = route

        def log_message(self, *_args):
            pass

    bridge = ThreadingHTTPServer(('127.0.0.1', 0), Bridge)
    worker = threading.Thread(target=bridge.serve_forever, daemon=True)
    worker.start()
    return bridge, worker


@pytest.fixture
def portal_lab(tmp_path):
    entered = threading.Event()
    release = threading.Event()
    attempts = []
    broker = Broker(None, RecordingTyper())

    def opener(*_args):
        attempts.append('attempt')  # No submitted value is inspected or retained.
        entered.set()
        assert release.wait(8), 'synthetic request gate expired'
        if len(attempts) == 1:
            raise CredentialsError('synthetic failure')
        return Vault([Entry()])

    socket = tmp_path / 'private' / 'portal.sock'
    server, url = start_unlock_server(broker, tmp_path / 'unused.kdbx', None,
                                      socket, 'http://127.0.0.1', opener=opener)

    bridge, worker = start_bridge(socket)
    parts = urlsplit(url)
    address = f'http://127.0.0.1:{bridge.server_port}{parts.path}?{parts.query}'
    try:
        yield address, entered, release, attempts, broker, bridge
    finally:
        release.set()
        bridge.shutdown()
        bridge.server_close()
        worker.join(3)
        server.shutdown()
        server.server_close()


def navigate(cdp, session, address):
    cdp.call('Page.navigate', {'url': address}, session)
    wait_for(cdp, session, "document.readyState === 'complete' && document.title === 'AKDBX: Unlock AKDBX'")


@pytest.mark.parametrize('reduced', [False, True])
def test_unlock_visibility_pending_failure_and_success(synthetic_chromium, portal_lab, tmp_path, reduced):
    _, _, cdp, session, _, _ = synthetic_chromium
    address, entered, release, attempts, broker, _ = portal_lab
    cdp.call('Emulation.setDeviceMetricsOverride', {
        'width': 390, 'height': 844, 'deviceScaleFactor': 1, 'mobile': True}, session)
    cdp.call('Emulation.setEmulatedMedia', {'features': [
        {'name': 'prefers-reduced-motion', 'value': 'reduce' if reduced else 'no-preference'}]}, session)
    navigate(cdp, session, address)
    wait_for(cdp, session, "document.getAnimations().every(a => a.effect.getTiming().iterations === Infinity || a.playState === 'finished')")
    assert cdp.evaluate("document.querySelector('h1').textContent", session) == 'Unlock AKDBX'
    assert cdp.evaluate("document.querySelector('#password').type", session) == 'password'
    assert cdp.evaluate("document.querySelector('[data-password-toggle]').getAttribute('aria-label')", session) == 'Show master password'
    # Native validation must not start a pending state or a request.
    cdp.evaluate("document.querySelector('.unlock-submit').click()", session)
    assert not attempts
    assert cdp.evaluate("document.querySelector('.unlock-submit').disabled", session) is False
    # Activate the eye by keyboard, including when its SVG is the click target.
    cdp.evaluate("document.querySelector('[data-password-toggle]').focus()", session)
    cdp.call('Input.dispatchKeyEvent', {'type': 'keyDown', 'key': ' ', 'code': 'Space', 'windowsVirtualKeyCode': 32}, session)
    cdp.call('Input.dispatchKeyEvent', {'type': 'keyUp', 'key': ' ', 'code': 'Space', 'windowsVirtualKeyCode': 32}, session)
    assert cdp.evaluate("document.querySelector('#password').type", session) == 'text'
    assert cdp.evaluate("document.querySelector('[data-password-toggle]').getAttribute('aria-pressed')", session) == 'true'
    cdp.evaluate("document.querySelector('.password-toggle svg').dispatchEvent(new MouseEvent('click', {bubbles:true}))", session)
    assert cdp.evaluate("document.querySelector('#password').type", session) == 'password'
    # Input is public synthetic text. Tests never read/return a password value.
    cdp.evaluate("document.querySelector('#password').focus()", session)
    cdp.call('Input.insertText', {'text': 'public-synthetic-test-only'}, session)
    rect = cdp.evaluate("(() => {const r=document.querySelector('.unlock-submit').getBoundingClientRect();return [r.width,r.height]})()", session)
    cdp.evaluate("document.querySelector('.unlock-submit').click()", session)
    assert entered.wait(3)
    pending = cdp.evaluate("""(() => {
      const form=document.querySelector('form'), button=form.querySelector('.unlock-submit');
      const bar=button.querySelector('[role=progressbar]'), r=button.getBoundingClientRect();
      const b=bar.getBoundingClientRect(), style=getComputedStyle(button);
      const duplicate=new Event('submit',{bubbles:true,cancelable:true});
      form.dispatchEvent(duplicate);
      return {busy:form.getAttribute('aria-busy'),disabled:button.disabled,
        pressed:button.classList.contains('is-pending'),label:button.innerText,
        barVisible:!bar.hidden,indeterminate:!bar.hasAttribute('aria-valuenow'),
        size:[r.width,r.height],contained:b.left>=r.left&&b.right<=r.right&&b.top>=r.top&&b.bottom<=r.bottom,
        clipped:style.overflow==='hidden',radius:style.borderRadius,opacity:style.opacity,
        buttonTransform:style.transform,sheetTransform:getComputedStyle(document.querySelector('.sheet')).transform,
        fieldTransform:getComputedStyle(document.querySelector('.field')).transform,
        buttonRect:[r.left,r.top,r.right,r.bottom],barRect:[b.left,b.top,b.right,b.bottom],
        animation:getComputedStyle(bar,'::before').animationName,
        outsideBusy:!document.querySelector('#unlock-status').closest('[aria-busy=true]'),
        status:document.querySelector('#unlock-status').textContent,
        duplicatePrevented:duplicate.defaultPrevented,
        noOverflow:document.documentElement.scrollWidth<=innerWidth};
    })()""", session)
    (tmp_path / 'synthetic-pending.json').write_text(json.dumps(pending, indent=2))
    assert pending['busy'] == 'true' and pending['disabled'] and pending['pressed']
    assert pending['size'] == rect
    assert pending['barVisible'] and pending['contained'] and pending['clipped'] and pending['indeterminate']
    assert pending['opacity'] == '1' and pending['radius'] == '13px'
    assert pending['outsideBusy'] and pending['duplicatePrevented'] and pending['noOverflow']
    assert pending['label'] == 'Unlocking AKDBX…'
    assert pending['status'] == 'Unlocking AKDBX. Please wait.'
    assert pending['animation'] == ('none' if reduced else 'unlock-loading')
    motion = cdp.call('Runtime.evaluate', {
        'expression': """(async () => {
          const bar=document.querySelector('.unlock-progress');
          const first=getComputedStyle(bar,'::before').transform;
          // The eased bar barely moves in its first frames; sample well apart.
          await new Promise(resolve => setTimeout(resolve, 300));
          await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
          return {first,last:getComputedStyle(bar,'::before').transform};
        })()""", 'awaitPromise': True, 'returnByValue': True}, session)
    assert 'exceptionDetails' not in motion
    positions = motion['result']['value']
    assert (positions['first'] == positions['last']) is reduced
    assert attempts == ['attempt'] and broker.locked
    # Capture only presentation: the synthetic input is hidden on submission.
    shot = cdp.call('Page.captureScreenshot', {'format': 'png'}, session)
    (tmp_path / 'synthetic-pending.png').write_bytes(base64.b64decode(shot['data']))
    (tmp_path / 'synthetic-pending.json').write_text(json.dumps(pending, indent=2))
    release.set()
    wait_for(cdp, session, "!!document.querySelector('[role=alert]') && !document.querySelector('.unlock-submit').disabled")
    assert broker.locked and len(attempts) == 1
    assert cdp.evaluate("document.querySelector('#password').type", session) == 'password'
    assert cdp.evaluate("document.querySelector('#password').hasAttribute('value')", session) is False
    assert cdp.evaluate("document.querySelector('#password').checkValidity()", session) is False
    assert cdp.evaluate("document.querySelector('.unlock-progress').hidden", session) is True
    assert cdp.evaluate("document.querySelector('form').getAttribute('aria-busy')", session) is None
    assert cdp.evaluate("document.querySelector('[role=alert]').textContent", session).startswith('AKDBX could not unlock')
    cdp.evaluate("document.querySelector('#password').focus()", session)
    cdp.call('Input.insertText', {'text': 'public-synthetic-test-only'}, session)
    cdp.evaluate("document.querySelector('.unlock-submit').click()", session)
    wait_for(cdp, session, "document.querySelector('h1').textContent === 'Vault unlocked'")
    assert not broker.locked and len(attempts) == 2
    assert cdp.evaluate("document.querySelector('.sheet').textContent.includes('The AKDBX broker is ready.')", session)
    assert cdp.evaluate("document.querySelector('form') === null", session)


def test_csp_blocks_unapproved_scripts_and_history_restores_controls(synthetic_chromium, portal_lab):
    _, _, cdp, session, _, _ = synthetic_chromium
    address, _, _, attempts, _, _ = portal_lab
    navigate(cdp, session, address)
    # Executed via DOM insertion, so Chrome enforces the real response CSP.
    cdp.evaluate("""(() => {
      const script=document.createElement('script');
      script.textContent='window.unapprovedScriptRan=true';document.body.append(script);
      const button=document.createElement('button');
      button.setAttribute('onclick','window.unapprovedHandlerRan=true');
      document.body.append(button);button.click();button.remove();
    })()""", session)
    assert cdp.evaluate("window.unapprovedScriptRan === undefined && window.unapprovedHandlerRan === undefined", session)
    # The hash-authorized script must still work under the same CSP.
    cdp.evaluate("document.querySelector('[data-password-toggle]').click()", session)
    assert cdp.evaluate("document.querySelector('#password').type", session) == 'text'
    # Simulate a back/forward-cache pageshow after an interrupted request.
    cdp.evaluate("""(() => {
      document.querySelector('form').setAttribute('aria-busy','true');
      const b=document.querySelector('.unlock-submit');b.disabled=true;b.classList.add('is-pending');
      b.querySelector('.unlock-progress').hidden=false;
      window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
    })()""", session)
    assert cdp.evaluate("document.querySelector('#password').type", session) == 'password'
    assert cdp.evaluate("!document.querySelector('.unlock-submit').disabled && document.querySelector('.unlock-progress').hidden && !document.querySelector('.unlock-submit').classList.contains('is-pending')", session)
    assert cdp.evaluate("document.querySelector('form').hasAttribute('aria-busy')", session) is False
    assert not attempts


def test_network_failure_restores_controls_without_claiming_success(synthetic_chromium, portal_lab):
    _, _, cdp, session, _, _ = synthetic_chromium
    address, _, release, attempts, broker, bridge = portal_lab
    navigate(cdp, session, address)
    release.set()
    cdp.evaluate("document.querySelector('#password').focus()", session)
    cdp.call('Input.insertText', {'text': 'public-synthetic-test-only'}, session)
    cdp.evaluate("document.querySelector('.unlock-submit').click()", session)
    wait_for(cdp, session, "!!document.querySelector('[role=alert]')")
    # The next POST succeeds in the synthetic broker, but its response is lost.
    bridge.drop_response = True
    cdp.evaluate("document.querySelector('#password').focus()", session)
    cdp.call('Input.insertText', {'text': 'public-synthetic-test-only'}, session)
    cdp.evaluate("document.querySelector('.unlock-submit').click()", session)
    wait_for(cdp, session, "document.querySelector('#unlock-status').classList.contains('is-error')")
    assert not broker.locked and len(attempts) == 2
    assert cdp.evaluate("document.querySelector('[role=alert]') === null", session)
    assert cdp.evaluate("document.querySelector('#unlock-status').textContent", session) == 'AKDBX unlock result not confirmed. Check its status before trying again.'
    assert cdp.evaluate("!document.querySelector('.unlock-submit').disabled && document.querySelector('.unlock-progress').hidden", session)
    assert cdp.evaluate("document.querySelector('#password').checkValidity()", session) is False
    assert cdp.evaluate("getComputedStyle(document.querySelector('#unlock-status')).position", session) == 'static'


@pytest.fixture
def card_lab(deployed):
    broker, _, _, socket = deployed
    entered, release = threading.Event(), threading.Event()
    original = broker.cards.submit

    def gated(*args, **kwargs):
        # Hold the save so the busy state can be observed; no value is read.
        entered.set()
        assert release.wait(8), 'synthetic save gate expired'
        return original(*args, **kwargs)

    broker.cards.submit = gated
    bridge, worker = start_bridge(socket)
    try:
        yield broker, socket, f'http://127.0.0.1:{bridge.server_port}', entered, release
    finally:
        release.set()
        bridge.shutdown()
        bridge.server_close()
        worker.join(3)


def open_card_page(cdp, session, base, prepared):
    parts = urlsplit(prepared['private_url'])
    cdp.call('Page.navigate', {'url': base + parts.path + '?' + parts.query}, session)
    wait_for(cdp, session, "document.readyState === 'complete' && document.title === 'AKDBX: Save AKDBX card'")


def enter(cdp, session, values):
    # Public synthetic test values only; tests never read a card value back.
    for key, text in values.items():
        cdp.evaluate(f"document.getElementById('{key}').value = ''", session)
        cdp.evaluate(f"document.getElementById('{key}').focus()", session)
        cdp.call('Input.insertText', {'text': text}, session)


def button(cdp, session):
    return cdp.evaluate("""(() => { const b = document.querySelector('.portal-submit');
      return {disabled: b.disabled, pending: b.classList.contains('is-pending'), done: b.classList.contains('is-done'),
        error: b.classList.contains('is-error'), label: b.querySelector('.button-label').textContent,
        bar: !b.querySelector('.portal-progress').hidden, busy: b.form.getAttribute('aria-busy'),
        status: document.getElementById('card-status').textContent}; })()""", session)


def test_card_page_checks_details_then_shows_busy_and_saved_states(synthetic_chromium, card_lab):
    _, _, cdp, session, _, _ = synthetic_chromium
    broker, _, base, entered, release = card_lab
    prepared = begin_card(broker)
    open_card_page(cdp, session, base, prepared)
    assert cdp.evaluate("document.getElementById('title').value", session) == 'Synthetic Visa'
    assert cdp.evaluate("[...document.querySelectorAll('#group option')].map(o => [o.value, o.selected])", session) == [
        ['', False], ['Web', True]]
    enter(cdp, session, dict(CARD, number='4111 1111 1111 1112', month='13', csc='12'))
    assert cdp.evaluate("document.getElementById('card-brand').textContent", session) == 'Detected brand: Visa.'
    cdp.evaluate("document.querySelector('input[name=confirmed]').click()", session)
    cdp.evaluate("document.querySelector('.portal-submit').click()", session)
    # The page refuses the checksum, month and code itself; nothing is sent.
    assert cdp.evaluate("[...document.querySelectorAll('.field-error:not([hidden])')].map(e => e.id)", session) == [
        'number-error', 'month-error', 'csc-error']
    assert cdp.evaluate("document.activeElement.id", session) == 'number'
    assert not entered.wait(.3)
    assert button(cdp, session)['status'] == 'Check the marked card details.'
    enter(cdp, session, dict(number=CARD['number'], month=CARD['month'], csc=CARD['csc']))
    assert cdp.evaluate("document.querySelectorAll('.field-error:not([hidden])').length", session) == 0
    cdp.evaluate("document.getElementById('title').value = 'Synthetic travel card'", session)
    cdp.evaluate("document.getElementById('group').value = ''", session)
    cdp.evaluate("document.querySelector('.portal-submit').click()", session)
    assert entered.wait(3)
    pending = button(cdp, session)
    assert pending['disabled'] and pending['pending'] and pending['bar'] and pending['busy'] == 'true'
    assert pending['label'] == 'Saving card\u2026'
    release.set()
    wait_for(cdp, session, "document.querySelector('.portal-submit').classList.contains('is-done')")
    saved = button(cdp, session)
    assert saved['disabled'] and saved['label'] == 'Saved' and not saved['bar'] and saved['busy'] is None
    assert saved['status'] == ('Card saved to AKDBX as \u201cSynthetic travel card\u201d in '
                               'Top level (no folder). You may close this page.')
    assert cdp.evaluate("[...document.querySelectorAll('form input, form select')].every(c => c.disabled)", session)
    assert cdp.evaluate("document.getElementById('number').value === ''", session)
    assert cdp.evaluate("document.getElementById('title').value", session) == 'Synthetic travel card'
    assert broker.dispatch(dict(action='write-status', write_handle=prepared['write_handle'])) == dict(
        ok=True, state='saved', title='Synthetic travel card', group='')


def test_card_page_shows_broker_refusal_and_vault_change(synthetic_chromium, card_lab):
    _, _, cdp, session, _, _ = synthetic_chromium
    broker, socket, base, _, release = card_lab
    release.set()
    first = begin_card(broker)
    assert post_card(socket, first)[0] == 200
    # A duplicate title passes the page checks but the broker refuses it.
    duplicate = begin_card(broker)
    open_card_page(cdp, session, base, duplicate)
    enter(cdp, session, CARD)
    cdp.evaluate("document.querySelector('input[name=confirmed]').click()", session)
    cdp.evaluate("document.querySelector('.portal-submit').click()", session)
    wait_for(cdp, session, "document.getElementById('card-status').classList.contains('is-error')")
    refused = button(cdp, session)
    assert not refused['disabled'] and not refused['error'] and refused['label'] == 'Save card to AKDBX'
    assert refused['status'] == 'A card with this title already exists in this group. Choose another title.'
    # Another save changes the vault; this page can no longer save.
    other = begin_card(broker, metadata=dict(title='Synthetic other card', group='Web'))
    assert post_card(socket, other)[0] == 200
    cdp.evaluate("document.querySelector('.portal-submit').click()", session)
    wait_for(cdp, session, "document.querySelector('.portal-submit').classList.contains('is-error')")
    changed = button(cdp, session)
    assert changed['disabled'] and changed['label'] == 'Vault changed'
    assert changed['status'].startswith('The vault changed after this page opened')
