"""Two real Chrome slots, each with its own Xvfb display and user-data directory.

This mirrors the agent desktop layout: `<root>/slotN` is the Chrome profile of
slot N, started with --remote-debugging-port=0 under umask 077. Both browsers
show the same HTTPS URL, so only the slot can select the browser.
"""
import json
import os
import select
import shutil
import signal
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from akdbx.broker import Broker
from test_broker import Entry, RecordingTyper, Vault
from test_browser_slots import IdentityEntry, PHONE
from test_card_chromium import CardEntry, card_browser_binary, connect_test_browser
from test_cards import CARD

PASSWORD = 'Synthetic-slot-ONLY!42'
HTML = b'''<!doctype html><title>Synthetic slot lab</title>
<style>input{display:block;width:230px;height:25px;margin:5px}</style>
<input id="password" type="password" autocomplete="current-password">
<input id="number" autocomplete="cc-number"><input id="tel" type="tel" autocomplete="tel">'''


def xvfb(log_path):
    """Start a private X server and hold one client connection open.

    The held connection proves the display accepts clients before Chrome starts
    and keeps the server from resetting when its last client disconnects.
    """
    from Xlib import display as xdisplay
    read_fd, write_fd = os.pipe()
    with open(log_path, 'wb') as log:
        process = subprocess.Popen(['Xvfb', '-displayfd', str(write_fd), '-screen', '0', '1000x1000x24',
                                    '-nolisten', 'tcp', '-noreset'],
                                   pass_fds=(write_fd,), stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
    os.close(write_fd)
    try:
        assert select.select([read_fd], [], [], 10)[0], 'isolated X server startup timed out'
        number = os.read(read_fd, 32).decode().strip()
        assert number.isdecimal() and number != '99'
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, 'isolated X server exited'
            try:
                client = xdisplay.Display(':' + number)
                break
            except Exception:
                assert time.monotonic() < deadline, 'isolated X server accepts no client'
                time.sleep(.05)
    except BaseException:
        process.terminate()
        stop(process)
        raise
    finally:
        os.close(read_fd)
    return process, ':' + number, client


def stop(process, timeout=8):
    try:
        process.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        # Each process group was started by this fixture with start_new_session=True.
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    except ProcessLookupError:
        process.wait(timeout=5)


@pytest.fixture
def slots(tmp_path):
    binary = card_browser_binary()
    for path in [tmp_path, tmp_path.parent]:
        if path.stat().st_uid == os.getuid():
            path.chmod(0o700)
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=127.0.0.1', '-keyout', str(key), '-out', str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(HTML)))
            self.end_headers()
            self.wfile.write(HTML)
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
    url = 'https://127.0.0.1:' + str(server.server_port) + '/checkout'
    root = tmp_path / 'profiles'
    root.mkdir(mode=0o700)
    (root / 'slot2').mkdir(mode=0o700)  # A slot with no running Chrome.
    running, browsers, clients = [], {}, []
    try:
        for name in ('slot1', 'slot4'):
            profile = root / name
            profile.mkdir(mode=0o700)
            display_process, display, client = xvfb(tmp_path / f'{name}-xvfb.log')
            running.append(display_process)
            clients.append(client)
            environment = {**os.environ, 'DISPLAY': display, 'NO_AT_BRIDGE': '1',
                           'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/nonexistent/akdbx-slot-test'}
            log = (tmp_path / f'{name}-chrome.log').open('wb')
            process = subprocess.Popen([binary, '--user-data-dir=' + str(profile), '--no-first-run',
                '--no-default-browser-check', '--disable-background-networking', '--disable-component-update',
                '--disable-sync', '--disable-extensions', '--disable-gpu', '--disable-dev-shm-usage',
                '--renderer-process-limit=2', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
                '--no-proxy-server', '--ignore-certificate-errors', '--window-size=900,900', '--ozone-platform=x11', url],
                env=environment, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True, umask=0o077)
            log.close()
            running.append(process)
            deadline = time.monotonic() + 60
            try:
                cdp = connect_test_browser(profile, process, deadline)
            except AssertionError:
                # Synthetic launch diagnostics only; the lab profile holds no user data.
                for log_name in (f'{name}-chrome.log', f'{name}-xvfb.log'):
                    print(log_name, (tmp_path / log_name).read_text(errors='replace')[-2000:])
                raise
            page = session = None
            while time.monotonic() < deadline:
                pages = [t for t in cdp.call('Target.getTargets')['targetInfos'] if t['type'] == 'page' and t['url'] == url]
                if pages:
                    page = pages[0]['targetId']
                    session = cdp.call('Target.attachToTarget', dict(targetId=page, flatten=True))['sessionId']
                    ready = cdp.call('Runtime.evaluate', dict(expression="document.readyState === 'complete' && "
                                     "!!document.getElementById('tel') && document.hasFocus()", returnByValue=True), session)
                    if ready['result'].get('value'):
                        break
                time.sleep(.05)
            assert page and session, f'{name} Chrome page did not become ready and focused'
            frame = cdp.call('Page.getFrameTree', session=session)['frameTree']['frame']['id']
            browsers[name] = SimpleNamespace(cdp=cdp, session=session, page=page, frame=frame, process=process)
        yield SimpleNamespace(root=root, url=url, browsers=browsers)
    finally:
        for browser in browsers.values():
            try:
                browser.cdp.call('Browser.close')
            except Exception:
                pass
            browser.cdp.close()
        for client in clients:
            client.close()
        for process in reversed(running):
            if process.args[0] == 'Xvfb':
                process.terminate()
            stop(process)
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        if all(process.poll() is not None for process in running):
            shutil.rmtree(root)


def evaluate(browser, expression):
    result = browser.cdp.call('Runtime.evaluate', dict(expression=expression, returnByValue=True), browser.session)
    assert 'exceptionDetails' not in result
    return result['result'].get('value')


def values(lab):
    return {name: evaluate(b, '[password.value, number.value, tel.value]') for name, b in lab.browsers.items()}


def focus(lab, name, element):
    for browser in lab.browsers.values():
        evaluate(browser, "password.value = number.value = tel.value = ''")
    evaluate(lab.browsers[name], f'{element}.focus()')


def password_pin(lab, name, browser=None):
    browser = lab.browsers[browser or name]
    return dict(action='pin-password-target', password_protocol=1, page_id=browser.page, frame_id=browser.frame,
                top_url=lab.url, selector='#password', mode='password', browser_slot=name)


def element_pin(lab, kind, name, field, selector):
    browser = lab.browsers[name]
    return {'action': f'pin-{kind}-target', f'{kind}_protocol': 1, 'page_id': browser.page, 'frame_id': browser.frame,
            'top_url': lab.url, 'frame_url': lab.url, 'selector': selector, 'field': field, 'browser_slot': name}


def fill_password(broker, target):
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    return broker.dispatch(dict(action='fill', handle=handle, mode='password', target=target, target_protocol=1))


def test_real_password_fills_only_the_named_slot_chrome(slots):
    broker = Broker(Vault([Entry(url=slots.url, password=PASSWORD)]), RecordingTyper(), browser_profile_root=slots.root)
    status = broker.dispatch(dict(action='ping'))
    assert status['browser_slots'] == ['slot1', 'slot2', 'slot4'] and status['browser_slots_live'] == ['slot1', 'slot4']
    for name, other in (('slot4', 'slot1'), ('slot1', 'slot4')):
        focus(slots, name, 'password')
        # The other slot's page id names no page in this slot's Chrome.
        assert not broker.dispatch(password_pin(slots, name, browser=other))['ok']
        pin = broker.dispatch(password_pin(slots, name))
        assert pin['ok'], pin
        assert fill_password(broker, pin['target'])['ok']
        assert values(slots) == {name: [PASSWORD, '', ''], other: ['', '', '']}
    del (request := password_pin(slots, 'slot1'))['browser_slot']
    assert 'slots: slot1, slot2, slot4' in broker.dispatch(request)['error']
    focus(slots, 'slot1', 'password')
    assert broker.dispatch(password_pin(slots, 'slot2', browser='slot1'))['delivery'] == 'not-started'
    assert values(slots) == {'slot1': ['', '', ''], 'slot4': ['', '', '']}


def test_real_pin_made_in_slot1_never_reaches_slot4(slots):
    broker = Broker(Vault([Entry(url=slots.url, password=PASSWORD)]), RecordingTyper(), browser_profile_root=slots.root)
    focus(slots, 'slot1', 'password')
    pin = broker.dispatch(password_pin(slots, 'slot1'))
    assert pin['ok'], pin
    # slot4 now has the focused password field too; the slot1 pin still fills slot1.
    evaluate(slots.browsers['slot4'], 'password.focus()')
    assert fill_password(broker, pin['target'])['ok']
    assert values(slots) == {'slot1': [PASSWORD, '', ''], 'slot4': ['', '', '']}


def test_real_card_and_identity_fill_only_the_named_slot_chrome(slots):
    broker = Broker(Vault([CardEntry(), IdentityEntry()]), RecordingTyper(), browser_profile_root=slots.root)
    focus(slots, 'slot4', 'number')
    pin = broker.dispatch(element_pin(slots, 'card', 'slot4', 'cc-number', '#number'))
    assert pin['ok'], pin
    handle = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill-card', card_protocol=1, handle=handle, target=pin['target'],
                                field='cc-number', start_deadline=broker.clock() + 4))['ok']
    assert values(slots) == {'slot4': ['', CARD['number'], ''], 'slot1': ['', '', '']}
    focus(slots, 'slot1', 'tel')
    pin = broker.dispatch(element_pin(slots, 'identity', 'slot1', 'tel', '#tel'))
    assert pin['ok'], pin
    handle = broker.dispatch(dict(action='search-identities', identity_protocol=1, query=''))['entries'][0]['handle']
    assert broker.dispatch(dict(action='fill-identity', identity_protocol=1, handle=handle, target=pin['target'],
                                field='tel', start_deadline=broker.clock() + 4))['ok']
    assert values(slots) == {'slot1': ['', '', PHONE], 'slot4': ['', '', '']}
