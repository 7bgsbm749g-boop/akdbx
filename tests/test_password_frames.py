"""Child-frame DOM password delivery in an isolated Chrome, TLS sites and X server.

Synthetic values only. Hostnames map to one local TLS server through Chrome's
host resolver rules; `auth.example.com` is forced out of process so both the
in-process and OOPIF routes run. Never attaches to an existing browser or :99.
"""
import json
import os
import shutil
import signal
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from akdbx import cli, password_frames
from akdbx.broker import Broker
from akdbx.browser_password import CDP, DELIVERY, FILL, endpoint
from akdbx.target import TargetError, X11Typer, failure
from test_broker import Entry, Vault
from test_target import isolated_x11

HOSTS = ('login.example.com', 'auth.example.com', 'sso.example.com', 'evil.example.net')
FORM = '''<!doctype html><style>body{margin:0}input{display:block;width:200px;height:20px;margin:2px}</style>
<form><input id=username autocomplete=username><input id=password type=password autocomplete=current-password></form>
<script>window.events=[];document.addEventListener('input',e=>events.push(e.target.id))</script>'''
FRAME = '<iframe id=f src="{}" {} style="width:280px;height:110px;border:0"></iframe>'
PAGES = {
    # Top-level scenarios on login.example.com unless the host says otherwise.
    '/same': FRAME.format('https://login.example.com/form', ''),
    '/inproc': FRAME.format('https://sso.example.com/form', ''),
    '/oopif': FRAME.format('https://auth.example.com/form', ''),
    '/nested': FRAME.format('https://sso.example.com/mid', ''),
    '/mid': FRAME.format('https://auth.example.com/form', '').replace('280px', '260px').replace('110px', '90px'),
    '/hostile-child': FRAME.format('https://evil.example.net/form', ''),
    '/hostile-middle': FRAME.format('https://evil.example.net/mid', ''),
    '/sandbox-scripts-only': FRAME.format('https://sso.example.com/form', 'sandbox="allow-scripts allow-forms"'),
    '/sandbox-no-scripts': FRAME.format('https://sso.example.com/form', 'sandbox="allow-same-origin allow-forms"'),
    '/sandbox-allowed': FRAME.format('https://sso.example.com/form', 'sandbox="allow-scripts allow-same-origin allow-forms"'),
    '/hostile-top': FRAME.format('https://auth.example.com/form', ''),
    '/form': FORM,
}
SECRET = 'Synthetic-FRAME-only!$`\\Aa19 Ω'
USERNAME = 'frame.user+7@example.test'


def browser_binary():
    binary = shutil.which('google-chrome') or shutil.which('chromium')
    if not binary or not shutil.which('openssl') or not shutil.which('Xvfb'):
        message = 'Child-frame password tests require Chrome/Chromium, Xvfb and openssl'
        if os.environ.get('AKDBX_REQUIRE_CARD_CHROMIUM') == '1':
            pytest.fail(message)
        pytest.skip(message)
    return binary


@pytest.fixture
def lab(tmp_path, request):
    binary = browser_binary()
    x11 = request.getfixturevalue('isolated_x11')
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=example.com',
                    '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=15)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            path = self.path.split('?')[0].split('#')[0]
            body = PAGES.get(path, '<!doctype html>blank').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    log = (tmp_path / 'chrome.log').open('wb')
    rules = ','.join(f'MAP {host} 127.0.0.1:{server.server_port}' for host in HOSTS)
    environment = {**os.environ, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/nonexistent/akdbx-frame-test', 'NO_AT_BRIDGE': '1'}
    environment.pop('AT_SPI_BUS_ADDRESS', None)
    process = subprocess.Popen([binary, '--user-data-dir=' + str(profile), '--no-first-run', '--no-default-browser-check',
        '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-extensions',
        '--disable-gpu', '--disable-dev-shm-usage', '--remote-debugging-port=0', '--site-per-process',
        '--isolate-origins=https://auth.example.com', '--no-proxy-server', '--host-resolver-rules=' + rules,
        '--ignore-certificate-errors', '--window-position=0,0', '--window-size=620,460', '--ozone-platform=x11',
        'https://login.example.com/same'], env=environment, stdout=subprocess.DEVNULL, stderr=log,
        start_new_session=True, umask=0o077)
    cdp = None
    try:
        deadline = time.monotonic() + 60
        while cdp is None and time.monotonic() < deadline:
            assert process.poll() is None, 'isolated Chrome exited'
            try:
                endpoint(profile)
                cdp = CDP(profile)
            except Exception:
                time.sleep(.05)
        assert cdp is not None, 'isolated Chrome did not accept a verified debugging connection'
        page = None
        while page is None and time.monotonic() < deadline:
            pages = [t for t in cdp.call('Target.getTargets')['targetInfos'] if t['type'] == 'page']
            page = pages[0]['targetId'] if pages else None
            time.sleep(.05)
        session = cdp.call('Target.attachToTarget', dict(targetId=page, flatten=True))['sessionId']
        from Xlib import Xatom
        from Xlib.error import XError
        root = x11.display.screen().root
        pid_atom = x11.display.intern_atom('_NET_WM_PID')
        window = None
        while window is None and time.monotonic() < deadline:
            for candidate in root.query_tree().children:
                try:
                    prop = candidate.get_full_property(pid_atom, Xatom.CARDINAL)
                    if (prop is not None and list(prop.value) == [process.pid] and candidate.get_wm_class()
                            and candidate.get_attributes().map_state == x11.X.IsViewable):
                        window = candidate
                except XError:
                    continue  # A transient startup window vanished during the scan.
            time.sleep(.05)
        assert window is not None, 'isolated Chrome window not found'
        x11.activate(window)
        yield SimpleNamespace(cdp=cdp, session=session, page=page, profile=profile, x11=x11, window=window)
    except Exception:
        log.flush()
        print('Isolated Chrome diagnostic:', (tmp_path / 'chrome.log').read_text(errors='replace')[-3000:])
        raise
    finally:
        if cdp is not None:
            try:
                cdp.call('Browser.close')
            except Exception:
                pass
            cdp.close()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try:
                # This exact process group belongs to this fixture's own profile.
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        log.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        if process.poll() is not None:
            shutil.rmtree(profile, ignore_errors=True)


def top_eval(env, expression):
    result = env.cdp.call('Runtime.evaluate', dict(expression=expression, returnByValue=True), env.session)
    assert 'exceptionDetails' not in result, result
    return result['result'].get('value')


def frames(env):
    return password_frames.forest(env.cdp, env.session, env.page)[0]


def frame_eval(env, frame_id, expression, gesture=False):
    record = frames(env)[frame_id]
    world = env.cdp.call('Page.createIsolatedWorld', dict(frameId=frame_id, worldName='akdbx-test-observer'),
                         record['session'])['executionContextId']
    result = env.cdp.call('Runtime.evaluate', dict(expression=expression, contextId=world, returnByValue=True,
                          userGesture=gesture), record['session'])
    assert 'exceptionDetails' not in result, result
    return result['result'].get('value')


def frame_with(env, origin, path_ok=lambda url: url.endswith('/form')):
    found = [fid for fid, r in frames(env).items() if r['frame'].get('securityOrigin') == origin
             and path_ok(password_frames.document_url(r['frame']))]
    assert len(found) == 1, found
    return found[0]


def navigate(env, url, origin, wait_form=True):
    env.cdp.call('Page.navigate', dict(url=url), env.session)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if top_eval(env, 'location.href') == url and top_eval(env, "document.readyState") == 'complete':
                if not wait_form:
                    return None
                fid = frame_with(env, origin)
                if frame_eval(env, fid, "document.readyState==='complete' && !!document.getElementById('password')"):
                    return fid
        except (AssertionError, TargetError, KeyError):
            pass
        time.sleep(.05)
    raise AssertionError('synthetic frame scenario did not load')


def focus(env, frame_id, field='password'):
    env.x11.activate(env.window)
    frame_eval(env, frame_id, f"document.getElementById('{field}').focus()", gesture=True)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if frame_eval(env, frame_id, f"document.hasFocus() && document.activeElement.id === '{field}'"):
            return
        time.sleep(.02)
    raise AssertionError('synthetic frame field did not receive focus')


def broker_for(env, url):
    entry = Entry(username=USERNAME, password=SECRET, url=url)
    return Broker(Vault([entry]), X11Typer(), password_browser_profile=env.profile), entry


def request(env, top_url, frame_id, origin, mode='password'):
    value = dict(action='pin-password-target', password_protocol=1, page_id=env.page, frame_id=frame_id, top_url=top_url,
                 selector='#username' if mode == 'username' else '#password', mode=mode,
                 frame_protocol=1, frame_origin=origin)
    if mode == 'login':
        value['username_selector'] = '#username'
    return value


def fill(broker, pin, mode='password'):
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    return broker.dispatch(dict(action='fill', handle=handle, mode=mode, target=pin['target'], target_protocol=1))


def values(env, frame_id):
    return frame_eval(env, frame_id, "[username.value, password.value]")


def secret_anywhere(env):
    """Observe every current document through a separate isolated world."""
    for frame_id in frames(env):
        try:
            found = frame_eval(env, frame_id, 'Array.from(document.querySelectorAll("input")).some(e => e.value === %s)'
                               % json.dumps(SECRET))
        except (AssertionError, TargetError):
            continue  # A document that vanished mid-scan holds no field.
        if found:
            return True
    return False


SCENARIOS = {
    'same-origin': ('https://login.example.com/same', 'https://login.example.com', False),
    'same-site-in-process': ('https://login.example.com/inproc', 'https://sso.example.com', False),
    'same-site-out-of-process': ('https://login.example.com/oopif', 'https://auth.example.com', True),
    'nested-two-levels': ('https://login.example.com/nested', 'https://auth.example.com', True),
    'sandbox-with-scripts-and-origin': ('https://login.example.com/sandbox-allowed', 'https://sso.example.com', None),
}


@pytest.mark.parametrize('mode', ['password', 'login', 'username'])
@pytest.mark.parametrize('scenario', sorted(SCENARIOS))
def test_child_frame_fill_reaches_only_retained_frame_fields(lab, scenario, mode, monkeypatch):
    top, origin, oopif = SCENARIOS[scenario]
    fid = navigate(lab, top, origin)
    broker, entry = broker_for(lab, origin + '/form')
    monkeypatch.setattr(broker.typer, 'deliver', lambda *a, **k: pytest.fail('frame delivery attempted keyboard fallback'))
    try:
        listed = broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=top))
        assert listed['ok'] and listed['page_id'] == lab.page and cli._valid_frame_list(listed), listed
        mine = next(f for f in listed['frames'] if f['frame_id'] == fid)
        assert mine['eligible'] and mine['origin'] == origin and mine['visible_fields'] == dict(password=1, text=1)
        if oopif is not None:
            assert mine['out_of_process'] is oopif
        assert '/form' not in json.dumps(listed)  # Origins only; never frame URLs.
        focus(lab, fid, 'password' if mode == 'password' else 'username')
        pin = broker.dispatch(request(lab, top, fid, origin, mode))
        assert pin == dict(ok=True, target=pin['target'], expires_in=30, target_delivery=DELIVERY), pin
        assert fill(broker, pin, mode) == dict(ok=True, filled=mode, target_delivery=DELIVERY)
        assert values(lab, fid) == [USERNAME if mode != 'password' else '', SECRET if mode != 'username' else '']
        assert top_eval(lab, "Array.from(document.querySelectorAll('input')).every(e => !e.value)")
        assert not fill(broker, pin, mode)['ok']  # Single use.
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('top,origin,saved', [
    # A legitimate page embedding a hostile frame: cross-site chain refuses.
    ('https://login.example.com/hostile-child', 'https://evil.example.net', 'https://evil.example.net/form'),
    # A hostile intermediate frame between legitimate top and login frame.
    ('https://login.example.com/hostile-middle', 'https://auth.example.com', 'https://auth.example.com/form'),
    # A hostile top page embedding the legitimate login frame.
    ('https://evil.example.net/hostile-top', 'https://auth.example.com', 'https://auth.example.com/form'),
    # Sandboxed without scripts, or with an opaque origin.
    ('https://login.example.com/sandbox-no-scripts', 'https://sso.example.com', 'https://sso.example.com/form'),
    ('https://login.example.com/sandbox-scripts-only', 'https://sso.example.com', 'https://sso.example.com/form'),
])
def test_phishing_and_sandboxed_routes_refuse_at_pin(lab, top, origin, saved):
    host = top.split('/')[2]
    fid = navigate(lab, top, origin)
    broker, _ = broker_for(lab, saved)
    try:
        listed = broker.dispatch(dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=top))
        assert listed['ok']
        # Listing applies the same chain and owner rules as a pin.
        assert not next(f for f in listed['frames'] if f['frame_id'] == fid)['eligible']
        if 'no-scripts' not in top:
            focus(lab, fid)
        assert broker.dispatch(request(lab, top, fid, origin)) == failure()
        assert values(lab, fid) == ['', '']
        assert host in top
    finally:
        broker.passwords.close()


def test_route_mismatches_refuse_without_any_value(lab):
    top, origin = 'https://login.example.com/oopif', 'https://auth.example.com'
    fid = navigate(lab, top, origin)
    broker, entry = broker_for(lab, origin + '/form')
    try:
        focus(lab, fid)
        good = request(lab, top, fid, origin)
        main = next(f for f, r in frames(lab).items() if not r['frame'].get('parentId'))
        for changes in [dict(frame_origin='https://sso.example.com'), dict(frame_origin='https://auth.example.com/'),
                        dict(frame_origin='https://AUTH.example.com'), dict(frame_origin='http://auth.example.com'),
                        dict(frame_origin='https://auth.example.com:443'), dict(frame_id=main),
                        dict(frame_id='0' * 32), dict(top_url=top + '#x'), dict(frame_protocol=2), dict(frame_protocol=True)]:
            assert broker.dispatch({**good, **changes}) == failure(), changes
        legacy = {k: v for k, v in good.items() if k not in ('frame_protocol', 'frame_origin')}
        assert broker.dispatch(legacy) == failure()  # Main-frame mode never routes into a child.
        assert broker.dispatch({k: v for k, v in good.items() if k != 'frame_protocol'}) == failure()
        # The saved credential must match the frame origin, not only the site or top page.
        pin = broker.dispatch(good)
        assert pin['ok'], pin
        entry.url = 'https://login.example.com/same'
        assert not fill(broker, pin)['ok']
        assert values(lab, fid) == ['', '']
    finally:
        broker.passwords.close()


def test_detached_frame_refuses(lab):
    top, origin = 'https://login.example.com/inproc', 'https://sso.example.com'
    fid = navigate(lab, top, origin)
    broker, _ = broker_for(lab, origin + '/form')
    try:
        top_eval(lab, 'f.remove()')
        assert broker.dispatch(request(lab, top, fid, origin)) == failure()
    finally:
        broker.passwords.close()


CHANGES = {
    'frame-reload': ('frame', 'location.reload()'),
    'frame-hash': ('frame', "location.hash = 'moved'"),
    'frame-focus-to-top': ('top', "document.body.insertAdjacentHTML('beforeend','<input id=topfield>'); topfield.focus()"),
    'owner-hidden': ('top', "f.style.display = 'none'"),
    'owner-transparent': ('top', "f.style.opacity = '0'"),
    'owner-sandboxed': ('top', "f.setAttribute('sandbox', 'allow-scripts')"),
    'owner-src-changed': ('top', "f.setAttribute('src', f.src + '?again')"),
    'owner-removed': ('top', 'f.remove()'),
    'owner-moved': ('top', 'document.body.append(f)'),
    'top-navigated': ('top', "history.pushState(null, '', location.pathname + '?next')"),
    # Restoring the original state must not resurrect a tainted pin.
    'top-navigated-restored': ('top', "const u = location.href; history.pushState(null, '', '/elsewhere'); history.replaceState(null, '', u)"),
    'owner-name-restored': ('top', "f.setAttribute('name', 'other'); f.removeAttribute('name')"),
    'owner-sandbox-restored': ('top', "f.setAttribute('sandbox', ''); f.removeAttribute('sandbox')"),
    'owner-hidden-restored': ('top', "const e = f; e.remove(); document.body.prepend(e)"),
    'field-replaced': ('frame', "password.outerHTML = '<input id=password type=password autocomplete=current-password>'"),
}


@pytest.mark.parametrize('route', ['same-site-in-process', 'same-site-out-of-process'])
@pytest.mark.parametrize('change', sorted(CHANGES))
def test_changes_after_pin_refuse(lab, route, change):
    top, origin, _ = SCENARIOS[route]
    fid = navigate(lab, top, origin)
    broker, _ = broker_for(lab, origin + '/form')
    try:
        focus(lab, fid)
        pin = broker.dispatch(request(lab, top, fid, origin))
        assert pin['ok'], pin
        where, expression = CHANGES[change]
        if where == 'top':
            top_eval(lab, expression)
        else:
            frame_eval(lab, fid, expression)
        time.sleep(.1)
        assert not fill(broker, pin)['ok']
        assert not secret_anywhere(lab)
    finally:
        broker.passwords.close()


@pytest.mark.parametrize('race', ['owner-hidden', 'focus-to-top', 'frame-navigated'])
def test_change_at_renderer_boundary_refuses(lab, race, monkeypatch):
    top, origin = 'https://login.example.com/oopif', 'https://auth.example.com'
    fid = navigate(lab, top, origin)
    broker, _ = broker_for(lab, origin + '/form')
    try:
        focus(lab, fid)
        pin = broker.dispatch(request(lab, top, fid, origin))
        assert pin['ok'], pin
        retained = broker.passwords.pins[pin['target']][1]
        call = retained.connection.call
        def change_first(method, params=None, session=None, **kwargs):
            if method == 'Runtime.callFunctionOn' and params.get('functionDeclaration') == password_frames.GUARD_CHECK:
                if race == 'owner-hidden':
                    top_eval(lab, "f.style.visibility='hidden'")
                elif race == 'focus-to-top':
                    top_eval(lab, "document.body.insertAdjacentHTML('beforeend','<input id=topfield>'); topfield.focus()")
                else:
                    frame_eval(lab, fid, "history.pushState(null, '', '/elsewhere')")
            return call(method, params, session, **kwargs)
        monkeypatch.setattr(retained.connection, 'call', change_first)
        assert not fill(broker, pin)['ok']
        assert not secret_anywhere(lab)
    finally:
        broker.passwords.close()


def test_listing_requires_exact_top_url_and_capability_shape(lab):
    top, origin = 'https://login.example.com/oopif', 'https://auth.example.com'
    navigate(lab, top, origin)
    broker, _ = broker_for(lab, origin + '/form')
    try:
        base = dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=top)
        for changes in [dict(top_url=top + '?x'), dict(top_url='http://login.example.com/oopif'), dict(frame_protocol=2),
                        dict(page_id='0' * 32), dict(extra=True)]:
            assert not broker.dispatch({**base, **changes})['ok'], changes
        listed = broker.dispatch({**base, 'page_id': lab.page})
        assert listed['ok'] and listed['main_frame_id'] == next(
            f for f, r in frames(lab).items() if not r['frame'].get('parentId'))
        # Discovery works while the vault is locked: it reads no credential.
        broker.vault = None
        assert broker.locked
        assert broker.dispatch(base)['ok']
        assert not broker.dispatch(request(lab, top, frame_with(lab, origin), origin))['ok']
    finally:
        broker.passwords.close()


def test_pin_binds_credential_origin_checks_to_the_frame_url(lab):
    top, origin = 'https://login.example.com/inproc', 'https://sso.example.com'
    fid = navigate(lab, top, origin)
    broker, entry = broker_for(lab, origin + '/form')
    try:
        focus(lab, fid)
        pin = broker.dispatch(request(lab, top, fid, origin))
        assert pin['ok']
        # fill and fill-generated compare the saved/generated origin with this URL.
        retained = broker.passwords.pins[pin['target']][1]
        assert retained.url.startswith(origin + '/') and retained.top_url == top
    finally:
        broker.passwords.close()


def test_failed_pin_releases_owner_tracking(lab, monkeypatch):
    top, origin = 'https://login.example.com/nested', 'https://auth.example.com'
    fid = navigate(lab, top, origin)
    broker, _ = broker_for(lab, origin + '/form')
    released = []
    original = password_frames.release_guards
    def record(cdp, guards):
        released.append(len(guards))
        return original(cdp, guards)
    monkeypatch.setattr(password_frames, 'release_guards', record)
    try:
        focus(lab, fid)
        # Both owner guards exist before the missing selector refuses.
        assert broker.dispatch({**request(lab, top, fid, origin), 'selector': '#missing'}) == failure()
        assert released == [2]
        assert broker.dispatch(request(lab, top, fid, origin))['ok']
    finally:
        broker.passwords.close()
