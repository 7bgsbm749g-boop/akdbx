"""Automatic authenticator enrollment end to end, in an isolated Chrome and X server.

A synthetic enrollment page on login.example.com shows a setup key the way
GitHub's "Set up authenticator app" step does (a setup key element and a
"verify the code from the app" field). The broker reads the key itself
(capture-totp), saves it as the entry's pending authenticator, fills a code of
that key into the verify field (fill-totp --pending) and, after the page
accepts it, moves it into the entry's otp field (commit-totp). The page checks
the code with WebCrypto against its own synthetic key: that is the non-secret
"site accepted" signal. Synthetic keys only; never the real vault, profile or
display. No response, CLI output or log may contain a key or a code.
"""
import base64
import hashlib
import hmac
import json
import logging
import secrets
import shutil
import time

import pytest
from pykeepass import PyKeePass

import test_password_frames as frames_lab
from akdbx import cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.target import DELIVERY as X11_DELIVERY, X11Typer, failure
from akdbx.totp_capture import PENDING_FIELD
from akdbx.web_unlock import start_unlock_server
from test_password_frames import frame_eval, lab, top_eval  # noqa: F401  (fixture)
from test_target import isolated_x11  # noqa: F401  (fixture)
from test_writes import MASTER, template  # noqa: F401  (fixture)


def b32(raw):
    return base64.b32encode(raw).decode('ascii').rstrip('=')


KEY = b32(secrets.token_bytes(20))      # The site's new key (32 Base32 characters).
NEXT_KEY = b32(secrets.token_bytes(20))  # The key a restarted enrollment shows.
OLD_KEY = b32(secrets.token_bytes(20))   # An authenticator the entry already has.
GROUPED = ' '.join(KEY[i:i + 4] for i in range(0, len(KEY), 4)).lower()
# A 16-byte key needs Base32 padding; printed in groups of four.
PADDED_KEY = base64.b32encode(secrets.token_bytes(16)).decode('ascii')
PADDED = ' '.join(PADDED_KEY[i:i + 4] for i in range(0, len(PADDED_KEY), 4))
URI = 'otpauth://totp/Synthetic:synthetic-octocat?secret=' + KEY + '&issuer=Synthetic'
STYLE = '<style>body{margin:0;font:14px sans-serif}code,input,p{display:block;margin:2px}code{font:14px monospace}</style>'


def enrollment_page(key):
    """The enrollment step: setup key, code field, and the site's own code check."""
    return STYLE + f'''<p id=intro>Scan the QR code or use the setup key.</p>
<code id=setup-key>{key}</code>
<code id=grouped>{' '.join(key[i:i + 4] for i in range(0, len(key), 4)).lower()}</code>
<code id=uri>{URI.replace(KEY, key)}</code>
<code id=padded>{PADDED}</code>
<code id=prose>you will not see this again</code>
<code id=notkey>Synth-{secrets.token_hex(8)}</code>
<label>Verify the code from the app <input id=otp autocomplete=one-time-code inputmode=numeric></label>
<script>
const KEY = {json.dumps(key)};
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
</script>'''


frames_lab.PAGES.update({
    '/settings/two_factor/setup': enrollment_page(KEY),
    '/settings/two_factor/restart': enrollment_page(NEXT_KEY),
    '/sessions/two-factor': enrollment_page(KEY).replace('Verify the code from the app', 'Authentication code'),
    '/sessions/two-factor-old': enrollment_page(OLD_KEY).replace('Verify the code from the app', 'Authentication code'),
})
SETUP = 'https://login.example.com/settings/two_factor/setup'
RESTART = 'https://login.example.com/settings/two_factor/restart'
SIGN_IN = 'https://login.example.com/sessions/two-factor'
SIGN_IN_OLD = 'https://login.example.com/sessions/two-factor-old'
NEW = dict(title='Synthetic GitHub', username='synthetic-octocat', url='https://login.example.com/login', group='Web')
HAS = dict(title='Synthetic GitHub with app', username='synthetic-second', url='https://login.example.com/login', group='Web')
NOBODY = dict(title='Synthetic GitHub no account', username='', url='https://login.example.com/login', group='Web')
SECRETS = (KEY, NEXT_KEY, OLD_KEY, GROUPED, KEY.lower(), PADDED_KEY.rstrip('='), PADDED)


def old_uri():
    return 'otpauth://totp/synthetic-second?secret=' + OLD_KEY + '&algorithm=SHA1&digits=6&period=30'


@pytest.fixture
def env(lab, tmp_path, template):  # noqa: F811
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    vault = PyKeePass(str(path), password=MASTER)
    web = vault.find_groups(name='Web', first=True)
    vault.add_entry(web, NEW['title'], NEW['username'], 'synthetic-github-password', url=NEW['url'])
    has = vault.add_entry(web, HAS['title'], HAS['username'], 'synthetic-second-password', url=HAS['url'])
    has.otp = old_uri()
    vault.add_entry(web, NOBODY['title'], '', 'synthetic-nobody-password', url=NOBODY['url'])
    vault.save()
    broker = Broker(open_vault_with_password(path, MASTER), X11Typer(), password_browser_profile=lab.profile)
    server, _ = start_unlock_server(broker, path, None, tmp_path / 'private' / 'capture.sock', 'https://node.example:9443')
    lab.broker, lab.path = broker, path
    from Xlib import Xatom
    lab.pid = lab.window.get_full_property(lab.x11.display.intern_atom('_NET_WM_PID'), Xatom.CARDINAL).value[0]
    try:
        yield lab
    finally:
        broker.passwords.close()
        server.shutdown()
        server.server_close()


def open_page(env, url):
    env.cdp.call('Page.navigate', dict(url=url), env.session)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if top_eval(env, 'location.href') == url and top_eval(env, "document.readyState === 'complete' && !!window.otp"):
                return env.cdp.call('Page.getFrameTree', session=env.session)['frameTree']['frame']['id']
        except Exception:
            pass
        time.sleep(.05)
    raise AssertionError('synthetic enrollment page did not load')


def focus(env, fid, selector):
    env.x11.activate(env.window)
    frame_eval(env, fid, 'window.focus()', gesture=True)
    frame_eval(env, fid, f"(e => {{ if (e.tabIndex < 0 && !e.hasAttribute('tabindex')) e.tabIndex = -1; e.focus(); }})"
                         f"(document.querySelector({json.dumps(selector)}))", gesture=True)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if frame_eval(env, fid, f'document.hasFocus() && document.activeElement === document.querySelector({json.dumps(selector)})'):
            return
        time.sleep(.02)
    raise AssertionError('synthetic page did not receive focus')


def read_pin(env, fid, selector, top):
    focus(env, fid, selector)
    return env.broker.dispatch(dict(action='pin-password-target', password_protocol=1, page_id=env.page, frame_id=fid,
                                    top_url=top, selector=selector, mode='read', capture_protocol=1))


def entry(env, values):
    found = [e for e in env.broker.dispatch(dict(action='search', query=values['title']))['entries']
             if e['title'] == values['title']]
    assert len(found) == 1
    return found[0]


def capture(env, target, values=NEW):
    selected = entry(env, values)
    return env.broker.dispatch(dict(action='capture-totp', totp_capture_protocol=1, target=target,
                                    handle=selected['handle'], metadata=dict(values)))


def commit(env, values=NEW, decision='site-accepted', **extra):
    selected = entry(env, values)
    return env.broker.dispatch(dict(action='commit-totp', totp_capture_protocol=1, handle=selected['handle'],
                                    metadata=dict(values), decision=decision, **extra))


def fill_code(env, fid, url, values=NEW, pending=False):
    """Fill a fresh code into the page's code field over a pinned X11 window; wait out a near-expiry code."""
    for _ in range(2):
        frame_eval(env, fid, "otp.value = ''; delete document.body.dataset.result")
        focus(env, fid, '#otp')
        target = env.broker.dispatch(dict(action='pin-target', pid=env.pid, window=env.window.id, target_protocol=1))
        assert target['ok'], target
        request = dict(action='fill-totp', handle=entry(env, values)['handle'], target=target['target'],
                       target_protocol=1, target_url=url)
        if pending:
            request['pending'] = True
        response = env.broker.dispatch(request)
        if 'retry_after' not in response:
            return response
        time.sleep(response['retry_after'] + .2)
    raise AssertionError('authenticator code stayed near expiry')


def page_result(env, fid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = frame_eval(env, fid, 'document.body.dataset.result || null')
        if result:
            return result
        time.sleep(.05)
    return None


def stored(env, title):
    vault = PyKeePass(str(env.path), password=MASTER)
    found = vault.find_entries(title=title, first=True)
    props = found.custom_properties
    return found, found.otp, props.get(PENDING_FIELD), (found.is_custom_property_protected(PENDING_FIELD)
                                                        if PENDING_FIELD in props else None)


def clean(*items):
    text = json.dumps(items)
    for value in SECRETS:
        assert value not in text
    return True


def receipt(values=NEW, had=False, delivery='chromium-dom-read-v1'):
    return dict(ok=True, state='pending', totp_configured=had, metadata=values, capture_delivery=delivery)


def test_enrollment_capture_fill_pending_code_commit_then_sign_in(env, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    fid = open_page(env, SETUP)
    pinned = read_pin(env, fid, '#setup-key', SETUP)
    assert pinned['ok'], pinned
    captured = capture(env, pinned['target'])
    assert captured == receipt(), captured
    found, otp, pending, protected = stored(env, NEW['title'])
    assert otp is None and pending.startswith('otpauth://totp/') and 'secret=' + KEY in pending and protected is True
    assert found.password == 'synthetic-github-password'
    listed = entry(env, NEW)
    assert listed.get('totp_pending') is True and 'totp_configured' not in listed
    # The pin was single use.
    assert capture(env, pinned['target'])['ok'] is False
    # Nothing to fill yet without --pending; the pending key fills the site's verify field.
    refused = fill_code(env, fid, SETUP)
    assert refused['ok'] is False and 'no TOTP configuration' in refused['error']
    filled = fill_code(env, fid, SETUP, pending=True)
    assert filled == dict(ok=True, filled='totp', target_delivery=X11_DELIVERY), filled
    assert page_result(env, fid) == 'accepted'
    saved = commit(env)
    assert saved == dict(ok=True, state='saved', replaced=False, metadata=NEW), saved
    found, otp, pending, _ = stored(env, NEW['title'])
    assert pending is None and 'secret=' + KEY in otp and found.password == 'synthetic-github-password'
    assert found._element.find('./String[Key="otp"]/Value').get('Protected') == 'True'
    listed = entry(env, NEW)
    assert listed['totp_configured'] is True and 'totp_pending' not in listed
    # A later sign-in challenge takes a normal code of the committed key.
    fid = open_page(env, SIGN_IN)
    later = fill_code(env, fid, SIGN_IN)
    assert later['ok'] and page_result(env, fid) == 'accepted'
    assert commit(env)['error'].startswith('no pending captured authenticator')
    out = capsys.readouterr()
    assert clean(pinned, captured, refused, filled, saved, listed, later, out.out, out.err, caplog.text)


@pytest.mark.parametrize('selector', ['#grouped', '#uri'])
def test_grouped_key_and_otpauth_uri_capture(env, selector):
    fid = open_page(env, SETUP)
    pinned = read_pin(env, fid, selector, SETUP)
    assert pinned['ok'], pinned
    assert capture(env, pinned['target']) == receipt()
    assert 'secret=' + KEY in stored(env, NEW['title'])[2]
    assert fill_code(env, fid, SETUP, pending=True)['ok'] and page_result(env, fid) == 'accepted'


def test_existing_authenticator_survives_capture_retry_refusal_and_discard(env):
    fid = open_page(env, SETUP)
    captured = capture(env, read_pin(env, fid, '#setup-key', SETUP)['target'], HAS)
    assert captured == receipt(HAS, had=True)
    _, otp, pending, _ = stored(env, HAS['title'])
    assert otp == old_uri() and 'secret=' + KEY in pending
    # The entry's own authenticator still signs in while the enrollment is pending.
    fid = open_page(env, SIGN_IN_OLD)
    assert fill_code(env, fid, SIGN_IN_OLD, HAS)['ok'] and page_result(env, fid) == 'accepted'
    # A commit without --replace keeps both keys.
    refused = commit(env, HAS)
    assert refused == dict(ok=False, error='TOTP already configured; explicit --replace is required; pending key kept')
    assert stored(env, HAS['title'])[1:3] == (old_uri(), pending)
    # The site restarted enrollment with a new key: the retry replaces only the pending key.
    fid = open_page(env, RESTART)
    assert capture(env, read_pin(env, fid, '#setup-key', RESTART)['target'], HAS)['ok']
    _, otp, pending, _ = stored(env, HAS['title'])
    assert otp == old_uri() and 'secret=' + NEXT_KEY in pending
    discarded = commit(env, HAS, 'discard')
    assert discarded == dict(ok=True, state='discarded', metadata=HAS)
    assert stored(env, HAS['title'])[1:3] == (old_uri(), None)
    assert commit(env, HAS, 'discard', replace=True)['ok'] is False
    # An authorized replacement: --replace, with the old key kept in entry history.
    assert capture(env, read_pin(env, fid, '#setup-key', RESTART)['target'], HAS)['ok']
    assert fill_code(env, fid, RESTART, HAS, pending=True)['ok'] and page_result(env, fid) == 'accepted'
    assert commit(env, HAS, replace=True) == dict(ok=True, state='saved', replaced=True, metadata=HAS)
    found, otp, pending, _ = stored(env, HAS['title'])
    assert 'secret=' + NEXT_KEY in otp and pending is None
    assert old_uri() in [h.otp for h in found.history]


@pytest.mark.parametrize('selector', ['#prose', '#intro'])
def test_prose_refuses_at_pin(env, selector):
    fid = open_page(env, SETUP)
    assert read_pin(env, fid, selector, SETUP) == failure()


def test_non_key_text_wrong_origin_and_changed_metadata_save_nothing(env):
    fid = open_page(env, SETUP)
    before = env.path.read_bytes()
    result = capture(env, read_pin(env, fid, '#notkey', SETUP)['target'])
    assert result['ok'] is False and result['error'].startswith('authenticator capture refused') and clean(result)
    # An entry on another site (example.test) never takes a login.example.com key.
    other = dict(title='Synthetic site', username='synthetic-account', url='https://example.test/login', group='Web')
    result = capture(env, read_pin(env, fid, '#setup-key', SETUP)['target'], other)
    assert result['ok'] is False and 'nothing saved' in result['error']
    selected = entry(env, NEW)
    result = env.broker.dispatch(dict(action='capture-totp', totp_capture_protocol=1,
                                      target=read_pin(env, fid, '#setup-key', SETUP)['target'],
                                      handle=selected['handle'], metadata=dict(NEW, username='someone-else')))
    assert result == dict(ok=False, error='entry metadata mismatch; search again')
    # A capture pin never fills, and a fill pin never captures.
    target = env.broker.dispatch(dict(action='pin-target', pid=env.pid, window=env.window.id, target_protocol=1))
    assert capture(env, target['target'])['ok'] is False
    assert env.path.read_bytes() == before
    assert stored(env, NEW['title'])[1:3] == (None, None)


def test_page_change_after_pin_refuses(env):
    fid = open_page(env, SETUP)
    pinned = read_pin(env, fid, '#setup-key', SETUP)
    frame_eval(env, fid, f"document.getElementById('setup-key').textContent = {json.dumps(NEXT_KEY)}")
    assert capture(env, pinned['target'])['ok'] is False
    assert stored(env, NEW['title'])[2] is None


def test_cli_capture_fill_and_commit_wire_flow(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, 'request', lambda socket, payload, **kwargs: env.broker.dispatch(payload))
    meta = [a for k, v in NEW.items() for a in ('--' + k, v)]
    fid = open_page(env, SETUP)
    focus(env, fid, '#setup-key')
    assert cli.main(['pin-password-target', '--mode', 'read', '--page-id', env.page, '--frame-id', fid,
                     '--top-url', SETUP, '--selector', '#setup-key']) == 0
    target = json.loads(capsys.readouterr().out)['target']
    assert cli.main(['search', NEW['title']]) == 0
    handle = json.loads(capsys.readouterr().out)['entries'][0]['handle']
    assert cli.main(['capture-totp', '--target', target, '--handle', handle, *meta]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)['state'] == 'pending' and clean(out.out, out.err)
    for _ in range(2):
        frame_eval(env, fid, "otp.value = ''; delete document.body.dataset.result")
        focus(env, fid, '#otp')
        assert cli.main(['pin-target', '--pid', str(env.pid), '--window', str(env.window.id)]) == 0
        pin_target = json.loads(capsys.readouterr().out)['target']
        assert cli.main(['search', NEW['title']]) == 0
        handle = json.loads(capsys.readouterr().out)['entries'][0]['handle']
        code = cli.main(['fill-totp', handle, '--pending', '--target-url', SETUP, '--target', pin_target])
        out = capsys.readouterr()
        if code == 0:
            break
        time.sleep(json.loads(out.out).get('retry_after', 0) + .2)
    assert code == 0 and clean(out.out, out.err)
    assert page_result(env, fid) == 'accepted'
    assert cli.main(['search', NEW['title']]) == 0
    handle = json.loads(capsys.readouterr().out)['entries'][0]['handle']
    assert cli.main(['commit-totp', '--handle', handle, '--site-accepted', *meta]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == dict(ok=True, state='saved', replaced=False, metadata=NEW) and clean(out.out, out.err)
    assert cli.main(['commit-totp', '--handle', handle, '--discard', '--replace', *meta]) == 2


def test_pending_key_survives_a_broker_restart_and_commits_after_it(env, tmp_path):
    fid = open_page(env, SETUP)
    assert capture(env, read_pin(env, fid, '#setup-key', SETUP)['target'])['ok']
    env.broker.passwords.close()
    # A restart: a new broker opens the saved vault; the pending key is in the file, not in memory.
    restarted = Broker(open_vault_with_password(env.path, MASTER), X11Typer(), password_browser_profile=env.profile)
    server, _ = start_unlock_server(restarted, env.path, None, tmp_path / 'private2' / 'capture.sock', 'https://node.example:9443')
    try:
        env.broker = restarted
        assert entry(env, NEW)['totp_pending'] is True
        assert fill_code(env, fid, SETUP, pending=True)['ok'] and page_result(env, fid) == 'accepted'
        assert commit(env) == dict(ok=True, state='saved', replaced=False, metadata=NEW)
        assert 'secret=' + KEY in stored(env, NEW['title'])[1]
    finally:
        restarted.passwords.close()
        server.shutdown()
        server.server_close()


def test_padded_grouped_key_captures(env):
    fid = open_page(env, SETUP)
    pinned = read_pin(env, fid, '#padded', SETUP)
    assert pinned['ok'], pinned
    assert capture(env, pinned['target']) == receipt()
    assert 'secret=' + PADDED_KEY.rstrip('=') in stored(env, NEW['title'])[2]


def test_entry_without_an_account_refuses_before_the_read(env):
    """As setup-totp: the username labels a bare key, so a blank one refuses with a fixed reason."""
    fid = open_page(env, SETUP)
    before = env.path.read_bytes()
    pinned = read_pin(env, fid, '#setup-key', SETUP)
    assert capture(env, pinned['target'], NOBODY) == dict(ok=False, error='title, account and a site URL are required')
    assert commit(env, NOBODY) == dict(ok=False, error='title, account and a site URL are required')
    assert env.path.read_bytes() == before
