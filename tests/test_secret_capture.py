"""capture-secret in an isolated Chrome, synthetic TLS sites and X server.

Synthetic secrets only; never the real vault, profile or display. The broker
reads the pinned element itself and saves it through the verified encrypted
persistence. No RPC response, CLI output or log may contain the value.
"""
import json
import logging
import secrets
import shutil

import pytest
from pykeepass import PyKeePass

import test_password_frames as frames_lab
from akdbx import cli
from akdbx.broker import Broker, open_vault_with_password
from akdbx.browser_password import DELIVERY
from akdbx.target import X11Typer, failure
from akdbx.web_unlock import start_unlock_server
from test_password_frames import frame_eval, frame_with, lab, top_eval  # noqa: F401  (fixture)
from test_target import isolated_x11  # noqa: F401  (fixture)
from test_writes import MASTER, template  # noqa: F401  (fixture)

VALUE = 'SynthCapture-' + secrets.token_hex(12)
OTHER = 'SynthOther-' + secrets.token_hex(12)
STYLE = '<style>body{margin:0}code,input,span{display:block;margin:2px;font:14px monospace}</style>'
SECRET_PAGE = STYLE + f'''<p>Copy it now. You will not see it again.</p>
<code id=secret tabindex=0>
   {VALUE}
</code>
<input id=tok readonly value="{VALUE}">
<input id=pw type=password value="{VALUE}">
<code id=multi>{VALUE}<br>{OTHER}</code>
<code id=spaced>{VALUE} {OTHER}</code>
<code id=empty tabindex=0>   </code>
<code id=invisible style="visibility:hidden">{VALUE}</code>
<code id=transparent style="opacity:0">{VALUE}</code>
<code id=twin class=dup>{VALUE}</code><code class=dup>{OTHER}</code>
<code id=wrapper><span style="opacity:0">{VALUE}</span></code>
<input id=writable value="{VALUE}">
<div style="position:relative"><code id=covered>{VALUE}</code><div style="position:absolute;inset:0;background:#fff"></div></div>
<code id=clipped style="clip-path:inset(50%)">{VALUE}</code>
<code id=indented style="overflow:hidden;text-indent:-9999px">{VALUE}</code>
<code id=halfclip style="clip-path:inset(0 0 0 60%)">{VALUE}</code>
<code id=clear style="color:transparent">{VALUE}</code>
<code id=tiny style="font-size:0.5px">{VALUE}</code>'''
frames_lab.PAGES.update({
    '/secret': SECRET_PAGE,
    '/secret-inner': SECRET_PAGE,
    '/secret-same-site-frame': frames_lab.FRAME.format('https://sso.example.com/secret-inner', ''),
    '/secret-cross-site-frame': frames_lab.FRAME.format('https://evil.example.net/secret-inner', ''),
})
TOP = 'https://login.example.com/secret'
NEW = dict(title='Synthetic OAuth app', username='synthetic-client-id', url='https://login.example.com/apps/1', group='Web')


@pytest.fixture
def env(lab, tmp_path, template):  # noqa: F811
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    broker = Broker(open_vault_with_password(path, MASTER), X11Typer(), password_browser_profile=lab.profile)
    server, _ = start_unlock_server(broker, path, None, tmp_path / 'private' / 'capture.sock', 'https://node.example:9443')
    lab.broker, lab.path = broker, path
    try:
        yield lab
    finally:
        broker.passwords.close()
        server.shutdown()
        server.server_close()


def open_page(env, url=TOP):
    env.cdp.call('Page.navigate', dict(url=url), env.session)
    import time
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if top_eval(env, 'location.href') == url and top_eval(env, 'document.readyState') == 'complete':
                if url == TOP:
                    return main_frame(env)
                fid = frame_with(env, url_origin(url, env), lambda u: u.endswith('/secret-inner'))
                if frame_eval(env, fid, "document.readyState==='complete' && !!document.getElementById('secret')"):
                    return fid
        except Exception:
            pass
        time.sleep(.05)
    raise AssertionError('synthetic secret page did not load')


def url_origin(url, env):
    return 'https://sso.example.com' if 'same-site' in url else 'https://evil.example.net'


def main_frame(env):
    return env.cdp.call('Page.getFrameTree', session=env.session)['frameTree']['frame']['id']


def point(env, frame_id, selector, how='focus'):
    """Focus the element like an agent would (making it focusable if needed), or select its text."""
    env.x11.activate(env.window)
    target = f"document.querySelector({json.dumps(selector)})"
    script = (f"getSelection().selectAllChildren({target})" if how == 'select'
              else f"(e => {{ if (e.tabIndex < 0 && !e.hasAttribute('tabindex')) e.tabIndex = -1; e.focus(); }})({target})")
    frame_eval(env, frame_id, "window.focus()", gesture=True)
    frame_eval(env, frame_id, script, gesture=True)
    import time
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if frame_eval(env, frame_id, 'document.hasFocus()'):
            return
        time.sleep(.02)
    raise AssertionError('synthetic page did not receive focus')


def pin(env, frame_id, selector, top=TOP, origin=None, **extra):
    request = dict(action='pin-password-target', password_protocol=1, page_id=env.page, frame_id=frame_id, top_url=top,
                   selector=selector, mode='read', capture_protocol=1, **extra)
    if origin is not None:
        request.update(frame_protocol=1, frame_origin=origin)
    return env.broker.dispatch(request)


def capture(env, target, metadata=NEW, **extra):
    request = dict(action='capture-secret', capture_protocol=1, target=target, field='client_secret',
                   metadata=dict(metadata), **({'create': True} if 'handle' not in extra else {}), **extra)
    return env.broker.dispatch(request)


def stored(env):
    vault = PyKeePass(str(env.path), password=MASTER)
    entry = vault.find_entries(title=NEW['title'], first=True)
    if entry is None:
        return None, None
    return entry.get_custom_property('client_secret'), entry.is_custom_property_protected('client_secret')


def clean(*responses):
    text = json.dumps(responses)
    assert VALUE not in text and OTHER not in text
    return True


@pytest.mark.parametrize('selector,how', [('#secret', 'focus'), ('#twin', 'focus'), ('#tok', 'focus')])
def test_capture_saves_protected_field_and_returns_receipt_only(env, selector, how, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    fid = open_page(env)
    point(env, fid, selector, how)
    pinned = pin(env, fid, selector)
    assert pinned == dict(ok=True, target=pinned['target'], expires_in=30, target_delivery=DELIVERY), pinned
    receipt = capture(env, pinned['target'])
    assert receipt == dict(ok=True, state='saved', created=True, field='client_secret', length=len(VALUE),
                           metadata=NEW, capture_delivery='chromium-dom-read-v1'), receipt
    assert stored(env) == (VALUE, True)
    # Single use: the same pin cannot read again, and a fill cannot use a read pin.
    assert not capture(env, pinned['target'])['ok']
    found = env.broker.dispatch(dict(action='search', query='Synthetic OAuth'))
    record = found['entries'][0]
    assert record['secret_record'] is True and record['captured_fields'] == ['client_secret']
    refused = env.broker.dispatch(dict(action='fill', handle=record['handle'], mode='password',
                                       target=pin(env, fid, selector).get('target', 'x'), target_protocol=1))
    assert not refused['ok']
    out = capsys.readouterr()
    assert clean(pinned, receipt, found, refused, out.out, out.err, caplog.text)


def test_capture_into_existing_entry_requires_exact_metadata_origin_and_replace(env):
    fid = open_page(env)
    point(env, fid, '#secret')
    assert capture(env, pin(env, fid, '#secret')['target'])['ok']
    selected = env.broker.dispatch(dict(action='search', query='Synthetic OAuth'))['entries'][0]
    values = {key: selected[key] for key in ('title', 'username', 'url', 'group')}
    point(env, fid, '#secret')
    # The same field exists: replacing needs an explicit flag.
    refused = capture(env, pin(env, fid, '#secret')['target'], values, handle=selected['handle'])
    assert refused == dict(ok=False, error='entry already has this field; pass --replace to replace it')
    selected = env.broker.dispatch(dict(action='search', query='Synthetic OAuth'))['entries'][0]
    point(env, fid, '#secret')
    wrong = dict(values, title='Other title')
    assert capture(env, pin(env, fid, '#secret')['target'], wrong, handle=selected['handle'],
                   replace=True)['error'] == 'entry metadata mismatch; search again'
    selected = env.broker.dispatch(dict(action='search', query='Synthetic OAuth'))['entries'][0]
    point(env, fid, '#secret')
    receipt = capture(env, pin(env, fid, '#secret')['target'], values, handle=selected['handle'], replace=True)
    assert receipt['ok'] and receipt['created'] is False and clean(receipt)
    # An entry on another origin (example.test) refuses a login.example.com page.
    other = env.broker.dispatch(dict(action='search', query='Synthetic site'))['entries'][0]
    other_values = {key: other[key] for key in ('title', 'username', 'url', 'group')}
    point(env, fid, '#secret')
    before = env.path.read_bytes()
    result = capture(env, pin(env, fid, '#secret')['target'], other_values, handle=other['handle'])
    assert result['ok'] is False and 'nothing saved' in result['error'] and env.path.read_bytes() == before


@pytest.mark.parametrize('selector', ['#multi', '#spaced', '#empty', '#invisible', '#transparent', '#wrapper', '#writable',
                                      '#covered', '#clipped', '#indented', '#halfclip', '#clear', '#tiny',
                                      '.dup', '#pw', '#missing'])
def test_unsafe_elements_refuse_at_pin(env, selector):
    fid = open_page(env)
    point(env, fid, selector if selector not in ('.dup', '#missing') else '#secret')
    assert pin(env, fid, selector) == failure()
    assert stored(env) == (None, None)


def test_pin_requires_focus_on_the_element_and_refuses_text_selection(env):
    fid = open_page(env)
    point(env, fid, '#tok')  # Focus is elsewhere.
    assert pin(env, fid, '#secret') == failure()
    frame_eval(env, fid, 'document.activeElement.blur()')
    point(env, fid, '#secret', 'select')  # A selection publishes PRIMARY on X11: never accepted.
    assert pin(env, fid, '#secret') == failure()
    point(env, fid, '#secret')  # Focused, but text is still selected elsewhere in the document.
    frame_eval(env, fid, "getSelection().selectAllChildren(document.getElementById('twin'))")
    assert pin(env, fid, '#secret') == failure()
    point(env, fid, '#tok')  # A focused input with its own text selected.
    frame_eval(env, fid, "document.getElementById('tok').select()")
    assert pin(env, fid, '#tok') == failure()


@pytest.mark.parametrize('change', [
    "document.getElementById('secret').textContent = %s" % json.dumps(OTHER),
    "document.getElementById('secret').setAttribute('data-x', '1')",
    "document.getElementById('secret').remove()",
    "document.getElementById('tok').focus()",
    "document.getElementById('secret').firstChild.appendData(' ')",  # Whitespace-only change.
    "document.body.contentEditable = 'true'",  # An ancestor makes the element editable.
    "history.pushState(null, '', '/secret?moved')",
])
def test_element_changes_after_pin_refuse_capture(env, change):
    fid = open_page(env)
    point(env, fid, '#secret')
    pinned = pin(env, fid, '#secret')
    assert pinned['ok']
    frame_eval(env, fid, change)
    result = capture(env, pinned['target'])
    assert result['ok'] is False and clean(result)
    assert stored(env) == (None, None)


def test_wrong_top_url_and_page_refuse(env):
    fid = open_page(env)
    point(env, fid, '#secret')
    assert pin(env, fid, '#secret', top='https://login.example.com/secret?x') == failure()
    assert pin(env, fid, '#secret', top='https://evil.example.net/secret') == failure()
    request = dict(action='pin-password-target', password_protocol=1, page_id=env.page, frame_id=fid, top_url=TOP,
                   selector='#secret', mode='read')  # Missing capture protocol.
    assert env.broker.dispatch(request) == failure()
    assert env.broker.dispatch(dict(request, capture_protocol=2)) == failure()
    assert env.broker.dispatch(dict(request, mode='password', capture_protocol=1)) == failure()


def test_same_site_child_frame_captures_and_cross_site_frame_refuses(env):
    top = 'https://login.example.com/secret-same-site-frame'
    fid = open_page(env, top)
    point(env, fid, '#secret', 'focus')
    pinned = pin(env, fid, '#secret', top=top, origin='https://sso.example.com')
    assert pinned['ok'], pinned
    metadata = dict(NEW, url='https://sso.example.com/apps/1')
    receipt = capture(env, pinned['target'], metadata)
    assert receipt['ok'] and clean(receipt)
    hostile = 'https://login.example.com/secret-cross-site-frame'
    fid = open_page(env, hostile)
    point(env, fid, '#secret', 'focus')
    assert pin(env, fid, '#secret', top=hostile, origin='https://evil.example.net') == failure()
    # The main-frame route never reaches into a child frame.
    assert pin(env, fid, '#secret', top=hostile) == failure()


def test_capture_on_page_origin_other_than_new_record_refuses(env):
    fid = open_page(env)
    point(env, fid, '#secret')
    result = capture(env, pin(env, fid, '#secret')['target'], dict(NEW, url='https://example.org/apps/1'))
    assert result['ok'] is False and 'nothing saved' in result['error']
    assert stored(env) == (None, None)


def test_cli_read_pin_and_capture_wire_flow(env, monkeypatch, capsys):
    fid = open_page(env)
    point(env, fid, '#secret')
    monkeypatch.setattr(cli, 'request', lambda socket, payload, **kwargs: env.broker.dispatch(payload))
    assert cli.main(['pin-password-target', '--mode', 'read', '--page-id', env.page, '--frame-id', fid,
                     '--top-url', TOP, '--selector', '#secret']) == 0
    target = json.loads(capsys.readouterr().out)['target']
    assert cli.main(['capture-secret', '--target', target, '--field', 'client_secret', '--new',
                     *[a for k, v in NEW.items() for a in ('--' + k, v)]]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out)['state'] == 'saved' and clean(out.out, out.err)
    assert stored(env) == (VALUE, True)


def test_programmatic_whitespace_change_of_input_value_refuses(env):
    fid = open_page(env)
    point(env, fid, '#tok')
    pinned = pin(env, fid, '#tok')
    assert pinned['ok']
    # Setting .value fires no input event and no mutation; the raw comparison catches it.
    frame_eval(env, fid, "document.getElementById('tok').value = ' ' + document.getElementById('tok').value")
    result = capture(env, pinned['target'])
    assert result['ok'] is False and clean(result)
    assert stored(env) == (None, None)
