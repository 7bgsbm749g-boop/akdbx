"""Shared Chromium operations through a private slot on Linux and macOS."""
import shutil

from akdbx.broker import Broker, open_vault_with_password
from test_broker import RecordingTyper
from test_card_chromium import chrome, evaluate  # noqa: F401
from test_target import isolated_x11  # noqa: F401
from test_writes import MASTER, template  # noqa: F401


def test_slot_login_generated_read_and_totp(chrome, template, tmp_path):
    database = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, database)
    database.chmod(0o600)
    broker = Broker(open_vault_with_password(database, MASTER), RecordingTyper(),
                    browser_profile_root=chrome.profile.parent)
    broker.writes.public_base = 'https://localhost:9443'
    metadata = dict(title='Synthetic CDP signup', username='synthetic', url=chrome.url, group='Web')
    evaluate(chrome, """document.body.innerHTML = '<input id=u autocomplete=username>' +
      '<input id=p type=password autocomplete=new-password>' +
      '<input id=q type=password autocomplete=new-password>' +
      '<input id=otp autocomplete=one-time-code>' +
      '<code tabindex=0 id=token>Synthetic-Only-CDP-Token</code>' +
      '<code tabindex=0 id=key>GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ</code>'""")

    def pin(field, mode, **extra):
        focused = "u" if mode == "login" else field
        evaluate(chrome, f"document.querySelector('#{focused}').focus()")
        result = broker.dispatch(dict(action='pin-password-target', route='cdp', browser_slot='slot1',
                                      password_protocol=1, page_id=chrome.page, frame_id=chrome.frame,
                                      top_url=chrome.url, selector='#' + field, mode=mode, **extra))
        assert result['ok'], result
        return result['target']

    def handle():
        return broker.dispatch(dict(action='search', query=metadata['title']))['entries'][0]['handle']

    try:
        staged = broker.dispatch(dict(action='generate-entry', metadata=metadata))
        assert staged['ok'], staged
        for reference, field in [('password', 'p'), ('confirmation', 'q')]:
            filled = broker.dispatch(dict(action='fill-generated', handle=staged['fill_handles'][reference],
                                          target_url=chrome.url, target=pin(field, 'password'), target_protocol=1))
            assert filled['ok'], filled
        assert evaluate(chrome, 'p.value.length === 24 && p.value === q.value')
        assert broker.dispatch(dict(action='commit-password', write_handle=staged['write_handle'],
                                    site_accepted=True))['ok']
        evaluate(chrome, "p.autocomplete = 'current-password'")
        for mode in ['username', 'password', 'login']:
            evaluate(chrome, "p.value=''; u.value=''")
            target = pin('u' if mode == 'username' else 'p', mode,
                         **({'username_selector': '#u'} if mode == 'login' else {}))
            assert broker.dispatch(dict(action='fill', target_protocol=1, handle=handle(), target=target,
                                        mode=mode))['ok']
            assert evaluate(chrome, "u.value === 'synthetic'") == (mode != 'password')
            assert evaluate(chrome, 'p.value === q.value') == (mode != 'username')

        saved = broker.dispatch(dict(action='capture-secret', capture_protocol=1, field='client_secret',
                                     target=pin('token', 'read', capture_protocol=1), create=True,
                                     metadata={**metadata, 'title': 'Synthetic captured token', 'username': 'client-id'}))
        assert saved['ok'] and saved['length'] == len('Synthetic-Only-CDP-Token'), saved
        pending = broker.dispatch(dict(action='capture-totp', totp_capture_protocol=1, metadata=metadata,
                                       handle=handle(), target=pin('key', 'read', capture_protocol=1)))
        assert pending['ok'], pending
        broker.wall_clock = lambda: 1111111111
        filled = broker.dispatch(dict(action='fill-totp', pending=True, handle=handle(), target_url=chrome.url,
                                      target_protocol=1, target=pin('otp', 'totp')))
        assert filled['ok'] and evaluate(chrome, 'otp.value === "050471"'), filled
        assert not broker.typer.events
    finally:
        broker.passwords.close()


def test_password_in_listed_child_frame(chrome):
    import time
    from test_broker import Entry, Vault
    origin = 'https://login.example.test'
    top = origin + '/framed'
    entry = Entry(url=origin + '/frame')
    broker = Broker(Vault([entry]), RecordingTyper(), password_browser_profile=chrome.profile)
    chrome.cdp.call('Page.navigate', dict(url=top), chrome.session)
    deadline = time.monotonic() + 5
    while not evaluate(chrome, "!!document.querySelector('iframe')?.contentDocument?.getElementById('password')"):
        assert time.monotonic() < deadline
        time.sleep(.02)
    try:
        listing = broker.dispatch(dict(action='list-password-frames', route='cdp', password_protocol=1,
                                       frame_protocol=1, top_url=top))
        assert listing['ok'], listing
        child, = [frame for frame in listing['frames'] if frame['frame_id'] != chrome.frame]
        assert child['eligible'], child
        evaluate(chrome, "document.querySelector('iframe').contentDocument.querySelector('#password').focus()")
        pin = broker.dispatch(dict(action='pin-password-target', route='cdp', mode='password',
                                   password_protocol=1, frame_protocol=1, top_url=top, page_id=chrome.page,
                                   frame_id=child['frame_id'], frame_origin=origin, selector='#password'))
        assert pin['ok'], pin
        handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
        assert broker.dispatch(dict(action='fill', handle=handle, mode='password', target_protocol=1,
                                    target=pin['target']))['ok']
        assert evaluate(chrome, "document.querySelector('iframe').contentDocument.querySelector('#password').value.length") == len(entry.password)
        assert evaluate(chrome, "document.querySelector('iframe') === document.activeElement")
    finally:
        broker.passwords.close()
