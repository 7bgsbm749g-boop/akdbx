"""Android route on a real emulator: Chrome pages from pin through save.

These tests drive a real Android emulator (or device) and its Chrome through
the real broker, the real CLI and the bundled helper. They are opt-in, because
they need KVM and an Android SDK with a Google Play system image:

    AKDBX_TEST_ANDROID_DEVICES  device file in the broker's format (0600)
    AKDBX_TEST_ANDROID_DEVICE   the name of one device in it
    AKDBX_TEST_ANDROID_COLD_BOOTS
                                managed emulators only: stop and cold-boot the
                                emulator this many times (default 0: skip)

Chrome must already show its normal browser UI (first-run screens done). The
device needs network access to https://example.com: the tests replace that
page's document with a synthetic form, so every value comes from this file
or the broker. Synthetic vault and values only; never a real vault or account.
No CLI output may contain a value.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from pykeepass import PyKeePass

from akdbx import android_lifecycle, cli
from akdbx.android_route import ORIGIN_MISMATCH, Adb, load_devices
from akdbx.broker import Broker, open_vault_with_password
from akdbx.totp import code_at, parse_setup
from akdbx.totp_capture import PENDING_FIELD
from akdbx.web_unlock import start_unlock_server
from test_broker import RecordingTyper, running_broker
from test_cards import CARD
from test_web_unlock import call
from test_writes import MASTER, template  # noqa: F401  (fixture)

DEVICES = os.environ.get('AKDBX_TEST_ANDROID_DEVICES')
NAME = os.environ.get('AKDBX_TEST_ANDROID_DEVICE')
COLD_BOOTS = int(os.environ.get('AKDBX_TEST_ANDROID_COLD_BOOTS', '0') or 0)
pytestmark = pytest.mark.skipif(not (DEVICES and NAME), reason='needs a real Android emulator or device '
                                '(AKDBX_TEST_ANDROID_DEVICES and AKDBX_TEST_ANDROID_DEVICE)')

URL = 'https://example.com/'
ORIGIN = 'https://example.com'
UNLOCK = 'https://node.example:9443'
SITE = dict(title='Synthetic Android site', username='synthetic-android-user', url=ORIGIN + '/login', group='Web')
OTHER = dict(title='Synthetic other site', username='synthetic-other-user', url='https://other.example/login', group='Web')


def b32(raw):
    return base64.b32encode(raw).decode('ascii').rstrip('=')


SECRET = 'SynthAndroid' + secrets.token_hex(12)
CHANGED = 'SynthChanged' + secrets.token_hex(12)
KEY = b32(secrets.token_bytes(20))
GROUPED = ' '.join(KEY[i:i + 4] for i in range(0, len(KEY), 4))
# The lab emulator's viewport is 360 CSS pixels wide: each value fits on one line.
STYLE = ('<meta name="viewport" content="width=device-width">'
         '<style>body{margin:8px;font:16px sans-serif}input,code{display:block;margin:6px 0;font:13px monospace}'
         'input{width:330px}</style>')
VALUES = (SECRET, CHANGED, KEY, GROUPED, MASTER)


def clean(*items, values=VALUES):
    text = json.dumps(items)
    return not any(value in text for value in values)


# ----- the device, Chrome and the page ------------------------------------

@pytest.fixture
def device():
    devices = load_devices(Path(DEVICES))
    if NAME not in devices:
        pytest.fail(f'device {NAME!r} is not in {DEVICES}')
    return devices[NAME]


def stop_managed(device):
    """Stop the managed emulator, so the next lease boots it from cold (the worker never uses snapshots)."""
    unit, directory = android_lifecycle.runtime(device)
    subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True, timeout=120)
    deadline = time.monotonic() + 60
    while directory.exists() or android_lifecycle.state(device) != 'asleep':
        assert time.monotonic() < deadline, 'managed emulator did not stop'
        time.sleep(.5)


class Chrome:
    """The test's own DevTools view of the device's Chrome: it loads the synthetic page and reads it back."""

    def __init__(self, route, device):
        self.route, self.device, self.adb = route, device, Adb(device)
        self.connection = None
        self.session = None

    def open(self, html, timeout=90):
        self.adb.run('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
        self.adb.run('shell', 'wm', 'dismiss-keyguard')
        # One application ID: Chrome reuses its tab instead of opening a new one each time.
        self.adb.run('shell', 'am', 'start', '-W', '-a', 'android.intent.action.VIEW', '-d', URL,
                     '--es', 'com.android.browser.application_id', 'org.akdbx.test', 'com.android.chrome',
                     timeout=timeout).check_returncode()
        deadline = time.monotonic() + timeout
        while True:
            try:
                if self.connection is None:
                    self.connection = self.route._cdp(self.adb)
                pages = [t for t in self.connection.call('Target.getTargets')['targetInfos']
                         if t['type'] == 'page' and t['url'] == URL]
                if pages:
                    break
            except Exception:
                if self.connection is not None:
                    self.connection.close()
                    self.connection = None
            assert time.monotonic() < deadline, 'Chrome did not show the fixture page'
            time.sleep(1)
        self.session = self.connection.call('Target.attachToTarget', {'targetId': pages[-1]['targetId'],
                                                                       'flatten': True})['sessionId']
        self.connection.call('Page.bringToFront', session=self.session)
        # Right after a boot the network may still be down and Chrome shows its error page.
        while self.js("location.href + ' ' + document.readyState") != URL + ' complete':
            assert time.monotonic() < deadline, 'Chrome could not load the fixture page'
            time.sleep(2)
            if self.js('location.href') != URL:
                self.connection.call('Page.navigate', {'url': URL}, self.session)
        self.load(html)
        return self

    def load(self, html):
        frame = self.connection.call('Page.getFrameTree', session=self.session)['frameTree']['frame']['id']
        self.connection.call('Page.setDocumentContent', {'frameId': frame, 'html': '<!doctype html>' + STYLE + html},
                             self.session)
        assert self.js('location.href') == URL

    def js(self, expression):
        response = self.connection.call('Runtime.evaluate', {'expression': expression, 'returnByValue': True,
                                                             'awaitPromise': True}, self.session, timeout=10)
        assert 'exceptionDetails' not in response, 'fixture script failed'
        return response['result'].get('value')

    def focus(self, selector):
        self.js(f"(e => {{ if (e.tabIndex < 0 && !e.hasAttribute('tabindex')) e.tabIndex = -1; e.focus(); }})"
                f"(document.querySelector({json.dumps(selector)}))")
        deadline = time.monotonic() + 5
        while not self.js(f'document.hasFocus() && document.activeElement === document.querySelector({json.dumps(selector)})'):
            assert time.monotonic() < deadline, 'fixture field did not get the focus'
            time.sleep(.1)

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None


class Lab:
    def __init__(self, broker, path, rpc, web, chrome):
        self.broker, self.path, self.rpc, self.web, self.chrome = broker, path, rpc, web, chrome
        self.last_pin = None
        # Every synthetic value that must never reach CLI output.
        # (Values shorter than 6 characters could match a token by chance.)
        values = {*VALUES, EMAIL, '482915', *CARD.values(), *(e.password for e in PyKeePass(str(path), password=MASTER).entries)}
        self.secrets = {value for value in values if isinstance(value, str) and len(value) >= 6}

    def cli(self, *args):
        """Run the real CLI against the running broker: (exit code, receipt or None, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(['--socket', str(self.rpc), '--unlock-origin', UNLOCK, *args])
        assert clean(out.getvalue(), err.getvalue(), values=self.secrets)
        try:
            receipt = json.loads(out.getvalue())
        except ValueError:
            receipt = None
        return code, receipt, err.getvalue()

    def pin(self, mode, selector, purpose=None):
        self.chrome.focus(selector)
        code, receipt, err = self.cli('android', 'pin', '--device', NAME, '--mode', mode, '--field', selector,
                                      *(('--purpose', purpose) if purpose else ()))
        assert code == 0 and receipt['ok'], (receipt, err)
        assert receipt['origin'] == ORIGIN and receipt['site_source'] == 'chrome'
        self.last_pin = receipt['target']
        return receipt['target']

    def entry(self, values):
        found = [e for e in self.broker.dispatch(dict(action='search', query=values['title']))['entries']
                 if e['title'] == values['title']]
        assert len(found) == 1
        return found[0]['handle']

    def stored(self, title):
        return PyKeePass(str(self.path), password=MASTER).find_entries(title=title, first=True)


def make_lab(tmp, template):  # noqa: F811
    tmp.mkdir(mode=0o700, exist_ok=True)
    path = tmp / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    vault = PyKeePass(str(path), password=MASTER)
    web = vault.find_groups(name='Web', first=True)
    for values in (SITE, OTHER):
        vault.add_entry(web, values['title'], values['username'], 'synthetic-login-' + secrets.token_hex(8),
                        url=values['url'])
    vault.save()
    broker = Broker(open_vault_with_password(path, MASTER), RecordingTyper(), android_devices_path=Path(DEVICES))
    server, _ = start_unlock_server(broker, path, None, tmp / 'private' / 'web.sock', UNLOCK)
    return broker, path, server


@pytest.fixture
def short_tmp(tmp_path):
    # Broker sockets need short paths (AF_UNIX is about 108 bytes).
    base = Path(os.environ.get('XDG_RUNTIME_DIR') or '/tmp')
    folder = Path(__import__('tempfile').mkdtemp(prefix='akdbx-emu-', dir=base))
    try:
        yield folder
    finally:
        shutil.rmtree(folder, ignore_errors=True)


@contextlib.contextmanager
def running(short_tmp, template, device, monkeypatch):  # noqa: F811
    monkeypatch.setenv('AKDBX_ANDROID_DEVICES', DEVICES)
    broker, path, server = make_lab(short_tmp, template)
    rpc = short_tmp / 'cli' / 'broker.sock'
    chrome = Chrome(broker.android, device)
    try:
        with running_broker(rpc, broker), android_lifecycle.use(device):
            yield Lab(broker, path, rpc, short_tmp / 'private' / 'web.sock', chrome)
    finally:
        chrome.close()
        server.shutdown()
        server.server_close()


@pytest.fixture
def lab(short_tmp, template, device, monkeypatch):  # noqa: F811
    with running(short_tmp, template, device, monkeypatch) as value:
        yield value


# ----- generated passwords ------------------------------------------------

GENERATED_PAGE = '<input id=username autocomplete=username><input id=password type=password autocomplete=new-password>'


def generated_fill(lab, title):
    """Stage a new entry with a generated password, fill it through an Android pin with the real CLI."""
    values = dict(SITE, title=title, username='synthetic-new-' + secrets.token_hex(4))
    staged = lab.broker.dispatch(dict(action='generate-entry', metadata=values, single_field=True))
    assert staged['ok'], staged
    target = lab.pin('password', '#password')
    started = time.monotonic()
    code, receipt, err = lab.cli('fill-generated', '--target-url', URL, '--target', target, '--',
                                 staged['fill_handles']['password'])
    return values, staged, (code, receipt, err), time.monotonic() - started


def test_generated_password_fills_a_chrome_page_and_saves_the_filled_value(lab):
    lab.chrome.open(GENERATED_PAGE)
    values, staged, (code, receipt, err), _ = generated_fill(lab, 'Synthetic generated')
    assert code == 0 and receipt == dict(ok=True, filled='password', target_delivery='android-chrome-verified-dom-v1'), err
    shown = lab.chrome.js('document.querySelector("#password").value')
    assert isinstance(shown, str) and len(shown) >= 16 and clean(receipt, err, values={shown})
    # The pin is single use: a second generated password cannot reach the field with it.
    again = lab.broker.dispatch(dict(action='generate-entry', single_field=True,
                                     metadata=dict(SITE, title='Synthetic generated 2', username='synthetic-second')))
    code, receipt, _ = lab.cli('fill-generated', '--target-url', URL, '--target', lab.last_pin, '--',
                               again['fill_handles']['password'])
    assert code == 1 and receipt['ok'] is False and receipt.get('delivery', 'not-started') == 'not-started'
    assert lab.chrome.js('document.querySelector("#password").value') == shown
    committed = lab.broker.dispatch(dict(action='commit-password', write_handle=staged['write_handle'], site_accepted=True))
    assert committed['ok'], committed
    saved = lab.stored(values['title'])
    assert saved.password == shown and saved.username == values['username'] and saved.url == values['url']


def test_generated_password_refuses_a_page_of_another_site(lab):
    lab.chrome.open(GENERATED_PAGE)
    staged = lab.broker.dispatch(dict(action='generate-entry', single_field=True,
                                      metadata=dict(OTHER, title='Synthetic elsewhere', username='synthetic-elsewhere')))
    target = lab.pin('password', '#password')
    # The asserted reset URL is not the staged entry's site: refused before the pin is used.
    code, receipt, _ = lab.cli('fill-generated', '--target-url', URL, '--target', target, '--',
                               staged['fill_handles']['password'])
    assert code == 1 and receipt == dict(ok=False, error='target site mismatch; no password filled')
    # The asserted URL matches the entry, but the pinned Chrome page is example.com: nothing moves.
    staged = lab.broker.dispatch(dict(action='generate-entry', single_field=True,
                                      metadata=dict(OTHER, title='Synthetic elsewhere 2', username='synthetic-elsewhere-2')))
    code, receipt, _ = lab.cli('fill-generated', '--target-url', OTHER['url'], '--target', target, '--',
                               staged['fill_handles']['password'])
    assert code == 1 and receipt['ok'] is False and receipt['error'] == ORIGIN_MISMATCH
    assert lab.chrome.js('document.querySelector("#password").value') == ''


# ----- cold boot ------------------------------------------------------------

@pytest.mark.skipif(COLD_BOOTS < 1, reason='set AKDBX_TEST_ANDROID_COLD_BOOTS to cold-boot a managed emulator')
def test_generated_fill_right_after_a_cold_boot_fills_or_refuses_cleanly(short_tmp, template, device, monkeypatch):  # noqa: F811
    """Regression: fill-generated right after a cold boot ended with 'connection lost' (exit 2, outcome uncertain).

    Each round stops the managed emulator, boots it again from cold and fills at once. The fill must
    either succeed (the field holds a generated password that the commit saves) or refuse with
    delivery 'not-started' and an empty field. It must never leave the outcome unknown.
    """
    if device.managed is None:
        pytest.skip('cold boots need a managed emulator')
    outcomes = []
    for round_ in range(COLD_BOOTS):
        stop_managed(device)
        booted = time.monotonic()
        with running(short_tmp / str(round_), template, device, monkeypatch) as lab:
            lab.chrome.open(GENERATED_PAGE, timeout=180)
            values, staged, (code, receipt, err), took = generated_fill(lab, f'Synthetic cold {round_}')
            shown = lab.chrome.js('document.querySelector("#password").value')
            if code == 0:
                result = 'filled' if receipt['ok'] and len(shown) >= 16 else 'wrong receipt'
                committed = lab.broker.dispatch(dict(action='commit-password', write_handle=staged['write_handle'],
                                                     site_accepted=True))
                if result == 'filled' and not (committed['ok'] and lab.stored(values['title']).password == shown):
                    result = 'not saved'
            elif code == 1:
                result = 'not started' if receipt.get('delivery') == 'not-started' and shown == '' else 'unclean refusal'
            else:
                result = 'outcome unknown: ' + err.strip()
            outcome = dict(round=round_, after_boot=round(time.monotonic() - booted - took, 1), fill_seconds=round(took, 2),
                           exit=code, result=result)
            outcomes.append(outcome)
            print('cold boot', json.dumps(outcome), flush=True)
    print('cold boot summary', json.dumps(outcomes), flush=True)
    assert all(o['result'] in ('filled', 'not started') for o in outcomes), outcomes


# ----- capture-secret -------------------------------------------------------

SECRET_PAGE = f'''<p>Copy it now. You will not see it again.</p>
<input id=read readonly value="{SECRET}">
<code id=leaf tabindex=0>{SECRET}</code>
<div style="position:relative"><code id=covered tabindex=0>{SECRET}</code>
<div style="position:absolute;inset:0;background:#fff"></div></div>
<input id=writable value="{SECRET}">'''


def capture_secret(lab, target, values=SITE, *, new=False, field='client_secret', replace=False):
    selection = ('--new',) if new else ('--handle', lab.entry(values))
    return lab.cli('capture-secret', '--target', target, '--field', field, *selection,
                   *(['--replace'] if replace else []),
                   *[item for key in ('title', 'username', 'url', 'group') for item in ('--' + key, values[key])])


@pytest.mark.parametrize('selector', ['#read', '#leaf'])
def test_capture_secret_from_an_android_read_pin_saves_a_protected_field(lab, selector):
    lab.chrome.open(SECRET_PAGE)
    code, receipt, err = capture_secret(lab, lab.pin('read', selector))
    assert code == 0, err
    assert receipt == dict(ok=True, state='saved', created=False, field='client_secret', length=len(SECRET),
                           metadata=SITE, capture_delivery='android-chrome-verified-read-v1')
    saved = lab.stored(SITE['title'])
    assert saved.get_custom_property('client_secret') == SECRET
    assert saved.is_custom_property_protected('client_secret')
    # A new secret record of the page's own site works the same way.
    record = dict(title='Synthetic Android app secret', username='synthetic-client-id', url=ORIGIN + '/apps/1', group='Web')
    code, receipt, err = capture_secret(lab, lab.pin('read', selector), record, new=True)
    assert code == 0 and receipt['created'] is True, err
    assert lab.stored(record['title']).get_custom_property('client_secret') == SECRET


def test_capture_secret_refusals_match_the_other_routes(lab):
    lab.chrome.open(SECRET_PAGE)
    # An entry of another site: the read pin is used up and nothing is read or saved.
    target = lab.pin('read', '#read')
    code, receipt, _ = capture_secret(lab, target, OTHER)
    assert code == 1 and receipt['ok'] is False and receipt['error'].startswith('secret capture refused')
    assert lab.stored(OTHER['title']).get_custom_property('client_secret') is None
    # The used pin cannot be spent again, not even for the right entry.
    code, receipt, _ = capture_secret(lab, target)
    assert code == 1 and receipt['ok'] is False
    # A new record must be for the page's own site.
    record = dict(title='Synthetic wrong record', username='synthetic-id', url='https://other.example/apps', group='Web')
    code, receipt, _ = capture_secret(lab, lab.pin('read', '#read'), record, new=True)
    assert code == 1 and receipt['ok'] is False and lab.stored(record['title']) is None
    # The value changes after the pin: refused.
    target = lab.pin('read', '#read')
    lab.chrome.js(f'document.querySelector("#read").value = {json.dumps(CHANGED)}')
    code, receipt, _ = capture_secret(lab, target)
    assert code == 1 and receipt['ok'] is False
    assert lab.stored(SITE['title']).get_custom_property('client_secret') is None
    # Covered text and an editable field are refused at the pin.
    lab.chrome.load(SECRET_PAGE)
    for selector in ('#covered', '#writable'):
        lab.chrome.focus(selector)
        code, receipt, _ = lab.cli('android', 'pin', '--device', NAME, '--mode', 'read', '--field', selector)
        assert code == 1 and receipt['ok'] is False, selector
    # A field that exists needs --replace; with it the old value moves to history.
    assert capture_secret(lab, lab.pin('read', '#read'))[0] == 0
    lab.chrome.js(f'document.querySelector("#read").value = {json.dumps(CHANGED)}')
    code, receipt, _ = capture_secret(lab, lab.pin('read', '#read'))
    assert code == 1 and 'pass --replace' in receipt['error']
    code, receipt, _ = capture_secret(lab, lab.pin('read', '#read'), replace=True)
    assert code == 0, receipt
    saved = lab.stored(SITE['title'])
    assert saved.get_custom_property('client_secret') == CHANGED
    assert saved.history[-1].get_custom_property('client_secret') == SECRET


# ----- capture-totp (text key) --------------------------------------------

TOTP_PAGE = f'''<p id=intro>Scan the QR code or use the setup key.</p>
<code id=setup-key tabindex=0>{GROUPED}</code>
<code id=prose tabindex=0>you will not see this again</code>
<code id=notkey tabindex=0>Synth-{secrets.token_hex(8)}</code>
<label>Verify the code from the app <input id=otp autocomplete=one-time-code inputmode=numeric></label>'''


def capture_totp(lab, target, values=SITE):
    return lab.cli('capture-totp', '--target', target, '--handle', lab.entry(values),
                   *[item for key in ('title', 'username', 'url', 'group') for item in ('--' + key, values[key])])


def fill_code(lab, values=SITE, *, pending):
    """Fill a code (of the pending key, or the saved one) through a fresh Android code pin; wait out a code near its end."""
    for _ in range(3):
        lab.chrome.js('document.querySelector("#otp").value = ""')
        target = lab.pin('totp', '#otp')
        before = time.time()
        code, receipt, err = lab.cli('android', 'fill-totp', lab.entry(values), *(['--pending'] if pending else []),
                                     '--target', target)
        after = time.time()
        if code == 1 and receipt and 'retry_after' in receipt:
            time.sleep(receipt['retry_after'] + .5)
            continue
        return code, receipt, err, (before, after)
    raise AssertionError('authenticator code stayed near expiry')


def test_capture_totp_text_key_fills_the_pending_code_then_commits(lab):
    lab.chrome.open(TOTP_PAGE)
    code, receipt, err = capture_totp(lab, lab.pin('read', '#setup-key'))
    assert code == 0, err
    assert receipt == dict(ok=True, state='pending', totp_configured=False, metadata=SITE,
                           capture_delivery='android-chrome-verified-read-v1')
    pending = lab.stored(SITE['title'])
    assert pending.otp is None and pending.is_custom_property_protected(PENDING_FIELD)
    assert parse_setup(pending.get_custom_property(PENDING_FIELD)).secret == base64.b32decode(KEY)
    code, receipt, err, (before, after) = fill_code(lab, pending=True)
    assert code == 0 and receipt == dict(ok=True, filled='totp', target_delivery='android-chrome-verified-dom-v1'), err
    configuration = parse_setup(KEY)
    assert lab.chrome.js('document.querySelector("#otp").value') in {code_at(configuration, before),
                                                                       code_at(configuration, after)}
    code, receipt, err = lab.cli('commit-totp', '--handle', lab.entry(SITE), '--site-accepted',
                                 *[item for key in ('title', 'username', 'url', 'group') for item in ('--' + key, SITE[key])])
    assert code == 0 and receipt == dict(ok=True, state='saved', replaced=False, metadata=SITE), err
    saved = lab.stored(SITE['title'])
    assert parse_setup(saved.otp).secret == configuration.secret and PENDING_FIELD not in saved.custom_properties
    # The saved authenticator now fills without --pending.
    code, receipt, err, (before, after) = fill_code(lab, pending=False)
    assert code == 0 and receipt == dict(ok=True, filled='totp', target_delivery='android-chrome-verified-dom-v1'), err
    assert lab.chrome.js('document.querySelector("#otp").value') in {code_at(configuration, before),
                                                                       code_at(configuration, after)}


def test_capture_totp_refusals_match_the_other_routes(lab):
    lab.chrome.open(TOTP_PAGE)
    # Prose (text with spaces that is not a grouped key) is refused at the pin, as on the CDP route.
    lab.chrome.focus('#prose')
    code, receipt, _ = lab.cli('android', 'pin', '--device', NAME, '--mode', 'read', '--field', '#prose')
    assert code == 1 and receipt['ok'] is False
    # One word that is not a Base32 key: the read pin is taken, capture-totp refuses and saves nothing.
    code, receipt, _ = capture_totp(lab, lab.pin('read', '#notkey'))
    assert code == 1 and receipt['ok'] is False
    # An entry of another site: the pin is used up, nothing pending.
    code, receipt, _ = capture_totp(lab, lab.pin('read', '#setup-key'), OTHER)
    assert code == 1 and receipt['ok'] is False
    # The page changes after the pin: refused.
    target = lab.pin('read', '#setup-key')
    lab.chrome.js('document.querySelector("#setup-key").textContent = "AAAA BBBB CCCC DDDD"')
    code, receipt, _ = capture_totp(lab, target)
    assert code == 1 and receipt['ok'] is False
    for title in (SITE['title'], OTHER['title']):
        saved = lab.stored(title)
        assert saved.otp is None and PENDING_FIELD not in saved.custom_properties
    # Without a pending key there is nothing to confirm.
    lab.chrome.load(TOTP_PAGE)
    code, receipt, _ = lab.cli('android', 'fill-totp', lab.entry(SITE), '--pending', '--target', lab.pin('totp', '#otp'))
    assert code == 1 and receipt['ok'] is False and lab.chrome.js('document.querySelector("#otp").value') == ''


# ----- identity with --notify-page -----------------------------------------

IDENTITY_PAGE = '<label>Email <input id=email autocomplete=email></label>'
EMAIL = 'synthetic-android@example.test'
LISTEN = '''(() => {
  const field = document.querySelector('#email');
  window.fixtureEvents = [];
  for (const type of ['input', 'change'])
    field.addEventListener(type, e => window.fixtureEvents.push([e.type, e.bubbles, field.value]));
})()'''


def saved_identity(lab):
    pending = lab.broker.dispatch(dict(action='create-identity', identity_protocol=1,
                                       metadata=dict(title='Synthetic Android identity', group='Web'), fields=['email']))
    from urllib.parse import urlencode, urlsplit
    parts = urlsplit(pending['private_url'])
    assert call(lab.web, 'POST', parts.path + '?' + parts.query, urlencode({'email': EMAIL, 'confirmed': 'yes'}))[0] == 200
    [selected] = lab.broker.dispatch(dict(action='search-identities', identity_protocol=1,
                                          query='Synthetic Android identity'))['entries']
    return selected['handle']


@pytest.mark.parametrize('notify', [True, False])
def test_identity_fill_notifies_the_page_only_with_notify_page(lab, notify):
    lab.chrome.open(IDENTITY_PAGE)
    lab.chrome.js(LISTEN)
    handle = saved_identity(lab)
    target = lab.pin('identity', '#email', 'email')
    code, receipt, err = lab.cli('fill-identity', handle, '--target', target, '--field', 'email',
                                 *(['--notify-page'] if notify else []))
    assert code == 0 and receipt == dict(ok=True, filled='email', identity_delivery='android-chrome-verified-dom-v1'), err
    assert lab.chrome.js('document.querySelector("#email").value') == EMAIL
    events = lab.chrome.js('window.fixtureEvents')
    assert events == ([['input', True, EMAIL], ['change', True, EMAIL]] if notify else [])


# ----- logins, cards and SMS codes -----------------------------------------

LOGIN_PAGE = ('<input id=username autocomplete=username><input id=password type=password autocomplete=current-password>'
              '<input id=card autocomplete=cc-name><input id=sms autocomplete=one-time-code inputmode=numeric>')


def test_login_card_and_sms_code_fill_chrome_fields(lab, short_tmp):
    from akdbx.sms import SmsInbox
    from test_cards import begin as begin_card, post as post_card, search as search_cards
    lab.chrome.open(LOGIN_PAGE)
    # Login: username then password, each after its own typed check.
    lab.chrome.focus('#username')
    code, receipt, err = lab.cli('android', 'pin', '--device', NAME, '--mode', 'login', '--username-field', '#username',
                                 '--field', '#password')
    assert code == 0 and receipt['ok'], err
    code, receipt, err = lab.cli('android', 'fill', lab.entry(SITE), '--target', receipt['target'], '--mode', 'login')
    assert code == 0 and receipt == dict(ok=True, filled='login', target_delivery='android-chrome-verified-dom-v1'), err
    saved = lab.stored(SITE['title'])
    assert lab.chrome.js('[username.value, password.value]') == [saved.username, saved.password]
    # Card holder name, saved through the private page.
    assert post_card(lab.web, begin_card(lab.broker))[0] == 200
    [card] = search_cards(lab.broker)['entries']
    code, receipt, err = lab.cli('fill-card', card['handle'], '--target', lab.pin('card', '#card', 'cc-name'),
                                 '--field', 'cc-name')
    assert code == 0 and receipt == dict(ok=True, filled='cc-name', card_delivery='android-chrome-verified-dom-v1'), err
    assert lab.chrome.js('card.value') == CARD['name']
    # An SMS code for this site's challenge page.
    lab.broker.sms = SmsInbox(short_tmp / 'sms' / 'state.json')
    source = lab.broker.sms.add_source('fixture', 'shortcut')
    assert lab.broker.sms.receive(source, 'Synthetic', 'Your synthetic code is 482915') == 'kept'
    [message] = lab.broker.dispatch(dict(action='sms-wait', sms_protocol=1))['messages']
    code, receipt, err = lab.cli('fill-sms-code', message['id'], '--target', lab.pin('sms', '#sms'), '--target-url', URL)
    assert code == 0 and receipt == dict(ok=True, filled='one-time-code', target_delivery='android-chrome-verified-dom-v1'), err
    assert lab.chrome.js('sms.value') == '482915'
