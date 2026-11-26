"""Hardware key challenge-response: protocol, discovery, the native host and a real kernel device.

Only synthetic secrets. The protocol tests drive akdbx's code against the
device side in ``virtual_hardware_key.Key``. On Linux with passwordless sudo
and /dev/uhid, ``test_real_hidraw_device`` creates a virtual USB key that the
kernel exposes as /dev/hidrawN, so the real ioctl path runs end to end.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from akdbx import extension_host, hardware_key
from virtual_hardware_key import Key

SECRET = bytes(range(20))
SEED = bytes.fromhex('011ed85afa703341893596fba2da60b6cacabaa5468a0e9ea74698b901bc89ab')


def expected(seed=SEED, secret=SECRET, fixed=False):
    challenge = hardware_key.padded(seed)
    return hmac.new(secret, challenge if fixed else challenge.rstrip(challenge[-1:]), hashlib.sha1).digest()


class FakeTransport:
    """The test side of a HID interface: the virtual key's device logic in memory."""

    def __init__(self, key):
        self.key, self.closed = key, False

    def get(self):
        return self.key.get()

    def set(self, data):
        assert len(data) == 8
        self.key.set(bytes(data))

    def close(self):
        self.closed = True


@pytest.mark.parametrize('fixed', [False, True])
@pytest.mark.parametrize('touch', [False, True])
def test_hid_protocol_answers_like_the_key(fixed, touch):
    key = Key(SECRET, 2, touch, fixed)
    touched = []
    answer = hardware_key.hid_hmac(FakeTransport(key), 0x38, SEED, time.monotonic() + 10, lambda: touched.append(1))
    assert answer == expected(fixed=fixed) and touched == ([1] if touch else [])
    # The read mode was reset: the next status report has no pending data.
    assert key.get()[7] == 0


def test_hid_slot_without_challenge_response_is_skipped_and_a_bad_crc_is_refused():
    key = Key(SECRET, 1, False, False)
    with pytest.raises(hardware_key._Rejected):
        hardware_key.hid_hmac(FakeTransport(key), 0x38, SEED, time.monotonic() + 5)
    assert hardware_key.hid_hmac(FakeTransport(key), 0x30, SEED, time.monotonic() + 5) == expected()
    key = Key(SECRET, 2, False, False)
    original = key.process

    def corrupt(frame):
        original(frame)
        key.pending[0] = bytes([key.pending[0][0] ^ 1]) + key.pending[0][1:]
    key.process = corrupt
    with pytest.raises(hardware_key.HardwareKeyError, match='invalid answer'):
        hardware_key.hid_hmac(FakeTransport(key), 0x38, SEED, time.monotonic() + 5)


def test_hid_touch_timeout_is_reported_without_device_data():
    key = Key(SECRET, 2, True, False)
    key.waiting = 10 ** 6
    with pytest.raises(hardware_key.TouchTimeout) as caught:
        hardware_key.hid_hmac(FakeTransport(key), 0x38, SEED, time.monotonic() + 0.3)
    assert str(caught.value) == 'the hardware key was not touched in time'


def test_card_applets_and_apdus():
    sent = []
    answer = hmac.new(SECRET, hardware_key.padded(SEED), hashlib.sha1).digest()

    def transmit(apdu):
        sent.append(apdu)
        if apdu[:4] == bytes([0, 0xA4, 4, 0]):
            return b'', 0x9000 if apdu[5:] == hardware_key.APPLETS[1] else 0x6A82
        assert apdu[:5] == bytes([0, 1, 0x38, 0, 64]) and apdu[5:] == hardware_key.padded(SEED)
        return answer, 0x9000
    assert hardware_key.card_hmac(transmit, 0x38, SEED) == answer
    # The YubiKey OTP applet first; then the OATH applet, which a Nitrokey 3 answers.
    assert [apdu[5:] for apdu in sent[:2]] == list(hardware_key.APPLETS[:2])
    with pytest.raises(hardware_key._Rejected):
        hardware_key.card_hmac(lambda apdu: (b'', 0x6A82), 0x38, SEED)


def test_linux_discovery_matches_vendor_and_keyboard_interface(tmp_path, monkeypatch):
    from virtual_hardware_key import DESCRIPTOR
    fido = bytes.fromhex('06d0f10901a101c0')  # FIDO usage page: not this protocol
    for name, hid_id, descriptor in [('hidraw0', '0003:00001050:00000407', DESCRIPTOR),
                                     ('hidraw1', '0003:00001050:00000407', fido),
                                     ('hidraw2', '0003:00001D50:000060FC', DESCRIPTOR),
                                     ('hidraw3', '0003:0000046D:0000C31C', DESCRIPTOR)]:
        device = tmp_path / name / 'device'
        device.mkdir(parents=True)
        (device / 'uevent').write_text(f'HID_ID={hid_id}\nHID_NAME=synthetic\n')
        (device / 'report_descriptor').write_bytes(descriptor)
    monkeypatch.setattr(hardware_key, 'SYSFS_HIDRAW', tmp_path)
    assert [d.path for d in hardware_key._linux_devices()] == ['/dev/hidraw0', '/dev/hidraw2']
    assert hardware_key.top_usage(DESCRIPTOR) == (1, 6) and hardware_key.top_usage(fido) == (0xF1D0, 1)


def test_no_key_and_no_answer_are_distinct(monkeypatch):
    monkeypatch.setattr(hardware_key, '_hid_sessions', lambda: iter(()))
    monkeypatch.setattr(hardware_key, '_Pcsc', lambda: (_ for _ in ()).throw(OSError()))
    with pytest.raises(hardware_key.NoHardwareKey):
        hardware_key.responses(SEED)
    key = Key(SECRET, 2, False, False)
    key.process = lambda frame: None  # no slot set up
    monkeypatch.setattr(hardware_key, '_hid_sessions', lambda: iter([lambda: FakeTransport(key)]))
    with pytest.raises(hardware_key.HardwareKeyError, match='no challenge-response slot') as caught:
        hardware_key.responses(SEED)
    assert not isinstance(caught.value, hardware_key.NoHardwareKey)


def test_responses_ask_every_key_and_slot(monkeypatch):
    first, second = Key(SECRET, 2, False, False), Key(b'\x01' * 20, 1, False, False)
    monkeypatch.setattr(hardware_key, '_hid_sessions',
                        lambda: iter([lambda: FakeTransport(first), lambda: FakeTransport(second)]))
    monkeypatch.setattr(hardware_key, '_Pcsc', lambda: (_ for _ in ()).throw(OSError()))
    assert hardware_key.responses(SEED) == [expected(), expected(secret=b'\x01' * 20)]


# ----- the native host ----------------------------------------------------------
def frames(data):
    stream, out = io.BytesIO(data), []
    while True:
        message = extension_host.read_frame(stream)
        if message is None:
            return out
        out.append(message)


def test_native_host_answers_hardware_key_requests_itself():
    out, lock = io.BytesIO(), threading.Lock()
    message = dict(type='hardware-key', id=7, challenge=SEED.hex())
    assert extension_host.hardware_request(message, out, lock, responses=lambda c: [expected(c)]) is not None
    deadline = time.monotonic() + 5
    while not out.getvalue() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert frames(out.getvalue()) == [dict(type='hardware-key', id=7, responses=[expected().hex()])]

    def missing(challenge):
        raise hardware_key.NoHardwareKey()
    out = io.BytesIO()
    assert extension_host.hardware_request(message, out, lock, responses=missing) is not None
    while not out.getvalue() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert frames(out.getvalue()) == [dict(type='hardware-key', id=7, error='no-key')]
    for bad in (dict(message, challenge='zz'), dict(message, id='7'), dict(message, extra=1),
                dict(message, challenge='00' * 65)):
        assert extension_host.hardware_request(bad, io.BytesIO(), lock, responses=lambda c: []) is None


def test_a_hardware_key_request_gets_its_own_connection_and_needs_no_broker(monkeypatch):
    """The extension opens a native connection for one request; no broker runs on this computer."""
    monkeypatch.setattr(hardware_key, 'responses', lambda challenge: [expected(challenge)])

    def no_broker():
        raise AssertionError('a hardware key request never connects to a broker')
    incoming = io.BytesIO()
    extension_host.write_frame(incoming, dict(type='hardware-key', id=1, challenge=SEED.hex()))
    incoming.seek(0)
    out = io.BytesIO()
    assert extension_host.relay(incoming, out, extension_host.EXTENSION_ORIGIN, 'chrome', no_broker) == 0
    assert frames(out.getvalue()) == [dict(type='hardware-key', id=1, responses=[expected().hex()])]
    # Another caller than the extension gets nothing.
    incoming.seek(0)
    assert extension_host.relay(incoming, io.BytesIO(), 'chrome-extension://another/', 'chrome', no_broker) == 1


def test_card_replies_that_continue_are_fetched():
    sent = []
    answer = bytes(range(20))

    def exchange(apdu):
        sent.append(apdu)
        if apdu[1] == 0xC0:
            return answer[12:], 0x9000
        return answer[:12], 0x6108
    assert hardware_key.with_continuation(exchange, b'\x00\x01\x38\x00\x40' + bytes(64)) == (answer, 0x9000)
    assert sent[1] == bytes([0, 0xC0, 0, 0, 8])


def test_only_cards_with_a_challenge_response_applet_count(monkeypatch):
    monkeypatch.setattr(hardware_key, '_hid_sessions', lambda: iter(()))

    class Readers:
        def __init__(self, status):
            self.status = status

        def readers(self):
            return [b'Reader 0']

        def connect(self, reader):
            return (1, 2)

        def transmit(self, card, apdu):
            return b'', self.status

        def disconnect(self, card):
            pass

        def close(self):
            pass
    monkeypatch.setattr(hardware_key, '_Pcsc', lambda: Readers(0x6A82))  # an ID card: no such applet
    assert hardware_key.available() is False
    monkeypatch.setattr(hardware_key, '_Pcsc', lambda: Readers(0x9000))
    assert hardware_key.available() is True


def test_a_key_that_answered_over_usb_is_not_asked_again_as_a_card(monkeypatch):
    key = Key(SECRET, 2, False, False)
    monkeypatch.setattr(hardware_key, '_hid_sessions', lambda: iter([lambda: FakeTransport(key)]))
    monkeypatch.setattr(hardware_key, '_Pcsc', lambda: pytest.fail('the smart card interface was asked too'))
    assert hardware_key.responses(SEED) == [expected()]


# ----- the real kernel path (Linux) ---------------------------------------------
# Defined only on Linux: other systems have no /dev/uhid, and their CI jobs refuse skips.
def _virtual_key_available():
    if sys.platform != 'linux' or not Path('/dev/uhid').exists() or not shutil.which('sudo'):
        return False
    return subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=10).returncode == 0


if sys.platform == 'linux':
    @pytest.fixture
    def virtual_key(request):
        if not _virtual_key_available():
            if os.environ.get('AKDBX_REQUIRE_VIRTUAL_KEY') == '1':
                pytest.fail('the virtual hardware key needs passwordless sudo and /dev/uhid')
            pytest.skip('the virtual hardware key needs passwordless sudo and /dev/uhid')
        options = getattr(request, 'param', {})
        script = Path(__file__).with_name('virtual_hardware_key.py')
        command = ['sudo', '-n', '/usr/bin/python3', '-I', str(script), '--uid', str(os.getuid()),
                   '--secret', options.get('secret', SECRET).hex(), '--slot', str(options.get('slot', 2))]
        command += ['--touch'] if options.get('touch', True) else []
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            node = process.stdout.readline().strip()
            assert node.startswith('/dev/hidraw'), 'the virtual key did not start'
            yield node
        finally:
            process.stdin.close()
            process.wait(15)


    def test_real_hidraw_device(virtual_key):
        assert hardware_key.available()
        touched = []
        assert hardware_key.responses(SEED, on_touch=lambda: touched.append(1)) == [expected()]
        assert touched == [1]


    @pytest.mark.parametrize('virtual_key', [dict(slot=1, touch=False)], indirect=True)
    def test_real_hidraw_device_on_slot_one(virtual_key):
        assert hardware_key.responses(SEED) == [expected()]


def test_this_computer_lists_its_keys_without_error():
    """The real OS discovery (hidraw, hid.dll and setupapi, IOKit, PC/SC) runs and fails closed."""
    assert hardware_key.available() in (True, False)
    try:
        answers = hardware_key.responses(SEED, timeout=1)
    except hardware_key.HardwareKeyError as exc:
        assert str(exc) in {'no hardware key found', 'the hardware key was not touched in time',
                            'the hardware key has no challenge-response slot set up'} or 'hardware key' in str(exc)
    else:
        assert all(len(answer) == 20 for answer in answers)
