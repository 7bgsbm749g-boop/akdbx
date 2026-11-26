"""A virtual challenge-response hardware key on Linux, through /dev/uhid (tests only).

Run as root: it creates a USB HID device with Yubico's vendor ID and a
keyboard interface. The kernel gives it a real /dev/hidrawN node, which this
script hands to the test user. The device side of the HID feature-report
protocol answers HMAC-SHA1 challenges with a synthetic secret, optionally
after a simulated touch. It prints the node path, then serves until stdin
closes.

    sudo -n python3 -I tests/virtual_hardware_key.py --uid UID --secret HEX [--slot 2] [--touch] [--fixed]
"""
import argparse
import hashlib
import hmac
import os
import select
import struct
import sys
import time
from pathlib import Path

UHID_DESTROY, UHID_START, UHID_STOP, UHID_OPEN, UHID_CLOSE, UHID_OUTPUT = 1, 2, 3, 4, 5, 6
UHID_GET_REPORT, UHID_GET_REPORT_REPLY, UHID_CREATE2, UHID_SET_REPORT, UHID_SET_REPORT_REPLY = 9, 10, 11, 13, 14
EVENT_SIZE = 4 + 4372
NAME = b'akdbx virtual hardware key'
# A keyboard collection with one 8-byte feature report, like the key's OTP interface.
DESCRIPTOR = bytes.fromhex(
    '05010906a101'  # Generic Desktop, Keyboard, Collection (Application)
    '050719e029e7150025017501950881029501750881019506750815002565190029658100'
    '7508950815002600ff0901b102'  # Feature: 8 bytes
    'c0')


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            carry = crc & 1
            crc >>= 1
            if carry:
                crc ^= 0x8408
    return crc


class Key:
    def __init__(self, secret, slot, touch, fixed):
        self.secret, self.slot, self.touch, self.fixed = secret, slot, touch, fixed
        self.prog_seq = 7
        self.frame = bytearray(70)
        self.pending = []  # response reports still to read
        self.waiting = 0  # status polls left while "waiting for touch"

    def status(self, flags=0):
        return bytes([0, 5, 4, 3, self.prog_seq, 0x03, 0, flags])

    def get(self):
        if self.waiting:
            self.waiting -= 1
            return self.status(0x20)
        if self.pending:
            return self.pending.pop(0)
        return self.status()

    def set(self, report):
        flags = report[7]
        if flags == 0xFF:  # reset read mode
            self.pending = []
            return
        if not flags & 0x80:
            return
        sequence = flags & 0x1F
        if sequence == 0:
            self.frame = bytearray(70)
        self.frame[sequence * 7:sequence * 7 + 7] = report[:7]
        if sequence == 9:
            self.process(bytes(self.frame))

    def process(self, frame):
        payload, command = frame[:64], frame[64]
        if int.from_bytes(frame[65:67], 'little') != crc16(payload):
            return
        wanted = {2: 0x38, 1: 0x30}[self.slot]
        if command != wanted:
            return  # not set up: the host sees an unchanged status report
        challenge = payload if self.fixed else payload.rstrip(payload[-1:])
        response = hmac.new(self.secret, challenge, hashlib.sha1).digest()
        data = response + (crc16(response) ^ 0xFFFF).to_bytes(2, 'little')
        data += bytes(-len(data) % 7)
        self.pending = [data[i:i + 7] + bytes([0x40 | (i // 7)]) for i in range(0, len(data), 7)]
        self.pending.append(bytes(7) + bytes([0x40]))  # sequence back to 0: complete
        self.waiting = 15 if self.touch else 0


def event(kind, body=b''):
    data = struct.pack('<I', kind) + body
    return data + bytes(EVENT_SIZE - len(data))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--secret', required=True)
    parser.add_argument('--slot', type=int, default=2, choices=(1, 2))
    parser.add_argument('--touch', action='store_true')
    parser.add_argument('--fixed', action='store_true')
    args = parser.parse_args()
    key = Key(bytes.fromhex(args.secret), args.slot, args.touch, args.fixed)
    fd = os.open('/dev/uhid', os.O_RDWR | os.O_CLOEXEC)
    create = (NAME.ljust(128, b'\0') + b'akdbx-test'.ljust(64, b'\0') + b''.ljust(64, b'\0')
              + struct.pack('<HHIIII', len(DESCRIPTOR), 0x03, 0x1050, 0x0407, 0x0543, 0) + DESCRIPTOR)
    os.write(fd, event(UHID_CREATE2, create))
    node = None
    try:
        deadline = time.monotonic() + 10
        while node is None and time.monotonic() < deadline:
            for entry in Path('/sys/class/hidraw').iterdir():
                try:
                    if 'HID_NAME=' + NAME.decode() in (entry / 'device' / 'uevent').read_text():
                        node = Path('/dev') / entry.name
                except OSError:
                    pass
            if node is None:
                ready, _, _ = select.select([fd], [], [], 0.05)
                if ready:
                    os.read(fd, EVENT_SIZE)
        if node is None:
            raise SystemExit('no hidraw node')
        while not node.exists():
            time.sleep(0.01)
        os.chown(node, args.uid, -1)
        os.chmod(node, 0o600)
        print(node, flush=True)
        while True:
            ready, _, _ = select.select([fd, sys.stdin], [], [], 1.0)
            if sys.stdin in ready and not sys.stdin.readline():
                break
            if fd not in ready:
                continue
            raw = os.read(fd, EVENT_SIZE)
            kind = struct.unpack_from('<I', raw)[0]
            if kind == UHID_GET_REPORT:
                ident, number, rtype = struct.unpack_from('<IBB', raw, 4)
                report = b'\0' + key.get()  # report ID 0, as usbhid returns it
                os.write(fd, event(UHID_GET_REPORT_REPLY, struct.pack('<IHH', ident, 0, len(report)) + report))
            elif kind == UHID_SET_REPORT:
                ident, number, rtype, size = struct.unpack_from('<IBBH', raw, 4)
                data = raw[12:12 + size]
                key.set(data[1:] if size == 9 else data)
                os.write(fd, event(UHID_SET_REPORT_REPLY, struct.pack('<IH', ident, 0)))
    finally:
        os.write(fd, event(UHID_DESTROY))
        os.close(fd)


if __name__ == '__main__':
    main()
