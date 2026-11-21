"""A small in-process akdbx relay for the broker tests: loopback only, no internet.

It speaks protocol v1 as docs/PROTOCOL.md in akdbx-relay describes: the
control API over TLS (its own test CA), the control and stream WebSockets,
and a public TCP listener that forwards a phone's TLS bytes to the broker
without reading them. Certificates come from a separate test "ACME" CA.
"""
from __future__ import annotations

import base64
from contextlib import suppress
import datetime
import hashlib
import json
import secrets
import socket
import ssl
import struct
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from akdbx.relay import Endpoint

GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
BASE32 = 'abcdefghijklmnopqrstuvwxyz234567'


def now():
    return datetime.datetime.now(datetime.timezone.utc)


class CA:
    def __init__(self, label):
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now() - datetime.timedelta(days=400))
                     .not_valid_after(now() + datetime.timedelta(days=400))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                  key_encipherment=False, data_encipherment=False,
                                                  key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                  encipher_only=False, decipher_only=False), critical=True)
                     .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
                                    critical=False)
                     .sign(self.key, hashes.SHA256()))

    @property
    def pem(self):
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def sign(self, public_key, name, not_before, not_after):
        return (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(self.cert.subject)
                .public_key(public_key).serial_number(x509.random_serial_number())
                .not_valid_before(not_before).not_valid_after(not_after)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                               critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
                .sign(self.key, hashes.SHA256()))

    def leaf_files(self, name, directory):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self.sign(key.public_key(), name, now() - datetime.timedelta(days=1), now() + datetime.timedelta(days=30))
        chain, key_file = directory / f'{name}-chain.pem', directory / f'{name}-key.pem'
        chain.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + self.pem)
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        return chain, key_file

    def client_context(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(cadata=self.pem.decode())
        return context


def _read_head(sock, limit=16384):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError('closed')
        data += chunk
        if len(data) > limit:
            raise ConnectionError('head too large')
    head, _, rest = data.partition(b'\r\n\r\n')
    lines = head.decode('latin-1').split('\r\n')
    method, path, _ = lines[0].split(' ', 2)
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(':')
        headers.setdefault(key.strip().lower(), []).append(value.strip())
    return method, path, {k: v[-1] for k, v in headers.items()}, headers, rest


class FakeWS:
    """Server side of one WebSocket: unmasked frames out, masked frames in."""

    def __init__(self, sock):
        self.sock, self.lock = sock, threading.Lock()
        self.closed = threading.Event()
        self.pongs = 0
        self.close_code = None

    def send(self, opcode, payload=b''):
        header = bytes([0x80 | opcode])
        if len(payload) < 126:
            header += bytes([len(payload)])
        elif len(payload) < 65536:
            header += bytes([126]) + struct.pack('!H', len(payload))
        else:
            header += bytes([127]) + struct.pack('!Q', len(payload))
        with self.lock:
            self.sock.sendall(header + payload)

    def send_text(self, text):
        self.send(1, text.encode())

    def send_binary(self, data):
        self.send(2, data)

    def close(self, code=1000):
        with suppress(OSError):
            self.send(8, struct.pack('!H', code))
        self.closed.set()

    def abort(self):
        self.closed.set()
        with suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            self.sock.close()

    def _exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError('closed')
            data += chunk
        return data

    def _frame(self):
        first, second = self._exact(2)
        length = second & 0x7f
        if length == 126:
            length = struct.unpack('!H', self._exact(2))[0]
        elif length == 127:
            length = struct.unpack('!Q', self._exact(8))[0]
        if not second & 0x80:
            raise ConnectionError('client frames must be masked')
        mask = self._exact(4)
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(self._exact(length)))
        return bool(first & 0x80), first & 0x0f, payload

    def recv(self):
        """(opcode, payload) of the next data message; 8 for a close."""
        message, kind = b'', None
        while True:
            fin, opcode, payload = self._frame()
            if opcode == 9:
                self.send(10, payload)
                continue
            if opcode == 10:
                self.pongs += 1
                continue
            if opcode == 8:
                self.close_code = struct.unpack('!H', payload[:2])[0] if len(payload) >= 2 else None
                if not self.closed.is_set():
                    self.close()
                return 8, payload
            if opcode != 0:
                kind = opcode
            message += payload
            if fin:
                return kind, message


class FakeRelay:
    def __init__(self, directory, domain='akdbx.link'):
        self.domain = domain
        self.control_ca, self.acme_ca = CA('fake relay control CA'), CA('fake ACME CA')
        chain, key = self.control_ca.leaf_files('relay.' + domain, directory)
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(chain, key)
        self.lock = threading.Lock()
        self.register_errors, self.certificate_errors = [], []
        self.registrations = {}  # secret -> broker id
        self.register_calls = 0
        self.csrs = []
        self.validity = (datetime.timedelta(minutes=-5), datetime.timedelta(days=90))
        self.reject_connects = 0
        self.control = None
        self.control_connects = 0
        self.control_ready = threading.Event()
        self.control_messages = []
        self.pending = {}
        self.streams = 0
        self.bad_name = None
        self._stop = threading.Event()
        self._listeners = []
        self.control_port = self._listen(self._serve_control)
        self.public_port = self._listen(self._serve_public)

    # Plumbing

    def _listen(self, handler):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(64)
        self._listeners.append(listener)

        def accept():
            while not self._stop.is_set():
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                threading.Thread(target=self._guard, args=(handler, conn), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()
        return listener.getsockname()[1]

    @staticmethod
    def _guard(handler, conn):
        try:
            handler(conn)
        except Exception:
            pass
        finally:
            with suppress(OSError):
                conn.close()

    def stop(self):
        self._stop.set()
        for listener in self._listeners:
            with suppress(OSError):
                listener.close()
        if self.control is not None:
            self.control.abort()

    @property
    def url(self):
        return f'https://relay.{self.domain}:{self.control_port}'

    def endpoint(self, url=None):
        return Endpoint.parse(url or self.url, context=self.control_ca.client_context(), connect_host='127.0.0.1')

    @staticmethod
    def _json(sock, status, body, headers=()):
        data = json.dumps(body).encode()
        reason = {200: 'OK', 201: 'Created', 101: 'Switching Protocols'}.get(status, 'Error')
        extra = ''.join(f'{k}: {v}\r\n' for k, v in headers)
        sock.sendall(f'HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{extra}'
                     f'Content-Length: {len(data)}\r\nConnection: close\r\n\r\n'.encode() + data)

    def _error(self, sock, status, code, retry_after=None):
        body = {'error': code, 'message': code.replace('_', ' ')}
        headers = []
        if retry_after is not None:
            body['retry_after'] = retry_after
            headers.append(('Retry-After', str(retry_after)))
        self._json(sock, status, body, headers)

    def _broker(self, headers):
        auth = headers.get('authorization', '')
        if not auth.startswith('Bearer '):
            return None
        return self.registrations.get(auth[len('Bearer '):])

    # Control API

    def _serve_control(self, raw):
        sock = self.server_context.wrap_socket(raw, server_side=True)
        sock.settimeout(30)
        method, path, headers, _, rest = _read_head(sock)
        body = rest
        while len(body) < int(headers.get('content-length', '0')):
            body += sock.recv(65536)
        if method == 'POST' and path == '/api/v1/register':
            return self._register(sock, json.loads(body))
        if method == 'POST' and path == '/api/v1/certificate':
            return self._certificate(sock, headers, json.loads(body))
        if method == 'GET' and path == '/api/v1/connect':
            return self._connect(sock, headers)
        if method == 'GET' and path.startswith('/api/v1/stream/'):
            return self._stream(sock, headers, path.rsplit('/', 1)[1])
        self._error(sock, 404, 'not_found')

    def _register(self, sock, body):
        with self.lock:
            self.register_calls += 1
            if self.register_errors:
                return self._error(sock, *self.register_errors.pop(0))
        assert body['protocol'] == 1 and body['client'].startswith('akdbx/')
        broker_id = ''.join(secrets.choice(BASE32) for _ in range(12))
        secret = secrets.token_urlsafe(32)
        self.registrations[secret] = broker_id
        name = self.bad_name or f'{broker_id}.{self.domain}'
        self._json(sock, 201, {'protocol': 1, 'name': name, 'broker_id': broker_id, 'secret': secret,
                               'public_port': 8443, 'future_field': True})

    def _upgrade(self, sock, headers):
        accept = base64.b64encode(hashlib.sha1(headers['sec-websocket-key'].encode() + GUID).digest()).decode()
        sock.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                      f'Sec-WebSocket-Accept: {accept}\r\n\r\n').encode())
        sock.settimeout(None)
        return FakeWS(sock)

    def _certificate(self, sock, headers, body):
        broker = self._broker(headers)
        if broker is None:
            return self._error(sock, 401, 'unauthorized')
        with self.lock:
            if self.certificate_errors:
                return self._error(sock, *self.certificate_errors.pop(0))
        csr = x509.load_pem_x509_csr(body['csr'].encode())
        self.csrs.append(csr)
        names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        name = f'{broker}.{self.domain}'
        if names.get_values_for_type(x509.DNSName) != [name] or len(list(names)) != 1:
            return self._error(sock, 400, 'bad_csr')
        start, end = self.validity
        cert = self.acme_ca.sign(csr.public_key(), name, now() + start, now() + end)
        chain = (cert.public_bytes(serialization.Encoding.PEM) + self.acme_ca.pem).decode()
        self._json(sock, 200, {'certificate': chain,
                               'not_after': cert.not_valid_after_utc.strftime('%Y-%m-%dT%H:%M:%SZ')})

    def _connect(self, sock, headers):
        broker = self._broker(headers)
        with self.lock:
            refuse = self.reject_connects > 0
            if refuse:
                self.reject_connects -= 1
        if broker is None or refuse:
            return self._error(sock, 401, 'unauthorized')
        ws = self._upgrade(sock, headers)
        old, self.control = self.control, ws
        if old is not None:
            old.close(4000)
        self.control_connects += 1
        self.control_ready.set()
        try:
            while True:
                opcode, payload = ws.recv()
                if opcode == 8:
                    return
                self.control_messages.append(json.loads(payload))
        finally:
            if self.control is ws:
                self.control = None
                self.control_ready.clear()

    def drop_control(self):
        """Close the control connection as a relay restart would (1001)."""
        ws = self.control
        if ws is not None:
            ws.close(1001)
            ws.abort()

    def ping_control(self):
        self.control.send_text('{"type":"ping"}')

    def announce(self, stream_id):
        self.control.send_text(json.dumps({'type': 'open', 'stream': stream_id}))

    def _stream(self, sock, headers, stream_id):
        broker = self._broker(headers)
        if broker is None:
            return self._error(sock, 401, 'unauthorized')
        with self.lock:
            waiter = self.pending.pop(stream_id, None)
        if waiter is None:
            return self._error(sock, 404, 'unknown_stream')
        ws = self._upgrade(sock, headers)
        waiter['ws'] = ws
        waiter['ready'].set()
        ws.closed.wait()
        waiter['done'].wait(60)

    # Public listener: pass TLS bytes through, never decrypt

    def _serve_public(self, phone):
        phone.settimeout(5)
        hello = phone.recv(65536)
        if not hello or self.control is None:
            return
        stream_id = secrets.token_hex(16)
        waiter = {'ready': threading.Event(), 'done': threading.Event()}
        with self.lock:
            self.pending[stream_id] = waiter
        self.announce(stream_id)
        if not waiter['ready'].wait(10):
            return
        self.streams += 1
        ws = waiter['ws']
        phone.settimeout(None)
        ws.send_binary(hello)

        def upstream():
            try:
                while True:
                    data = phone.recv(65536)
                    if not data:
                        break
                    ws.send_binary(data)
            except OSError:
                pass
            ws.close(1000)

        threading.Thread(target=upstream, daemon=True).start()
        try:
            while True:
                opcode, payload = ws.recv()
                if opcode != 2:
                    break
                phone.sendall(payload)
        except (OSError, ConnectionError):
            pass
        finally:
            with suppress(OSError):
                phone.shutdown(socket.SHUT_RDWR)
            ws.abort()
            waiter['done'].set()


def phone_request(port, name, context, method='GET', path='/', headers=(), body=b'', host=None):
    """A browser-like HTTPS request through the relay's public port.

    Return ``(status, body, peer_certificate_der)``.
    """
    raw = socket.create_connection(('127.0.0.1', port), timeout=20)
    with context.wrap_socket(raw, server_hostname=name) as tls:
        peer = tls.getpeercert(binary_form=True)
        lines = [f'{method} {path} HTTP/1.1', f'Host: {host or name + ":8443"}', 'Connection: close',
                 *(f'{k}: {v}' for k, v in headers)]
        if body:
            lines.append(f'Content-Length: {len(body)}')
        tls.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode() + body)
        data = b''
        while True:
            try:
                chunk = tls.recv(65536)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            data += chunk
    head, _, payload = data.partition(b'\r\n\r\n')
    status = int(head.split(b' ', 2)[1]) if head else 0
    return status, payload, peer
