"""`akdbx extension sign` against a fake AMO over loopback TLS: no request reaches Mozilla.

The fake checks each request's JSON Web Token (HS256, issuer, lifetime, unique
jti) the way AMO documents it, and answers with AMO's own status codes and
messages (addons-server: 409 for a taken version or add-on ID, 403 for another
account's add-on). Every AMO request runs through the real child process
(amo_https.py). All vaults, keys and secrets are synthetic.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import ssl
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pykeepass import create_database, PyKeePass

from akdbx import extension_host, extension_route, firefox_signing
from akdbx.broker import Broker
from akdbx.secrets_capture import CAPTURED_FIELDS

MASTER = 'synthetic-signing-master-only'
ISSUER = 'user:' + str(secrets.randbelow(10**7)) + ':' + str(secrets.randbelow(1000))
SECRET = secrets.token_hex(32)
ORIGIN = 'https://node.example:9443'
GUID = 'akdbx@akdbx.org'
TITLE = 'AMO API key'


class NoKeys:
    """The broker's typer: signing never types."""


class Link:
    """The broker's private page, as far as signing and locking read it: only its origin."""

    def __init__(self, origin=ORIGIN):
        self.origin, self.blocked, self.public_base, self.url = origin, False, None, None
        self.lock, self.unlock_lock = threading.Lock(), threading.Lock()


# ----- synthetic vault -----------------------------------------------------
@pytest.fixture(scope='module')
def template(tmp_path_factory):
    path = tmp_path_factory.mktemp('signing') / 'synthetic.kdbx'
    vault = create_database(io.BytesIO(), password=MASTER)
    params = vault.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value = 1
    params['M'].value = 1024 * 1024
    web = vault.add_group(vault.root_group, 'Web')

    def amo(title, url, fields, protect=True):
        entry = vault.add_entry(web, title, 'akdbx-signing', '', url=url)
        for name, value in fields.items():
            entry.set_custom_property(name, value, protect=protect)
        entry.set_custom_property(CAPTURED_FIELDS, ','.join(sorted(fields)))
    keys = {'jwt_issuer': ISSUER, 'jwt_secret': SECRET}
    amo(TITLE, 'https://addons.mozilla.org/en-US/developers/addon/api/key/', keys)
    amo('Look-alike key', 'https://addons.mozilla.org.example/en-US/developers/addon/api/key/', keys)
    amo('Staging key', 'https://addons.allizom.org/en-US/developers/addon/api/key/', keys)
    amo('Issuer only', 'https://addons.mozilla.org/issuer-only/', {'jwt_issuer': ISSUER})
    amo('Unprotected key', 'https://addons.mozilla.org/unprotected/', keys, protect=False)
    amo('Other account key', 'https://addons.mozilla.org/other/', {'jwt_issuer': 'user:1:1', 'jwt_secret': 'f' * 64})
    buffer = io.BytesIO()
    vault.save(buffer)
    path.write_bytes(buffer.getvalue())
    return path


def handle(broker, title=TITLE):
    entries = broker.dispatch({'action': 'search', 'query': title})['entries']
    return next(e['handle'] for e in entries if e['title'] == title)


# ----- fake AMO -----------------------------------------------------------
def certificate(folder):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                           x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = folder / 'amo-cert.pem', folder / 'amo-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


def decode(segment):
    return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))


class Amo:
    """The parts of the AMO v5 API that web-ext sign and akdbx use, with AMO's answers."""

    def __init__(self, cert, key):
        self.lock = threading.Lock()
        self.issuer, self.secret = ISSUER, SECRET
        self.owner = 'mine'            # 'mine', 'other-listed' (403) or 'other-hidden' (404, then 409)
        self.exists = False
        self.versions = {}             # version string -> dict(id, upload, polls, deleted)
        self.taken = set()             # Versions that another deployment of the account created.
        self.deleted = set()
        self.uploads = {}
        self.validation_polls = 1
        self.review_polls = 1
        self.validation_errors = []
        self.reject = False
        self.tamper = False
        self.redirect = None           # Another origin that serves the signed file.
        self.jtis = set()
        self.claims = []
        self.log = []                  # (method, path, has_token)
        self.next_id = 100
        handler = self.handler()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.origin = f'https://127.0.0.1:{self.server.server_port}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    # AMO checks: HS256 over header.claims with the API secret; exp at most 300 s after iat; unique jti.
    def authorized(self, header):
        if not header or not header.startswith('JWT '):
            return False
        try:
            head, body, signature = header[4:].split('.')
            expected = base64.urlsafe_b64encode(hmac.new(self.secret.encode(), (head + '.' + body).encode(),
                                                         hashlib.sha256).digest()).rstrip(b'=').decode()
            claims, alg = json.loads(decode(body)), json.loads(decode(head)).get('alg')
        except Exception:
            return False
        now = time.time()
        with self.lock:
            fresh = claims.get('jti') not in self.jtis
            self.jtis.add(claims.get('jti'))
            self.claims.append(claims)
        return (alg == 'HS256' and hmac.compare_digest(signature, expected) and claims.get('iss') == self.issuer
                and fresh and 0 < claims['exp'] - claims['iat'] <= 300 and claims['iat'] <= now + 5 < claims['exp'] + 5)

    def signed(self, item):
        with zipfile.ZipFile(io.BytesIO(item['xpi'])) as source:
            files = {name: source.read(name) for name in source.namelist()}
        if self.tamper:
            files['content.js'] += b'\n// not what was uploaded'
        files.update({'META-INF/manifest.mf': b'Manifest-Version: 1.0\n', 'META-INF/mozilla.sf': b'Signature\n',
                      'META-INF/mozilla.rsa': b'\x30\x82synthetic', 'META-INF/cose.manifest': b'cose',
                      'META-INF/cose.sig': b'\xd2synthetic'})
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name in ['META-INF/cose.manifest', 'META-INF/cose.sig', *sorted(files)]:
                if name not in archive.namelist():  # Fixed times: the same signed bytes on every download.
                    archive.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), files[name], zipfile.ZIP_DEFLATED)
        return buffer.getvalue()

    def handler(self):
        amo = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, value=None, *, body=None, headers=()):
                data = body if body is not None else json.dumps(value).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json' if body is None else 'application/x-xpinstall')
                for name, text in headers:
                    self.send_header(name, text)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def route(self, method):
                parts = urlsplit(self.path)
                token = self.headers.get('Authorization')
                amo.log.append((method, parts.path, token is not None))
                if not amo.authorized(token):
                    return self.reply(401, {'detail': 'Unable to authenticate.'})
                data = self.rfile.read(int(self.headers.get('Content-Length') or 0))
                base = f'/api/v5/addons/addon/{GUID}/'
                path = parts.path
                if path == '/api/v5/addons/upload/' and method == 'POST':
                    return self.upload(data)
                if path.startswith('/api/v5/addons/upload/') and method == 'GET':
                    return self.upload_status(path.split('/')[-2])
                if path == base + 'versions/' and method == 'GET':
                    if parse_qs(parts.query).get('filter') != ['all_with_unlisted']:
                        return self.reply(400, {'detail': 'filter'})
                    if amo.owner == 'other-listed':
                        return self.reply(403, {'detail': 'You do not have permission to perform this action.'})
                    if amo.owner == 'other-hidden' or not amo.exists:
                        return self.reply(404, {'detail': 'Not found.'})
                    listed = sorted(((v['id'], k) for k, v in amo.versions.items() if not v.get('deleted')), reverse=True)
                    return self.reply(200, {'count': len(listed), 'next': None, 'previous': None,
                                            'results': [{'id': i, 'version': k} for i, k in listed]})
                if path.startswith(base + 'versions/') and method == 'GET':
                    return self.version(path.split('/')[-2])
                if path == base and method == 'PUT':
                    return self.create(json.loads(data))
                if path.startswith('/files/') and method == 'GET':
                    if amo.redirect is not None and not path.endswith('/direct.xpi'):
                        return self.reply(302, {}, headers=[('Location', amo.redirect + path)])
                    item = next(v for v in amo.versions.values() if str(v['id']) == path.split('/')[2])
                    return self.reply(200, body=amo.signed(item))
                return self.reply(404, {'detail': 'Not found.'})

            def upload(self, data):
                kind, _, boundary = self.headers['Content-Type'].partition('; boundary=')
                fields = {}
                for part in data.split(b'--' + boundary.encode())[1:-1] if kind == 'multipart/form-data' else []:
                    head, _, body = part.partition(b'\r\n\r\n')
                    name = re.search(rb'name="([a-z]+)"', head)
                    if name and body.endswith(b'\r\n'):
                        fields[name.group(1).decode()] = body[:-2]
                if set(fields) != {'channel', 'upload'} or fields['channel'] != b'unlisted':
                    return self.reply(400, {'channel': ['Invalid channel.']})
                with zipfile.ZipFile(io.BytesIO(fields['upload'])) as archive:
                    manifest = json.loads(archive.read('manifest.json'))
                uuid = secrets.token_hex(16)
                amo.uploads[uuid] = dict(xpi=fields['upload'], version=manifest['version'], polls=0,
                                         guid=manifest['browser_specific_settings']['gecko']['id'], used=False)
                return self.reply(201, {'uuid': uuid, 'channel': 'unlisted', 'processed': False, 'submitted': False,
                                        'url': amo.origin + f'/api/v5/addons/upload/{uuid}/', 'valid': False,
                                        'validation': None, 'version': manifest['version']})

            def upload_status(self, uuid):
                item = amo.uploads[uuid]
                item['polls'] += 1
                processed = item['polls'] > amo.validation_polls
                valid = processed and not amo.validation_errors
                validation = ({'errors': len(amo.validation_errors), 'warnings': 0, 'messages': [
                    {'type': 'error', 'message': m, 'description': ['synthetic'], 'file': 'manifest.json'}
                    for m in amo.validation_errors] + [{'type': 'warning', 'message': 'unsafe assignment'}]}
                    if processed else None)
                return self.reply(200, {'uuid': uuid, 'channel': 'unlisted', 'processed': processed,
                                        'submitted': item['used'], 'valid': valid, 'validation': validation,
                                        'version': item['version']})

            def create(self, data):
                upload = amo.uploads.get(data.get('version', {}).get('upload'))
                if upload is None or upload['used'] or amo.validation_errors:
                    return self.reply(400, {'version': {'upload': ['Upload is not valid.']}})
                if amo.owner == 'other-listed':
                    return self.reply(403, {'detail': 'You do not have permission to perform this action.'})
                if amo.owner == 'other-hidden':
                    return self.reply(409, {'version': {'upload': ['Duplicate add-on ID found.']}})
                version = upload['version']
                if version in amo.taken or version in amo.versions:
                    return self.reply(409, {'version': {'version': [f'Version {version} already exists.']}})
                if version in amo.deleted:
                    return self.reply(409, {'version': {'version': [f'Version {version} was uploaded before and '
                                                                    'deleted.']}})
                upload['used'] = True
                amo.next_id += 1
                amo.versions[version] = dict(id=amo.next_id, xpi=upload['xpi'], polls=0)
                amo.exists = True
                return self.reply(201 if amo.next_id == 101 else 202, {
                    'guid': GUID, 'id': 9, 'version': {'id': amo.next_id, 'version': version, 'channel': 'unlisted',
                                                       'edit_url': amo.origin + '/developers/edit'}})

            def version(self, key):
                item = (amo.versions.get(key[1:]) if key.startswith('v')
                        else next((v for v in amo.versions.values() if str(v['id']) == key), None))
                if item is None:
                    return self.reply(404, {'detail': 'Not found.'})
                item['polls'] += 1
                public = item['polls'] > amo.review_polls
                status = 'disabled' if amo.reject and public else 'public' if public else 'unreviewed'
                number = next(k for k, v in amo.versions.items() if v is item)
                signed = amo.signed(item) if status == 'public' else b''
                return self.reply(200, {'id': item['id'], 'version': number, 'channel': 'unlisted',
                                        'is_disabled': False, 'file': {
                                            'id': item['id'], 'status': status, 'size': len(signed),
                                            'hash': 'sha256:' + hashlib.sha256(signed).hexdigest(),
                                            'url': amo.origin + f'/files/{item["id"]}/akdbx-{number}.xpi'}})

            def do_GET(self):
                self.route('GET')

            def do_POST(self):
                self.route('POST')

            def do_PUT(self):
                self.route('PUT')

        return Handler


class Other(BaseHTTPRequestHandler):
    """Another origin that a redirect names: it records whether a token arrived."""
    seen = []
    amo = None

    def log_message(self, *args):
        pass

    def do_GET(self):
        Other.seen.append(self.headers.get('Authorization'))
        item = next(v for v in Other.amo.versions.values() if str(v['id']) == self.path.split('/')[2])
        data = Other.amo.signed(item)
        self.send_response(200)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def lab(tmp_path, template, monkeypatch):
    cert, key = certificate(tmp_path)
    amo = Amo(cert, key)
    vault = PyKeePass(str(template), password=MASTER)
    broker = Broker(vault, NoKeys())
    broker.unlock_link = Link()
    if os.name == 'nt':
        folder = Path(os.environ['LOCALAPPDATA']) / ('akdbx-sign-test-' + secrets.token_hex(8)) / 'signed'
    else:
        folder = tmp_path.resolve() / 'state' / 'signed'
    signing = firefox_signing.FirefoxSigning(broker, folder, api_base=amo.origin + '/api/v5/', ca_file=cert,
                                             sleep=lambda seconds: None)
    broker.firefox_signing = signing
    requests = []
    real = firefox_signing.run_child

    def recording(request, timeout):
        requests.append(json.dumps(request))
        return real(request, timeout)
    signing.runner = recording
    try:
        yield SimpleNamespace(amo=amo, broker=broker, folder=folder, cert=cert, requests=requests, tmp=tmp_path)
    finally:
        amo.close()
        if os.name == 'nt':
            import shutil
            shutil.rmtree(folder.parent, ignore_errors=True)


def sign(lab, title=TITLE, **extra):
    return lab.broker.dispatch(dict(action='sign-firefox-extension', firefox_signing_protocol=1,
                                    handle=handle(lab.broker, title), **extra))


def assert_no_secret(lab, *values):
    text = json.dumps(values)
    assert SECRET not in text and ISSUER not in text
    assert all(SECRET not in request for request in lab.requests)  # Only short-lived tokens reach the child.


# ----- the signed build version -----------------------------------------
def test_signed_versions_encode_this_builds_contents_and_stay_apart_from_unsigned_ones():
    built = extension_host.built_version()
    part = int(built.rsplit('.', 1)[1])
    first, last = extension_host.signed_version(1), extension_host.signed_version(999)
    assert first == f'{extension_route.EXTENSION_VERSION}.{100_000_000 + 1000 * part + 1}'
    assert extension_host.signed_sequence(first) == 1 and extension_host.signed_sequence(last) == 999
    for version in (first, last):
        assert extension_route.valid_extension_version(version)
        assert extension_route.version_status(version) == 'current'
        assert len(version.rsplit('.', 1)[1]) == 9  # Firefox and AMO allow up to nine digits.
    for bad in (0, 1000, True, '1'):
        with pytest.raises(ValueError):
            extension_host.signed_version(bad)
    # Another build's contents, an unsigned build, sequence 0 and a ten-digit part are not this build's signature.
    other = f'{extension_route.EXTENSION_VERSION}.{100_000_000 + 1000 * ((part + 1) % 65536) + 1}'
    for version in (other, built, first.rsplit('.', 1)[0] + '.' + str(100_000_000 + 1000 * part),
                    first.rsplit('.', 1)[0] + '.1' + first.rsplit('.', 1)[1]):
        assert extension_host.signed_sequence(version) is None
    assert extension_route.version_status(other) == 'mismatch'
    assert extension_route.version_status(built) == 'current'
    assert not extension_route.valid_extension_version(first.rsplit('.', 1)[0] + '.1000000000')


def test_the_signing_archive_holds_exactly_the_firefox_build_with_its_version(tmp_path):
    version = extension_host.signed_version(7)
    files = extension_host.firefox_signing_files(ORIGIN, version)
    folder = extension_host.build(tmp_path / 'ff', unlock_origin=ORIGIN, browser='firefox')
    on_disk = {p.name: p.read_bytes() for p in folder.iterdir()}
    assert set(files) == set(on_disk)
    for name in set(files) - {'manifest.json', 'config.js'}:
        assert files[name] == on_disk[name]
    manifest, built = json.loads(files['manifest.json']), json.loads(on_disk['manifest.json'])
    assert manifest == dict(built, version=version)
    config = files['config.js'].decode()
    assert f'globalThis.AKDBX_TRUSTED_ORIGIN = "{ORIGIN}";' in config
    assert f'globalThis.AKDBX_EXTENSION_VERSION = "{version}";' in config
    assert extension_host.BUILD_ID.search(config) is not None
    # A new trust anchor for every signed build; the archive bytes depend only on the files.
    again = extension_host.firefox_signing_files(ORIGIN, version)
    assert again['config.js'] != files['config.js']
    assert extension_host.xpi_bytes(files) == extension_host.xpi_bytes(dict(files))
    with zipfile.ZipFile(io.BytesIO(extension_host.xpi_bytes(files))) as archive:
        assert sorted(archive.namelist()) == sorted(files) and 'manifest.json' in archive.namelist()
        assert all(archive.read(name) == files[name] for name in files)
    with pytest.raises(ValueError):
        extension_host.firefox_signing_files(ORIGIN, extension_host.built_version())


@pytest.mark.skipif(not os.environ.get('AKDBX_TEST_ADDONS_LINTER'),
                    reason='set AKDBX_TEST_ADDONS_LINTER to the addons-linter bin script (CI installs 10.16.0)')
def test_mozillas_add_on_validator_accepts_the_archive_that_sign_submits(tmp_path):
    """addons-linter is the validator AMO runs on every upload; an error there would refuse the signature."""
    version = extension_host.signed_version(1)
    archive = tmp_path / 'akdbx-firefox.xpi'
    archive.write_bytes(extension_host.xpi_bytes(extension_host.firefox_signing_files(ORIGIN, version)))
    done = subprocess.run(['node', os.environ['AKDBX_TEST_ADDONS_LINTER'], '--output', 'json', str(archive)],
                          capture_output=True, timeout=300, check=False)
    report = json.loads(done.stdout)
    assert report['errors'] == [] and report['summary']['errors'] == 0, report['errors']
    assert report['metadata']['version'] == version and report['metadata']['manifestVersion'] == 3
    assert done.returncode == 0


def test_the_host_relays_a_signed_build_version():
    """The native host checks the worker's hello with the same version rule as the broker."""
    version = extension_host.signed_version(3)
    assert extension_route.valid_extension_version(version)
    assert extension_route.REPORTED_VERSION_FORMAT.fullmatch(version)


# ----- the signing flow ---------------------------------------------------
def test_sign_submits_the_brokers_own_build_unlisted_and_saves_the_signed_file(lab, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    status = lab.broker.dispatch({'action': 'ping'})
    assert {k: status[k] for k in status if k.startswith('firefox_signing')} == dict(
        firefox_signing_protocol=1, firefox_signing_channel='unlisted',
        firefox_signing_entry_origin='https://addons.mozilla.org', firefox_signing_fields=['jwt_issuer', 'jwt_secret'],
        firefox_signing_configured=True)
    receipt = sign(lab)
    version = extension_host.signed_version(1)
    assert receipt['ok'] and receipt['state'] == 'signed', receipt
    assert set(receipt) == {'ok', 'state', 'addon_id', 'addon_version', 'channel', 'xpi', 'size', 'sha256',
                            'trusted_origin'}
    assert (receipt['addon_id'], receipt['addon_version'], receipt['channel'], receipt['trusted_origin']) == \
        (GUID, version, 'unlisted', ORIGIN)
    path = Path(receipt['xpi'])
    assert path.parent == lab.folder and path.name == f'akdbx-firefox-{version}.xpi'
    data = path.read_bytes()
    assert len(data) == receipt['size'] and hashlib.sha256(data).hexdigest() == receipt['sha256']
    if os.name != 'nt':
        assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(lab.folder.stat().st_mode) == 0o700
    uploaded = lab.amo.uploads[next(iter(lab.amo.uploads))]['xpi']
    with zipfile.ZipFile(io.BytesIO(data)) as signed, zipfile.ZipFile(io.BytesIO(uploaded)) as submitted:
        assert all(signed.read(n) == submitted.read(n) for n in submitted.namelist())
        assert {n for n in signed.namelist() if n not in submitted.namelist()} <= {
            'META-INF/manifest.mf', 'META-INF/mozilla.sf', 'META-INF/mozilla.rsa', 'META-INF/cose.manifest',
            'META-INF/cose.sig'}
        manifest = json.loads(submitted.read('manifest.json'))
        config = submitted.read('config.js').decode()
    assert manifest['version'] == version and manifest['browser_specific_settings']['gecko']['id'] == GUID
    assert f'"{ORIGIN}"' in config and f'"{version}"' in config
    # The submitted sources are this akdbx's own, unchanged.
    for name, content in extension_host._source_files().items():
        if name != 'manifest.json':
            assert zipfile.ZipFile(io.BytesIO(uploaded)).read(name) == content
    # AMO order: version list, upload, upload status, create the version, version status, download.
    paths = [(method, path) for method, path, _ in lab.amo.log]
    assert paths[0] == ('GET', f'/api/v5/addons/addon/{GUID}/versions/')
    assert paths[1] == ('POST', '/api/v5/addons/upload/') and ('PUT', f'/api/v5/addons/addon/{GUID}/') in paths
    assert paths[-1][1].startswith('/files/') and all(has for _, _, has in lab.amo.log)
    assert all(c['exp'] - c['iat'] == 60 and c['iss'] == ISSUER for c in lab.amo.claims)
    assert len({c['jti'] for c in lab.amo.claims}) == len(lab.amo.claims)
    assert extension_route.version_status(version) == 'current' and lab.broker.firefox_signing.job is None
    out = capsys.readouterr()
    assert_no_secret(lab, receipt, status, out.out, out.err, caplog.text)
    # The handle was used up; the next signature gets the next version.
    assert lab.broker.dispatch(dict(action='sign-firefox-extension', firefox_signing_protocol=1,
                                    handle='0' * 64))['error'] == 'unknown or expired handle; search again'
    second = sign(lab)
    assert second['ok'] and second['addon_version'] == extension_host.signed_version(2), second


def test_the_next_version_follows_amo_and_skips_versions_another_deployment_took(lab):
    lab.amo.exists = True
    lab.amo.versions = {extension_host.signed_version(n): dict(id=n, xpi=b'', polls=0) for n in (1, 2, 4)}
    lab.amo.versions['0.1.0'] = dict(id=50, xpi=b'', polls=0)
    lab.amo.taken = {extension_host.signed_version(5)}
    lab.amo.deleted = {extension_host.signed_version(6)}
    receipt = sign(lab)
    assert receipt['ok'] and receipt['addon_version'] == extension_host.signed_version(7), receipt
    assert [u['version'] for u in lab.amo.uploads.values()] == [extension_host.signed_version(n) for n in (5, 6, 7)]
    assert_no_secret(lab, receipt)


def test_slow_review_answers_pending_and_a_fresh_handle_resumes_the_same_job(lab, monkeypatch):
    lab.amo.validation_polls, lab.amo.review_polls = 1, 10**6
    clock = [1000.0]
    lab.broker.clock = lambda: clock[0]
    # Each poll interval takes 20 s of broker time: one call ends in review, before its 100 s budget.
    lab.broker.firefox_signing.sleep = lambda seconds: clock.__setitem__(0, clock[0] + 20)
    pending = sign(lab)
    version = extension_host.signed_version(1)
    assert pending == dict(ok=True, state='pending', stage='review', addon_id=GUID, addon_version=version,
                           channel='unlisted', retry_after=30)
    assert not lab.folder.exists() or not any(lab.folder.iterdir())
    again = sign(lab)
    assert again['state'] == 'pending' and again['addon_version'] == version
    lab.amo.review_polls = 0
    done = sign(lab)
    assert done['ok'] and done['state'] == 'signed' and done['addon_version'] == version, done
    assert len(lab.amo.uploads) == 1 and len(lab.amo.versions) == 1  # Resumed, not submitted again.
    # A pending job belongs to its API key and origin.
    lab.amo.review_polls = 10**6
    assert sign(lab)['state'] == 'pending'
    other = sign(lab, 'Other account key')
    assert not other['ok'] and 'another AMO API key is pending' in other['error']
    lab.broker.unlock_link = Link('https://moved.example')
    moved = sign(lab)
    assert not moved['ok'] and 'pass --restart' in moved['error'] and 'https://moved.example' in moved['error']
    lab.amo.review_polls = 0
    restarted = sign(lab, restart=True)
    assert restarted['ok'] and restarted['trusted_origin'] == 'https://moved.example'
    assert restarted['addon_version'] == extension_host.signed_version(3)


def test_an_interrupted_version_create_is_looked_up_before_it_is_sent_again(lab):
    real = lab.broker.firefox_signing.runner
    dropped = []

    def drop_first_put(request, timeout):
        response = real(request, timeout)
        if request['method'] == 'PUT' and not dropped:
            dropped.append(True)
            return None  # AMO created the version, but the answer was lost.
        return response
    lab.broker.firefox_signing.runner = drop_first_put
    lost = sign(lab)
    assert lost == dict(ok=False, resumable=True, error=lost['error']) and 'network error' in lost['error']
    done = sign(lab)
    assert done['ok'] and done['addon_version'] == extension_host.signed_version(1), done
    assert len(lab.amo.versions) == 1 and sum(1 for m, *_ in lab.amo.log if m == 'PUT') == 1


@pytest.mark.parametrize('title, error', [
    ('Look-alike key', 'the entry is not on https://addons.mozilla.org'),
    ('Staging key', 'the entry is not on https://addons.mozilla.org'),
    ('Issuer only', 'no captured protected jwt_issuer and jwt_secret fields'),
    ('Unprotected key', 'no captured protected jwt_issuer and jwt_secret fields'),
])
def test_entries_other_than_the_amo_key_are_refused_before_any_request(lab, title, error):
    receipt = sign(lab, title)
    assert not receipt['ok'] and error in receipt['error'] and 'nothing submitted' in receipt['error']
    assert lab.amo.log == [] and lab.requests == []
    assert_no_secret(lab, receipt)


def test_locked_unconfigured_or_originless_brokers_refuse(lab):
    value = handle(lab.broker)
    assert lab.broker.dispatch(dict(action='sign-firefox-extension', firefox_signing_protocol=2,
                                    handle=value))['error'].startswith('invalid Firefox signing request')
    assert lab.broker.dispatch(dict(action='sign-firefox-extension', firefox_signing_protocol=1, handle=value,
                                    restart=False))['error'].startswith('invalid Firefox signing request')
    lab.broker.unlock_link = None
    receipt = sign(lab)
    assert not receipt['ok'] and 'serves no private HTTPS page' in receipt['error']
    lab.broker.unlock_link = Link()
    lab.broker.firefox_signing.folder = None
    receipt = sign(lab)
    assert not receipt['ok'] and 'no folder for signed add-ons' in receipt['error']
    assert lab.broker.dispatch({'action': 'ping'})['firefox_signing_configured'] is False
    value = handle(lab.broker)
    lab.broker.lock()
    locked = lab.broker.dispatch(dict(action='sign-firefox-extension', firefox_signing_protocol=1, handle=value))
    assert locked['ok'] is False and locked['error'] == 'vault locked'
    assert lab.amo.log == []


def test_a_second_concurrent_call_is_refused(lab):
    signing = lab.broker.firefox_signing
    assert signing._busy.acquire(blocking=False)
    try:
        receipt = sign(lab)
    finally:
        signing._busy.release()
    assert not receipt['ok'] and 'another Firefox signing call is running' in receipt['error']


def test_amo_refusals_are_clear_and_never_show_the_key(lab):
    amo = lab.amo
    amo.secret = 'e' * 64  # The vault holds another secret: every token fails.
    receipt = sign(lab)
    assert not receipt['ok'] and 'HTTP 401' in receipt['error'] and receipt['resumable'] is True
    amo.secret = SECRET
    lab.broker.firefox_signing.job = None
    amo.owner = 'other-listed'
    receipt = sign(lab)
    assert not receipt['ok'] and 'another AMO account owns this ID' in receipt['error'] and 'HTTP 403' in receipt['error']
    assert 'resumable' not in receipt and not amo.uploads
    amo.owner = 'other-hidden'
    receipt = sign(lab)
    assert not receipt['ok'] and 'HTTP 409' in receipt['error'] and 'Duplicate add-on ID found' in receipt['error']
    amo.owner = 'mine'
    amo.validation_errors = ['The "version" property must be a string.\x1b[31m', 'Unsupported permission']
    receipt = sign(lab)
    assert not receipt['ok'] and receipt['error'].startswith('AMO validation failed for ')
    assert 'The "version" property must be a string. [31m manifest.json; Unsupported permission' in receipt['error']
    assert 'unsafe assignment' not in receipt['error'] and lab.broker.firefox_signing.job is None
    amo.validation_errors = []
    amo.reject = True
    receipt = sign(lab)
    assert not receipt['ok'] and 'Mozilla did not sign' in receipt['error'] and 'resumable' not in receipt
    amo.reject = False
    amo.tamper = True
    receipt = sign(lab)
    assert not receipt['ok'] and 'does not match the submitted build' in receipt['error']
    assert not lab.folder.exists() or not any(lab.folder.iterdir())
    assert_no_secret(lab, receipt)


def test_network_failure_keeps_the_job(lab):
    lab.amo.close()
    receipt = sign(lab)
    assert receipt == dict(ok=False, resumable=True, error='AMO could not be reached (network error or timeout); the '
                           'signing job is kept; run `akdbx extension sign` again with a fresh search handle to resume')
    assert lab.broker.firefox_signing.job is not None


def test_a_download_redirect_to_another_origin_gets_no_token(lab):
    other = ThreadingHTTPServer(('127.0.0.1', 0), Other)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(lab.cert, lab.cert.with_name('amo-key.pem'))
    other.socket = context.wrap_socket(other.socket, server_side=True)
    thread = threading.Thread(target=other.serve_forever, daemon=True)
    thread.start()
    Other.seen, Other.amo = [], lab.amo
    lab.amo.redirect = f'https://localhost:{other.server_port}'
    try:
        receipt = sign(lab)
    finally:
        other.shutdown()
        other.server_close()
    assert receipt['ok'], receipt
    assert Other.seen == [None]


# ----- CLI ---------------------------------------------------------------
def test_cli_copies_the_checked_file_and_prints_only_non_secret_data(lab, capsys):
    output = lab.tmp / 'out'
    args = SimpleNamespace(output=output, handle=handle(lab.broker), restart=False)
    assert firefox_signing.run(args, lab.broker.dispatch) == 0
    printed = json.loads(capsys.readouterr().out)
    version = extension_host.signed_version(1)
    assert printed['xpi'] == str(output / f'akdbx-firefox-{version}.xpi')
    assert Path(printed['broker_xpi']).read_bytes() == Path(printed['xpi']).read_bytes()
    assert hashlib.sha256(Path(printed['xpi']).read_bytes()).hexdigest() == printed['sha256']
    assert_no_secret(lab, printed)
    # An existing file with other contents is never replaced.
    Path(printed['broker_xpi']).unlink()
    args.handle = handle(lab.broker)
    (output / f'akdbx-firefox-{extension_host.signed_version(2)}.xpi').write_bytes(b'other')
    assert firefox_signing.run(args, lab.broker.dispatch) == 1
    refused = json.loads(capsys.readouterr().out)
    assert 'exists with other contents' in refused['error'] and Path(refused['broker_xpi']).is_file()


def test_cli_reports_pending_and_refuses_an_old_broker(lab, capsys):
    lab.amo.review_polls = 10**6
    clock = [0.0]
    lab.broker.clock = lambda: clock[0]
    lab.broker.firefox_signing.sleep = lambda seconds: clock.__setitem__(0, clock[0] + 60)
    args = SimpleNamespace(output=lab.tmp / 'out', handle=handle(lab.broker), restart=False)
    assert firefox_signing.run(args, lab.broker.dispatch) == 0
    assert json.loads(capsys.readouterr().out)['state'] == 'pending'

    def old(payload):
        assert payload == {'action': 'ping'}
        return {'ok': True, 'locked': False}
    assert firefox_signing.run(args, old) == 1
    assert 'broker lacks Firefox signing' in json.loads(capsys.readouterr().out)['error']

    def leaky(payload):
        if payload['action'] == 'ping':
            return lab.broker.dispatch(payload)
        return {'ok': True, 'state': 'signed', 'addon_id': GUID, 'secret': SECRET}
    assert firefox_signing.run(args, leaky) == 2
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err and 'outcome unconfirmed' in out.err


@pytest.mark.skipif(os.name == 'nt', reason='the Unix socket transport; Windows uses the named pipe')
def test_cli_command_over_the_broker_socket(lab, capsys):
    from akdbx import cli
    from test_broker import running_broker
    import tempfile
    short = Path(os.path.realpath(tempfile.mkdtemp(prefix='aks', dir='/tmp')))  # AF_UNIX paths are short.
    socket_path = short / 'run' / 's'
    output = lab.tmp / 'cli-out'
    try:
        with running_broker(socket_path, lab.broker):
            value = handle(lab.broker)
            assert cli.main(['--socket', str(socket_path), '--unlock-origin', ORIGIN, 'extension', 'sign',
                             '--output', str(output), value]) == 0
    finally:
        import shutil
        shutil.rmtree(short, ignore_errors=True)
    printed = json.loads(capsys.readouterr().out)
    assert printed['state'] == 'signed' and Path(printed['xpi']).parent == output
    assert cli._request_timeout({'action': 'sign-firefox-extension'}) == firefox_signing.CLI_TIMEOUT
