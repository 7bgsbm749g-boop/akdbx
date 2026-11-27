"""The release's signing step (python -m akdbx.firefox_signing) against a fake AMO over loopback TLS.

No request reaches Mozilla. The fake checks each request's JSON Web Token
(HS256, issuer, lifetime, unique jti) the way AMO documents it, and answers
with AMO's own status codes and messages (addons-server: 409 for a taken
version or add-on ID, 403 for another account's add-on). Every AMO request
runs through the real child process (amo_https.py). The API key is synthetic.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import os
import re
import secrets
import ssl
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

from akdbx import extension_host, extension_route, firefox_signing

ISSUER = 'user:' + str(secrets.randbelow(10**7)) + ':' + str(secrets.randbelow(1000))
SECRET = secrets.token_hex(32)
GUID = 'akdbx@akdbx.org'
ROOT = Path(__file__).resolve().parents[1]


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
        self.taken = set()             # Versions that another run created after this run's lookup (a race).
        self.deleted = set()
        self.uploads = {}
        self.validation_polls = 1
        self.review_polls = 1
        self.validation_errors = []
        self.reject = False
        self.tamper = False
        self.unsigned = False          # Serve the upload itself as the "signed" file.
        self.redirect = None           # Another origin that serves the signed file.
        self.next_host = None          # Another host name in the version list's next links.
        self.by_number = True          # False: the lookup by version string misses (AMO does not document it).
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
        if self.unsigned:
            return item['xpi']
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
                    query = parse_qs(parts.query)
                    if query.get('filter') != ['all_with_unlisted'] or query.get('page_size') != ['50']:
                        return self.reply(400, {'detail': 'filter'})
                    if amo.owner == 'other-listed':
                        return self.reply(403, {'detail': 'You do not have permission to perform this action.'})
                    if amo.owner == 'other-hidden' or not amo.exists:
                        return self.reply(404, {'detail': 'Not found.'})
                    # AMO lists newest first, 50 a page (page_size's maximum), with an absolute next link.
                    listed = sorted(((v['id'], k) for k, v in amo.versions.items() if not v.get('deleted')), reverse=True)
                    page = int(query.get('page', ['1'])[0])
                    more = len(listed) > 50 * page
                    host = amo.next_host or '127.0.0.1'
                    following = (f'https://{host}:{amo.server.server_port}{path}?filter=all_with_unlisted&page_size=50'
                                 f'&page={page + 1}' if more else None)
                    return self.reply(200, {'count': len(listed), 'next': following, 'previous': None, 'results': [
                        {'id': i, 'version': k} for i, k in listed[50 * (page - 1):50 * page]]})
                if path.startswith(base + 'versions/') and method == 'GET':
                    return self.version(path.split('/')[-2])
                if path == base and method == 'PUT':
                    return self.create(json.loads(data))
                if path.startswith(base + 'versions/') and method == 'PATCH':
                    fields = self.form(data)
                    item = next((v for v in amo.versions.values() if str(v['id']) == path.split('/')[-2]), None)
                    if item is None or set(fields) != {'source'}:
                        return self.reply(400, {'source': ['Invalid source.']})
                    item['source'] = fields['source']
                    return self.reply(200, {'id': item['id'], 'source': amo.origin + '/source.zip'})
                if path.startswith('/files/') and method == 'GET':
                    if amo.redirect is not None and not path.endswith('/direct.xpi'):
                        return self.reply(302, {}, headers=[('Location', amo.redirect + path)])
                    item = next(v for v in amo.versions.values() if str(v['id']) == path.split('/')[2])
                    return self.reply(200, body=amo.signed(item))
                return self.reply(404, {'detail': 'Not found.'})

            def form(self, data):
                kind, _, boundary = self.headers['Content-Type'].partition('; boundary=')
                fields = {}
                for part in data.split(b'--' + boundary.encode())[1:-1] if kind == 'multipart/form-data' else []:
                    head, _, body = part.partition(b'\r\n\r\n')
                    name = re.search(rb'name="([a-z]+)"', head)
                    if name and body.endswith(b'\r\n'):
                        fields[name.group(1).decode()] = body[:-2]
                return fields

            def upload(self, data):
                fields = self.form(data)
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
                if version in amo.taken:  # Another run created it after this run looked: it exists now.
                    amo.taken.discard(version)
                    amo.next_id += 1
                    amo.versions[version] = dict(id=amo.next_id, xpi=upload['xpi'], polls=0, source=b'other run')
                    amo.exists = True
                if version in amo.versions:
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
                item = ((amo.versions.get(key[1:]) if amo.by_number else None) if key.startswith('v')
                        else next((v for v in amo.versions.values() if str(v['id']) == key), None))
                if item is None:
                    return self.reply(404, {'detail': 'Not found.'})
                item['polls'] += 1
                public = item['polls'] > amo.review_polls
                status = 'disabled' if amo.reject and public else 'public' if public else 'unreviewed'
                number = next(k for k, v in amo.versions.items() if v is item)
                signed = amo.signed(item) if status == 'public' else b''
                return self.reply(200, {'id': item['id'], 'version': number, 'channel': 'unlisted',
                                        'source': amo.origin + '/source.zip' if item.get('source') else None,
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

            def do_PATCH(self):
                self.route('PATCH')

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
def lab(tmp_path):
    cert, key = certificate(tmp_path)
    amo = Amo(cert, key)
    requests = []
    real = firefox_signing.run_child

    def recording(request, timeout):
        requests.append(json.dumps(request))
        return real(request, timeout)
    try:
        yield SimpleNamespace(amo=amo, cert=cert, requests=requests, tmp=tmp_path, runner=recording)
    finally:
        amo.close()


class Clock:
    """A clock that only sleeps move: review polls in no wall time."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def release(lab, *argv, environ=None, clock=None, runner=None, output=None, capsys=None):
    """Run the release workflow's signing step against the fake: (exit status, printed JSON)."""
    clock = clock or Clock()
    output = output or lab.tmp / 'ext'
    environ = {'AMO_JWT_ISSUER': ISSUER, 'AMO_JWT_SECRET': SECRET} if environ is None else environ
    code = firefox_signing.main(['--output', str(output), *argv], environ=environ, api_base=lab.amo.origin + '/api/v5/',
                                ca_file=lab.cert, runner=runner or lab.runner, sleep=clock.sleep, clock=clock)
    printed = capsys.readouterr().out if capsys is not None else None
    return code, (json.loads(printed) if printed else None)


def assert_no_secret(lab, *values):
    text = json.dumps(values)
    assert SECRET not in text and ISSUER not in text
    assert all(SECRET not in request for request in lab.requests)  # Only short-lived tokens reach the child.


# ----- the build that the release signs -----------------------------------
def test_the_signed_upload_is_the_release_firefox_zip_at_the_build_version(tmp_path, monkeypatch, capsys):
    build = firefox_signing.Build.current()
    assert build.version == extension_host.built_version()
    assert build.files == extension_host.build_files('firefox')
    manifest = json.loads(build.files['manifest.json'])
    assert manifest['version'] == build.version and manifest['browser_specific_settings']['gecko']['id'] == GUID
    assert build.files['config.js'].decode().count('globalThis.') == 1  # Only the version: no address, no build ID.
    # The upload equals `akdbx extension pack --browser firefox`, which the release attaches unsigned.
    zipped = tmp_path / extension_host.archive_name('firefox')
    assert extension_host.run(SimpleNamespace(extension_command='pack', output=zipped, browser='firefox')) == 0
    capsys.readouterr()
    assert zipped.read_bytes() == build.xpi
    # The same bytes when another platform builds it (zipfile records Windows as creating system 0).
    monkeypatch.setattr(sys, 'platform', 'linux' if sys.platform == 'win32' else 'win32')
    there = extension_host.archive_bytes(build.files)
    monkeypatch.undo()
    assert there == build.xpi
    with zipfile.ZipFile(io.BytesIO(build.xpi)) as archive:
        assert {(i.compress_type, i.create_system, i.external_attr >> 16) for i in archive.infolist()} == {
            (zipfile.ZIP_STORED, 3, 0o644)}
        assert {name: archive.read(name) for name in archive.namelist()} == build.files
    # The broker calls this version current: the signed add-on reports the version it builds itself.
    assert extension_route.version_status(build.version) == 'current'


def test_the_source_archive_rebuilds_the_upload_byte_for_byte(tmp_path):
    build = firefox_signing.Build.current()
    source = firefox_signing.source_archive(build.version, build.xpi)
    folder = tmp_path / 'source'
    with zipfile.ZipFile(io.BytesIO(source)) as archive:
        names = archive.namelist()
        assert {'BUILD.md', 'rebuild.py', 'akdbx/extension_host.py', 'akdbx/fill_extension/trust.js'} <= set(names)
        assert not any('__pycache__' in name or name.endswith('.pyc') for name in names)
        archive.extractall(folder)
    notes = (folder / 'BUILD.md').read_text()
    assert build.version in notes and hashlib.sha256(build.xpi).hexdigest() in notes and 'origin' not in notes.lower()
    out = tmp_path / 'rebuilt'
    done = subprocess.run([sys.executable, '-I', str(folder / 'rebuild.py'), str(out)], capture_output=True, text=True,
                          timeout=120, check=False)
    assert done.returncode == 0, done.stderr
    printed = json.loads(done.stdout)
    assert printed['sha256'] == hashlib.sha256(build.xpi).hexdigest()
    assert Path(printed['akdbx']).resolve().is_relative_to(folder.resolve())  # The archive's akdbx, not this one.
    assert out.with_name('rebuilt.xpi').read_bytes() == build.xpi
    assert {p.name: p.read_bytes() for p in out.iterdir()} == build.files


@pytest.mark.skipif(not os.environ.get('AKDBX_TEST_ADDONS_LINTER'),
                    reason='set AKDBX_TEST_ADDONS_LINTER to the addons-linter bin script (CI installs 10.16.0)')
def test_mozillas_add_on_validator_accepts_the_archive_that_the_release_signs(tmp_path):
    """addons-linter is the validator AMO runs on every upload; an error there would refuse the signature."""
    build = firefox_signing.Build.current()
    archive = tmp_path / 'akdbx-firefox.xpi'
    archive.write_bytes(build.xpi)
    done = subprocess.run(['node', os.environ['AKDBX_TEST_ADDONS_LINTER'], '--output', 'json', str(archive)],
                          capture_output=True, timeout=300, check=False)
    report = json.loads(done.stdout)
    assert report['errors'] == [] and report['summary']['errors'] == 0, report['errors']
    assert report['metadata']['version'] == build.version and report['metadata']['manifestVersion'] == 3
    assert done.returncode == 0


def test_the_rebuild_instructions_name_akdbx_s_own_dependencies():
    import tomllib
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    everywhere = sorted(d for d in project['project']['dependencies'] if ';' not in d)
    assert sorted(firefox_signing.REBUILD_REQUIREMENTS) == everywhere


# ----- the signing step ------------------------------------------------
def test_the_release_step_uploads_the_generic_build_unlisted_and_saves_the_signed_file(lab, capsys):
    build = firefox_signing.Build.current()
    code, printed = release(lab, capsys=capsys)
    assert code == 0, printed
    name = extension_host.archive_name('firefox', signed=True)
    saved = lab.tmp / 'ext' / name
    data = saved.read_bytes()
    assert printed == dict(ok=True, state='signed', addon_id=GUID, version=build.version, channel='unlisted', file=name,
                           size=len(data), sha256=hashlib.sha256(data).hexdigest())
    firefox_signing.verify(build, data)  # The submitted files plus Mozilla's signature files, nothing else.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert {n for n in archive.namelist() if not n.startswith('META-INF/')} == set(build.files)
    [item] = lab.amo.versions.values()
    assert item['xpi'] == build.xpi  # The release's unsigned Firefox ZIP, byte for byte.
    assert list(lab.amo.versions) == [build.version]
    # The source archive went with the version, as AMO asks for generated code.
    with zipfile.ZipFile(io.BytesIO(item['source'])) as source:
        assert 'rebuild.py' in source.namelist()
    paths = [(m, p) for m, p, _ in lab.amo.log]
    base = f'/api/v5/addons/addon/{GUID}/'
    # The lookup by version string, then the author's version list (404: no add-on yet), then the upload.
    assert paths[:3] == [('GET', base + f'versions/v{build.version}/'), ('GET', base + 'versions/'),
                         ('POST', '/api/v5/addons/upload/')]
    assert ('PUT', base) in paths and ('PATCH', base + f'versions/{item["id"]}/') in paths
    assert all(token for _, _, token in lab.amo.log)  # Every request to the API's own origin has a token.
    assert len({c['jti'] for c in lab.amo.claims}) == len(lab.amo.claims)
    assert all(c['exp'] - c['iat'] == 60 for c in lab.amo.claims)
    assert_no_secret(lab, printed)


def test_a_rerun_of_the_tag_resumes_the_same_version_and_uploads_nothing(lab, capsys):
    """Review outlasts the first run; the re-run waits for the same version, and a third run downloads it again."""
    build = firefox_signing.Build.current()
    lab.amo.review_polls = 10_000
    code, printed = release(lab, '--timeout', '60', capsys=capsys)
    assert code == 1 and printed['stage'] == 'review' and printed['version'] == build.version
    assert printed['error'] == (f'AMO has not signed {build.version} within 60 seconds (stage review); the version stays '
                                'on AMO; re-run the failed release jobs to resume this version')
    assert not (lab.tmp / 'ext').exists() or not any((lab.tmp / 'ext').iterdir())
    uploads = len(lab.amo.uploads)
    lab.amo.review_polls = 0
    code, printed = release(lab, capsys=capsys)
    assert code == 0 and printed['state'] == 'signed', printed
    assert len(lab.amo.uploads) == uploads == 1 and list(lab.amo.versions) == [build.version]
    log = len(lab.amo.log)
    # A later release with the same extension contents (or a re-run after a later job failed): no upload either.
    code, again = release(lab, capsys=capsys)
    assert code == 0 and again == printed
    assert [m for m, _, _ in lab.amo.log[log:]] == ['GET', 'GET', 'GET']  # Lookup, review, download.
    assert len(lab.amo.uploads) == 1


def test_a_rerun_finds_the_version_in_the_authors_list_when_the_lookup_by_number_misses(lab, capsys):
    """AMO does not document that the lookup by version string shows an unlisted version; the list does."""
    build = firefox_signing.Build.current()
    lab.amo.by_number = False
    lab.amo.review_polls = 10_000
    code, printed = release(lab, '--timeout', '60', capsys=capsys)
    assert code == 1 and printed['stage'] == 'review'
    # 59 newer versions first (AMO lists newest first, 50 a page): the build's version is on the second page.
    lab.amo.versions = {f'0.0.{n}': dict(id=1000 + n, xpi=b'', polls=0) for n in range(1, 60)} | lab.amo.versions
    lab.amo.review_polls = 0
    code, printed = release(lab, capsys=capsys)
    assert code == 0 and printed['state'] == 'signed', printed
    assert len(lab.amo.uploads) == 1 and printed['version'] == build.version
    lab.amo.next_host = 'localhost'  # A next link on another host than the API's: refused, no token sent there.
    code, printed = release(lab, output=lab.tmp / 'other', capsys=capsys)
    assert code == 1 and 'another origin' in printed['error']


def test_no_request_outlasts_the_run(lab, capsys):
    """Every request, and the child that sends it, ends by the deadline; slow but successful answers end the run on
    time. A run that stops before AMO has the version does not say that it does."""
    clock = Clock()
    start, calls = clock.now, []
    real = lab.runner
    lab.amo.by_number = False
    lab.amo.exists = True
    lab.amo.versions = {f'0.0.{n}': dict(id=1000 + n, xpi=b'', polls=0) for n in range(1, 120)}

    def slow(request, stop):
        calls.append((request['timeout'], stop, start + 60 - clock.now))
        clock.now += min(21, stop)  # Each answer takes 21 seconds, or the child is stopped first.
        return real(request, stop)
    code, printed = release(lab, '--timeout', '60', clock=clock, runner=slow, capsys=capsys)
    version = firefox_signing.Build.current().version
    assert code == 1 and printed['error'] == (f'AMO has not signed {version} within 60 seconds (stage lookup); AMO has '
                                              f'no version {version} from this run; re-run the failed release jobs')
    assert clock.now - start <= 60
    assert all(asked + 1 == stop <= left for asked, stop, left in calls) and len(calls) == 3


def test_the_https_child_gets_no_amo_key(lab, monkeypatch):
    """The step's environment holds the key; the child that sends each request gets only its one-minute token."""
    monkeypatch.setenv('AMO_JWT_ISSUER', ISSUER)
    monkeypatch.setenv('AMO_JWT_SECRET', SECRET)
    seen = []
    real = firefox_signing.subprocess.run

    def recording(*args, **kwargs):
        seen.append(kwargs.get('env'))
        return real(*args, **kwargs)
    monkeypatch.setattr(firefox_signing.subprocess, 'run', recording)
    response = firefox_signing.run_child(dict(method='GET', url=lab.amo.origin + '/api/v5/x/', timeout=5,
                                              ca_file=str(lab.cert)), 10)
    assert response is not None and response['status'] == 401  # The child ran, with no token.
    [env] = seen
    assert env is not None and 'AMO_JWT_ISSUER' not in env and 'AMO_JWT_SECRET' not in env
    assert SECRET not in json.dumps(env) and ISSUER not in json.dumps(env)
    assert env.get('PATH') == os.environ.get('PATH')  # Everything else is inherited.


def test_a_rerun_attaches_a_source_archive_that_an_earlier_run_could_not(lab, capsys):
    real = lab.runner

    def refuse_patch(request, timeout):
        if request['method'] == 'PATCH':
            return dict(status=400, location=None, body=b'{"source": ["Invalid source."]}')
        return real(request, timeout)
    code, printed = release(lab, runner=refuse_patch, capsys=capsys)
    assert code == 1 and printed['stage'] == 'source' and 'Invalid source' in printed['error']
    assert 're-run the failed release jobs' in printed['error']
    [item] = lab.amo.versions.values()
    assert not item.get('source')
    code, printed = release(lab, capsys=capsys)
    assert code == 0, printed
    assert item['source'] and len(lab.amo.uploads) == 1


def test_a_version_another_run_created_meanwhile_is_resumed(lab, capsys):
    build = firefox_signing.Build.current()
    lab.amo.taken.add(build.version)  # Created between this run's lookup and its version create.
    code, printed = release(lab, capsys=capsys)
    assert code == 0, printed
    assert list(lab.amo.versions) == [build.version]
    assert lab.amo.versions[build.version]['source'] == b'other run'  # Not attached twice.


def test_no_api_key_signs_nothing_and_says_so(lab, capsys):
    for environ in ({}, {'AMO_JWT_ISSUER': ISSUER}, {'AMO_JWT_SECRET': SECRET}, {'AMO_JWT_ISSUER': '', 'AMO_JWT_SECRET': ''}):
        code, printed = release(lab, environ=environ, capsys=capsys)
        assert code == 3
        assert printed == dict(ok=False, state='unsigned', file=extension_host.archive_name('firefox', signed=True),
                               error='AMO_JWT_ISSUER and AMO_JWT_SECRET are not both set, so Mozilla signs nothing; '
                                     'this release has no signed Firefox add-on')
    assert lab.amo.log == [] and lab.requests == []


def test_a_rejected_or_deleted_version_asks_for_an_extension_version_bump(lab, capsys):
    build = firefox_signing.Build.current()
    lab.amo.reject = True
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and 'Mozilla did not sign' in printed['error'] and 'bump the fill extension version' in printed['error']
    # The re-run finds the same disabled version: the same refusal, and nothing uploaded again.
    code, again = release(lab, capsys=capsys)
    assert code == 1 and again['error'] == printed['error'] and len(lab.amo.uploads) == 1
    lab.amo.reject = False
    lab.amo.versions.clear()
    lab.amo.deleted.add(build.version)
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and 'deleted it, so it can never be used again' in printed['error']
    assert 'bump the fill extension version' in printed['error']
    assert not (lab.tmp / 'ext').exists() or not any((lab.tmp / 'ext').iterdir())


def test_amo_refusals_are_clear_and_never_show_the_key(lab, capsys):
    amo = lab.amo
    amo.secret = 'e' * 64  # Another secret: every token fails.
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and 'HTTP 401' in printed['error'] and 'AMO_JWT_SECRET' in printed['error']
    amo.secret = SECRET
    amo.owner = 'other-listed'
    amo.exists = True
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and 'another AMO account owns this ID' in printed['error'] and 'HTTP 403' in printed['error']
    assert not amo.versions  # An upload alone creates no version; AMO drops it.
    amo.owner, amo.exists = 'other-hidden', False
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and 'HTTP 409' in printed['error'] and 'Duplicate add-on ID found' in printed['error']
    amo.owner = 'mine'
    amo.validation_errors = ['The "version" property must be a string.\x1b[31m', 'Unsupported permission ' + SECRET]
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and printed['error'].startswith('AMO validation failed for ')
    assert 'The "version" property must be a string. [31m manifest.json; Unsupported permission [withheld]' in printed['error']
    assert 'unsafe assignment' not in printed['error']
    amo.validation_errors = []
    amo.tamper = True
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and 'does not match the' in printed['error']
    amo.versions.clear()
    amo.tamper, amo.unsigned = False, True  # The submitted files with no Mozilla signature.
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and 'does not match the' in printed['error']
    assert not (lab.tmp / 'ext').exists() or not any((lab.tmp / 'ext').iterdir())
    assert_no_secret(lab, printed)


def test_network_errors_and_a_busy_amo_are_retried_within_the_deadline(lab, capsys):
    real, seen = lab.runner, []

    def flaky(request, timeout):
        seen.append(request['method'])
        if len(seen) == 1:
            return None  # A network error.
        if len(seen) == 2:
            return dict(status=503, location=None, body=b'')
        return real(request, timeout)
    code, printed = release(lab, runner=flaky, capsys=capsys)
    assert code == 0, printed
    lab.amo.close()
    code, printed = release(lab, output=lab.tmp / 'second', capsys=capsys)
    assert code == 1 and printed['error'] == ('AMO could not be reached (network error or timeout); re-run the '
                                              'failed release jobs to resume this version')


def test_a_download_redirect_to_another_origin_gets_no_token(lab, capsys):
    other = ThreadingHTTPServer(('127.0.0.1', 0), Other)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(lab.cert, lab.cert.with_name('amo-key.pem'))
    other.socket = context.wrap_socket(other.socket, server_side=True)
    thread = threading.Thread(target=other.serve_forever, daemon=True)
    thread.start()
    Other.seen, Other.amo = [], lab.amo
    lab.amo.redirect = f'https://localhost:{other.server_port}'
    try:
        code, printed = release(lab, capsys=capsys)
    finally:
        other.shutdown()
        other.server_close()
    assert code == 0, printed
    assert Other.seen == [None]


def test_an_existing_file_with_other_contents_is_never_replaced(lab, capsys):
    output = lab.tmp / 'ext'
    output.mkdir()
    target = output / extension_host.archive_name('firefox', signed=True)
    target.write_bytes(b'something else')
    code, printed = release(lab, capsys=capsys)
    assert code == 1 and 'exists with other contents' in printed['error'] and target.read_bytes() == b'something else'
    assert release(lab, '--timeout', '5', capsys=capsys)[0] == 1  # Outside 60..21600 seconds: refused.


# ----- the release workflow ------------------------------------------------
def test_the_release_workflow_signs_with_the_amo_secrets_and_publishes_the_extension_archives():
    """The Release workflow runs exactly this step, with the two secrets, after the tests; exit 3 publishes the
    rest and says that the signed add-on is missing, any other failure publishes nothing."""
    text = (ROOT / '.github' / 'workflows' / 'release.yml').read_text(encoding='utf-8')
    job = text[text.index('\n  extension:\n'):text.index('\n  publish:\n')]
    assert 'needs: [verify, build]' in job  # build needs every test workflow.
    assert 'AMO_JWT_ISSUER: ${{ secrets.AMO_JWT_ISSUER }}' in job and 'AMO_JWT_SECRET: ${{ secrets.AMO_JWT_SECRET }}' in job
    assert 'clean/bin/python -m akdbx.firefox_signing --output ext --timeout 1200' in job
    assert 'pip install "dist/akdbx-${VERSION}-py3-none-any.whl"' in job  # The released wheel builds the archives.
    assert 'extension pack --browser "$browser" --output "ext/$name"' in job
    assert '"$status" -eq 3' in job and 'echo signed=false' in job and 'exit 1' in job
    assert text.count('secrets.AMO_JWT') == 2  # No other step sees the key.
    publish = text[text.index('\n  publish:\n'):]
    assert 'needs: [verify, build, install, extension]' in publish
    assert 'sha256sum akdbx-* > SHA256SUMS' in publish and 'subject-path: dist/akdbx-*' in publish
    assert publish.index('sha256sum akdbx-* > SHA256SUMS') < publish.index('attest-build-provenance')
    assert 'no Mozilla-signed Firefox add-on' in publish
    # The asset names that the workflow checks are the ones this akdbx writes.
    assert extension_host.archive_name('chrome').startswith('akdbx-extension-chrome-')
    assert extension_host.archive_name('firefox', signed=True).startswith('akdbx-extension-firefox-')


def test_the_step_runs_as_the_workflow_runs_it_and_needs_no_key_to_publish_the_rest(tmp_path):
    """`python -m akdbx.firefox_signing` with no key in the environment: exit 3 and no request."""
    env = {k: v for k, v in os.environ.items() if not k.startswith('AMO_JWT_')}
    done = subprocess.run([sys.executable, '-m', 'akdbx.firefox_signing', '--output', str(tmp_path / 'ext'),
                           '--timeout', '1200'], capture_output=True, text=True, timeout=120, env=env, check=False)
    assert done.returncode == 3, done.stderr
    assert json.loads(done.stdout)['state'] == 'unsigned' and not (tmp_path / 'ext').exists()
