"""Mozilla signs the release's generic Firefox build (addons.mozilla.org, unlisted channel).

Firefox installs an add-on permanently only when Mozilla signed it. From fill
extension 0.19.0 the extension is one generic build, the same for every user:
it holds no broker address and no build ID, and the popup asks the user to
confirm the broker address on first use (``fill_extension/trust.js``). So one
signature per extension version serves everybody. The Release workflow runs::

    python -m akdbx.firefox_signing --output DIR [--timeout SECONDS]

with the AMO API key in ``AMO_JWT_ISSUER`` and ``AMO_JWT_SECRET`` (GitHub
Actions secrets) and attaches the signed XPI to the release. This replaces
``akdbx extension sign`` (akdbx 0.53.0 to 0.54.x), which had the broker sign
a per-deployment build with an AMO key from the vault.

- The upload is ``extension_host.archive_bytes(build_files('firefox'))``: the
  same bytes as the release's unsigned Firefox ZIP. Its version is the build's
  own (``built_version``), so the signed add-on reports the version that a
  broker of the same akdbx calls current.
- AMO needs a new version string for every version it creates. A re-run of the
  same tag, or a later release with the same extension contents, finds that
  version on AMO and resumes it: it attaches the source archive if it is
  missing, waits for the review and downloads the signed file. AMO never gives
  a version string back once a version was disabled or deleted; then the fill
  extension version must be bumped.
- Each AMO request runs in a short child process (``amo_https``) with a fixed
  deadline. This process signs a JSON Web Token (HS256, one minute, unique
  ``jti``) for each request; only that token goes to the child, never the
  secret. No output, log or error text holds the issuer or the secret.
- Review can take minutes. The whole run is bounded by ``--timeout`` and then
  fails with a message that says how to resume (re-run the failed jobs).
- Each version gets a source archive (``source_archive``): the akdbx package
  that generated the files, BUILD.md and rebuild.py, because Mozilla asks for
  the source of generated code (content.js is filled in from Python modules).
- The signed file must hold exactly the submitted files plus Mozilla's
  signature files under META-INF/.

The add-on ID is fixed (``akdbx@akdbx.org``, which the native host allows), so
only the AMO account that owns that ID can sign; any other account gets AMO's
403 or 409 as a clear refusal.

Exit status: 0 signed (prints the file name, version, size and SHA-256), 3 no
API key in the environment (prints ``state: "unsigned"``; the release then
ships no signed add-on and says so), 1 refused or timed out.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import subprocess
import sys
import time
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .extension_route import FIREFOX_EXTENSION_ID

AMO_ORIGIN = 'https://addons.mozilla.org'
API_BASE = AMO_ORIGIN + '/api/v5/'
CHANNEL = 'unlisted'
ISSUER_ENV = 'AMO_JWT_ISSUER'
SECRET_ENV = 'AMO_JWT_SECRET'
DEFAULT_TIMEOUT = 900.0    # Seconds for the whole run, review included.
REQUEST_TIMEOUT = 30.0     # One AMO request (the child is killed after this).
UPLOAD_TIMEOUT = 60.0
VALIDATION_POLL = 3.0
REVIEW_POLL = 10.0
RETRIES = 4                # Further tries of a request that met a network error, 429 or 5xx.
TOKEN_LIFETIME = 60        # AMO allows at most 300 seconds.
MAX_XPI = 8 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
MAX_SOURCE = 8 * 1024 * 1024
MAX_REDIRECTS = 3
MAX_VERSION_PAGES = 20     # 50 versions a page: the author's version list, when the version lookup finds nothing.
CHILD = Path(__file__).resolve().with_name('amo_https.py')
UUID = re.compile(r'[0-9a-f]{32}|[0-9a-f-]{36}')
SIGNATURE_FILE = re.compile(r'META-INF/[A-Za-z0-9._-]{1,64}')
# Mozilla signs with PKCS#7 and with COSE; a signed file holds at least one complete set.
SIGNATURE_SETS = ({'META-INF/manifest.mf', 'META-INF/mozilla.sf', 'META-INF/mozilla.rsa'},
                  {'META-INF/cose.manifest', 'META-INF/cose.sig'})
SOURCE_SUFFIXES = {'.py', '.js', '.json', '.html', '.css', '.txt', '.dat', '.LICENSE'}
RESUME = 're-run the failed release jobs to resume this version'


class SigningError(Exception):
    """A fixed, secret-free refusal."""


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def token(issuer, secret, now):
    """An AMO API token: HS256 over the issuer, a unique jti and a one-minute lifetime."""
    header = _b64url(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    claims = _b64url(json.dumps({'iss': issuer, 'jti': secrets.token_hex(16), 'iat': int(now),
                                 'exp': int(now) + TOKEN_LIFETIME}, separators=(',', ':')).encode())
    signature = _b64url(hmac.new(secret.encode('utf-8'), header + b'.' + claims, hashlib.sha256).digest())
    return (header + b'.' + claims + b'.' + signature).decode('ascii')


def child_environment():
    """This process's environment without the API key: the child gets only the one-minute token on stdin."""
    return {name: value for name, value in os.environ.items() if name not in (ISSUER_ENV, SECRET_ENV)}


def run_child(request, timeout):
    """One AMO request in a child process: the result object, or None for a network failure."""
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if os.name == 'nt' else 0
    try:
        done = subprocess.run([sys.executable, '-I', str(CHILD)], input=json.dumps(request).encode('utf-8'),
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
                              creationflags=flags, env=child_environment(), check=False)
        result = json.loads(done.stdout)
    except Exception:
        return None
    if not isinstance(result, dict) or 'error' in result or type(result.get('status')) is not int:
        return None
    try:
        body = base64.b64decode(result.get('body') or '', validate=True)
    except Exception:
        return None
    location = result.get('location')
    return dict(status=result['status'], location=location if isinstance(location, str) else None, body=body)


def _clean(text, secrets_to_hide=()):
    """AMO's own words, made safe to show: one bounded line without control characters."""
    for value in secrets_to_hide:
        if value:
            text = text.replace(value, '[withheld]')
    text = ''.join(c if unicodedata.category(c)[0] not in 'CZ' else ' ' for c in text)
    text = ' '.join(text.split())
    return text[:200] + ('...' if len(text) > 200 else '')


def _texts(value, out):
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, list):
        for item in value[:10]:
            _texts(item, out)
    elif isinstance(value, dict):
        for key in sorted(value)[:20]:
            if key not in {'url', 'edit_url', 'code'}:
                _texts(value[key], out)
    return out


def _json(response):
    try:
        return json.loads(response['body'])
    except Exception:
        return None


def _messages(response, hide):
    data = _json(response)
    return _clean('; '.join(_texts(data, [])), hide) if data is not None else ''


# akdbx's runtime dependencies on every platform (pyproject.toml; a test keeps them equal).
REBUILD_REQUIREMENTS = ('cryptography>=43,<47', 'idna>=3.7,<4', 'pykeepass==4.2.0', 'websocket-client>=1.8,<2')

BUILD_NOTES = '''# Source of the akdbx Firefox add-on {version}

akdbx {package} generated this add-on (https://github.com/7bgsbm749g-boop/akdbx).
This archive holds the exact akdbx package that built it (`akdbx/`), without
compiled files and without the Android helper binary, which the add-on does not
use. The add-on is the same generic build for every user: it holds no broker
address and no per-user value.

- `akdbx/fill_extension/` holds the add-on's files as written. No minifier,
  bundler or transpiler runs.
- `content.js` is generated: `akdbx/extension_host.py` (`_content_script`)
  replaces each `__MARKER__` placeholder in `fill_extension/content.js` with a
  JavaScript constant from `browser_password.py`, `browser_card.py`,
  `browser_code.py`, `browser_identity.py`, `card_processor.py` and
  `password_frames.py`.
- `manifest.json`: `_manifest_for('firefox', ...)` adds the Firefox fields and
  the version {version} (the source version and a fourth part from the
  contents, `built_version`).
- `config.js` holds only that version.
- `jsQR.js` and `jsQR.LICENSE`: jsQR 1.4.0, unmodified
  (`akdbx/import_assets/VENDOR.txt` names the npm package and its integrity).

Rebuild with Python 3.11 or newer, in the folder that holds this file:

    python -m pip install {requirements}
    python rebuild.py OUT

`rebuild.py` calls `extension_host.build_files('firefox')` and writes every
file of the add-on to OUT and the archive to OUT.xpi. Each file equals the
submitted one, and OUT.xpi equals the uploaded archive byte for byte
(SHA-256 {sha256}).
'''

REBUILD_SCRIPT = '''"""Rebuild the akdbx Firefox add-on {version} from this archive: python rebuild.py OUT"""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # This archive's akdbx, not an installed one.
import akdbx
from akdbx import extension_host

if extension_host.built_version() != {version!r}:
    raise SystemExit('this archive builds another version than ' + {version!r})
files = extension_host.build_files('firefox')
out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)
for name, data in sorted(files.items()):
    (out / name).write_bytes(data)
archive = extension_host.archive_bytes(files)
out.with_name(out.name + '.xpi').write_bytes(archive)
print(json.dumps({{'akdbx': akdbx.__file__, 'files': len(files), 'sha256': hashlib.sha256(archive).hexdigest()}}))
'''


def source_archive(version, xpi):
    """What AMO reviewers get for one version: this akdbx package, BUILD.md and rebuild.py.

    ``rebuild.py`` reproduces every submitted file and the uploaded archive itself from the archived package.
    """
    from . import __version__
    package = Path(__file__).resolve().parent
    values = dict(version=version, package=__version__, sha256=hashlib.sha256(xpi).hexdigest(),
                  requirements=' '.join(f'"{r}"' for r in REBUILD_REQUIREMENTS))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, text in (('BUILD.md', BUILD_NOTES), ('rebuild.py', REBUILD_SCRIPT)):
            archive.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), text.format(**values), zipfile.ZIP_DEFLATED)
        for path in sorted(package.rglob('*')):
            relative = path.relative_to(package)
            if (not path.is_file() or path.is_symlink() or '__pycache__' in relative.parts
                    or path.suffix not in SOURCE_SUFFIXES):
                continue
            info = zipfile.ZipInfo('akdbx/' + relative.as_posix(), (2020, 1, 1, 0, 0, 0))
            archive.writestr(info, path.read_bytes(), zipfile.ZIP_DEFLATED)
    data = buffer.getvalue()
    if len(data) > MAX_SOURCE:
        raise ValueError('the akdbx source archive is larger than 8 MiB')
    return data


def _multipart(fields, name, filename, content_type, data):
    """A multipart/form-data body: plain fields, then one file."""
    boundary = 'akdbx-' + secrets.token_hex(16)
    head = ''.join(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'
                   for key, value in fields.items())
    head += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
             f'Content-Type: {content_type}\r\n\r\n')
    return (head.encode('ascii') + data + f'\r\n--{boundary}--\r\n'.encode('ascii'),
            'multipart/form-data; boundary=' + boundary)


@dataclass
class Build:
    """The generic Firefox build that this akdbx writes, and its archive."""
    version: str
    files: dict
    xpi: bytes

    @classmethod
    def current(cls):
        from .extension_host import archive_bytes, build_files, built_version
        files = build_files('firefox')
        return cls(built_version(), files, archive_bytes(files))


class Signer:
    """One signing run for one build, bounded by ``timeout`` seconds."""

    def __init__(self, issuer, secret, *, timeout=DEFAULT_TIMEOUT, api_base=API_BASE, ca_file=None, runner=run_child,
                 sleep=time.sleep, clock=time.monotonic, wall_clock=time.time):
        self.issuer, self.secret = issuer, secret
        self.api_base = api_base  # Tests point this at a loopback fake; the release never changes it.
        self.ca_file = ca_file
        self.runner, self.sleep, self.clock, self.wall_clock = runner, sleep, clock, wall_clock
        self.deadline = clock() + timeout
        self.timeout = timeout
        self.stage = 'lookup'

    @property
    def hide(self):
        return (self.issuer, self.secret)

    def _late(self, seconds=0.0):
        return self.clock() + seconds > self.deadline

    def _out_of_time(self, version):
        return SigningError(f'AMO has not signed {version} within {int(self.timeout)} seconds (stage {self.stage}); '
                            f'the version stays on AMO; {RESUME}')

    # ---- AMO requests --------------------------------------------------
    def _call(self, method, path, *, body=None, content_type=None, timeout=REQUEST_TIMEOUT, url=None, auth=True):
        request = dict(method=method, url=url or urljoin(self.api_base, path), timeout=timeout)
        if body is not None:
            request.update(body=base64.b64encode(body).decode('ascii'), content_type=content_type)
        if self.ca_file is not None:
            request['ca_file'] = str(self.ca_file)
        pause = 2.0
        for attempt in range(RETRIES + 1):
            if auth:
                request['token'] = token(self.issuer, self.secret, self.wall_clock())
            response = self.runner(request, timeout + 5)
            request.pop('token', None)
            status = response['status'] if response is not None else None
            if status is not None and status != 429 and status < 500:
                break
            if attempt == RETRIES or self._late(pause + timeout):
                if status is None:
                    raise SigningError('AMO could not be reached (network error or timeout); ' + RESUME)
                raise SigningError(f'AMO is busy or failed (HTTP {status}); {RESUME}')
            self.sleep(pause)
            pause *= 2
        if status == 401:
            raise SigningError(f'AMO refused the API key (HTTP 401): check the {ISSUER_ENV} and {SECRET_ENV} '
                               "secrets and this runner's clock; nothing signed")
        return response

    def _owner_refusal(self, response):
        detail = _messages(response, self.hide)
        return SigningError(f'AMO refused add-on ID {FIREFOX_EXTENSION_ID} (HTTP {response["status"]}): another AMO '
                            'account owns this ID (only that account can sign akdbx), or this API key cannot '
                            'manage it' + (f'. AMO says: {detail}' if detail else '') + '; nothing signed')

    def _version(self, version):
        """AMO's record of this version string, or None when AMO has no such version (or no such add-on).

        The lookup by version string (`v` prefix) comes first. AMO does not document that it shows an unlisted
        version there, so a miss is checked in the author's list of all versions (`filter=all_with_unlisted`,
        pages from the API's own origin only) before the version counts as new.
        """
        record = self._record(f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/v{version}/', version)
        if record is not None:
            return record
        url = urljoin(self.api_base, f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/?filter=all_with_unlisted'
                                     '&page_size=50')
        for _ in range(MAX_VERSION_PAGES):
            response = self._call('GET', None, url=url)
            if response['status'] == 404:
                return None  # No add-on with this ID yet: the first upload creates it.
            if response['status'] == 403:
                raise self._owner_refusal(response)
            data = _json(response)
            if response['status'] != 200 or not isinstance(data, dict) or not isinstance(data.get('results'), list):
                raise SigningError(f'AMO refused the version list (HTTP {response["status"]}); nothing signed')
            for item in data['results']:
                if isinstance(item, dict) and item.get('version') == version and type(item.get('id')) is int:
                    found = self._record(f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/{item["id"]}/', version)
                    if found is None:
                        raise SigningError(f'AMO lists version {version} but does not show it; nothing signed')
                    return found
            following = data.get('next')
            if following is None:
                return None
            # Pages come from the API's own origin only, so the token never goes elsewhere.
            if not isinstance(following, str) or not self._same_api_origin(following):
                raise SigningError('AMO named a version list page on another origin; nothing signed')
            url = following
        raise SigningError(f'AMO lists more than {MAX_VERSION_PAGES * 50} versions of {FIREFOX_EXTENSION_ID}; '
                           'nothing signed')

    def _record(self, path, version):
        """One version record by its path, or None for HTTP 404."""
        response = self._call('GET', path)
        if response['status'] == 404:
            return None
        if response['status'] == 403:
            raise self._owner_refusal(response)
        data = _json(response)
        if response['status'] != 200 or not isinstance(data, dict) or type(data.get('id')) is not int \
                or data.get('version') != version:
            raise SigningError(f'AMO refused the version lookup of {version} (HTTP {response["status"]}); '
                               'nothing signed')
        return data

    def _same_api_origin(self, url):
        api, parts = urlsplit(self.api_base), urlsplit(url)
        return (parts.scheme == 'https' and parts.hostname is not None and not parts.username and not parts.password
                and (parts.hostname.lower(), parts.port) == (api.hostname.lower(), api.port))

    def _upload(self, build):
        self.stage = 'upload'
        body, content_type = _multipart({'channel': CHANNEL}, 'upload', f'akdbx-firefox-{build.version}.xpi',
                                        'application/x-xpinstall', build.xpi)
        response = self._call('POST', 'addons/upload/', body=body, timeout=UPLOAD_TIMEOUT, content_type=content_type)
        data = _json(response)
        if response['status'] not in (200, 201, 202) or not isinstance(data, dict) \
                or not isinstance(data.get('uuid'), str) or not UUID.fullmatch(data['uuid']):
            detail = _messages(response, self.hide)
            raise SigningError(f'AMO refused the upload of {build.version} (HTTP {response["status"]})'
                               + (f': {detail}' if detail else '') + '; nothing signed')
        upload = data['uuid']
        self.stage = 'validation'
        while True:
            response = self._call('GET', f'addons/upload/{upload}/')
            data = _json(response)
            if response['status'] != 200 or not isinstance(data, dict):
                raise SigningError(f'AMO refused the upload status (HTTP {response["status"]}); nothing signed')
            if data.get('processed') is True:
                break
            if self._late(VALIDATION_POLL + REQUEST_TIMEOUT):
                raise self._out_of_time(build.version)
            self.sleep(VALIDATION_POLL)
        if data.get('valid') is not True:
            messages = (data.get('validation') or {}).get('messages') if isinstance(data.get('validation'), dict) else None
            errors = [m for m in messages if isinstance(m, dict) and m.get('type') == 'error'] if isinstance(messages, list) else []
            detail = _clean('; '.join(' '.join(_texts([m.get('message'), m.get('file')], [])) for m in errors[:3]),
                            self.hide)
            raise SigningError(f'AMO validation failed for {build.version}' + (f': {detail}' if detail else '')
                               + '; nothing signed')
        return upload

    def _create(self, build, upload):
        """Create the version from the upload: its AMO record, or None when AMO already has that version."""
        self.stage = 'submit'
        response = self._call('PUT', f'addons/addon/{FIREFOX_EXTENSION_ID}/',
                              body=json.dumps({'version': {'upload': upload}}).encode('utf-8'),
                              content_type='application/json')
        status, data = response['status'], _json(response)
        if status in (200, 201, 202) and isinstance(data, dict) and isinstance(data.get('version'), dict) \
                and type(data['version'].get('id')) is int:
            return dict(data['version'], source=None)
        detail = _messages(response, self.hide)
        if status == 409 and 'already exists' in detail:
            return None  # Another run created it first: look it up again.
        if status == 409 and 'uploaded before and deleted' in detail:
            raise SigningError(f'AMO had version {build.version} before and deleted it, so it can never be used again; '
                               'bump the fill extension version (docs/releasing.md); nothing signed')
        if status in (403, 409):
            raise self._owner_refusal(response)
        raise SigningError(f'AMO refused version {build.version} (HTTP {status})' + (f': {detail}' if detail else '')
                           + '; nothing signed')

    def _source(self, build, version_id):
        """Attach the source archive, as AMO asks for generated code (as web-ext does)."""
        self.stage = 'source'
        try:
            data = source_archive(build.version, build.xpi)
        except (OSError, ValueError) as exc:
            raise SigningError(f'the akdbx source archive could not be built ({exc}); nothing signed') from None
        body, content_type = _multipart({}, 'source', f'akdbx-source-{build.version}.zip', 'application/zip', data)
        response = self._call('PATCH', f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/{version_id}/',
                              body=body, content_type=content_type, timeout=UPLOAD_TIMEOUT)
        if response['status'] not in (200, 201, 202):
            detail = _messages(response, self.hide)
            raise SigningError(f'AMO refused the source archive of {build.version} (HTTP {response["status"]})'
                               + (f': {detail}' if detail else '') + '; ' + RESUME)

    def _signed_file(self, build, version_id):
        """Wait for the review: the signed file's URL and hash."""
        self.stage = 'review'
        while True:
            response = self._call('GET', f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/{version_id}/')
            data = _json(response)
            item = data.get('file') if isinstance(data, dict) else None
            if response['status'] != 200 or not isinstance(item, dict):
                raise SigningError(f'AMO refused the version status (HTTP {response["status"]}); ' + RESUME)
            status = item.get('status')
            if status == 'public' and isinstance(item.get('url'), str):
                return item['url'], item.get('hash') if isinstance(item.get('hash'), str) else None
            if status == 'disabled' or data.get('is_disabled') is True:
                raise SigningError(f'Mozilla did not sign {build.version} (file status disabled: rejected or '
                                   'disabled on AMO); AMO never accepts this version string again, so bump the fill '
                                   'extension version (docs/releasing.md); nothing signed')
            if self._late(REVIEW_POLL + REQUEST_TIMEOUT):
                raise self._out_of_time(build.version)
            self.sleep(REVIEW_POLL)

    def _download(self, build, url, file_hash):
        self.stage = 'download'
        api = urlsplit(self.api_base)
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(url)
            if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
                raise SigningError('AMO named an unusable download address for the signed add-on; nothing saved')
            # The token goes only to the API's own origin; a redirect elsewhere gets none.
            same = (parts.hostname.lower(), parts.port) == (api.hostname.lower(), api.port)
            response = self._call('GET', None, url=url, auth=same)
            if response['status'] in (301, 302, 303, 307, 308) and response['location']:
                url = urljoin(url, response['location'])
                continue
            break
        else:
            raise SigningError('AMO redirected the signed add-on download too often; ' + RESUME)
        if response['status'] != 200:
            raise SigningError(f'AMO refused the signed add-on download (HTTP {response["status"]}); ' + RESUME)
        data = response['body']
        verify(build, data, file_hash)
        return data

    def sign(self, build):
        """The signed XPI bytes of ``build``: an existing AMO version of it is resumed, else one is created."""
        self.stage = 'lookup'
        record = self._version(build.version)
        if record is None:
            upload = self._upload(build)
            record = self._create(build, upload)
            if record is None:
                self.stage = 'lookup'
                record = self._version(build.version)
                if record is None:
                    raise SigningError(f'AMO said version {build.version} exists but does not list it; ' + RESUME)
        # AMO shows its own add-on's `source` to the author: null until an archive is attached.
        if 'source' in record and not record['source']:
            self._source(build, record['id'])
        url, file_hash = self._signed_file(build, record['id'])
        return self._download(build, url, file_hash)


def verify(build, data, file_hash=None):
    """The signed file must be the submitted build plus Mozilla's signature files, nothing else."""
    refused = SigningError(f'the signed add-on from AMO does not match the {build.version} build; nothing saved')
    if not data or len(data) > MAX_XPI:
        raise refused
    if file_hash is not None and file_hash.startswith('sha256:') \
            and not hmac.compare_digest(file_hash[7:].lower(), hashlib.sha256(data).hexdigest()):
        raise refused
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or set(build.files) - set(names) \
                    or sum(info.file_size for info in infos) > MAX_UNPACKED \
                    or not any(signature <= set(names) for signature in SIGNATURE_SETS):
                raise refused  # An unsigned copy of the upload is refused too.
            for info in infos:
                if info.filename in build.files:
                    if archive.read(info) != build.files[info.filename]:
                        raise refused
                elif not SIGNATURE_FILE.fullmatch(info.filename) or info.is_dir():
                    raise refused
    except SigningError:
        raise
    except Exception:
        raise refused from None


def _save(output, name, data):
    output.mkdir(parents=True, exist_ok=True)
    target = output / name
    try:
        with open(target, 'xb') as stream:
            stream.write(data)
    except FileExistsError:
        with open(target, 'rb') as stream:
            if stream.read(MAX_XPI + 1) != data:
                raise SigningError(f'{target} exists with other contents; nothing saved') from None
    return target


def main(argv=None, *, environ=None, api_base=API_BASE, ca_file=None, runner=run_child, sleep=time.sleep,
         clock=time.monotonic):
    """The Release workflow's signing step. Tests pass a loopback ``api_base`` and its ``ca_file``."""
    parser = argparse.ArgumentParser(prog='python -m akdbx.firefox_signing',
                                     description='Have Mozilla sign the generic Firefox build of this akdbx (AMO, '
                                                 f'unlisted) with the API key in {ISSUER_ENV} and {SECRET_ENV}.')
    parser.add_argument('--output', required=True, type=Path, help='folder for the signed XPI (created if missing)')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT,
                        help=f'seconds for the whole run, review included (default {int(DEFAULT_TIMEOUT)})')
    args = parser.parse_args(argv)
    environ = os.environ if environ is None else environ
    issuer, secret = environ.get(ISSUER_ENV, ''), environ.get(SECRET_ENV, '')
    from .extension_host import archive_name
    name = archive_name('firefox', signed=True)
    if not issuer or not secret:
        print(json.dumps(dict(ok=False, state='unsigned', file=name, error=f'{ISSUER_ENV} and {SECRET_ENV} are not '
                              'both set, so Mozilla signs nothing; this release has no signed Firefox add-on')))
        return 3
    if not 60 <= args.timeout <= 6 * 3600:
        print(json.dumps(dict(ok=False, error='--timeout must be 60 to 21600 seconds; nothing submitted')))
        return 1
    build = Build.current()
    signer = Signer(issuer, secret, timeout=args.timeout, api_base=api_base, ca_file=ca_file, runner=runner, sleep=sleep,
                    clock=clock)
    try:
        data = signer.sign(build)
        target = _save(args.output, name, data)
    except SigningError as exc:
        print(json.dumps(dict(ok=False, version=build.version, stage=signer.stage, error=_clean(str(exc), signer.hide))))
        return 1
    except OSError:
        print(json.dumps(dict(ok=False, version=build.version, error='the signed add-on could not be saved in '
                              f'{args.output}; nothing saved')))
        return 1
    finally:
        issuer = secret = signer.issuer = signer.secret = None
    print(json.dumps(dict(ok=True, state='signed', addon_id=FIREFOX_EXTENSION_ID, version=build.version,
                          channel=CHANNEL, file=target.name, size=len(data), sha256=hashlib.sha256(data).hexdigest())))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
