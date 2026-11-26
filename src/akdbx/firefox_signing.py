"""`akdbx extension sign`: the broker gets its own Firefox build signed by Mozilla (AMO).

Firefox installs an add-on permanently only when Mozilla signed it. AMO signs
an unlisted ("self-distributed") add-on for the account that owns its ID,
after automatic review. Each akdbx deployment needs its own signed file: the
build writes the deployment's private-page origin and a new random build ID
(the extension's trust anchor) into config.js, so a file shared by all users
would share one trust anchor.

The broker does all of it, so no caller can get other code signed under the
owner's account and the API secret never leaves the broker:

- The caller gives only a fresh search handle of the owner's AMO entry: an
  entry on exactly https://addons.mozilla.org with the captured protected
  fields ``jwt_issuer`` and ``jwt_secret`` (`capture-secret`).
- The broker builds the Firefox files from its own installed source
  (``extension_host.firefox_signing_files``), with the origin of its own
  private page and a new add-on version (``extension_host.signed_version``):
  AMO needs a new version string for every signature, and the broker still
  recognizes the signed add-on as its own build.
- Each AMO request runs in a short child process (``amo_https``) with a fixed
  deadline. The broker signs a JSON Web Token (HS256, one minute, unique
  ``jti``) for each request; only that token goes to the child, never the
  secret, argv, the environment, a log or a response.
- Review can take minutes, so one call works for at most ``CALL_BUDGET``
  seconds and then answers ``state: pending``. The job stays in broker memory
  (no secret in it); the same command with a fresh handle resumes it.
- Each version also gets a source archive (``source_archive``): the akdbx
  package that generated the files and BUILD.md, because Mozilla asks for the
  source of generated code (content.js is filled in from Python modules).
- The signed file must hold exactly the submitted files plus Mozilla's
  signature files under META-INF/. The broker saves it in its own private
  folder and returns only its path, version, size and SHA-256. The CLI copies
  it to ``--output``.

The add-on ID is fixed (``akdbx@akdbx.org``, which the native host allows), so
only the AMO account that owns that ID can sign; any other account gets
AMO's 403 or 409 as a clear refusal.
"""
from __future__ import annotations

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
import threading
import time
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .extension_route import FIREFOX_EXTENSION_ID

PROTOCOL = 1
ACTION = 'sign-firefox-extension'
AMO_ORIGIN = 'https://addons.mozilla.org'
API_BASE = AMO_ORIGIN + '/api/v5/'
CHANNEL = 'unlisted'
ISSUER_FIELD = 'jwt_issuer'
SECRET_FIELD = 'jwt_secret'
CALL_BUDGET = 100.0        # Seconds of AMO work in one call; then the job answers "pending".
REQUEST_TIMEOUT = 30.0     # One AMO request (the child is killed after this).
UPLOAD_TIMEOUT = 60.0
VALIDATION_POLL = 3.0
REVIEW_POLL = 5.0
RETRY_AFTER = 30           # What a pending answer suggests, in seconds.
JOB_TTL = 24 * 3600.0      # A job that has not finished by then is dropped.
TOKEN_LIFETIME = 60        # AMO allows at most 300 seconds.
MAX_XPI = 8 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
MAX_SOURCE = 8 * 1024 * 1024
MAX_VERSION_PAGES = 200    # 50 versions a page, newest first; across calls of one job.
MAX_DUPLICATES = 5         # Versions taken by another deployment of the same account.
MAX_REDIRECTS = 3
CLI_TIMEOUT = 150          # The CLI waits this long for one call (CALL_BUDGET plus margin).
CHILD = Path(__file__).resolve().with_name('amo_https.py')
UUID = re.compile(r'[0-9a-f]{32}|[0-9a-f-]{36}')
SIGNATURE_FILE = re.compile(r'META-INF/[A-Za-z0-9._-]{1,64}')
# Mozilla signs with PKCS#7 and with COSE; a signed file holds at least one complete set.
SIGNATURE_SETS = ({'META-INF/manifest.mf', 'META-INF/mozilla.sf', 'META-INF/mozilla.rsa'},
                  {'META-INF/cose.manifest', 'META-INF/cose.sig'})
SOURCE_SUFFIXES = {'.py', '.js', '.json', '.html', '.css', '.txt', '.dat', '.LICENSE'}
XPI_NAME = re.compile(r'akdbx-firefox-[0-9.]{5,40}\.xpi')
STAGES = ('plan', 'upload', 'validation', 'submit', 'source', 'review', 'download')
RESUME = 'run `akdbx extension sign` again with a fresh search handle to resume'


class SigningError(Exception):
    """A fixed, secret-free refusal. ``keep``: the job stays and a later call resumes it."""

    def __init__(self, message, *, keep=False):
        super().__init__(message)
        self.keep = keep


@dataclass
class Job:
    issuer_digest: bytes
    origin: str
    created: float
    stage: str = 'plan'
    sequence: int = 0
    version: str | None = None
    files: dict = field(default_factory=dict, repr=False)
    xpi: bytes = field(default=b'', repr=False)
    upload: str | None = None
    version_id: int | None = None
    submitted: bool = False   # A version create was sent; its outcome may be unknown.
    listed: int = 0           # The highest sequence of this build seen in AMO's version list so far.
    list_url: str | None = None  # The next page of that list.
    list_pages: int = 0       # Pages of that list read so far.
    file_url: str | None = None
    file_hash: str | None = None
    duplicates: int = 0


def default_folder(socket_path):
    """The broker's private folder for signed XPI files, keyed to the broker endpoint."""
    if os.name == 'nt':
        return Path(os.environ['LOCALAPPDATA']) / 'akdbx' / 'firefox-signed'
    base = os.environ.get('XDG_STATE_HOME', '')
    root = Path(base) if os.path.isabs(base) else Path.home() / '.local' / 'state'
    key = hashlib.sha256(os.fsencode(os.path.realpath(socket_path))).hexdigest()[:16]
    return root / 'akdbx' / f'firefox-signed-{key}'


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def token(issuer, secret, now):
    """An AMO API token: HS256 over the issuer, a unique jti and a one-minute lifetime."""
    header = _b64url(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    claims = _b64url(json.dumps({'iss': issuer, 'jti': secrets.token_hex(16), 'iat': int(now),
                                 'exp': int(now) + TOKEN_LIFETIME}, separators=(',', ':')).encode())
    signature = _b64url(hmac.new(secret.encode('utf-8'), header + b'.' + claims, hashlib.sha256).digest())
    return (header + b'.' + claims + b'.' + signature).decode('ascii')


def run_child(request, timeout):
    """One AMO request in a child process: the result object, or None for a network failure."""
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if os.name == 'nt' else 0
    try:
        done = subprocess.run([sys.executable, '-I', str(CHILD)], input=json.dumps(request).encode('utf-8'),
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
                              creationflags=flags, check=False)
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
        value = json.loads(response['body'])
    except Exception:
        return None
    return value


def _messages(response, hide):
    data = _json(response)
    return _clean('; '.join(_texts(data, [])), hide) if data is not None else ''


# akdbx's runtime dependencies on every platform (pyproject.toml; a test keeps them equal).
REBUILD_REQUIREMENTS = ('cryptography>=43,<47', 'idna>=3.7,<4', 'pykeepass==4.2.0', 'websocket-client>=1.8,<2')

BUILD_NOTES = '''# Source of the akdbx Firefox add-on {version}

akdbx {package} generated this add-on (https://github.com/7bgsbm749g-boop/akdbx).
This archive holds the exact akdbx package that built it (`akdbx/`), which can
be a development build, without compiled files and without the Android helper
binary, which the add-on does not use. Rebuild from this archive, not from a
release.

- `akdbx/fill_extension/` holds the add-on's files as written. No minifier,
  bundler or transpiler runs.
- `content.js` is generated: `akdbx/extension_host.py` (`_content_script`)
  replaces each `__MARKER__` placeholder in `fill_extension/content.js` with a
  JavaScript constant from `browser_password.py`, `browser_card.py`,
  `browser_code.py`, `browser_identity.py`, `card_processor.py` and
  `password_frames.py`.
- `manifest.json`: `_manifest_for('firefox', ...)` adds the Firefox fields and
  the version {version}.
- `config.js` holds this deployment's values: the private-page origin
  {origin}, the build ID {build_id} and the version.
- `jsQR.js` and `jsQR.LICENSE`: jsQR 1.4.0, unmodified
  (`akdbx/import_assets/VENDOR.txt` names the npm package and its integrity).

Rebuild with Python 3.11 or newer, in the folder that holds this file:

    python -m pip install {requirements}
    python rebuild.py OUT

`rebuild.py` calls `extension_host.firefox_signing_files` with the values
above and writes every file of the add-on to OUT and the archive to OUT.xpi.
Each file equals the submitted one, and OUT.xpi equals the uploaded archive
byte for byte (SHA-256 {sha256}).
'''

REBUILD_SCRIPT = '''"""Rebuild the akdbx Firefox add-on {version} from this archive: python rebuild.py OUT"""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # This archive's akdbx, not an installed one.
import akdbx
from akdbx import extension_host

files = extension_host.firefox_signing_files({origin!r}, {version!r}, build_id={build_id!r})
out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True)
for name, data in sorted(files.items()):
    (out / name).write_bytes(data)
archive = extension_host.xpi_bytes(files)
out.with_name(out.name + '.xpi').write_bytes(archive)
print(json.dumps({{'akdbx': akdbx.__file__, 'files': len(files), 'sha256': hashlib.sha256(archive).hexdigest()}}))
'''


def source_archive(version, origin, build_id, xpi):
    """What AMO reviewers get for one signed version: this akdbx package, BUILD.md and rebuild.py.

    ``rebuild.py`` reproduces every submitted file and the uploaded archive itself from
    the archived package with this version's origin, build ID and version.
    """
    from . import __version__
    package = Path(__file__).resolve().parent
    values = dict(version=version, package=__version__, origin=origin, build_id=build_id,
                  sha256=hashlib.sha256(xpi).hexdigest(), requirements=' '.join(f'"{r}"' for r in REBUILD_REQUIREMENTS))
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


class FirefoxSigning:
    """One signing job at a time, kept in memory between calls."""

    def __init__(self, broker, folder=None, *, api_base=API_BASE, ca_file=None, runner=run_child, sleep=time.sleep):
        self.broker = broker
        self.folder = Path(folder) if folder is not None else None
        self.api_base = api_base  # Tests point this at a loopback fake; serve never changes it.
        self.ca_file = ca_file
        self.runner = runner
        self.sleep = sleep
        self.job: Job | None = None
        self._busy = threading.Lock()
        self._last_sequence = 0

    def capabilities(self):
        return dict(firefox_signing_protocol=PROTOCOL, firefox_signing_channel=CHANNEL,
                    firefox_signing_entry_origin=AMO_ORIGIN, firefox_signing_fields=[ISSUER_FIELD, SECRET_FIELD],
                    firefox_signing_configured=self.folder is not None)

    # ---- the request ---------------------------------------------------
    def sign(self, request):
        if (set(request) - {'restart'} != {'action', 'firefox_signing_protocol', 'handle'}
                or type(request.get('firefox_signing_protocol')) is not int
                or request['firefox_signing_protocol'] != PROTOCOL
                or 'restart' in request and request['restart'] is not True):
            return dict(ok=False, error='invalid Firefox signing request; nothing submitted')
        try:
            issuer, secret = self._credentials(request.get('handle'))
        except SigningError as exc:
            return dict(ok=False, error=str(exc))
        try:
            if not self._busy.acquire(blocking=False):
                return dict(ok=False, error='another Firefox signing call is running; retry in a minute')
            try:
                return self._sign(issuer, secret, restart=request.get('restart') is True)
            finally:
                self._busy.release()
        finally:
            issuer = secret = None

    def _credentials(self, handle):
        """Read the two protected fields under the vault lock; the handle is used up either way."""
        from .cards import is_card
        from .identities import is_identity
        from .secrets_capture import _protected_value
        from .totp import https_origin
        from .writes import allowed_origins
        broker = self.broker
        with broker._vault_lock:
            try:
                entry = broker._resolve(handle)
            except ValueError:
                raise SigningError('unknown or expired handle; search again') from None
            if is_card(entry) or is_identity(entry):
                raise SigningError('select the AMO API key entry, not a card or identity; nothing submitted')
            try:
                on_amo = https_origin(AMO_ORIGIN) in allowed_origins(entry)  # Exact scheme, host and port.
            except Exception:
                on_amo = False
            if not on_amo:
                raise SigningError(f'the entry is not on {AMO_ORIGIN}; select the AMO API key entry; nothing submitted')
            issuer, secret = _protected_value(entry, ISSUER_FIELD), _protected_value(entry, SECRET_FIELD)
        if issuer is None or secret is None:
            raise SigningError(f'the entry has no captured protected {ISSUER_FIELD} and {SECRET_FIELD} fields; '
                               'capture both from the AMO API key page with capture-secret; nothing submitted')
        if self.folder is None:
            raise SigningError('this broker has no folder for signed add-ons; start it with `akdbx serve`; '
                               'nothing submitted')
        return issuer, secret

    def _origin(self):
        from .extension_host import trusted_origin
        origin = getattr(self.broker.unlock_link, 'origin', None)
        try:
            return trusted_origin(origin) if isinstance(origin, str) else None
        except Exception:
            return None

    def _sign(self, issuer, secret, *, restart):
        broker = self.broker
        origin = self._origin()
        if origin is None:
            return dict(ok=False, error='this broker serves no private HTTPS page, so the add-on would trust no '
                                        'origin; nothing submitted')
        digest = hashlib.sha256(issuer.encode('utf-8')).digest()
        now = broker.clock()
        job = self.job
        if job is not None and (restart or now - job.created > JOB_TTL):
            job = self.job = None
        if job is not None and not hmac.compare_digest(job.issuer_digest, digest):
            return dict(ok=False, error='a signing job for another AMO API key is pending; finish it with that '
                                        'entry, or pass --restart to drop it; nothing submitted')
        if job is not None and job.origin != origin:
            return dict(ok=False, error=f'the pending signing job built the add-on for {job.origin}, but this broker '
                                        f'now serves {origin}; pass --restart to build and submit a new one')
        if job is None:
            job = self.job = Job(issuer_digest=digest, origin=origin, created=now)
        deadline = now + CALL_BUDGET
        hide = (issuer, secret)
        try:
            return self._advance(job, issuer, secret, deadline, hide)
        except SigningError as exc:
            if not exc.keep and self.job is job:
                self.job = None
            return dict(ok=False, error=str(exc), **({'resumable': True} if exc.keep else {}))
        except Exception:
            return dict(ok=False, error='Firefox signing failed; ' + RESUME, resumable=True)

    # ---- AMO requests --------------------------------------------------
    def _call(self, method, path, issuer, secret, *, body=None, content_type=None, timeout=REQUEST_TIMEOUT,
              url=None, auth=True):
        request = dict(method=method, url=url or urljoin(self.api_base, path), timeout=timeout)
        if auth:
            request['token'] = token(issuer, secret, self.broker.wall_clock())
        if body is not None:
            request.update(body=base64.b64encode(body).decode('ascii'), content_type=content_type)
        if self.ca_file is not None:
            request['ca_file'] = str(self.ca_file)
        try:
            response = self.runner(request, timeout + 5)
        finally:
            request = None
        if response is None:
            raise SigningError('AMO could not be reached (network error or timeout); the signing job is kept; '
                               + RESUME, keep=True)
        status = response['status']
        if status == 401:
            raise SigningError('AMO refused the API key (HTTP 401): check the jwt_issuer and jwt_secret fields and '
                               "this computer's clock; the signing job is kept; " + RESUME, keep=True)
        if status == 429 or status >= 500:
            raise SigningError(f'AMO is busy or failed (HTTP {status}); the signing job is kept; ' + RESUME
                               + ' later', keep=True)
        return response

    def _owner_refusal(self, response, hide):
        detail = _messages(response, hide)
        return SigningError(f'AMO refused add-on ID {FIREFOX_EXTENSION_ID} (HTTP {response["status"]}): another AMO '
                            'account owns this ID (only that account can sign akdbx), or this API key cannot '
                            'manage it' + (f'. AMO says: {detail}' if detail else '') + '; nothing signed')

    def _advance(self, job, issuer, secret, deadline, hide):
        clock = self.broker.clock

        def room(seconds):
            return clock() + seconds <= deadline

        while True:
            if job.stage == 'plan':
                if not room(REQUEST_TIMEOUT) or not self._plan(job, issuer, secret, hide, room):
                    return self._pending(job)
            elif job.stage == 'upload':
                if not room(UPLOAD_TIMEOUT):
                    return self._pending(job)
                self._upload(job, issuer, secret, hide)
            elif job.stage == 'validation':
                if not room(REQUEST_TIMEOUT + VALIDATION_POLL):
                    return self._pending(job)
                if not self._validated(job, issuer, secret, hide):
                    self.sleep(VALIDATION_POLL)
            elif job.stage == 'submit':
                if not room(2 * REQUEST_TIMEOUT):
                    return self._pending(job)
                self._submit(job, issuer, secret, hide)
            elif job.stage == 'source':
                if not room(UPLOAD_TIMEOUT):
                    return self._pending(job)
                self._source(job, issuer, secret, hide)
            elif job.stage == 'review':
                if not room(REQUEST_TIMEOUT + REVIEW_POLL):
                    return self._pending(job)
                if not self._reviewed(job, issuer, secret, hide):
                    self.sleep(REVIEW_POLL)
            else:
                return self._download(job, issuer, secret, hide, room)

    def _pending(self, job):
        return dict(ok=True, state='pending', stage=job.stage, addon_id=FIREFOX_EXTENSION_ID,
                    addon_version=job.version, channel=CHANNEL, retry_after=RETRY_AFTER)

    def _same_api_origin(self, url):
        api, parts = urlsplit(self.api_base), urlsplit(url)
        return (parts.scheme == 'https' and parts.hostname is not None and not parts.username and not parts.password
                and (parts.hostname.lower(), parts.port) == (api.hostname.lower(), api.port))

    def _plan(self, job, issuer, secret, hide, room):
        """Pick the next unused version from all of AMO's versions of this add-on and this broker's last one.

        False when the call ran out of time; the pages read so far count at the next call.
        """
        from .extension_host import firefox_signing_files, signed_sequence, signed_version, xpi_bytes
        first = urljoin(self.api_base, f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/?filter=all_with_unlisted'
                                       '&page_size=50')
        if job.list_url is None:
            job.list_pages = 0  # A new scan (also after a version another deployment took).
        url, pages = job.list_url or first, 0
        while url is not None:
            if pages and not room(REQUEST_TIMEOUT):
                job.list_url = url
                return False
            if job.list_pages >= MAX_VERSION_PAGES:
                job.list_url = None
                raise SigningError(f'AMO lists more than {MAX_VERSION_PAGES * 50} versions of {FIREFOX_EXTENSION_ID}, '
                                   'so the next free version is unknown; nothing submitted')
            response = self._call('GET', None, issuer, secret, url=url)
            pages += 1
            job.list_pages += 1
            if response['status'] == 403:
                raise self._owner_refusal(response, hide)
            if response['status'] == 404 and url == first:
                break  # AMO has no add-on with this ID yet; the first signature creates it.
            data = _json(response)
            if response['status'] != 200 or not isinstance(data, dict) or not isinstance(data.get('results'), list):
                raise SigningError(f'AMO refused the version list (HTTP {response["status"]}); nothing submitted')
            for item in data['results']:
                number = signed_sequence(item.get('version')) if isinstance(item, dict) else None
                job.listed = max(job.listed, number or 0)
            following = data.get('next')
            # Pages come from the API's own origin only, so the token never goes elsewhere.
            if isinstance(following, str) and not self._same_api_origin(following):
                raise SigningError('AMO named a version list page on another origin; nothing submitted')
            url = following if isinstance(following, str) else None
        job.list_url = None
        job.sequence = max(job.listed, self._last_sequence, job.sequence) + 1
        try:
            job.version = signed_version(job.sequence)
        except ValueError as exc:
            raise SigningError(str(exc) + '; update akdbx to sign again') from None
        self._last_sequence = job.sequence
        job.files = firefox_signing_files(job.origin, job.version)
        job.xpi = xpi_bytes(job.files)
        job.upload = job.version_id = job.file_url = job.file_hash = None
        job.submitted = False
        job.stage = 'upload'
        return True

    def _upload(self, job, issuer, secret, hide):
        body, content_type = _multipart({'channel': CHANNEL}, 'upload', f'akdbx-firefox-{job.version}.xpi',
                                        'application/x-xpinstall', job.xpi)
        response = self._call('POST', 'addons/upload/', issuer, secret, body=body, timeout=UPLOAD_TIMEOUT,
                              content_type=content_type)
        data = _json(response)
        if response['status'] not in (200, 201, 202) or not isinstance(data, dict) \
                or not isinstance(data.get('uuid'), str) or not UUID.fullmatch(data['uuid']):
            detail = _messages(response, hide)
            raise SigningError(f'AMO refused the upload of {job.version} (HTTP {response["status"]})'
                               + (f': {detail}' if detail else '') + '; nothing signed')
        job.upload = data['uuid']
        job.stage = 'validation'

    def _validated(self, job, issuer, secret, hide):
        response = self._call('GET', f'addons/upload/{job.upload}/', issuer, secret)
        data = _json(response)
        if response['status'] != 200 or not isinstance(data, dict):
            raise SigningError(f'AMO refused the upload status (HTTP {response["status"]}); the signing job is kept; '
                               + RESUME, keep=True)
        if data.get('processed') is not True:
            return False
        if data.get('valid') is not True:
            messages = (data.get('validation') or {}).get('messages') if isinstance(data.get('validation'), dict) else None
            errors = [m for m in messages if isinstance(m, dict) and m.get('type') == 'error'] if isinstance(messages, list) else []
            detail = _clean('; '.join(' '.join(_texts([m.get('message'), m.get('file')], [])) for m in errors[:3]), hide)
            raise SigningError(f'AMO validation failed for {job.version}' + (f': {detail}' if detail else '')
                               + '; nothing signed')
        job.stage = 'submit'
        return True

    def _submit(self, job, issuer, secret, hide):
        if job.submitted:
            # An earlier create may have reached AMO: look the version up before sending it again.
            response = self._call('GET', f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/v{job.version}/',
                                  issuer, secret)
            data = _json(response)
            if response['status'] == 200 and isinstance(data, dict) and type(data.get('id')) is int \
                    and data.get('version') == job.version:
                job.version_id, job.stage = data['id'], 'source'
                return
        job.submitted = True
        response = self._call('PUT', f'addons/addon/{FIREFOX_EXTENSION_ID}/', issuer, secret,
                              body=json.dumps({'version': {'upload': job.upload}}).encode('utf-8'),
                              content_type='application/json')
        status, data = response['status'], _json(response)
        if status in (200, 201, 202) and isinstance(data, dict) and isinstance(data.get('version'), dict) \
                and type(data['version'].get('id')) is int:
            job.version_id, job.stage = data['version']['id'], 'source'
            return
        detail = _messages(response, hide)
        if status == 409 and ('already exists' in detail or 'uploaded before and deleted' in detail):
            # Another deployment of this account took the version: build the next one.
            job.duplicates += 1
            if job.duplicates > MAX_DUPLICATES:
                raise SigningError(f'AMO already has {job.version} and the next versions; nothing signed')
            job.stage = 'plan'
            return
        if status == 403 or status == 409:
            raise self._owner_refusal(response, hide)
        raise SigningError(f'AMO refused version {job.version} (HTTP {status})' + (f': {detail}' if detail else '')
                           + '; nothing signed')

    def _source(self, job, issuer, secret, hide):
        """Attach the source archive to the new version, as AMO asks for generated code (as web-ext does)."""
        try:
            from .extension_host import BUILD_ID
            build_id = BUILD_ID.search(job.files['config.js'].decode('utf-8')).group(1)
            data = source_archive(job.version, job.origin, build_id, job.xpi)
        except (OSError, ValueError, AttributeError) as exc:
            raise SigningError(f'the akdbx source archive could not be built ({exc}); the signing job is kept; '
                               + RESUME, keep=True) from None
        body, content_type = _multipart({}, 'source', f'akdbx-source-{job.version}.zip', 'application/zip', data)
        response = self._call('PATCH', f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/{job.version_id}/', issuer,
                              secret, body=body, content_type=content_type, timeout=UPLOAD_TIMEOUT)
        if response['status'] not in (200, 201, 202):
            detail = _messages(response, hide)
            raise SigningError(f'AMO refused the source archive of {job.version} (HTTP {response["status"]})'
                               + (f': {detail}' if detail else '') + '; the signing job is kept; ' + RESUME,
                               keep=True)
        job.stage = 'review'

    def _reviewed(self, job, issuer, secret, hide):
        response = self._call('GET', f'addons/addon/{FIREFOX_EXTENSION_ID}/versions/{job.version_id}/',
                              issuer, secret)
        data = _json(response)
        item = data.get('file') if isinstance(data, dict) else None
        if response['status'] != 200 or not isinstance(item, dict):
            raise SigningError(f'AMO refused the version status (HTTP {response["status"]}); the signing job is '
                               'kept; ' + RESUME, keep=True)
        status = item.get('status')
        if status == 'public' and isinstance(item.get('url'), str):
            job.file_url = item['url']
            job.file_hash = item.get('hash') if isinstance(item.get('hash'), str) else None
            job.stage = 'download'
            return True
        if status == 'disabled' or data.get('is_disabled') is True:
            raise SigningError(f'Mozilla did not sign {job.version} (file status disabled: rejected or disabled '
                               'on AMO); see the add-on on the AMO developer hub; nothing signed')
        return False

    def _download(self, job, issuer, secret, hide, room):
        api = urlsplit(self.api_base)
        url = job.file_url
        for _ in range(MAX_REDIRECTS + 1):
            if not room(REQUEST_TIMEOUT):
                return self._pending(job)
            parts = urlsplit(url)
            if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
                raise SigningError('AMO named an unusable download address for the signed add-on; nothing saved')
            # The token goes only to the API's own origin; a redirect elsewhere gets none.
            same = (parts.hostname.lower(), parts.port) == (api.hostname.lower(), api.port)
            response = self._call('GET', None, issuer, secret, url=url, auth=same)
            if response['status'] in (301, 302, 303, 307, 308) and response['location']:
                url = urljoin(url, response['location'])
                continue
            break
        else:
            raise SigningError('AMO redirected the signed add-on download too often; ' + RESUME, keep=True)
        if response['status'] != 200:
            raise SigningError(f'AMO refused the signed add-on download (HTTP {response["status"]}); the signing '
                               'job is kept; ' + RESUME, keep=True)
        data = response['body']
        self._verify(job, data)
        try:
            path = self._save(f'akdbx-firefox-{job.version}.xpi', data)
        except (OSError, RuntimeError, ValueError) as exc:
            raise SigningError(f'the signed add-on could not be saved in the broker folder {self.folder} ({exc}); '
                               'fix the folder, then ' + RESUME, keep=True) from None
        self.job = None
        return dict(ok=True, state='signed', addon_id=FIREFOX_EXTENSION_ID, addon_version=job.version,
                    channel=CHANNEL, xpi=str(path), size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                    trusted_origin=job.origin)

    def _verify(self, job, data):
        """The signed file must be the submitted build plus Mozilla's signature files, nothing else."""
        refused = SigningError('the signed add-on from AMO does not match the submitted build; nothing saved')
        if not data or len(data) > MAX_XPI:
            raise refused
        if job.file_hash is not None and job.file_hash.startswith('sha256:') \
                and not hmac.compare_digest(job.file_hash[7:].lower(), hashlib.sha256(data).hexdigest()):
            raise refused
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                names = [info.filename for info in infos]
                if len(names) != len(set(names)) or set(job.files) - set(names) \
                        or sum(info.file_size for info in infos) > MAX_UNPACKED \
                        or not any(signature <= set(names) for signature in SIGNATURE_SETS):
                    raise refused  # An unsigned copy of the upload is refused too.
                for info in infos:
                    if info.filename in job.files:
                        if archive.read(info) != job.files[info.filename]:
                            raise refused
                    elif not SIGNATURE_FILE.fullmatch(info.filename) or info.is_dir():
                        raise refused
        except SigningError:
            raise
        except Exception:
            raise refused from None

    def _save(self, name, data):
        folder = self.folder
        if os.name == 'nt':
            from . import windows_security
            folder.parent.mkdir(parents=True, exist_ok=True)
            windows_security.ensure_private_directory(folder)
            windows_security.replace_private(folder / name, data)
            return folder / name
        from .runtime import prepare_private_runtime_directory
        path, directory = prepare_private_runtime_directory(folder, create_ancestors=True)
        temporary = '.' + name + '.' + secrets.token_hex(8)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)
        return path / name


# ----- CLI ---------------------------------------------------------------
def add_parser(actions):
    command = actions.add_parser(
        'sign', help='have Mozilla sign this broker\'s own Firefox build (AMO, unlisted) for a permanent install',
        description=('The broker builds the Firefox add-on from its own akdbx source with its private-page origin '
                     'and a new add-on version, submits it to addons.mozilla.org on the unlisted channel with the '
                     'API key of the selected entry, waits up to about 100 seconds for Mozilla\'s signature, and '
                     'saves the signed XPI. The entry must be on https://addons.mozilla.org and hold the captured '
                     'protected fields jwt_issuer and jwt_secret. Prints only the path, version, size and SHA-256. '
                     'If review takes longer, the result is state "pending": run the command again with a fresh '
                     'search handle to resume.'))
    command.add_argument('--output', required=True, type=Path,
                         help='folder for the signed XPI (created if missing); an existing file is never replaced')
    command.add_argument('--restart', action='store_true',
                         help='drop a pending signing job and submit a new version')
    command.add_argument('handle', help='fresh search handle of the AMO API key entry')


def _valid_receipt(response):
    if not isinstance(response, dict):
        return False
    if response.get('ok') is False:
        error = response.get('error')
        allowed = {'ok', 'error', 'unlock_url', 'unlock_blocked'} if error == 'vault locked' else {'ok', 'error', 'resumable'}
        return (isinstance(error, str) and len(error) <= 600 and set(response) <= allowed
                and response.get('resumable', True) is True)
    if response.get('ok') is not True or response.get('addon_id') != FIREFOX_EXTENSION_ID \
            or response.get('channel') != CHANNEL:
        return False
    version = response.get('addon_version')
    if response.get('state') == 'pending':
        return (set(response) == {'ok', 'state', 'stage', 'addon_id', 'addon_version', 'channel', 'retry_after'}
                and response['stage'] in STAGES and (version is None or isinstance(version, str))
                and type(response['retry_after']) is int)
    return (response.get('state') == 'signed'
            and set(response) == {'ok', 'state', 'addon_id', 'addon_version', 'channel', 'xpi', 'size', 'sha256',
                                  'trusted_origin'}
            and isinstance(version, str) and XPI_NAME.fullmatch(f'akdbx-firefox-{version}.xpi') is not None
            and isinstance(response['xpi'], str) and Path(response['xpi']).name == f'akdbx-firefox-{version}.xpi'
            and type(response['size']) is int and 0 < response['size'] <= MAX_XPI
            and isinstance(response['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', response['sha256']) is not None
            and isinstance(response['trusted_origin'], str))


def _copy(response, output):
    """Copy the broker's signed file into the caller's folder after checking its size and hash."""
    source = Path(response['xpi'])
    with open(source, 'rb') as stream:
        data = stream.read(MAX_XPI + 1)
    if len(data) != response['size'] or hashlib.sha256(data).hexdigest() != response['sha256']:
        raise ValueError('the signed XPI in the broker folder does not match the broker receipt')
    target = output / source.name
    try:
        with open(target, 'xb') as stream:
            stream.write(data)
    except FileExistsError:
        with open(target, 'rb') as stream:
            if stream.read(MAX_XPI + 1) != data:
                raise ValueError(f'{target} exists with other contents; choose another --output folder') from None
    return target


def run(args, request):
    """``request(payload)`` sends one broker request."""
    output = args.output.expanduser().absolute()
    try:
        output.mkdir(parents=True, exist_ok=True)
        if not output.is_dir() or not os.access(output, os.W_OK):
            raise OSError
    except OSError:
        print(json.dumps(dict(ok=False, error=f'--output {output} is not a writable folder; request not sent')))
        return 2
    try:
        caps = request({'action': 'ping'})
    except (FileNotFoundError, ConnectionRefusedError):
        print('broker is not running; request not sent', file=sys.stderr)
        return 2
    except Exception:
        print('Firefox signing not started: broker connection or capability check failed; request not sent',
              file=sys.stderr)
        return 2
    if caps.get('ok') is not True or type(caps.get('firefox_signing_protocol')) is not int \
            or caps['firefox_signing_protocol'] != PROTOCOL:
        print(json.dumps(dict(ok=False, error='broker lacks Firefox signing (firefox_signing_protocol 1); require a '
                                              'broker newer than 0.52.0; request not sent')))
        return 1
    if caps.get('firefox_signing_configured') is not True:
        print(json.dumps(dict(ok=False, error='this broker has no folder for signed add-ons; start it with '
                                              '`akdbx serve`; request not sent')))
        return 1
    payload = dict(action=ACTION, firefox_signing_protocol=PROTOCOL, handle=args.handle)
    if args.restart:
        payload['restart'] = True
    try:
        response = request(payload)
        if not _valid_receipt(response):
            raise ValueError
    except (FileNotFoundError, ConnectionRefusedError):
        print('broker is not running', file=sys.stderr)
        return 2
    except Exception:
        print('Firefox signing outcome unconfirmed; response withheld. Run `akdbx extension sign` again with a '
              'fresh search handle: it resumes a pending job.', file=sys.stderr)
        return 2
    if response['ok'] and response['state'] == 'signed':
        try:
            target = _copy(response, output)
        except (OSError, ValueError) as exc:
            detail = str(exc) if isinstance(exc, ValueError) else 'it could not be copied (read or write failed)'
            print(json.dumps(dict(ok=False, error=f'signed XPI saved in the broker folder as {response["xpi"]}, but '
                                                  f'{detail}', broker_xpi=response['xpi'],
                                  addon_version=response['addon_version'], sha256=response['sha256'])))
            return 1
        response = dict(response, broker_xpi=response['xpi'], xpi=str(target))
    print(json.dumps(response, indent=2))
    return 0 if response['ok'] else 1
