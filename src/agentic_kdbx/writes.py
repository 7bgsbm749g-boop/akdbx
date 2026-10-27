"""Private password writes and explicit metadata-only SSO identity creation."""
from __future__ import annotations

import ipaddress
import re
import secrets
import string
import unicodedata
from dataclasses import dataclass, field
from types import SimpleNamespace
from urllib.parse import urlsplit

from .persistence import SaveError
from .versions import active_entries, is_archive_group

MAX_WRITES = 64
SSO_AUTH_METHODS = ('google', 'github')
SSO_MARKER = 'akdbx.passwordless-sso'
AUTH_METHOD = 'akdbx.auth-method'


class WriteError(ValueError):
    """Only fixed, non-secret messages may cross RPC."""


def sso_capabilities():
    return dict(sso_identity_supported=True, sso_identity_protocol=1,
                sso_auth_methods=list(SSO_AUTH_METHODS))


def sso_identity(entry):
    """Read only our non-secret markers; fail closed on incomplete markers."""
    getter = getattr(entry, 'get_custom_property', None)
    if getter is None:
        return None
    marker, method = getter(SSO_MARKER), getter(AUTH_METHOD)
    if marker is None and method is None:
        # PyKeePass returns None for both absent and empty Value elements.
        # An empty/corrupt marker must not re-enable password delivery.
        element = getattr(entry, '_element', None)
        if element is None or all(element.find('./String[Key="' + key + '"]') is None
                                  for key in (SSO_MARKER, AUTH_METHOD)):
            return None
    return dict(passwordless=True, auth_method=method if method in SSO_AUTH_METHODS else 'unknown')


def validate_sso_metadata(values):
    try:
        if not isinstance(values, dict) or any(
            not isinstance(value, str) or any(unicodedata.category(c).startswith('C') for c in value)
            for value in values.values()
        ):
            raise ValueError
        validate_metadata(values)
        if values['username'] != values['username'].strip() or any(c.isspace() for c in values['username']):
            raise ValueError
        url = values['url']
        if not url.isascii() or any(c.isspace() for c in url) or '\\' in url:
            raise ValueError
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or '?' in url or '#' in url or re.search(r'%(?![0-9a-fA-F]{2})', url):
            raise ValueError
        host = parsed.hostname
        authority = '[' + host + ']' if ':' in host else host
        if not re.fullmatch(re.escape(authority) + r'(?::[0-9]+)?', parsed.netloc.lower()):
            raise ValueError
        if ':' in host:
            ipaddress.IPv6Address(host)
            if '%' in host:
                raise ValueError
        elif host.rsplit('.', 1)[-1].isdigit() or re.fullmatch(r'0x[0-9a-f]+', host.rsplit('.', 1)[-1]):
            # URL parsers disagree on abbreviated/hex/octal IPv4 spellings.
            # Accept only the unambiguous dotted decimal form for new records.
            ipaddress.IPv4Address(host)
        elif len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise ValueError
    except (ValueError, TypeError, UnicodeError):
        raise WriteError('invalid SSO metadata; require title, account, existing group and an ASCII HTTPS site URL without query or fragment') from None


def metadata(entry):
    return dict(title=entry.title or '', username=entry.username or '', url=entry.url or '', group='/'.join(entry.path[:-1]))


def site_origin(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {'http', 'https'} or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.port == 0
    ):
        raise WriteError('invalid site URL')
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    host = parsed.hostname
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        host = host.encode('idna').decode('ascii').lower()
    return parsed.scheme, host, port


def validate_metadata(values):
    if set(values) != {'title', 'username', 'url', 'group'} or any(
        not isinstance(v, str) or len(v.encode('utf-8')) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in v)
        for v in values.values()
    ):
        raise WriteError('invalid destination metadata')
    if not values['title'].strip() or not values['username'].strip():
        raise WriteError('title, account and a site URL are required')
    site_origin(values['url'])


def group_for(vault, path):
    groups = []
    for group in vault.groups:
        if '/'.join(group.path) != path:
            continue
        ancestor = group
        while ancestor is not None and not is_archive_group(ancestor):
            ancestor = getattr(ancestor, 'parentgroup', None)
        if ancestor is None:
            groups.append(group)
    if len(groups) != 1:
        raise WriteError('destination group is missing or ambiguous')
    return groups[0]


def duplicate(vault, values):
    # Conservative: same account on an origin anywhere in the vault is a
    # duplicate even if title, URL path or group differs.
    for entry in active_entries(vault):
        if (entry.username or '').casefold() != values['username'].casefold():
            continue
        try:
            if site_origin(entry.url or '') == site_origin(values['url']):
                return True
        except (ValueError, TypeError):
            # An unusable URL cannot be an origin match. Exact valid metadata
            # is still required for selecting that entry for an update.
            continue
    return False


@dataclass
class Write:
    token: str
    expires: float
    revision: int
    values: dict
    uuid: object = None
    state: str = 'pending'
    error: str | None = None
    password: str | None = field(default=None, repr=False)
    filled: set = field(default_factory=set)
    fill_refs: dict = field(default_factory=dict, repr=False)


class WriteManager:
    # All methods run under the broker's vault lock.
    def __init__(self, broker):
        self.broker = broker
        self.operations = {}
        self.revision = 0
        self.public_base = None

    def available(self):
        store = getattr(self.broker.vault, '_akdbx_store', None)
        return bool(self.public_base and store and store.writable_path and not store.recovery_required)

    def invalidate_revision(self, current=None, *, all_pending=False):
        self.revision += 1
        for other in self.operations.values():
            if other is not current and other.state == 'pending' and (all_pending or other.password is not None):
                other.state = 'failed'
                other.error = 'stale write; search and start again'
                other.password = None
                other.fill_refs.clear()
        with self.broker._state_lock:
            self.broker._handles.clear()

    def _prune(self):
        now = self.broker.clock()
        for handle, op in list(self.operations.items()):
            if op.expires <= now:
                op.password = None
                del self.operations[handle]

    def get(self, handle):
        self._prune()
        return self.operations.get(handle) if isinstance(handle, str) else None

    def by_token(self, token):
        self._prune()
        return next((op for op in self.operations.values() if secrets.compare_digest(op.token, token) and op.state == 'pending'), None)

    def create_sso(self, request):
        # This explicit action accepts metadata only. It cannot accept a secret
        # or silently reinterpret an ordinary create-entry/password request.
        if set(request) != {'action', 'metadata', 'auth_method'}:
            raise WriteError('SSO creation accepts only destination metadata and auth_method')
        method = request.get('auth_method')
        if not isinstance(method, str) or method not in SSO_AUTH_METHODS:
            raise WriteError('SSO auth_method must be google or github')
        values = request.get('metadata')
        validate_sso_metadata(values)
        if not self.available():
            raise WriteError('private writes unavailable; check activation and vault path safety')
        vault = self.broker.vault
        group_for(vault, values['group'])
        if duplicate(vault, values):
            raise WriteError('duplicate site/account; select an existing entry')

        def mutate(candidate):
            group = group_for(candidate, values['group'])
            if duplicate(candidate, values):
                raise WriteError('duplicate site/account; select an existing entry')
            label = {'google': 'Google', 'github': 'GitHub'}[method]
            entry = candidate.add_entry(group, values['title'], values['username'], '', url=values['url'],
                                        notes=f'Sign-in method: {label} SSO. No separate site password.')
            entry.set_custom_property(SSO_MARKER, 'v1')
            entry.set_custom_property(AUTH_METHOD, method)

        try:
            self.broker.vault = vault._akdbx_store.commit(vault, mutate)
        except (SaveError, WriteError):
            raise
        except Exception:
            raise WriteError('save failed; vault update not confirmed') from None
        self.invalidate_revision()
        return dict(ok=True, state='saved', metadata=dict(values), auth_method=method, passwordless=True)

    def begin(self, request):
        entry = None
        if request['action'] in {'update-password', 'generate-password'}:
            try:
                entry = self.broker._resolve(request.get('handle'))
            except ValueError:
                raise WriteError('unknown or expired handle; search again') from None
            if sso_identity(entry):
                raise WriteError('SSO-only record has no separate password; use its sign-in method')
        if not self.available():
            raise WriteError('private writes unavailable; check activation and vault path safety')
        values = request.get('metadata')
        if not isinstance(values, dict):
            raise WriteError('invalid destination metadata')
        validate_metadata(values)
        if entry is not None:
            if metadata(entry) != values or sum(metadata(e) == values for e in active_entries(self.broker.vault)) != 1 or not any(e.uuid == entry.uuid for e in active_entries(self.broker.vault)):
                raise WriteError('entry metadata mismatch; search again')
        else:
            group_for(self.broker.vault, values['group'])
            if duplicate(self.broker.vault, values):
                raise WriteError('duplicate site/account; select an existing entry')
        self._prune()
        if len(self.operations) >= MAX_WRITES:
            raise WriteError('too many pending writes; cancel or wait')
        handle = secrets.token_urlsafe(32)
        op = Write(secrets.token_urlsafe(32), self.broker.clock() + self.broker.handle_ttl, self.revision, dict(values), entry.uuid if entry else None)
        if request['action'] == 'generate-password':
            if urlsplit(values['url']).scheme != 'https':
                raise WriteError('generated resets require an HTTPS site')
            length = request.get('length', 24)
            symbols = request.get('symbols', '!@#$%*-_+=?')
            if type(length) is not int or not 16 <= length <= 128 or not isinstance(symbols, str) or len(symbols) > 32 or any(c not in string.punctuation for c in symbols):
                raise WriteError('generation policy requires length 16..128 and at most 32 ASCII punctuation symbols')
            symbols = ''.join(dict.fromkeys(symbols))
            alphabet = string.ascii_letters + string.digits + symbols
            # Rejection sampling avoids biased forced positions. Require each
            # selected class; all characters come from the requested alphabet.
            while True:
                password = ''.join(secrets.choice(alphabet) for _ in range(length))
                if all(any(c in group for c in password) for group in (string.ascii_lowercase, string.ascii_uppercase, string.digits, *([symbols] if symbols else []))):
                    break
            op.password = password
            op.fill_refs = {secrets.token_urlsafe(32): mode for mode in ('password', 'confirmation')}
        self.operations[handle] = op
        if op.password is not None:
            return {'ok': True, 'write_handle': handle, 'state': op.state, 'fill_handles': {mode: ref for ref, mode in op.fill_refs.items()}}
        return {'ok': True, 'write_handle': handle, 'private_url': self.public_base.rstrip('/') + '/write?token=' + op.token, 'state': op.state}

    def status(self, handle, cancel=False):
        op = self.get(handle)
        if op is None:
            return {'ok': False, 'error': 'unknown or expired write; start again'}
        if cancel and op.state == 'pending':
            op.state = 'cancelled'
            op.password = None
            op.fill_refs.clear()
        return {'ok': True, 'state': op.state, **({'error': op.error} if op.error else {})}

    def submit(self, op, password, confirmation, confirmed):
        if op.state != 'pending' or op.expires <= self.broker.clock():
            return {'ok': False, 'error': 'unknown or expired write; start again'}
        try:
            self.broker._validate_credential_text(password)
            if not confirmed or not password or password != confirmation:
                raise WriteError('confirm destination and matching nonempty passwords')
        except Exception:
            return {'ok': False, 'error': 'confirm destination and matching safe nonempty passwords'}
        # One save attempt consumes the private authorization, including failure.
        op.state = 'failed'
        try:
            if op.revision != self.revision:
                raise WriteError('stale write; search and start again')
            vault = self.broker.vault
            def mutate(candidate):
                if op.uuid is not None:
                    entries = [e for e in active_entries(candidate) if e.uuid == op.uuid]
                    if len(entries) != 1 or metadata(entries[0]) != op.values:
                        raise WriteError('entry changed; search again')
                    if sso_identity(entries[0]):
                        raise WriteError('SSO-only record has no separate password; use its sign-in method')
                    entries[0].save_history()
                    entries[0].password = password
                else:
                    if duplicate(candidate, op.values):
                        raise WriteError('duplicate site/account; select an existing entry')
                    candidate.add_entry(group_for(candidate, op.values['group']), op.values['title'], op.values['username'], password, url=op.values['url'])
            self.broker.vault = vault._akdbx_store.commit(vault, mutate)
            self.invalidate_revision(op)
            op.state = 'saved'
            op.password = None
            op.fill_refs.clear()
            return {'ok': True, 'state': 'saved'}
        except SaveError as exc:
            op.error = str(exc)
        except ValueError:
            op.error = 'stale or conflicting destination; search and start again'
        except Exception:
            op.error = 'save failed; vault update not confirmed'
        op.password = None
        op.fill_refs.clear()
        return {'ok': False, 'error': op.error}

    def fill(self, request, delivery_ready):
        self._prune()
        ref = request.get('handle')
        found = next(((op, op.fill_refs.pop(ref)) for op in self.operations.values() if isinstance(ref, str) and ref in op.fill_refs), None)
        if found is None:
            raise WriteError('unknown or expired generated fill handle; start again')
        op, mode = found
        if op.state != 'pending' or op.password is None or op.revision != self.revision:
            raise WriteError('stale generated password; start again')
        target = request.get('target_url')
        if not isinstance(target, str):
            raise WriteError('verified target URL required')
        if site_origin(target) != site_origin(op.values['url']):
            raise WriteError('target site mismatch; no password filled')
        # Reuse the existing keyboard preflight/deadline/dispatch boundary.
        proxy = SimpleNamespace(uuid=secrets.token_hex(16), password=op.password, username='')
        handle = self.broker._new_handle(proxy)
        response = self.broker._dispatch({'action': 'fill', 'handle': handle, 'mode': 'password', 'start_deadline': request.get('start_deadline')}, delivery_ready=delivery_ready)
        if response.get('ok'):
            op.filled.add(mode)
        return response

    def commit_generated(self, request):
        op = self.get(request.get('write_handle'))
        if op is None or op.state != 'pending' or op.password is None:
            raise WriteError('unknown or expired generated password; start again')
        if request.get('site_accepted') is not True or op.filled != {'password', 'confirmation'}:
            raise WriteError('both fills and explicit site acceptance are required')
        return self.submit(op, op.password, op.password, True)
