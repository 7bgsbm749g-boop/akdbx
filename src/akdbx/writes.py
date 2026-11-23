"""Private password writes and explicit metadata-only passwordless identities."""
from __future__ import annotations

import ipaddress
import re
import secrets
import string
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import monotonic, sleep
from types import SimpleNamespace
from urllib.parse import urlsplit

import idna

from .persistence import SaveError
from .versions import active_entries, is_archive_group
from .totp import TotpError, configured as totp_configured, https_origin, parse_setup

MAX_WRITES = 64
SSO_AUTH_METHODS = ('google', 'github')
SSO_MARKER = 'akdbx.passwordless-sso'
PASSWORDLESS_AUTH_METHODS = ('email_code',)
PASSWORDLESS_MARKER = 'akdbx.passwordless'
AUTH_METHOD = 'akdbx.auth-method'


class WriteError(ValueError):
    """Only fixed, non-secret messages may cross RPC."""


def _entry_write_clock(entry, wall_clock, *, latest=None):
    """Refuse known future versions without waiting; reuse history during a save wait."""
    try:
        if latest is None:
            latest = max([entry.mtime, *(version.mtime for version in entry.history)]).replace(microsecond=0)
    except (ValueError, TypeError, OverflowError):
        raise WriteError('entry timestamps could not be verified; entry not saved') from None
    try:
        timestamp = wall_clock()
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise ValueError
        now = datetime.fromtimestamp(timestamp, timezone.utc).replace(microsecond=0)
        future = latest > now
    except (ValueError, TypeError, OverflowError):
        raise WriteError('invalid write clock; entry not saved') from None
    if future:
        raise WriteError('entry or history is future-dated; synchronize the clock before updating the entry')
    return latest, now


def _entry_changed_at(entry, wall_clock):
    """Use a real, strictly newer KDBX second without inventing future dates."""
    latest, now = _entry_write_clock(entry, wall_clock)
    deadline = monotonic() + 1.25
    while latest == now:
        # Ordinary same-second saves can wait for a real clock boundary. A
        # frozen/backward clock must refuse instead of creating a merge tie or
        # letting remote edits lose to an artificially future-dated version.
        if monotonic() >= deadline:
            raise WriteError('clock did not advance beyond the entry timestamp; retry the update later')
        sleep(0.05)
        _, now = _entry_write_clock(entry, wall_clock, latest=latest)
    return now


def _generated_origin(url):
    try:
        return https_origin(url)
    except TotpError:
        raise WriteError('generated resets require a verified ASCII HTTPS site URL without credentials') from None


GENERATED_MODES = ('password', 'confirmation')
GENERATED_SINGLE_MODES = ('password',)


def generated_capabilities():
    """Generated writes may be staged for a form with one new-password field.

    generated_additional_urls: a generated fill accepts the selected entry's
    exact KP2A_URL* origins as well as its main URL origin (0.31.2+).
    """
    return dict(generated_entry_protocol=1, generated_single_field=True, generated_additional_urls=True)


def sso_capabilities():
    return dict(sso_identity_supported=True, sso_identity_protocol=1,
                sso_auth_methods=list(SSO_AUTH_METHODS))


SECRET_SAVE_PROTOCOL = 1
SECRET_SAVE_FIELD = 'password'


def secret_save_capabilities():
    """Operator secrets piped to the CLI are saved to the protected Password field."""
    return dict(secret_save_protocol=SECRET_SAVE_PROTOCOL, secret_save_field=SECRET_SAVE_FIELD)


def passwordless_capabilities():
    return dict(passwordless_identity_supported=True, passwordless_identity_protocol=1,
                passwordless_auth_methods=list(PASSWORDLESS_AUTH_METHODS))


def passwordless_identity(entry):
    """Read only our non-secret markers; fail closed on incomplete markers."""
    getter = getattr(entry, 'get_custom_property', None)
    if getter is None:
        return None
    markers = (SSO_MARKER, PASSWORDLESS_MARKER, AUTH_METHOD)
    method = getter(AUTH_METHOD)
    if all(getter(key) is None for key in markers):
        # PyKeePass returns None for both absent and empty Value elements.
        # An empty/corrupt marker must not re-enable password delivery.
        element = getattr(entry, '_element', None)
        if element is None or all(element.find('./String[Key="' + key + '"]') is None
                                  for key in markers):
            return None
    return dict(passwordless=True, auth_method=method if method in SSO_AUTH_METHODS + PASSWORDLESS_AUTH_METHODS else 'unknown')


ADDITIONAL_URLS_PROTOCOL = 1
ADDITIONAL_URLS_POLICY = 'kp2a-exact-origin-v1'
ADDITIONAL_URL_KEY = re.compile(r'KP2A_URL(?:_[1-9][0-9]{0,3})?')
MAX_ADDITIONAL_URLS = 32


def additional_urls_capabilities():
    return dict(additional_urls_protocol=ADDITIONAL_URLS_PROTOCOL, additional_urls_policy=ADDITIONAL_URLS_POLICY)


def _serialize_origin(origin):
    _, host, port = origin
    return 'https://' + (f'[{host}]' if ':' in host else host) + ('' if port == 443 else f':{port}')


def _additional_fields(entry):
    """Return [(key, value)] of KeePassXC/KP2A additional URL strings, in key order."""
    element = getattr(entry, '_element', None)
    if element is None:
        return []
    fields = []
    for string_element in element.findall('./String'):
        key = string_element.findtext('Key')
        if isinstance(key, str) and ADDITIONAL_URL_KEY.fullmatch(key):
            fields.append((key, string_element.findtext('Value') or ''))
    fields.sort(key=lambda item: -1 if item[0] == 'KP2A_URL' else int(item[0][9:]))
    return fields


def _optional_origin(url):
    try:
        origin = https_origin(url)
    except Exception:
        return None
    # KeePassXC-Browser reads '*' as a wildcard; never treat it as a literal host.
    return None if '*' in origin[1] else origin


def additional_origins(entry):
    """Exact HTTPS origins from KP2A_URL* fields; invalid, http or wildcard values grant nothing."""
    origins = []
    for _, value in _additional_fields(entry)[:MAX_ADDITIONAL_URLS]:
        origin = _optional_origin(value)
        if origin is not None and origin not in origins:
            origins.append(origin)
    return origins


def additional_urls(entry):
    """Non-secret search metadata: canonical additional origins."""
    return [_serialize_origin(origin) for origin in additional_origins(entry)]


def allowed_origins(entry):
    """The exact HTTPS origins a credential may be delivered to: main URL plus KP2A_URL*."""
    main = _optional_origin(getattr(entry, 'url', None) or '')
    return {*([main] if main is not None else []), *additional_origins(entry)}


def _additional_origin_input(value):
    """Accept only an exact HTTPS origin, optionally with one trailing '/'."""
    from .password_frames import canonical_origin
    if not isinstance(value, str) or not 0 < len(value) <= 512:
        raise WriteError('additional URL must be an exact HTTPS origin such as https://login.example.com/')
    try:
        serialized = canonical_origin(value[:-1] if value.endswith('/') else value)
        if '*' in serialized:
            raise ValueError
    except Exception:
        raise WriteError('additional URL must be an exact HTTPS origin such as https://login.example.com/') from None
    return serialized, https_origin(serialized)


def _same_owner_host(main, new):
    """Agent-added origins stay on the saved URL's site (same registrable domain).

    The registrable domain comes from the vendored Public Suffix List,
    including private suffixes such as github.io, so another user's subdomain
    is never the same site. A saved host that is itself a public suffix, or an
    IP literal, permits only its own exact host. Other origins must be added
    by the user in KeePassXC.
    """
    from .public_suffix import registrable_domain
    main_host, new_host = main[1], new[1]
    if main_host == new_host:
        return True
    site = registrable_domain(main_host)
    try:
        ipaddress.ip_address(main_host)
        site = None
    except ValueError:
        pass
    return site is not None and registrable_domain(new_host) == site


def validate_identity_metadata(values, kind):
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
        raise WriteError(f'invalid {kind} metadata; require title, account, existing group and an ASCII HTTPS site URL without query or fragment') from None


def metadata(entry):
    return dict(title=entry.title or '', username=entry.username or '', url=entry.url or '', group='/'.join(entry.path[:-1]))


def _site_label(label):
    """Check joiners in Unicode and A-label forms without excluding emoji or underscores."""
    try:
        contextual = label[4:].encode('ascii').decode('punycode') if label.startswith('xn--') else label
        valid = all(c not in '\u200c\u200d' or idna.valid_contextj(contextual, i)
                    for i, c in enumerate(contextual))
    except ValueError:
        raise WriteError('invalid site URL') from None
    if not valid:
        raise WriteError('invalid site URL')
    return label.encode('ascii') if label.isascii() else b'xn--' + label.encode('punycode')


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
        # Keep IDNA2008 deviations distinct while preserving accepted ASCII
        # labels (including local underscores) and Unicode compatibility maps.
        mapped = idna.uts46_remap(host, std3_rules=False, transitional=False)
        labels = [_site_label(label) for label in mapped.split('.')]
        checked = labels[:-1] if labels[-1] == b'' else labels
        if not checked or any(not label or len(label) > 63 for label in checked):
            raise WriteError('invalid site URL')
        host = b'.'.join(labels).decode('ascii').lower()
    return parsed.scheme, host, port


def validate_metadata(values):
    from lxml import etree
    try:
        if set(values) != {'title', 'username', 'url', 'group'} or any(
            not isinstance(v, str) or len(v.encode('utf-8')) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in v)
            for v in values.values()
        ):
            raise ValueError
        if any(unicodedata.category(c) == 'Cc' for c in values['username']):
            raise ValueError
        for value in values.values():
            etree.Element('Value').text = value
    except (ValueError, TypeError):
        raise WriteError('invalid destination metadata') from None
    if not values['title'].strip() or not values['username'].strip():
        raise WriteError('title, account and a site URL are required')
    site_origin(values['url'])


def _group_path(group):
    """Slash-joined path of a writable group, or None for archive/unnamed paths."""
    parts = []
    ancestor = group
    while ancestor is not None:
        if is_archive_group(ancestor):
            return None
        if not ancestor.is_root_group:
            name = ancestor.name
            # The dependency's path drops unnamed ancestors. Do not let a
            # child of an unnamed group alias a different named path.
            if not isinstance(name, str) or not name:
                return None
            parts.append(name)
        ancestor = getattr(ancestor, 'parentgroup', None)
    return '/'.join(reversed(parts))


def group_for(vault, path):
    groups = [group for group in vault.groups if _group_path(group) == path]
    if len(groups) != 1:
        raise WriteError('destination group is missing or ambiguous')
    return groups[0]


def group_paths(vault):
    """Existing groups that group_for resolves, in vault order. '' is the top level."""
    paths = [_group_path(group) for group in vault.groups]
    counts = Counter(paths)
    return [path for path in dict.fromkeys(paths) if path is not None and counts[path] == 1]


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


def _append_entry(vault, group, values, password, *, notes=None):
    """Append broker-validated metadata without the dependency's label/XPath preflight."""
    from pykeepass.entry import Entry
    entry = Entry(title=values['title'], username=values['username'], password=password,
                  url=values['url'], notes=notes, kp=vault)
    group.append(entry)
    return entry


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
    kind: str = 'password'
    replace: bool = False
    import_candidates: tuple = field(default=(), repr=False)
    import_nonce: str | None = field(default=None, repr=False)
    import_source: str = ''
    # Identity saves: the fields the private page shows and accepts.
    fields: tuple = ()
    # Generated writes: set once at staging for a form with one new-password
    # field and no confirmation field. It never changes afterwards.
    single_field: bool = False


class WriteManager:
    # All methods run under the broker's vault lock.
    def __init__(self, broker):
        self.broker = broker
        self.operations = {}
        self.revision = 0
        self.public_base = None

    def available(self, *, refresh_inputs=False):
        """Refresh changed key contents for discovery, keeping delivery checks metadata-only."""
        store = getattr(self.broker.vault, '_akdbx_store', None)
        if not (self.public_base and store and not store.recovery_required):
            return False
        try:
            return bool(store.check_write_inputs() if refresh_inputs else store.writable_path)
        except (OSError, SaveError):
            return False

    def _require_available(self):
        store = getattr(self.broker.vault, '_akdbx_store', None)
        try:
            ready = bool(self.public_base and store and not store.recovery_required
                         and store.check_write_inputs())
        except (OSError, SaveError):
            ready = False
        if not ready:
            raise WriteError('private writes unavailable; check activation, vault/key changes and path safety')

    def notify_card(self, op):
        if op.kind == 'card' and op.state != 'pending':
            for handle, candidate in self.operations.items():
                if candidate is op:
                    self.broker.card_save_notifications.publish_save(handle, op.state)
                    break

    def invalidate_revision(self, current=None, *, all_pending=False):
        self.revision += 1
        for other in self.operations.values():
            if other is not current:
                other.import_candidates = ()
                other.import_nonce = None
            if other is not current and other.state == 'pending' and (all_pending or other.password is not None or other.kind in {'card', 'identity'}):
                other.state = 'failed'
                other.error = 'stale write; search and start again'
                other.password = None
                other.fill_refs.clear()
                self.notify_card(other)
        with self.broker._state_lock:
            self.broker._handles.clear()

    def _prune(self):
        now = self.broker.clock()
        for handle, op in list(self.operations.items()):
            if op.expires <= now:
                if op.kind == 'card' and op.state == 'pending':
                    self.broker.card_save_notifications.publish_save(handle, 'expired')
                op.password = None
                op.import_candidates = ()
                op.import_nonce = None
                del self.operations[handle]

    def get(self, handle):
        self._prune()
        return self.operations.get(handle) if isinstance(handle, str) else None

    def by_token(self, token, kind='password'):
        """Return a pending private operation for the current vault revision."""
        self._prune()
        return next((op for op in self.operations.values()
                     if op.revision == self.revision and secrets.compare_digest(op.token, token)
                     and op.state == 'pending' and op.password is None and op.kind == kind), None)

    def create_sso(self, request):
        return self._create_identity(request, SSO_AUTH_METHODS, SSO_MARKER, 'SSO')

    def create_passwordless(self, request):
        return self._create_identity(request, PASSWORDLESS_AUTH_METHODS, PASSWORDLESS_MARKER, 'passwordless')

    def _create_identity(self, request, methods, marker, kind):
        # This explicit action accepts metadata only. It cannot accept a secret
        # or silently reinterpret an ordinary create-entry/password request.
        if set(request) != {'action', 'metadata', 'auth_method'}:
            raise WriteError(f'{kind} creation accepts only destination metadata and auth_method')
        method = request.get('auth_method')
        if not isinstance(method, str) or method not in methods:
            raise WriteError(f'{kind} auth_method must be ' + ' or '.join(methods))
        values = request.get('metadata')
        validate_identity_metadata(values, kind)
        self._require_available()
        vault = self.broker.vault
        group_for(vault, values['group'])
        if duplicate(vault, values):
            raise WriteError('duplicate site/account; select an existing entry')

        def mutate(candidate):
            group = group_for(candidate, values['group'])
            if duplicate(candidate, values):
                raise WriteError('duplicate site/account; select an existing entry')
            label = {'google': 'Google SSO', 'github': 'GitHub SSO', 'email_code': 'Email code'}[method]
            entry = _append_entry(candidate, group, values, '',
                                  notes=f'Sign-in method: {label}. No separate site password.')
            entry.set_custom_property(marker, 'v1')
            entry.set_custom_property(AUTH_METHOD, method)

        try:
            self.broker.vault = vault._akdbx_store.commit(vault, mutate)
        except (SaveError, WriteError):
            raise
        except Exception:
            raise WriteError('save failed; vault update not confirmed') from None
        self.invalidate_revision()
        return dict(ok=True, state='saved', metadata=dict(values), auth_method=method, passwordless=True)

    def save_secret(self, request):
        """Save an operator-supplied secret into a new or selected entry's Password field.

        The secret arrives only over the private broker socket. It is never
        returned, logged or placed in an error message: every message below
        is fixed text.
        """
        updating = 'handle' in request
        if (set(request) - {'handle'} != {'action', 'metadata', 'secret', 'secret_save_protocol'}
                or type(request.get('secret_save_protocol')) is not int
                or request['secret_save_protocol'] != SECRET_SAVE_PROTOCOL):
            raise WriteError('secret save accepts only destination metadata, one secret and protocol 1')
        secret = request.get('secret')
        try:
            if not isinstance(secret, str) or not secret or secret.startswith('\ufeff'):
                raise ValueError
            self.broker._validate_credential_text(secret)
            if any(unicodedata.category(c) in {'Zl', 'Zp'} for c in secret):
                raise ValueError
        except Exception:
            raise WriteError('secret must be nonempty UTF-8 text of at most 64 KiB without control characters, line separators or a byte order mark') from None
        values = request.get('metadata')
        if not isinstance(values, dict):
            raise WriteError('invalid destination metadata')
        validate_metadata(values)
        entry = None
        if updating:
            try:
                entry = self.broker._resolve(request.get('handle'))
            except ValueError:
                raise WriteError('unknown or expired handle; search again') from None
            from .cards import is_card
            from .identities import is_identity
            if is_identity(entry):
                raise WriteError('identity record cannot be used for login writes')
            if is_card(entry):
                raise WriteError('card record requires card save')
            if passwordless_identity(entry):
                raise WriteError('passwordless record has no separate password; use its sign-in method')
        self._require_available()
        vault = self.broker.vault
        if entry is not None:
            if (metadata(entry) != values
                    or sum(metadata(e) == values for e in active_entries(vault)) != 1
                    or not any(e.uuid == entry.uuid for e in active_entries(vault))):
                raise WriteError('entry metadata mismatch; search again')
            _entry_write_clock(entry, self.broker.wall_clock)
            uuid = entry.uuid
        else:
            group_for(vault, values['group'])
            if duplicate(vault, values):
                raise WriteError('duplicate site/account; select an existing entry')
            uuid = None

        def selected(candidate):
            if uuid is not None:
                entries = [e for e in active_entries(candidate) if e.uuid == uuid]
            else:
                entries = [e for e in active_entries(candidate) if metadata(e) == values]
            if len(entries) != 1 or metadata(entries[0]) != values:
                raise WriteError('entry changed; search again')
            return entries[0]

        def mutate(candidate):
            if uuid is not None:
                target = selected(candidate)
                if passwordless_identity(target):
                    raise WriteError('passwordless record has no separate password; use its sign-in method')
                changed_at = _entry_changed_at(target, self.broker.wall_clock)
                target.save_history()
                target.password = secret
                target.mtime = changed_at
            else:
                if duplicate(candidate, values):
                    raise WriteError('duplicate site/account; select an existing entry')
                target = _append_entry(candidate, group_for(candidate, values['group']), values, secret)
            target._element.find('./String[Key="Password"]/Value').set('Protected', 'True')

        def verify_saved(candidate):
            target = selected(candidate)
            value = target._element.find('./String[Key="Password"]/Value')
            if target.password != secret or value is None or value.get('Protected') != 'True':
                raise WriteError('secret save verification failed; vault update not confirmed')

        try:
            self.broker.vault = vault._akdbx_store.commit(vault, mutate, verify_candidate=verify_saved)
        except (SaveError, WriteError):
            raise
        except Exception:
            raise WriteError('save failed; vault update not confirmed') from None
        finally:
            secret = None
        self.invalidate_revision()
        return dict(ok=True, state='saved', saved='updated' if updating else 'created', metadata=dict(values))

    def change_additional_url(self, request):
        """Metadata-only add/remove of one KP2A_URL* origin; never reads or changes the password."""
        adding = request.get('action') == 'add-url'
        if (set(request) != {'action', 'handle', 'url', 'additional_urls_protocol'}
                or type(request.get('additional_urls_protocol')) is not int
                or request['additional_urls_protocol'] != ADDITIONAL_URLS_PROTOCOL):
            raise WriteError('additional URL changes accept only a fresh handle and one HTTPS origin')
        serialized, origin = _additional_origin_input(request.get('url'))
        try:
            entry = self.broker._resolve(request.get('handle'))
        except ValueError:
            raise WriteError('unknown or expired handle; search again') from None
        from .cards import is_card
        from .identities import is_identity
        if is_identity(entry):
            raise WriteError('identity record has no site URLs')
        if is_card(entry):
            raise WriteError('card record has no site URLs')
        self._require_available()
        vault = self.broker.vault
        uuid, values = entry.uuid, metadata(entry)
        if sum(e.uuid == uuid for e in active_entries(vault)) != 1:
            raise WriteError('entry metadata mismatch; search again')

        def check(selected):
            main = _optional_origin(selected.url or '')
            if main is None:
                raise WriteError('entry needs an HTTPS site URL before additional URLs can be changed')
            present = [key for key, value in _additional_fields(selected) if _optional_origin(value) == origin]
            if adding:
                if origin == main or present:
                    raise WriteError('duplicate URL; origin already allowed for this entry')
                if not _same_owner_host(main, origin):
                    raise WriteError('additional URL must be on the same site as the saved URL; '
                                     'add other origins in KeePassXC')
                if len(_additional_fields(selected)) >= MAX_ADDITIONAL_URLS:
                    raise WriteError('too many additional URLs on this entry')
            elif not present:
                raise WriteError('additional URL not found on this entry')
            return present

        check(entry)
        _entry_write_clock(entry, self.broker.wall_clock)

        def selected(candidate):
            entries = [e for e in active_entries(candidate) if e.uuid == uuid]
            if len(entries) != 1 or metadata(entries[0]) != values:
                raise WriteError('entry changed; search again')
            return entries[0]

        password = entry.password

        def mutate(candidate):
            target = selected(candidate)
            present = check(target)
            changed_at = _entry_changed_at(target, self.broker.wall_clock)
            target.save_history()
            if adding:
                used = {key for key, _ in _additional_fields(target)}
                key = next(k for k in ('KP2A_URL', *(f'KP2A_URL_{n}' for n in range(1, MAX_ADDITIONAL_URLS + 1)))
                           if k not in used)
                target.set_custom_property(key, serialized + '/')
            else:
                for key in present:
                    target.delete_custom_property(key)
            target.mtime = changed_at

        def verify_saved(candidate):
            target = selected(candidate)
            if (target.password != password
                    or (origin in additional_origins(target)) != adding):
                raise WriteError('additional URL save verification failed; vault update not confirmed')

        try:
            self.broker.vault = vault._akdbx_store.commit(vault, mutate, verify_candidate=verify_saved)
        except (SaveError, WriteError):
            raise
        except Exception:
            raise WriteError('save failed; vault update not confirmed') from None
        finally:
            password = None
        self.invalidate_revision()
        saved = selected(self.broker.vault)
        return dict(ok=True, state='saved', metadata=values, additional_urls=additional_urls(saved),
                    changed='added' if adding else 'removed', url=serialized + '/')

    def begin(self, request):
        entry = None
        is_totp = request['action'] == 'setup-totp'
        if is_totp and (set(request) - {'action', 'handle', 'metadata', 'replace'} or type(request.get('replace', False)) is not bool):
            raise WriteError('TOTP setup accepts only selected entry metadata and an explicit replace flag')
        if request['action'] == 'generate-entry' and set(request) - {'action', 'metadata', 'length', 'symbols', 'single_field'}:
            raise WriteError('generated entry accepts only destination metadata and generation policy')
        single_field = request.get('single_field', False)
        if 'single_field' in request and (request['action'] not in {'generate-password', 'generate-entry'}
                                          or type(single_field) is not bool):
            raise WriteError('single_field is a boolean generation option for generate-password and generate-entry only')
        if request['action'] in {'update-password', 'generate-password', 'setup-totp'}:
            try:
                entry = self.broker._resolve(request.get('handle'))
            except ValueError:
                raise WriteError('unknown or expired handle; search again') from None
            from .cards import is_card
            from .identities import is_identity
            if is_identity(entry):
                raise WriteError('identity record cannot be used for login writes')
            if is_card(entry):
                raise WriteError('card record requires card save')
            if not is_totp and passwordless_identity(entry):
                raise WriteError('passwordless record has no separate password; use its sign-in method')
        self._require_available()
        values = request.get('metadata')
        if not isinstance(values, dict):
            raise WriteError('invalid destination metadata')
        validate_metadata(values)
        if entry is not None:
            if metadata(entry) != values or sum(metadata(e) == values for e in active_entries(self.broker.vault)) != 1 or not any(e.uuid == entry.uuid for e in active_entries(self.broker.vault)):
                raise WriteError('entry metadata mismatch; search again')
            if request['action'] == 'generate-password':
                _entry_write_clock(entry, self.broker.wall_clock)
            if is_totp:
                https_origin(values['url'])
                if totp_configured(entry) and not request.get('replace', False):
                    raise WriteError('TOTP already configured; explicit --replace is required')
        else:
            group_for(self.broker.vault, values['group'])
            if duplicate(self.broker.vault, values):
                raise WriteError('duplicate site/account; select an existing entry')
        self._prune()
        if len(self.operations) >= MAX_WRITES:
            raise WriteError('too many recent write requests; wait for earlier requests to expire, then start again')
        # These references are CLI positionals. URL-safe randomness can begin
        # with '-' and be parsed as an option; hex keeps all 256 random bits.
        handle = secrets.token_hex(32)
        op = Write(secrets.token_urlsafe(32), self.broker.clock() + self.broker.handle_ttl, self.revision, dict(values), entry.uuid if entry else None)
        if is_totp:
            op.kind = 'totp'
            op.replace = request.get('replace', False)
        if request['action'] in {'generate-password', 'generate-entry'}:
            _generated_origin(values['url'])
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
            op.single_field = single_field
            modes = GENERATED_SINGLE_MODES if single_field else GENERATED_MODES
            op.fill_refs = {secrets.token_hex(32): mode for mode in modes}
        self.operations[handle] = op
        if op.password is not None:
            return {'ok': True, 'write_handle': handle, 'state': op.state,
                    'fill_handles': {mode: ref for ref, mode in op.fill_refs.items()},
                    **({'single_field': True} if op.single_field else {})}
        route = '/totp' if is_totp else '/write'
        return {'ok': True, 'write_handle': handle, 'private_url': self.public_base.rstrip('/') + route + '?token=' + op.token, 'state': op.state}

    def status(self, handle, cancel=False):
        """Report stale pending writes as failed before applying cancellation."""
        op = self.get(handle)
        if op is None:
            return {'ok': False, 'error': 'unknown or expired write; start again'}
        if op.state == 'pending' and op.revision != self.revision:
            op.state = 'failed'
            op.error = 'stale write; search and start again'
            op.password = None
            op.fill_refs.clear()
            op.import_candidates = ()
            op.import_nonce = None
        if cancel and op.state == 'pending':
            op.state = 'cancelled'
            op.password = None
            op.fill_refs.clear()
            op.import_candidates = ()
            op.import_nonce = None
        self.notify_card(op)
        result = {'ok': True, 'state': op.state, **({'error': op.error} if op.error else {})}
        if op.kind == 'card' and op.state == 'saved':
            # The page can change the title and group; report what was saved.
            result.update(title=op.values['title'], group=op.values['group'])
        return result

    def page_state(self, token, kind='card'):
        """Why a save page token no longer opens a form: saved, cancelled, stale,
        failed or expired, and the failure text of a failed save."""
        self._prune()
        for op in self.operations.values():
            if (op.kind == kind and isinstance(token, str)
                    and secrets.compare_digest(op.token.encode(), token.encode())):
                if op.state == 'saved':
                    return 'saved', None
                if op.state == 'cancelled':
                    return 'cancelled', None
                if op.revision != self.revision or op.error == 'stale write; search and start again':
                    return 'stale', None
                return ('failed', op.error) if op.state == 'failed' else ('expired', None)
        return 'expired', None

    def submit(self, op, password, confirmation, confirmed):
        if op.kind != 'password' or op.state != 'pending' or op.expires <= self.broker.clock():
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
                    if passwordless_identity(entries[0]):
                        raise WriteError('passwordless record has no separate password; use its sign-in method')
                    entry = entries[0]
                    changed_at = _entry_changed_at(entry, self.broker.wall_clock)
                    entry.save_history()
                    entry.password = password
                    entry.mtime = changed_at
                else:
                    if duplicate(candidate, op.values):
                        raise WriteError('duplicate site/account; select an existing entry')
                    _append_entry(candidate, group_for(candidate, op.values['group']), op.values, password)
            self.broker.vault = vault._akdbx_store.commit(vault, mutate)
            self.invalidate_revision(op)
            op.state = 'saved'
            op.password = None
            op.fill_refs.clear()
            return {'ok': True, 'state': 'saved'}
        except (SaveError, WriteError) as exc:
            op.error = str(exc)
        except ValueError:
            op.error = 'stale or conflicting destination; search and start again'
        except Exception:
            op.error = 'save failed; vault update not confirmed'
        op.password = None
        op.fill_refs.clear()
        return {'ok': False, 'error': op.error}

    def stage_totp_import(self, op, payloads, source=''):
        """Private HTTP/native ingestion only. No secret-bearing RPC action."""
        from .import_totp import parse_import
        if (op.kind != 'totp' or op.state != 'pending' or op.expires <= self.broker.clock()
                or op.revision != self.revision or not self.available() or op.import_candidates):
            raise WriteError('stale or already captured import; start again')
        if source and https_origin(source) != https_origin(op.values['url']):
            raise WriteError('capture site does not match selected vault entry')
        configs = parse_import(payloads, label=op.values['username'])
        if source and len(configs) != 1:
            raise WriteError('browser capture requires one TOTP setup')
        op.import_candidates = configs
        op.import_nonce = secrets.token_urlsafe(32)
        # Store origin only, never a page path/query that may itself carry keys.
        op.import_source = ('https://' + urlsplit(source).netloc) if source else 'Private QR/key import'

    def confirm_totp_import(self, op, choice, nonce, confirmed):
        candidates = op.import_candidates
        if (not candidates or not isinstance(nonce, str) or not op.import_nonce
                or not secrets.compare_digest(nonce, op.import_nonce)
                or type(choice) is not int or not 0 <= choice < len(candidates)):
            return {'ok': False, 'error': 'invalid import selection; start again'}
        if confirmed is not True:
            return {'ok': False, 'error': 'confirm the destination and imported account'}
        # submit_totp rechecks revision, destination, replacement and persistence.
        return self.submit_totp(op, candidates[choice].uri(), True)

    def submit_totp(self, op, setup, confirmed):
        if op.kind != 'totp' or op.state != 'pending' or op.expires <= self.broker.clock():
            return {'ok': False, 'error': 'unknown or expired TOTP setup; start again'}
        # Validation errors allow correction on the same private page, but no
        # submitted value or parser diagnostic is ever reflected to the client.
        try:
            if confirmed is not True:
                raise ValueError
            configuration = parse_setup(setup, label=op.values['username'])
            uri = configuration.uri()
        except Exception:
            return {'ok': False, 'error': 'confirm the account and enter a supported TOTP setup key or URI'}
        op.state = 'failed'
        op.import_candidates = ()
        op.import_nonce = None
        try:
            if op.revision != self.revision or not self.available():
                raise WriteError('stale TOTP setup; search and start again')
            vault = self.broker.vault

            def selected(candidate):
                entries = [e for e in active_entries(candidate) if e.uuid == op.uuid]
                if len(entries) != 1 or metadata(entries[0]) != op.values:
                    raise WriteError('entry changed; search again')
                return entries[0]

            def mutate(candidate):
                entry = selected(candidate)
                if totp_configured(entry) and not op.replace:
                    raise WriteError('TOTP already configured; explicit --replace is required')
                # KDBX/native merge selects versions at second precision.
                # A field assignment and save_history() do not advance mtime.
                # Wait only for ordinary same-second collisions; a future
                # current/history version must not advance the active clock.
                changed_at = _entry_changed_at(entry, self.broker.wall_clock)
                entry.save_history()
                entry.otp = uri
                entry.mtime = changed_at
                # PyKeePass reserves otp as a standard field. Its setter keeps
                # an existing field's protection flag, so force protection for
                # imported/replaced keys, including formerly unprotected OTPs.
                entry._element.find('./String[Key="otp"]/Value').set('Protected', 'True')

            def verify_saved(candidate):
                entry = selected(candidate)
                if (entry.otp != uri
                        or entry._element.find('./String[Key="otp"]/Value').get('Protected') != 'True'):
                    raise WriteError('TOTP encrypted save verification failed; target not replaced')

            self.broker.vault = vault._akdbx_store.commit(vault, mutate, verify_candidate=verify_saved)
            self.invalidate_revision(op)
            op.state = 'saved'
            return {'ok': True, 'state': 'saved'}
        except SaveError as exc:
            op.error = str(exc)
        except WriteError as exc:
            op.error = str(exc)
        except ValueError:
            op.error = 'stale or conflicting TOTP destination; search and start again'
        except Exception:
            op.error = 'TOTP save failed; vault update not confirmed'
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
        self._require_available()
        preflight_error = None
        entry, latest = None, None
        if op.uuid is not None:
            entries = [entry for entry in active_entries(self.broker.vault) if entry.uuid == op.uuid]
            if len(entries) != 1 or metadata(entries[0]) != op.values:
                raise WriteError('entry changed; search again')
            entry = entries[0]
            latest, _ = _entry_write_clock(entry, self.broker.wall_clock)

        def checked_ready():
            nonlocal preflight_error
            if delivery_ready is not None and not delivery_ready():
                return False
            try:
                # Only metadata and the cached entry time are checked at the
                # keyboard boundary; changed key contents are read beforehand.
                if not self.available():
                    raise WriteError('private writes unavailable; check activation, vault/key changes and path safety')
                if entry is not None:
                    _entry_write_clock(entry, self.broker.wall_clock, latest=latest)
            except WriteError as exc:
                preflight_error = str(exc)
                raise
            return True
        if set(request) - {'action', 'handle', 'target_url', 'start_deadline', 'target', 'target_protocol'}:
            raise WriteError('autofill not started: unsupported target request')
        target = request.get('target_url')
        if not isinstance(target, str):
            raise WriteError('verified target URL required')
        target_origin = _generated_origin(target)
        # Same origins as a login fill: the main URL or one exact KP2A_URL*
        # origin of the entry as it is now. A new entry has only its main URL.
        if target_origin not in {_generated_origin(op.values['url']),
                                 *(additional_origins(entry) if entry is not None else ())}:
            raise WriteError('target site mismatch; no password filled')
        # Reuse the existing keyboard preflight/deadline/dispatch boundary.
        # The proxy has only the asserted target origin, so the delivery
        # route also requires the pinned document to have exactly that origin.
        proxy = SimpleNamespace(uuid=secrets.token_hex(16), password=op.password, username='',
                                url=_serialize_origin(target_origin) + '/')
        handle = self.broker._new_handle(proxy)
        response = self.broker._dispatch({'action': 'fill', 'handle': handle, 'mode': 'password', 'start_deadline': request.get('start_deadline'), 'target': request.get('target'), 'target_protocol': request.get('target_protocol')}, delivery_ready=checked_ready)
        if preflight_error is not None and response.get('delivery') != 'uncertain':
            # Forward only our fixed preflight reason, never a backend exception.
            raise WriteError(preflight_error) from None
        if response.get('ok'):
            op.filled.add(mode)
        return response

    def commit_generated(self, request):
        # The fill count is fixed when the write is staged. A commit cannot
        # carry options, so it cannot switch a write to single-field mode.
        if set(request) - {'action', 'write_handle', 'site_accepted'}:
            raise WriteError('commit accepts only a write handle and explicit site acceptance')
        op = self.get(request.get('write_handle'))
        if op is None or op.state != 'pending' or op.password is None:
            raise WriteError('unknown or expired generated password; start again')
        if op.single_field:
            if request.get('site_accepted') is not True or op.filled != set(GENERATED_SINGLE_MODES):
                raise WriteError('the password fill and explicit site acceptance are required')
        elif request.get('site_accepted') is not True or op.filled != set(GENERATED_MODES):
            raise WriteError('both fills and explicit site acceptance are required')
        return self.submit(op, op.password, op.password, True)
