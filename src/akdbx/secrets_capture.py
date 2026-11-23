"""Capture a secret that a website shows once, and deliver it to a fixed sink.

`capture-secret` consumes a single-use DOM read pin (`pin-password-target
--mode read`). The broker reads the pinned element's text itself over its own
CDP connection, or through the paired browser extension (`--route extension`,
sealed in both directions), and saves it as a protected custom field through the verified
encrypted persistence. `deliver-secret` writes such a field only to a sink
that the operator configured at broker start (see `sink_helper`). Responses
are receipts; no value ever crosses RPC, argv, logs or error messages.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import struct
import threading
import unicodedata

from .persistence import SaveError
from .sink_helper import MAX_VALUE, valid_field, PROTOCOL as SINK_PROTOCOL, SinkError, load_config
from .sink_helper import deliver as deliver_direct, sink_digest
from .totp import TotpError, https_origin
from .versions import active_entries
from .writes import (WriteError, _append_entry, _entry_changed_at, _entry_write_clock, allowed_origins, duplicate,
                     group_for, metadata, validate_identity_metadata)

CAPTURE_PROTOCOL = 1
CAPTURE_DELIVERY = 'chromium-dom-read-v1'
SECRET_RECORD = 'akdbx.secret-record'
CAPTURED_FIELDS = 'akdbx.captured-fields'
REFUSED = 'secret capture refused: target missing, expired, changed, hidden, empty, multi-line or not on the entry origin; nothing saved'
HELPER_TIMEOUT = 90
SINK_WAIT = 30


def _helper_errors():
    """The helper's own fixed SinkError texts; any other reply text is withheld."""
    import re
    from . import sink_helper
    with open(sink_helper.__file__, encoding='utf-8') as source:
        return frozenset(re.findall(r"SinkError\('([^'\\]{1,200})'\)", source.read()))


HELPER_ERRORS = _helper_errors()


def capabilities(sinks):
    return dict(secret_capture_protocol=CAPTURE_PROTOCOL, secret_capture_delivery=CAPTURE_DELIVERY,
                secret_sink_protocol=SINK_PROTOCOL, secret_sinks=sorted(sinks))


def valid_value(value):
    """One visible line: no whitespace, control, format or separator characters."""
    return (isinstance(value, str) and 0 < len(value) <= MAX_VALUE
            and not any(c.isspace() or unicodedata.category(c)[0] in 'CZ' for c in value))


def is_secret_record(entry):
    """A record created by capture-secret: it has no site password to fill."""
    getter = getattr(entry, 'get_custom_property', None)
    element = getattr(entry, '_element', None)
    return bool(getter and getter(SECRET_RECORD) is not None or element is not None
                and element.find('./String[Key="' + SECRET_RECORD + '"]') is not None)


def captured_fields(entry):
    """Names of captured fields that exist; a protected marker is never read."""
    getter = getattr(entry, 'get_custom_property', None)
    try:
        if getter is None or entry.is_custom_property_protected(CAPTURED_FIELDS):
            return []
        raw = getter(CAPTURED_FIELDS)
        names = raw.split(',') if isinstance(raw, str) else []
        return sorted({name for name in names if valid_field(name) and getter(name) is not None
                       and entry.is_custom_property_protected(name)})
    except Exception:
        return []


def _protected_marker(entry):
    try:
        return bool(entry.is_custom_property_protected(CAPTURED_FIELDS))
    except Exception:
        return True


def _protected_value(entry, field):
    try:
        if field not in captured_fields(entry) or not entry.is_custom_property_protected(field):
            return None
        value = entry.get_custom_property(field)
    except Exception:
        return None
    return value if valid_value(value) else None


class SecretCaptures:
    """Runs under the broker's vault lock, like the other writes."""

    def __init__(self, broker, sinks_path=None):
        self.broker = broker
        if sinks_path is not None and os.name == 'nt':
            raise SinkError('secret sinks are available only on Linux in this release')
        self.config = (load_config(os.fspath(sinks_path), {0, os.getuid()}) if sinks_path is not None
                       else dict(sinks={}, helper_socket=None, broker_uids=set()))
        # One delivery per sink at a time, from reading the field to the end of
        # the restart, so an older value cannot overtake a newer delivery.
        # Keyed by destination path, so two sink names for one file share it.
        self._sink_locks = {sink['path']: threading.Lock() for sink in self.config['sinks'].values()}

    def capabilities(self):
        return capabilities(self.config['sinks'])

    # ---- capture -------------------------------------------------------
    def capture(self, request, ready):
        broker = self.broker
        pin = None
        try:
            try:
                # An extension read pin, else a CDP one; either way the token is used up.
                token = request.get('target')
                pin = broker.extension.take(token, 'read') if hasattr(broker, 'extension') else None
                if pin is None:
                    pin = broker.passwords.consume(token)
            except Exception:
                return dict(ok=False, error=REFUSED)
            from .extension_route import ExtensionPin, CAPTURE_DELIVERY as EXTENSION_CAPTURE_DELIVERY
            extension = isinstance(pin, ExtensionPin)
            if pin.mode != 'read':
                return dict(ok=False, error=REFUSED)
            create = request.get('create') is True
            allowed = {'action', 'capture_protocol', 'target', 'field', 'metadata', 'start_deadline'}
            allowed |= {'create'} if create else {'handle', 'replace'}
            if (set(request) - allowed or not {'action', 'capture_protocol', 'target', 'field', 'metadata'} <= set(request)
                    or type(request.get('capture_protocol')) is not int or request['capture_protocol'] != CAPTURE_PROTOCOL
                    or 'replace' in request and type(request['replace']) is not bool):
                return dict(ok=False, error='invalid secret capture request; nothing saved')
            field = request.get('field')
            if not valid_field(field):
                return dict(ok=False, error='invalid field name; use letters, digits and underscores, not a standard or akdbx field')
            deadline = request.get('start_deadline')
            if type(deadline) not in {int, float} or not broker.clock() < deadline <= broker.clock() + 4:
                return dict(ok=False, error='secret capture not started: request expired; nothing saved')
            values = request.get('metadata')
            try:
                if create:
                    validate_identity_metadata(values, 'secret record')
                    origins = {https_origin(values['url'])}
                    entry = None
                else:
                    try:
                        entry = broker._resolve(request.get('handle'))
                    except ValueError:
                        raise WriteError('unknown or expired handle; search again') from None
                    from .cards import is_card
                    from .identities import is_identity
                    if is_card(entry) or is_identity(entry):
                        raise WriteError('card and identity records cannot hold captured secrets')
                    if not isinstance(values, dict) or metadata(entry) != values:
                        raise WriteError('entry metadata mismatch; search again')
                    origins = allowed_origins(entry)
                    try:
                        exists = entry.get_custom_property(field) is not None
                    except Exception:
                        exists = True
                    if exists and request.get('replace') is not True:
                        raise WriteError('entry already has this field; pass --replace to replace it')
                    if _protected_marker(entry):
                        raise WriteError('entry has a protected akdbx.captured-fields value; not changed')
                    _entry_write_clock(entry, broker.wall_clock)
                broker.writes._require_available()
                vault = broker.vault
                if create:
                    group_for(vault, values['group'])
                    if duplicate(vault, values):
                        raise WriteError('duplicate site/account; select an existing entry')
                elif sum(e.uuid == entry.uuid for e in active_entries(vault)) != 1:
                    raise WriteError('entry metadata mismatch; search again')
            except (WriteError, SaveError) as exc:
                return dict(ok=False, error=str(exc))
            except TotpError:
                return dict(ok=False, error='invalid secret record metadata; nothing saved')
            started = lambda: ready() and broker.clock() < deadline
            try:
                value = (broker.extension if extension else broker.passwords).read(pin, origins, started, deadline)
            except Exception:
                return dict(ok=False, error=REFUSED)
            if not valid_value(value):
                return dict(ok=False, error=REFUSED)
            return self._save(entry, values, field, value, create,
                              EXTENSION_CAPTURE_DELIVERY if extension else CAPTURE_DELIVERY)
        finally:
            if pin is not None:
                try:
                    pin.close()
                except Exception:
                    pass

    def _save(self, entry, values, field, value, create, delivery=CAPTURE_DELIVERY):
        broker = self.broker
        uuid = None if create else entry.uuid
        password = None if create else entry.password

        def selected(candidate):
            if create:
                found = [e for e in active_entries(candidate) if e.get_custom_property(SECRET_RECORD) is not None
                         and metadata(e) == values]
            else:
                found = [e for e in active_entries(candidate) if e.uuid == uuid]
            if len(found) != 1 or metadata(found[0]) != values:
                raise WriteError('entry changed; search again')
            return found[0]

        def mutate(candidate):
            if create:
                group = group_for(candidate, values['group'])
                if duplicate(candidate, values):
                    raise WriteError('duplicate site/account; select an existing entry')
                target = _append_entry(candidate, group, values, '',
                                       notes='Captured secret record. It has no site password.')
                target.set_custom_property(SECRET_RECORD, 'v1')
            else:
                target = selected(candidate)
                if _protected_marker(target):
                    raise WriteError('entry has a protected akdbx.captured-fields value; not changed')
                changed_at = _entry_changed_at(target, broker.wall_clock)
                target.save_history()
                target.mtime = changed_at
            names = sorted(set(captured_fields(target)) | {field})
            target.set_custom_property(field, value, protect=True)
            target.set_custom_property(CAPTURED_FIELDS, ','.join(names))

        def verify_saved(candidate):
            target = selected(candidate)
            if (target.get_custom_property(field) != value or not target.is_custom_property_protected(field)
                    or field not in captured_fields(target) or not create and target.password != password):
                raise WriteError('secret save verification failed; vault update not confirmed')

        try:
            broker.vault = broker.vault._akdbx_store.commit(broker.vault, mutate, verify_candidate=verify_saved)
        except (SaveError, WriteError) as exc:
            return dict(ok=False, error=str(exc))
        except Exception:
            return dict(ok=False, error='secret save failed; vault update not confirmed')
        finally:
            value = password = None
        broker.writes.invalidate_revision()
        saved = selected(broker.vault)
        length = len(saved.get_custom_property(field))
        return dict(ok=True, state='saved', created=create, field=field, length=length,
                    metadata=dict(values), capture_delivery=delivery)

    # ---- delivery ------------------------------------------------------
    def deliver(self, request):
        """Read the field under the vault lock, then write outside it."""
        broker = self.broker
        if (set(request) != {'action', 'sink_protocol', 'sink', 'field', 'handle'}
                or type(request.get('sink_protocol')) is not int or request['sink_protocol'] != SINK_PROTOCOL):
            return dict(ok=False, error='invalid secret delivery request; nothing written')
        name = request.get('sink')
        sink = self.config['sinks'].get(name) if isinstance(name, str) else None
        lock = self._sink_locks.setdefault(sink['path'], threading.Lock()) if sink is not None else None
        if lock is not None and not lock.acquire(timeout=SINK_WAIT):
            with broker._vault_lock:
                try:
                    broker._resolve(request.get('handle'))  # One use, even on refusal.
                except ValueError:
                    pass
            return dict(ok=False, error='sink busy with another delivery; nothing written')
        try:
            return self._deliver(request, sink)
        finally:
            if lock is not None:
                lock.release()

    def _deliver(self, request, sink):
        broker = self.broker
        with broker._vault_lock:
            try:
                entry = broker._resolve(request.get('handle'))  # One use, even on refusal.
            except ValueError:
                return dict(ok=False, error='unknown or expired handle; search again')
            if sink is None:
                return dict(ok=False, error='unknown sink; only sinks configured at broker start are allowed; nothing written')
            if request.get('field') != sink['field']:
                return dict(ok=False, error='field does not match the sink; nothing written')
            try:
                origin_ok = https_origin(sink['entry_origin']) in allowed_origins(entry)
            except Exception:
                origin_ok = False
            if not origin_ok:
                return dict(ok=False, error='entry is not on the sink origin; nothing written')
            value = _protected_value(entry, sink['field'])
        if value is None:
            return dict(ok=False, error='entry has no valid captured protected field of this name; nothing written')
        try:
            result = (deliver_direct(sink, value) if sink['writer'] == 'direct'
                      else self._helper(sink, value))
        except SinkError as exc:
            return dict(ok=False, error=str(exc))
        except Exception:
            return dict(ok=False, error='secret delivery failed; check the sink before any retry')
        finally:
            value = None
        return dict(ok=True, state='delivered', sink=sink['name'], field=sink['field'], restarted=result['restarted'])

    def _helper(self, sink, value):
        """Send the value to the root-owned helper only after proving the peer is root."""
        path = self.config['helper_socket']
        info = os.stat(path, follow_symlinks=False)
        parent = os.stat(os.path.dirname(path), follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise SinkError('sink helper socket is not root-owned')
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(5)
            connection.connect(path)
            size = struct.calcsize('3i')
            if struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))[1] != 0:
                raise SinkError('sink helper is not root')
            connection.sendall(json.dumps(dict(sink_protocol=SINK_PROTOCOL, sink=sink['name'], field=sink['field'],
                                               sink_digest=sink_digest(sink), value=value)).encode('utf-8') + b'\n')
            connection.shutdown(socket.SHUT_WR)
            connection.settimeout(HELPER_TIMEOUT)
            data = b''
            while len(data) <= 4096:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            connection.close()
        try:
            reply = json.loads(data.decode('utf-8'))
        except (UnicodeError, ValueError):
            raise SinkError('sink helper reply unconfirmed; check the sink before any retry') from None
        if not isinstance(reply, dict):
            raise SinkError('sink helper reply unconfirmed; check the sink before any retry')
        if set(reply) == {'ok', 'error'} and reply['ok'] is False:
            raise SinkError('sink helper refused: ' + reply['error'] if isinstance(reply['error'], str) and reply['error'] in HELPER_ERRORS
                            else 'sink helper refused; nothing confirmed')
        if set(reply) != {'ok', 'restarted'} or reply['ok'] is not True or reply['restarted'] not in (True, False, None):
            raise SinkError('sink helper reply unconfirmed; check the sink before any retry')
        return dict(restarted=reply['restarted'])
