"""Automatic authenticator enrollment: capture a site's TOTP setup key directly.

`capture-totp` consumes a single-use DOM read pin (`pin-password-target --mode
read`, CDP or extension route) on the element where an enrollment page shows
its setup key or otpauth URI. The broker reads the element itself, checks that
the page is on the selected entry's origin, parses the value as a supported TOTP
setup, and saves it as the entry's *pending* authenticator: a protected custom
field beside the entry's `otp`. The entry's existing authenticator is never
changed by a capture, so a failed or repeated enrollment cannot destroy it.

A QR read pin (`pin-password-target --mode read --qr`, `capture-totp --qr`)
decodes the setup QR code that the page shows in an `<img>`, `<canvas>` or
inline `<svg>` instead, in the browser itself (the vendored jsQR in the pin's
isolated world or the extension's content script). It must hold exactly one
code with an `otpauth://totp/` URI; the image must come from the page's own
origin. No pixel leaves the browser, and the decoded value goes only to the
broker, which saves it as for a text key.

`fill-totp --pending` fills the code of the pending key, for the site's
"enter the code from your app" check. `commit-totp` then moves the pending key
into the standard `otp` field after the caller has seen the site accept it
(an existing `otp` needs an explicit replace; its old value stays in the
entry's encrypted history), or discards it. No key or code ever crosses RPC,
argv, logs or error messages; every response is a fixed receipt.
"""
from __future__ import annotations

from .persistence import SaveError
from .totp import TotpError, configured as totp_configured, parse_setup
from .versions import active_entries
from .writes import WriteError, _entry_changed_at, _entry_write_clock, allowed_origins, metadata, validate_metadata

PROTOCOL = 1
# capture-totp --qr: the read pin decodes a QR code (read_kind "qr"); it must hold an otpauth://totp/ URI.
QR_PROTOCOL = 1
PENDING_FIELD = 'akdbx.pending-otp'
REFUSED = ('authenticator capture refused: target missing, expired, changed, hidden, not a supported TOTP setup key '
           'or URI, or not on the entry origin; nothing saved')
# A QR pin also refuses for a cross-origin or tainted image, no code, two codes or a non-TOTP code. The
# message names them all at once: it never tells which check failed.
QR_REFUSED = ('authenticator QR capture refused: target missing, expired, changed, hidden, cross-origin, not exactly '
              'one QR code, not an otpauth TOTP URI, or not on the entry origin; nothing saved')
INVALID = 'invalid authenticator capture request; nothing saved'
# The CLI's refusal before it sends a QR request to a broker without QR capture.
OLD_BROKER = 'broker lacks authenticator QR capture protocol 1 (totp_qr_capture_protocol); update the broker'


def capabilities():
    return dict(totp_capture_protocol=PROTOCOL, totp_qr_capture_protocol=QR_PROTOCOL)


def pending(entry):
    """Whether the entry has a pending captured authenticator (presence only)."""
    element = getattr(entry, '_element', None)
    if element is not None:
        return element.find('./String[Key="' + PENDING_FIELD + '"]') is not None
    getter = getattr(entry, 'get_custom_property', None)
    try:
        return bool(getter and getter(PENDING_FIELD) is not None)
    except Exception:
        return False


def _pending_uri(entry):
    """The pending key's normalized URI, or None if absent, unprotected or malformed."""
    try:
        if not pending(entry) or not entry.is_custom_property_protected(PENDING_FIELD):
            return None
        value = entry.get_custom_property(PENDING_FIELD)
        if not isinstance(value, str) or not value.startswith('otpauth://totp/'):
            return None
        # Only a value this broker wrote: the normalized URI of a valid setup.
        return value if parse_setup(value).uri() == value else None
    except Exception:
        return None


def read_pending(entry):
    """The pending configuration for `fill-totp --pending`; fixed errors only."""
    uri = _pending_uri(entry)
    if uri is None:
        raise TotpError('no pending captured authenticator on this entry; capture it first')
    return parse_setup(uri)


def _otp_state(entry):
    """The exact current otp element text and protection, to prove a capture left it alone."""
    element = entry._element.find('./String[Key="otp"]/Value')
    return None if element is None else (element.text, element.get('Protected'))


class TotpCaptures:
    """Runs under the broker's vault lock, like the other writes."""

    def __init__(self, broker):
        self.broker = broker

    def capabilities(self):
        return capabilities()

    def _entry(self, request):
        """The selected entry, checked against the exact metadata the caller saw."""
        broker = self.broker
        try:
            entry = broker._resolve(request.get('handle'))
        except ValueError:
            raise WriteError('unknown or expired handle; search again') from None
        from .cards import is_card
        from .identities import is_identity
        if is_card(entry) or is_identity(entry):
            raise WriteError('card and identity records cannot hold an authenticator')
        values = request.get('metadata')
        if not isinstance(values, dict) or metadata(entry) != values:
            raise WriteError('entry metadata mismatch; search again')
        # As setup-totp: a title, an account (the key's label) and a site URL.
        validate_metadata(values)
        _entry_write_clock(entry, broker.wall_clock)
        broker.writes._require_available()
        if sum(e.uuid == entry.uuid for e in active_entries(broker.vault)) != 1:
            raise WriteError('entry metadata mismatch; search again')
        return entry, dict(values)

    def _commit(self, entry, values, mutate, verify):
        broker = self.broker
        uuid = entry.uuid

        def selected(candidate):
            found = [e for e in active_entries(candidate) if e.uuid == uuid]
            if len(found) != 1 or metadata(found[0]) != values:
                raise WriteError('entry changed; search again')
            return found[0]

        password = entry.password
        broker.vault = broker.vault._akdbx_store.commit(
            broker.vault, lambda candidate: mutate(selected(candidate)),
            verify_candidate=lambda candidate: verify(selected(candidate), password))
        broker.writes.invalidate_revision()

    # ---- capture -------------------------------------------------------
    def capture(self, request, ready):
        broker = self.broker
        pin = None
        try:
            try:
                # Spend the pin once, including a native read pin refused for lack of a verified origin.
                token = request.get('target')
                if hasattr(broker, 'native'):
                    pin = broker.native.take(token, 'read')
                    if pin is not None:
                        return dict(ok=False, error='authenticator capture refused: native controls cannot verify '
                                                    'the site origin; nothing saved')
                pin = broker.android.take(token) if hasattr(broker, 'android') else None
                if pin is None:
                    pin = broker.extension.take(token, 'read') if hasattr(broker, 'extension') else None
                if pin is None:
                    pin = broker.passwords.consume(token)
            except Exception:
                return dict(ok=False, error=QR_REFUSED if request.get('read_kind') == 'qr' else REFUSED)
            from .secrets_capture import CAPTURE_DELIVERY as CDP_DELIVERY
            from .extension_route import ExtensionPin, CAPTURE_DELIVERY as EXTENSION_DELIVERY
            from .android_route import AndroidPin, READ_DELIVERY as ANDROID_READ_DELIVERY
            android = isinstance(pin, AndroidPin)
            extension = isinstance(pin, ExtensionPin)
            qr = request.get('read_kind') == 'qr'
            refused = QR_REFUSED if qr else REFUSED
            if pin.mode != 'read':
                return dict(ok=False, error=refused)
            if (set(request) - {'read_kind'} != {'action', 'totp_capture_protocol', 'target', 'handle', 'metadata', 'start_deadline'}
                    or 'read_kind' in request and not qr
                    or type(request.get('totp_capture_protocol')) is not int or request['totp_capture_protocol'] != PROTOCOL):
                return dict(ok=False, error=INVALID)
            # A QR pin only with --qr, and --qr only with a QR pin: the pin and the request agree on what was read.
            if getattr(pin, 'read_kind', 'text') != ('qr' if qr else 'text'):
                return dict(ok=False, error=refused)
            deadline = request.get('start_deadline')
            if type(deadline) not in {int, float} or not broker.clock() < deadline <= broker.clock() + 4:
                return dict(ok=False, error='authenticator capture not started: request expired; nothing saved')
            try:
                entry, values = self._entry(request)
                origins = allowed_origins(entry)
            except (WriteError, SaveError) as exc:
                return dict(ok=False, error=str(exc))
            started = lambda: ready() and broker.clock() < deadline
            try:
                value = (broker.android if android else broker.extension if extension else broker.passwords).read(pin, origins, started, deadline)
                if qr and not (isinstance(value, str) and value.startswith('otpauth:')):
                    raise TotpError('a QR code must hold an otpauth URI')  # Not a bare key or other text.
                uri = parse_setup(value, label=values['username']).uri()
                if parse_setup(uri).uri() != uri:
                    raise TotpError('unsupported label')  # The save check reads it back the same way.
            except Exception:
                return dict(ok=False, error=refused)
            finally:
                value = None
            had_otp = totp_configured(entry)
            otp_before = _otp_state(entry)

            def mutate(target):
                changed_at = _entry_changed_at(target, broker.wall_clock)
                target.save_history()
                target.set_custom_property(PENDING_FIELD, uri, protect=True)
                target.mtime = changed_at

            def verify(target, password):
                if (_pending_uri(target) != uri or _otp_state(target) != otp_before
                        or target.password != password):
                    raise WriteError('authenticator save verification failed; vault update not confirmed')

            try:
                self._commit(entry, values, mutate, verify)
            except (SaveError, WriteError) as exc:
                return dict(ok=False, error=str(exc))
            except Exception:
                return dict(ok=False, error='authenticator save failed; vault update not confirmed')
            finally:
                uri = None
            return dict(ok=True, state='pending', totp_configured=had_otp, metadata=values,
                        capture_delivery=ANDROID_READ_DELIVERY if android else EXTENSION_DELIVERY if extension else CDP_DELIVERY)
        finally:
            if pin is not None:
                try:
                    pin.close()
                except Exception:
                    pass

    # ---- commit or discard ---------------------------------------------
    def commit(self, request):
        """Move the pending key into `otp` (site accepted it), or discard it."""
        allowed = {'action', 'totp_capture_protocol', 'handle', 'metadata', 'decision', 'replace'}
        if (set(request) - allowed or not allowed - {'replace'} <= set(request)
                or type(request.get('totp_capture_protocol')) is not int or request['totp_capture_protocol'] != PROTOCOL
                or request.get('decision') not in {'site-accepted', 'discard'}
                or 'replace' in request and (type(request['replace']) is not bool or request['decision'] != 'site-accepted')):
            return dict(ok=False, error='invalid authenticator commit request; nothing changed')
        try:
            entry, values = self._entry(request)
        except (WriteError, SaveError) as exc:
            return dict(ok=False, error=str(exc))
        uri = _pending_uri(entry)
        if uri is None:
            return dict(ok=False, error='no pending captured authenticator on this entry; nothing changed')
        accept = request['decision'] == 'site-accepted'
        replaced = totp_configured(entry)
        if accept and replaced and request.get('replace') is not True:
            return dict(ok=False, error='TOTP already configured; explicit --replace is required; pending key kept')
        otp_before = _otp_state(entry)

        def mutate(target):
            if _pending_uri(target) != uri or _otp_state(target) != otp_before:
                raise WriteError('entry changed; search again')
            changed_at = _entry_changed_at(target, self.broker.wall_clock)
            target.save_history()
            if accept:
                target.otp = uri
                # PyKeePass keeps an existing field's protection flag: force it.
                target._element.find('./String[Key="otp"]/Value').set('Protected', 'True')
            target.delete_custom_property(PENDING_FIELD)
            target.mtime = changed_at

        def verify(target, password):
            otp_ok = (target.otp == uri and _otp_state(target) == (uri, 'True')) if accept else _otp_state(target) == otp_before
            if pending(target) or not otp_ok or target.password != password:
                raise WriteError('authenticator save verification failed; vault update not confirmed')

        try:
            self._commit(entry, values, mutate, verify)
        except (SaveError, WriteError) as exc:
            return dict(ok=False, error=str(exc))
        except Exception:
            return dict(ok=False, error='authenticator save failed; vault update not confirmed')
        finally:
            uri = None
        if accept:
            return dict(ok=True, state='saved', replaced=replaced, metadata=values)
        return dict(ok=True, state='discarded', metadata=values)
