from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import select
import socket
import stat
import time
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Callable, Protocol

from .target import TargetPins, TargetError, DeliveryError, DELIVERY, capabilities as target_capabilities, failure as target_failure
from .writes import (WriteManager, WriteError, sso_capabilities, passwordless_capabilities, passwordless_identity,
                     additional_origins, additional_urls, additional_urls_capabilities, allowed_origins,
                     secret_save_capabilities)
from .merge import MergeError, create_manager as create_merge_manager
from .persistence import SaveError
from .versions import active_entries
from .totp import (MIN_VALIDITY, TotpError, capabilities as totp_capabilities,
                   configured as totp_configured, read_configuration, code_at, https_origin)
from .browser_password import BrowserPasswords, PasswordPin, DELIVERY as PASSWORD_DELIVERY
from .password_frames import PROTOCOL as PASSWORD_FRAME_PROTOCOL, POLICY as PASSWORD_FRAME_POLICY
from . import __version__
from .notifications import UnlockNotifications, capabilities as notification_capabilities
from .card_notifications import CardSaveNotifications, capabilities as card_notification_capabilities
from .protocol import ProtocolError, receive_message, send_message
from .cards import CardManager, is_card
from .browser_card import BrowserCards
from .browser_identity import BrowserIdentities
from .extension_route import (ExtensionHub, ExtensionError, ExtensionPin, RoutedTargets,
                              DELIVERY as EXTENSION_DELIVERY)
from .identities import COMMANDS as IDENTITY_COMMANDS, IdentityManager, is_identity
from .secrets_capture import SecretCaptures, captured_fields, is_secret_record
from .runtime import (
    acquire_lifecycle_lock,
    anchored_socket_path,
    prepare_private_runtime_directory,
    remove_stale_socket,
    unlink_socket_if_same,
)


CONNECTION_TIMEOUT = 1.0
MAX_RPC_WORKERS = 16
FILL_START_TIMEOUT = 4.0
MAX_CREDENTIAL_CHARACTERS = 64 * 1024
MAX_CREDENTIAL_BYTES = 64 * 1024
MAX_METADATA_BYTES = 4 * 1024
MAX_SEARCH_RESPONSE = 48 * 1024
MAX_OUTSTANDING_HANDLES = 1024
# Failed master-password attempts allowed per unlock link, in total. The
# failure that reaches it blocks the link; only new-unlock-link replaces it.
UNLOCK_LINK_MAX_FAILURES = 3
UNLOCK_LINK_PROTOCOL = 1
CONNECTION_ERROR = {"ok": False, "error": "request failed"}
DOM_PINS = (PasswordPin, ExtensionPin)


class EntryLike(Protocol):
    uuid: object
    title: str | None
    username: str | None
    password: str | None
    url: str | None
    path: list[str]


class VaultLike(Protocol):
    entries: list[EntryLike]


class Typer(Protocol):
    def capture(self, pid: int, window: int) -> object: ...
    def deliver(self, identity: object, steps: list[str | None], ready: Callable[[], bool], *, guard: Callable[[], bool] | None = None) -> None: ...


@dataclass
class Handle:
    entry: EntryLike
    expires_at: float


class Broker:
    """Transforms vault entries into secret-free responses and performs local fills."""

    def __init__(
        self,
        vault: VaultLike | None,
        typer: Typer,
        *,
        handle_ttl: float = 300,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        card_browser_profile: Path | None = None,
        notification_state_path=None,
        password_browser_profile=None,
        secret_sinks_path=None,
        default_fill_route='cdp',
    ) -> None:
        self.vault = vault
        self.typer = typer
        self.targets = TargetPins(typer, clock)
        self.passwords = BrowserPasswords(password_browser_profile, clock=clock)
        self.handle_ttl = handle_ttl
        self.clock = clock
        self.wall_clock = wall_clock
        self._key = secrets.token_bytes(32)
        self._handles: dict[str, Handle] = {}
        self._state_lock = threading.Lock()
        self._keyboard_lock = threading.Lock()
        self._vault_lock = threading.RLock()
        self.writes = WriteManager(self)
        self.cards = CardManager(self)
        # The extension route sits next to CDP; the operator picks the default.
        self.extension = ExtensionHub(self, default_route=default_fill_route)
        self.card_targets = RoutedTargets(BrowserCards(card_browser_profile, clock=clock), self.extension, 'card')
        self.identity_targets = RoutedTargets(
            BrowserIdentities(password_browser_profile or card_browser_profile, clock=clock), self.extension, 'identity')
        self.identities = IdentityManager(self)
        self.merges = create_merge_manager(self)
        self.secrets = SecretCaptures(self, secret_sinks_path)
        self.unlock_url: str | None = None
        # The private page's UnlockState, when this broker serves one.
        self.unlock_link = None
        self.unlock_notifications = UnlockNotifications(state_path=notification_state_path)
        self.card_save_notifications = CardSaveNotifications(
            expire_handler=self._expire_card_save, clock=clock,
            state_path=(Path(str(notification_state_path) + '.card-saves')
                        if notification_state_path is not None else None))

    def _expire_card_save(self, handle):
        with self._vault_lock:
            op = self.writes.operations.get(handle)
            state = op.state if op is not None and op.state != 'pending' else 'expired'
            self.card_save_notifications.publish_save(handle, state)

    @property
    def locked(self) -> bool:
        with self._state_lock:
            return self.vault is None

    @property
    def unlock_blocked(self) -> bool:
        """True after the current unlock link used all its failed attempts."""
        link = self.unlock_link
        return bool(link is not None and link.blocked)

    def unlock_fields(self) -> dict:
        """What a locked response may say about unlocking: never a blocked link."""
        if self.unlock_blocked:
            return {"unlock_blocked": True}
        return {"unlock_url": self.unlock_url} if self.unlock_url else {}

    def _blocked_status(self) -> dict:
        """Status of a blocked link: no URL, but its non-secret origin.

        The CLI checks the origin against its configuration before it asks
        for a new link, so a wrong origin leaves the broker blocked.
        """
        origin = getattr(self.unlock_link, "origin", None)
        return {"unlock_blocked": True, **({"unlock_origin": origin} if isinstance(origin, str) else {})}

    def _new_unlock_link(self, request: dict) -> dict:
        # The broker cannot verify the user. The agent must first ask the user
        # whether the failed attempts were theirs and whether they want a link.
        if set(request) != {"action", "user_confirmed"} or request["user_confirmed"] is not True:
            return {"ok": False, "error": "new unlock link needs user_confirmed: true after the user "
                                          "confirms; no link created"}
        link = self.unlock_link
        if link is None:
            return {"ok": False, "error": "this broker has no private unlock page; no link created"}
        url = link.new_link()
        if url is None:
            return {"ok": False, "error": "the current unlock link is not blocked; no link created"}
        return {"ok": True, "unlock_url": url, "locked": self.locked}

    def unlock(self, vault: VaultLike) -> bool:
        with self._state_lock:
            if self.vault is not None:
                return False
            self.vault = vault
            self.unlock_notifications.publish()
        self.extension.refresh()
        return True

    def _new_handle(self, entry: EntryLike) -> str:
        nonce = secrets.token_bytes(16)
        tag = hmac.new(self._key, nonce + str(entry.uuid).encode(), hashlib.sha256).digest()[:16]
        handle = (nonce + tag).hex()
        now = self.clock()
        with self._state_lock:
            self._prune_expired_handles(now)
            # dicts retain insertion order, so this evicts the oldest issued
            # live authorization rather than allowing retained state to grow.
            while len(self._handles) >= MAX_OUTSTANDING_HANDLES:
                self._handles.pop(next(iter(self._handles)))
            self._handles[handle] = Handle(entry, now + self.handle_ttl)
        return handle

    def _prune_expired_handles(self, now: float) -> None:
        """Remove expired handles while the caller holds ``_state_lock``."""
        for handle, item in list(self._handles.items()):
            if item.expires_at <= now:
                self._handles.pop(handle, None)

    def _resolve(self, handle: object) -> EntryLike:
        if not isinstance(handle, str):
            raise ValueError("invalid handle")
        now = self.clock()
        with self._state_lock:
            self._prune_expired_handles(now)
            item = self._handles.pop(handle, None)  # one use, successful or not
        if item is None:
            raise ValueError("unknown or expired handle; search again")
        return item.entry

    @staticmethod
    def _validate_credential_text(*values: str) -> None:
        """Bound preflight and reject text a keyboard backend may interpret as controls."""
        for value in values:
            if not isinstance(value, str):
                raise ValueError("invalid credential text")
            # Bound both the Unicode scan and the eventual keyboard operation.
            # The byte cap also catches compact character counts with unusually
            # large UTF-8 representations.
            if (
                len(value) > MAX_CREDENTIAL_CHARACTERS
                or len(value.encode("utf-8")) > MAX_CREDENTIAL_BYTES
            ):
                raise ValueError("credential text exceeds delivery budget")
            if any(unicodedata.category(character) == "Cc" for character in value):
                raise ValueError("unsafe credential text")

    def dispatch(self, request: dict, *, delivery_ready=None) -> dict:
        action = request.get("action")
        if action == 'subscribe-card-save':
            with self._vault_lock:
                handle = request.get('write_handle')
                op = self.writes.get(handle)
                if op is None or op.kind != 'card':
                    return dict(ok=False, error='unknown or expired card write')
                state = self.writes.status(handle)['state']
                return self.card_save_notifications.subscribe_save(request, state=state, expires=op.expires)
        if action in {'card-save-subscription-status', 'unsubscribe-card-save'}:
            return self.card_save_notifications.status(
                request.get('subscription_id'), cancel=action == 'unsubscribe-card-save')
        if action == "new-unlock-link":
            return self._new_unlock_link(request)
        if action == "subscribe-unlock":
            # Share unlock's lock so registration cannot miss a racing unlock
            # or a racing block: a block either reaches this subscription as
            # an event or is reported in this receipt.
            with self._state_lock:
                receipt = self.unlock_notifications.subscribe(request, unlocked=self.vault is not None)
                if receipt.get("ok") and self.vault is None and self.unlock_blocked:
                    receipt["unlock_blocked"] = True
                return receipt
        if action in {"unlock-subscription-status", "unsubscribe-unlock"}:
            return self.unlock_notifications.status(
                request.get("subscription_id"), cancel=action == "unsubscribe-unlock",
            )
        if action in {'merge', 'admit', 'merge-status'}:
            if not self._vault_lock.acquire(blocking=False):
                return {'ok': False, 'error': 'vault busy; merge not started; check merge-status before retry'}
            try:
                if action == 'merge-status':
                    return self.merges.status(request.get('operation_id'))
                return self._dispatch(request, delivery_ready=delivery_ready)
            except (MergeError, SaveError) as exc:
                return {'ok': False, 'error': str(exc)}
            except Exception:
                return {'ok': False, 'error': 'merge operation failed'}
            finally:
                self._vault_lock.release()
        if action in {'fill', 'fill-generated', 'fill-totp', 'fill-card', 'fill-identity', 'capture-secret'} and delivery_ready is None and 'start_deadline' not in request:
            request = {**request, 'start_deadline': self.clock() + FILL_START_TIMEOUT}
        # Search and write operations observe a consistent vault/revision.
        if action in {"pin-target", "fill", "fill-totp", "setup-totp", "search", "create-sso-entry", "create-passwordless-entry", "create-entry", "update-password", "generate-password", "generate-entry", "write-status", "cancel-write", "commit-password", "fill-generated", "add-url", "remove-url", "save-secret", "capture-secret", "create-card", "update-card", "search-cards", "pin-card-target", "fill-card"} | IDENTITY_COMMANDS:
            with self._vault_lock:
                return self._dispatch(request, delivery_ready=delivery_ready)
        return self._dispatch(request, delivery_ready=delivery_ready)

    def _dispatch(
        self,
        request: dict,
        *,
        delivery_ready: Callable[[], bool] | None = None,
    ) -> dict:
        """Handle capabilities and authorized vault, target, and write actions."""
        internal_dispatch = delivery_ready is None
        if delivery_ready is None:
            delivery_ready = lambda: True
        action = request.get("action")
        if action == "ping":
            return {"ok": True, "version": __version__, **self.extension.capabilities(), **self.card_targets.capabilities(), **self.identity_targets.capabilities(), **self.merges.capabilities(), **sso_capabilities(), **passwordless_capabilities(), **additional_urls_capabilities(), **secret_save_capabilities(), **target_capabilities(), **totp_capabilities(), **notification_capabilities(), **card_notification_capabilities(), **self.secrets.capabilities(), "password_fill_protocol": 1, "password_purpose_protocol": 1, "password_autocomplete_off_protocol": 1, "password_frame_protocol": PASSWORD_FRAME_PROTOCOL, "password_frame_policy": PASSWORD_FRAME_POLICY, "password_fill_delivery": PASSWORD_DELIVERY, "password_browser_configured": self.passwords.profile is not None, "generated_entry_protocol": 1, "writes_available": self.writes.available(refresh_inputs=True), "recovery_required": bool(getattr(getattr(self.vault, "_akdbx_store", None), "recovery_required", False)), "unlock_link_protocol": UNLOCK_LINK_PROTOCOL, "unlock_link_max_failures": UNLOCK_LINK_MAX_FAILURES, "locked": self.locked, **(self._blocked_status() if self.unlock_blocked else self.unlock_fields() if self.locked else {})}
        if action == 'list-password-frames':
            # Read-only browser discovery: no vault access, credential or pin.
            try:
                route = request.get('route', self.extension.default_route)
                if route == 'extension':
                    return self.extension.frames({**request, 'route': 'extension'})
                if route != 'cdp':
                    raise TargetError()
                return self.passwords.frames({k: v for k, v in request.items() if k != 'route'})
            except Exception:
                return {'ok': False, 'error': 'frame list unavailable: page missing, ambiguous, changed or unsupported'}
        if self.locked:
            return {"ok": False, "error": "vault locked", **self.unlock_fields()}
        if getattr(getattr(self.vault, "_akdbx_store", None), "recovery_required", False):
            return {"ok": False, "error": "save outcome uncertain; restart and unlock"}
        if action == 'pin-password-target':
            try:
                route = request.get('route', self.extension.default_route)
                if route == 'extension' and request.get('mode') != 'read':
                    return self.extension.pin_password({**request, 'route': 'extension'})
                if 'route' in request and request['route'] != 'cdp':
                    raise TargetError()  # Read pins (secret capture) stay on CDP.
                return self.passwords.pin({k: v for k, v in request.items() if k != 'route'})
            except Exception:
                return target_failure()
        if action == 'pin-target':
            try:
                return self.targets.pin(request)
            except Exception:
                return target_failure()
        if action == 'capture-secret':
            try:
                return self.secrets.capture(request, delivery_ready)
            except Exception:
                return {'ok': False, 'error': 'secret capture failed; vault update not confirmed'}
        if action == 'deliver-secret':
            try:
                return self.secrets.deliver(request)
            except Exception:
                return {'ok': False, 'error': 'secret delivery failed; check the sink before any retry'}
        if action in {'create-card', 'update-card', 'search-cards', 'pin-card-target', 'fill-card'}:
            return self.cards.dispatch(request, delivery_ready)
        if action in IDENTITY_COMMANDS:
            return self.identities.dispatch(request, delivery_ready)
        if action in {'merge', 'admit'}:
            return self.merges.begin(request)
        if action in {'add-url', 'remove-url'}:
            try:
                return self.writes.change_additional_url(request)
            except (WriteError, SaveError) as exc:
                return {'ok': False, 'error': str(exc)}
            except Exception:
                return {'ok': False, 'error': 'additional URL save failed; vault update not confirmed'}
        if action == 'save-secret':
            try:
                return self.writes.save_secret(request)
            except (WriteError, SaveError) as exc:
                return {'ok': False, 'error': str(exc)}
            except Exception:
                return {'ok': False, 'error': 'secret save failed; vault update not confirmed'}
        if action in {'create-sso-entry', 'create-passwordless-entry'}:
            try:
                return (self.writes.create_sso(request) if action == 'create-sso-entry'
                        else self.writes.create_passwordless(request))
            except (WriteError, SaveError) as exc:
                return {'ok': False, 'error': str(exc)}
            except Exception:
                return {'ok': False, 'error': 'passwordless save failed; vault update not confirmed'}
        if action in {"create-entry", "update-password", "generate-password", "generate-entry", "setup-totp", "write-status", "cancel-write", "commit-password", "fill-generated"}:
            try:
                if action in {"create-entry", "update-password", "generate-password", "generate-entry", "setup-totp"}:
                    return self.writes.begin(request)
                if action in {"write-status", "cancel-write"}:
                    return self.writes.status(request.get("write_handle"), cancel=action == "cancel-write")
                if action == "fill-generated":
                    return self.writes.fill(request, delivery_ready)
                return self.writes.commit_generated(request)
            except (WriteError, TotpError) as exc:
                return {"ok": False, "error": str(exc)}
            except Exception:
                return {"ok": False, "error": "password operation failed"}
        if action == "search":
            query = request.get("query", "")
            if not isinstance(query, str) or len(query) > 500:
                return {"ok": False, "error": "invalid query"}
            needle = query.casefold()
            matches = []
            try:
                with self._state_lock:
                    vault = self.vault
                assert vault is not None
                for entry in active_entries(vault):
                    try:
                        if is_card(entry) or is_identity(entry):
                            continue
                        title = entry.title or ""
                        username = entry.username or ""
                        url = entry.url or ""
                        path = entry.path
                        if (
                            not all(isinstance(value, str) for value in (title, username, url))
                            or not isinstance(path, (list, tuple))
                            or not all(isinstance(value, str) for value in path)
                        ):
                            continue
                        group = "/".join(path[:-1]) if path else ""
                        extra = additional_urls(entry)
                        metadata = (title, username, url, group, *extra)
                        is_match = not needle or any(needle in value.casefold() for value in metadata)
                    except Exception:
                        # A malformed/inaccessible entry must not disable
                        # searches for other entries.
                        continue
                    if not is_match:
                        continue
                    if any(len(value.encode("utf-8")) > MAX_METADATA_BYTES for value in metadata):
                        raise ValueError("metadata exceeds response budget")
                    candidate = {
                        "handle": "0" * 64,
                        "title": title,
                        "username": username,
                        "url": url,
                        "group": group,
                    }
                    if extra:
                        candidate["additional_urls"] = extra
                    identity = passwordless_identity(entry)
                    if identity:
                        candidate.update(identity)
                    if totp_configured(entry):
                        candidate['totp_configured'] = True
                    if is_secret_record(entry):
                        candidate['secret_record'] = True
                    fields = captured_fields(entry)
                    if fields:
                        candidate['captured_fields'] = fields
                    projected = {
                        "ok": True,
                        "entries": [*(item for item, _entry in matches), candidate],
                    }
                    encoded_size = len(json.dumps(projected, separators=(",", ":")).encode("utf-8"))
                    if encoded_size > MAX_SEARCH_RESPONSE:
                        raise ValueError("search response exceeds budget")
                    matches.append((candidate, entry))
                    if len(matches) == 20:
                        break
            except Exception:
                return {"ok": False, "error": "search failed"}
            entries = []
            for candidate, entry in matches:
                candidate["handle"] = self._new_handle(entry)
                entries.append(candidate)
            return {"ok": True, "entries": entries}
        if action in {'fill', 'fill-totp'}:
            target = None
            try:
                entry = self._resolve(request.get("handle"))
                token = request.get('target')
                if isinstance(token, str):
                    target = self.extension.take(token, 'password')
                    if target is None:
                        try:
                            target = self.passwords.consume(token)
                        except TargetError:
                            target = self.targets.consume(request)
                else:
                    target = self.targets.consume(request)
                if isinstance(target, DOM_PINS) and (type(request.get('target_protocol')) is not int or request['target_protocol'] != 1):
                    raise TargetError()
                allowed = {'action', 'handle', 'start_deadline', 'target', 'target_protocol'}
                allowed.add('target_url' if action == 'fill-totp' else 'mode')
                if set(request) - allowed:
                    raise TargetError()
                mode = 'totp' if action == 'fill-totp' else request.get("mode", "login")
                if action != 'fill-totp' and mode not in ("login", "username", "password"):
                    raise ValueError("mode must be login, username, or password")
                start_deadline = request.get("start_deadline")
                if start_deadline is None and internal_dispatch:
                    start_deadline = self.clock() + FILL_START_TIMEOUT
                if (
                    isinstance(start_deadline, bool)
                    or not isinstance(start_deadline, (int, float))
                    or not math.isfinite(start_deadline)
                ):
                    raise ValueError("autofill not started: invalid deadline")
            except TargetError:
                if isinstance(target, DOM_PINS):
                    target.close()
                return target_failure()
            except ValueError as exc:
                if isinstance(target, DOM_PINS):
                    target.close()
                return {"ok": False, "error": str(exc)}
            # Once credentials are accessed, backend errors must never reach RPC
            # responses: exception messages can contain the text being typed.
            try:
                remaining = min(start_deadline - self.clock(), FILL_START_TIMEOUT)
                if remaining <= 0 or not self._keyboard_lock.acquire(timeout=remaining):
                    return {"ok": False, "error": "autofill not started: request expired"}
                try:
                    # This lock is the fill queue boundary. Avoid credential
                    # access for requests already known to be abandoned.
                    if self.clock() >= start_deadline:
                        return {"ok": False, "error": "autofill not started: request expired"}
                    if not delivery_ready():
                        return {"ok": False, "error": "autofill not started: caller disconnected"}

                    if is_identity(entry):
                        return {'ok': False, 'error': 'identity record requires identity fill; no keys sent'}
                    if is_card(entry):
                        return {'ok': False, 'error': 'card record requires card fill; no keys sent'}
                    if mode not in {'username', 'totp'} and passwordless_identity(entry):
                        return {'ok': False, 'error': 'passwordless record has no separate password; no keys sent'}
                    if mode not in {'username', 'totp'} and is_secret_record(entry):
                        return {'ok': False, 'error': 'captured secret record has no site password; no keys sent'}

                    # A keyboard backend cannot authorize browser password delivery.
                    # Refuse before reading the password, irrespective of its methods.
                    if mode in {"login", "password"} and not isinstance(target, DOM_PINS):
                        raise DeliveryError(False)

                    # Materialize and validate every value needed by this mode
                    # before emitting any event. Entry access and validation
                    # may take time, so neither is itself the delivery boundary.
                    code_valid = lambda: True
                    if mode == 'totp':
                        # Main URL or an exact KP2A_URL* origin; nothing broader.
                        target_origin = https_origin(request.get('target_url'))
                        if target_origin not in additional_origins(entry) and target_origin != https_origin(entry.url):
                            return {'ok': False, 'error': 'autofill not started: TOTP target site mismatch'}
                        configuration = read_configuration(entry)
                        now = self.wall_clock()
                        password = code_at(configuration, now)
                        valid_from = int(now // configuration.period) * configuration.period
                        valid_until = valid_from + configuration.period
                        if valid_until - now < MIN_VALIDITY:
                            return {'ok': False, 'error': 'autofill not started: TOTP code near expiry; wait and use fresh handles',
                                    'retry_after': math.ceil(valid_until - now)}
                        code_valid = lambda: valid_from <= self.wall_clock() < valid_until - 2
                    elif mode == "login":
                        username, password = entry.username or "", entry.password or ""
                        self._validate_credential_text(username, password)
                    elif mode == "username":
                        username = entry.username or ""
                        self._validate_credential_text(username)
                    else:
                        password = entry.password or ""
                        self._validate_credential_text(password)

                    # This is the delivery boundary: re-authorize immediately
                    # before the first keyboard call, after all preflight work.
                    if self.clock() >= start_deadline:
                        return {"ok": False, "error": "autofill not started: request expired"}
                    if not delivery_ready():
                        return {"ok": False, "error": "autofill not started: caller disconnected"}
                    if not code_valid():
                        return {'ok': False, 'error': 'autofill not started: authenticator clock changed or code expired'}

                    steps = [username, None, password] if mode == 'login' else [username if mode == 'username' else password]
                    ready = lambda: self.clock() < start_deadline and delivery_ready() and code_valid()
                    if isinstance(target, DOM_PINS):
                        if mode == 'totp':
                            raise DeliveryError(False)
                        (self.extension.deliver_password if isinstance(target, ExtensionPin) else self.passwords.deliver)(target, mode, username if mode != 'password' else '',
                                               password if mode != 'username' else '', allowed_origins(entry), ready, start_deadline)
                    elif mode == 'totp':
                        self.typer.deliver(target, steps, ready, guard=code_valid)
                        if not code_valid():
                            return target_failure(True)
                    elif mode == "username":
                        self.typer.deliver(target, steps, ready)
                    else:
                        raise DeliveryError(False)
                    return {"ok": True, "filled": mode, "target_delivery": EXTENSION_DELIVERY if isinstance(target, ExtensionPin)
                            else PASSWORD_DELIVERY if isinstance(target, DOM_PINS) else DELIVERY}
                finally:
                    self._keyboard_lock.release()
            except DeliveryError as exc:
                return target_failure(exc.started)
            except TotpError as exc:
                return {'ok': False, 'error': 'autofill not started: ' + str(exc)}
            except Exception:
                return {"ok": False, "error": "autofill failed"}
            finally:
                if isinstance(target, DOM_PINS):
                    try:
                        target.close()
                    except Exception:
                        pass
        return {"ok": False, "error": "unknown action"}


def is_wrong_credentials(exc: BaseException) -> bool:
    """True only for a wrong master password or key file.

    Store, file and I/O errors say nothing about the password, so they never
    count toward an unlock link's failed attempts.
    """
    from pykeepass.exceptions import CredentialsError
    return isinstance(exc, CredentialsError)


def open_vault_with_password(database: Path, password: str, keyfile: Path | None = None):
    if os.name == 'nt':
        from .windows_store import WindowsVaultStore as VaultStore
    else:
        from .persistence import VaultStore
    return VaultStore(database).open(password, keyfile)


def _serve_connection(connection: socket.socket, broker: Broker) -> None:
    """Handle one bounded RPC without allowing its failure to stop the listener."""
    with connection:
        connection.settimeout(CONNECTION_TIMEOUT)
        try:
            request = receive_message(
                connection,
                deadline=time.monotonic() + CONNECTION_TIMEOUT,
            )
            if request.get('action') == 'extension-attach':
                # A paired browser extension's native host: one long-lived,
                # bidirectional channel instead of one request.
                broker.extension.attach(connection, request)
                return
            response = broker.dispatch(
                request,
                delivery_ready=lambda: _connection_is_alive(connection),
            )
        except (ProtocolError, TimeoutError, OSError):
            response = CONNECTION_ERROR
        except Exception:
            response = CONNECTION_ERROR
        try:
            send_message(connection, response)
        except ProtocolError:
            try:
                send_message(connection, CONNECTION_ERROR)
            except (ProtocolError, TimeoutError, OSError):
                pass
        except (TimeoutError, OSError):
            pass


def _connection_is_alive(connection: socket.socket) -> bool:
    """Check that a one-request RPC has neither EOF nor trailing input pending."""
    try:
        if os.name == 'nt':
            return connection.is_alive()
        readable, _, _ = select.select([connection], [], [], 0)
        # After receive_message consumed the one permitted request, readability
        # means either EOF or unexpected trailing protocol bytes. Neither state
        # is authorized to start credential delivery.
        return not readable
    except OSError:
        return False


def serve(socket_path: Path, broker: Broker, stop: Event | None = None) -> None:
    if os.name == 'nt':
        from .windows_rpc import serve as windows_serve
        return windows_serve(socket_path, broker, stop)
    socket_path = Path(os.path.abspath(os.fspath(socket_path)))
    runtime_path, runtime_fd = prepare_private_runtime_directory(socket_path.parent)
    socket_path = runtime_path / socket_path.name
    lifecycle_lock: int | None = None
    server: socket.socket | None = None
    socket_identity: tuple[int, int] | None = None
    workers: set[threading.Thread] = set()
    workers_lock = threading.Lock()
    try:
        lifecycle_lock = acquire_lifecycle_lock(runtime_fd, socket_path.name)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        remove_stale_socket(socket_path, runtime_fd, socket_path.name)
        server.bind(anchored_socket_path(runtime_fd, socket_path.name))
        server.listen(8)
        os.chmod(socket_path.name, 0o600, dir_fd=runtime_fd)
        socket_info = os.stat(socket_path.name, dir_fd=runtime_fd, follow_symlinks=False)
        socket_identity = (socket_info.st_dev, socket_info.st_ino)
        server.settimeout(0.2 if stop else None)
        admission = threading.BoundedSemaphore(MAX_RPC_WORKERS)
        broker.card_save_notifications.resume()

        def run_connection(connection: socket.socket) -> None:
            try:
                _serve_connection(connection, broker)
            finally:
                with workers_lock:
                    workers.discard(threading.current_thread())
                admission.release()

        while stop is None or not stop.is_set():
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            if not admission.acquire(blocking=False):
                connection.close()
                continue
            worker: threading.Thread | None = None
            try:
                worker = threading.Thread(
                    target=run_connection, args=(connection,), daemon=True,
                )
                with workers_lock:
                    workers.add(worker)
                worker.start()
            except Exception:
                with workers_lock:
                    if worker is not None:
                        workers.discard(worker)
                try:
                    connection.close()
                finally:
                    admission.release()
                continue
    finally:
        try:
            if server is not None:
                server.close()
            broker.extension.close()
            broker.unlock_notifications.close()
            broker.card_save_notifications.close()
            with workers_lock:
                pending = list(workers)
            join_deadline = time.monotonic() + CONNECTION_TIMEOUT + 0.2
            for worker in pending:
                worker.join(max(0, join_deadline - time.monotonic()))
        finally:
            try:
                unlink_socket_if_same(
                    runtime_fd, socket_path.name, socket_identity,
                )
            finally:
                try:
                    if lifecycle_lock is not None:
                        os.close(lifecycle_lock)
                finally:
                    os.close(runtime_fd)
