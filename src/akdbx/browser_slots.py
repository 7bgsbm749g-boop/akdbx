"""Agent desktop browser slots: one operator-selected root, one Chrome per slot.

The operator gives the broker one profile root at startup. Each slot is a
private Chrome user-data directory `<root>/<slot>/`. A pin request names a
slot; the broker never takes a path by RPC. The name selects only a direct
child of the root, and the existing profile checks (owner, mode, no symlink
component, DevToolsActivePort, TCP peer UID) then apply to that exact
directory. A pin keeps the browser connection it was created with, so a pin
made in one slot can never deliver into another.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

PROTOCOL = 1
FIELD = 'browser_slot'
NAME = re.compile(r'slot[1-9][0-9]?')
MAX_SLOTS = 99
_LIST = r'(?:slot[1-9][0-9]?(?:, slot[1-9][0-9]?)*|none)'
# Every slot refusal is one of these exact messages, so the CLI can accept
# them without passing through any other broker text.
MESSAGES = re.compile(
    r'browser slot required: this broker fills the Chrome of one agent desktop slot; '
    r'pass --browser-slot SLOT or set AGENT_DESKTOP_SLOT \(slots: ' + _LIST + r'\)'
    r'|browser slot invalid: use a slot name such as slot1'
    r'|browser slot unknown: slot[1-9][0-9]? \(slots: ' + _LIST + r'\)'
    r'|browser slot not supported: this broker has no --browser-profile-root; omit --browser-slot'
    r'|browser slot applies only to the cdp route; omit --browser-slot with --route extension'
    r'|browser slot not running: slot[1-9][0-9]? has no verified Chrome on a local X display; start the slot and pin again'
    r'|browser slot window pins need Linux X11')


class SlotError(Exception):
    """A refused slot request; the message is safe to return over RPC."""


def valid_name(value) -> bool:
    return isinstance(value, str) and NAME.fullmatch(value) is not None


def valid_message(value) -> bool:
    return isinstance(value, str) and MESSAGES.fullmatch(value) is not None


def _real_directory(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)


class BrowserSlots:
    """The configured profile root. Names only; every path check stays in the transports."""

    def __init__(self, root):
        self.root = Path(os.path.abspath(os.fspath(root)))

    def names(self) -> list[str]:
        """Slot directories under the root, in numeric order; never follows a symlink."""
        if not _real_directory(self.root):
            return []
        found = []
        try:
            with os.scandir(self.root) as entries:
                for entry in entries:
                    if valid_name(entry.name) and entry.is_dir(follow_symlinks=False):
                        found.append(entry.name)
        except OSError:
            return []
        return sorted(found, key=lambda name: int(name[4:]))[:MAX_SLOTS]

    def live(self, endpoint) -> list[str]:
        """Slots whose DevToolsActivePort passes `endpoint`'s checks; no browser connection."""
        result = []
        for name in self.names():
            try:
                endpoint(self.root / name)
            except Exception:
                continue
            result.append(name)
        return result

    def _listing(self) -> str:
        return ', '.join(self.names()) or 'none'

    def profile(self, name) -> Path:
        if not valid_name(name):
            raise SlotError('browser slot invalid: use a slot name such as slot1')
        path = self.root / name
        if not _real_directory(path):
            raise SlotError(f'browser slot unknown: {name} (slots: {self._listing()})')
        return path

    def required(self) -> SlotError:
        return SlotError('browser slot required: this broker fills the Chrome of one agent desktop slot; '
                         f'pass --browser-slot SLOT or set AGENT_DESKTOP_SLOT (slots: {self._listing()})')

    def chrome(self, name) -> int:
        """The PID of the Chrome that runs this slot's profile, checked from that process itself.

        Chrome's profile lock (`SingletonLock`, a symlink to `HOST-PID`) names
        the browser process. That process must be ours, on this host, and run
        with exactly this profile directory. Chrome rewrites its command line
        as its process title (arguments joined by spaces), so the argument is
        matched as a whole, followed by a space or the end.
        """
        import socket as socket_module
        path = self.profile(name)
        if os.name == 'nt':
            raise SlotError('browser slot window pins need Linux X11')
        try:
            host, _, pid_text = os.readlink(path / 'SingletonLock').rpartition('-')
            if host not in {socket_module.gethostname(), os.uname().nodename} or not pid_text.isdigit():
                raise ValueError
            pid = int(pid_text)
            proc = Path('/proc') / str(pid)
            profiles = {os.fsencode(os.path.realpath(path)), os.fsencode(path)}
            if pid <= 1 or proc.stat().st_uid != os.getuid():
                raise ValueError
            title = b' ' + (proc / 'cmdline').read_bytes().rstrip(b'\0').replace(b'\0', b' ') + b' '
            if not any(b' --user-data-dir=' + profile + b' ' in title for profile in profiles):
                raise ValueError
            return pid
        except (OSError, ValueError, UnicodeError):
            raise self.not_running(name) from None

    @staticmethod
    def not_running(name) -> SlotError:
        return SlotError(f'browser slot not running: {name} has no verified Chrome on a local X display; '
                         'start the slot and pin again')


def x11_servers() -> list[str]:
    """Local X displays of this user: ':N' for each Unix socket /tmp/.X11-unix/XN that this user owns."""
    found = []
    try:
        with os.scandir('/tmp/.X11-unix') as entries:
            for entry in entries:
                match = re.fullmatch(r'X([0-9]{1,5})', entry.name)
                if match:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid():
                        found.append(int(match.group(1)))
    except OSError:
        return []
    return [':' + str(number) for number in sorted(found)]


def x11_cookie_file(server_pid: int):
    """The `-auth FILE` of this user's X server process (X servers keep their argv), or None.

    Raises ValueError for a process of another user or an unsafe file: a
    regular file of this user that others cannot write, by absolute path.
    """
    proc = Path('/proc') / str(server_pid)
    if proc.stat().st_uid != os.getuid():
        raise ValueError
    argv = (proc / 'cmdline').read_bytes().split(b'\0')
    if b'-auth' not in argv:
        return None
    index = argv.index(b'-auth')
    path = os.fsdecode(argv[index + 1]) if index + 1 < len(argv) else ''
    info = os.lstat(path)
    if not os.path.isabs(path) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError
    return path


def select(request: dict, profile, slots: BrowserSlots | None):
    """Return `(request without the slot field, profile, slot name)` for one CDP pin.

    With a root, a request must name a slot: the broker never guesses. Without
    one, a slot request is refused and the single operator profile is used.
    """
    if FIELD not in request:
        if slots is not None:
            raise slots.required()
        return request, profile, None
    name = request[FIELD]
    rest = {k: v for k, v in request.items() if k != FIELD}
    if slots is None:
        if not valid_name(name):
            raise SlotError('browser slot invalid: use a slot name such as slot1')
        raise SlotError('browser slot not supported: this broker has no --browser-profile-root; omit --browser-slot')
    return rest, slots.profile(name), name


def refuse_extension(request: dict) -> None:
    """The extension route is paired to one browser; a slot never selects it."""
    if FIELD in request:
        raise SlotError('browser slot applies only to the cdp route; omit --browser-slot with --route extension')


def status(slots: BrowserSlots | None, endpoint) -> dict:
    if slots is None:
        return {}
    return {'browser_profile_root': str(slots.root), 'browser_slots': slots.names(),
            'browser_slots_live': slots.live(endpoint)}


# CLI side. The slot of an agent comes from --browser-slot, else from the
# AGENT_DESKTOP_SLOT variable that the agent desktop sets for its agents.
ENV = 'AGENT_DESKTOP_SLOT'
ROOT_ENV = 'AKDBX_BROWSER_PROFILE_ROOT'


def add_argument(parser) -> None:
    parser.add_argument('--browser-slot', metavar='SLOT',
                        help=f'agent desktop slot whose Chrome holds the page (cdp route), for example slot2; '
                             f'default: ${ENV}. Required when the broker runs with --browser-profile-root')


def chosen(args):
    """The slot this command names: --browser-slot, else $AGENT_DESKTOP_SLOT, else None."""
    explicit = getattr(args, 'browser_slot', None)
    return explicit if explicit is not None else (os.environ.get(ENV) or None)


def request_field(args, caps, route):
    """Return `(fields to add, None)` or `(None, refusal)` before a pin request is sent."""
    explicit = getattr(args, 'browser_slot', None)
    name = chosen(args)
    if name is None:
        return {}, None
    if route == 'extension':
        # The paired extension is bound to one browser. Only an explicit
        # option is an error; the desktop's variable does not select it.
        if explicit is None:
            return {}, None
        return None, 'browser slot applies only to the cdp route; omit --browser-slot with --route extension; request not sent'
    if explicit is None and not isinstance(caps.get('browser_profile_root'), str):
        # A broker with one profile (or an older one) keeps working in an
        # agent desktop shell; only an explicit option is refused there.
        return {}, None
    if not valid_name(name):
        source = '--browser-slot' if explicit is not None else ENV
        return None, f'{source} is not a slot name such as slot1; request not sent'
    if type(caps.get('browser_slot_protocol')) is not int or caps['browser_slot_protocol'] != PROTOCOL:
        return None, 'broker lacks browser slot protocol 1; require broker 0.30.0 or newer; request not sent'
    return {FIELD: name}, None
