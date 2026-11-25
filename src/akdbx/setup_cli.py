"""`akdbx setup`: one guided command from install to a working broker.

The broker is the only required part. Every other part is an optional stage
that can be skipped. Each stage checks what is already done, shows what it
will change before it changes it, and changes only after a confirmation:
an answer at the terminal, or ``--yes`` together with the flag that selects
the change. ``--dry-run`` changes nothing, and ``--json`` prints a
machine-readable summary on stdout.

Setup reuses the existing commands and checks: the broker's own vault path
and TLS checks, ``akdbx relay enable``, ``akdbx extension install`` and
``build``, ``akdbx-browser-import install-host``, and the broker socket or
pipe checks of ``akdbx status``. It never creates, copies, opens, decrypts
or reads the vault, never asks for or handles the master password, never
installs system software or a certificate authority, and never prints or
stores a secret. The unlock link it prints is the broker's own private link.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import sysconfig
import time
from xml.sax.saxutils import escape

from . import __version__, native_merge
from .extension_route import BROWSERS, CHROMIUM_BROWSERS, FIREFOX_EXTENSION_ID, EXTENSION_ID, EXTENSION_VERSION

COMMAND = 'setup'
STAGES = ('system', 'vault', 'page', 'access', 'login', 'fill', 'features', 'skill')
TITLES = {
    'system': '1. System check',
    'vault': '2. Vault',
    'page': '3. Local page',
    'access': '4. Access',
    'login': '5. Start at login',
    'fill': '6. Fill route',
    'features': '7. Optional features',
    'skill': '8. Agent skill',
    'final': '9. Final check',
}
ACCESS = ('local', 'tailscale', 'relay', 'tunnel', 'decrypting')
ACCESS_LINES = {
    'local': 'Local only: open the page on this computer; nothing else can reach it (always available).',
    'tailscale': ('A private proxy such as Tailscale Serve: open the page on any device in your tailnet '
                  '(RECOMMENDED for remote use; setup prints the tailscale serve command).'),
    'relay': ('The akdbx relay: open the page on any device, with no open port; the relay forwards '
              'encrypted traffic that it cannot read.'),
    'tunnel': ('Another public tunnel that does not decrypt, such as Tailscale Funnel: anyone on the '
               'internet can reach the page (instructions only).'),
    'decrypting': ('A proxy that decrypts HTTPS, such as Cloudflare Tunnel: STRONGLY DISCOURAGED; '
                   'setup does not configure it.'),
}
DECRYPTING_WARNING = ('WARNING: a proxy that decrypts HTTPS (for example Cloudflare Tunnel) ends TLS on the '
                      "provider's servers. The proxy operator, and anyone who controls that proxy, can read the "
                      'master password and every secret you enter on the page. Do not use it for akdbx. '
                      'Setup does not configure it and uses local access instead.')
DEFAULT_ORIGIN = 'https://localhost:9443'
FUNNEL_PORTS = (443, 8443, 10000)
SERVICE_NAME = 'akdbx.service'
TASK_NAME = 'akdbx-broker'
MARKER = 'akdbx-setup'
SAFE_WORD = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=\\')
STATE_LIMIT = 64 * 1024
LINUX_BROWSERS = {
    'firefox': ('firefox',),
    'helium': ('helium', 'helium-browser'),
    'chrome': ('google-chrome', 'google-chrome-stable'),
    'edge': ('microsoft-edge', 'microsoft-edge-stable'),
    'chromium': ('chromium', 'chromium-browser'),
}
STATE_KEYS = ('vault', 'keyfile', 'tls_cert', 'tls_key', 'access', 'tailscale_name', 'tailnet_port',
              'local_port', 'start_at_login', 'browsers', 'extension_dir', 'firefox_extension_dir', 'cdp_profile', 'capture_host',
              'capture_browser', 'capture_dir', 'capture_extension_id', 'link_skill', 'skill_dirs')
NOTIFICATIONS = ('Unlock notifications: an agent can register a one-shot HTTPS webhook with '
                 "'akdbx subscribe-unlock --webhook-url-file FILE' and end its turn; the broker posts one "
                 'event when the vault is unlocked (no polling). Nothing to set up here; see the skill\'s '
                 'unlock-notifications reference.')


def add_parser(commands):
    command = commands.add_parser(
        COMMAND, help='guided setup from install to a working broker; every answer is also a flag',
        description=('One guided command from install to a working broker. The broker is the only required '
                     'part; every other stage is optional. At a terminal it asks questions with defaults. '
                     'With --yes it never asks, and only the flags of this run select a change (start at login, '
                     'relay, browsers, CDP profile, capture host, skill link); the saved answers of an earlier '
                     'run give only values such as paths and ports. Setup never reads the vault, never asks for '
                     'the master password, and never inspects or changes Tailscale: it prints the tailscale '
                     'serve command for you to run.'))
    command.add_argument('-y', '--yes', action='store_true',
                         help=('never ask; make only the changes that the flags of this run select (saved answers '
                               'give only paths, ports and other values)'))
    command.add_argument('--dry-run', action='store_true', help='show every check and planned change; change nothing')
    command.add_argument('--json', action='store_true', help='print a machine-readable summary on stdout')
    command.add_argument('--skip', action='append', choices=STAGES, default=[], metavar='STAGE',
                         help='skip one stage: ' + ', '.join(STAGES) + ' (repeatable)')
    command.add_argument('--vault', type=Path, help='existing .kdbx file; setup never creates, copies or reads it')
    command.add_argument('--keyfile', type=Path, help='existing key file of the vault, if it has one')
    command.add_argument('--no-keyfile', action='store_true', help='forget a key file saved by an earlier run')
    command.add_argument('--tls-cert', type=Path, help='existing PEM certificate for localhost or 127.0.0.1')
    command.add_argument('--tls-key', type=Path, help='its unencrypted PEM private key (Linux: mode 0600)')
    command.add_argument('--create-cert', action='store_true',
                         help='issue the certificate with mkcert after you ran mkcert -install yourself')
    command.add_argument('--access', choices=ACCESS, help='how the private page is reached; default local')
    command.add_argument('--tailscale-name', help="this computer's full MagicDNS name, for example node.tailnet.ts.net "
                              "(tailscale status --json: Self.DNSName, without the final dot)")
    command.add_argument('--tailnet-port', type=int, help='tailnet HTTPS port (Serve default 9443; Funnel 8443)')
    command.add_argument('--local-port', type=int, help='loopback port of the broker behind a proxy (default 9444)')
    command.add_argument('--relay-url', help='relay control URL for akdbx relay enable')
    command.add_argument('--start-at-login', action='store_true', default=None,
                         help='write the login service or task and enable it')
    command.add_argument('--no-start-at-login', action='store_false', dest='start_at_login',
                         help='do not set up a start at login')
    command.add_argument('--browser', action='append', choices=BROWSERS, metavar='BROWSER',
                         help='install the fill extension host for this browser: ' + ', '.join(BROWSERS)
                              + ' (repeatable)')
    command.add_argument('--no-extension', action='store_true', help='do not set up the extension route')
    command.add_argument('--extension-dir', type=Path, help='folder for the unpacked fill extension')
    command.add_argument('--cdp-profile', type=Path,
                         help='private Chromium user-data folder for the CDP route (debugging port)')
    command.add_argument('--no-cdp', action='store_true', help='do not set up the CDP route')
    command.add_argument('--capture-host', action='store_true', default=None,
                         help='set up the authenticator capture extension and native host')
    command.add_argument('--no-capture-host', action='store_false', dest='capture_host')
    command.add_argument('--capture-browser', choices=CHROMIUM_BROWSERS, help='browser for the capture host (default chrome)')
    command.add_argument('--capture-extension-id',
                         help='ID of the loaded capture extension (32 letters a-p), shown in chrome://extensions')
    command.add_argument('--capture-dir', type=Path, help='folder for the unpacked capture extension')
    command.add_argument('--link-skill', action='store_true', default=None,
                         help="link the agent skills folders to akdbx's skill")
    command.add_argument('--no-link-skill', action='store_false', dest='link_skill')
    command.add_argument('--skill-dir', action='append', type=Path,
                         help='agent skills folder to link (default: ~/.claude/skills and ~/.codex/skills)')
    command.add_argument('--skill-source', type=Path, help='the skills/akdbx folder to link to')


# ----- small helpers --------------------------------------------------------

class Prompter:
    """Questions with defaults at a terminal; the default, without asking, otherwise."""

    def __init__(self, interactive, out, ask=None):
        self.interactive = interactive
        self.out = out
        self.ask = ask or input

    def say(self, text=''):
        print(text, file=self.out, flush=True)

    def _answer(self, prompt):
        self.out.write(prompt)
        self.out.flush()
        return self.ask().strip()

    def text(self, question, default=None):
        if not self.interactive:
            return default
        answer = self._answer(f'{question}' + (f' [{default}]' if default else '') + ': ')
        return answer or default

    def confirm(self, question, default):
        if not self.interactive:
            return default
        while True:
            answer = self._answer(f'{question} [{"Y/n" if default else "y/N"}] ').lower()
            if not answer:
                return default
            if answer in ('y', 'yes'):
                return True
            if answer in ('n', 'no'):
                return False
            self.say('Answer y or n.')

    def choose(self, question, options, default):
        if not self.interactive:
            return default
        keys = [key for key, _ in options]
        for number, (key, line) in enumerate(options, 1):
            self.say(f'  {number}. {line}')
        while True:
            answer = self._answer(f'{question} [{keys.index(default) + 1}] ').lower()
            if not answer:
                return default
            if answer.isdigit() and 1 <= int(answer) <= len(keys):
                return keys[int(answer) - 1]
            if answer in keys:
                return answer
            self.say(f'Answer a number from 1 to {len(keys)}.')


def run_command(argv, *, timeout=120, umask=None):
    """Run one external command with its output captured; never through a shell."""
    options = {} if umask is None or os.name == 'nt' else {'umask': umask}
    return subprocess.run([str(part) for part in argv], stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, encoding='utf-8', errors='replace', timeout=timeout, check=False, **options)


def systemd_quote(value):
    """One ExecStart word: quoted, with systemd's specifier and variable expansion turned off."""
    value = str(value)
    if any(c in value for c in '\0\r\n'):
        raise ValueError('a path for the login service contains a line break')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def systemd_path(value):
    """The executable word of ExecStart: systemd never expands variables in it, so "$" stays as it is."""
    value = str(value)
    if any(c in value for c in '\0\r\n'):
        raise ValueError('a path for the login service contains a line break')
    return value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')


def systemd_exec(argv):
    """ExecStart with the "@" prefix: the program path as written, then argv[0] and the arguments, in
    which systemd expands variables (so "$" is written "$$" there). Python finds its venv from argv[0]."""
    return '"@' + systemd_path(argv[0]) + '" ' + ' '.join(systemd_quote(part) for part in argv)


def systemd_environment(name, value):
    value = str(value)
    if any(c in value for c in '\0\r\n'):
        raise ValueError('an environment value for the login service contains a line break')
    return 'Environment="' + (name + '=' + value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def unit_text(argv, environment):
    """The systemd user unit that runs `akdbx serve`; marked so setup recognizes its own file."""
    lines = [
        f'# {MARKER}: written by akdbx setup. Run akdbx setup again to change it.',
        '[Unit]',
        'Description=akdbx KeePass autofill broker (starts locked; unlock on its private page)',
        'After=graphical-session.target',
        '',
        '[Service]',
        'Type=simple',
        'ExecStart=' + systemd_exec(argv),
    ]
    lines += [systemd_environment(name, value) for name, value in environment]
    if not any(name == 'AKDBX_UNLOCK_ORIGIN' for name, _ in environment):
        # The origin is on the command line, or comes from the relay: an
        # imported variable must not change it.
        lines.append('UnsetEnvironment=AKDBX_UNLOCK_ORIGIN')
    lines += [
        'UMask=0077',
        # Exit status 2 is a refusal (for example a live broker or untrusted
        # files): restarting would only repeat it.
        'Restart=on-failure',
        'RestartSec=10',
        'RestartPreventExitStatus=2',
        '',
        '[Install]',
        'WantedBy=default.target',
        '',
    ]
    return '\n'.join(lines)


def task_xml(command, arguments, user):
    """A Task Scheduler task: at this user's logon, as this user, without elevation."""
    user, command, arguments = escape(user), escape(str(command)), escape(arguments)
    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{MARKER}: akdbx broker at logon (starts locked; unlock on its private page). Run akdbx setup again to change it.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
'''


def task_action(xml):
    """(marker present, command, arguments) of a queried task's XML."""
    import re
    from xml.sax.saxutils import unescape

    def field(name):
        match = re.search(rf'<{name}>(.*?)</{name}>', xml, re.S)
        return unescape(match.group(1).strip()) if match else None
    return MARKER in (field('Description') or ''), field('Command'), field('Arguments')


def link_target(path):
    """'missing', ('link', target) for a symlink or junction, or 'other'."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return 'missing'
    junction = getattr(info, 'st_reparse_tag', 0) == getattr(stat, 'IO_REPARSE_TAG_MOUNT_POINT', -1)
    if stat.S_ISLNK(info.st_mode) or junction:
        target = os.readlink(path)
        if target.startswith('\\\\?\\'):
            target = target[4:]
        return 'link', Path(os.path.join(os.path.dirname(os.path.abspath(path)), target))
    return 'other'


def same_folder(left, right):
    try:
        return os.path.normcase(os.path.realpath(left)) == os.path.normcase(os.path.realpath(right))
    except OSError:
        return False


def create_link(source, target):
    """A symlink on Linux; a directory junction on Windows, which needs no elevation."""
    if os.name == 'nt':
        import _winapi
        _winapi.CreateJunction(str(source), str(target))
    else:
        os.symlink(source, target, target_is_directory=True)


def powershell_quote(value):
    """One PowerShell word: bare when it is plainly safe, else a single-quoted literal ('' for ')."""
    value = str(value)
    if value and all(c in SAFE_WORD for c in value):
        return value
    # PowerShell also ends a literal at the typographic single quotes: double them too.
    return "'" + ''.join(c * 2 if c in "'\u2018\u2019\u201a\u201b" else c for c in value) + "'"


def shell_command(argv, windows):
    """The command as a user types it: POSIX sh on Linux; PowerShell, with the call operator &, on Windows."""
    if windows:
        return '& ' + ' '.join(powershell_quote(part) for part in argv)
    return shlex.join(str(part) for part in argv)


# ----- the setup run -------------------------------------------------------

class Refusal(Exception):
    """Answers that cannot work together: setup stops before any change (exit status 2)."""


class Setup:
    def __init__(self, args, *, ui, runner=run_command, status=None, which=shutil.which, windows=None,
                 env=None, home=None, sleep=time.sleep, link=create_link, executable=None):
        self.args = args
        self.ui = ui
        self.runner = runner
        self.status_request = status
        self.which = which
        self.windows = (os.name == 'nt') if windows is None else windows
        self.env = os.environ if env is None else env
        self.home = Path(home) if home is not None else Path.home()
        self.sleep = sleep
        self.link = link
        self.executable = Path(executable) if executable else Path(sys.executable).absolute()
        self.dry_run = args.dry_run
        self.stages = {}
        self.user_steps = []
        self.commands_run = []
        self.socket_explicit = getattr(args, 'socket_explicit', False)
        self.socket = args.socket  # the CLI made an explicit one absolute, with ~ expanded
        self.origin = DEFAULT_ORIGIN
        self.started_service = False
        self.service_ready = False
        self.tools = {}
        self.choice = {}
        self.declined = set()  # selections whose change was declined: never saved as selected
        self.unselected = set()  # selections that --yes left out: the earlier saved answer is kept
        self.state, self.state_problem = self._load_state()

    # -- paths
    def config_home(self):
        base = self.env.get('XDG_CONFIG_HOME', '')
        return Path(base) if os.path.isabs(base) else self.home / '.config'

    def data_home(self):
        base = self.env.get('XDG_DATA_HOME', '')
        return Path(base) if os.path.isabs(base) else self.home / '.local' / 'share'

    def private_dir(self):
        if self.windows:
            return Path(self.env['LOCALAPPDATA']) / 'akdbx'
        return self.config_home() / 'akdbx'

    def state_path(self):
        return self.private_dir() / 'setup.json'

    def default_tls(self):
        folder = self.private_dir() if self.windows else self.private_dir() / 'tls'
        return folder / 'localhost.pem', folder / 'localhost-key.pem'

    def unit_path(self):
        return self.config_home() / 'systemd' / 'user' / SERVICE_NAME

    def task_path(self):
        return self.private_dir() / (TASK_NAME + '.task.xml')

    def default_extension_dir(self):
        return (self.private_dir() if self.windows else self.data_home() / 'akdbx') / 'extension'

    def default_capture_dir(self):
        return (self.private_dir() if self.windows else self.data_home() / 'akdbx') / 'capture-extension'

    # -- recording
    def record(self, stage, state, **details):
        entry = self.stages.setdefault(stage, {'state': state})
        entry['state'] = state
        entry.update(details)
        return entry

    def note(self, stage, key, value):
        self.stages.setdefault(stage, {'state': 'ok'}).setdefault(key, []).append(value)

    def step(self, text, stage=None):
        if text not in self.user_steps:
            self.user_steps.append(text)
        if stage:
            self.note(stage, 'user_steps', text)
        self.ui.say('  Your step: ' + text)

    def say(self, text):
        self.ui.say('  ' + text)

    def change(self, stage, what, show, action, *, selected, default=True, key=None):
        """Show a change, then apply it after confirmation. True: applied; None: not applied; False: failed.

        ``key`` names the saved selection that the change belongs to: a declined change keeps it from
        being saved as selected (a failed one stays selected, so the next run offers it again).
        """
        self.say('Will ' + what + ':')
        for line in show:
            self.ui.say('    ' + line)
        if self.dry_run:
            self.note(stage, 'planned', what)
            return None
        if not (self.ui.confirm('  Apply this change?', default) if self.ui.interactive else selected):
            self.note(stage, 'not_applied', what)
            if key and self.ui.interactive:
                # A real decline; under --yes an unselected change keeps the earlier answer.
                self.declined.add(key)
            return None
        errors = [OSError, ValueError, RuntimeError, subprocess.SubprocessError]
        if self.windows:
            try:
                import pywintypes
                errors.append(pywintypes.error)
            except ImportError:
                pass
        try:
            action()
        except tuple(errors) as exc:
            self.note(stage, 'errors', f'{what}: {exc}')
            self.say(f'Failed: {exc}')
            return False
        self.note(stage, 'changed', what)
        return True

    def outcome(self, applied):
        if applied:
            return 'changed'
        return 'failed' if applied is False else 'planned' if self.dry_run else 'todo'

    def run(self, argv, **options):
        self.commands_run.append(shell_command(argv, self.windows))
        return self.runner(argv, **options)

    def akdbx_argv(self, *arguments, origin=None):
        argv = [self.executable, '-m', 'akdbx.cli']
        if self.socket_explicit:
            argv += ['--socket', str(self.socket)]
        if origin is not None:
            argv += ['--unlock-origin', origin]
        return argv + list(arguments)

    def run_json(self, argv, **options):
        """Run an existing akdbx command; return (ok, parsed JSON or None, short error)."""
        result = self.run(argv, **options)
        parsed = None
        for text in (result.stdout, result.stderr):
            try:
                parsed = json.loads(text)
                break
            except (TypeError, ValueError):
                continue
        if result.returncode == 0:
            return True, parsed, None
        error = parsed.get('error') if isinstance(parsed, dict) else None
        return False, parsed, error or (result.stderr or result.stdout or '').strip()[-300:] or 'failed'

    # -- state
    def _load_state(self):
        path = self.state_path()
        if not os.path.lexists(path):
            return {}, None
        try:
            if self.windows:
                from .windows_security import read_private_optional
                data = read_private_optional(path, limit=STATE_LIMIT)
                if data is None:
                    return {}, None
            else:
                from .runtime import open_private_runtime_directory
                try:
                    _, directory = open_private_runtime_directory(path.parent)
                except RuntimeError as exc:
                    if isinstance(exc.__cause__, FileNotFoundError):
                        return {}, None
                    raise
                try:
                    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
                except FileNotFoundError:
                    return {}, None
                finally:
                    os.close(directory)
                with os.fdopen(fd, 'rb') as source:
                    info = os.fstat(source.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > STATE_LIMIT):
                        raise ValueError('not a private file')
                    data = source.read(STATE_LIMIT + 1)
            state = json.loads(data)
            if not isinstance(state, dict):
                raise ValueError('not an object')
            return {key: state[key] for key in STATE_KEYS if key in state}, None
        except Exception as exc:
            return {}, f'the saved answers in {path} are not used ({type(exc).__name__}: {exc})'

    def saved_choices(self):
        """The answers to save. A selection is saved as selected only when no change of it was declined;
        one that --yes left out keeps the earlier answer."""
        choices = dict(self.choice)
        for key in self.unselected:
            choices[key] = self.state.get(key)
        browsers = [b for b in choices.get('browsers') or [] if 'browser:' + b not in self.declined]
        choices['browsers'] = [] if 'browsers' in self.declined else browsers
        for key in ('start_at_login', 'capture_host', 'link_skill'):
            if key in self.declined:
                choices[key] = False
        if 'cdp_profile' in self.declined:
            choices['cdp_profile'] = None
        if 'access' in self.declined:
            earlier = self.state.get('access')
            choices['access'] = earlier if earlier in ACCESS and earlier != choices.get('access') else None
        return choices

    def save_state(self):
        if self.dry_run:
            return
        state = {'version': __version__, **{key: value for key, value in self.saved_choices().items()
                                            if key in STATE_KEYS and value is not None}}
        data = json.dumps(state, indent=2, default=str).encode('utf-8')
        path = self.state_path()
        try:
            if self.windows:
                from .windows_security import ensure_private_directory, replace_private
                ensure_private_directory(path.parent)
                replace_private(path, data)
            else:
                self._write_private_posix(path, data)
        except Exception as exc:
            # The answers only give defaults to the next run: a folder that
            # fails the private-file checks is reported, never repaired.
            warning = (f'the answers were not saved in {path} ({exc}); the next run asks again. '
                       f'A folder above it must not be writable by group or others (chmod go-w)')
            self.note('final', 'warnings', warning)
            self.say('Note: ' + warning)

    def _write_private_posix(self, path, data):
        from .runtime import prepare_private_runtime_directory
        path.parent.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _, directory = prepare_private_runtime_directory(path.parent)
        temporary = '.' + path.name + '.tmp'
        try:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            os.close(directory)

    def remembered(self, key, flag=None, default=None):
        """A value (a path, a port, a name): the flag, else the earlier saved answer, else the default."""
        if flag is not None:
            return flag
        return self.state.get(key, default)

    def selected(self, key, flag, empty=False):
        """A selection of a change. At a terminal the earlier answer is the question's default; with --yes
        only this run's flag selects it."""
        if flag is not None:
            return flag
        if self.ui.interactive:
            return self.state.get(key, empty)
        if key in self.state:
            self.unselected.add(key)
        return empty

    # -- broker status
    def broker_status(self):
        """{'running': True/False/'unknown', 'response': dict or None}, with the CLI's own checks."""
        self._follow_relay_origin()
        for attempt in (1, 2):
            origin = self.origin
            try:
                response = self.status_request(origin)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                return {'running': False, 'response': None}
            except Exception as exc:
                # The broker may have saved a relay move after the read above: read it again once.
                self._follow_relay_origin()
                if attempt == 2 or self.origin == origin:
                    return {'running': 'unknown', 'response': None, 'error': type(exc).__name__}
        return {'running': True, 'response': response if isinstance(response, dict) else None}

    def _follow_relay_origin(self):
        """Use the relay origin saved now: a broker moves to the relay's new port when it starts.

        Read only, no network: the broker that serves the pages saves the move,
        so later stages (the extension build) get the origin that it serves.
        """
        if self.choice.get('access') != 'relay' or self.dry_run:
            return
        from .relay import RelayStore, RelayStoreError
        try:
            config = RelayStore().load()
        except RelayStoreError:
            return
        if config is not None and config.enabled:
            self.origin = config.origin

    # ----- 1. system ------------------------------------------------------
    def stage_system(self):
        gaps = []
        python = '.'.join(map(str, sys.version_info[:3]))
        if sys.version_info < (3, 11):
            gaps.append(f'Python {python} is older than 3.11')
        if self.windows:
            platform = 'windows'
            desktop = 'Windows desktop'
            if self._elevated():
                gaps.append('this shell is elevated: run setup and the broker as a normal user, without elevation')
        elif sys.platform.startswith('linux'):
            platform = 'linux'
            session = self.env.get('XDG_SESSION_TYPE', '')
            if self.env.get('DISPLAY'):
                desktop = f'X11 desktop (DISPLAY={self.env["DISPLAY"]})'
                if session == 'wayland':
                    gaps.append('this is a Wayland session: native-window fills need X11 (browser fills work)')
            else:
                desktop = 'no X11 desktop in this environment'
                gaps.append('DISPLAY is not set: native-window fills need an X11 desktop (browser fills work); '
                            'run setup from the desktop session that the broker will use')
        else:
            platform = sys.platform
            desktop = 'unsupported'
            gaps.append('akdbx supports Linux (X11) and Windows only')
        tools = {
            'merge_engine': native_merge.ENGINE,
            'mkcert': self.which('mkcert'),
            'tailscale': self.which('tailscale'),
            'systemctl': None if self.windows else self.which('systemctl'),
            'browsers': self._browsers(),
        }
        self.tools = tools
        if not tools['browsers']:
            gaps.append('no supported Chromium browser (Helium, Chrome, Edge) found (needed for browser fills)')
        self.say(f'Python {python}; {platform}: {desktop}')
        self.say('Built-in merge engine: ' + native_merge.ENGINE)
        self.say('mkcert: ' + (tools['mkcert'] or 'not found') + '; tailscale: ' + (tools['tailscale'] or 'not found'))
        self.say('Browsers: ' + (', '.join(sorted(tools['browsers'])) or 'none found'))
        for gap in gaps:
            self.say('Gap: ' + gap)
        self.record('system', 'ok' if platform in ('linux', 'windows') else 'failed', python=python,
                    platform=platform, desktop=desktop, tools=tools, gaps=gaps)
        return platform in ('linux', 'windows')

    def _elevated(self):
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _browsers(self):
        found = {}
        if self.windows:
            local = self.env.get('LOCALAPPDATA', '')
            programs = [self.env.get(name, '') for name in ('ProgramFiles', 'ProgramFiles(x86)')]
            candidates = {
                'firefox': [Path(base) / 'Mozilla Firefox' / 'firefox.exe' for base in programs if base],
                'helium': [Path(local) / 'imput' / 'Helium' / 'Application' / 'chrome.exe'],
                'chrome': [Path(base) / 'Google' / 'Chrome' / 'Application' / 'chrome.exe'
                           for base in (*programs, local) if base],
                'edge': [Path(base) / 'Microsoft' / 'Edge' / 'Application' / 'msedge.exe'
                         for base in programs if base],
            }
            for name, paths in candidates.items():
                for path in paths:
                    if local and path.is_file():
                        found[name] = str(path)
                        break
        else:
            for name, commands in LINUX_BROWSERS.items():
                for command in commands:
                    path = self.which(command)
                    if path:
                        found[name] = path
                        break
        return found

    # ----- answers ----------------------------------------------------------
    def collect(self):
        """Every answer. A value: a flag, else the earlier answer, else a question or the default. A selection
        of a change: with --yes only a flag of this run; at a terminal a question whose default is the earlier
        answer."""
        args, ui, choice = self.args, self.ui, self.choice
        skip = set(args.skip)
        vault = self.remembered('vault', args.vault)
        if 'vault' not in skip:
            vault = ui.text('Vault: path of your existing .kdbx file', str(vault) if vault else None)
        choice['vault'] = str(Path(vault).expanduser().absolute()) if vault else None
        keyfile = None if args.no_keyfile else self.remembered('keyfile', args.keyfile)
        if 'vault' not in skip and ui.interactive:
            answer = ui.text("Key file of the vault ('none' if it has none)", str(keyfile) if keyfile else 'none')
            keyfile = None if not answer or answer.lower() == 'none' else answer
        choice['keyfile'] = str(Path(keyfile).expanduser().absolute()) if keyfile else None

        access = self.remembered('access', args.access, 'local')
        if access not in ACCESS:
            access = 'local'
        if 'access' not in skip:
            if ui.interactive:
                ui.say('How will you open the private page?')
            access = ui.choose('Access', [(key, ACCESS_LINES[key]) for key in ACCESS], access)
        choice['access'] = access
        if access in ('tailscale', 'tunnel'):
            explicit = self.explicit_origin_parts()
            if explicit:
                # The explicit origin names the tailnet host and port; a different flag cannot work.
                name, port = explicit
                for flag, value, given in (('--tailscale-name', name, args.tailscale_name),
                                           ('--tailnet-port', port, args.tailnet_port)):
                    if given is not None and str(given).rstrip('.').lower() != str(value):
                        raise Refusal(f'{flag} {given} does not match the explicit unlock origin '
                                      f'{self.args.unlock_origin} (it names {value}); give one of them only')
                choice['tailscale_name'], choice['tailnet_port'] = name, port
            else:
                choice['tailscale_name'] = ui.text("This computer's full MagicDNS name, for example node.tailnet.ts.net "
                                                   "(tailscale status --json shows it as Self.DNSName; omit the final dot)",
                                                   self.remembered('tailscale_name', args.tailscale_name))
                port = args.tailnet_port or (self.state.get('tailnet_port') if self.state.get('access') == access
                                             else None) or (9443 if access == 'tailscale' else 8443)
                choice['tailnet_port'] = self._port('Tailnet HTTPS port', port)
            choice['local_port'] = self._port('Loopback port of the broker',
                                              self.remembered('local_port', args.local_port, 9444))

        if (args.tls_cert is None) != (args.tls_key is None):
            raise Refusal('give --tls-cert and --tls-key together (the certificate and its private key), or '
                          'neither')
        cert, key = ((args.tls_cert, args.tls_key) if args.tls_cert is not None
                     else (self.state.get('tls_cert'), self.state.get('tls_key')))
        if (cert is None) != (key is None):
            raise Refusal(f'the saved answers in {self.state_path()} name only one of the certificate and its key: '
                          'give --tls-cert and --tls-key')
        if cert is None:
            cert, key = self.default_tls()
        choice['tls_cert'] = str(Path(cert).expanduser().absolute())
        choice['tls_key'] = str(Path(key).expanduser().absolute())

        start = self.selected('start_at_login', args.start_at_login)
        if 'login' not in skip:
            start = ui.confirm('Start the broker at login (it starts locked)?', bool(start))
        choice['start_at_login'] = bool(start)

        browsers = [] if args.no_extension else (args.browser or self.selected('browsers', None, []) or [])
        browsers = [b for b in browsers if b in BROWSERS]
        if 'fill' not in skip and ui.interactive:
            self.ui.say('Fill route. The extension route works in your everyday browser and is preferred; the '
                        'CDP route needs a browser profile with a debugging port.')
            detected = [b for b in BROWSERS if b in self.tools.get('browsers', {})]
            answer = ui.text("Browsers for the extension route (" + ', '.join(BROWSERS) + "; comma-separated; 'none')",
                             ','.join(browsers or detected) or 'none')
            browsers = [] if answer.lower() == 'none' else [b.strip() for b in answer.split(',') if b.strip()]
            unknown = [b for b in browsers if b not in BROWSERS]
            browsers = [b for b in browsers if b in BROWSERS]
            for name in unknown:
                ui.say(f'  Ignored unknown browser {name!r}.')
        choice['browsers'] = list(dict.fromkeys(browsers))
        chromium = any(b in CHROMIUM_BROWSERS for b in choice['browsers'])
        firefox = 'firefox' in choice['browsers']
        chrome_dir = self._remembered_extension_dir('chrome')
        firefox_dir = self._remembered_extension_dir('firefox')
        if args.extension_dir is not None:
            folder = Path(os.path.abspath(args.extension_dir.expanduser()))
            if chromium or not firefox:
                chrome_dir = folder
            if firefox:
                firefox_dir = folder.with_name(folder.name + '-firefox') if chromium else folder
        # The manifest establishes the format of an existing folder. Defaults
        # are assigned only for selected formats that have no folder yet.
        if chromium and chrome_dir is None:
            chrome_dir = self._default_extension_folder('chrome', firefox_dir)
        if firefox and firefox_dir is None:
            firefox_dir = self._default_extension_folder('firefox', chrome_dir)
        choice['extension_dir'] = str(chrome_dir) if chrome_dir is not None else None
        choice['firefox_extension_dir'] = str(firefox_dir) if firefox_dir is not None else None
        cdp = None if args.no_cdp else self.selected('cdp_profile', args.cdp_profile, None)
        if 'fill' not in skip and ui.interactive:
            answer = ui.text("Private Chromium profile folder for the CDP route ('none' to skip)",
                             str(cdp) if cdp else 'none')
            cdp = None if not answer or answer.lower() == 'none' else answer
        choice['cdp_profile'] = str(Path(cdp).expanduser().absolute()) if cdp else None

        capture = self.selected('capture_host', args.capture_host)
        if 'features' not in skip:
            capture = ui.confirm('Set up the authenticator capture extension (reads a setup QR from a page)?',
                                 bool(capture))
        choice['capture_host'] = bool(capture)
        if capture or 'capture_host' in self.unselected:
            # Values only: a capture host that --yes left out keeps its saved browser, folder and ID.
            choice['capture_browser'] = self.remembered('capture_browser', args.capture_browser, 'chrome')
            choice['capture_dir'] = str(Path(self.remembered('capture_dir', args.capture_dir)
                                             or self.default_capture_dir()).expanduser().absolute())
            extension_id = self.remembered('capture_extension_id', args.capture_extension_id)
            if ui.interactive and not extension_id:
                extension_id = ui.text("Capture extension ID from chrome://extensions ('later' if it is not "
                                       'loaded yet)', 'later')
                extension_id = None if extension_id == 'later' else extension_id
            choice['capture_extension_id'] = extension_id

        link = self.selected('link_skill', args.link_skill)
        if 'skill' not in skip:
            link = ui.confirm('Link the akdbx skill into your agent skills folders?', bool(link) or ui.interactive)
        choice['link_skill'] = bool(link)
        dirs = args.skill_dir or self.state.get('skill_dirs')
        choice['skill_dirs'] = [str(Path(d).expanduser().absolute()) for d in dirs] if dirs else None

    def explicit_origin_parts(self):
        """(host, port) of an explicit --unlock-origin or AKDBX_UNLOCK_ORIGIN, or None."""
        if not getattr(self.args, 'unlock_origin_explicit', False):
            return None
        from urllib.parse import urlsplit
        try:
            parts = urlsplit(self.args.unlock_origin)
            host, port = parts.hostname, parts.port or 443
        except ValueError as exc:
            raise Refusal(f'the explicit unlock origin {self.args.unlock_origin!r} is not a URL ({exc})') from None
        if parts.scheme != 'https' or not host:
            raise Refusal(f'the explicit unlock origin {self.args.unlock_origin!r} is not an https:// origin')
        return host.rstrip('.').lower(), port

    def _port(self, question, default):
        while True:
            answer = self.ui.text(question, str(default))
            try:
                return int(answer)
            except (TypeError, ValueError):
                if not self.ui.interactive:
                    return default
                self.ui.say('  Answer a port number.')

    # ----- 2. vault ---------------------------------------------------------
    def stage_vault(self):
        vault, keyfile = self.choice.get('vault'), self.choice.get('keyfile')
        if not vault:
            self.say('No vault chosen. Setup needs the path of an existing .kdbx file; it never creates one.')
            self.record('vault', 'failed', error='no vault: give --vault PATH')
            return False
        try:
            writable_problem = self.check_vault(Path(vault), Path(keyfile) if keyfile else None)
        except ValueError as exc:
            self.say(f'Vault refused: {exc}')
            self.record('vault', 'failed', vault=vault, keyfile=keyfile, error=str(exc))
            return False
        if not vault.lower().endswith('.kdbx'):
            self.say('Note: the file name does not end in .kdbx.')
        self.say(f'Vault: {vault}' + (f' (key file {keyfile})' if keyfile else ''))
        self.say('The broker can open this path. Saves: ' + ('allowed' if writable_problem is None
                                                              else 'refused: ' + writable_problem))
        self.record('vault', 'ok', vault=vault, keyfile=keyfile, writes=writable_problem is None,
                    **({'writes_problem': writable_problem} if writable_problem else {}))
        return True

    def check_vault(self, vault, keyfile):
        """The broker's own path checks, from metadata only; returns why saves would be refused, or None."""
        if not vault.is_absolute():
            raise ValueError('use an absolute vault path')
        if self.windows:
            import pywintypes
            from .windows_store import WindowsVaultStore
            try:
                return WindowsVaultStore(vault).check_location(keyfile)
            except FileNotFoundError:
                raise ValueError('the vault or key file does not exist; setup never creates one') from None
            except pywintypes.error as exc:
                if exc.winerror in (2, 3):
                    raise ValueError('the vault or key file does not exist; setup never creates one') from None
                raise ValueError('the broker could not open this path (Windows error '
                                 f'{exc.winerror}); use a private local NTFS folder') from None
            except PermissionError as exc:
                raise ValueError(f'{exc}; the vault, key file and their folder must be private to you') from None
        from .persistence import SaveError, VaultStore
        try:
            store = VaultStore(vault)
        except FileNotFoundError:
            raise ValueError('the vault file does not exist; setup never creates one') from None
        except OSError as exc:
            raise ValueError(f'the vault path cannot be resolved ({exc.strerror})') from None
        try:
            problem = store.check_location()
        except SaveError as exc:
            raise ValueError(f'the broker would refuse this vault: {exc}') from None
        except OSError as exc:
            raise ValueError(f'the broker could not open this path ({exc.strerror})') from None
        if keyfile is not None:
            try:
                store.check_keyfile_location(keyfile)
            except FileNotFoundError:
                raise ValueError('the key file does not exist') from None
            except SaveError as exc:
                raise ValueError(str(exc)) from None
            except OSError as exc:
                raise ValueError(f'the key file cannot be opened ({exc.strerror})') from None
        return problem

    # ----- 3. local page ----------------------------------------------------
    def stage_page(self):
        if self.choice['access'] == 'relay':
            self.say('Skipped: the akdbx relay brings its own certificate for the page.')
            self.record('page', 'skipped', reason='the relay brings its own certificate')
            return True
        cert, key = Path(self.choice['tls_cert']), Path(self.choice['tls_key'])
        hosts = self._page_hosts()
        if cert.exists() or key.exists():
            return self._check_page(cert, key, hosts)
        self.say(f'No certificate at {cert} yet. The page needs one that your browser trusts for '
                 'localhost and 127.0.0.1, with its unencrypted private key.')
        mkcert = self.tools.get('mkcert')
        if not mkcert:
            self.step('Install mkcert (https://github.com/FiloSottile/mkcert), or bring your own certificate and '
                      'key with --tls-cert and --tls-key; then run akdbx setup again.', 'page')
            self.record('page', 'todo', tls_cert=str(cert), tls_key=str(key))
            return False
        ca_ready = self._mkcert_ca_ready(mkcert)
        issue = [mkcert, '-cert-file', cert, '-key-file', key, 'localhost', '127.0.0.1']
        if not ca_ready:
            self.step(f'Run {shell_command([mkcert, "-install"], self.windows)} yourself. It installs a local '
                      'certificate authority, which changes which certificates this computer trusts; setup never '
                      'does that for you. Keep its key (rootCA-key.pem in mkcert -CAROOT) private. On Linux, '
                      'Chrome and Firefox also need certutil (libnss3-tools) first. Then run akdbx setup again.',
                      'page')
            self.say('Setup will then issue the certificate with: ' + shell_command(issue, self.windows))
            self.record('page', 'todo', tls_cert=str(cert), tls_key=str(key))
            return False
        applied = self.change('page', f'issue a certificate for localhost and 127.0.0.1 into {cert.parent}',
                              ([] if self.windows else ['umask 077; mkdir -p ' + shlex.quote(str(cert.parent))])
                              + [shell_command(issue, self.windows)], lambda: self._issue(issue, cert),
                              selected=self.args.create_cert)
        if applied:
            return self._check_page(cert, key, hosts)
        if applied is None and not self.dry_run and not self.args.create_cert:
            self.say('Add --create-cert to issue it, or give --tls-cert and --tls-key.')
        self.record('page', self.outcome(applied), tls_cert=str(cert), tls_key=str(key))
        return False

    def _page_hosts(self):
        if self.choice['access'] in ('tailscale', 'tunnel'):
            # Tailscale Serve verifies the broker's certificate for 127.0.0.1.
            return ['127.0.0.1']
        from urllib.parse import urlsplit
        return [urlsplit(self.origin_for_access()).hostname]

    def _mkcert_ca_ready(self, mkcert):
        try:
            result = self.run([mkcert, '-CAROOT'], timeout=15)
        except (OSError, subprocess.SubprocessError):
            return False
        root = result.stdout.strip()
        return result.returncode == 0 and bool(root) and (Path(root) / 'rootCA.pem').is_file()

    def _issue(self, argv, cert):
        if self.windows:
            from .windows_security import ensure_private_directory
            ensure_private_directory(cert.parent)
        else:
            cert.parent.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            cert.parent.mkdir(exist_ok=True, mode=0o700)
        result = self.run(argv, timeout=60, umask=0o077)
        if result.returncode != 0:
            raise RuntimeError('mkcert failed: ' + (result.stderr or result.stdout).strip()[-300:])

    def _check_page(self, cert, key, hosts):
        try:
            names, not_after = self.check_tls(cert, key)
        except ValueError as exc:
            self.say(f'Certificate refused: {exc}')
            self.record('page', 'failed', tls_cert=str(cert), tls_key=str(key), error=str(exc))
            return False
        missing = [host for host in hosts if host not in names]
        if missing:
            error = f'the certificate does not name {", ".join(missing)} (it names {", ".join(names) or "nothing"})'
            self.say(f'Certificate refused: {error}')
            self.record('page', 'failed', tls_cert=str(cert), tls_key=str(key), error=error)
            return False
        self.say(f'Certificate {cert} and key pass the broker checks; valid until {not_after}.')
        self.record('page', 'ok', tls_cert=str(cert), tls_key=str(key), names=names, not_after=not_after)
        return True

    def check_tls(self, cert, key):
        """The broker's own load of the pair; then the names and expiry of the public certificate."""
        from .local_https import server_context
        try:
            server_context(cert, key)
        except FileNotFoundError:
            raise ValueError('the certificate or the key file does not exist') from None
        except PermissionError as exc:
            raise ValueError(str(exc)) from None
        except ssl.SSLError:
            raise ValueError('the certificate and key do not load: they do not match, or the key is '
                             'encrypted') from None
        except Exception as exc:
            raise ValueError(f'the certificate or key cannot be opened ({type(exc).__name__})') from None
        from cryptography import x509
        try:
            leaf = x509.load_pem_x509_certificates(cert.read_bytes()[:1024 * 1024])[0]
        except (OSError, ValueError, IndexError):
            raise ValueError('the certificate file is not PEM') from None
        try:
            extension = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = [*extension.get_values_for_type(x509.DNSName),
                     *(str(ip) for ip in extension.get_values_for_type(x509.IPAddress))]
        except x509.ExtensionNotFound:
            names = []
        not_after = leaf.not_valid_after_utc
        import datetime
        if not_after <= datetime.datetime.now(datetime.timezone.utc):
            raise ValueError(f'the certificate expired on {not_after:%Y-%m-%d}')
        return names, f'{not_after:%Y-%m-%d}'

    # ----- 4. access --------------------------------------------------------
    def origin_for_access(self):
        access = self.choice['access']
        if getattr(self.args, 'unlock_origin_explicit', False) and access != 'relay':
            return self.args.unlock_origin
        if access in ('tailscale', 'tunnel') and self.choice.get('tailscale_name'):
            port = self.choice['tailnet_port']
            return f'https://{self.choice["tailscale_name"]}' + ('' if port == 443 else f':{port}')
        return DEFAULT_ORIGIN

    def stage_access(self):
        access = self.choice['access']
        self.say(ACCESS_LINES[access])
        if access == 'decrypting':
            self.say(DECRYPTING_WARNING)
            self.choice['access'] = access = 'local'
            self.note('access', 'warnings', DECRYPTING_WARNING)
        relay_enabled = self._relay_enabled()
        if access == 'relay':
            return self._access_relay(relay_enabled)
        self.origin = self.origin_for_access()
        if (access in ('tailscale', 'tunnel') and not self.choice.get('tailscale_name')
                and not getattr(self.args, 'unlock_origin_explicit', False)):
            # No tailnet name and no explicit origin: say what is missing, not that loopback was refused.
            self.say('No tailnet name: give --tailscale-name with the full MagicDNS name, for example '
                     'node.tailnet.ts.net (tailscale status --json: Self.DNSName, without the final dot).')
            self.record('access', 'failed', access=access,
                        error='no tailnet name: give --tailscale-name with the full MagicDNS name '
                              '(tailscale status --json: Self.DNSName, without the final dot)')
            return False
        try:
            from .local_https import local_origin
            self.origin = local_origin(self.origin, self.choice.get('local_port')
                                       if access in ('tailscale', 'tunnel') else None)[0]
        except ValueError as exc:
            self.say(f'Origin refused: {exc}')
            self.record('access', 'failed', access=access, error=str(exc))
            return False
        if relay_enabled:
            self.step("The akdbx relay is enabled. The broker that setup configures uses --unlock-origin, but "
                      "other akdbx commands use the relay origin: run 'akdbx relay disable' (files are kept).",
                      'access')
        if self.origin != DEFAULT_ORIGIN:
            self.step(f'Set AKDBX_UNLOCK_ORIGIN={self.origin} in your private shell environment for every akdbx '
                      'command (or pass --unlock-origin before the subcommand).', 'access')
        if access == 'local':
            self.say(f'The page opens at {self.origin} on this computer only.')
            self.record('access', 'ok', access=access, origin=self.origin)
            return True
        return self._access_tailscale(access)

    def _relay_enabled(self):
        from .relay import RelayStore, RelayStoreError
        try:
            config = RelayStore().load()
        except RelayStoreError:
            return False
        return config is not None and config.enabled

    def _access_relay(self, enabled):
        from .relay import RelayStore, RelayStoreError
        self.say('Trust point: the relay operator controls the akdbx.link DNS zone and could get a second '
                 'certificate for your broker name; public Certificate Transparency logs would show it.')
        store = RelayStore()
        try:
            config = store.load()
            ready = config is not None and config.enabled and store.certificate(config.name) is not None
        except RelayStoreError as exc:
            self.say(f'The relay folder cannot be trusted: {exc}')
            self.step("Fix the relay folder permissions, or run 'akdbx relay disable --forget'.", 'access')
            self.record('access', 'failed', access='relay', error=str(exc))
            return False
        if ready:
            self.origin = config.origin
            self.say(f'The relay is already enabled: {config.origin}')
            self._warn_origin_variable()
            self.record('access', 'done', access='relay', origin=config.origin)
            return True
        argv = self.akdbx_argv('relay', 'enable', *(['--relay', self.args.relay_url] if self.args.relay_url else []))
        outcome = {}

        def enable():
            ok, result, error = self.run_json(argv, timeout=420)
            if not ok:
                raise RuntimeError(error)
            outcome.update(result or {})
        applied = self.change('access', 'register this broker at the akdbx relay and save its key and certificate '
                              'in the private relay folder', [shell_command(argv, self.windows)], enable,
                              selected=self.args.access == 'relay', key='access')
        if applied:
            self.origin = outcome.get('origin') or self.origin
            self.say(f'The private pages will open at {self.origin} on any device.')
            self._warn_origin_variable()
            self.record('access', 'changed', access='relay', origin=self.origin)
            return True
        if applied is None and not self.dry_run and not self.ui.interactive:
            self.say('Add --access relay to register this broker at the relay.')
        self.record('access', self.outcome(applied), access='relay')
        return False

    def _warn_origin_variable(self):
        """`serve --relay` ignores AKDBX_UNLOCK_ORIGIN, but every other akdbx command would still use it."""
        variable = (self.env.get('AKDBX_UNLOCK_ORIGIN') or '').rstrip('/')
        if variable and variable != self.origin:
            warning = (f'AKDBX_UNLOCK_ORIGIN is {variable}, not the relay origin {self.origin}: the broker uses the '
                       'relay, but other akdbx commands would expect that other page')
            self.note('access', 'warnings', warning)
            self.say('Warning: ' + warning + '.')
            self.step('Unset AKDBX_UNLOCK_ORIGIN wherever you set it: every akdbx command finds the relay origin '
                      'by itself.', 'access')

    def _access_tailscale(self, access):
        """Instructions only: setup never inspects or changes Tailscale, and the broker works on loopback."""
        port, local_port = self.choice['tailnet_port'], self.choice['local_port']
        if not self.choice.get('tailscale_name'):
            self.say('No tailnet name: give --tailscale-name with the full MagicDNS name, for example '
                     'node.tailnet.ts.net (tailscale status --json: Self.DNSName, without the final dot).')
            self.record('access', 'failed', access=access,
                        error='no tailnet name: give --tailscale-name with the full MagicDNS name '
                              '(tailscale status --json: Self.DNSName, without the final dot)')
            return False
        if access == 'tunnel' and port not in FUNNEL_PORTS:
            error = 'Tailscale Funnel accepts only ports 443, 8443 and 10000'
            self.say(error)
            self.record('access', 'failed', access=access, error=error)
            return False
        verb = 'serve' if access == 'tailscale' else 'funnel'
        target = f'https://127.0.0.1:{local_port}'
        command = shell_command(['tailscale', verb, '--bg', f'--https={port}', target], self.windows)
        self.say(f'The broker listens on {target} only. Setup does not check or change Tailscale.')
        if access == 'tunnel':
            self.say('Funnel publishes the page to the whole internet: only the secret link and the three-attempt '
                     'block protect it. Funnel accepts only ports 443, 8443 and 10000.')
            off = shell_command(['tailscale', 'funnel', f'--https={port}', 'off'], self.windows)
            check = f'{off} removes it'
            first = (f'first run tailscale funnel status; if port {port} already serves something else, choose '
                     'another --tailnet-port instead of replacing it (and update or remove --unlock-origin or '
                     'AKDBX_UNLOCK_ORIGIN if it names the old port); otherwise ')
        else:
            check = (f'then tailscale serve status must show {self.origin} (tailnet only) with / proxy {target}, '
                     'and no Funnel')
            first = (f'first run tailscale serve status: if it already shows {self.origin} (tailnet only) with / '
                     f'proxy {target} and no Funnel, nothing more is needed; if port {port} serves something else, '
                     'choose another --tailnet-port instead of replacing it (and update or remove --unlock-origin '
                     'or AKDBX_UNLOCK_ORIGIN if it names the old port); otherwise ')
        self.step(('' if self.windows else 'On Linux as root or as the Tailscale operator user: ')
                  + f'{first}run {command} yourself; {check}.', 'access')
        if self.windows:
            self.step('Make the Tailscale service trust your CA: as your user run Join-Path (mkcert -CAROOT) '
                      "'rootCA.pem', then in an elevated PowerShell run certutil -addstore -f Root with that exact "
                      'path. This changes the trust of the whole computer.', 'access')
        else:
            self.step('Make tailscaled trust your CA: mkcert -install adds it to the system store; then run '
                      'sudo systemctl restart tailscaled (this briefly drops tailnet connections).', 'access')
        self.record('access', 'todo', access=access, origin=self.origin, local_port=local_port)
        return True

    # ----- 5. start at login -----------------------------------------------
    def serve_argv(self, service=False):
        """The exact `akdbx serve` command for the chosen settings.

        ``service``: for the login unit or task, whose output a log keeps; the broker then prints no
        unlock link at start (`akdbx status` shows it).
        """
        access = self.choice['access']
        python = self.executable
        if self.windows and python.with_name('pythonw.exe').is_file():
            # No console window at logon; the unlock link comes from `akdbx status`.
            python = python.with_name('pythonw.exe')
        argv = [str(python), '-m', 'akdbx.cli']
        if self.socket_explicit:
            argv += ['--socket', str(self.socket)]
        if access != 'relay':
            # Explicit, so that an enabled relay cannot take over this broker.
            argv += ['--unlock-origin', self.origin]
        argv += ['serve', self.choice['vault']]
        if access == 'relay':
            # Refuse to start without the relay, instead of serving another origin.
            argv += ['--relay']
        if service:
            argv += ['--no-print-unlock-link']
        if self.choice.get('keyfile'):
            argv += ['--keyfile', self.choice['keyfile']]
        if access != 'relay':
            argv += ['--tls-cert', self.choice['tls_cert'], '--tls-key', self.choice['tls_key']]
            if access in ('tailscale', 'tunnel'):
                argv += ['--local-port', str(self.choice['local_port'])]
        # A fill route that --yes left out keeps its saved values: they belong to this login change.
        browsers, cdp = (self.state.get(key) if key in self.unselected else self.choice.get(key)
                         for key in ('browsers', 'cdp_profile'))
        if cdp:
            argv += ['--password-browser-profile', cdp, '--card-browser-profile', cdp]
        if browsers:
            argv += ['--default-fill-route', 'extension']
        return argv

    def stage_login(self, broker_ready):
        if not self.choice['start_at_login']:
            self.say('Not selected. Add --start-at-login to start the broker when you log in.')
            self.record('login', 'skipped', reason='not selected')
            return
        if not broker_ready:
            self.say('Waiting for the required parts above; the broker cannot start yet.')
            self.record('login', 'todo', reason='the vault, the page or the access stage is not ready')
            return
        broker = self.broker_status()
        if self.windows:
            self._login_windows(broker)
        else:
            self._login_linux(broker)

    def _login_linux(self, broker):
        path = self.unit_path()
        try:
            text = unit_text(self.serve_argv(service=True), [(name, self.env[name])
                                                             for name in ('DISPLAY', 'XAUTHORITY')
                                                             if self.env.get(name)])
        except ValueError as exc:
            self.record('login', 'failed', error=str(exc))
            return
        systemctl = self.tools.get('systemctl')
        current = self._read_own_file(path)
        if current is False:
            self.say(f'{path} exists and was not written by akdbx setup. Setup never replaces it.')
            self.step(f'Move {path} away or start the broker your own way: '
                      + shell_command(self.serve_argv(service=True), False), 'login')
            self.record('login', 'failed', unit=str(path), error='a unit that setup did not write exists')
            return
        if current != text:
            applied = self.change('login', f'write the systemd user unit {path}', text.rstrip('\n').splitlines(),
                                  lambda: self._write_unit(path, text), selected=True, key='start_at_login')
            if not applied:
                self.record('login', self.outcome(applied), unit=str(path))
                return
            if systemctl:
                self.run([systemctl, '--user', 'daemon-reload'], timeout=30)
        if not systemctl:
            self.step(f'This system has no systemctl: start the broker at login with your desktop session, using '
                      f'{shell_command(self.serve_argv(service=True), False)}', 'login')
            self.record('login', 'todo', unit=str(path))
            return
        enabled = self._unit_enabled(systemctl)
        if not enabled:
            applied = self.change('login', f'enable {SERVICE_NAME} so it starts at login',
                                  [f'{systemctl} --user enable {SERVICE_NAME}'],
                                  lambda: self._checked([systemctl, '--user', 'enable', SERVICE_NAME]), selected=True,
                                  key='start_at_login')
            if not applied:
                self.record('login', self.outcome(applied), unit=str(path))
                return
        if broker['running'] is False:
            applied = self.change('login', f'start {SERVICE_NAME} now (no broker runs yet)',
                                  [f'{systemctl} --user start {SERVICE_NAME}'],
                                  lambda: self._checked([systemctl, '--user', 'start', SERVICE_NAME]), selected=True)
            self.started_service = bool(applied)
        else:
            self.say('A broker already runs (or its check failed): setup does not start a second one. The service '
                     'starts at the next login.')
        changed = 'changed' in self.stages.get('login', {})
        self.service_ready = True
        self.record('login', 'changed' if changed else 'done', unit=str(path))

    def _read_own_file(self, path):
        """None when missing, the text when setup wrote it, False for anything else."""
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return False
        try:
            text = Path(path).read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            return False
        return text if text.startswith(f'# {MARKER}:') else False

    def _write_unit(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = path.with_name('.' + path.name + '.tmp')
        temporary.unlink(missing_ok=True)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
        if self._read_own_file(path) is False:
            temporary.unlink()
            raise ValueError(f'{path} appeared and was not written by setup')
        os.replace(temporary, path)

    def _unit_enabled(self, systemctl):
        try:
            result = self.run([systemctl, '--user', 'is-enabled', SERVICE_NAME], timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return result.stdout.strip() == 'enabled'

    def _checked(self, argv, timeout=60):
        result = self.run(argv, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout).strip()[-300:] or f'exit status {result.returncode}')
        return result

    def _login_windows(self, broker):
        argv = self.serve_argv(service=True)
        xml = task_xml(argv[0], subprocess.list2cmdline(argv[1:]), self._windows_user())
        path = self.task_path()
        schtasks = self.which('schtasks') or 'schtasks'
        query = self.run([schtasks, '/Query', '/TN', TASK_NAME, '/XML'], timeout=30)
        replace = False
        if query.returncode == 0:
            ours, command, arguments = task_action(query.stdout)
            if not ours:
                self.say(f'A task named {TASK_NAME} exists and was not made by akdbx setup. Setup never replaces it.')
                self.record('login', 'failed', task=TASK_NAME, error='a task that setup did not make exists')
                return
            if (command, arguments) == (argv[0], subprocess.list2cmdline(argv[1:])):
                self.say(f'The logon task {TASK_NAME} is already set up.')
                self.service_ready = True
                self._start_task(schtasks, broker)
                self.record('login', 'changed' if self.started_service else 'done', task=TASK_NAME)
                return
            replace = True
        create = [schtasks, '/Create', '/TN', TASK_NAME, '/XML', str(path)] + (['/F'] if replace else [])
        applied = self.change('login', f'{"replace" if replace else "create"} the logon task {TASK_NAME} for this '
                              'user (no elevation), from ' + str(path),
                              [*xml.rstrip('\n').splitlines(), shell_command(create, True)],
                              lambda: self._create_task(path, xml, create), selected=True, key='start_at_login')
        if not applied:
            self.record('login', self.outcome(applied), task=TASK_NAME)
            return
        self.service_ready = True
        self._start_task(schtasks, broker)
        self.record('login', 'changed', task=TASK_NAME, task_file=str(path))

    def _start_task(self, schtasks, broker):
        if broker['running'] is False:
            applied = self.change('login', f'start the task {TASK_NAME} now (no broker runs yet)',
                                  [shell_command([schtasks, '/Run', '/TN', TASK_NAME], True)],
                                  lambda: self._checked([schtasks, '/Run', '/TN', TASK_NAME]), selected=True)
            self.started_service = bool(applied)
        else:
            self.say('A broker already runs (or its check failed): setup does not start a second one.')

    def _create_task(self, path, xml, create):
        from .windows_security import ensure_private_directory, replace_private
        ensure_private_directory(path.parent)
        replace_private(path, xml.encode('utf-16'))
        self._checked(create)

    def _windows_user(self):
        try:
            import win32api
            import win32con
            return win32api.GetUserNameEx(win32con.NameSamCompatible)
        except Exception:
            domain, user = self.env.get('USERDOMAIN', ''), self.env.get('USERNAME', '')
            return f'{domain}\\{user}' if domain else user

    # ----- 6. fill route ----------------------------------------------------
    def stage_fill(self):
        browsers, cdp = self.choice.get('browsers') or [], self.choice.get('cdp_profile')
        if not browsers and not cdp:
            self.say('Not selected. Add --browser NAME (extension route, preferred) or --cdp-profile DIR.')
            self.record('fill', 'skipped', reason='not selected')
            return
        state = 'done'
        for browser in browsers:
            state = self._merge_state(state, self._install_host(browser))
        if browsers:
            if any(browser in CHROMIUM_BROWSERS for browser in browsers):
                state = self._merge_state(state, self._build_extension())
            if 'firefox' in browsers:
                state = self._merge_state(state, self._build_extension('firefox'))
        if cdp:
            state = self._merge_state(state, self._cdp(Path(cdp)))
        folders = {browser: str(self._extension_folder(browser)) for browser in browsers}
        primary = self.choice['extension_dir'] if any(b in CHROMIUM_BROWSERS for b in browsers) else folders.get('firefox')
        self.record('fill', state, browsers=browsers, extension_dir=primary,
                    extension_dirs=folders, cdp_profile=cdp)

    @staticmethod
    def _merge_state(current, new):
        order = ('done', 'ok', 'changed', 'planned', 'todo', 'failed')
        return max(current, new, key=order.index)

    def _install_host(self, browser):
        from .extension_host import LAUNCHER_LIMIT, _owned_manifest, _read_regular, expected_launcher, paths
        where = paths(browser)
        socket_path = str(self.socket) if self.socket_explicit else None
        try:
            expected = expected_launcher(browser, str(self.executable), socket_path).encode('utf-8')
            # Regular files only: a link at either path is never taken as installed.
            installed = (_read_regular(where['launcher'], LAUNCHER_LIMIT) == expected
                         and _owned_manifest(where['manifest'], where['launcher']))
            if installed and self.windows:
                import winreg
                from .extension_host import HOST_NAME, WINDOWS_KEYS
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, WINDOWS_KEYS[browser] + '\\' + HOST_NAME) as key:
                    installed = winreg.QueryValueEx(key, '')[0] == str(where['manifest'])
        except (OSError, ValueError):
            installed = False
        if installed:
            self.say(f'The extension host for {browser} is already installed.')
            return 'done'
        argv = self.akdbx_argv('extension', 'install', '--browser', browser)
        show = [shell_command(argv, self.windows), f'writes {where["launcher"]} and {where["manifest"]}'
                + (f' and {where["registry"]}' if 'registry' in where else '')]
        applied = self.change('fill', f'install the native-messaging host for {browser}', show,
                              lambda: self._akdbx_ok(argv), selected=True, key='browser:' + browser)
        return self.outcome(applied)

    def _akdbx_ok(self, argv, timeout=120):
        ok, _, error = self.run_json(argv, timeout=timeout)
        if not ok:
            raise RuntimeError(error)

    def _extension_folder(self, browser):
        return Path(self.choice['firefox_extension_dir' if browser == 'firefox' else 'extension_dir'])

    @staticmethod
    def _extension_format(folder):
        from .extension_host import EXTENSION_KEY, _read_regular
        try:
            data = _read_regular(folder / 'manifest.json', 64 * 1024)
            if data is None or len(data) > 64 * 1024:
                return None
            manifest = json.loads(data)
            if manifest.get('key') == EXTENSION_KEY:
                return 'chrome'
            if manifest.get('browser_specific_settings', {}).get('gecko', {}).get('id') == FIREFOX_EXTENSION_ID:
                return 'firefox'
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        return None

    def _remembered_extension_dir(self, browser):
        value = self.remembered('firefox_extension_dir' if browser == 'firefox' else 'extension_dir')
        if not value:
            return None
        folder = Path(value)
        # Older setup versions saved unused paths too. A known build on disk
        # takes precedence over a saved answer for the other format.
        return folder if self._extension_format(folder) in (None, browser) else None

    def _default_extension_folder(self, browser, other):
        base = self.default_extension_dir()
        name = 'chromium' if browser == 'chrome' else 'firefox'
        folder = (base if browser == 'chrome' or self._extension_format(base) == 'firefox'
                  else base.with_name(base.name + '-firefox'))
        for number in range(100):
            collision = other is not None and folder.resolve() == other.resolve()
            if not collision and self._extension_format(folder) in (None, browser):
                return folder
            suffix = '' if number == 0 else '-' + str(number + 1)
            folder = base.with_name(base.name + '-' + name + suffix)
        raise Refusal('no separate default extension folder is available; give --extension-dir')

    def _build_extension(self, browser='chrome'):
        from .extension_host import BUILD_ID, EXTENSION_KEY, built_version, trusted_origin
        folder = self._extension_folder(browser)
        try:
            origin = trusted_origin(self.origin)
            manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
            config = (folder / 'config.js').read_text(encoding='utf-8')
            # An unchanged folder is not rebuilt, so it keeps its build ID and the extension its saved trust.
            own = (manifest.get('browser_specific_settings', {}).get('gecko', {}).get('id') == FIREFOX_EXTENSION_ID
                   if browser == 'firefox' else manifest.get('key') == EXTENSION_KEY)
            built = (own and manifest.get('version') == built_version()
                     and f'globalThis.AKDBX_EXTENSION_VERSION = {json.dumps(built_version())};' in config
                     and json.dumps(origin) in config and BUILD_ID.search(config) is not None)
        except Exception:
            built = False
        argv = self.akdbx_argv('extension', 'build', '--output', str(folder), origin=self.origin)
        if browser == 'firefox':
            argv += ['--browser', 'firefox']
        result = 'done'
        if built:
            self.say(f'The extension {EXTENSION_VERSION} for {self.origin} is already built in {folder}.')
        else:
            applied = self.change('fill', f'write the unpacked fill extension {EXTENSION_VERSION} to {folder}',
                                  [shell_command(argv, self.windows)], lambda: self._akdbx_ok(argv), selected=True,
                                  key='browsers')
            result = self.outcome(applied)
            if not applied:
                return result
        if browser == 'firefox':
            self.step(f'Firefox 153 or newer: open about:debugging#/runtime/this-firefox, choose Load Temporary '
                      f'Add-on and select {folder / "manifest.json"}. The add-on ID is {FIREFOX_EXTENSION_ID}. '
                      'A temporary add-on must be loaded again after Firefox restarts. Permanent installation '
                      'requires a Mozilla-signed XPI.', 'fill')
        else:
            self.step(f'Load the extension once in each Chromium browser: open chrome://extensions, turn on Developer mode, '
                  f'choose Load unpacked and select {folder} (extension ID {EXTENSION_ID}). After an akdbx update, '
                  'setup rebuilds it: click reload on the akdbx card.', 'fill')
        self.step('Pair the extension once per browser session: click the akdbx toolbar button, choose Open the '
                  'pairing page, check that the page shows the same code, and enter the master password there.',
                  'fill')
        return result

    def _cdp(self, profile):
        self.say('CDP route: the broker fills a Chromium profile that runs with a debugging port. Any process of '
                 'your user can control that profile, and anti-bot checks often flag it (sign-in checks fail, '
                 'cards are declined). Prefer the extension route; keep CDP for secret capture.')
        if self.windows:
            browser = self.tools.get('browsers', {}).get('chrome') or 'chrome.exe'
        else:
            browser = next((self.tools.get('browsers', {}).get(b) for b in ('chrome', 'chromium', 'helium', 'edge')
                            if self.tools.get('browsers', {}).get(b)), 'google-chrome')
        launch = [browser, f'--user-data-dir={profile}', '--remote-debugging-port=0']
        self.step('Start that browser for the broker with: ' + ('' if self.windows else 'umask 077; ')
                  + shell_command(launch, self.windows) + ' (a non-default profile; port 0 writes DevToolsActivePort).',
                  'fill')
        if profile.is_dir():
            self.say(f'The CDP profile {profile} exists; the broker checks its permissions when it starts.')
            return 'done'
        show = [f'mkdir -m 700 {shlex.quote(str(profile))}' if not self.windows
                else f'create {profile} for this user and SYSTEM only']
        applied = self.change('fill', f'create the private CDP profile folder {profile}', show,
                              lambda: self._private_folder(profile), selected=True, key='cdp_profile')
        return self.outcome(applied)

    def _private_folder(self, path):
        if self.windows:
            from .windows_security import ensure_private_directory
            ensure_private_directory(path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.mkdir(mode=0o700)

    # ----- 7. optional features ---------------------------------------------
    def stage_features(self):
        self.say(NOTIFICATIONS)
        self.say("Optional Android device: run akdbx android setup to attach a device or create an on-demand Google Play emulator on Linux.")
        self.say('Merge: built into akdbx')
        details = {'merge_engine': native_merge.ENGINE}
        if not self.choice.get('capture_host'):
            self.say('Authenticator capture host: not selected (--capture-host).')
            self.record('features', 'ok', capture_host=False, **details)
            return
        state = self._capture()
        self.record('features', state, capture_host=True, **details)

    def _browser_import(self):
        name = 'akdbx-browser-import.exe' if self.windows else 'akdbx-browser-import'
        return Path(sysconfig.get_path('scripts')) / name

    def _capture(self):
        from .browser_import import config_path
        folder, browser = Path(self.choice['capture_dir']), self.choice['capture_browser']
        tool = self._browser_import()
        state = 'done'
        if (folder / 'manifest.json').is_file():
            self.say(f'The capture extension is already in {folder}.')
        else:
            argv = [tool, 'build-extension', folder]
            show = ([] if self.windows else ['mkdir -p -m 700 ' + shlex.quote(str(folder.parent))]) + [
                shell_command(argv, self.windows)]
            applied = self.change('features', f'write the unpacked capture extension to {folder}', show,
                                  lambda: self._build_capture(argv, folder), selected=True, key='capture_host')
            if not applied:
                return self.outcome(applied)
            state = 'changed'
        if os.path.lexists(config_path()):
            self.say(f'The capture host is already registered ({config_path()}); setup leaves it unchanged.')
            return state
        extension_id = self.choice.get('capture_extension_id')
        if not extension_id:
            self.step(f'Load {folder} unpacked in {browser} (chrome://extensions, Developer mode), copy its ID, then '
                      'run akdbx setup again with --capture-host --capture-extension-id ID.', 'features')
            return 'todo'
        argv = [tool, 'install-host', '--extension-id', extension_id, '--origin', self.origin]
        if self.windows:
            argv += ['--browser', browser]
            if self.socket_explicit:
                argv += ['--socket', str(self.socket) + '-capture']
        else:
            from .extension_host import linux_manifest_dir
            name = 'agentic-kdbx-unlock.sock' if Path(self.socket).name == 'agentic-kdbx.sock' else 'akdbx-unlock.sock'
            argv += ['--socket', Path(self.socket).with_name(name), '--manifest-dir', linux_manifest_dir(browser)]
        applied = self.change('features', f'register the capture native host for {browser}',
                              [shell_command(argv, self.windows)], lambda: self._checked(argv), selected=True,
                              key='capture_host')
        return self.outcome(applied)

    def _build_capture(self, argv, folder):
        """The builder never replaces an existing folder; it needs the parent folder, private to this user."""
        if self.windows:
            from .windows_security import ensure_private_directory
            ensure_private_directory(folder.parent)
        else:
            folder.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._checked(argv)

    # ----- 8. agent skill ---------------------------------------------------
    def skill_source(self):
        if self.args.skill_source:
            candidates = [Path(self.args.skill_source).expanduser()]
        else:
            candidates = [Path(__file__).resolve().parents[2] / 'skills' / 'akdbx']
            for scheme in (None, f'{os.name}_user'):
                try:
                    data = sysconfig.get_path('data', scheme) if scheme else sysconfig.get_path('data')
                except KeyError:
                    continue
                candidates.append(Path(data) / 'share' / 'akdbx' / 'skills' / 'akdbx')
        for candidate in candidates:
            if (candidate / 'SKILL.md').is_file():
                return candidate.absolute()
        return None

    def stage_skill(self):
        if not self.choice.get('link_skill'):
            self.say('Not selected (--link-skill).')
            self.record('skill', 'skipped', reason='not selected')
            return
        source = self.skill_source()
        if source is None:
            self.say("akdbx's skill folder was not found with this install; give --skill-source PATH "
                     '(a checkout\'s skills/akdbx).')
            self.record('skill', 'failed', error='no skill source')
            return
        if self.choice.get('skill_dirs'):
            folders = [Path(d) for d in self.choice['skill_dirs']]
        else:
            folders = [self.home / agent / 'skills' for agent in ('.claude', '.codex')
                       if (self.home / agent).is_dir()]
        if not folders:
            self.say('No agent skills folder found (~/.claude or ~/.codex); give --skill-dir PATH.')
            self.record('skill', 'todo', source=str(source))
            return
        state, links = 'done', []
        for folder in folders:
            target = folder / 'akdbx'
            current = link_target(target)
            if current == 'missing':
                kind = 'directory junction' if self.windows else 'symbolic link'
                applied = self.change('skill', f'link {target} to {source} ({kind})',
                                      [f'{target} -> {source}'], lambda t=target: self._link(source, t), selected=True,
                                      key='link_skill')
                result = self.outcome(applied)
            elif current != 'other' and same_folder(current[1], source):
                self.say(f'{target} already links to {source}.')
                result = 'done'
            else:
                self.say(f'{target} exists and is not a link to {source}. Setup never replaces it.')
                self.note('skill', 'errors', f'{target} exists and is a different link or folder')
                result = 'failed'
            links.append({'path': str(target), 'state': result})
            state = self._merge_state(state, result)
        self.record('skill', state, source=str(source), links=links)

    def _link(self, source, target):
        target.parent.mkdir(parents=True, exist_ok=True)
        self.link(source, target)

    # ----- 9. final check ---------------------------------------------------
    def wait_for_started_broker(self):
        """The broker status, after waiting for a broker that this run started to answer.

        A relay broker saves a relay port move before its socket listens, and
        its relay check can take up to the relay timeouts; until it answers,
        the saved origin may still be the old one.
        """
        broker = self.broker_status()
        if self.started_service and broker['running'] is False:
            for _ in range(150):  # up to 75 s: a just-started broker needs a moment for its socket
                self.sleep(0.5)
                broker = self.broker_status()
                if broker['running'] is not False:
                    break
        return broker

    def stage_final(self, broker_ready):
        broker = self.wait_for_started_broker()
        response = broker.get('response') or {}
        summary = {'ready': broker_ready, 'running': broker['running'], 'origin': self.origin}
        serve = self.serve_argv() if broker_ready else None
        if serve:
            summary['serve_command'] = shell_command(serve, self.windows)
        if broker['running'] is True:
            summary.update(version=response.get('version'), locked=response.get('locked'))
            self.say(f'The broker runs (version {response.get("version")}).')
            if response.get('unlock_blocked'):
                summary['unlock_blocked'] = True
                self.step('The unlock link is blocked after three failed attempts. Only if those attempts were '
                          'yours and you want a new link, run: akdbx new-unlock-link --user-confirmed', 'final')
            elif response.get('locked') and isinstance(response.get('unlock_url'), str):
                summary['unlock_url'] = response['unlock_url']
                self.say('It is locked. Open this private link and enter the master password there '
                         '(never in chat or a terminal):')
                self.ui.say('    ' + response['unlock_url'])
            elif response.get('locked') is False:
                self.say('It is unlocked.')
            for key in ('fill_routes', 'default_fill_route', 'extension_paired', 'relay'):
                if key in response:
                    summary[key] = response[key]
        elif broker['running'] == 'unknown':
            self.say(f'The broker check failed ({broker.get("error")}); a broker may run with other settings. '
                     'Run akdbx status.')
        elif serve and not self.service_ready:
            self.step('Start the broker in a terminal that stays open (it starts locked): '
                      + summary['serve_command'], 'final')
        elif serve:
            start = (f'schtasks /Run /TN {TASK_NAME}' if self.windows
                     else f'systemctl --user start {SERVICE_NAME}')
            self.step(f'Start the broker now with {start}, or log in again (it starts locked).', 'final')
        elif not serve:
            self.say('The broker cannot start yet: finish the steps above.')
        self.record('final', 'ok', **summary)
        return summary

    # ----- driver -----------------------------------------------------------
    def execute(self):
        self.ui.say(f'akdbx setup {__version__}' + (' (dry run: nothing changes)' if self.dry_run else ''))
        if self.state_problem:
            self.ui.say('Note: ' + self.state_problem)
        self.ui.say('\n' + TITLES['system'])
        if 'system' in self.args.skip:
            self.ui.say('  Skipped.')
            self.record('system', 'skipped')
            self.tools = {'browsers': {}}
            supported = self.windows or sys.platform.startswith('linux')
        else:
            supported = self.stage_system()
        if not supported:
            return self.summary(False)
        if self.ui.interactive:
            self.ui.say('\nAnswers (press Enter for the default in brackets)')
        self.collect()
        ready = True
        for name in ('vault', 'page', 'access'):
            self.ui.say('\n' + TITLES[name])
            if name in self.args.skip:
                self.ui.say('  Skipped.')
                self.record(name, 'skipped')
                if name == 'vault':
                    ready = False
                if name == 'access':
                    self.origin = self.origin_for_access()
                continue
            ok = getattr(self, 'stage_' + name)()
            if name in ('vault', 'page'):
                ready = ready and ok
        # A failed access stage (a refused origin, no tailnet name) blocks the broker, and the relay route
        # needs an enabled relay. Tailscale instructions (todo) do not: the broker works on loopback.
        access_state = self.stages.get('access', {}).get('state')
        if access_state == 'failed' or (self.choice['access'] == 'relay'
                                        and access_state not in ('done', 'changed')):
            ready = False
        for name in ('login', 'fill', 'features', 'skill'):
            self.ui.say('\n' + TITLES[name])
            if name in self.args.skip:
                self.ui.say('  Skipped.')
                self.record(name, 'skipped')
                continue
            if name == 'login':
                self.stage_login(ready)
                if self.started_service and self.choice['access'] == 'relay':
                    # Later stages build the extension for the origin the broker serves.
                    if self.wait_for_started_broker()['running'] is False:
                        browsers = self.choice['browsers']
                        formats = (['chrome'] if any(b in CHROMIUM_BROWSERS for b in browsers) else [])
                        formats += ['firefox'] if 'firefox' in browsers else []
                        for browser in formats:
                            argv = self.akdbx_argv('extension', 'build', '--output', str(self._extension_folder(browser)),
                                                  '--browser', browser)
                            build = shell_command(argv, self.windows)
                            self.step('The broker has not started yet. When it runs, build the extension again so it '
                                      f'uses the relay origin the broker serves: {build}', 'login')
            else:
                getattr(self, 'stage_' + name)()
        self.save_state()
        self.ui.say('\n' + TITLES['final'])
        broker = self.stage_final(ready)
        return self.summary(ready, broker)

    def summary(self, ready, broker=None):
        failed = [name for name, stage in self.stages.items() if stage.get('state') == 'failed'
                  or stage.get('errors')]
        result = {'ok': not failed, 'version': __version__, 'dry_run': self.dry_run,
                  'broker': broker or {'ready': ready, 'running': False}, 'stages': self.stages,
                  'user_steps': self.user_steps, 'commands_run': self.commands_run}
        self.ui.say('\nSummary')
        for name in (*STAGES, 'final'):
            if name in self.stages:
                self.ui.say(f'  {TITLES[name]}: {self.stages[name]["state"]}')
        if self.user_steps:
            self.ui.say('What remains for you:')
            for number, text in enumerate(self.user_steps, 1):
                self.ui.say(f'  {number}. {text}')
        if failed:
            self.ui.say('Failed or refused: ' + ', '.join(failed) + '. Fix them and run akdbx setup again.')
        return result


def run(args, *, status, ask=None, interactive=None, **options):
    """`akdbx setup`; ``status(origin)`` sends the CLI's peer-checked status request."""
    if interactive is None:
        try:
            interactive = sys.stdin.isatty() and not args.yes
        except (AttributeError, ValueError):
            interactive = False
    interactive = interactive and not args.yes
    out = sys.stderr if args.json else sys.stdout
    if not interactive and not args.yes and not args.dry_run:
        print('akdbx setup: no terminal to ask questions: add --yes to apply the selected changes, or --dry-run '
              'to show the plan', file=sys.stderr)
        return 2
    setup = Setup(args, ui=Prompter(interactive, out, ask), status=status, **options)
    try:
        result = setup.execute()
    except Refusal as exc:
        # Before any change: answers that cannot work together.
        print(f'akdbx setup: refused: {exc}', file=sys.stderr)
        if args.json:
            print(json.dumps({'ok': False, 'version': __version__, 'dry_run': args.dry_run, 'error': str(exc)},
                             indent=2))
        return 2
    except (KeyboardInterrupt, EOFError):
        print('\nakdbx setup stopped; nothing more was changed. Run it again to continue.', file=sys.stderr)
        return 130
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    return 0 if result['ok'] else 1
