"""`akdbx setup`: every stage with temporary homes, synthetic vaults and fakes.

No real browser, network, Tailscale, relay, systemd or Task Scheduler: every
external command goes to a recording fake runner. The akdbx commands that
setup runs (`extension install` and `extension build`) run in-process here,
so their real files land in the temporary home.
"""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest
from pykeepass import create_database

from akdbx import cli, extension_host, setup_cli
from akdbx.extension_route import EXTENSION_ID
from akdbx.persistence import VaultStore
from test_windows_unlock import certificates  # noqa: F401

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Linux paths and modes; Windows parts are native tests')
EXECUTABLE = str(Path(sys.executable).absolute())
LOCKED = {'ok': True, 'locked': True, 'version': '0.43.0', 'unlock_url': 'https://localhost:9443/?token=synthetic',
          'fill_routes': ['cdp', 'extension'], 'default_fill_route': 'extension'}


class Runner:
    """Records argv; answers like the real tools. akdbx commands run in-process."""

    def __init__(self, tools=None):
        self.calls = []
        self.enabled = False
        self.tools = tools or {}

    def __call__(self, argv, **options):
        argv = [str(part) for part in argv]
        self.calls.append((argv, options))
        if argv[1:3] == ['-m', 'akdbx.cli']:
            if 'relay' in argv:
                return self.done(json.dumps({'ok': True, 'origin': 'https://k3x7q2mbn5vd.akdbx.link:8443'}))
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli.main(argv[3:])
            return self.done(out.getvalue(), code)
        name = Path(argv[0]).name
        if name in self.tools:
            return self.tools[name](argv)
        if name == 'systemctl':
            if argv[2] == 'is-enabled':
                return self.done('enabled\n' if self.enabled else 'disabled\n', 0 if self.enabled else 1)
            if argv[2] == 'enable':
                self.enabled = True
            return self.done('')
        return self.done('')

    @staticmethod
    def done(stdout='', code=0, stderr=''):
        return subprocess.CompletedProcess([], code, stdout, stderr)

    def commands(self):
        return [argv for argv, _ in self.calls]


class Status:
    """Fake peer-checked status: no broker until the service starts."""

    def __init__(self, runner, running=False, response=LOCKED):
        self.runner, self.running, self.response, self.origins = runner, running, response, []

    def __call__(self, origin):
        self.origins.append(origin)
        started = any('start' in argv for argv in self.runner.commands() if Path(argv[0]).name == 'systemctl')
        if not (self.running or started):
            raise FileNotFoundError
        return dict(self.response)


@pytest.fixture(autouse=True)
def no_origin_variable(monkeypatch):
    # No test depends on the shell: parse() resolves the origin from the real environment.
    monkeypatch.delenv('AKDBX_UNLOCK_ORIGIN', raising=False)


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    for name in ('.config', '.local', '.claude', '.codex'):
        (home / name).mkdir(mode=0o700)
    monkeypatch.setenv('HOME', str(home))
    for name in ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'CHROME_CONFIG_HOME'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(tmp_path / 'run'))
    monkeypatch.setenv('DISPLAY', ':7')
    monkeypatch.setattr(setup_cli.Setup, '_engine_version', lambda self: None)
    return home


@pytest.fixture
def vault(tmp_path):
    folder = tmp_path / 'vaults'
    folder.mkdir(mode=0o700)
    path = folder / 'synthetic.kdbx'
    create_database(str(path), password='synthetic setup master')
    path.chmod(0o600)
    return path


@pytest.fixture
def pair(certificates):
    cert, key = certificates
    key.chmod(0o600)
    return cert, key


def which_for(*names):
    return lambda name: f'/usr/bin/{name}' if name in names else None


def parse(*argv, global_options=()):
    args = cli.parser().parse_args([*global_options, 'setup', *argv])
    cli.resolve_unlock_origin(args)
    args.socket_explicit = args.socket is not None
    args.socket = args.socket or cli.default_socket()
    return args


def setup(*argv, runner=None, status=None, which=None, ask=None, interactive=False, capsys=None, global_options=(),
          **options):
    runner = runner or Runner()
    status = status or Status(runner)
    args = parse(*argv, global_options=global_options)
    code = setup_cli.run(args, status=status, runner=runner, which=which or which_for('systemctl'),
                         ask=ask, interactive=interactive, executable=EXECUTABLE, sleep=lambda _: None, **options)
    result = json.loads(capsys.readouterr().out) if capsys is not None and args.json else None
    return code, result, runner


def base(vault, pair, *extra):
    return ('--yes', '--json', '--vault', str(vault), '--tls-cert', str(pair[0]), '--tls-key', str(pair[1]), *extra)


def test_without_a_terminal_it_needs_yes_or_dry_run(home, vault, capsys):
    code, _, runner = setup('--vault', str(vault))
    assert code == 2 and runner.calls == []
    assert '--yes' in capsys.readouterr().err


def test_a_non_interactive_run_sets_up_every_selected_stage(home, vault, pair, capsys):
    code, result, runner = setup(*base(vault, pair, '--start-at-login', '--browser', 'chrome', '--link-skill'),
                                 capsys=capsys)
    assert code == 0 and result['ok'], result
    stages = result['stages']
    assert stages['vault']['state'] == 'ok' and stages['vault']['writes'] is True
    assert stages['page']['state'] == 'ok' and set(stages['page']['names']) >= {'localhost', '127.0.0.1'}
    assert stages['access'] == {'state': 'ok', 'access': 'local', 'origin': 'https://localhost:9443'}
    assert stages['login']['state'] == 'changed'
    assert stages['fill']['state'] == 'changed' and stages['skill']['state'] == 'changed'
    unit = (home / '.config/systemd/user/akdbx.service').read_text()
    assert unit.startswith('# akdbx-setup:')
    assert (f'ExecStart="@{EXECUTABLE}" "{EXECUTABLE}" "-m" "akdbx.cli" "--unlock-origin" "https://localhost:9443" '
            f'"serve" "{vault}" "--no-print-unlock-link" "--tls-cert" "{pair[0]}" "--tls-key" "{pair[1]}" '
            '"--default-fill-route" "extension"') in unit
    assert 'Environment="DISPLAY=:7"' in unit and 'UnsetEnvironment=AKDBX_UNLOCK_ORIGIN' in unit
    assert stat.S_IMODE((home / '.config/systemd/user/akdbx.service').stat().st_mode) == 0o600
    commands = [argv[1:] for argv in runner.commands() if argv[0].endswith('systemctl')]
    assert commands == [['--user', 'daemon-reload'], ['--user', 'is-enabled', 'akdbx.service'],
                        ['--user', 'enable', 'akdbx.service'], ['--user', 'start', 'akdbx.service']]
    # The real extension commands wrote their files into the temporary home.
    manifest = home / '.config/google-chrome/NativeMessagingHosts/org.akdbx.extension.json'
    assert json.loads(manifest.read_text())['path'].endswith('chrome.sh')
    built = home / '.local/share/akdbx/extension'
    assert '"https://localhost:9443"' in (built / 'config.js').read_text()
    link = home / '.claude/skills/akdbx'
    assert link.is_symlink() and (link / 'SKILL.md').is_file()
    assert (home / '.codex/skills/akdbx').is_symlink()
    # The final check prints the broker's own private link, and the summary is complete.
    assert result['broker']['unlock_url'] == LOCKED['unlock_url'] and result['broker']['running'] is True
    assert any('Load unpacked' in step for step in result['user_steps'])
    state = home / '.config/akdbx/setup.json'
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    saved = json.loads(state.read_text())
    assert saved['vault'] == str(vault) and saved['browsers'] == ['chrome'] and saved['start_at_login'] is True
    assert 'synthetic setup master' not in state.read_text() + json.dumps(result)


def test_running_setup_again_changes_nothing(home, vault, pair, capsys):
    options = base(vault, pair, '--start-at-login', '--browser', 'edge', '--link-skill')
    first = Runner()
    setup(*options, runner=first, capsys=capsys)
    config = home / '.local/share/akdbx/extension/config.js'
    built = config.read_text()
    assert extension_host.BUILD_ID.search(built)
    second = Runner()
    second.enabled = True
    # The service started the broker after the first run. The flags select the same changes again; the
    # vault and certificate paths come from the saved answers.
    code, result, runner = setup('--yes', '--json', '--start-at-login', '--browser', 'edge', '--link-skill',
                                 runner=second, status=Status(second, running=True), capsys=capsys)
    assert code == 0, result
    assert {name: result['stages'][name]['state'] for name in ('login', 'fill', 'skill')} == {
        'login': 'done', 'fill': 'done', 'skill': 'done'}
    # The unchanged extension was not rebuilt: it keeps its build ID, so the browser keeps its broker trust.
    assert config.read_text() == built
    # Only read-only checks ran.
    assert [argv[1:] for argv in runner.commands()] == [['--user', 'is-enabled', 'akdbx.service']]


def test_setup_rebuilds_a_folder_whose_config_js_names_another_build(home, vault, pair, capsys):
    """A build that stopped after the manifest leaves config.js with the old version: not built yet."""
    setup(*base(vault, pair, '--browser', 'edge'), runner=Runner(), capsys=capsys)
    config = home / '.local/share/akdbx/extension/config.js'
    version = extension_host.built_version()
    stamp = f'globalThis.AKDBX_EXTENSION_VERSION = "{version}";'
    assert stamp in config.read_text()
    config.write_text(config.read_text().replace(stamp, 'globalThis.AKDBX_EXTENSION_VERSION = "0.0.1.1";'))
    second = Runner()
    second.enabled = True
    code, result, _ = setup('--yes', '--json', '--browser', 'edge', runner=second,
                            status=Status(second, running=True), capsys=capsys)
    assert code == 0, result
    assert stamp in config.read_text()


def test_with_yes_only_the_flags_of_this_run_select_a_change(home, vault, pair, tmp_path, capsys):
    # M2: saved answers give paths and ports; they never select a change under --yes.
    profile = tmp_path / 'cdp-profile'
    state = home / '.config/akdbx/setup.json'
    setup(*base(vault, pair), capsys=capsys)
    saved = json.loads(state.read_text())
    saved.update(start_at_login=True, browsers=['chrome'], cdp_profile=str(profile), capture_host=True,
                 link_skill=True, access='relay')
    state.write_text(json.dumps(saved))
    runner = Runner()
    code, result, _ = setup('--yes', '--json', runner=runner, capsys=capsys)
    assert runner.calls == [], runner.calls
    assert not (home / '.config/systemd').exists() and not profile.exists()
    assert not (home / '.claude/skills').exists() and not (home / '.local/share/akdbx').exists()
    assert {result['stages'][name]['state'] for name in ('login', 'fill', 'skill')} == {'skipped'}
    assert result['stages']['access']['state'] == 'todo' and result['stages']['features']['capture_host'] is False
    # The answers that this run did not decide stay saved for the next interactive run.
    again = json.loads(state.read_text())
    assert again['start_at_login'] is True and again['browsers'] == ['chrome'] and again['link_skill'] is True


def test_with_yes_a_login_change_keeps_the_saved_fill_values(home, vault, pair, tmp_path, capsys):
    # N1: --start-at-login alone keeps the saved fill route and CDP profile in the unit it writes.
    profile = tmp_path / 'cdp-profile'
    setup(*base(vault, pair, '--start-at-login', '--browser', 'chrome', '--cdp-profile', str(profile)), capsys=capsys)
    unit = home / '.config/systemd/user/akdbx.service'
    first = unit.read_text()
    assert '"--default-fill-route" "extension"' in first and f'"--password-browser-profile" "{profile}"' in first
    runner = Runner()
    runner.enabled = True
    code, result, _ = setup('--yes', '--json', '--start-at-login', runner=runner,
                            status=Status(runner, running=True), capsys=capsys)
    assert code == 0, result
    assert unit.read_text() == first and result['stages']['login']['state'] == 'done'
    assert result['stages']['fill']['state'] == 'skipped'
    assert '--default-fill-route extension' in result['broker']['serve_command']
    assert ['/usr/bin/systemctl', '--user', 'daemon-reload'] not in runner.commands()


def test_with_yes_an_unselected_capture_host_keeps_its_saved_values(home, vault, pair, tmp_path, capsys):
    # N2: a later run that leaves the capture host out does not lose its browser, folder or ID.
    values = {'capture_browser': 'edge', 'capture_dir': str(tmp_path / 'capture'), 'capture_extension_id': 'b' * 32}
    setup(*base(vault, pair, '--capture-host', '--capture-browser', 'edge', '--capture-dir', values['capture_dir'],
                '--capture-extension-id', values['capture_extension_id']), capsys=capsys)
    state = home / '.config/akdbx/setup.json'
    assert {key: json.loads(state.read_text())[key] for key in values} == values
    code, result, runner = setup('--yes', '--json', capsys=capsys)
    assert result['stages']['features']['capture_host'] is False and runner.calls == []
    saved = json.loads(state.read_text())
    assert saved['capture_host'] is True and {key: saved[key] for key in values} == values


def test_a_socket_under_home_is_expanded_once_for_the_status_check_and_the_unit(home, vault, pair, monkeypatch,
                                                                                 capsys):
    # N7: the CLI's status callback and the written commands use the same absolute path.
    seen = []

    def request(socket_path, payload, **options):
        seen.append(socket_path)
        raise FileNotFoundError
    monkeypatch.setattr(cli, 'request', request)
    socket = home / 'sockets' / 'broker.sock'
    code = cli.main(['--socket', '~/sockets/broker.sock', 'setup', '--dry-run', '--json', '--skip', 'system',
                     '--vault', str(vault), '--tls-cert', str(pair[0]), '--tls-key', str(pair[1]),
                     '--start-at-login'])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert seen and set(seen) == {socket}
    assert f'"--socket" "{socket}"' in captured.err and '~/sockets' not in captured.out + captured.err


def test_a_declined_change_is_never_saved_as_selected(home, vault, pair, capsys):
    # M2: at a terminal, a selection whose change was declined is saved as not selected.
    answers = iter([
        str(vault), '',      # vault, no key file
        '1',                 # local
        'y',                 # start at login
        'chrome',            # extension browser
        '',                  # no CDP profile
        '',                  # no capture host
        'y',                 # link the skill
        'n',                 # decline the unit
        'n',                 # decline the host install
        'n',                 # decline the extension build
        'n', 'n',            # decline both skill links
    ])
    code, _, runner = setup('--tls-cert', str(pair[0]), '--tls-key', str(pair[1]), ask=lambda: next(answers),
                            interactive=True)
    capsys.readouterr()
    assert next(answers, None) is None
    saved = json.loads((home / '.config/akdbx/setup.json').read_text())
    assert saved['start_at_login'] is False and saved['browsers'] == [] and saved['link_skill'] is False


def test_dry_run_changes_nothing(home, vault, pair, capsys):
    code, result, runner = setup('--dry-run', '--json', '--vault', str(vault), '--tls-cert', str(pair[0]),
                                 '--tls-key', str(pair[1]), '--start-at-login', '--browser', 'chrome',
                                 '--link-skill', capsys=capsys)
    assert code == 0 and result['dry_run'] is True
    assert runner.commands() == []
    assert {result['stages'][name]['state'] for name in ('login', 'fill', 'skill')} == {'planned'}
    assert not (home / '.config/systemd').exists() and not (home / '.config/akdbx').exists()
    assert not (home / '.claude/skills').exists()


def test_a_unit_that_setup_did_not_write_is_never_replaced(home, vault, pair, capsys):
    unit = home / '.config/systemd/user/akdbx.service'
    unit.parent.mkdir(parents=True)
    unit.write_text('[Service]\nExecStart=/usr/bin/true\n')
    code, result, runner = setup(*base(vault, pair, '--start-at-login'), capsys=capsys)
    assert code == 1 and result['stages']['login']['state'] == 'failed'
    assert unit.read_text() == '[Service]\nExecStart=/usr/bin/true\n'
    assert not any('enable' in argv for argv in runner.commands())


def test_a_running_broker_is_never_started_twice(home, vault, pair, capsys):
    runner = Runner()
    code, result, _ = setup(*base(vault, pair, '--start-at-login'), runner=runner,
                            status=Status(runner, running=True), capsys=capsys)
    assert code == 0
    assert ['/usr/bin/systemctl', '--user', 'enable', 'akdbx.service'] in runner.commands()
    assert not any(argv[-2:] == ['start', 'akdbx.service'] for argv in runner.commands())


def test_a_broker_check_that_fails_is_not_treated_as_stopped(home, vault, pair, capsys):
    runner = Runner()

    def status(origin):
        raise PermissionError('socket owned by another user')
    code, result, _ = setup(*base(vault, pair, '--start-at-login'), runner=runner, status=status, capsys=capsys)
    assert result['broker']['running'] == 'unknown'
    assert not any(argv[-2:] == ['start', 'akdbx.service'] for argv in runner.commands())


def test_without_selection_the_optional_stages_change_nothing(home, vault, pair, capsys):
    code, result, runner = setup(*base(vault, pair), capsys=capsys)
    assert code == 0 and runner.calls == []
    assert {result['stages'][name]['state'] for name in ('login', 'fill', 'skill')} == {'skipped'}
    assert result['broker']['ready'] is True and result['broker']['running'] is False
    assert any(step.startswith('Start the broker in a terminal') and 'serve' in step for step in result['user_steps'])


def test_stages_can_be_skipped(home, vault, pair, capsys):
    code, result, runner = setup(*base(vault, pair, '--browser', 'chrome', '--skip', 'fill', '--skip', 'system'),
                                 capsys=capsys)
    assert result['stages']['fill'] == {'state': 'skipped'} and result['stages']['system'] == {'state': 'skipped'}
    assert runner.calls == []


# ----- vault ------------------------------------------------------------------

def test_a_missing_vault_is_refused_and_never_created(home, tmp_path, pair, capsys):
    missing = tmp_path / 'vaults-missing' / 'new.kdbx'
    code, result, _ = setup(*base(missing, pair), capsys=capsys)
    assert code == 1 and result['stages']['vault']['state'] == 'failed'
    assert 'never creates' in result['stages']['vault']['error'] and not missing.exists()
    assert result['broker']['ready'] is False


def test_no_vault_without_a_question_fails_with_the_flag_to_use(home, pair, capsys):
    code, result, _ = setup('--yes', '--json', capsys=capsys)
    assert code == 1 and '--vault' in result['stages']['vault']['error']


def test_the_broker_vault_checks_report_unsafe_saves(home, vault, pair, capsys):
    vault.parent.chmod(0o770)
    try:
        code, result, _ = setup(*base(vault, pair), capsys=capsys)
    finally:
        vault.parent.chmod(0o700)
    assert result['stages']['vault']['writes'] is False
    assert 'another user' in result['stages']['vault']['writes_problem']


def test_a_directory_or_missing_key_file_is_refused(home, vault, pair, tmp_path, capsys):
    code, result, _ = setup(*base(vault, pair, '--keyfile', str(tmp_path / 'absent.key')), capsys=capsys)
    assert result['stages']['vault']['error'] == 'the key file does not exist'
    code, result, _ = setup(*base(vault, pair, '--keyfile', str(tmp_path)), capsys=capsys)
    assert result['stages']['vault']['error'] == 'key file must be a regular file'


def test_the_vault_check_never_opens_the_file(vault, monkeypatch):
    opened = []
    real_open = os.open

    def tracking(path, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(os, 'open', tracking)
    assert VaultStore(vault).check_location() is None
    assert vault.name not in opened


def test_a_vault_link_to_a_directory_is_refused(home, tmp_path, pair, capsys):
    folder = tmp_path / 'vaults'
    folder.mkdir(mode=0o700)
    (folder / 'dir.kdbx').mkdir()
    code, result, _ = setup(*base(folder / 'dir.kdbx', pair), capsys=capsys)
    assert 'unsafe vault file' in result['stages']['vault']['error']


# ----- local page -------------------------------------------------------------

def test_a_readable_tls_key_is_refused_by_the_broker_check(home, vault, pair, capsys):
    pair[1].chmod(0o640)
    code, result, _ = setup(*base(vault, pair), capsys=capsys)
    assert code == 1 and "mode 0600" in result['stages']['page']['error']


def test_mkcert_without_a_ca_leaves_the_trust_change_to_the_user(home, vault, tmp_path, capsys):
    tools = {'mkcert': lambda argv: Runner.done(str(tmp_path / 'no-ca') + '\n')}
    runner = Runner(tools)
    code, result, _ = setup('--yes', '--json', '--vault', str(vault), '--create-cert', runner=runner,
                            which=which_for('mkcert'), capsys=capsys)
    assert runner.commands() == [['/usr/bin/mkcert', '-CAROOT']]
    assert result['stages']['page']['state'] == 'todo'
    assert any('/usr/bin/mkcert -install' in step and 'trust' in step for step in result['user_steps'])


def test_mkcert_issues_the_certificate_after_the_user_installed_the_ca(home, vault, tmp_path, certificates, capsys):
    ca = tmp_path / 'ca'
    ca.mkdir()
    (ca / 'rootCA.pem').write_text('public CA')

    def mkcert(argv):
        if argv[1] == '-CAROOT':
            return Runner.done(str(ca) + '\n')
        cert, key = Path(argv[2]), Path(argv[4])
        cert.write_bytes(certificates[0].read_bytes())
        key.write_bytes(certificates[1].read_bytes())
        key.chmod(0o600)
        return Runner.done()
    runner = Runner({'mkcert': mkcert})
    code, result, _ = setup('--yes', '--json', '--vault', str(vault), '--create-cert', runner=runner,
                            which=which_for('mkcert'), capsys=capsys)
    assert code == 0 and result['stages']['page']['state'] == 'ok', result
    issue = runner.calls[1]
    folder = home / '.config/akdbx/tls'
    assert issue[0] == ['/usr/bin/mkcert', '-cert-file', str(folder / 'localhost.pem'), '-key-file',
                        str(folder / 'localhost-key.pem'), 'localhost', '127.0.0.1']
    assert issue[1]['umask'] == 0o077 and stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert '-install' not in sum(runner.commands(), [])


def test_without_create_cert_the_certificate_is_only_planned(home, vault, tmp_path, capsys):
    (tmp_path / 'ca').mkdir()
    (tmp_path / 'ca' / 'rootCA.pem').write_text('public CA')
    runner = Runner({'mkcert': lambda argv: Runner.done(str(tmp_path / 'ca'))})
    code, result, _ = setup('--yes', '--json', '--vault', str(vault), runner=runner, which=which_for('mkcert'),
                            capsys=capsys)
    assert runner.commands() == [['/usr/bin/mkcert', '-CAROOT']]
    assert result['stages']['page']['state'] == 'todo' and result['broker']['ready'] is False


# ----- access -----------------------------------------------------------------

def test_tailscale_access_prints_the_serve_command_and_never_runs_tailscale(home, vault, pair, capsys):
    # N3: no inspection, no configuration; the instruction is todo and does not block the login stage.
    # Without a tailnet name setup cannot build the command; it asks no tool for one.
    runner = Runner()
    code, result, _ = setup(*base(vault, pair, '--access', 'tailscale'), runner=runner,
                            which=which_for('tailscale'), capsys=capsys)
    assert result['stages']['access']['state'] == 'failed' and runner.calls == []
    # The short name from plain 'tailscale status' is not enough: ask for the full MagicDNS name.
    assert 'Self.DNSName' in result['stages']['access'].get('error', '') or any(
        'Self.DNSName' in note for note in result.get('notes', []) + result.get('user_steps', []))
    runner = Runner()
    code, result, _ = setup(*base(vault, pair, '--access', 'tailscale', '--tailscale-name', 'node.tailnet.ts.net',
                                  '--start-at-login'), runner=runner,
                            which=which_for('tailscale', 'systemctl'), capsys=capsys)
    assert code == 0, result
    assert not any(Path(argv[0]).name == 'tailscale' for argv in runner.commands())
    access = result['stages']['access']
    assert access['origin'] == 'https://node.tailnet.ts.net:9443' and access['state'] == 'todo'
    # The status check comes before the command, so an existing route on that port is never replaced.
    step = next(step for step in result['user_steps'] if 'tailscale serve --bg' in step)
    assert step.index('first run tailscale serve status') < step.index('run tailscale serve --bg')
    assert 'choose another --tailnet-port instead of replacing it' in step
    assert 'update or remove --unlock-origin or AKDBX_UNLOCK_ORIGIN if it names the old port' in step
    assert any('run tailscale serve --bg --https=9443 https://127.0.0.1:9444 yourself' in step
               and 'tailscale serve status must show https://node.tailnet.ts.net:9443 (tailnet only)' in step
               and 'no Funnel' in step for step in result['user_steps'])
    assert any('AKDBX_UNLOCK_ORIGIN=https://node.tailnet.ts.net:9443' in step for step in result['user_steps'])
    assert result['stages']['login']['state'] == 'changed' and result['broker']['ready'] is True
    unit = (home / '.config/systemd/user/akdbx.service').read_text()
    assert '"--unlock-origin" "https://node.tailnet.ts.net:9443"' in unit and '"--local-port" "9444"' in unit
    assert result['broker']['serve_command'].endswith('--local-port 9444')
    with pytest.raises(SystemExit):
        parse('--configure-tailscale')


def test_an_explicit_localhost_origin_is_not_reported_as_a_missing_name(home, vault, pair, capsys):
    # The origin is explicit, so the problem is the loopback origin with a proxy port, not a missing name.
    code, result, _ = setup(*base(vault, pair, '--access', 'tailscale'), runner=Runner(),
                            global_options=('--unlock-origin', 'https://localhost:9443'),
                            which=which_for('tailscale'), capsys=capsys)
    access = result['stages']['access']
    assert access['state'] == 'failed' and 'no tailnet name' not in access.get('error', '')


def test_a_proxy_origin_needs_a_certificate_for_127_0_0_1(home, vault, tmp_path, capsys):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'only-localhost.pem', tmp_path / 'only-localhost-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_path.chmod(0o600)
    code, result, _ = setup(*base(vault, (cert_path, key_path), '--access', 'tailscale',
                                  '--tailscale-name', 'node.tailnet.ts.net'), capsys=capsys)
    assert 'does not name 127.0.0.1' in result['stages']['page']['error']


def test_the_relay_runs_the_existing_relay_enable(home, vault, capsys):
    runner = Runner()
    code, result, _ = setup('--yes', '--json', '--vault', str(vault), '--access', 'relay', '--start-at-login',
                            '--relay-url', 'https://relay.example.test:8443', runner=runner, capsys=capsys)
    assert code == 0, result
    assert [EXECUTABLE, '-m', 'akdbx.cli', 'relay', 'enable', '--relay',
            'https://relay.example.test:8443'] in runner.commands()
    assert result['stages']['page']['state'] == 'skipped'
    assert result['stages']['access']['origin'] == 'https://k3x7q2mbn5vd.akdbx.link:8443'
    unit = (home / '.config/systemd/user/akdbx.service').read_text()
    assert '"serve"' in unit and '--tls-cert' not in unit and '--unlock-origin' not in unit
    assert 'UnsetEnvironment=AKDBX_UNLOCK_ORIGIN' in unit
    # It refuses to start without the relay, and keeps the link out of the journal.
    assert '"--relay"' in unit and '"--no-print-unlock-link"' in unit


def test_an_inherited_origin_variable_only_warns_for_the_relay(home, vault, monkeypatch, capsys):
    # N4: serve --relay ignores AKDBX_UNLOCK_ORIGIN, so the unit works; other commands would still use it.
    monkeypatch.setenv('AKDBX_UNLOCK_ORIGIN', 'https://node.tailnet.ts.net:9443')
    runner = Runner()
    code, result, _ = setup('--yes', '--json', '--vault', str(vault), '--access', 'relay', '--start-at-login',
                            runner=runner, capsys=capsys)
    access = result['stages']['access']
    assert code == 0 and access['state'] == 'changed', result
    assert 'AKDBX_UNLOCK_ORIGIN is https://node.tailnet.ts.net:9443, not the relay origin' in access['warnings'][0]
    assert any(step.startswith('Unset AKDBX_UNLOCK_ORIGIN') for step in result['user_steps'])
    assert result['stages']['login']['state'] == 'changed'
    assert '"--relay"' in (home / '.config/systemd/user/akdbx.service').read_text()


def test_on_windows_an_inherited_origin_variable_does_not_block_the_relay_task(tmp_path):
    # N4: the logon task inherits the variable, and serve --relay ignores it.
    windows = windows_setup(tmp_path, Runner())
    windows.origin = 'https://k3x7q2mbn5vd.akdbx.link:8443'
    windows.env['AKDBX_UNLOCK_ORIGIN'] = windows.origin + '/'
    windows._warn_origin_variable()
    assert 'access' not in windows.stages
    windows.env['AKDBX_UNLOCK_ORIGIN'] = 'https://localhost:9443'
    windows._warn_origin_variable()
    assert windows.stages['access'].get('state') != 'failed' and windows.stages['access']['warnings']


def test_a_public_tunnel_is_instructions_only(home, vault, pair, capsys):
    runner = Runner()
    name = ('--tailscale-name', 'node.tailnet.ts.net')
    code, result, _ = setup(*base(vault, pair, '--access', 'tunnel', *name), runner=runner,
                            which=which_for('tailscale'), capsys=capsys)
    assert result['stages']['access']['origin'] == 'https://node.tailnet.ts.net:8443'
    assert runner.calls == []
    assert any('tailscale funnel --bg --https=8443 https://127.0.0.1:9444' in step
               and 'tailscale funnel --https=8443 off' in step for step in result['user_steps'])
    code, result, _ = setup(*base(vault, pair, '--access', 'tunnel', '--tailnet-port', '9443', *name),
                            runner=runner, which=which_for('tailscale'), capsys=capsys)
    assert 'Funnel accepts only' in result['stages']['access']['error']


def test_a_decrypting_proxy_is_warned_about_and_not_configured(home, vault, pair, capsys):
    code, result, runner = setup(*base(vault, pair, '--access', 'decrypting'), capsys=capsys)
    access = result['stages']['access']
    assert access['access'] == 'local' and access['origin'] == 'https://localhost:9443'
    assert 'can read the master password' in access['warnings'][0]
    assert runner.calls == []


def test_an_explicit_origin_gives_the_tailnet_name_and_port(home, vault, pair, capsys):
    # M13: the Serve port and the origin cannot disagree.
    origin = ('--unlock-origin', 'https://node.tailnet.ts.net:8443')
    code, result, _ = setup(*base(vault, pair, '--access', 'tailscale'), which=which_for('tailscale'),
                            global_options=origin, capsys=capsys)
    assert result['stages']['access']['origin'] == 'https://node.tailnet.ts.net:8443'
    assert any('tailscale serve --bg --https=8443 https://127.0.0.1:9444' in step for step in result['user_steps'])
    code, result, runner = setup(*base(vault, pair, '--access', 'tailscale', '--tailnet-port', '9443'),
                                 global_options=origin, capsys=capsys)
    assert code == 2 and result['ok'] is False and runner.calls == []
    assert '--tailnet-port 9443 does not match the explicit unlock origin' in result['error']
    code, result, _ = setup(*base(vault, pair, '--access', 'tailscale', '--tailscale-name', 'other.ts.net'),
                            global_options=origin, capsys=capsys)
    assert code == 2 and '--tailscale-name other.ts.net does not match' in result['error']


def test_only_one_of_the_certificate_and_key_is_refused(home, vault, pair, capsys):
    # M9: a clear refusal with exit status 2, also in --json.
    code, result, runner = setup('--yes', '--json', '--vault', str(vault), '--tls-cert', str(pair[0]),
                                 capsys=capsys)
    assert code == 2 and result['ok'] is False and runner.calls == []
    assert '--tls-cert and --tls-key together' in result['error']
    code, _, _ = setup('--yes', '--vault', str(vault), '--tls-key', str(pair[1]))
    assert code == 2 and '--tls-cert and --tls-key together' in capsys.readouterr().err


def test_a_relative_socket_becomes_absolute_in_the_unit_and_the_host(home, vault, pair, tmp_path, monkeypatch,
                                                                     capsys):
    # M6: the unit and the extension launcher run from another folder.
    monkeypatch.chdir(tmp_path)
    socket = tmp_path / 'sockets' / 'broker.sock'
    code, result, runner = setup(*base(vault, pair, '--start-at-login', '--browser', 'chrome'),
                                 global_options=('--socket', 'sockets/broker.sock'), capsys=capsys)
    assert code == 0, result
    unit = (home / '.config/systemd/user/akdbx.service').read_text()
    assert f'"--socket" "{socket}"' in unit and '"sockets/broker.sock"' not in unit
    launcher = home / '.local/share/akdbx/extension-host/chrome.sh'
    assert f'--socket {socket} ' in launcher.read_text()
    assert all('sockets/broker.sock' not in argv for argv in runner.commands())


def test_capture_only_setup_on_a_fresh_install_creates_the_private_parent(home, vault, pair, capsys):
    # M8: ~/.local/share/akdbx does not exist yet; the real builder never replaces a folder.
    from akdbx.browser_import import build_extension

    def build(argv):
        try:
            build_extension(Path(argv[2]))
        except OSError as exc:
            return Runner.done('', 1, str(exc))
        return Runner.done()
    assert not (home / '.local/share').exists()
    runner = Runner({'akdbx-browser-import': build})
    code, result, _ = setup(*base(vault, pair, '--capture-host'), runner=runner, capsys=capsys)
    capture = home / '.local/share/akdbx/capture-extension'
    assert result['stages']['features']['state'] == 'todo', result['stages']['features']
    assert (capture / 'manifest.json').is_file()
    assert stat.S_IMODE(capture.parent.stat().st_mode) == 0o700
    # An existing destination is still never replaced.
    (capture / 'manifest.json').unlink()
    code, result, _ = setup(*base(vault, pair, '--capture-host'), runner=runner, capsys=capsys)
    assert result['stages']['features']['state'] == 'failed'


# ----- fill route, features, skill --------------------------------------------

def test_the_cdp_route_explains_the_tradeoff_and_creates_a_private_profile(home, vault, pair, tmp_path, capsys):
    profile = tmp_path / 'cdp-profile'
    code, result, _ = setup(*base(vault, pair, '--cdp-profile', str(profile), '--start-at-login'), capsys=capsys)
    assert stat.S_IMODE(profile.stat().st_mode) == 0o700
    assert any('--remote-debugging-port=0' in step for step in result['user_steps'])
    unit = (home / '.config/systemd/user/akdbx.service').read_text()
    assert f'"--password-browser-profile" "{profile}" "--card-browser-profile" "{profile}"' in unit
    assert '--default-fill-route' not in unit


def test_an_extension_host_of_someone_else_is_refused(home, vault, pair, capsys):
    manifest = home / '.config/microsoft-edge/NativeMessagingHosts/org.akdbx.extension.json'
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({'path': '/somewhere/else.sh'}))
    code, result, _ = setup(*base(vault, pair, '--browser', 'edge'), capsys=capsys)
    assert code == 1 and result['stages']['fill']['state'] == 'failed'
    assert json.loads(manifest.read_text()) == {'path': '/somewhere/else.sh'}


def test_the_capture_host_is_built_then_installed_with_its_extension_id(home, vault, pair, capsys):
    runner = Runner()
    code, result, _ = setup(*base(vault, pair, '--capture-host'), runner=runner, capsys=capsys)
    tool = str(Path(setup_cli.sysconfig.get_path('scripts')) / 'akdbx-browser-import')
    capture = home / '.local/share/akdbx/capture-extension'
    assert runner.commands() == [[tool, 'build-extension', str(capture)]]
    assert result['stages']['features']['state'] == 'todo'
    assert any('--capture-extension-id' in step for step in result['user_steps'])
    capture.mkdir(parents=True)
    (capture / 'manifest.json').write_text('{}')
    runner = Runner()
    extension_id = 'a' * 32
    code, result, _ = setup('--yes', '--json', '--capture-host', '--capture-extension-id', extension_id,
                            runner=runner, capsys=capsys)
    socket = Path(os.environ['XDG_RUNTIME_DIR']) / 'akdbx' / 'akdbx-unlock.sock'
    assert runner.commands() == [[tool, 'install-host', '--extension-id', extension_id, '--origin',
                                  'https://localhost:9443', '--socket', str(socket), '--manifest-dir',
                                  str(home / '.config/google-chrome/NativeMessagingHosts')]]


def test_a_skill_folder_or_another_link_is_never_replaced(home, vault, pair, tmp_path, capsys):
    (home / '.claude/skills').mkdir()
    (home / '.claude/skills/akdbx').mkdir()
    (home / '.codex/skills').mkdir()
    (home / '.codex/skills/akdbx').symlink_to(tmp_path)
    code, result, _ = setup(*base(vault, pair, '--link-skill'), capsys=capsys)
    assert code == 1 and result['stages']['skill']['state'] == 'failed'
    assert (home / '.claude/skills/akdbx').is_dir() and not (home / '.claude/skills/akdbx').is_symlink()
    assert os.readlink(home / '.codex/skills/akdbx') == str(tmp_path)


def test_explicit_skill_folders_and_source(home, vault, pair, tmp_path, capsys):
    source = tmp_path / 'skill-source'
    source.mkdir()
    (source / 'SKILL.md').write_text('---\nname: akdbx\n---\n')
    target = tmp_path / 'agent-skills'
    code, result, _ = setup(*base(vault, pair, '--link-skill', '--skill-dir', str(target), '--skill-source',
                                  str(source)), capsys=capsys)
    assert os.readlink(target / 'akdbx') == str(source)
    assert result['stages']['skill']['links'] == [{'path': str(target / 'akdbx'), 'state': 'changed'}]


def test_the_status_check_reports_a_blocked_link_without_creating_one(home, vault, pair, capsys):
    runner = Runner()
    blocked = {'ok': True, 'locked': True, 'unlock_blocked': True, 'unlock_origin': 'https://localhost:9443'}
    code, result, _ = setup(*base(vault, pair), runner=runner, status=Status(runner, True, blocked), capsys=capsys)
    assert result['broker']['unlock_blocked'] is True and 'unlock_url' not in result['broker']
    assert any('new-unlock-link --user-confirmed' in step for step in result['user_steps'])
    assert not any('new-unlock-link' in argv for argv in runner.commands())


# ----- interactive --------------------------------------------------------------

def test_interactive_questions_have_defaults_and_confirmations(home, vault, pair, capsys):
    answers = iter([
        str(vault),          # vault
        '',                  # key file: none
        '1',                 # access: local
        'y',                 # start at login
        'helium',            # extension browsers
        '',                  # CDP profile: none
        '',                  # capture host: no
        'n',                 # skill: no
        'y', 'y', 'n',       # write the unit, enable it, do not start now
        'y', 'y',            # install the host, build the extension
    ])
    runner = Runner()
    code, _, _ = setup('--tls-cert', str(pair[0]), '--tls-key', str(pair[1]), runner=runner,
                       ask=lambda: next(answers), interactive=True)
    out = capsys.readouterr().out
    assert code == 0, out
    assert next(answers, None) is None
    assert 'RECOMMENDED for remote use' in out and 'STRONGLY DISCOURAGED' in out
    assert ['/usr/bin/systemctl', '--user', 'enable', 'akdbx.service'] in runner.commands()
    assert not any(argv[-2:] == ['start', 'akdbx.service'] for argv in runner.commands())
    assert (home / '.config/net.imput.helium/NativeMessagingHosts/org.akdbx.extension.json').is_file()
    assert 'systemctl --user start akdbx.service' in out


def test_interactive_numbers_are_checked(home):
    out = io.StringIO()
    answers = iter(['9', 'relay'])
    prompter = setup_cli.Prompter(True, out, lambda: next(answers))
    assert prompter.choose('Access', [(k, k) for k in setup_cli.ACCESS], 'local') == 'relay'
    assert 'Answer a number from 1 to 5' in out.getvalue()


# ----- helpers and Windows content (pure functions) ----------------------------

def exec_words(value):
    """Split an ExecStart value the way systemd does: double quotes and C escapes, then %% to %."""
    words, word, quoted, index = [], None, False, 0
    while index < len(value):
        char = value[index]
        if quoted and char == '\\':
            word += value[index + 1]
            index += 1
        elif char == '"':
            quoted, word = not quoted, word or ''
        elif char == ' ' and not quoted:
            if word is not None:
                words.append(word)
            word = None
        else:
            word = (word or '') + char
        index += 1
    if word is not None:
        words.append(word)
    return [word.replace('%%', '%') for word in words]


def test_a_dollar_in_the_python_path_survives_in_the_unit(tmp_path):
    # M12: systemd never expands variables in the program path, only in argv.
    folder = tmp_path / 'py $HOME ${USER} 100%'
    folder.mkdir()
    python = folder / 'python3'
    python.write_text('#!/bin/sh\nexit 0\n')
    python.chmod(0o700)
    argv = [str(python), '-m', 'akdbx.cli', 'serve', str(tmp_path / '$vault.kdbx')]
    text = setup_cli.unit_text(argv, [])
    words = exec_words(next(line for line in text.splitlines() if line.startswith('ExecStart='))[10:])
    path = words[0][1:] if words[0].startswith('@') else words[0]
    rest = words[1:] if words[0].startswith('@') else words
    assert path == str(python)
    assert [word.replace('$$', '$') for word in rest] == argv
    analyze = shutil.which('systemd-analyze')
    if analyze:
        unit = tmp_path / 'akdbx-setup-test.service'
        unit.write_text(text)
        checked = subprocess.run([analyze, 'verify', str(unit)], capture_output=True, text=True, timeout=120,
                                 check=False)
        assert 'is not executable' not in checked.stdout + checked.stderr, checked.stderr


def test_windows_commands_are_valid_powershell():
    # M7: single-quoted literals, apostrophes doubled, and the call operator.
    argv = [r"C:\Users\O'Neil\venv\Scripts\python.exe", '-m', 'akdbx.cli', '--https=9443', r'C:\a b\v.kdbx',
            'it\u2019s', '$env:USERNAME', 'a;b', '']
    assert setup_cli.shell_command(argv, True) == (
        r"& 'C:\Users\O''Neil\venv\Scripts\python.exe' -m akdbx.cli --https=9443 'C:\a b\v.kdbx' "
        "'it\u2019\u2019s' '$env:USERNAME' 'a;b' ''")
    assert setup_cli.shell_command(['schtasks', '/Run', '/TN', 'akdbx-broker'], True) == (
        '& schtasks /Run /TN akdbx-broker')


def test_systemd_quoting_disables_specifiers_and_variables():
    assert setup_cli.systemd_quote('/a b/100%$HOME"\\') == '"/a b/100%%$$HOME\\"\\\\"'
    with pytest.raises(ValueError):
        setup_cli.systemd_quote('a\nb')


def test_the_windows_task_runs_at_this_users_logon_without_elevation():
    arguments = subprocess.list2cmdline(['-m', 'akdbx.cli', 'serve', r'C:\Users\Ann & Bo\v.kdbx'])
    xml = setup_cli.task_xml(r'C:\venv\Scripts\pythonw.exe', arguments, r'PC\Ann')
    assert '<LogonType>InteractiveToken</LogonType>' in xml and '<RunLevel>LeastPrivilege</RunLevel>' in xml
    assert xml.count(r'<UserId>PC\Ann</UserId>') == 2 and '&amp;' in xml
    assert setup_cli.task_action(xml) == (True, r'C:\venv\Scripts\pythonw.exe', arguments)
    assert setup_cli.task_action('<Task><Description>other</Description></Task>')[0] is False


def windows_setup(tmp_path, runner, *argv):
    local = tmp_path / 'LocalAppData'
    local.mkdir(exist_ok=True)
    args = parse('--dry-run', *argv)
    return setup_cli.Setup(args, ui=setup_cli.Prompter(False, io.StringIO()), runner=runner, status=Status(runner),
                           which=lambda name: None, windows=True, home=tmp_path, executable=r'C:\venv\Scripts\python.exe',
                           env={'LOCALAPPDATA': str(local), 'USERDOMAIN': 'PC', 'USERNAME': 'Ann'})


def test_windows_plans_a_logon_task_and_refuses_a_foreign_one(tmp_path):
    runner = Runner({'schtasks': lambda argv: Runner.done('', 1)})
    windows = windows_setup(tmp_path, runner)
    windows.choice.update(vault=r'C:\Users\Ann\v.kdbx', access='local', tls_cert=r'C:\a\c.pem', tls_key=r'C:\a\k.pem')
    windows.origin = setup_cli.DEFAULT_ORIGIN
    windows._login_windows({'running': False})
    plan = windows.ui.out.getvalue()
    assert 'schtasks /Create /TN akdbx-broker /XML' in plan and '<UserId>PC\\Ann</UserId>' in plan
    assert '&quot;' not in plan and 'serve' in plan
    assert windows.stages['login']['state'] == 'planned'
    foreign = Runner({'schtasks': lambda argv: Runner.done('<Task><Description>mine</Description></Task>')})
    windows = windows_setup(tmp_path, foreign)
    windows.choice.update(vault=r'C:\v.kdbx', access='local', tls_cert='c', tls_key='k')
    windows._login_windows({'running': False})
    assert windows.stages['login']['state'] == 'failed'
    assert [argv[1] for argv in foreign.commands()] == ['/Query']


def test_windows_skill_links_are_directory_junctions(tmp_path):
    linked = []
    windows = windows_setup(tmp_path, Runner())
    windows.dry_run = False
    windows.link = lambda source, target: linked.append((source, target))
    (tmp_path / '.claude').mkdir()
    windows.choice['link_skill'] = True
    windows.stage_skill()
    assert 'directory junction' in windows.ui.out.getvalue()
    assert linked == [(windows.skill_source(), tmp_path / '.claude' / 'skills' / 'akdbx')]


def test_windows_paths_live_in_the_private_local_app_data_folder(tmp_path):
    windows = windows_setup(tmp_path, Runner())
    local = tmp_path / 'LocalAppData' / 'akdbx'
    assert windows.state_path() == local / 'setup.json'
    assert windows.default_tls() == (local / 'localhost.pem', local / 'localhost-key.pem')
    assert windows.task_path() == local / 'akdbx-broker.task.xml'
    assert windows.default_extension_dir() == local / 'extension'


def test_setup_help_lists_every_stage():
    text = cli.parser().parse_args(['setup', '--dry-run'])
    assert text.dry_run is True
    with pytest.raises(SystemExit):
        cli.parser().parse_args(['setup', '--skip', 'unknown'])


def test_end_of_input_stops_setup_cleanly(home, vault, capsys):
    def closed():
        raise EOFError
    code, _, runner = setup(ask=closed, interactive=True)
    assert code == 130 and runner.calls == []
    assert 'Run it again to continue' in capsys.readouterr().err


def test_an_enabled_relay_follows_a_port_move_before_later_stages_use_the_origin(home, vault, monkeypatch, capsys):
    # The broker saves a relay port move when it starts; later stages (the extension build) must use
    # the origin it serves. setup itself never asks the relay (no network, no second writer).
    from akdbx import relay as relay_module
    old = relay_module.RelayConfig('https://relay.akdbx.link:8443', 'k3x7q2mbn5vd.akdbx.link', 'k3x7q2mbn5vd',
                                   8443, True, 'A' * 43)
    new = relay_module.RelayConfig('https://relay.akdbx.link', old.name, old.broker_id, 443, True, old.secret)
    moved = []

    class Store:
        def load(self):
            return new if moved else old

        def certificate(self, name):
            return object()

    monkeypatch.setattr(relay_module, 'RelayStore', Store)
    monkeypatch.setattr(relay_module, 'refresh', lambda *a, **k: pytest.fail('setup must not ask the relay'))
    login = setup_cli.Setup.stage_login

    def start_broker(self, ready):  # the broker the login stage starts saves the move
        moved.append(True)
        return login(self, ready)
    monkeypatch.setattr(setup_cli.Setup, 'stage_login', start_broker)
    code, result, _ = setup('--yes', '--json', '--vault', str(vault), '--access', 'relay', runner=Runner(),
                            capsys=capsys)
    assert moved and result['stages']['access']['origin'] == 'https://k3x7q2mbn5vd.akdbx.link:8443', result
    assert result['broker']['origin'] == 'https://k3x7q2mbn5vd.akdbx.link'


def test_the_extension_waits_for_a_started_relay_broker_to_save_its_move(home, vault, monkeypatch, capsys):
    # systemctl start returns before the broker answers; it saves the relay move before its socket listens.
    from akdbx import relay as relay_module
    old = relay_module.RelayConfig('https://relay.akdbx.link:8443', 'k3x7q2mbn5vd.akdbx.link', 'k3x7q2mbn5vd',
                                   8443, True, 'A' * 43)
    new = relay_module.RelayConfig('https://relay.akdbx.link', old.name, old.broker_id, 443, True, old.secret)
    moved = []

    class Store:
        def load(self):
            return new if moved else old

        def certificate(self, name):
            return object()

    class SlowStart(Status):
        def __call__(self, origin):
            response = super().__call__(origin)  # FileNotFoundError until the service starts
            self.answers = getattr(self, 'answers', 0) + 1
            if self.answers <= 3:
                if self.answers == 3:
                    moved.append(True)  # the broker saved the move; its socket listens next
                raise FileNotFoundError  # still asking the relay
            return response

    monkeypatch.setattr(relay_module, 'RelayStore', Store)
    runner = Runner()
    code, result, _ = setup('--yes', '--json', '--vault', str(vault), '--access', 'relay', '--start-at-login',
                            '--browser', 'chrome', runner=runner, status=SlowStart(runner), capsys=capsys)
    builds = [argv for argv in runner.commands() if 'extension' in argv and 'build' in argv]
    assert builds, result
    assert all(argv[argv.index('--unlock-origin') + 1] == 'https://k3x7q2mbn5vd.akdbx.link' for argv in builds)


def test_setup_reads_the_origin_again_when_the_broker_moved_during_its_status_check(home, vault, monkeypatch,
                                                                                    capsys):
    # The broker saves the move after setup read the origin and answers before setup asks: the CLI then
    # refuses the new unlock URL. setup reads the saved origin again and asks once more.
    from akdbx import relay as relay_module
    old = relay_module.RelayConfig('https://relay.akdbx.link:8443', 'k3x7q2mbn5vd.akdbx.link', 'k3x7q2mbn5vd',
                                   8443, True, 'A' * 43)
    new = relay_module.RelayConfig('https://relay.akdbx.link', old.name, old.broker_id, 443, True, old.secret)
    moved = []

    class Store:
        def load(self):
            return new if moved else old

        def certificate(self, name):
            return object()

    class MovesDuringCheck(Status):
        def __call__(self, origin):
            response = super().__call__(origin)  # FileNotFoundError until the service starts
            if not moved:
                moved.append(True)
                raise ValueError('broker returned an untrusted unlock URL')
            assert origin == 'https://k3x7q2mbn5vd.akdbx.link'
            return response

    monkeypatch.setattr(relay_module, 'RelayStore', Store)
    runner = Runner()
    code, result, _ = setup('--yes', '--json', '--vault', str(vault), '--access', 'relay', '--start-at-login',
                            '--browser', 'chrome', runner=runner, status=MovesDuringCheck(runner), capsys=capsys)
    builds = [argv for argv in runner.commands() if 'extension' in argv and 'build' in argv]
    assert builds and result['broker']['running'] is True, result
    assert all(argv[argv.index('--unlock-origin') + 1] == 'https://k3x7q2mbn5vd.akdbx.link' for argv in builds)
