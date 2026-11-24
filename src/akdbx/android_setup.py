"""Optional Linux Android setup. The SDK and device data stay outside the vault."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from .android_route import (Adb, AndroidError, CONFIG_ENV, DEVICE_NAME, Device, MAX_DEVICES, SERIAL,
                            _read_private_file, default_config_path, load_devices)


IMAGE = 'system-images;android-35;google_apis_playstore;x86_64'


def config_path():
    return Path(os.environ.get(CONFIG_ENV) or default_config_path()).absolute()


def add_parsers(sub):
    setup = sub.add_parser('setup', help='connect an existing device or provision an on-demand Google Play emulator')
    choice = setup.add_mutually_exclusive_group()
    choice.add_argument('--attach', metavar='ADB_SERIAL', help='connect a device you manage; never start or stop it')
    choice.add_argument('--create', action='store_true', help='create a private persistent stock Google Play AVD')
    choice.add_argument('--manage-avd', metavar='AVD', help='explicitly manage an existing, stopped AVD')
    setup.add_argument('--device', default='android', help='device name in the broker configuration')
    setup.add_argument('--adb', type=Path, help='adb executable for --attach')
    setup.add_argument('--adb-port', type=int, help='adb server port (existing: 5037, managed: 5043)')
    setup.add_argument('--emulator-port', type=int, default=5584, help='private even console port (managed)')
    setup.add_argument('--sdk', type=Path, help='Android SDK root (default: ANDROID_HOME or ~/Android/Sdk)')
    setup.add_argument('--avd-home', type=Path, help='AVD registry containing NAME.ini, or directory for a new AVD')
    setup.add_argument('--idle-seconds', type=int, default=180, help='stop after last operation (120–3600 seconds)')
    for name, help_text in [('wake', 'boot a managed emulator before requesting a mobile approval'),
                            ('run', 'keep the device awake for a command; release when the command finishes')]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument('--device', required=True)
        if name == 'run':
            p.add_argument('argv', nargs=argparse.REMAINDER, help='-- PROGRAM ARGS (no shell)')


def android_sdk(args):
    sdk = (args.sdk or Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
                            or Path.home() / 'Android/Sdk')).resolve()
    return sdk


def install_command_tools(sdk):
    """Bootstrap only Google's pinned Linux command-line tools. sdkmanager installs the SDK."""
    if not (shutil.which('java') or os.access(Path(os.environ.get('JAVA_HOME', '/nonexistent')) / 'bin/java', os.X_OK)):
        raise AndroidError('install a Java runtime for sdkmanager, or set JAVA_HOME, then rerun setup')
    root = sdk / 'cmdline-tools'
    root.mkdir(parents=True, exist_ok=True)
    destination = root / 'latest'
    if destination.exists():
        raise AndroidError('incomplete SDK command-line tools; repair the SDK or select a different --sdk')
    url = 'https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip'
    digest = '4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583'
    with tempfile.TemporaryDirectory(dir=root) as directory:
        work = Path(directory)
        archive = work / 'tools.zip'
        checksum = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=60) as source, archive.open('xb') as target:
            while block := source.read(1024 * 1024):
                if target.tell() + len(block) > 256 * 1024 * 1024:
                    raise AndroidError('SDK tools archive exceeds size limit')
                checksum.update(block)
                target.write(block)
        if checksum.hexdigest() != digest:
            raise AndroidError('Google SDK command-line tools checksum mismatch')
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(work)
        tools = work / 'cmdline-tools'
        for executable in (tools / 'bin').iterdir():
            executable.chmod(0o755)
        tools.rename(destination)
    return destination / 'bin/sdkmanager'


def provision(sdk, avd_home, name):
    if (avd_home / (name + '.ini')).exists() or (avd_home / (name + '.avd')).exists():
        raise AndroidError('AVD already exists; choose --manage-avd to use it without replacing data')
    # Let the vendor installer verify packages, present its licence, and choose compatible revisions.
    manager = sdk / 'cmdline-tools/latest/bin/sdkmanager'
    if not manager.is_file():
        # avdmanager resolves images relative to its own SDK, even with ANDROID_HOME.
        manager = install_command_tools(sdk)
    avdmanager = manager.with_name('avdmanager')
    if not avdmanager.is_file():
        raise AndroidError('avdmanager must be installed beside sdkmanager')
    try:
        subprocess.run([manager, '--sdk_root=' + str(sdk), 'platform-tools', 'emulator', IMAGE], check=True)
    except subprocess.CalledProcessError:
        raise AndroidError('sdkmanager could not install the Google Play image; check Java, disk space and SDK license') from None
    if not (sdk / 'system-images/android-35/google_apis_playstore/x86_64/system.img').is_file():
        raise AndroidError('Google Play image missing after sdkmanager; check the SDK license and rerun setup')
    avd_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    env = {**os.environ, 'ANDROID_HOME': str(sdk), 'ANDROID_SDK_ROOT': str(sdk),
           'ANDROID_AVD_HOME': str(avd_home)}
    subprocess.run([avdmanager, 'create', 'avd', '--name', name, '--package', IMAGE,
                    '--device', 'pixel_6', '--path', str(avd_home / (name + '.avd'))],
                   input=b'no\n', env=env, check=True)
    # Some avdmanager versions create a Play Store image with the profile
    # switch disabled. Only change a virtual device we just created.
    config = avd_home / (name + '.avd') / 'config.ini'
    lines = [line for line in config.read_text().splitlines()
             if line.partition('=')[0].strip() != 'PlayStore.enabled']
    config.write_text('\n'.join([*lines, 'PlayStore.enabled=true', '']))


def setup(args):
    if not sys.platform.startswith('linux'):
        raise AndroidError('the Android broker and emulator setup require Linux')
    import fcntl
    name = args.device
    if not DEVICE_NAME.fullmatch(name):
        raise AndroidError('invalid Android device name')
    if not any((args.attach, args.create, args.manage_avd)):
        if not sys.stdin.isatty():
            raise AndroidError('select --attach SERIAL, --create, or --manage-avd NAME')
        answer = input('Create an on-demand Google Play emulator or attach an existing device? [create/attach] ')
        if answer.strip().lower() == 'attach':
            args.attach = input('ADB serial: ').strip()
        elif answer.strip().lower() == 'create':
            args.create = True
        else:
            raise AndroidError('no device selected')
    sdk = android_sdk(args)
    port = args.adb_port if args.adb_port is not None else (5037 if args.attach else 5043)
    if not 1024 <= port <= 65535:
        raise AndroidError('invalid adb server port')
    managed = None
    if args.attach:
        if not SERIAL.fullmatch(args.attach):
            raise AndroidError('invalid adb serial')
        serial = args.attach
        adb = (args.adb or Path(shutil.which('adb') or sdk / 'platform-tools/adb')).resolve()
    else:
        if not (args.create or args.manage_avd) or args.adb:
            raise AndroidError('managed setup uses the SDK platform-tools/adb')
        if (not 120 <= args.idle_seconds <= 3600 or not 5554 <= args.emulator_port <= 5682
                or args.emulator_port % 2 or port in (args.emulator_port, args.emulator_port + 1)):
            raise AndroidError('invalid idle interval or emulator ports')
        if not os.access('/dev/kvm', os.R_OK | os.W_OK) or platform.machine() != 'x86_64':
            raise AndroidError('managed Google Play images require an x86_64 Linux host with KVM access')
        subprocess.run(['systemctl', '--user', 'show-environment'], stdout=subprocess.DEVNULL, check=True)
        avd = args.manage_avd or name
        if not DEVICE_NAME.fullmatch(avd):
            raise AndroidError('invalid managed AVD name')
        home = (args.avd_home or Path(os.environ.get('XDG_DATA_HOME') or Path.home() / '.local/share')
                / 'akdbx/android/avd').resolve()
        managed = dict(sdk=str(sdk), avd_home=str(home), avd=avd, idle_seconds=args.idle_seconds)
        serial = 'emulator-' + str(args.emulator_port)
        adb = sdk / 'platform-tools/adb'
    device = Device(name, str(adb), port, serial, managed)
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise AndroidError('Android configuration directory must be owned by you and not writable by others')
    # Serialize setup even when two installers start before the config exists.
    fd = os.open(path.with_name(path.name + '.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        devices = load_devices(path)
        if devices.get(name) == device:
            return {'ok': True, 'device': name, 'changed': False}
        previous = devices.get(name)
        if previous is None and len(devices) >= MAX_DEVICES:
            raise AndroidError('device limit reached')
        if previous and not (args.manage_avd and previous == Device(name, str(adb), port, serial)):
            raise AndroidError('device name already registered with different settings')
        if any(device.conflicts_with(other) for other in devices.values() if other.name != name):
            raise AndroidError('another device uses this managed transport or AVD')
        if managed:
            if args.create:
                provision(sdk, home, avd)
            if not (home / (avd + '.ini')).is_file() or not os.access(sdk / 'emulator/emulator', os.X_OK):
                raise AndroidError('AVD registry entry or SDK emulator missing')
        if not os.access(adb, os.X_OK):
            raise AndroidError('adb executable not found')
        if args.attach:
            transport = Adb(device)
            if transport.run('get-state').stdout.strip() != b'device':
                raise AndroidError('the attached device must be online on its existing adb server')
            transport.run('shell', 'settings', 'put', 'secure', 'speak_password', '0').check_returncode()
            if transport.run('shell', 'settings', 'get', 'secure', 'speak_password').stdout.strip() != b'0':
                raise AndroidError('could not verify Android password privacy setting')
        raw = json.loads(_read_private_file(path)) if path.exists() else {'version': 1, 'devices': {}}
        entry = dict(adb=str(adb), adb_server_port=port, serial=serial)
        if managed:
            entry['managed'] = managed
        raw['devices'][name] = entry
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
            temp = Path(out.name)
            try:
                out.write(json.dumps(raw, indent=2).encode() + b'\n')
                out.flush()
                os.fsync(out.fileno())
                load_devices(temp)
                os.replace(temp, path)
            finally:
                temp.unlink(missing_ok=True)
    return {'ok': True, 'device': name, 'changed': True}
