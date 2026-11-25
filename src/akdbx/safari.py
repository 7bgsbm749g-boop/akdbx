"""Build the macOS Safari app with Apple's packager and an isolated build folder.

The app extension connects only to the default local broker socket. No Python
host manifest, remote broker, vault access or signing credentials are needed for
an unsigned developer build. Safari still requires the user to enable it.
"""
from importlib.resources import files
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

from .extension_route import SAFARI_EXTENSION_ID

APP_ID = 'org.akdbx.safari'
APP_NAME = 'akdbx Safari'


def assets():
    return files('akdbx').joinpath('safari_assets')


def _run(argv, *, timeout=120):
    # -quiet keeps compiler output small. Bound captured output and diagnostics.
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError(f'{Path(argv[0]).name} could not finish the Safari build') from None
        output.seek(0)
        data = output.read(2 * 1024 * 1024 + 1)
        if result.returncode or len(data) > 2 * 1024 * 1024:
            output.seek(0, 2)
            output.seek(max(0, output.tell() - 8192))
            detail = output.read(8192).decode('utf-8', errors='replace')
            raise RuntimeError(f'{Path(argv[0]).name} failed during the Safari build: {detail}')
        return data


def _owned_app(path):
    if path.is_symlink() or not path.is_dir():
        return False
    info = path / 'Contents' / 'Info.plist'
    try:
        if info.is_symlink() or info.stat().st_size > 65536:
            return False
        return plistlib.loads(info.read_bytes()).get('CFBundleIdentifier') == APP_ID
    except (OSError, ValueError, plistlib.InvalidFileException):
        return False


def build_app(destination, *, unlock_origin):
    """Create a new developer app. Refuse existing paths, including another app.

    Use a new output path to build an update, then replace the old app through
    Finder after quitting its containing app. Building never removes an app.
    """
    if sys.platform != 'darwin':
        raise RuntimeError('the Safari native app must be built on macOS with Xcode')
    from .extension_host import build
    destination = Path(destination).expanduser().absolute()
    if destination.suffix != '.app' or destination.exists() or destination.is_symlink():
        raise ValueError('choose a new .app output path for the Safari build')
    if not unlock_origin:
        raise ValueError('configure the broker HTTPS origin before building the Safari app')
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Keeping the staging directory beside the result makes the final rename atomic.
    with tempfile.TemporaryDirectory(prefix='.akdbx-safari-', dir=destination.parent) as temporary:
        root = Path(temporary)
        resources = build(root / 'resources', browser='safari', unlock_origin=unlock_origin)
        packager = None
        for candidate in ('safari-web-extension-packager', 'safari-web-extension-converter'):
            probe = subprocess.run(['xcrun', '--find', candidate], capture_output=True, timeout=30)
            if probe.returncode == 0:
                packager = candidate
                break
        if packager is None:
            raise RuntimeError('install full Xcode with the Safari web extension packager')
        _run(['xcrun', packager, str(resources), '--project-location', str(root / 'project'),
              '--app-name', APP_NAME, '--bundle-identifier', APP_ID, '--swift', '--macos-only',
              '--no-open', '--no-prompt'])
        projects = list((root / 'project').rglob('*.xcodeproj'))
        handlers = list((root / 'project').rglob('SafariWebExtensionHandler.swift'))
        if len(projects) != 1 or len(handlers) != 1:
            raise RuntimeError('the Safari packager returned an unsupported project layout')
        project = projects[0]
        # Older converters derive identifiers from the app name even when a
        # bundle identifier was supplied. Set both native target identifiers
        # explicitly before signing; changing Info.plist afterwards breaks it.
        project_file = project / 'project.pbxproj'
        project_data = plistlib.loads(_run(['plutil', '-convert', 'xml1', '-o', '-', str(project_file)]))
        objects = project_data['objects']
        identifiers = {
            '.app': APP_ID,
            '.appex': SAFARI_EXTENSION_ID,
        }
        configured = []
        for target in objects.values():
            if target.get('isa') != 'PBXNativeTarget':
                continue
            product = objects[target['productReference']]['path']
            identifier = identifiers.get(Path(product).suffix)
            if identifier is None:
                if target.get('productType') == 'com.apple.product-type.bundle.unit-test':
                    continue
                details = dict(name=target.get('name'), kind=target.get('productType'),
                               product=objects[target['productReference']])
                raise RuntimeError('the Safari project has an unexpected native target: ' + json.dumps(details))
            configurations = objects[target['buildConfigurationList']]['buildConfigurations']
            for configuration in configurations:
                objects[configuration]['buildSettings']['PRODUCT_BUNDLE_IDENTIFIER'] = identifier
            configured.append(identifier)
        if sorted(configured) != sorted(identifiers.values()):
            raise RuntimeError('the Safari project must contain one app and one extension target')
        project_file.write_bytes(plistlib.dumps(project_data, sort_keys=False))
        # One existing source file keeps the generated Xcode target unchanged.
        handlers[0].write_bytes(assets().joinpath('BrokerBridge.swift').read_bytes() + b'\n' +
                               assets().joinpath('SafariWebExtensionHandler.swift').read_bytes())
        entitlements = list((root / 'project').rglob('*.entitlements'))
        if not entitlements:
            raise RuntimeError('the generated Safari targets have no sandbox entitlements')
        extension_entitlements = plistlib.loads(assets().joinpath('Extension.entitlements').read_bytes())
        extension_targets = 0
        for path in entitlements:
            value = plistlib.loads(path.read_bytes())
            # The native app extension needs the narrow socket-directory grant.
            # The containing app keeps its generated sandbox settings.
            if 'extension' in str(path.relative_to(root / 'project')).lower():
                value.update(extension_entitlements)
                extension_targets += 1
            value['com.apple.security.app-sandbox'] = True
            path.write_bytes(plistlib.dumps(value))
        if extension_targets != 1:
            raise RuntimeError('the Safari project must have exactly one native extension entitlement file')
        listing = json.loads(_run(['xcodebuild', '-list', '-json', '-project', str(project)]))
        schemes = listing.get('project', {}).get('schemes', [])
        mac_schemes = [name for name in schemes if 'macos' in name.lower()]
        scheme = mac_schemes[0] if len(mac_schemes) == 1 else APP_NAME if APP_NAME in schemes else None
        if scheme is None:
            raise RuntimeError('the generated Safari project has no unique macOS app scheme')
        derived = root / 'derived'
        _run(['xcodebuild', '-quiet', '-project', str(project), '-scheme', scheme, '-configuration', 'Release',
              '-derivedDataPath', str(derived), 'MACOSX_DEPLOYMENT_TARGET=14.0', 'CODE_SIGN_IDENTITY=-',
              'CODE_SIGN_STYLE=Manual', 'DEVELOPMENT_TEAM=', 'build'], timeout=600)
        built = derived / 'Build' / 'Products' / 'Release' / (APP_NAME + '.app')
        if not _owned_app(built):
            products = []
            for candidate in (derived / 'Build' / 'Products' / 'Release').glob('*.app'):
                info = candidate / 'Contents/Info.plist'
                bundle_id = None
                if info.is_file() and info.stat().st_size <= 65536:
                    bundle_id = plistlib.loads(info.read_bytes()).get('CFBundleIdentifier')
                products.append(dict(name=candidate.name, bundle_id=bundle_id))
                if len(products) == 8:
                    break
            raise RuntimeError('Xcode did not produce the expected Safari app: ' + json.dumps(products))
        extensions = list((built / 'Contents' / 'PlugIns').glob('*.appex'))
        if len(extensions) != 1:
            raise RuntimeError('the Safari app must contain exactly one native extension')
        info = plistlib.loads((extensions[0] / 'Contents' / 'Info.plist').read_bytes())
        if info.get('CFBundleIdentifier') != SAFARI_EXTENSION_ID:
            raise RuntimeError('the generated Safari extension has an unexpected bundle identifier')
        # The parent is user-selected. Move only the complete, checked build;
        # an output path created while the build ran must not be replaced.
        if destination.exists() or destination.is_symlink():
            raise ValueError('the Safari output path appeared during the build; choose a new path')
        shutil.move(str(built), destination)
    return destination
