"""Small, disposable Xcode UI-test host for the installed Safari application.

The runner uses XCTest's supported cross-application UI API. It changes no
TCC database, Safari security preference file, or production app resource.
"""
import json
from pathlib import Path
import plistlib
from xml.sax.saxutils import escape


def create_project(folder, probe_url):
    folder = Path(folder)
    folder.mkdir()
    (folder / 'main.swift').write_text('import Cocoa\nNSApplication.shared.run()\n')
    source = Path(__file__).with_name('safari_settings_ui.swift').read_text()
    source = source.replace('__PROBE_URL__', json.dumps(probe_url))
    source = source.replace('__ARTIFACT_DIR__', json.dumps(str(folder)))
    (folder / 'SafariSettingsTests.swift').write_text(source)
    objects = {}

    def add(isa, **fields):
        key = f'{len(objects) + 1:024X}'
        objects[key] = dict(isa=isa, **fields)
        return key

    def configurations(extra):
        items = []
        for name in ('Debug', 'Release'):
            settings = dict(SDKROOT='macosx', SUPPORTED_PLATFORMS='macosx', SWIFT_VERSION='5.0',
                            MACOSX_DEPLOYMENT_TARGET='14.0', CODE_SIGN_IDENTITY='-',
                            CODE_SIGN_STYLE='Manual', DEVELOPMENT_TEAM='',
                            GENERATE_INFOPLIST_FILE='YES', SWIFT_OPTIMIZATION_LEVEL='-Onone',
                            ENABLE_HARDENED_RUNTIME='NO', **extra)
            items.append(add('XCBuildConfiguration', name=name, buildSettings=settings))
        return add('XCConfigurationList', buildConfigurations=items,
                   defaultConfigurationIsVisible=0, defaultConfigurationName='Debug')

    products = []

    def target(name, source_name, product_type, settings, dependencies=()):
        source_ref = add('PBXFileReference', path=source_name, sourceTree='<group>',
                         lastKnownFileType='sourcecode.swift')
        build_file = add('PBXBuildFile', fileRef=source_ref)
        sources = add('PBXSourcesBuildPhase', buildActionMask=2147483647,
                      files=[build_file], runOnlyForDeploymentPostprocessing=0)
        suffix = '.app' if product_type == 'application' else '.xctest'
        product = add('PBXFileReference', explicitFileType='wrapper.application' if suffix == '.app'
                      else 'wrapper.cfbundle', path=name + suffix, sourceTree='BUILT_PRODUCTS_DIR')
        products.append(product)
        key = add('PBXNativeTarget', name=name, productName=name, productReference=product,
                  productType='com.apple.product-type.' + product_type,
                  buildConfigurationList=configurations(dict(PRODUCT_NAME=name, **settings)),
                  buildPhases=[sources], buildRules=[], dependencies=list(dependencies))
        return key, source_ref

    host, host_source = target('SafariUITestHost', 'main.swift', 'application',
                               dict(PRODUCT_BUNDLE_IDENTIFIER='org.akdbx.safari.ui-host'))
    dependency = add('PBXTargetDependency', target=host)
    ui, ui_source = target('SafariSettingsTests', 'SafariSettingsTests.swift', 'bundle.ui-testing',
                           dict(PRODUCT_BUNDLE_IDENTIFIER='org.akdbx.safari.ui-tests',
                                TEST_TARGET_NAME='SafariUITestHost',
                                LD_RUNPATH_SEARCH_PATHS=['$(inherited)', '@executable_path/../Frameworks',
                                                        '@loader_path/../Frameworks']), [dependency])
    product_group = add('PBXGroup', children=products, name='Products', sourceTree='<group>')
    main_group = add('PBXGroup', children=[host_source, ui_source, product_group], sourceTree='<group>')
    project = add('PBXProject', attributes=dict(LastUpgradeCheck='1600',
                  TargetAttributes={ui: dict(TestTargetID=host)}),
                  buildConfigurationList=configurations({}), compatibilityVersion='Xcode 14.0',
                  developmentRegion='en', knownRegions=['en'], mainGroup=main_group,
                  productRefGroup=product_group, projectDirPath='', projectRoot='', targets=[host, ui])
    bundle = folder / 'SafariUI.xcodeproj'
    bundle.mkdir()
    (bundle / 'project.pbxproj').write_bytes(plistlib.dumps(dict(
        archiveVersion='1', classes={}, objectVersion='56', objects=objects, rootObject=project)))
    scheme_dir = bundle / 'xcshareddata/xcschemes'
    scheme_dir.mkdir(parents=True)

    def reference(identifier, name, product):
        return (f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{identifier}" '
                f'BuildableName="{escape(product)}" BlueprintName="{name}" '
                'ReferencedContainer="container:SafariUI.xcodeproj"/>')

    host_ref = reference(host, 'SafariUITestHost', 'SafariUITestHost.app')
    ui_ref = reference(ui, 'SafariSettingsTests', 'SafariSettingsTests.xctest')
    scheme = f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
  <BuildAction parallelizeBuildables="NO" buildImplicitDependencies="YES"><BuildActionEntries>
    <BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="NO"
      buildForArchiving="NO" buildForAnalyzing="NO">{host_ref}</BuildActionEntry>
    <BuildActionEntry buildForTesting="YES" buildForRunning="NO" buildForProfiling="NO"
      buildForArchiving="NO" buildForAnalyzing="NO">{ui_ref}</BuildActionEntry>
  </BuildActionEntries></BuildAction>
  <TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB"
    selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES">
    <Testables><TestableReference skipped="NO">{ui_ref}</TestableReference></Testables>
    <MacroExpansion>{host_ref}</MacroExpansion>
  </TestAction>
</Scheme>
'''
    (scheme_dir / 'SafariUI.xcscheme').write_text(scheme)
    return bundle
