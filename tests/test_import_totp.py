"""Synthetic transfer payloads only. Never uses a real authenticator/vault."""
import base64
import io
import json
import os
import random
import struct
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit

import pytest

from akdbx import browser_import
from akdbx.import_totp import parse_import, MAX_FRAMES, MAX_ACCOUNTS
from akdbx.totp import TotpError, parse_setup
from test_totp import KEY, URI, prepare
from test_writes import deployed, template, reopened
from test_web_unlock import UnixHTTPConnection, call


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def number(key, value):
    return varint(key << 3) + varint(value)


def blob(key, value):
    return varint(key << 3 | 2) + varint(len(value)) + value


def account(label='Example:synthetic-account', algorithm=1, digits=1, kind=2):
    return (blob(1, b'12345678901234567890') + blob(2, label.encode()) + blob(3, b'Example')
            + number(4, algorithm) + number(5, digits) + number(6, kind))


def migration(accounts=None, size=1, index=0, batch=123, version=1):
    raw = b''.join(blob(1, a) for a in (accounts if accounts is not None else [account()]))
    raw += number(2, version) + number(3, size) + number(4, index) + number(5, batch)
    return 'otpauth-migration://offline?data=' + quote(base64.b64encode(raw).decode(), safe='')


def private(socket, prepared, path, values=None, origin='https://node.example:9443', identity=True):
    parsed = urlsplit(prepared['private_url'])
    connection = UnixHTTPConnection(socket)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    if identity:
        headers['Tailscale-User-Login'] = 'synthetic@example.test'
    if origin is not None:
        headers['Origin'] = origin
    try:
        connection.request('POST' if values is not None else 'GET', path + '?' + parsed.query,
                           urlencode(values) if values is not None else None, headers)
    except BrokenPipeError:
        # The server can reject headers (including Content-Length) before a
        # form upload completes. Read that response; never resend a mutation.
        pass
    response = connection.getresponse()
    result = response.status, dict(response.headers), response.read()
    connection.close()
    return result


def nonce(broker, prepared):
    return broker.writes.get(prepared['write_handle']).import_nonce


def test_manual_and_migration_roundtrip():
    assert parse_import([KEY]) == (parse_setup(KEY),)
    assert parse_import([URI]) == (parse_setup(URI),)
    for algorithm, name in [(1, 'SHA1'), (2, 'SHA256'), (3, 'SHA512')]:
        for digits, length in [(1, 6), (2, 8)]:
            config, = parse_import([migration([account(algorithm=algorithm, digits=digits)])])
            assert config.algorithm == name and config.digits == length and config.period == 30
            assert KEY not in repr(config)


def test_multi_part_order_and_complete_batch():
    frames = [migration([account('Example:second')], size=2, index=1),
              migration([account()], size=2, index=0)]
    assert [c.label for c in parse_import(frames)] == ['Example:synthetic-account', 'Example:second']
    for invalid in [frames[:1], frames + frames[:1],
                    [frames[0], migration(size=2, index=0, batch=999)],
                    [migration(size=MAX_FRAMES+1)], [migration(index=1)],
                    [migration([account(), account()])], [migration([])],
                    [migration([account('Example:' + str(i)) for i in range(MAX_ACCOUNTS+1)])]]:
        with pytest.raises(TotpError):
            parse_import(invalid)


@pytest.mark.parametrize('payloads', [None, [], 'secret', [1], ['x'*8193], ['x']*9,
    [URI, URI], [migration(kind) for kind in []],
    [migration(version=0)], [migration([account(kind=1)])],
    [migration([account(algorithm=4)])], [migration([account(digits=0)])],
    ['otpauth-migration://evil?data=AAAA'], ['otpauth-migration://offline?data=%%%'],
    [migration() + '&data=AAAA'], [migration() + '#fragment']])
def test_malformed_fixed_errors(payloads):
    with pytest.raises(TotpError) as exc:
        parse_import(payloads)
    assert str(exc.value) == 'import rejected; use supported TOTP keys or one complete Google export batch'


def test_bounded_random_wire_inputs_have_no_diagnostics():
    rng = random.Random(700)
    for _ in range(250):
        raw = rng.randbytes(rng.randrange(0, 300))
        uri = 'otpauth-migration://offline?data=' + quote(base64.b64encode(raw).decode(), safe='')
        with pytest.raises(TotpError):
            parse_import([uri])


def test_private_preview_selection_and_encrypted_save(deployed, caplog, capsys):
    broker, _, path, socket = deployed
    before = path.read_bytes()
    prepared = prepare(broker)
    status, headers, page = private(socket, prepared, '/totp/import')
    assert status == 200 and "script-src 'self'" in headers['Content-Security-Policy']
    assert KEY.encode() not in page and b'Review accounts' in page
    for name in ['jsQR.js', 'import.js']:
        status, headers, asset = private(socket, prepared, '/totp/assets/'+name)
        assert status == 200 and headers['Content-Type'] == 'application/javascript' and asset
    payload = migration([account(), account('Example:second')])
    status, headers, page = private(socket, prepared, '/totp/import', {'payloads': json.dumps([payload])})
    assert status == 200 and b'Example:second' in page
    assert KEY.encode() not in page and payload.encode() not in page
    assert path.read_bytes() == before
    assert broker.dispatch({'action':'write-status','write_handle':prepared['write_handle']}) == {'ok':True,'state':'pending'}
    assert KEY not in repr(broker.writes.get(prepared['write_handle']))
    selected = {'choice':'0','nonce':nonce(broker, prepared),'confirmed':'yes'}
    assert private(socket, prepared, '/totp/review', selected)[0] == 200
    assert private(socket, prepared, '/totp/review', selected)[0] == 400
    entry = reopened(path).find_entries(title='Synthetic site', first=True)
    assert parse_setup(entry.otp).secret == parse_setup(KEY).secret
    assert entry._element.find('./String[Key="otp"]/Value').get('Protected') == 'True'
    assert KEY.encode() not in path.read_bytes()
    assert KEY not in caplog.text + capsys.readouterr().out
    assert not broker.writes.get(prepared['write_handle']).import_candidates


def test_private_manual_base32_save_has_destination_label(deployed):
    broker, _, path, socket = deployed
    prepared = prepare(broker)
    status, _, page = private(socket, prepared, '/totp/import', {'payloads': json.dumps([KEY])})
    assert status == 200 and b'synthetic-account' in page and KEY.encode() not in page
    assert private(socket, prepared, '/totp/review', {
        'choice': '0', 'nonce': nonce(broker, prepared), 'confirmed': 'yes'})[0] == 200
    config = parse_setup(reopened(path).find_entries(title='Synthetic site', first=True).otp)
    assert config.label == 'synthetic-account' and config.secret == parse_setup(KEY).secret


@pytest.mark.parametrize('origin,identity', [(None,True),('https://evil.test',True),('https://node.example:9443',False)])
def test_import_requires_identity_and_same_origin(deployed, origin, identity):
    broker, _, path, socket = deployed
    before = path.read_bytes()
    prepared = prepare(broker)
    assert private(socket, prepared, '/totp/import', {'payloads':json.dumps([KEY])},origin,identity)[0] == 400
    assert path.read_bytes() == before
    assert not broker.writes.get(prepared['write_handle']).import_candidates


def test_wrong_nonce_choice_cancel_expiry_and_stale_state(deployed):
    broker, _, path, socket = deployed
    before = path.read_bytes()
    prepared = prepare(broker)
    assert private(socket, prepared, '/totp/import', {'payloads':json.dumps([KEY])})[0] == 200
    for choice, code in [('0','wrong'), ('99',nonce(broker,prepared))]:
        assert private(socket, prepared, '/totp/review', {'choice':choice,'nonce':code,'confirmed':'yes'})[0] == 409
    assert private(socket, prepared, '/totp/import', {'payloads':json.dumps([KEY])})[0] == 400
    broker.dispatch({'action':'cancel-write','write_handle':prepared['write_handle']})
    assert not broker.writes.get(prepared['write_handle']).import_candidates
    assert private(socket, prepared, '/totp/review')[0] == 400
    assert path.read_bytes() == before
    prepared=prepare(broker)
    assert private(socket, prepared, '/totp/import', {'payloads':json.dumps([KEY])})[0] == 200
    op=broker.writes.get(prepared['write_handle'])
    op.expires=broker.clock()-1
    assert private(socket, prepared, '/totp/review')[0] == 400
    assert not op.import_candidates


def test_native_capture_origin_binding_confirmation_and_replay(deployed):
    broker, _, path, socket = deployed
    before = path.read_bytes()
    prepared=prepare(broker)
    config={'origin':'https://node.example:9443','socket':str(socket),'extension_id':'a'*32}
    message={'private_url':prepared['private_url'],'source_url':'https://example.test/setup','payloads':[URI]}
    with pytest.raises(ValueError):
        browser_import.capture({**message,'source_url':'https://evil.test'}, config)
    receipt=browser_import.capture(message,config)
    assert receipt==browser_import.RECEIPT and KEY not in json.dumps(receipt)
    assert path.read_bytes()==before
    assert private(socket, prepared, '/totp/review')[0]==200
    with pytest.raises(ValueError):
        browser_import.capture(message,config)
    assert private(socket,prepared,'/totp/review',{'choice':'0','nonce':nonce(broker,prepared),'confirmed':'yes'})[0]==200


def test_native_route_rejects_tailnet_identity_and_browser_origin(deployed):
    broker, _, path, socket=deployed
    prepared=prepare(broker)
    parts=urlsplit(prepared['private_url'])
    assert call(socket,'POST','/totp/capture?'+parts.query,'{}')[0]==400
    assert private(socket,prepared,'/totp/capture',{'payloads':json.dumps([URI])},identity=False)[0]==400


def test_native_host_framing_and_fixed_failure(monkeypatch):
    config={'extension_id':'a'*32}
    caller='chrome-extension://'+'a'*32+'/'
    def captured(message, config):
        assert message=={'synthetic':'only'}
        return browser_import.RECEIPT
    monkeypatch.setattr(browser_import,'capture',captured)
    raw=json.dumps({'synthetic':'only'}).encode()
    output=io.BytesIO()
    browser_import.native_session(io.BytesIO(struct.pack('<I',len(raw))+raw),output,config,caller)
    framed=output.getvalue()
    assert struct.unpack('<I',framed[:4])[0]==len(framed)-4
    assert json.loads(framed[4:])==browser_import.RECEIPT
    for raw, origin in [(b'',caller),(struct.pack('<I',999999),caller),(struct.pack('<I',1)+b'{',caller),(b'','chrome-extension://evil/')]:
        output=io.BytesIO()
        browser_import.native_session(io.BytesIO(raw),output,config,origin)
        assert json.loads(output.getvalue()[4:])['ok'] is False


def test_extension_build_no_profile_overwrite_and_private_configuration(tmp_path):
    target=tmp_path/'extension'
    browser_import.build_extension(target)
    manifest=json.loads((target/'manifest.json').read_text())
    assert manifest['permissions']==['activeTab','scripting','nativeMessaging']
    assert 'host_permissions' not in manifest
    assert (target/'jsQR.js').is_file() and (target/'jsQR.LICENSE').is_file()
    with pytest.raises(FileExistsError):
        browser_import.build_extension(target)
    directory=tmp_path/'config'
    directory.mkdir(mode=0o700)
    path=directory/'browser-import.json'
    config={'extension_id':'a'*32,'origin':'https://example.test','socket':'/synthetic/socket'}
    path.write_text(json.dumps(config));path.chmod(0o600)
    assert browser_import.load_config(path)==config
    path.chmod(0o644)
    with pytest.raises(ValueError):browser_import.load_config(path)


def test_competing_vault_save_drops_import_and_stale_review(deployed):
    from test_writes import begin, private_post
    broker, _, path, socket=deployed
    prepared=prepare(broker)
    assert private(socket,prepared,'/totp/import',{'payloads':json.dumps([KEY])})[0]==200
    op=broker.writes.get(prepared['write_handle'])
    winner=begin(broker)
    assert private_post(socket,winner)[0]==200
    assert not op.import_candidates and op.import_nonce is None
    assert private(socket,prepared,'/totp/review')[0]==400
    assert reopened(path).find_entries(title='Synthetic site',first=True).otp is None


def test_import_replacement_preserves_old_protected_history(deployed):
    from test_totp import post_setup
    broker, _, path, socket=deployed
    assert post_setup(socket,prepare(broker))[0]==200
    assert prepare(broker)['ok'] is False
    prepared=prepare(broker,replace=True)
    assert private(socket,prepared,'/totp/import',{'payloads':json.dumps([URI+'&algorithm=SHA256'])})[0]==200
    assert private(socket,prepared,'/totp/review',{'choice':'0','nonce':nonce(broker,prepared),'confirmed':'yes'})[0]==200
    entry=reopened(path).find_entries(title='Synthetic site',first=True)
    assert parse_setup(entry.otp).algorithm=='SHA256'
    assert parse_setup(entry.history[-1].otp).algorithm=='SHA1'


def test_native_route_requires_same_uid_peer(deployed,monkeypatch):
    from akdbx import cli
    broker, _, path, socket=deployed
    prepared=prepare(broker)
    monkeypatch.setattr(cli,'_peer_credentials',lambda _: (123,os.getuid()+1,0))
    connection=UnixHTTPConnection(socket)
    parts=urlsplit(prepared['private_url'])
    connection.request('POST','/totp/capture?'+parts.query,
        json.dumps({'payloads':[URI],'source_url':'https://example.test'}),{'Content-Type':'application/json'})
    response=connection.getresponse()
    assert response.status==400 and KEY.encode() not in response.read()
    connection.close()
    assert not broker.writes.get(prepared['write_handle']).import_candidates


def test_large_deep_and_wrong_format_http_is_secret_free(deployed):
    broker, _, path, socket=deployed
    prepared=prepare(broker)
    for payload in ['['*2000+KEY+']'*2000,'["'+KEY+'"]'+'x'*70000,'{"payloads":"'+KEY+'"}']:
        status,_,body=private(socket,prepared,'/totp/import',{'payloads':payload})
        assert status==400 and KEY.encode() not in body
    assert not broker.writes.get(prepared['write_handle']).import_candidates


def test_early_oversized_rejection_is_read_without_resending(deployed, monkeypatch):
    broker, _, path, socket = deployed
    before = path.read_bytes()
    prepared = prepare(broker)
    requests, bodies = [], []
    class EarlyRejection(UnixHTTPConnection):
        def request(self, *args, **kwargs):
            requests.append(True)
            return super().request(*args, **kwargs)
        def send(self, data):
            if isinstance(data, bytes) and data.startswith(b'payloads='):
                bodies.append(True)
                # Headers have reached the real server. Its Content-Length
                # check rejects this body before upload can finish.
                raise BrokenPipeError('synthetic early rejection')
            return super().send(data)
    monkeypatch.setattr(sys.modules[__name__], 'UnixHTTPConnection', EarlyRejection)
    status, _, body = private(socket, prepared, '/totp/import', {'payloads': KEY + 'x'*70000})
    assert status == 400 and KEY.encode() not in body
    assert len(requests) == len(bodies) == 1
    assert path.read_bytes() == before
    assert not broker.writes.get(prepared['write_handle']).import_candidates


def test_native_exception_never_reveals_key(monkeypatch):
    def fail(*_):raise RuntimeError(KEY)
    monkeypatch.setattr(browser_import,'capture',fail)
    raw=json.dumps({'payloads':[URI]}).encode();output=io.BytesIO()
    browser_import.native_session(io.BytesIO(struct.pack('<I',len(raw))+raw),output,
        {'extension_id':'a'*32},'chrome-extension://'+'a'*32+'/')
    assert KEY.encode() not in output.getvalue()
    assert json.loads(output.getvalue()[4:])['ok'] is False


def test_host_install_is_explicit_and_refuses_overwrite(tmp_path,monkeypatch):
    from types import SimpleNamespace
    base=tmp_path/'configuration';base.mkdir(mode=0o700)
    monkeypatch.setenv('XDG_CONFIG_HOME',str(base))
    executable=tmp_path/'akdbx-browser-import'
    executable.write_text('#!/bin/sh\nexit 1\n');executable.chmod(0o700)
    monkeypatch.setattr(sys,'argv',[str(executable)])
    args=SimpleNamespace(extension_id='a'*32,origin='https://private.example:9443',socket=tmp_path/'unlock.sock',manifest_dir=tmp_path/'NativeMessagingHosts')
    browser_import.install_host(args)
    path=browser_import.config_path()
    manifest=args.manifest_dir/(browser_import.HOST_NAME+'.json')
    assert path.stat().st_mode & 0o777==0o600
    assert browser_import.load_config(path)['extension_id']=='a'*32
    saved=manifest.read_bytes();config=path.read_bytes()
    assert json.loads(saved)['path']==str(executable)
    with pytest.raises(ValueError):browser_import.install_host(args)
    assert manifest.read_bytes()==saved and path.read_bytes()==config


@pytest.mark.parametrize('competing_install', [False, True])
def test_host_install_records_invoked_script_without_path_lookup(tmp_path, competing_install):
    """An absolute console command must not select a missing or competing PATH host."""
    installation=tmp_path/'intended install';installation.mkdir()
    executable=installation/'akdbx-browser-import'
    executable.write_text(f'#!{sys.executable}\nfrom akdbx.browser_import import main\nraise SystemExit(main())\n')
    executable.chmod(0o700)
    other=tmp_path/'other-bin';other.mkdir()
    if competing_install:
        wrong=other/'akdbx-browser-import'
        wrong.write_text('#!/bin/sh\nexit 99\n');wrong.chmod(0o700)
    configuration=tmp_path/'config';configuration.mkdir(mode=0o700)
    manifests=tmp_path/'NativeMessagingHosts'
    result=subprocess.run([str(executable),'install-host','--extension-id','a'*32,
        '--origin','https://private.example:9443','--socket',str(tmp_path/'unlock.sock'),
        '--manifest-dir',str(manifests)],env={**os.environ,'PATH':str(other),
        'XDG_CONFIG_HOME':str(configuration),'PYTHONPATH':str(Path(browser_import.__file__).parents[1])},
        cwd=tmp_path,capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    manifest=json.loads((manifests/(browser_import.HOST_NAME+'.json')).read_text())
    assert manifest['path']==str(executable)


def test_importer_capabilities_are_independent_and_strict():
    from akdbx import cli
    from akdbx.totp import capabilities
    caps=capabilities()
    assert caps['totp_import_supported'] is True and type(caps['totp_import_protocol']) is int
    for bad in [dict(ok=True,totp_import_protocol=True),dict(ok=True,totp_import_protocol=2),
                dict(ok=True,totp_import_supported=1)]:
        with pytest.raises(cli.ProtocolError):cli._validate_response(bad,'https://private.example')


def test_native_host_subprocess_to_private_broker(deployed,tmp_path):
    broker, _, path, socket=deployed
    prepared=prepare(broker)
    before=path.read_bytes()
    root=tmp_path/'native-configuration';root.mkdir(mode=0o700)
    directory=root/'akdbx';directory.mkdir(mode=0o700)
    config=directory/'browser-import.json'
    config.write_text(json.dumps({'extension_id':'a'*32,'origin':'https://node.example:9443','socket':str(socket)}))
    config.chmod(0o600)
    message=json.dumps({'private_url':prepared['private_url'],'source_url':'https://example.test/setup','payloads':[URI]}).encode()
    result=subprocess.run([sys.executable,'-m','akdbx.browser_import','chrome-extension://'+'a'*32+'/'],
        input=struct.pack('<I',len(message))+message,capture_output=True,timeout=15,
        env={**os.environ,'XDG_CONFIG_HOME':str(root),'PYTHONPATH':str(Path(__file__).parent.parent/'src')})
    assert result.returncode==0 and result.stderr==b''
    assert json.loads(result.stdout[4:])==browser_import.RECEIPT
    assert KEY.encode() not in result.stdout+result.stderr
    assert path.read_bytes()==before
    assert private(socket,prepared,'/totp/review')[0]==200
