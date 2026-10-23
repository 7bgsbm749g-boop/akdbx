"""Synthetic conditional admission: exact encrypted bytes, never a merge."""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from pykeepass import PyKeePass

from agentic_kdbx import admission, cli, group_selection, merge as merging, selection, versions
from agentic_kdbx.broker import Broker, open_vault_with_password
from agentic_kdbx.persistence import VaultStore
from test_broker import RecordingTyper, running_broker
from test_merge import MASTER, SECRET, BASE_TIME, base, tombstone
from test_selection import put, style, CASES


@pytest.fixture
def case(tmp_path, base):
    folder = tmp_path / 'vault'; folder.mkdir(mode=0o700)
    snapshots = tmp_path / 'snapshots'; snapshots.mkdir(mode=0o700)
    target, source = folder / 'target.kdbx', tmp_path / 'incoming.kdbx'
    shutil.copyfile(base, target)
    vault = PyKeePass(target, password=MASTER)
    versions.ensure(vault, versions.collect([vault], capture=True))
    vault.save()
    shutil.copyfile(target, source)
    broker = Broker(open_vault_with_password(target, MASTER), RecordingTyper())
    return broker, target, source, snapshots


def admit(case, **options):
    broker, target, source, snapshots = case
    return broker.dispatch({'action': 'admit', 'source': str(source),
                            'snapshot_directory': str(snapshots), 'policy': admission.POLICY,
                            'verification': admission.VERIFICATION,
                            'operation_id': uuid.uuid4().hex, **options})


def edit(source, *, password='synthetic newer phone value', day=2):
    vault = PyKeePass(source, password=MASTER)
    entry = vault.find_entries(title='Shared', first=True)
    entry.save_history(); entry.password = password; entry.mtime = BASE_TIME + timedelta(days=day)
    vault.save()
    return vault


def bundle(result):
    return Path(result['receipt_path']).parent


def test_exact_bytes_preview_reopen_refresh_history_trim_reencrypted_retry(case, caplog, capsys):
    broker, target, source, snapshots = case
    before = target.read_bytes(); handle = broker.dispatch({'action': 'search','query':'Shared'})['entries'][0]['handle']
    vault = edit(source)
    # This separately named policy permits ordinary History pruning, with full
    # original versions still in retained encrypted inputs. No capsule removed.
    vault.find_entries(title='Shared', first=True).delete_history(all=True); vault.save()
    incoming = source.read_bytes(); ledger = versions.archives(broker.vault)
    checked = admit(case, check=True)
    assert checked['state'] == 'checked' and checked['exact_bytes']
    assert target.read_bytes() == before and broker.vault.password == MASTER
    result = admit(case)
    assert result['ok'] and result['state'] == 'saved', result
    assert result['policy'] == admission.POLICY and result['verification'] == admission.VERIFICATION
    assert target.read_bytes() == incoming == source.read_bytes()
    assert broker.vault.find_entries(title='Shared', first=True).password == 'synthetic newer phone value'
    assert not broker.dispatch({'action':'fill','handle':handle})['ok']
    assert versions.archives(PyKeePass(target, password=MASTER)) == ledger
    for name, data in [('target.kdbx',before),('broker.kdbx',before),('source.kdbx',incoming),('candidate.kdbx',incoming)]:
        assert (bundle(result)/name).read_bytes() == data
    assert bundle(result).parent == snapshots
    assert not list(target.parent.glob('*.kdbx.akdbx-merge-*'))
    for path in bundle(result).iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert MASTER.encode() not in path.read_bytes() and SECRET.encode() not in path.read_bytes()
    assert admit(case,operation_id=result['operation_id']) == result
    again = admit(case); assert again['state'] == 'unchanged', again
    vault = PyKeePass(source,password=MASTER); vault.save()
    assert source.read_bytes() != incoming
    retry = admit(case); assert retry['state'] == 'saved', retry
    assert target.read_bytes() == source.read_bytes()
    response = json.dumps(result)+caplog.text+capsys.readouterr().out
    for secret in (MASTER, SECRET, 'Shared', 'synthetic newer phone value'):
        assert secret not in response


@pytest.mark.parametrize('change', ['missing','older','tie','capsule-drop','capsule-corrupt','kdf','cipher','settings','group','protected','tombstone'])
@pytest.mark.parametrize('profile', admission.GROUP_VERIFIERS)
def test_refusal_preserves_originals_and_fixed_diagnostics(case, change, profile):
    broker,target,source,_ = case
    v = PyKeePass(source,password=MASTER); e=v.find_entries(title='Shared',first=True)
    if change == 'missing': v.delete_entry(e)
    elif change in {'older','tie'}:
        e.password='synthetic refused';e.mtime=BASE_TIME-timedelta(days=1) if change=='older' else BASE_TIME
    elif change=='capsule-drop': v.delete_entry(next(g for g in v.groups if versions.is_archive_group(g)).entries[0])
    elif change=='capsule-corrupt':
        cap=next(g for g in v.groups if versions.is_archive_group(g)).entries[0]
        cap.attachments[0].delete();cap.add_attachment(v.add_binary(b'not a capsule'),'original-record.akdbx')
    elif change=='kdf': v.kdbx.header.value.dynamic_header.kdf_parameters.data.dict['I'].value=2
    elif change=='cipher':
        v.kdbx.header.value.dynamic_header.cipher_id.data='chacha20'
        v.kdbx.header.value.dynamic_header.encryption_iv.data=os.urandom(12)
    elif change=='settings': v.database_name='synthetic changed settings'
    elif change=='group': v.find_groups(name='Synthetic group',first=True).name='synthetic changed group'
    elif change=='protected':
        e._element.find('./String[Key="Password"]/Value').set('Protected','False');e.mtime=BASE_TIME+timedelta(days=1)
    elif change=='tombstone':
        tombstone(broker.vault,broker.vault.find_entries(title='Delete me',first=True),BASE_TIME+timedelta(days=1))
        # Establish a verified current state through an ordinary encrypted save.
        broker.vault.save(target); broker.vault=open_vault_with_password(target,MASTER)
    v.save(); before=target.read_bytes(); incoming=source.read_bytes()
    result=admit(case, group_protocol=2, group_verification=profile)
    assert not result['ok'] and result['state']=='failed',result
    assert target.read_bytes()==before and source.read_bytes()==incoming
    assert (bundle(result)/'source.kdbx').read_bytes()==incoming
    text=json.dumps(result)
    assert 'Shared' not in text and 'synthetic refused' not in text and MASTER not in text
    if 'verification_diagnostics' in result:
        assert set(result['verification_diagnostics']) <= admission.CATEGORIES | selection.CATEGORIES | group_selection.CATEGORIES


def test_deletion_addition_custom_attachment_and_native_reference(case, tmp_path):
    broker,target,source,_=case
    v=edit(source)
    e=v.find_entries(title='Shared',first=True)
    e.set_custom_property('Synthetic protected field','synthetic field value',protect=True)
    e.add_attachment(v.add_binary(b'synthetic bytes'),'synthetic.bin')
    group=v.add_group(v.root_group,'New group'); new=v.add_entry(group,'New entry','synthetic','synthetic')
    tombstone(v,v.find_entries(title='Delete me',first=True),BASE_TIME+timedelta(days=3))
    tombstone(v,v.find_groups(name='Delete empty group',first=True),BASE_TIME+timedelta(days=3));v.save()
    # Independent actual KeePassXC engine reference, then repository tombstone
    # semantics. Admission itself never calls the engine or changes input bytes.
    reference=tmp_path/'reference';reference.mkdir(mode=0o700)
    shutil.copyfile(target,reference/'candidate.kdbx');shutil.copyfile(source,reference/'source.kdbx')
    merging.run_engine(reference,broker.vault)
    native=PyKeePass(reference/'candidate.kdbx',password=MASTER)
    merging.synchronize_deletions(native,broker.vault,v)
    selection.verify(v,(native, v))
    before=source.read_bytes();result=admit(case)
    assert result['ok'],result
    assert target.read_bytes()==before
    actual=PyKeePass(target,password=MASTER)
    assert {e.uuid for e in versions.active_entries(actual)}=={e.uuid for e in versions.active_entries(native)}
    selection.verify(actual,(native,actual))
    assert actual.find_entries(title='Shared',first=True).attachments[0].data==b'synthetic bytes'


@pytest.mark.parametrize('case_name', ['empty-protected-password','quality-false','custom-data','custom-data-timed','tags-unicode','autotype-associations','expired','creation-non-epoch','iso-times','iso-offset-times'])
def test_legitimate_native_style_entry_metadata(case,case_name,tmp_path):
    broker,target,source,_=case
    v=PyKeePass(source,password=MASTER);style(v,case_name)
    v.find_entries(title='Shared',first=True).mtime=BASE_TIME+timedelta(days=3);v.save()
    ref=tmp_path/'ref';ref.mkdir(mode=0o700)
    shutil.copyfile(target,ref/'candidate.kdbx');shutil.copyfile(source,ref/'source.kdbx')
    merging.run_engine(ref,broker.vault)
    native=PyKeePass(ref/'candidate.kdbx',password=MASTER)
    selection.verify(native,(broker.vault,v))
    result=admit(case);assert result['ok'],result
    selection.verify(PyKeePass(target,password=MASTER),(native,))


def test_external_branch_cannot_discard_held_then_explicit_reconcile(case):
    broker,target,source,_=case
    held=target.read_bytes()
    external=PyKeePass(source,password=MASTER);external.add_entry(external.root_group,'External only','synthetic','synthetic');external.save(target)
    v=edit(source);v.add_entry(v.root_group,'Incoming only','synthetic','synthetic');v.save()
    before=target.read_bytes();refused=admit(case)
    assert not refused['ok'] and target.read_bytes()==before
    assert (bundle(refused)/'broker.kdbx').read_bytes()==held
    merged=broker.dispatch({'action':'merge','source':str(source),'refresh_target':True,'preserve_conflicts':True,'operation_id':uuid.uuid4().hex})
    assert merged['ok'],merged
    # A fresh client GET/open after explicit reconciliation is required.
    shutil.copyfile(target,source);edit(source,day=4)
    accepted=admit(case);assert accepted['ok'],accepted
    assert broker.vault.find_entries(title='External only',first=True)


@pytest.mark.parametrize('which', ['incoming','current'])
def test_wrong_key_no_reset(case,which):
    broker,target,source,_=case
    path=source if which=='incoming' else target
    wrong=PyKeePass(path,password=MASTER);wrong.password='synthetic different master';wrong.save()
    before=target.read_bytes();result=admit(case)
    assert result['state']=='failed' and target.read_bytes()==before
    assert 'synthetic different master' not in json.dumps(result)
    assert broker.vault.password==MASTER


@pytest.mark.parametrize('phase',['source-race','target-race','write-failure','rename-failure','after-replace','receipt-failure','interrupt'])
def test_race_faults_and_restart_recovery(case,monkeypatch,phase):
    broker,target,source,_=case;edit(source);before=target.read_bytes()
    real_verify=admission.verify;real_replace=os.replace;real_receipt=broker.merges._receipt
    def verify(*a,**k):
        result=real_verify(*a,**k)
        if phase=='source-race': source.write_bytes(source.read_bytes()+b'race')
        if phase=='target-race': target.write_bytes(before+b'race')
        if phase=='interrupt': raise KeyboardInterrupt
        return result
    monkeypatch.setattr(admission,'verify',verify)
    def replace(src,dst,*a,**k):
        if dst==target.name:
            if phase=='rename-failure': raise OSError('synthetic secret exception')
            real_replace(src,dst,*a,**k)
            if phase=='after-replace': raise OSError('synthetic secret exception')
            return
        return real_replace(src,dst,*a,**k)
    monkeypatch.setattr(os,'replace',replace)
    def receipt(fd,value):
        if phase=='receipt-failure' and value['state']=='saved': raise OSError('synthetic secret exception')
        return real_receipt(fd,value)
    monkeypatch.setattr(broker.merges,'_receipt',receipt)
    if phase=='write-failure':
        original=VaultStore._write_file
        def fail(fd,name,data):
            if name.endswith('.replace'): raise OSError('synthetic secret exception')
            return original(fd,name,data)
        monkeypatch.setattr(VaultStore,'_write_file',staticmethod(fail))
    if phase=='interrupt':
        with pytest.raises(KeyboardInterrupt):admit(case)
        reopened=open_vault_with_password(target,MASTER)
        assert reopened._akdbx_store.recovery_required
    else:
        result=admit(case);assert not result['ok'],result
        assert 'synthetic secret exception' not in json.dumps(result)
        if phase in {'after-replace','receipt-failure'}:
            assert result['state']=='uncertain'
            assert open_vault_with_password(target,MASTER)._akdbx_store.recovery_required
        elif phase!='target-race':assert target.read_bytes()==before


def test_precondition_concurrency_policy_guards_and_locked(case,monkeypatch):
    broker,target,source,_=case;edit(source)
    assert not admit(case,if_match='f'*64)['ok']
    assert admit(case,if_match=hashlib.sha256(target.read_bytes()).hexdigest())['ok']
    assert not admit(case,policy='capsule-v1')['ok']
    assert not admit(case,verification='old')['ok']
    assert not admit(case,preserve_conflicts=True)['ok']
    assert not admit(case,if_match='*')['ok']
    ready=threading.Event();release=threading.Event()
    def hold():
        with broker._vault_lock:
            ready.set();release.wait(5)
    worker=threading.Thread(target=hold);worker.start();assert ready.wait(2)
    try:assert 'busy' in admit(case)['error']
    finally:release.set();worker.join(2)
    broker.vault=None;broker.unlock_url='https://synthetic.test/private'
    assert admit(case)['error']=='vault locked'


def test_keyfile_and_rotation_guard(case,tmp_path,monkeypatch):
    broker,target,source,_=case
    key=tmp_path/'synthetic.key';key.write_bytes(b'synthetic key material')
    for path in (target,source):
        v=PyKeePass(path,password=MASTER);v.keyfile=str(key);v.save()
    broker.vault=open_vault_with_password(target,MASTER,key)
    assert admit(case)['ok']
    key.write_bytes(b'changed synthetic key')
    result=admit(case);assert not result['ok'] and 'key file changed' in result['error']


def test_real_cli_policy_capabilities_and_restart_status(case,tmp_path):
    broker,target,source,snapshots=case;edit(source)
    socket=tmp_path/'runtime'/'broker.sock'
    with running_broker(socket,broker):
        cmd=[sys.executable,'-m','agentic_kdbx.cli','--socket',str(socket)]
        result=subprocess.run([*cmd,'admit',str(source),'--policy',admission.POLICY,'--snapshot-dir',str(snapshots)],capture_output=True,text=True)
        assert result.returncode==0,result.stderr+result.stdout
        value=json.loads(result.stdout);assert value['state']=='saved'
        assert cli.request(socket,{'action':'ping'})['admission_policy']==admission.POLICY
    restarted=Broker(open_vault_with_password(target,MASTER),RecordingTyper())
    assert restarted.merges.status(value['operation_id'])==value
    assert not restarted.vault._akdbx_store.recovery_required


def test_genuine_old_cli_rejection_and_result_downgrade(case,monkeypatch,capsys):
    _,_,source,snapshots=case
    calls=[]
    def old(sock,payload,**kw):
        calls.append(payload);return {'ok':True,'version':'0.6.0','merge_preservation_policy':'capsule-v1'}
    monkeypatch.setattr(cli,'request',old)
    args=['admit',str(source),'--policy',admission.POLICY,'--snapshot-dir',str(snapshots)]
    assert cli.main(args)==1 and [p['action'] for p in calls]==['ping']
    def downgraded(sock,payload,**kw):
        if payload['action']=='ping':return case[0].dispatch({'action':'ping'})
        return {'ok':True,'state':'saved','policy':'capsule-v1'}
    monkeypatch.setattr(cli,'request',downgraded)
    assert cli.main(args)==2

@pytest.mark.parametrize('unsafe',['symlink-source','same-inode','public-snapshots','inside-vault','rebind','missing-locator','snapshot-race'])
def test_path_snapshot_binding_and_identity_guards(case,tmp_path,monkeypatch,unsafe):
    broker,target,source,snapshots=case;edit(source);before=target.read_bytes()
    if unsafe=='symlink-source':
        alternate=source.with_name('real-incoming.kdbx');source.rename(alternate);source.symlink_to(alternate)
    elif unsafe=='same-inode':source.unlink();os.link(target,source)
    elif unsafe=='public-snapshots':snapshots.chmod(0o755)
    elif unsafe=='inside-vault':
        nested=target.parent/'snapshots';nested.mkdir(mode=0o700)
        result=admit(case,snapshot_directory=str(nested));assert not result['ok'];return
    elif unsafe in {'rebind','missing-locator'}:
        assert admit(case,check=True)['ok']
        if unsafe=='rebind':
            other=tmp_path/'other-snapshots';other.mkdir(mode=0o700)
            result=admit(case,snapshot_directory=str(other));assert not result['ok'];return
        # Lost external storage must not be treated as no interrupted work.
        snapshots.rename(tmp_path/'retained-snapshots')
    elif unsafe=='snapshot-race':
        original=broker.merges._receipt
        def receipt(fd,value):
            original(fd,value)
            if value['state']=='prepared':
                snapshots.rename(tmp_path/'retained-snapshots');snapshots.mkdir(mode=0o700)
        monkeypatch.setattr(broker.merges,'_receipt',receipt)
    result=admit(case)
    assert not result['ok'] and target.read_bytes()==before


def test_unlocked_state_contains_all_three_active_branches_before_admission(case,tmp_path):
    broker,target,source,_=case
    # Current held image has a broker-only active UUID.
    v=PyKeePass(target,password=MASTER);v.add_entry(v.root_group,'Held only','synthetic','synthetic');v.save()
    broker.vault=open_vault_with_password(target,MASTER);held=target.read_bytes()
    external=PyKeePass(source,password=MASTER);external.add_entry(external.root_group,'External only','synthetic','synthetic');external.save(target)
    incoming=PyKeePass(source,password=MASTER);incoming.add_entry(incoming.root_group,'Incoming only','synthetic','synthetic');incoming.save()
    refusal=admit(case);assert not refusal['ok']
    assert refusal['verification_diagnostics'].get('missing_entry')==2
    # Supported explicit native reconciliation, fresh read, then byte admission.
    reconciled=broker.dispatch({'action':'merge','source':str(source),'refresh_target':True,'preserve_conflicts':True,'operation_id':uuid.uuid4().hex})
    assert reconciled['ok'],reconciled
    shutil.copyfile(target,source);edit(source,day=5)
    result=admit(case);assert result['ok'],result
    assert {e.title for e in versions.active_entries(broker.vault)}>={'Held only','External only','Incoming only'}


@pytest.mark.parametrize('commit,version', [('42cdedee4b75d151def765543419536f3fe4d348','0.6.0'), ('d3657b7f9337895ce65068a4b9a57341fe90e783','0.7.0'), ('642c5c194cbdad4754a8c8a0dc24a437f0ace5c2','0.7.1')])
def test_actual_old_broker_rejected_and_070_receipts_recover(case,tmp_path,commit,version):
    """Run the real previous committed broker, not a mocked capability dict."""
    broker,target,source,snapshots=case
    frozen=tmp_path/'frozen';frozen.mkdir(mode=0o700)
    # Git object source only; never read the separate production checkout.
    archive=subprocess.run(['git','archive',commit,'src'],capture_output=True,check=True)
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:tar.extractall(frozen,filter='data')
    socket=tmp_path/'old-runtime'/'broker.sock';socket.parent.mkdir(mode=0o700)
    script=tmp_path/'old-broker.py'
    script.write_text("from pathlib import Path\nimport sys\nfrom test_merge import MASTER\nfrom agentic_kdbx.broker import Broker,open_vault_with_password,serve\nfrom test_broker import RecordingTyper\nserve(Path(sys.argv[2]),Broker(open_vault_with_password(Path(sys.argv[1]),MASTER),RecordingTyper()))\n")
    env={**os.environ,'PYTHONPATH':str(frozen/'src')+os.pathsep+str(Path(__file__).parent)}
    process=subprocess.Popen([sys.executable,str(script),str(target),str(socket)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    historical=None
    try:
        end=time.monotonic()+8
        while not socket.exists() and time.monotonic()<end:time.sleep(0.02)
        assert cli.request(socket,{'action':'ping'})['version']==version
        for profile in admission.GROUP_VERIFIERS:
            result=subprocess.run([sys.executable,'-m','agentic_kdbx.cli','--socket',str(socket),'admit',str(source),'--policy',admission.POLICY,'--snapshot-dir',str(snapshots),'--group-verification',profile],capture_output=True,text=True)
            assert result.returncode==1 and 'admission not sent' in result.stdout
        assert not list(snapshots.iterdir())
        if version in {'0.7.0','0.7.1'}:
            # The actual prior CLI/server writes its original external locator
            # and receipt. The new broker must recover it without migration.
            old=subprocess.run([sys.executable,'-m','agentic_kdbx.cli','--socket',str(socket),'admit',str(source),'--policy',admission.POLICY,'--snapshot-dir',str(snapshots)],env=env,capture_output=True,text=True)
            assert old.returncode==0,old.stdout+old.stderr
            historical=json.loads(old.stdout)
            assert historical['state']=='unchanged' and 'group_protocol' not in historical
            assert historical.get('group_verification') == ('group-semantic-v1' if version=='0.7.1' else None)
    finally:process.terminate();process.wait(5)
    if historical:
        reopened=Broker(open_vault_with_password(target,MASTER),RecordingTyper())
        assert reopened.merges.status(historical['operation_id'])==historical
        assert not reopened.vault._akdbx_store.recovery_required
        with running_broker(tmp_path/'new-runtime'/'broker.sock',reopened):
            command=[sys.executable,'-m','agentic_kdbx.cli','--socket',str(tmp_path/'new-runtime'/'broker.sock')]
            status=subprocess.run([*command,'merge-status',historical['operation_id']],capture_output=True,text=True)
            assert status.returncode==0 and json.loads(status.stdout)==historical
            reused=subprocess.run([*command,'admit',str(source),'--policy',admission.POLICY,'--snapshot-dir',str(snapshots),'--operation-id',historical['operation_id']],capture_output=True,text=True)
            assert reused.returncode==2 and 'outcome unconfirmed' in reused.stderr


def test_capsule_optimization_matches_frozen_original_and_revalidates_changed_bytes(case):
    import copy
    broker,_,source,_=case
    original={}
    frozen=subprocess.run(['git','show','42cdedee4b75d151def765543419536f3fe4d348:src/agentic_kdbx/versions.py'],capture_output=True,check=True)
    exec(compile(frozen.stdout,'frozen_versions.py','exec'),original)
    vault=PyKeePass(source,password=MASTER)
    for entry in versions.active_entries(vault):
        for record in [entry,*entry.history]:
            assert versions._json(versions._capsule(record,entry.group))==original['_json'](original['_capsule'](record,entry.group))
    known=versions.archives(vault)
    assert versions.archives(vault,trusted=known)==known
    cap=next(g for g in vault.groups if versions.is_archive_group(g)).entries[0]
    data=cap.attachments[0].data
    changed=json.loads(data);changed['record'][2]='synthetic changed capsule'
    changed=versions._json(changed)
    cap.attachments[0].delete();cap.add_attachment(vault.add_binary(changed),versions.FILENAME)
    cap.set_custom_property(versions.CHECKSUM,hashlib.sha256(changed).hexdigest(),protect=True)
    with pytest.raises(versions.PreservationError):versions.archives(vault,trusted=known)


@pytest.mark.parametrize('kind',['negative-binary','duplicate-tombstone','database-knownbad','snapshot-corruption'])
def test_structural_metadata_and_snapshot_readback_fail_closed(case,kind,monkeypatch):
    broker,target,source,_=case;before=target.read_bytes()
    v=PyKeePass(source,password=MASTER)
    if kind=='negative-binary':
        e=v.find_entries(title='Shared',first=True);e.add_attachment(v.add_binary(b'synthetic'),'synthetic.bin')
        e._element.find('./Binary/Value').set('Ref','-1');v.save()
    elif kind=='duplicate-tombstone':
        tombstone(v,v.find_entries(title='Delete me',first=True),BASE_TIME+timedelta(days=3))
        node=v.tree.find('./Root/DeletedObjects/DeletedObject')
        from lxml import etree
        etree.SubElement(node,'UUID').text=node.findtext('UUID');v.save()
    elif kind=='database-knownbad':
        from lxml import etree
        custom=v.tree.find('./Meta/CustomData')
        item=etree.SubElement(custom,'Item');etree.SubElement(item,'Key').text='KnownBad';etree.SubElement(item,'Value').text='synthetic metadata'
        v.save()
    else:
        real=VaultStore._write_file
        def corrupt(fd,name,data):return real(fd,name,data+b'synthetic-corruption' if name=='broker.kdbx' else data)
        monkeypatch.setattr(VaultStore,'_write_file',staticmethod(corrupt))
    result=admit(case);assert not result['ok'] and result['state']=='failed',result
    assert target.read_bytes()==before


def test_real_cli_locked_existing_private_unlock_continuation(case,tmp_path):
    from agentic_kdbx.web_unlock import start_unlock_server
    from test_web_unlock import call
    from urllib.parse import urlencode,urlsplit
    _,target,source,snapshots=case;edit(source)
    broker=Broker(None,RecordingTyper())
    web=tmp_path/'web'/'unlock.sock'
    server,url=start_unlock_server(broker,target,None,web,'https://unlock.synthetic.example:9443')
    sock=tmp_path/'runtime'/'broker.sock';op=uuid.uuid4().hex
    args=[sys.executable,'-m','agentic_kdbx.cli','--socket',str(sock),'--unlock-origin','https://unlock.synthetic.example:9443','admit',str(source),'--policy',admission.POLICY,'--snapshot-dir',str(snapshots),'--operation-id',op]
    try:
        with running_broker(sock,broker):
            locked=subprocess.run(args,capture_output=True,text=True,timeout=20)
            value=json.loads(locked.stdout)
            assert locked.returncode==1 and value['unlock_url']==url and value['operation_id']==op
            assert 'continuation' in value and not list(snapshots.iterdir())
            code,_,body=call(web,'POST','/?'+urlsplit(url).query,urlencode({'password':MASTER}),timeout=10)
            assert code==200 and MASTER.encode() not in body
            saved=subprocess.run(args,capture_output=True,text=True,timeout=20)
            assert saved.returncode==0 and json.loads(saved.stdout)['state']=='saved'
            assert target.read_bytes()==source.read_bytes()
    finally:server.shutdown();server.server_close()


def test_signature_projection_does_not_retain_binary_pool_until_cyclic_gc():
    import gc
    import weakref
    from lxml import etree
    class Pool(dict):pass
    pool=Pool();reference=weakref.ref(pool)
    was_enabled=gc.isenabled();gc.disable()
    try:
        versions._canonical(etree.Element('Entry'),pool,(4,1),times=True)
        del pool
        assert reference() is None
    finally:
        if was_enabled:gc.enable()


def test_entry_location_and_newer_than_tombstone_follow_native_selection(case,tmp_path):
    broker,target,source,_=case
    from datetime import datetime,timezone
    current=PyKeePass(target,password=MASTER)
    deleted=current.find_entries(title='Delete me',first=True)
    identity=deleted.uuid
    tombstone(current,deleted,BASE_TIME+timedelta(days=2));current.save()
    broker.vault=open_vault_with_password(target,MASTER)
    incoming=edit(source,day=4)
    group=incoming.add_group(incoming.root_group,'New moved group')
    entry=incoming.find_entries(title='Shared',first=True)
    incoming.move_entry(entry,group)
    entry._element.find('Times/LocationChanged').text=incoming._encode_time(datetime(2035,1,1,tzinfo=timezone.utc))
    revived=incoming.find_entries(title='Delete me',first=True);revived.mtime=BASE_TIME+timedelta(days=5)
    container=incoming.tree.find('./Root/DeletedObjects')
    import copy
    container.append(copy.deepcopy(broker.vault.tree.find('./Root/DeletedObjects/DeletedObject')))
    incoming.save()
    ref=tmp_path/'reference-location';ref.mkdir(mode=0o700)
    shutil.copyfile(target,ref/'candidate.kdbx');shutil.copyfile(source,ref/'source.kdbx')
    merging.run_engine(ref,broker.vault)
    native=PyKeePass(ref/'candidate.kdbx',password=MASTER)
    merging.synchronize_deletions(native,broker.vault,incoming)
    result=admit(case);assert result['ok'],result
    assert broker.vault.find_entries(title='Shared',first=True).group.uuid==group.uuid
    assert broker.vault.find_entries(title='Delete me',first=True).uuid==identity
    selection.verify(broker.vault,(native,))


@pytest.mark.parametrize('tag',['Entry','Group'])
def test_duplicate_uuid_fields_are_refused_instead_of_client_dependent_identity(case,tag):
    from lxml import etree
    broker,target,source,_=case
    v=PyKeePass(source,password=MASTER);node=v.tree.find('.//'+tag)
    etree.SubElement(node,'UUID').text=__import__('base64').b64encode(uuid.uuid4().bytes).decode()
    v.save();before=target.read_bytes();result=admit(case)
    assert not result['ok'] and target.read_bytes()==before
    assert result['verification_diagnostics']=={'unsupported_structure':1}


def test_admission_without_capsules_or_attachments(tmp_path,base):
    root=tmp_path/'vault';root.mkdir(mode=0o700)
    snapshots=tmp_path/'snapshots';snapshots.mkdir(mode=0o700)
    target=root/'target.kdbx';source=tmp_path/'incoming.kdbx'
    shutil.copyfile(base,target);shutil.copyfile(base,source)
    broker=Broker(open_vault_with_password(target,MASTER),RecordingTyper())
    edit(source)
    result=admit((broker,target,source,snapshots))
    assert result['ok'] and result['retained_capsules']==0,result
    assert target.read_bytes()==source.read_bytes()


def test_benign_database_and_group_field_order_matches_native_reference(case,tmp_path):
    broker,target,source,_=case;v=edit(source)
    for node in [v.tree.find('./Meta'),*v.tree.findall('.//Group')]:
        node[:]=list(reversed(list(node)))
    protection=v.tree.find('./Meta/MemoryProtection');protection[:]=list(reversed(list(protection)))
    v.save();incoming=source.read_bytes()
    ref=tmp_path/'reference-order';ref.mkdir(mode=0o700)
    shutil.copyfile(target,ref/'candidate.kdbx');shutil.copyfile(source,ref/'source.kdbx')
    merging.run_engine(ref,broker.vault)
    native=PyKeePass(ref/'candidate.kdbx',password=MASTER)
    result=admit(case);assert result['ok'],result
    assert target.read_bytes()==incoming==source.read_bytes()
    selection.verify(broker.vault,(native,))


def test_duplicate_database_setting_refuses_instead_of_serialization_dependent_value(case):
    import copy
    _,target,source,_=case;v=PyKeePass(source,password=MASTER)
    meta=v.tree.find('./Meta');meta.append(copy.deepcopy(meta.find('HistoryMaxItems')));v.save()
    before=target.read_bytes();result=admit(case)
    assert not result['ok'] and result['verification_diagnostics']=={'unsupported_structure':1}
    assert target.read_bytes()==before


@pytest.mark.parametrize('tag',['Meta','Root'])
def test_duplicate_database_containers_are_refused(case,tag):
    import copy
    _,target,source,_=case;v=PyKeePass(source,password=MASTER)
    v.tree.getroot().append(copy.deepcopy(v.tree.find('./'+tag)));v.save()
    before=target.read_bytes();result=admit(case)
    assert not result['ok'] and target.read_bytes()==before
    assert result['verification_diagnostics']=={'unsupported_structure':1}
