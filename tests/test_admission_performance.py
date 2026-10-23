"""Full-cost generated KDBX4.1, actual CLI/RPC and two-hop HTTP timings.

Ten seconds is a measured client deadline, not a guarantee under arbitrary
load. Thirty seconds must succeed on this host. Metrics contain no record data.
"""
import hashlib
import io
import json
import os
import shutil
import resource
import time
import uuid
from datetime import timedelta
from pathlib import Path

from pykeepass import PyKeePass,create_database
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids

from agentic_kdbx import merge as merging, versions
from agentic_kdbx.broker import Broker,open_vault_with_password
from test_broker import running_broker,RecordingTyper
from test_merge import MASTER,BASE_TIME
from upload_lab import Lab,servers,http,KeePassiumSequence


def save_metrics(path, metrics):
    path=Path(path)
    next_path=path.with_name(path.name+'.next')
    fd=os.open(next_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(metrics,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    os.replace(next_path,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def full_fixture(path):
    v=create_database(io.BytesIO(),password=MASTER)
    params=v.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    params['I'].value=1;params['M'].value=1024*1024
    for i in range(300):
        e=v.add_entry(v.root_group,'Synthetic record '+str(i),'synthetic', 'synthetic active value')
        e.set_custom_property('Synthetic protected field',hashlib.shake_256(str(i).encode()).hexdigest(128),protect=True)
        if i%10==0:e.add_attachment(v.add_binary(hashlib.shake_256(('attachment'+str(i)).encode()).digest(16384)),'synthetic.bin')
        for day in range(3):
            e.password='synthetic historical value '+str(day);e.mtime=BASE_TIME+timedelta(days=day);e.save_history()
        e.password='synthetic active value';e.mtime=BASE_TIME+timedelta(days=4)
    versions.ensure(v,versions.collect([v],capture=True))
    params['$UUID'].value=kdf_uuids['argon2'];params['I'].value=119;params['M'].value=67108864
    params['P'].value=2;params['V'].value=19;v.kdbx.header.value.minor_version=1
    v.save(path)
    assert len(versions.archives(v))==1200
    return v


def next_save(path,day):
    began=time.monotonic();v=PyKeePass(path,password=MASTER)
    e=next(versions.active_entries(v));e.save_history();e.password='synthetic phone edit '+str(day)
    e.mtime=BASE_TIME+timedelta(days=day)
    # Keep realistic ordinary history size constant without modifying capsules.
    e.delete_history(history_entry=e.history[0])
    v.save(path)
    return time.monotonic()-began


def test_full_cost_deadlines_consecutive_sha512_and_native_baseline(tmp_path,monkeypatch):
    vaultdir=tmp_path/'vault';vaultdir.mkdir(mode=0o700)
    snapshots=tmp_path/'snapshots';snapshots.mkdir(mode=0o700)
    staging=tmp_path/'uploads';staging.mkdir(mode=0o700)
    target=vaultdir/'target.kdbx';source=tmp_path/'source.kdbx'
    print('full-cost fixture: start',flush=True)
    started=time.monotonic();full_fixture(target);fixture_s=time.monotonic()-started
    print('full-cost fixture: saved',flush=True)
    shutil.copyfile(target,source);initial=target.read_bytes()
    broker=Broker(open_vault_with_password(target,MASTER),RecordingTyper())
    socket=tmp_path/'runtime'/'broker.sock';lab=Lab(target,snapshots,staging,socket)
    metrics={'fixture_s':fixture_s,'encrypted_bytes':len(initial),'entries':300,'history':900,'capsules':1200,
             'kdbx':'4.1','cipher':'AES256','kdf':'Argon2d','I':119,'M':67108864,'P':2,'V':19,'uploads':[]}
    report=Path(os.environ.get('AKDBX_SYNTHETIC_BENCHMARK_REPORT',str(tmp_path/'benchmark.json')))
    save_metrics(report,metrics)
    with running_broker(socket,broker),servers(lab) as address:
        client=KeePassiumSequence(address);client.read()
        for day,deadline in ((5,10),(6,30),(7,10)):
            metrics['client_encrypt_open_s']=next_save(source,day)
            data=source.read_bytes();op=uuid.uuid4().hex;began=time.monotonic()
            try:
                status=client.save(data,timeout=deadline,operation=op)
                elapsed=time.monotonic()-began
                assert status==204
                met=True
            except TimeoutError:
                elapsed=time.monotonic()-began;met=False
                assert deadline==10, '30-second full-cost admission deadline missed'
                assert lab.finished.wait(90)
                result=lab.command('merge-status',op);assert result['state']=='saved',result
                # A timed-out native client must recover status and re-read;
                # it cannot cache an unacknowledged upload as confirmed.
                client.read()
            assert target.read_bytes()==data and source.read_bytes()==data
            assert hashlib.sha512(http(address,'GET')[1]).digest()==client.cached
            metrics['uploads'].append({'deadline_s':deadline,'client_observed_s':elapsed,'met_deadline':met,**lab.metrics[-1]})
            save_metrics(report,metrics)
            print('full-cost upload',deadline,'seconds deadline:',met,'elapsed',round(elapsed,3),flush=True)
        # A Windows-style atomic external re-encryption forces a fresh current
        # decrypt as well as the fresh incoming decrypt. Logical state is kept;
        # branch-loss/conflict cases are independently tested in the HTTP lab.
        external=PyKeePass(target,password=MASTER)
        replacement=tmp_path/'windows-replacement.kdbx';external.save(replacement)
        os.replace(replacement,target)
        client.read();next_save(source,8)
        began=time.monotonic()
        assert client.save(source.read_bytes(),timeout=30)==204
        elapsed=time.monotonic()-began
        result=next(reversed(lab.results.values()))
        assert result['target_refreshed'] is True and result['timings']['current_decrypt_s']>0.1
        metrics['external_replacement']={'deadline_s':30,'client_observed_s':elapsed,**lab.metrics[-1]}
        save_metrics(report,metrics)
        print('full-cost external replacement: saved',round(elapsed,3),flush=True)
        assert not any(result.get('state')=='uncertain' for result in lab.results.values())
        assert broker.vault._akdbx_store.verified_encrypted==target.read_bytes()
    # Reopen after the complete encrypted round trip and check exact capsule
    # ledger, full active data, KDF cost and source immutability independently.
    reopened=PyKeePass(target,password=MASTER)
    assert len(versions.archives(reopened))==1200
    assert len(list(versions.active_entries(reopened)))==300
    assert sum(len(e.history) for e in versions.active_entries(reopened))==900
    assert reopened.version==(4,1)
    actual_params=reopened.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    assert {k:actual_params[k].value for k in ('I','M','P','V')}=={'I':119,'M':67108864,'P':2,'V':19}
    assert actual_params['$UUID'].value==kdf_uuids['argon2']
    assert reopened.kdbx.header.value.dynamic_header.cipher_id.data=='aes256'
    # Actual native default path on a separate full-cost fixture, instrumented
    # only inside this synthetic test process. Never make a live timing probe.
    print('full-cost native reference: start',flush=True)
    native_dir=tmp_path/'native';native_dir.mkdir(mode=0o700)
    native_target=native_dir/'target.kdbx';native_target.write_bytes(initial)
    reference_broker=Broker(open_vault_with_password(native_target,MASTER),RecordingTyper())
    timings=[];real_open=merging._open;real_engine=merging.run_engine;real_save=PyKeePass.save
    def measured(label,fn):
        def call(*a,**k):
            began=time.monotonic()
            try:return fn(*a,**k)
            except Exception as exc:
                metrics['failure_type']=type(exc).__name__
                raise
            finally:timings.append({'stage':label,'seconds':time.monotonic()-began})
        return call
    monkeypatch.setattr(merging,'_open',measured('decrypt_reopen',real_open))
    monkeypatch.setattr(merging,'run_engine',measured('native_engine',real_engine))
    monkeypatch.setattr(PyKeePass,'save',measured('encrypt_save',real_save))
    began=time.monotonic()
    result=reference_broker.dispatch({'action':'merge','source':str(source),'refresh_target':True,'preserve_conflicts':True,'operation_id':uuid.uuid4().hex})
    metrics['native_total_s']=time.monotonic()-began;metrics['native_stages']=timings
    metrics['native_result']={k:result.get(k) for k in ('ok','state','error')}
    metrics['max_rss_kib']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    save_metrics(report,metrics)
    assert result['ok'] and result['state']=='saved',result
    assert native_target.read_bytes()!=source.read_bytes()
    metrics['native_preserved_versions']=result['preserved_versions']
    save_metrics(report,metrics)
    print('full-cost native reference: saved',round(metrics['native_total_s'],3),flush=True)
