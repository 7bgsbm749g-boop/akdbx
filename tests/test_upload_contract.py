"""Real CLI/RPC through two isolated local HTTP hops; synthetic vaults only."""
import hashlib
import io
import json
import os
import shutil
import threading
import time
import uuid

import pytest
from pykeepass import PyKeePass
from agentic_kdbx import admission, versions
from agentic_kdbx.broker import Broker,open_vault_with_password
from test_broker import running_broker,RecordingTyper
from test_merge import MASTER,BASE_TIME,base
from test_admission import case,edit,admit,bundle
from upload_lab import Lab,servers,http,KeePassiumSequence


def test_consecutive_exact_bytes_and_genuine_remote_conflict(case,tmp_path):
    broker,target,source,snapshots=case
    staging=tmp_path/'uploads';staging.mkdir(mode=0o700)
    socket=tmp_path/'runtime'/'broker.sock';lab=Lab(target,snapshots,staging,socket)
    with running_broker(socket,broker),servers(lab) as address:
        client=KeePassiumSequence(address);client.read()
        for day in (2,3,4):
            edit(source,day=day);data=source.read_bytes()
            assert client.save(data)==204
            status,remote,headers=http(address,'GET');assert status==200 and remote==data
            assert http(address,'HEAD')[2]['ETag']=='"'+hashlib.sha256(data).hexdigest()+'"'
        # An external replacement produces a real remote-hash conflict, never
        # a silent conditional overwrite. A client re-read is explicit.
        external=PyKeePass(target,password=MASTER);external.add_entry(external.root_group,'External only','synthetic','synthetic');external.save(target)
        assert client.save(source.read_bytes())=='conflict'
        client.read()
        assert client.save(source.read_bytes())==409
        # Reconciliation outside the admission request, then a fresh GET.
        result=lab.command('merge',str(source),'--refresh-target','--preserve-conflicts');assert result['ok'],result
        data=client.read();source.write_bytes(data);edit(source,day=5)
        assert client.save(source.read_bytes())==204
        assert broker.vault.find_entries(title='External only',first=True)


def test_transformed_merge_positive_ack_reproduces_false_self_conflict(case,tmp_path):
    broker,target,source,snapshots=case
    staging=tmp_path/'uploads';staging.mkdir(mode=0o700)
    socket=tmp_path/'runtime'/'broker.sock';lab=Lab(target,snapshots,staging,socket);lab.mode='merge'
    with running_broker(socket,broker),servers(lab) as address:
        client=KeePassiumSequence(address);client.read();edit(source)
        assert client.save(source.read_bytes())==204
        assert target.read_bytes()!=source.read_bytes()
        assert client.save(source.read_bytes())=='conflict'


@pytest.mark.parametrize("profile",admission.GROUP_VERIFIERS)
def test_client_timeout_same_id_recovery_no_early_ack_and_metadata_queue(case,tmp_path,profile):
    broker,target,source,snapshots=case;edit(source);before=target.read_bytes()
    staging=tmp_path/'uploads';staging.mkdir(mode=0o700)
    socket=tmp_path/'runtime'/'broker.sock';lab=Lab(target,snapshots,staging,socket);lab.group_verification=profile;lab.delay=0.6
    op=uuid.uuid4().hex
    with running_broker(socket,broker),servers(lab) as address:
        with pytest.raises(TimeoutError):http(address,'PUT',source.read_bytes(),timeout=0.15,headers={'X-Test-Operation':op})
        assert lab.active.wait(1) and target.read_bytes()==before
        # Metadata is fast independently of the active mutation if it can read
        # the atomic canonical file without waiting for the operation lock.
        began=time.monotonic();assert http(address,'HEAD',timeout=0.2)[0]==200
        assert time.monotonic()-began<0.2
        # A single-worker/serialized adapter can instead exhaust a fixed
        # reference/metadata deadline. This is a separate synthetic possibility.
        lab.queue_metadata=True
        with pytest.raises(TimeoutError):http(address,'PROPFIND',timeout=0.12)
        lab.queue_metadata=False
        assert lab.finished.wait(5)
        result=lab.command('merge-status',op);assert result['state']=='saved'
        assert target.read_bytes()==source.read_bytes()
        count=len(list(snapshots.iterdir()))
        assert http(address,'PUT',source.read_bytes(),headers={'X-Test-Operation':op})[0]==204
        assert len(list(snapshots.iterdir()))==count
        # A fixed metadata delay can fail before a longer upload timeout even
        # with no active operation. It does not identify the live failure.
        lab.metadata_delay=0.25
        with pytest.raises(TimeoutError):http(address,'HEAD',timeout=0.1)


@pytest.mark.parametrize("profile",admission.GROUP_VERIFIERS)
def test_transport_if_match_false_no_if_match_held_branch_and_no_false_ack(case,tmp_path,profile):
    broker,target,source,snapshots=case;edit(source)
    staging=tmp_path/'uploads';staging.mkdir(mode=0o700)
    socket=tmp_path/'runtime'/'broker.sock';lab=Lab(target,snapshots,staging,socket);lab.group_verification=profile
    with running_broker(socket,broker),servers(lab) as address:
        before=target.read_bytes()
        assert http(address,'PUT',source.read_bytes(),headers={'If-Match':'"'+'f'*64+'"'})[0]==409
        assert target.read_bytes()==before
        assert http(address,'PUT',source.read_bytes())[0]==204
        # Current disk replacement omits a broker-held entry. No If-Match does
        # not permit discarding it, including when history/capsules contain it.
        broker.vault.add_entry(broker.vault.root_group,'Held only','synthetic','synthetic')
        broker.vault.save(target);broker.vault=open_vault_with_password(target,MASTER)
        held=target.read_bytes();shutil.copyfile(source,target)
        assert http(address,'PUT',source.read_bytes())[0]==409
        result=next(reversed(lab.results.values()))
        assert result['state']=='failed'
        assert (bundle(result)/'broker.kdbx').read_bytes()==held


@pytest.mark.parametrize("profile",admission.GROUP_VERIFIERS)
def test_transport_and_locked_broker_restart_recover_same_durable_id(case,tmp_path,profile):
    broker,target,source,snapshots=case;edit(source)
    staging=tmp_path/'uploads';staging.mkdir(mode=0o700)
    socket=tmp_path/'runtime'/'broker.sock';lab=Lab(target,snapshots,staging,socket);lab.group_verification=profile;op=uuid.uuid4().hex
    with running_broker(socket,broker),servers(lab) as address:
        assert http(address,'PUT',source.read_bytes(),headers={'X-Test-Operation':op})[0]==204
    restarted=Broker(None,RecordingTyper());restarted.merges.database=target
    lab2=Lab(target,snapshots,staging,socket);lab2.group_verification=profile
    with running_broker(socket,restarted),servers(lab2) as address:
        assert http(address,'PUT',source.read_bytes(),headers={'X-Test-Operation':op})[0]==204
        assert lab2.command('merge-status',op)['state']=='saved'
        assert len(list(snapshots.iterdir()))==1
