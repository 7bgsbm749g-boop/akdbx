"""Exact-client group interop and actual native references; synthetic KDBXs only."""
import shutil
from datetime import timedelta

import pytest
from pykeepass import PyKeePass

from agentic_kdbx.broker import open_vault_with_password
from test_admission import case, admit, bundle
from test_group_admission import native_case, project
from test_merge import MASTER, BASE_TIME, base
from test_selection import put


@pytest.mark.parametrize('kind', ['tags', 'parent-propagation', 'nonroot-modified'])
def test_071_remaining_refusals_reproduced(native_case, kind):
    broker, target, source, _ = native_case
    v = PyKeePass(target, password=MASTER)
    if kind == 'tags':
        put(v.find_groups(name='Synthetic group', first=True)._element, 'Tags', ' first ; second ')
        v.save(); broker.vault = open_vault_with_password(target, MASTER)
    shutil.copyfile(target, source)
    v = PyKeePass(source, password=MASTER)
    if kind != 'tags':
        group = v.find_groups(name='Synthetic group', first=True)
        group.mtime = BASE_TIME + timedelta(days=2)
        if kind == 'parent-propagation': v.root_group.mtime = group.mtime
    project(v); v.save()
    before, uploaded = target.read_bytes(), source.read_bytes()
    result = admit(native_case)
    assert result['ok'] is False and result['state'] == 'failed'
    assert result['verification_diagnostics'] == {'group_metadata': 2 if kind == 'parent-propagation' else 1}
    assert target.read_bytes() == before and source.read_bytes() == uploaded
    assert (bundle(result) / 'source.kdbx').read_bytes() == uploaded

import base64
import copy
import hashlib
import json
import os
import subprocess
import uuid
from lxml import etree
from agentic_kdbx import admission, cli, group_selection, group_tags, merge as merging, versions
from test_broker import running_broker
from test_merge import SECRET, tombstone
from upload_lab import Lab, servers, http, KeePassiumSequence

TAG = admission.TAG_GROUP_VERIFICATION
NATIVE = admission.NATIVE_GROUP_VERIFICATION


def extended(case, profile=NATIVE, **kwargs):
    return admit(case, group_protocol=2, group_verification=profile, **kwargs)


def reset(case, vault):
    broker, target, source, _ = case
    vault.save(target); broker.vault = open_vault_with_password(target, MASTER)
    shutil.copyfile(target, source)


@pytest.mark.parametrize('raw,expected', [
    (' a ; b ,a ', ('a','b','a')), (';; ,\t', ()), ('A,a,A', ('A','a','A')),
    ('"a;b",c', ('"a','b"','c')), (r'a\;b', ('a\\','b')),
    ('a\nb,é,e\u0301,😀', ('a\nb','é','e\u0301','😀')),
    ('\u00a0a\u00a0', ('\u00a0a\u00a0',)),
])
def test_tag_sequence_contract(raw, expected):
    assert group_tags.sequence(raw) == expected


@pytest.mark.parametrize('raw', [' first ; second ', 'a,a;A', ',;\t', r'"a;b",c\;d', 'é; e\u0301,😀'])
@pytest.mark.parametrize('profile', [TAG, NATIVE])
def test_exact_release_tag_projection_admitted(native_case, raw, profile):
    broker,target,source,_ = native_case
    v=PyKeePass(target,password=MASTER)
    for g in v.groups: put(g._element,'Tags',raw)
    reset(native_case,v)
    ledger=versions.archives(broker.vault)
    v=PyKeePass(source,password=MASTER);project(v);v.save()
    before,uploaded=target.read_bytes(),source.read_bytes()
    check=extended(native_case,profile,check=True);assert check['ok'],check
    assert target.read_bytes()==before
    result=extended(native_case,profile);assert result['ok'],result
    assert result['group_protocol']==2 and result['group_verification']==profile
    assert result['group_tag_verification']==group_tags.VERIFICATION
    assert result['group_selection']==(group_selection.VERIFICATION if profile==NATIVE else 'strict-v1')
    assert target.read_bytes()==source.read_bytes()==uploaded
    assert versions.archives(broker.vault)==ledger
    assert (bundle(result)/'target.kdbx').read_bytes()==before
    assert extended(native_case,profile)['state']=='unchanged'


@pytest.mark.parametrize('before,after', [('a,b','b,a'),('a,a','a'),('a','A'),('é','e\u0301'),
    (r'a\;b','a;b'),('"a;b"','a;b'),('a b','ab'),('\u00a0a\u00a0','a'),('a\nb','a b')])
@pytest.mark.parametrize('profile',[TAG,NATIVE])
def test_tag_distinctions_refused(native_case,before,after,profile):
    broker,target,source,_=native_case
    v=PyKeePass(target,password=MASTER);put(v.root_group._element,'Tags',before);reset(native_case,v)
    v=PyKeePass(source,password=MASTER);put(v.root_group._element,'Tags',after);v.save()
    original=target.read_bytes();result=extended(native_case,profile)
    assert not result['ok'] and result['state']=='failed'
    assert result['verification_diagnostics']==({'group_tags':1} if profile==NATIVE else {'group_metadata':1})
    assert target.read_bytes()==original


def verify_native(native, originals):
    # Native CustomData reader regenerates its _LAST_MODIFIED dictionary clock
    # and its writer drops item clocks. Independently assert every other key/
    # value, then restore the stronger raw-input preservation floor in memory.
    # This is a test oracle, not a production admission transformation.
    first={}
    for vault in originals:
        for group in vault.groups:first.setdefault(group.uuid,group)
    def values(node):
        return {item.findtext('Key'):item.findtext('Value') or '' for item in node} if node is not None else {}
    for group in native.groups:
        expected=first[group.uuid]._element.find('CustomData');actual=group._element.find('CustomData')
        left,right=values(expected),values(actual)
        assert {k:v for k,v in left.items() if k!='_LAST_MODIFIED'}=={k:v for k,v in right.items() if k!='_LAST_MODIFIED'}
        if actual is not None:group._element.remove(actual)
        if expected is not None:group._element.append(copy.deepcopy(expected))
    group_selection.verify(native,originals)


def reference(tmp_path, originals):
    folder=tmp_path/('reference-'+uuid.uuid4().hex);folder.mkdir(mode=0o700)
    originals[0].save(folder/'candidate.kdbx')
    for v in originals[1:]:
        v.save(folder/'source.kdbx');merging.run_engine(folder,originals[0])
    return PyKeePass(folder/'candidate.kdbx',password=MASTER)


def test_native_raw_group_tags_and_entry_only_search(native_case,tmp_path):
    broker,target,source,_=native_case
    a=PyKeePass(target,password=MASTER);g=a.find_groups(name='Synthetic group',first=True)
    put(g._element,'Tags',' onlyGroupTag ; Other , onlyGroupTag ')
    a.find_entries(title='Shared',first=True).tags=['onlyEntryTag']
    reset(native_case,a)
    b=PyKeePass(source,password=MASTER);project(b)
    b.find_groups(uuid=g.uuid,first=True).mtime=BASE_TIME+timedelta(days=3)
    b.add_entry(b.root_group,'Synthetic native trigger','synthetic',SECRET)
    output=reference(tmp_path,(a,b))
    assert output.find_groups(uuid=g.uuid,first=True)._element.findtext('Tags')==' onlyGroupTag ; Other , onlyGroupTag '
    for term,found in [('onlyGroupTag',False),('onlyEntryTag',True)]:
        p=subprocess.run(['keepassxc-cli','search','-q',str(output.filename),'tag:'+term],input=(MASTER+'\n').encode(),capture_output=True,timeout=20)
        assert bool(p.stdout.strip()) is found


@pytest.mark.parametrize('change',['newer','older','tie','expiry','expires','creation','autotype','search','custom','icon','icon-zero','unknown','root-clock'])
def test_native_property_selection_reference(native_case,tmp_path,change):
    broker,target,source,_=native_case
    a=PyKeePass(target,password=MASTER);g=a.find_groups(name='Synthetic group',first=True)
    put(g._element,'IconID','12');reset(native_case,a)
    b=PyKeePass(source,password=MASTER);other=b.find_groups(uuid=g.uuid,first=True)
    other.mtime=BASE_TIME+timedelta(days=3)
    other.name='Synthetic selected name';other.notes='Synthetic selected notes'
    if change=='older':other.mtime=BASE_TIME-timedelta(days=1)
    if change=='tie':other.mtime=BASE_TIME
    if change=='expiry':other.expiry_time=BASE_TIME+timedelta(days=20)
    if change=='expires':other.expires=not g.expires
    if change=='creation':other.ctime=BASE_TIME+timedelta(days=1)
    if change=='autotype':put(other._element,'DefaultAutoTypeSequence','{USERNAME}')
    if change=='search':put(other._element,'EnableSearching','false')
    if change=='custom':
        data=etree.SubElement(other._element,'CustomData');item=etree.SubElement(data,'Item')
        put(item,'Key','Synthetic metadata');put(item,'Value','Synthetic value')
    if change=='icon':put(other._element,'IconID','17')
    if change=='icon-zero':put(other._element,'IconID','0')
    if change=='unknown':put(other._element,'SyntheticUnknown','synthetic')
    if change=='root-clock':b.root_group.mtime=BASE_TIME+timedelta(days=3)
    # Actual native engine independently creates the selected group result.
    native=reference(tmp_path,(a,b))
    if change=='unknown':
        with pytest.raises(group_selection.GroupSelectionError) as caught:group_selection.verify(native,(a,b))
        assert caught.value.diagnostics=={'unsupported_group_metadata':1}
        return
    verify_native(native,(a,b))
    chosen=native.find_groups(uuid=g.uuid,first=True)
    assert chosen.name==('Synthetic group' if change in {'tie','older'} else 'Synthetic selected name')
    assert chosen._element.findtext('IconID')==('17' if change=='icon' else '12')
    assert chosen.expires==g.expires and chosen.ctime==g.ctime
    assert chosen._element.findtext('EnableSearching')==g._element.findtext('EnableSearching')
    assert native.root_group.mtime==a.root_group.mtime
    b.save(source)
    result=extended(native_case)
    acceptable=change in {'newer','expiry','icon'}
    assert result['ok'] is acceptable,result
    if acceptable:assert target.read_bytes()==source.read_bytes()


def test_native_three_way_independent_move_and_properties(native_case,tmp_path):
    broker,target,source,_=native_case
    current=PyKeePass(target,password=MASTER);moving=current.find_groups(name='Synthetic group',first=True)
    parent=current.add_group(current.root_group,'Synthetic destination');parent.mtime=BASE_TIME
    parent._element.find('Times/LocationChanged').text=current._encode_time(BASE_TIME)
    reset(native_case,current)
    held=PyKeePass(target,password=MASTER);hg=held.find_groups(uuid=moving.uuid,first=True)
    hg._element.getparent().remove(hg._element);held.find_groups(uuid=parent.uuid,first=True)._element.append(hg._element)
    put(hg._element,'PreviousParentGroup',current.root_group._element.findtext('UUID'))
    put(hg._element.find('Times'),'LocationChanged',held._encode_time(BASE_TIME+timedelta(days=2)))
    incoming=PyKeePass(target,password=MASTER);ig=incoming.find_groups(uuid=moving.uuid,first=True)
    ig.name='Synthetic property winner';ig.mtime=BASE_TIME+timedelta(days=3)
    selected=reference(tmp_path,(current,held,incoming))
    verify_native(selected,(current,held,incoming))
    chosen=selected.find_groups(uuid=moving.uuid,first=True)
    assert chosen.parentgroup.uuid==parent.uuid and chosen.name=='Synthetic property winner'
    assert chosen._element.findtext('PreviousParentGroup')==current.root_group._element.findtext('UUID')
    # Wrong source-only active location is not excused by matching properties.
    with pytest.raises(group_selection.GroupSelectionError):group_selection.verify(incoming,(current,held))
    # Full broker integration with encrypted held-only and external branches.
    held.save(target);broker.vault=open_vault_with_password(target,MASTER)
    current.save(target)
    # Native metadata normalization is outside this group-only oracle. Model
    # an upload with selected groups and the unchanged destination settings.
    meta=selected.tree.find('./Meta');meta.getparent().replace(meta,copy.deepcopy(current.tree.find('./Meta')))
    selected.save(source)
    result=extended(native_case);assert result['ok'] and result['target_refreshed'],json.dumps(result)
    assert (bundle(result)/'broker.kdbx').read_bytes()!= (bundle(result)/'target.kdbx').read_bytes()


@pytest.mark.parametrize('clock',['CreationTime','LastModificationTime','LocationChanged','ExpiryTime'])
def test_fractional_clocks_never_erased_or_falsely_ordered(native_case,clock):
    broker,target,source,_=native_case
    v=PyKeePass(target,password=MASTER);g=v.find_groups(name='Synthetic group',first=True)
    put(g._element.find('Times'),clock,BASE_TIME.replace(microsecond=123456).isoformat());reset(native_case,v)
    # Tag-only profile can retain exact fractional instants, native selection
    # refuses unsupported precision instead of converting it to whole seconds.
    result=extended(native_case,TAG,check=True);assert result['ok'],result
    original=target.read_bytes();result=extended(native_case)
    assert not result['ok'] and result['verification_diagnostics']=={'unsupported_group_metadata':1}
    assert target.read_bytes()==original


def phone_action(v, action, day):
    """Independent exact-2.5.171 transaction/relocation projection, not GUI."""
    moment=BASE_TIME+timedelta(days=day)
    e=v.find_entries(title='Shared',first=True)
    if action=='add':
        e=v.add_entry(v.root_group,'Synthetic phone added','synthetic',SECRET)
        e.ctime=e.mtime=e.atime=moment
    elif action=='edit':
        e.save_history();e.password='synthetic ordinary field edit';e.mtime=moment
    elif action=='permanent-delete':tombstone(v,e,moment)
    elif action in {'move','recycle'}:
        dest=v.find_groups(name='Synthetic recycle bin' if action=='recycle' else 'Delete empty group',first=True)
        previous=e.group;previous._element.remove(e._element);dest._element.append(e._element)
        put(e._element,'PreviousParentGroup',previous._element.findtext('UUID'))
        put(e._element.find('Times'),'LocationChanged',v._encode_time(moment))
        e.atime=moment
        for g in (dest,v.root_group):
            put(g._element.find('Times'),'LastAccessTime',v._encode_time(moment))
    elif action=='propagated-property':
        e.save_history();e.password='synthetic property edit';e.mtime=moment
        # EntryViewer actions using default updateParents:true touch root too.
        e.group.mtime=moment;v.root_group.mtime=moment
    else:raise AssertionError('invalid synthetic action')
    project(v)


def test_consecutive_exact_release_ordinary_edits_two_hop_cli(native_case,tmp_path):
    broker,target,source,snapshots=native_case
    v=PyKeePass(target,password=MASTER)
    for g in v.groups:put(g._element,'Tags',' Phone ; group,Phone ')
    reset(native_case,v)
    ledger=versions.archives(broker.vault)
    handle=broker.dispatch({'action':'search','query':'Shared'})['entries'][0]['handle']
    staging=tmp_path/'uploads';staging.mkdir(mode=0o700)
    socket=tmp_path/'runtime'/'broker.sock';lab=Lab(target,snapshots,staging,socket);lab.group_verification=NATIVE
    with running_broker(socket,broker),servers(lab) as address:
        assert lab.command('status')['admission_group_verifiers']==list(admission.GROUP_VERIFIERS)
        client=KeePassiumSequence(address);client.read()
        for day,action in enumerate(('add','edit','permanent-delete'),2):
            source.write_bytes(http(address,'GET')[1]);v=PyKeePass(source,password=MASTER)
            phone_action(v,action,day);v.save();encrypted=source.read_bytes()
            assert client.save(encrypted,timeout=10)==204
            result=next(reversed(lab.results.values()))
            assert result['group_verification']==NATIVE and result['group_protocol']==2
            assert http(address,'GET')[1]==target.read_bytes()==encrypted
            assert http(address,'HEAD')[2]['ETag']=='"'+hashlib.sha256(encrypted).hexdigest()+'"'
            assert lab.command('merge-status',result['operation_id'])==result
            assert versions.archives(broker.vault)==ledger
        assert broker.vault.find_entries(title='Shared',first=True) is None
        assert broker.vault.find_entries(title='Synthetic phone added',first=True)
        assert not broker.dispatch({'action':'fill','handle':handle})['ok']


@pytest.mark.parametrize('action',['move','recycle','propagated-property'])
def test_exact_release_ordinary_limits_with_native_reference(native_case,tmp_path,action):
    broker,target,source,_=native_case
    original=PyKeePass(target,password=MASTER)
    put(original.find_entries(title='Shared',first=True)._element.find('Times'),'LocationChanged',original._encode_time(BASE_TIME))
    reset(native_case,original);before=target.read_bytes()
    v=PyKeePass(source,password=MASTER);phone_action(v,action,4);v.save()
    native=reference(tmp_path,(original,v))
    verify_native(native,(original,v))
    # Current semantic-v1 entry selection stays intact. Native retains base
    # entry times on pure moves, while the phone uploads its new location clock.
    if action!='propagated-property':
        active=native.find_entries(title='Shared',first=True)
        assert active.group.uuid==v.find_entries(title='Shared',first=True).group.uuid
        assert active.mtime==original.find_entries(title='Shared',first=True).mtime
        assert active._element.findtext('Times/LocationChanged')==original.find_entries(title='Shared',first=True)._element.findtext('Times/LocationChanged')
    result=extended(native_case);assert not result['ok'] and result['state']=='failed'
    assert result['verification_diagnostics']==({'group_times':1} if action=='propagated-property' else {'location':1})
    assert target.read_bytes()==before
    assert (bundle(result)/'source.kdbx').read_bytes()==source.read_bytes()


@pytest.mark.parametrize('kind',['delete-empty','delete-nonempty','newer-than-delete','earliest-delete','new-group','lost-group','cycle','root-delete','archive-delete'])
def test_group_membership_deletions_and_unsupported_topology(native_case,tmp_path,kind):
    broker,target,source,_=native_case
    a=PyKeePass(target,password=MASTER)
    group=a.add_group(a.root_group,'Synthetic branch');group.mtime=BASE_TIME
    put(group._element.find('Times'),'LocationChanged',a._encode_time(BASE_TIME))
    if kind=='delete-nonempty':
        e=a.add_entry(group,'Synthetic retained child','synthetic',SECRET);e.mtime=BASE_TIME+timedelta(days=8)
    reset(native_case,a)
    b=PyKeePass(source,password=MASTER);g=b.find_groups(uuid=group.uuid,first=True)
    if kind.startswith('delete') or kind in {'newer-than-delete','earliest-delete'}:
        if kind=='newer-than-delete':g.mtime=BASE_TIME+timedelta(days=6)
        # Keep group present for occupied/newer tombstones: native synchronize
        # semantics retain it, not an unconditional UUID removal.
        if kind=='delete-empty':tombstone(b,g,BASE_TIME+timedelta(days=4))
        else:
            deleted=etree.SubElement(b.tree.find('./Root/DeletedObjects'),'DeletedObject')
            put(deleted,'UUID',g._element.findtext('UUID'));put(deleted,'DeletionTime',b._encode_time(BASE_TIME+timedelta(days=4)))
            if kind=='earliest-delete':
                stamp=etree.SubElement(a.tree.find('./Root/DeletedObjects'),'DeletedObject')
                put(stamp,'UUID',g._element.findtext('UUID'));put(stamp,'DeletionTime',a._encode_time(BASE_TIME-timedelta(days=1)))
                reset(native_case,a)
    elif kind=='new-group':
        g=b.add_group(b.root_group,'Synthetic incoming group');g.mtime=BASE_TIME+timedelta(days=4)
    elif kind=='lost-group':b.delete_group(g)
    elif kind=='cycle':
        # Construct a cross-input move cycle without invalid XML in either input.
        child=a.add_group(group,'Synthetic descendant');child.mtime=BASE_TIME
        put(child._element.find('Times'),'LocationChanged',a._encode_time(BASE_TIME))
        reset(native_case,a)
        b=PyKeePass(source,password=MASTER);g=b.find_groups(uuid=group.uuid,first=True)
        c=b.find_groups(uuid=child.uuid,first=True)
        g._element.remove(c._element);b.root_group._element.append(c._element)
        g._element.getparent().remove(g._element);c._element.append(g._element)
        put(g._element.find('Times'),'LocationChanged',b._encode_time(BASE_TIME+timedelta(days=5)))
        # Child's older move is not selected; source parent's final order cycles.
    elif kind in {'root-delete','archive-delete'}:
        chosen=b.root_group if kind=='root-delete' else next(g for g in b.groups if versions.is_archive_group(g))
        deleted=etree.SubElement(b.tree.find('./Root/DeletedObjects'),'DeletedObject')
        put(deleted,'UUID',chosen._element.findtext('UUID'));put(deleted,'DeletionTime',b._encode_time(BASE_TIME+timedelta(days=8)))
    b.save(source)
    if kind in {'delete-empty','delete-nonempty','newer-than-delete','new-group'}:
        native=reference(tmp_path,(a,b));merging.synchronize_deletions(native,a,b)
        verify_native(native,(a,b))
    before=target.read_bytes();result=extended(native_case)
    assert result['ok'] is (kind in {'delete-empty','delete-nonempty','newer-than-delete','new-group'}),json.dumps(result)
    if not result['ok']:assert target.read_bytes()==before


@pytest.mark.parametrize('profile',[TAG,NATIVE])
@pytest.mark.parametrize('phase',['source-race','target-race','after-replace','receipt-failure','interrupt'])
def test_extended_uncertainty_same_id_and_restart(native_case,monkeypatch,profile,phase):
    from agentic_kdbx.broker import Broker
    from test_broker import RecordingTyper
    broker,target,source,_=native_case
    v=PyKeePass(source,password=MASTER);phone_action(v,'edit',4);v.save()
    before=target.read_bytes();operation=uuid.uuid4().hex
    actual=admission.verify;replace=os.replace;receipt=broker.merges._receipt
    def verify(*a,**k):
        result=actual(*a,**k)
        if phase=='source-race':source.write_bytes(source.read_bytes()+b'race')
        if phase=='target-race':target.write_bytes(before+b'race')
        if phase=='interrupt':raise KeyboardInterrupt
        return result
    def renamed(src,dst,*a,**k):
        replace(src,dst,*a,**k)
        if phase=='after-replace' and dst==target.name:raise OSError('synthetic private exception')
    def recorded(fd,value):
        if phase=='receipt-failure' and value['state']=='saved':raise OSError('synthetic private exception')
        return receipt(fd,value)
    monkeypatch.setattr(admission,'verify',verify);monkeypatch.setattr(os,'replace',renamed);monkeypatch.setattr(broker.merges,'_receipt',recorded)
    if phase=='interrupt':
        with pytest.raises(KeyboardInterrupt):extended(native_case,profile,operation_id=operation)
    else:
        result=extended(native_case,profile,operation_id=operation)
        assert not result['ok'] and 'synthetic private exception' not in json.dumps(result)
        assert result['state']==('uncertain' if phase in {'after-replace','receipt-failure'} else 'failed')
    if phase=='source-race':assert target.read_bytes()==before
    recovered=Broker(open_vault_with_password(target,MASTER),RecordingTyper())
    status=recovered.merges.status(operation)
    assert status['group_verification']==profile and status['group_protocol']==2
    if phase in {'after-replace','receipt-failure','interrupt'}:
        assert status['ok'] is False and status['state']=='uncertain'
        assert recovered.vault._akdbx_store.recovery_required
        assert not extended((recovered,target,source,native_case[3]),profile)['ok']


@pytest.mark.parametrize('profile',[TAG,NATIVE])
def test_capabilities_requests_and_results_fail_closed(native_case,monkeypatch,capsys,profile):
    broker,target,source,snapshots=native_case
    args=['admit',str(source),'--policy',admission.POLICY,'--snapshot-dir',str(snapshots),'--group-verification',profile]
    actual=broker.dispatch({'action':'ping'});calls=[]
    def previous(sock,payload,**kw):
        calls.append(payload);return {k:v for k,v in actual.items() if k!='admission_group_protocol'}
    monkeypatch.setattr(cli,'request',previous)
    assert cli.main(args)==1 and [x['action'] for x in calls]==['ping']
    for field in ('group_protocol','group_verification','group_tag_verification','group_selection'):
        def downgrade(sock,payload,**kw):
            if payload['action']=='ping':return actual
            return {**broker.dispatch(payload),field:None}
        monkeypatch.setattr(cli,'request',downgrade)
        assert cli.main(args)==2
    assert 'outcome unconfirmed' in capsys.readouterr().err
    assert not admit(native_case,group_verification=profile)['ok'] # missing protocol2
    original=broker.merges._version;broker.merges._version='2.7.11'
    assert broker.dispatch({'action':'ping'})['admission_group_verifiers']==[admission.GROUP_VERIFICATION]
    assert not extended(native_case,profile)['ok']
    broker.merges._version=original


@pytest.mark.parametrize('kind',['value','item-clock','dictionary-clock','drop','fractional-item-clock'])
def test_native_group_custom_data_preservation_floor(native_case,kind):
    broker,target,source,_=native_case
    v=PyKeePass(target,password=MASTER);g=v.find_groups(name='Synthetic group',first=True)
    custom=etree.SubElement(g._element,'CustomData')
    item=etree.SubElement(custom,'Item');put(item,'Key','Synthetic preserved metadata');put(item,'Value','synthetic original')
    put(item,'LastModificationTime',BASE_TIME.replace(microsecond=123456).isoformat())
    dictionary=etree.SubElement(custom,'Item');put(dictionary,'Key','_LAST_MODIFIED');put(dictionary,'Value','synthetic dictionary clock')
    reset(native_case,v)
    assert extended(native_case,check=True)['ok']
    v=PyKeePass(source,password=MASTER);g=v.find_groups(uuid=g.uuid,first=True);g.mtime=BASE_TIME+timedelta(days=4)
    item=g._element.find('CustomData/Item');dictionary=g._element.find('CustomData/Item[Key="_LAST_MODIFIED"]')
    if kind=='value':put(item,'Value','synthetic different')
    elif kind=='item-clock':put(item,'LastModificationTime',(BASE_TIME+timedelta(days=1)).isoformat())
    elif kind=='fractional-item-clock':put(item,'LastModificationTime',BASE_TIME.replace(microsecond=123457).isoformat())
    elif kind=='dictionary-clock':put(dictionary,'Value','synthetic changed clock')
    else:item.getparent().remove(item)
    v.save();before=target.read_bytes();result=extended(native_case)
    assert not result['ok'] and result['verification_diagnostics']=={'group_custom_data':1}
    assert target.read_bytes()==before
    text=json.dumps(result)
    assert all(secret not in text for secret in ('Synthetic preserved metadata','synthetic different','synthetic original',MASTER))


@pytest.mark.parametrize('choice',['new-custom','clear-custom-with-builtin','null-custom-noop'])
def test_native_custom_icon_selection_reference(native_case,tmp_path,choice):
    broker,target,source,_=native_case
    a=PyKeePass(target,password=MASTER);g=a.find_groups(name='Synthetic group',first=True)
    container=a.tree.find('./Meta/CustomIcons')
    if container is None:container=etree.SubElement(a.tree.find('./Meta'),'CustomIcons')
    ids=[base64.b64encode(uuid.uuid4().bytes).decode() for _ in range(2)]
    for identity in ids:
        icon=etree.SubElement(container,'Icon');put(icon,'UUID',identity)
        put(icon,'Data','iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aD1sAAAAASUVORK5CYII=')
    put(g._element,'IconID','0');put(g._element,'CustomIconUUID',ids[0]);reset(native_case,a)
    b=PyKeePass(source,password=MASTER);g=b.find_groups(uuid=g.uuid,first=True)
    g.mtime=BASE_TIME+timedelta(days=3)
    if choice=='new-custom':put(g._element,'CustomIconUUID',ids[1])
    else:
        g._element.remove(g._element.find('CustomIconUUID'))
        put(g._element,'IconID','17' if choice=='clear-custom-with-builtin' else '0')
    native=reference(tmp_path,(a,b));verify_native(native,(a,b))
    active=native.find_groups(uuid=g.uuid,first=True)
    assert active._element.findtext('CustomIconUUID')==({'new-custom':ids[1],'null-custom-noop':ids[0]}.get(choice))
    b.save(source);result=extended(native_case)
    assert result['ok'] is (choice!='null-custom-noop'),result


def test_supplemental_all_three_group_branches_native_union(native_case,tmp_path):
    broker,target,source,_=native_case
    held=PyKeePass(target,password=MASTER)
    h=held.add_group(held.root_group,'Synthetic held branch')
    held.add_entry(h,'Synthetic held branch entry','synthetic',SECRET)
    held.save(target);broker.vault=open_vault_with_password(target,MASTER)
    current=PyKeePass(source,password=MASTER)
    c=current.add_group(current.root_group,'Synthetic external branch')
    current.add_entry(c,'Synthetic external branch entry','synthetic',SECRET);current.save(target)
    incoming=PyKeePass(source,password=MASTER)
    g=incoming.add_group(incoming.root_group,'Synthetic incoming branch')
    incoming.add_entry(g,'Synthetic incoming branch entry','synthetic',SECRET);incoming.save(source)
    before,upload=target.read_bytes(),source.read_bytes()
    refusal=extended(native_case)
    assert not refusal['ok'] and refusal['verification_diagnostics']=={'group_membership':2}
    assert target.read_bytes()==before and source.read_bytes()==upload
    assert (bundle(refusal)/'broker.kdbx').read_bytes()==broker.vault._akdbx_store.verified_encrypted
    native=reference(tmp_path,(current,held,incoming));verify_native(native,(current,held,incoming))
    for identity in (h.uuid,c.uuid,g.uuid):assert native.find_groups(uuid=identity,first=True)
    meta=native.tree.find('./Meta');meta.getparent().replace(meta,copy.deepcopy(current.tree.find('./Meta')))
    native.save(source);uploaded=source.read_bytes()
    result=extended(native_case);assert result['ok'] and result['target_refreshed'],json.dumps(result)
    assert target.read_bytes()==source.read_bytes()==uploaded
    for identity in (h.uuid,c.uuid,g.uuid):assert broker.vault.find_groups(uuid=identity,first=True)


def test_supplemental_xml_escaping_and_empty_tag_text(native_case):
    broker,target,source,_=native_case
    a=PyKeePass(target,password=MASTER)
    # lxml's normal encrypted XML writer escapes &, < and >. Public Swift
    # AEXML supplies decoded text to TagHelper, not raw entity spelling.
    for group in a.groups:put(group._element,'Tags',' a&b ; <tag>,a&b ')
    reset(native_case,a)
    b=PyKeePass(source,password=MASTER);project(b);b.save()
    assert b.root_group._element.findtext('Tags')=='a&b,<tag>,a&b'
    result=extended(native_case);assert result['ok'],result
    assert target.read_bytes()==source.read_bytes()
    before=target.read_bytes();b=PyKeePass(source,password=MASTER)
    put(b.root_group._element,'Tags','a&b,<tag>');b.save()
    refused=extended(native_case);assert not refused['ok']
    assert refused['verification_diagnostics']=={'group_tags':1}
    assert target.read_bytes()==before
