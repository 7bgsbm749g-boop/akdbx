import json
import os
from pathlib import Path
import time

import pytest
from akdbx.notifications import UnlockNotifications

URL = 'https://callback.example/private-test-token'
def request(**fields):
    return dict(notification_protocol=1, webhook_url=URL, **fields)

def wait(manager, key):
    deadline=time.monotonic()+3
    while manager.status(key).get('state') not in {'delivered','failed'}:
        assert time.monotonic()<deadline
        time.sleep(.01)

def test_default_wait_does_not_expire_after_a_year():
    now=[0]
    sent=[]
    m=UnlockNotifications(clock=lambda:now[0],sender=lambda *a:sent.append(a))
    try:
        r=m.subscribe(request(),unlocked=False)
        assert r['expires_in'] is None
        now[0]=366*86400
        assert m.status(r['subscription_id'])['state']=='subscribed'
        m.publish();wait(m,r['subscription_id'])
        assert len(sent)==1
    finally:m.close()

def test_wait_survives_close_and_restore_and_delivers_same_event(tmp_path):
    path=tmp_path/'private'/'subscriptions.json'
    m=UnlockNotifications(state_path=path)
    r=m.subscribe(request(),unlocked=False)
    saved=json.loads(path.read_text());event=saved[0]['event_id']
    assert path.stat().st_mode&0o777==0o600
    assert URL not in json.dumps(r)
    m.close()
    sent=[]
    m=UnlockNotifications(state_path=path,sender=lambda *a:sent.append(a))
    try:
        assert m.status(r['subscription_id'])['state']=='subscribed'
        retry=m.subscribe(request(),unlocked=False)
        assert retry['subscription_id']==r['subscription_id']
        assert retry['expires_in'] is None
        m.publish();wait(m,r['subscription_id'])
        assert sent[0][1]['event_id']==event
        assert json.loads(path.read_text())==[]
    finally:m.close()

def test_cancel_removes_durable_wait(tmp_path):
    path=tmp_path/'private'/'subscriptions.json'
    m=UnlockNotifications(state_path=path)
    r=m.subscribe(request(),unlocked=False)
    assert m.status(r['subscription_id'],cancel=True)['state']=='cancelled'
    m.close()
    m=UnlockNotifications(state_path=path)
    try:assert m.status(r['subscription_id'])['ok'] is False
    finally:m.close()

@pytest.mark.parametrize('kind',['symlink','public','malformed','oversized'])
def test_untrusted_state_refused(tmp_path,kind):
    root=tmp_path/'private';root.mkdir(mode=0o700)
    path=root/'subscriptions.json'
    if kind=='symlink':path.symlink_to(tmp_path/'missing')
    else:
        path.write_text('x'*(512*1024+1) if kind=='oversized' else 'bad' if kind=='malformed' else '[]')
        path.chmod(0o644 if kind=='public' else 0o600)
    with pytest.raises((OSError,ValueError)):
        UnlockNotifications(state_path=path)

def test_capacity_reclaims_completed_receipts_without_expiring_waits(monkeypatch):
    import akdbx.notifications as module
    monkeypatch.setattr(module,'MAX_SUBSCRIPTIONS',1)
    m=UnlockNotifications(sender=lambda *a:None)
    try:
        r=m.subscribe(request(),unlocked=True);wait(m,r['subscription_id'])
        assert m.subscribe(dict(request(),webhook_url=URL+'-next'),unlocked=False)['ok']
        assert not m.subscribe(dict(request(),webhook_url=URL+'-third'),unlocked=False)['ok']
    finally:m.close()

def test_cli_does_not_silently_fall_back_to_expiring_subscription(monkeypatch,capsys):
    from akdbx import cli
    calls=[]
    def old_broker(_socket,payload,**kwargs):
        calls.append(payload)
        return {'ok':True,'locked':True,'unlock_notifications_supported':True,
                'unlock_notifications_protocol':1}
    monkeypatch.setattr(cli,'request',old_broker)
    assert cli.main(['subscribe-unlock','--webhook-url-file','/absent'])==1
    assert calls==[{'action':'ping'}]
    assert 'until-unlock' in capsys.readouterr().out
