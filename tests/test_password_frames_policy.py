"""Browser-free child-frame policy and CLI contract checks."""
import pytest

from akdbx import cli, password_frames
from akdbx.browser_password import DELIVERY
from akdbx.target import TargetError

TOP = 'https://login.example.com/signin?step=1'


def frame(fid, url, parent=None, origin=None, site='example.com', secure='Secure'):
    path, _, fragment = url.partition('#')
    value = dict(id=fid, url=path, securityOrigin=origin or 'https://' + url.split('/')[2], domainAndRegistry=site,
                 secureContextType=secure)
    if fragment:
        value['urlFragment'] = '#' + fragment
    if parent:
        value['parentId'] = parent
    return value


def hops(*frames):
    return [dict(frame=f, session='s', target='page') for f in frames]


def good_chain():
    return hops(frame('top', TOP), frame('mid', 'https://sso.example.com/mid', 'top'),
                frame('leaf', 'https://auth.example.com/form#x', 'mid'))


def test_same_site_chain_proof_includes_exact_urls_parents_and_targets():
    proof = password_frames.check_chain(good_chain(), TOP, 'https://auth.example.com')
    assert proof == (('top', TOP, None, 'page'), ('mid', 'https://sso.example.com/mid', 'top', 'page'),
                     ('leaf', 'https://auth.example.com/form#x', 'mid', 'page'))


@pytest.mark.parametrize('mutate', [
    lambda c: c[0]['frame'].update(domainAndRegistry='example.net'),       # hostile top, legitimate frame
    lambda c: c[1]['frame'].update(domainAndRegistry='example.net'),       # hostile middle frame
    lambda c: c[2]['frame'].update(domainAndRegistry='example.net'),       # hostile child frame
    lambda c: c[2]['frame'].update(securityOrigin='null'),                 # opaque/sandboxed origin
    lambda c: c[2]['frame'].update(securityOrigin='https://sso.example.com'),  # origin/URL disagreement
    lambda c: c[2]['frame'].update(url='http://auth.example.com/form', securityOrigin='http://auth.example.com'),
    lambda c: c[2]['frame'].update(secureContextType='InsecureAncestor'),
    lambda c: c[2]['frame'].update(url='about:blank', securityOrigin='https://auth.example.com'),
    lambda c: c[0]['frame'].update(url='https://login.example.com/other'),
    lambda c: c.__delitem__(slice(1, 3)),                                  # the main frame is not a child
])
def test_policy_refusals(mutate):
    chain = good_chain()
    mutate(chain)
    with pytest.raises(TargetError):
        password_frames.check_chain(chain, TOP, 'https://auth.example.com')


def test_wrong_requested_origin_and_ip_hosts_need_one_exact_origin():
    with pytest.raises(TargetError):
        password_frames.check_chain(good_chain(), TOP, 'https://sso.example.com')
    top = 'https://127.0.0.1:8443/a'
    same = hops(frame('t', top, site=''), frame('c', 'https://127.0.0.1:8443/b', 't', site=''))
    assert password_frames.check_chain(same, top, 'https://127.0.0.1:8443')
    other = hops(frame('t', top, site=''), frame('c', 'https://127.0.0.2:8443/b', 't', site=''))
    with pytest.raises(TargetError):
        password_frames.check_chain(other, top, 'https://127.0.0.2:8443')


def test_depth_limit_and_detached_or_unknown_frames():
    frames = {'f0': dict(frame=frame('f0', TOP), session='s', target='page')}
    for index in range(1, 11):
        frames[f'f{index}'] = dict(frame=frame(f'f{index}', 'https://a.example.com/x', f'f{index - 1}'), session='s', target='page')
    assert len(password_frames.chain(frames, 'f8')) == 9
    with pytest.raises(TargetError):
        password_frames.chain(frames, 'f10')
    with pytest.raises(TargetError):
        password_frames.chain(frames, 'missing')
    del frames['f3']
    with pytest.raises(TargetError):
        password_frames.chain(frames, 'f5')


@pytest.mark.parametrize('value', ['https://auth.example.com', 'https://auth.example.com:8443', 'https://xn--bcher-kva.example'])
def test_canonical_origins_accepted(value):
    assert password_frames.canonical_origin(value) == value


@pytest.mark.parametrize('value', ['https://auth.example.com/', 'https://Auth.example.com', 'http://auth.example.com',
                                   'https://auth.example.com:443', 'https://user@auth.example.com', 'https://auth.example.com?',
                                   'https://auth.example.com#', 'https://auth.example.com/x', 'auth.example.com', '', None,
                                   'https://bücher.example', 'null'])
def test_non_canonical_origins_refused(value):
    with pytest.raises(TargetError):
        password_frames.canonical_origin(value)


def argv(*extra):
    return ['pin-password-target', '--page-id', 'P', '--frame-id', 'F', '--top-url', TOP, '--selector', '#password', *extra]


@pytest.mark.parametrize('capability', [None, True, 0, 2, '1'])
def test_cli_sends_only_ping_to_broker_without_frame_protocol(monkeypatch, capsys, capability):
    calls = []
    def rpc(socket, payload, **kwargs):
        calls.append(payload)
        return dict(ok=True, password_fill_protocol=1, password_fill_delivery=DELIVERY,
                    password_frame_protocol=capability, password_frame_policy='same-site-chain-v1')
    monkeypatch.setattr(cli, 'request', rpc)
    assert cli.main(argv('--frame-origin', 'https://auth.example.com')) == 1
    assert calls == [{'action': 'ping'}]
    assert 'frame request not sent' in capsys.readouterr().out
    calls.clear()
    assert cli.main(['list-password-frames', '--top-url', TOP]) == 1
    assert calls == [{'action': 'ping'}]


def test_cli_sends_frame_route_and_keeps_main_frame_requests_unchanged(monkeypatch, capsys):
    calls = []
    def rpc(socket, payload, **kwargs):
        calls.append(payload)
        if payload['action'] == 'ping':
            return dict(ok=True, password_fill_protocol=1, password_fill_delivery=DELIVERY,
                        password_frame_protocol=1, password_frame_policy='same-site-chain-v1')
        return dict(ok=True, target='a' * 64, expires_in=30, target_delivery=DELIVERY)
    monkeypatch.setattr(cli, 'request', rpc)
    assert cli.main(argv('--frame-origin', 'https://auth.example.com')) == 0
    assert calls[-1] == dict(action='pin-password-target', password_protocol=1, page_id='P', frame_id='F', top_url=TOP,
                             selector='#password', mode='password', frame_protocol=1, frame_origin='https://auth.example.com')
    calls.clear()
    assert cli.main(argv()) == 0
    assert 'frame_origin' not in calls[-1] and 'frame_protocol' not in calls[-1]


def listing(**changes):
    value = dict(ok=True, page_id='P', main_frame_id='M', frame_policy='same-site-chain-v1', truncated=False, frames=[
        dict(frame_id='M', parent_frame_id=None, depth=0, origin='https://login.example.com', out_of_process=False,
             eligible=True, visible_fields=dict(password=0, text=0)),
        dict(frame_id='F', parent_frame_id='M', depth=1, origin='https://auth.example.com', out_of_process=True,
             eligible=True, visible_fields=dict(password=1, text=1))])
    value.update(changes)
    return value


def test_cli_lists_frames_and_rejects_unexpected_receipts(monkeypatch, capsys):
    responses = []
    def rpc(socket, payload, **kwargs):
        if payload['action'] == 'ping':
            return dict(ok=True, password_frame_protocol=1, password_frame_policy='same-site-chain-v1')
        assert payload == dict(action='list-password-frames', password_protocol=1, frame_protocol=1, top_url=TOP, page_id='P')
        return responses.pop()
    monkeypatch.setattr(cli, 'request', rpc)
    responses.append(listing())
    assert cli.main(['list-password-frames', '--top-url', TOP, '--page-id', 'P']) == 0
    assert '"https://auth.example.com"' in capsys.readouterr().out
    bad = listing()
    bad['frames'][1]['url'] = 'https://auth.example.com/form?token=x'
    for response in [listing(extra=1), bad, listing(frame_policy='other'), listing(truncated=None)]:
        responses.append(response)
        assert cli.main(['list-password-frames', '--top-url', TOP, '--page-id', 'P']) == 2
