"""Endpoint trust, authorization lifetimes and non-secret failure receipts."""
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from akdbx.broker import Broker
from akdbx.browser_card import BrowserCards, CardTargetError, browser_endpoint, failure
from akdbx.cards import value_for
from test_card_chromium import CardEntry
from test_broker import RecordingTyper, Vault


@pytest.mark.parametrize('content', ['80\nhttp://evil.test', '0\n/devtools/browser/id',
    '65536\n/devtools/browser/id', '12\n/devtools/page/id', '12\n/devtools/browser/id\nextra',
    '12\n/devtools/browser/' + 'a'*300, '１２\n/devtools/browser/id'])
def test_untrusted_endpoint_metadata_is_refused(tmp_path, content):
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    (profile / 'DevToolsActivePort').write_text(content)
    with pytest.raises(Exception):
        browser_endpoint(profile)


def test_endpoint_symlink_writable_file_and_replaceable_profile_refused(tmp_path):
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    source = tmp_path / 'source'
    source.write_text('1234\n/devtools/browser/synthetic-id')
    active = profile / 'DevToolsActivePort'
    active.symlink_to(source)
    with pytest.raises(Exception): browser_endpoint(profile)
    active.unlink()
    active.write_text(source.read_text())
    active.chmod(0o666)
    with pytest.raises(Exception): browser_endpoint(profile)
    active.chmod(0o600)
    assert browser_endpoint(profile) == 'ws://127.0.0.1:1234/devtools/browser/synthetic-id'
    profile.chmod(0o777)
    with pytest.raises(Exception): browser_endpoint(profile)


def test_fixture_waits_for_complete_header_after_empty_file_creation(tmp_path, monkeypatch):
    import test_card_chromium as lab
    profile = tmp_path / 'profile'
    profile.mkdir(mode=0o700)
    active = profile / 'DevToolsActivePort'
    active.write_text('')
    active.chmod(0o600)
    observed_incomplete = threading.Event()
    original = browser_endpoint
    def observe(path):
        try:
            return original(path)
        except CardTargetError:
            observed_incomplete.set()
            raise
    monkeypatch.setattr(lab, 'browser_endpoint', observe)
    errors = []
    def publish():
        if not observed_incomplete.wait(2):
            errors.append('reader did not reject the incomplete file')
            return
        active.write_text('1234\n/devtools/browser/synthetic-complete-id')
    writer = threading.Thread(target=publish)
    writer.start()
    try:
        endpoint = lab.wait_for_browser_endpoint(profile, SimpleNamespace(poll=lambda: None), time.monotonic()+3)
        assert endpoint == 'ws://127.0.0.1:1234/devtools/browser/synthetic-complete-id'
    finally:
        writer.join(timeout=3)
    assert observed_incomplete.is_set() and not writer.is_alive() and not errors


class FakeCDP:
    def __init__(self, result='filled', fail_at=None):
        self.result, self.fail_at, self.closed, self.calls = result, fail_at, 0, []
    def close(self): self.closed += 1
    def call(self, method, params=None, session=None):
        self.calls.append(method)
        if method == self.fail_at:
            raise RuntimeError('4111111111111111 MUST NOT escape')
        if method == 'Page.getFrameTree':
            return dict(frameTree=dict(frame=dict(id='frame', url='https://example.test/pay')))
        return dict(result=dict(value=self.result))


def target(cdp, clock):
    return dict(cdp=cdp, session='session', obj='object', field='cc-number', created=clock(), expires=clock()+30,
                request=dict(top_url='https://example.test/pay', frame_url='https://example.test/pay', frame_id='frame'))


@pytest.mark.parametrize('stage,expected', [('Page.getFrameTree', 'not-started'), ('Runtime.callFunctionOn', 'uncertain')])
def test_transport_exceptions_never_disclose_and_do_not_claim_safe_retry(stage, expected):
    cards = BrowserCards(clock=lambda: 0)
    cdp = FakeCDP(fail_at=stage)
    result = cards.fill(target(cdp, lambda: 0), '4111111111111111', 'cc-number', lambda: True)
    assert not result['ok'] and result['delivery'] == expected
    assert '4111111111111111' not in str(result)
    assert cdp.closed


@pytest.mark.parametrize('result,delivery', [('uncertain', 'uncertain'), ('refused', 'not-started'), ('unexpected', 'uncertain')])
def test_transport_only_accepts_explicit_fill_receipt(result, delivery):
    cards = BrowserCards(clock=lambda: 0)
    cdp = FakeCDP(result)
    assert cards.fill(target(cdp, lambda: 0), '4111111111111111', 'cc-number', lambda: True)['delivery'] == delivery


@pytest.mark.parametrize('changes', [dict(card_protocol=True), dict(field='password'), dict(start_deadline=float('nan')),
    dict(start_deadline=float('inf')), dict(start_deadline=0), dict(extra=True)])
def test_malformed_fill_consumes_both_authorizations_without_any_transport(changes):
    broker = Broker(Vault([CardEntry()]), RecordingTyper())
    cdp = FakeCDP()
    broker.card_targets.pins['target'] = target(cdp, broker.clock)
    selected = broker.dispatch(dict(action='search-cards', card_protocol=1))['entries'][0]['handle']
    request = dict(action='fill-card', card_protocol=1, field='cc-number', target='target', handle=selected)
    request.update(changes)
    assert not broker.dispatch(request)['ok']
    assert not broker.card_targets.pins and selected not in broker._handles
    assert cdp.closed and not cdp.calls and broker.typer.events == []


def test_invalid_handle_still_closes_and_consumes_target():
    broker = Broker(Vault([CardEntry()]), RecordingTyper())
    cdp = FakeCDP()
    broker.card_targets.pins['target'] = target(cdp, broker.clock)
    result = broker.dispatch(dict(action='fill-card', card_protocol=1, field='cc-number', target='target', handle='invalid'))
    assert not result['ok'] and not broker.card_targets.pins and cdp.closed and not cdp.calls


def test_prune_and_close_release_connections_and_expired_cards_refuse():
    clock = [0]
    cards = BrowserCards(clock=lambda: clock[0])
    one, two = FakeCDP(), FakeCDP()
    cards.pins['a'], cards.pins['b'] = target(one, lambda: 0), target(two, lambda: 10)
    clock[0] = 30
    cards.prune()
    assert one.closed and not two.closed and set(cards.pins) == {'b'}
    cards.close()
    assert two.closed and not cards.pins
    with pytest.raises(ValueError): value_for(CardEntry(), 'cc-number', None, 2208988800)  # 2040


def test_unconfigured_browser_and_locked_broker_never_access_transport():
    broker = Broker(None, RecordingTyper())
    assert broker.dispatch(dict(action='fill-card'))['error'] == 'vault locked'
    broker.vault = Vault([CardEntry()])
    assert not broker.dispatch(dict(action='pin-card-target', card_protocol=1))['ok']
    assert not broker.card_targets.pins and broker.typer.events == []
