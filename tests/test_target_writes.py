"""Target failures must never certify a generated password for persistence."""
import json

import pytest

from akdbx.broker import Broker
from akdbx.target import DeliveryError, failure
from test_broker import Entry, RecordingTyper, Vault, target_request
from test_writes import deployed, template, begin, commit, reopened, OLD


@pytest.mark.parametrize('started', [False, True])
def test_saved_fill_target_failure_is_secret_free_and_consumed(started, capsys, caplog):
    class Interrupted(RecordingTyper):
        def deliver(self, identity, steps, ready):
            error = DeliveryError(started)
            error.args = (str(steps),)  # a backend error can contain a secret
            raise error
    broker = Broker(Vault([Entry()]), Interrupted())
    pin = target_request(broker, 'password')
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    result = broker.dispatch(dict(action='fill', mode='password', handle=handle, **pin))
    assert result == failure(started)
    assert Entry.password not in json.dumps(result)
    assert not broker.dispatch(dict(action='fill', handle=handle, **pin))['ok']
    assert capsys.readouterr() == ('', '') and not caplog.records


def test_partial_generated_fills_are_not_counted_and_cannot_commit(deployed, monkeypatch, capsys, caplog):
    broker, typer, path, _ = deployed
    generated = begin(broker, 'generate-password')
    def interrupted(identity, steps, ready):
        raise DeliveryError(True)
    monkeypatch.setattr(typer, 'deliver', interrupted)
    for ref in generated['fill_handles'].values():
        request = dict(action='fill-generated', handle=ref, target_url='https://example.test/reset', **target_request(broker, 'password'))
        assert broker.dispatch(request) == failure(True)
        assert not broker.dispatch(request)['ok']
    assert not broker.writes.get(generated['write_handle']).filled
    assert not commit(broker, generated)['ok']
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
    assert not typer.events
    assert capsys.readouterr() == ('', '') and not caplog.records


@pytest.mark.parametrize('target_data', [{}, {'target': 'unknown', 'target_protocol': 1},
                                       {'target': 'unknown', 'target_protocol': 1, 'global_fallback': True}])
def test_generated_fill_never_bypasses_required_target(deployed, target_data):
    broker, typer, _, _ = deployed
    generated = begin(broker, 'generate-password')
    ref = generated['fill_handles']['password']
    request = dict(action='fill-generated', handle=ref, target_url='https://example.test/reset', **target_data)
    assert not broker.dispatch(request)['ok']
    assert not broker.dispatch({**request, **target_request(broker, 'password')})['ok']
    assert not commit(broker, generated)['ok'] and not typer.events


@pytest.mark.parametrize('mode', ['password', 'login'])
def test_broker_refuses_x11_passwords_even_if_backend_offers_to_type(mode):
    from test_broker import x11_target_request
    class UnsafeKeyboard(RecordingTyper):
        def deliver_password(self, identity, steps, ready, **kwargs):
            self.deliver(identity, steps, ready)
    class UnreadPassword:
        uuid, title, username, url, path = Entry.uuid, Entry.title, Entry.username, Entry.url, Entry.path
        @property
        def password(self):
            raise AssertionError('password must not be read for an X11 pin')
    typer = UnsafeKeyboard()
    broker = Broker(Vault([UnreadPassword()]), typer)
    handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
    result = broker.dispatch(dict(action='fill', handle=handle, mode=mode, **x11_target_request(broker)))
    assert result == failure(False)
    assert 'target_delivery' not in result and not typer.events


def test_generated_x11_refusal_does_not_trust_backend_or_certify_commit(deployed, monkeypatch):
    from test_broker import x11_target_request
    broker, typer, path, _ = deployed
    calls = []
    monkeypatch.setattr(typer, 'deliver_password', lambda *a, **kw: calls.append(True), raising=False)
    generated = begin(broker, 'generate-password')
    for ref in generated['fill_handles'].values():
        result = broker.dispatch(dict(action='fill-generated', handle=ref,
                    target_url='https://example.test/reset', **x11_target_request(broker)))
        assert result == failure(False)
    assert not calls and not typer.events
    assert not broker.writes.get(generated['write_handle']).filled
    assert not commit(broker, generated)['ok']
    assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
