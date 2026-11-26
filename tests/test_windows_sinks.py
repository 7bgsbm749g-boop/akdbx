"""Real Windows pipe and private-file checks, with a disposable encrypted vault."""
from contextlib import contextmanager
import json
import os
import sys
import threading
import uuid

import pytest

if sys.platform != 'win32':
    pytest.skip('native Windows APIs required', allow_module_level=True)

from akdbx import windows_rpc as rpc, windows_security as security, windows_sinks
from akdbx.broker import Broker, open_vault_with_password
from akdbx.sink_helper import SinkError
from akdbx.secrets_capture import CAPTURED_FIELDS
from test_windows_browser import set_dacl, PUBLIC
from test_windows_native import private_dir, synthetic_vault


@pytest.fixture
def config(private_dir):
    path = private_dir / 'sinks.json'
    security.write_new(path, json.dumps(dict(version=1, helper_pipe=rpc.PREFIX + 'akdbx-' + uuid.uuid4().hex + '-sinks',
        sinks={'test': dict(path=str(private_dir / 'test.env'), key='TEST_KEY', field='client_secret',
                            entry_origin='https://example.test')})).encode())
    return path


@contextmanager
def helper(config):
    stop = threading.Event()
    name = config['helper_pipe']
    pending = rpc.new_pipe(name, first=True)
    thread = threading.Thread(target=rpc.accept_connections, args=(name, pending,
                              lambda conn: windows_sinks.handle(conn, config), stop))
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(10)
        assert not thread.is_alive()


def test_operator_sink_delivers_only_a_receipt(config, private_dir, synthetic_vault):
    vault = open_vault_with_password(synthetic_vault, 'synthetic master')
    broker = Broker(vault, object(), secret_sinks_path=config)
    entry = vault.entries[0]
    entry.set_custom_property(CAPTURED_FIELDS, 'client_secret')
    entry.set_custom_property('client_secret', 'synthetic-token', protect=True)
    status = broker.dispatch(dict(action='ping'))
    assert status['windows_secret_sink_pipe'] and status['secret_sinks'] == ['test']
    path = private_dir / 'test.env'
    with helper(windows_sinks.load_config(config)):
        for previous, expected in [(None, b'TEST_KEY=synthetic-token\n'),
                                   (b'OTHER=keep\r\nTEST_KEY=old\r\n', b'OTHER=keep\r\nTEST_KEY=synthetic-token\r\n')]:
            if previous is not None:
                security.replace_private(path, previous)
            handle = broker.dispatch(dict(action='search'))['entries'][0]['handle']
            result = broker.dispatch(dict(action='deliver-secret', sink_protocol=1, sink='test',
                                          field='client_secret', handle=handle))
            assert result == dict(ok=True, state='delivered', sink='test', field='client_secret', restarted=None)
            assert security.read_private(path)[0] == expected


@pytest.mark.parametrize('case', ['public-config', 'public-destination', 'other-definition', 'hard-link', 'other-integrity'])
def test_helper_refuses_without_modifying_destination(config, private_dir, monkeypatch, case):
    path = private_dir / 'test.env'
    security.write_new(path, b'OTHER=keep\n')
    if case == 'public-config':
        set_dacl(config, PUBLIC)
        with pytest.raises(SinkError):
            windows_sinks.load_config(config)
        return
    client = windows_sinks.load_config(config)
    server = windows_sinks.load_config(config)
    if case == 'public-destination':
        set_dacl(path, PUBLIC)
    elif case == 'hard-link':
        os.link(path, private_dir / 'second-name')
    elif case == 'other-definition':
        server['sinks']['test']['key'] = 'DIFFERENT'
    else:
        def refuse(_):
            raise PermissionError()
        monkeypatch.setattr(security, 'require_same_integrity', refuse)
    with helper(server), pytest.raises((SinkError, PermissionError)):
        windows_sinks.deliver(client, client['sinks']['test'], 'synthetic-token')
    assert path.read_bytes() == b'OTHER=keep\n'
