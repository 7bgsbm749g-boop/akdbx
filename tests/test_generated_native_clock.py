"""Generated passwords never reach owned isolated X11 windows, whatever the clock.

Before 0.15.0 this suite proved that a changed write clock stopped native key
delivery. Generated passwords now go only to verified Chromium DOM pins, whose
final setter boundary rechecks the same write clock through ``ready()``. The
native route must refuse before any key event, so no clock state can matter.
"""
import importlib
import os
import shutil
from datetime import timedelta

import pytest

from test_target import isolated_x11, key_events
from test_writes import MASTER, OLD, begin, commit, reopened, template


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('latest_in', ['active', 'history'])
@pytest.mark.parametrize('change', ['rollback', 'invalid', 'stable'])
def test_generated_password_never_reaches_native_x11_delivery(
    template, tmp_path, isolated_x11, namespace, latest_in, change,
):
    """No real key is emitted and nothing can be committed for an X11 pin."""
    module = importlib.import_module(namespace + '.broker')
    target = importlib.import_module(namespace + '.target')
    lab = isolated_x11
    path = tmp_path / 'synthetic.kdbx'
    shutil.copyfile(template, path)
    vault = reopened(path)
    entry = vault.find_entries(title='Synthetic site', first=True)
    latest = entry.mtime
    if latest_in == 'history':
        entry.save_history()
        entry.mtime = latest - timedelta(days=1)
        vault.save()
    wall = [latest.timestamp() + 1]
    prepared_sessions = []

    class RecordingSession(target.X11Session):
        def prepare(self, steps):
            prepared_sessions.append(True)
            return super().prepare(steps)

    broker = module.Broker(module.open_vault_with_password(path, MASTER),
                           target.X11Typer(RecordingSession), wall_clock=lambda: wall[0])
    broker.writes.public_base = 'https://node.example:9443'
    before = path.read_bytes()
    try:
        assert broker.dispatch(dict(action='ping'))['writes_available']
        prepared = begin(broker, 'generate-password')
        assert prepared['ok'], prepared
        results, delivered = [], []
        for reference in prepared['fill_handles'].values():
            wall[0] = latest.timestamp() + 1
            if change != 'stable':
                wall[0] = latest.timestamp() - 1 if change == 'rollback' else float('nan')
            pin = broker.dispatch(dict(action='pin-target', pid=os.getpid(),
                window=lab.windows[0].id, target_protocol=1))
            assert pin['ok'], pin
            results.append(broker.dispatch(dict(action='fill-generated', handle=reference,
                target_url='https://example.test/reset', target=pin['target'], target_protocol=1)))
            delivered.append(key_events(lab))
        assert all(not result['ok'] for result in results), results
        assert all(result.get('delivery', 'not-started') == 'not-started' for result in results), results
        assert delivered == [[], []] and not prepared_sessions
        assert not commit(broker, prepared)['ok']
        assert path.read_bytes() == before
        assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
        assert not list(tmp_path.glob('.*.akdbx-backup-*'))
    finally:
        broker.unlock_notifications.close()
