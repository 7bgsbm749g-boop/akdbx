"""Generated-password clock checks on owned isolated X11 windows only."""
import importlib
import os
import shutil
from datetime import timedelta

import pytest

from test_target import isolated_x11, key_events
from test_writes import MASTER, OLD, begin, commit, reopened, template


@pytest.mark.parametrize('namespace', ['akdbx', 'agentic_kdbx'])
@pytest.mark.parametrize('latest_in', ['active', 'history'])
@pytest.mark.parametrize('hook', ['prepare', 'final-check'])
@pytest.mark.parametrize('change', ['rollback', 'invalid', 'stable'])
def test_generated_clock_at_native_delivery_boundary(
    template, tmp_path, isolated_x11, namespace, latest_in, hook, change,
):
    """A late clock refusal emits no real key; a stable clock still saves."""
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
    hooks = []

    def change_clock():
        hooks.append(hook)
        if change != 'stable':
            wall[0] = latest.timestamp() - 1 if change == 'rollback' else float('nan')

    class LateClockSession(target.X11Session):
        def __init__(self, pid, window):
            self.prepared = False
            self.prepared_checks = 0
            super().__init__(pid, window)

        def prepare(self, steps):
            codes = super().prepare(steps)
            self.prepared = True
            if hook == 'prepare':
                change_clock()
            return codes

        def check(self):
            super().check()
            if self.prepared:
                self.prepared_checks += 1
                if hook == 'final-check' and self.prepared_checks == 2:
                    change_clock()

    broker = module.Broker(module.open_vault_with_password(path, MASTER),
                           target.X11Typer(LateClockSession), wall_clock=lambda: wall[0])
    broker.writes.public_base = 'https://node.example:9443'
    before = path.read_bytes()
    try:
        assert broker.dispatch(dict(action='ping'))['writes_available']
        prepared = begin(broker, 'generate-password')
        assert prepared['ok'], prepared
        results, delivered = [], []
        for reference in prepared['fill_handles'].values():
            wall[0] = latest.timestamp() + 1
            pin = broker.dispatch(dict(action='pin-target', pid=os.getpid(),
                window=lab.windows[0].id, target_protocol=1))
            assert pin['ok'], pin
            results.append(broker.dispatch(dict(action='fill-generated', handle=reference,
                target_url='https://example.test/reset', target=pin['target'], target_protocol=1)))
            delivered.append(key_events(lab))
        assert hooks == [hook, hook]
        if change != 'stable':
            assert all(not result['ok'] for result in results), {
                'results': results, 'native_event_counts': [len(events) for events in delivered],
            }
            reason = 'future-dated' if change == 'rollback' else 'write clock'
            assert all(reason in result['error'] for result in results), results
            assert delivered == [[], []]
            assert path.read_bytes() == before
            assert reopened(path).find_entries(title='Synthetic site', first=True).password == OLD
            assert not commit(broker, prepared)['ok']
            assert not list(tmp_path.glob('.*.akdbx-backup-*'))
        else:
            assert all(result['ok'] for result in results), results
            decoded = []
            for events in delivered:
                assert events and {event[0] for event in events} == {lab.windows[0].id}
                codes = [lab.display.keycode_to_keysym(code, 1 if state & lab.X.ShiftMask else 0)
                         for _, kind, code, state in events if kind == lab.X.KeyPress]
                decoded.append(''.join(chr(code) for code in codes))
            assert decoded[0] == decoded[1] and decoded[0] != OLD
            assert commit(broker, prepared)['state'] == 'saved'
            saved = reopened(path).find_entries(title='Synthetic site', first=True)
            assert saved.password == decoded[0] and saved.mtime > latest
    finally:
        broker.unlock_notifications.close()
