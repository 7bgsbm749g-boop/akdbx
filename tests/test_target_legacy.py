"""Run the actual 0.8.1 source with only synthetic entries and recording input."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from agentic_kdbx import cli

BASELINE = '1e6fc5167c156e59857e055b1cfd57a70110f20e'


def test_actual_081_global_input_reproduction_and_new_cli_preflight(tmp_path):
    package = tmp_path / 'legacy' / 'agentic_kdbx'
    package.mkdir(parents=True)
    names = subprocess.run(['git', 'ls-tree', '--name-only', BASELINE + ':src/agentic_kdbx'],
                           capture_output=True, text=True, check=True, timeout=10).stdout.splitlines()
    for name in names:
        data = subprocess.run(['git', 'show', BASELINE + ':src/agentic_kdbx/' + name],
                              capture_output=True, check=True, timeout=10).stdout
        (package / name).write_bytes(data)
    socket = tmp_path / 'private' / 'broker.sock'
    script = '''import signal,sys,threading
from pathlib import Path
from types import SimpleNamespace
from agentic_kdbx.broker import Broker,serve
class RecordingGlobalInput:
    count=0
    foreground='unrelated-synthetic-app'
    destination=None
    def type_text(self,text):
        self.count+=len(text)
        self.destination=self.foreground
    def press_tab(self):
        self.count+=1
entry=SimpleNamespace(uuid='synthetic-id',title='Synthetic',username='synthetic-user',
    password='synthetic-only-password',url='https://example.test',path=('Web','Synthetic'))
typer=RecordingGlobalInput()
broker=Broker(SimpleNamespace(entries=[entry]),typer)
original=broker.dispatch
def dispatch(request,**kwargs):
    response=original(request,**kwargs)
    if request.get('action')=='ping':
        response.update(synthetic_key_count=typer.count,synthetic_destination=typer.destination)
    return response
broker.dispatch=dispatch
stop=threading.Event()
signal.signal(signal.SIGTERM,lambda *_:stop.set())
serve(Path(sys.argv[1]),broker,stop)
'''
    process = subprocess.Popen([sys.executable, '-c', script, str(socket)],
                               env={**os.environ, 'PYTHONPATH': str(package.parent)},
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.02)
        assert socket.exists()
        status = cli.request(socket, dict(action='ping'))
        assert status['version'] == '0.8.1' and status['synthetic_key_count'] == 0
        handle = cli.request(socket, dict(action='search'))['entries'][0]['handle']
        # Actual baseline silently ignores target data and reports success even
        # though the recording global destination is the unrelated app.
        result = cli.request(socket, dict(action='fill', mode='password', handle=handle,
                                         target='wrong-synthetic-target', target_protocol=1,
                                         start_deadline=time.monotonic() + 4))
        assert result == dict(ok=True, filled='password')
        before = cli.request(socket, dict(action='ping'))
        assert before['synthetic_destination'] == 'unrelated-synthetic-app'
        assert before['synthetic_key_count'] > 0
        prefix = [str(Path(sys.executable).with_name('akdbx')), '--socket', str(socket)]
        for command in [['pin-target', '--pid', '123', '--window', '456'],
                        ['fill', 'synthetic-handle', '--target', 'synthetic-target'],
                        ['fill-generated', 'synthetic-handle', '--target', 'synthetic-target',
                         '--target-url', 'https://example.test']]:
            result = subprocess.run([*prefix, *command], capture_output=True, text=True, timeout=10)
            assert result.returncode == 1
            assert 'target request not sent' in json.loads(result.stdout)['error']
            assert not result.stderr
        after = cli.request(socket, dict(action='ping'))
        assert after['synthetic_key_count'] == before['synthetic_key_count']
    finally:
        process.terminate()
        output, errors = process.communicate(timeout=10)
        assert not output and not errors
