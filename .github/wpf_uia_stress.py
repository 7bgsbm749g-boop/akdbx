"""TEMPORARY PR proof for the WPF UI Automation connection fix. Removed before merge.

Runs tests/test_windows_fields.py on a fresh Windows runner, cold first, then
the WPF case under CPU load, then times cold WPF connections with generous
limits. `unfixed` repeats the same steps with the v0.50.0 windows_uia.py.
All values are synthetic; the fixture app holds only invented text.
"""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
UNFIXED = '05fa1bd'  # v0.50.0


def pytest(select, basetemp):
    args = [sys.executable, '-m', 'pytest', '-q', '-rfEs', '-p', 'no:cacheprovider',
            'tests/test_windows_fields.py', '--basetemp=' + str(basetemp)]
    if select:
        args += ['-k', select]
    start = time.perf_counter()
    done = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=600)
    tail = [line for line in done.stdout.splitlines() if line.startswith(('FAILED', 'ERROR', 'E   '))][:6]
    summary = (done.stdout.strip().splitlines() or [''])[-1]
    return dict(ok=done.returncode == 0, seconds=round(time.perf_counter() - start, 1), summary=summary, tail=tail)


class Load:
    """One busy Python process per logical CPU, at normal priority."""

    def __enter__(self):
        self.hogs = [subprocess.Popen([sys.executable, '-c', 'while True: pass'])
                     for _ in range(os.cpu_count() or 2)]
        time.sleep(1)
        return self

    def __exit__(self, *exc):
        for hog in self.hogs:
            hog.kill()
            hog.wait()


def build(directory):
    framework = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319'
    exe = Path(directory) / 'fields.exe'
    subprocess.run([str(framework / 'csc.exe'), '/nologo', '/target:exe', '/out:' + str(exe),
                    '/r:System.Windows.Forms.dll', '/r:System.Xaml.dll',
                    *('/r:' + str(framework / 'WPF' / (name + '.dll'))
                      for name in ('WindowsBase', 'PresentationCore', 'PresentationFramework')),
                    str(ROOT / 'tests/windows_managed_fields.cs')], check=True, timeout=60)
    return exe


def timing(exe, launches):
    """Time a fresh WPF app's first UI Automation answers with 20 s limits."""
    import comtypes
    import comtypes.client
    import win32api
    import win32gui
    import win32process
    comtypes.CoInitializeEx(comtypes.COINIT_MULTITHREADED)
    types = comtypes.client.GetModule(str(Path(win32api.GetSystemDirectory()) / 'UIAutomationCore.dll'))
    results = []
    for _ in range(launches):
        app = subprocess.Popen([str(exe), 'wpf'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            assert app.stdout.readline().strip() == 'ready'
            ctypes.windll.user32.AllowSetForegroundWindow(app.pid)
            app.stdin.write('user\n')
            app.stdin.flush()
            assert app.stdout.readline().strip() == 'focused'
            window = win32gui.GetForegroundWindow()
            assert win32process.GetWindowThreadProcessId(window)[1] == app.pid
            assert win32gui.GetClassName(window).startswith('HwndWrapper[')
            uia = comtypes.client.CreateObject(types.CUIAutomation8, interface=types.IUIAutomation2)
            uia.AutoSetFocus = False
            uia.ConnectionTimeout = uia.TransactionTimeout = 20000
            slowest = [0.0]

            def timed(call):
                start = time.perf_counter()
                value = call()
                slowest[0] = max(slowest[0], time.perf_counter() - start)
                return value

            start = time.perf_counter()
            root = uia.ElementFromHandle(window)
            first = time.perf_counter() - start
            walker = uia.RawViewWalker
            start = time.perf_counter()

            def walk(node, depth=0):
                for name in ('CurrentProcessId', 'CurrentFrameworkId', 'CurrentControlType', 'CurrentClassName'):
                    timed(lambda: getattr(node, name))
                child = timed(lambda: walker.GetFirstChildElement(node))
                while child and depth < 48:
                    walk(child, depth + 1)
                    child = timed(lambda: walker.GetNextSiblingElement(child))

            walk(root)
            walk_total, walk_slowest = time.perf_counter() - start, slowest[0]
            slowest[0] = 0.0
            for _ in range(10):
                timed(lambda: uia.ElementFromHandle(window))
            warm_connection = slowest[0]
            slowest[0] = 0.0
            for _ in range(10):
                timed(uia.GetFocusedElement)
            warm_focus = slowest[0]
            results.append(dict(first_connection_ms=round(first * 1000), walk_ms=round(walk_total * 1000),
                                walk_slowest_call_ms=round(walk_slowest * 1000),
                                warm_connection_max_ms=round(warm_connection * 1000),
                                warm_focus_max_ms=round(warm_focus * 1000)))
        finally:
            try:
                app.stdin.write('exit\n')
                app.stdin.close()
                app.wait(timeout=10)
            except Exception:
                app.kill()
                app.wait()
    return results


def main():
    variant, runs = sys.argv[1], int(sys.argv[2])
    assert variant in {'fixed', 'unfixed'}
    module = ROOT / 'src/akdbx/windows_uia.py'
    if variant == 'unfixed':
        module.write_bytes(subprocess.run(['git', 'show', UNFIXED + ':src/akdbx/windows_uia.py'], cwd=ROOT,
                                          check=True, capture_output=True).stdout)
    assert ('FIRST_CONNECTION_MS = 2000' in module.read_text()) == (variant == 'fixed')
    report = dict(variant=variant, cpus=os.cpu_count(), idle=[], load=[], timing_idle=[], timing_load=[])
    scratch = Path(os.environ.get('RUNNER_TEMP') or tempfile.gettempdir()) / 'wpf-stress'
    # Cold first: a fresh runner's first WPF launch is where CI failed.
    for n in range(runs):
        report['idle'].append(pytest(None, scratch / f'idle{n}'))
        print('idle', n, report['idle'][-1], flush=True)
    with Load():
        for n in range(runs):
            report['load'].append(pytest('wpf', scratch / f'load{n}'))
            print('load', n, report['load'][-1], flush=True)
    exe = build(tempfile.mkdtemp(prefix='wpf-timing-'))
    report['timing_idle'] = timing(exe, 5)
    with Load():
        report['timing_load'] = timing(exe, 5)
    print(json.dumps(report, indent=1), flush=True)
    out = Path(os.environ.get('RUNNER_TEMP') or tempfile.gettempdir()) / 'wpf-stress.json'
    out.write_text(json.dumps(report, indent=1))
    passed = sum(r['ok'] for r in report['idle'] + report['load'])
    lines = [f'### {variant}: {passed}/{2 * runs} pytest runs passed ({os.cpu_count()} CPUs)', '',
             '| phase | run | result | seconds | detail |', '|---|---|---|---|---|']
    for phase in ('idle', 'load'):
        for n, r in enumerate(report[phase]):
            lines.append(f"| {phase} | {n} | {'pass' if r['ok'] else 'FAIL'} | {r['seconds']} | "
                         f"{' / '.join(r['tail'])[:300] or r['summary']} |")
    lines += ['', '| timing | first connection ms | walk ms | slowest walk call ms | warm connection max ms | warm focus max ms |',
              '|---|---|---|---|---|---|']
    for phase in ('timing_idle', 'timing_load'):
        for r in report[phase]:
            lines.append(f"| {phase} | {r['first_connection_ms']} | {r['walk_ms']} | {r['walk_slowest_call_ms']} | "
                         f"{r['warm_connection_max_ms']} | {r['warm_focus_max_ms']} |")
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
    if variant == 'unfixed':
        subprocess.run(['git', 'checkout', '--', 'src/akdbx/windows_uia.py'], cwd=ROOT, check=True)
        return 0  # The reproduction records failures; it never fails the job.
    return 0 if passed == 2 * runs else 1


if __name__ == '__main__':
    sys.exit(main())
