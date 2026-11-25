"""Owned Qt capture fixture. Invented values only, on an isolated test display."""
import json
from pathlib import Path
import sys

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QMainWindow, QPlainTextEdit

directory = Path(sys.argv[1])
app = QApplication([])
window = QMainWindow()
field = QPlainTextEdit('abc')
field.setReadOnly(True)
window.setCentralWidget(field)
window.show()
window.activateWindow()
field.setFocus()


def tick():
    command = directory / 'command.json'
    if not command.exists():
        return
    data = json.loads(command.read_text())
    command.unlink()
    if 'value' in data:
        field.setPlainText(data['value'])
    field.setFocus()
    (directory / 'result.json').write_text(json.dumps([field.toPlainText()]))


timer = QTimer()
timer.timeout.connect(tick)
timer.start(40)
QTimer.singleShot(100, lambda: (directory / 'ready').write_text(app.platformName()))
app.exec()
