"""Manual X11 autofill target used by the real-desktop smoke test."""

from __future__ import annotations

import os
from pathlib import Path
import tkinter as tk


EXPECTED = "synthetic-secret-42"
RESULT = Path(os.environ["AKDBX_GUI_RESULT"])

root = tk.Tk()
root.title("AKDBX Autofill Test")
root.geometry("500x160+390+300")
tk.Label(root, text="Real desktop autofill target").pack(pady=12)
entry = tk.Entry(root, name="password_target", width=42)
entry.pack(pady=8)
entry.focus_force()


def observe() -> None:
    if entry.get() == EXPECTED:
        RESULT.write_text("PASS\n", encoding="ascii")
    else:
        root.after(50, observe)


root.after(50, observe)
root.mainloop()
