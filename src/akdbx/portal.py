"""Shared private portal presentation. No scripts or remote assets."""
from __future__ import annotations

import html


STYLE = r"""
:root {
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #fff; background: #030303; color-scheme: dark;
  font-synthesis: none; -webkit-font-smoothing: antialiased;
  --ease: cubic-bezier(.22, 1, .36, 1);
}
* { box-sizing: border-box; }
body { margin: 0; min-width: 280px; }
button, input, select, textarea { font: inherit; }
button { -webkit-tap-highlight-color: transparent; touch-action: manipulation; }
::selection { background: #ffffff30; color: #fff; }
.atmosphere { position: fixed; inset: 0; overflow: hidden; pointer-events: none; isolation: isolate; }
.grain { position: absolute; inset: 0; width: 100%; height: 100%; opacity: .13; }
.light { position: absolute; border-radius: 50%; filter: blur(60px); }
.light-one { width: 700px; height: 700px; left: calc(50% - 620px); top: -330px; background: radial-gradient(ellipse, #ffffff24 0%, #ffffff0a 40%, transparent 68%); }
.light-two { width: 720px; height: 900px; right: calc(50% - 690px); bottom: -470px; background: radial-gradient(ellipse, #ffffff1c, transparent 68%); }
.light-line { position: absolute; width: 1px; height: 85vh; top: -200px; left: calc(50% - 110px); transform: rotate(38deg); background: linear-gradient(transparent, #ffffff12 45%, transparent); box-shadow: 0 0 80px 18px #ffffff04; }
main {
  position: relative; z-index: 1; width: min(100%, 484px); min-height: 100svh;
  margin: auto; padding: 60px 24px 32px;
  padding-top: max(60px, env(safe-area-inset-top));
  padding-bottom: calc(32px + env(safe-area-inset-bottom));
  display: flex; flex-direction: column; justify-content: center;
}
.sheet {
  position: relative; width: 100%; padding: 24px; border-radius: 26px;
  border: 1px solid #ffffff18; border-top-color: #ffffff32;
  background: linear-gradient(145deg, #ffffff0a, #ffffff01 38%, #ffffff04), #080808a8;
  -webkit-backdrop-filter: blur(30px); backdrop-filter: blur(30px);
  box-shadow: 0 36px 80px #0008, 0 4px 16px #0007, inset 0 1px 0 #ffffff07;
}
.sheet::before { content: ""; position: absolute; height: 1px; top: -1px; left: 18%; right: 18%; background: linear-gradient(90deg, transparent, #ffffff36, transparent); }
h1 { margin: 0 0 18px; font-size: 18px; line-height: 1.4; font-weight: 450; letter-spacing: -.4px; overflow-wrap: anywhere; }
p { color: #ffffffb3; font-size: 13px; line-height: 1.65; margin: 0 0 18px; overflow-wrap: anywhere; }
p:last-child { margin-bottom: 0; }
strong { color: #fff; font-weight: 500; }
form { display: grid; grid-template-columns: minmax(0, 1fr); gap: 12px; }
.sheet > form + p { margin-top: 18px; }
.field, label:has(> input[type=file]), label:has(> #manual) {
  position: relative; min-width: 0; padding: 13px 16px 12px;
  border: 1px solid #ffffff1a; border-top-color: #ffffff20; border-radius: 14px;
  background: linear-gradient(135deg, #ffffff04, transparent 55%), #00000038;
  box-shadow: inset 0 1px 0 #ffffff03;
}
label { display: block; color: #ffffffb3; font-size: 11px; line-height: 1.5; letter-spacing: .12px; overflow-wrap: anywhere; }
.field label { margin-bottom: 5px; }
.field:focus-within, label:has(> input:focus-visible) { border-color: #ffffff5c; background-color: #ffffff04; box-shadow: 0 0 0 3px #ffffff04, inset 0 1px 0 #ffffff06; }
.field:focus-within label { color: #fff; }
input:not([type=checkbox]):not([type=radio]):not([type=file]):not([type=hidden]), select, textarea {
  width: 100%; min-width: 0; padding: 0; border: 0; outline: 0; border-radius: 0;
  background: transparent; color: #fff; font-size: 16px; line-height: 1.5; letter-spacing: -.2px;
}
input::placeholder, textarea::placeholder { color: #ffffff80; opacity: 1; }
input:disabled, select:disabled, textarea:disabled { opacity: .5; }
input:-webkit-autofill { -webkit-text-fill-color: #fff; -webkit-box-shadow: 0 0 0 1000px #111 inset; caret-color: #fff; border-radius: 3px; }
input[type=file] { display: block; width: 100%; min-width: 0; margin-top: 8px; color: #ffffffa6; font-size: 12px; }
input[type=file]::file-selector-button { font: inherit; color: #fff; background: #ffffff08; border: 1px solid #ffffff24; border-radius: 6px; padding: 6px 9px; margin-right: 10px; }
label:has(> #manual) input { display: block; margin-top: 5px; }
label:has(> input[type=checkbox]), label:has(> input[type=radio]) {
  display: flex; align-items: flex-start; gap: 10px; color: #ffffffb3; font-size: 12px; line-height: 1.6; padding: 4px 1px; cursor: pointer;
}
input[type=checkbox], input[type=radio] { flex-shrink: 0; width: 17px; height: 17px; margin: 1px 0 0; accent-color: #fff; cursor: pointer; }
input:focus-visible, a:focus-visible { outline: 1px solid #fff; outline-offset: 4px; }
.field input:focus-visible { outline: 0; }
button {
  position: relative; overflow: hidden; width: 100%; display: flex; justify-content: space-between; align-items: center; gap: 12px;
  color: #fff; padding: 16px 18px; min-height: 56px; border-radius: 13px; font-size: 13px; font-weight: 500; letter-spacing: -.1px; cursor: pointer;
  border: 1px solid #ffffff32; border-top-color: #ffffff52;
  background: linear-gradient(165deg, #ffffff16, #ffffff06 52%, #ffffff0a), #08080880;
  box-shadow: inset 0 1px 0 #ffffff07, 0 6px 16px #0005;
}
button::before { content: ""; position: absolute; inset: 0; background: linear-gradient(110deg, transparent 20%, #ffffff0c 46%, transparent 70%); transform: translateX(-110%); pointer-events: none; }
button::after { content: ""; flex-shrink: 0; width: 8px; height: 8px; border-top: 1px solid currentColor; border-right: 1px solid currentColor; transform: rotate(45deg); }
button:hover { border-color: #ffffff63; background-color: #ffffff05; box-shadow: 0 0 30px #ffffff05, inset 0 1px 0 #ffffff16; }
button:active { transform: scale(.985); }
button:focus-visible { outline: 1px solid #fff; outline-offset: 4px; }
button[type=button] { border-color: #ffffff20; background: #ffffff03; box-shadow: none; color: #ffffffb3; }
button:disabled { cursor: default; opacity: .4; }
a { color: #ffffffd9; text-underline-offset: 4px; text-decoration-color: #ffffff52; overflow-wrap: anywhere; }
a:hover { color: #fff; text-decoration-color: #fff; }
dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 6px 14px; margin: 0 0 20px; padding: 0 0 18px; border-bottom: 1px solid #ffffff18; font-size: 12px; line-height: 1.6; }
dt { color: #ffffffa6; text-transform: capitalize; }
dd { color: #fff; margin: 0; overflow-wrap: anywhere; }
.error { color: #fff; border-left: 1px solid #ffffff70; padding-left: 12px; }
#message:empty { display: none; }
@media (min-width: 700px) { main { padding-top: 80px; padding-bottom: 56px; } .sheet { padding: 30px; } }
@media (max-width: 360px) { main { padding-left: 16px; padding-right: 16px; } .sheet { padding: 20px; } .field { padding-left: 13px; padding-right: 13px; } dl { grid-template-columns: minmax(0, 1fr); gap: 2px; } dd { margin-bottom: 6px; } }
@media (prefers-reduced-motion: no-preference) {
  .light-one { animation: drift-one 24s ease-in-out infinite alternate; }
  .light-two { animation: drift-two 30s ease-in-out infinite alternate; }
  .sheet { animation: enter .8s var(--ease) both; }
  .field { animation: reveal .7s var(--ease) both; }
  .field:nth-of-type(1) { animation-delay: .08s; } .field:nth-of-type(2) { animation-delay: .12s; }
  .field:nth-of-type(3) { animation-delay: .16s; } .field:nth-of-type(4) { animation-delay: .20s; }
  .field:nth-of-type(5) { animation-delay: .24s; }
  .field, label, button, a { transition: border-color .3s, color .3s, background-color .3s, box-shadow .3s, transform .35s var(--ease), opacity .25s; }
  button:not([type=button])::before { animation: glint 9s ease-in-out 2s infinite; }
  @keyframes enter { from { opacity: 0; transform: translateY(16px) scale(.985); } to { opacity: 1; transform: none; } }
  @keyframes reveal { from { opacity: 0; transform: translateY(9px); } to { opacity: 1; transform: none; } }
  @keyframes drift-one { from { transform: translate3d(-50px, 0, 0); opacity: .7; } to { transform: translate3d(100px, 140px, 0); opacity: 1; } }
  @keyframes drift-two { from { transform: translate3d(0, 20px, 0); } to { transform: translate3d(-100px, -150px, 0); } }
  @keyframes glint { 0%, 70%, 100% { transform: translateX(-110%); } 87% { transform: translateX(110%); } }
}
"""


def field(label: str, name: str, *, kind: str = "password",
          autocomplete: str = "off", maxlength: int | None = None,
          required: bool = True, autofocus: bool = False) -> str:
    """Keep labels associated with inputs without changing submitted field names."""
    escaped = html.escape(name, quote=True)
    attrs = (f' id="{escaped}" name="{escaped}" type="{html.escape(kind, quote=True)}"'
             f' autocomplete="{html.escape(autocomplete, quote=True)}"')
    if maxlength is not None:
        attrs += f' maxlength="{maxlength}"'
    if required:
        attrs += ' required'
    if autofocus:
        attrs += ' autofocus'
    return (f'<div class="field"><label for="{escaped}">{html.escape(label)}</label>'
            f'<input{attrs}></div>')


def render(title: str, body: str) -> bytes:
    """Wrap server-generated, already escaped form markup in the shared shell."""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="referrer" content="no-referrer"><meta name="color-scheme" content="dark">
<title>{html.escape('akdbx: ' + title)}</title><style>{STYLE}</style></head>
<body><div class="atmosphere" aria-hidden="true"><div class="light light-one"></div>
<div class="light light-two"></div><div class="light-line"></div>
<svg class="grain" xmlns="http://www.w3.org/2000/svg"><filter id="portal-grain">
<feTurbulence type="fractalNoise" baseFrequency=".95" numOctaves="3" stitchTiles="stitch"/>
</filter><rect width="100%" height="100%" filter="url(#portal-grain)" opacity=".16"/></svg></div>
<main><section class="sheet" aria-labelledby="portal-title"><h1 id="portal-title">{html.escape(title)}</h1>
{body}</section></main></body></html>""".encode("utf-8")
