"""Temporary CI probe: how Chrome renders the /secret-inert-text cover (synthetic page only; no secret values).

Run: python -m pytest -q -s tests/probe_cover.py (AKDBX_TEST_EXTENSION_BROWSER set). Writes
$AKDBX_PROBE_DIR/inert-text.json and inert-text.png. Remove this file and its CI step after the fix.
"""
import base64
import json
import os
from pathlib import Path

import pytest

from test_extension_browser import PAGES, extension_browser, private_dir  # noqa: F401
from test_windows_unlock import certificates  # noqa: F401
from windows_chromium_lab import chromium_lab

COLOUR = (10, 200, 30)
MEASURE = '''(() => {
  const rects = node => { const r = document.createRange(); r.selectNodeContents(node);
    return Array.from(r.getClientRects(), q => [q.left, q.top, q.width, q.height]); };
  const secret = document.getElementById('secret'), cover = document.querySelector('div[inert]');
  const box = secret.getBoundingClientRect(), style = getComputedStyle(secret);
  const line = rects(secret)[0];
  const edge = 4, top = box.top + 4, bottom = box.bottom - 4;
  const clamp = v => Math.min(Math.max(v, top), bottom);
  const rows = [0, 0.5, 1].map(f => clamp(line[1] + edge + (line[3] - 2 * edge) * f));
  const chain = (x, y) => document.elementsFromPoint(x, y).map(e => e.tagName + (e.id ? '#' + e.id : '') + (e.inert ? '[inert]' : ''));
  return {secretBox: [box.left, box.top, box.width, box.height], secretLines: rects(secret), coverLines: rects(cover),
          coverInert: cover.inert, coverPointerEvents: getComputedStyle(cover).pointerEvents,
          coverFont: getComputedStyle(cover).font, secretFont: style.font, dpr: devicePixelRatio,
          view: [innerWidth, innerHeight], rows,
          chains: rows.map(y => [y, chain(line[0] + 20, y)])};
})()'''


def fonts(lab, selector):
    root = lab.observer.call('DOM.getDocument', dict(depth=-1), lab.session)['root']['nodeId']
    node = lab.observer.call('DOM.querySelector', dict(nodeId=root, selector=selector), lab.session)['nodeId']
    return lab.observer.call('CSS.getPlatformFontsForNode', dict(nodeId=node), lab.session)['fonts']


def test_probe_inert_text_cover(private_dir, certificates):  # noqa: F811
    folder = Path(os.environ.get('AKDBX_PROBE_DIR', private_dir))
    folder.mkdir(parents=True, exist_ok=True)
    certificates[1].chmod(0o600)
    with chromium_lab(private_dir, *certificates, pages=PAGES, binary=extension_browser()) as lab:
        lab.navigate('/secret-inert-text')
        for domain in ('DOM', 'CSS'):
            lab.observer.call(domain + '.enable', {}, lab.session)
        report = lab.evaluate(MEASURE)
        report['coverFonts'] = fonts(lab, 'div[inert]')
        report['secretFonts'] = fonts(lab, '#secret')
        rgb = 'rgb(%d, %d, %d)' % COLOUR
        # The challenge rule's paint, as an author rule (the cover paints above it either way).
        lab.evaluate("document.head.insertAdjacentHTML('beforeend', '<style>#secret{box-shadow:inset 0 0 0 9999px "
                     + rgb + "!important;color:" + rgb + "!important;-webkit-text-fill-color:" + rgb + "!important}</style>')")
        lab.evaluate('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))', await_promise=True)
        shot = lab.observer.call('Page.captureScreenshot', dict(format='png'), lab.session)['data']
        png = base64.b64decode(shot)
        (folder / 'inert-text.png').write_bytes(png)
        # Which rows of the secret's line box show the challenge colour, per CSS pixel row.
        profile = lab.evaluate('''(async () => {
          const img = new Image(); img.src = 'data:image/png;base64,%s'; await img.decode();
          const c = new OffscreenCanvas(img.width, img.height), g = c.getContext('2d'); g.drawImage(img, 0, 0);
          const scale = img.width / innerWidth, range = document.createRange();
          range.selectNodeContents(document.getElementById('secret'));
          const box = range.getClientRects()[0], out = [];  // The secret's text line, not its block.
          for (let y = Math.floor(box.top) - 2; y <= Math.ceil(box.bottom) + 2; ++y) {
            let hit = 0, n = 0;
            for (let x = box.left + 2; x < box.right - 2; x += 3, ++n) {
              const d = g.getImageData(Math.round(x * scale), Math.round(y * scale), 1, 1).data;
              if (Math.abs(d[0] - %d) <= 2 && Math.abs(d[1] - %d) <= 2 && Math.abs(d[2] - %d) <= 2) ++hit;
            }
            out.push([y, n ? Math.round(100 * hit / n) : null]);
          }
          return {scale, width: img.width, height: img.height, rows: out};
        })()''' % ((shot,) + COLOUR), await_promise=True)
        report['challengeProfile'] = profile
        (folder / 'inert-text.json').write_text(json.dumps(report, indent=1))
        print('PROBE', json.dumps(report))
