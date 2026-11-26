"""DOM delivery of an SMS verification code (or a source's webhook URL).

It reuses the card transport and its same-origin, hit-tested DOM guards, with
a derived pin script: one focused, visible, enabled plain input; any
autocomplete value. The shared card script stays unchanged. The browser
extension embeds both: its code pins (``--route extension``) run this derived
script, so both routes apply the same field rules.
"""
import sys

from . import native_fields
from .browser_card import BrowserCards, PIN_SCRIPT

DELIVERY = 'cdp-code-element-v1'
FIELDS = ('one-time-code', 'webhook-url')


def _derive(script: str) -> str:
    replacements = (
        ("(selector, field, frameURL, topURL, processor=false, identity=false, purpose=false, allowOff=false, shadowRootOf=null) => {",
         "(selector, field, frameURL, topURL, processor=false, identity=false, purpose=false, allowOff=false, code=false, shadowRootOf=null) => {"),
        ("  if (!input && !select && !textarea) return null;\n",
         "  if (!input && !select && !textarea) return null;\n  if (code && !input) return null;\n"),
        ("  } else if (computop ? !knownComputopField() :",
         "  } else if (code) {\n"
         "    if (!(field === 'one-time-code' ? ['text','tel','number','password'] : ['text','url']).includes(type)) return null;\n"
         "  } else if (computop ? !knownComputopField() :"),
        ("  if (!identity && input && !['text','tel','password'].includes(type)) return null;",
         "  if (!identity && !code && input && !['text','tel','password'].includes(type)) return null;"),
        ("    if (identity && (!doc.hasFocus() || doc.activeElement !== el || (select && el.multiple))) return false;",
         "    if ((identity || code) && (!doc.hasFocus() || doc.activeElement !== el || (select && el.multiple))) return false;"),
    )
    for old, new in replacements:
        if script.count(old) != 1:
            raise RuntimeError('card pin script changed; update browser_code')
        script = script.replace(old, new)
    return script


CODE_PIN_SCRIPT = _derive(PIN_SCRIPT)


class BrowserCodes(BrowserCards):
    kind = 'code'
    delivery = DELIVERY
    fields = FIELDS
    pin_script = CODE_PIN_SCRIPT
    pin_extra = (False, False, False, False, True)

    def capabilities(self):
        cdp = self.configured
        routes = ['cdp'] if cdp else []
        # The broker adds the extension route to this manager (RoutedTargets): a
        # paired fill extension 0.13.0 or newer takes code pins on Linux, Windows
        # and macOS. `extension_paired` says whether one is paired now.
        routes.append('extension')
        if native_fields.supported():
            routes.append('native')
        if sys.platform.startswith('linux') or sys.platform == 'win32':
            routes.append('window')
        return dict(code_protocol=1, code_browser_configured=cdp, sms_fill_routes=routes, **self._receipt())
