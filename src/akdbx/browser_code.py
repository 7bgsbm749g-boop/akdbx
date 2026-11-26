"""DOM delivery of an SMS verification code (or a source's webhook URL).

It reuses the card transport and its same-origin, hit-tested DOM guards, with
a derived pin script: one focused, visible, enabled plain input; any
autocomplete value. The shared card script, which the browser extension also
embeds, stays unchanged.
"""
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
        return dict(code_protocol=1, code_browser_configured=self.configured, **self._receipt())
