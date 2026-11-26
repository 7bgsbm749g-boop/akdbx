"""Identity delivery through the card transport's same-origin DOM guards."""
from .browser_card import BrowserCards, PIN_SCRIPT
from .identities import FILL_FIELDS

DELIVERY = 'cdp-identity-element-v1'


def _popup(script: str) -> str:
    """The pin script for the toolbar popup's address fields (fill extension 0.15.0).

    The popup applies the identity pin's own rules to every field it fills:
    autocomplete grammar, input type, select options, style guard, hit tests
    through same-origin frames, exact URLs and the retained-element checks.
    Two checks differ. The popup holds the window focus while the user
    chooses, and it fills the focused field's partners in the same form, so
    the extension checks the focused field itself: it must stay the
    document's active element until the fill. And the popup names each field
    by the element it kept since the user opened it, not by an agent's
    selector: the selector it passes only finds that element at the pin, so
    a node the page adds above a field during the fill does not refuse it.
    """
    replacements = (
        ("    if (identity && (!doc.hasFocus() || doc.activeElement !== el || (select && el.multiple))) return false;",
         "    if (identity && select && el.multiple) return false;"),
        ("        document.querySelectorAll(selector).length !== 1 || document.querySelector(selector) !== el ||\n", ""),
    )
    for old, new in replacements:
        if script.count(old) != 1:
            raise RuntimeError('card pin script changed; update browser_identity')
        script = script.replace(old, new)
    return script


POPUP_PIN_SCRIPT = _popup(PIN_SCRIPT)


class BrowserIdentities(BrowserCards):
    kind = 'identity'
    delivery = DELIVERY
    fields = FILL_FIELDS

    def capabilities(self):
        return dict(identity_protocol=1, identity_browser_configured=self.configured,
                    **self._receipt())
