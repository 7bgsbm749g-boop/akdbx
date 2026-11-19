"""Identity delivery through the card transport's same-origin DOM guards."""
from .browser_card import BrowserCards
from .identities import FILL_FIELDS

DELIVERY = 'cdp-identity-element-v1'


class BrowserIdentities(BrowserCards):
    kind = 'identity'
    delivery = DELIVERY
    fields = FILL_FIELDS

    def capabilities(self):
        return dict(identity_protocol=1, identity_browser_configured=self.profile is not None,
                    **self._receipt())
