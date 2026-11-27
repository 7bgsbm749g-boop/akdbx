"""Identity delivery through the card transport's same-origin DOM guards."""
from .browser_card import BrowserCards, CardTargetError, PIN_SCRIPT
from .identities import FILL_FIELDS, PHONE_DIGIT_BOXES

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


def _digit_pin(script: str) -> str:
    """The pin script for one box of a split phone-digit challenge (0.55.0, fill extension 0.20.0).

    A page such as "Enter the missing digits from the last four digits of your
    number" shows one single-character box per digit. ``digit`` is
    ``{index, count}``: the box for digit ``index + 1`` (from 0) of the last
    ``count`` digits of the saved number. The script checks that the pinned
    element is a single-character ``text``, ``tel`` or ``number`` input
    (``maxlength`` 1), focused, visible, enabled and editable, and that the
    nearest ancestor holding another such box holds exactly ``count`` of them,
    with the pinned one at ``index``. Any autocomplete value is accepted: such
    boxes rarely have one, and a box takes one digit only.

    The broker sends the last ``count`` digits sealed to this isolated script
    and nothing else. The script writes only the pinned box's digit, and first
    refuses when a disabled or read-only box of the group shows a digit that
    differs from the saved digit at its place: the page then asks about
    another number. After the write the page may move the focus to the next
    box, so the focus check no longer applies to the confirmation.
    """
    replacements = (
        ("(selector, field, frameURL, topURL, processor=false, identity=false, purpose=false, allowOff=false, shadowRootOf=null) => {",
         "(selector, field, frameURL, topURL, processor=false, identity=false, purpose=false, allowOff=false, shadowRootOf=null, digit=null) => {"),
        ("  if (!input && !select && !textarea && !aria) return null;\n",
         "  if (!input && !select && !textarea && !aria) return null;\n"
         "  // One single-character box among the boxes for the last digits of a phone number.\n"
         "  const box = n => n instanceof HTMLInputElement && ['text','tel','number'].includes(n.type) &&\n"
         "    n.maxLength === 1 && n.getRootNode() === doc;\n"
         "  function digitBoxes() {\n"
         "    let node = el.parentElement;\n"
         "    for (let i = 0; node && i < 8; ++i, node = node.parentElement) {\n"
         "      const boxes = Array.from(node.querySelectorAll('input')).filter(box);\n"
         "      if (boxes.length > 1) return boxes;\n"
         "    }\n"
         "    return null;\n"
         "  }\n"
         "  function digitPlace() {\n"
         "    const boxes = box(el) ? digitBoxes() : null;\n"
         "    return boxes !== null && boxes.length === digit.count && boxes[digit.index] === el;\n"
         "  }\n"
         "  if (!identity || field !== 'tel' || purpose !== false || digit === null || typeof digit !== 'object' ||\n"
         "      !Number.isInteger(digit.index) || !Number.isInteger(digit.count) ||\n"
         "      digit.count < __MIN_BOXES__ || digit.count > __MAX_BOXES__ || digit.index < 0 || digit.index >= digit.count ||\n"
         "      !digitPlace()) return null;\n"
         "  let digitWritten = false;\n"
         "  // The saved number's last digits arrive together; only the pinned box's digit is\n"
         "  // written. A disabled or read-only box that shows a digit must show the saved\n"
         "  // digit at its place, or the page asks about another number.\n"
         "  function digitOf(value) {\n"
         "    if (typeof value !== 'string' || value.length !== digit.count || !/^[0-9]+$/.test(value)) return null;\n"
         "    const boxes = digitBoxes();\n"
         "    if (boxes === null || boxes.length !== digit.count || boxes[digit.index] !== el) return null;\n"
         "    for (let i = 0; i < boxes.length; ++i) {\n"
         "      const other = boxes[i];\n"
         "      if (other === el || !(other.disabled || other.matches(':disabled') || other.readOnly)) continue;\n"
         "      const shown = getter.call(other).trim();\n"
         "      if (/^[0-9]$/.test(shown) && shown !== value[i]) return null;\n"
         "    }\n"
         "    return value[digit.index];\n"
         "  }\n"),
        ("  if (identity && !attested) {", "  if (identity && !attested && !digit) {"),
        ("    if (input && !(type === 'text' || type === 'email' && field === 'email' ||",
         "    if (!digit && input && !(type === 'text' || type === 'email' && field === 'email' ||"),
        ("        (aria && ariaList() !== listId) ||\n",
         "        (aria && ariaList() !== listId) ||\n        !digitPlace() ||\n"),
        ("    if (identity && (!doc.hasFocus() || doc.activeElement !== el || (select && el.multiple))) return false;",
         "    if (identity && !digitWritten && (!doc.hasFocus() || doc.activeElement !== el || (select && el.multiple))) return false;"),
        ("    if ((input || textarea) && el.maxLength >= 0 && value.length > el.maxLength) return 'refused';",
         "    value = digitOf(value);\n"
         "    if (value === null) return 'refused';\n"
         "    if ((input || textarea) && el.maxLength >= 0 && value.length > el.maxLength) return 'refused';"),
        ("      setter.call(el, actual);\n    }\n", "      setter.call(el, actual);\n    }\n    digitWritten = true;\n"),
    )
    for old, new in replacements:
        if script.count(old) != 1:
            raise RuntimeError('card pin script changed; update browser_identity')
        script = script.replace(old, new)
    return script.replace('__MIN_BOXES__', str(PHONE_DIGIT_BOXES[0])).replace('__MAX_BOXES__', str(PHONE_DIGIT_BOXES[1]))


DIGIT_PIN_SCRIPT = _digit_pin(PIN_SCRIPT)


def digit_spec(request):
    """``(index, count)`` of a phone-digit identity pin, or None for an ordinary pin.

    ``phone_digit`` N (from 1) and ``of_last`` M come together, as plain
    integers, with ``field`` ``tel``, M within PHONE_DIGIT_BOXES and N at most
    M. A field purpose does not combine with them: the box rules replace the
    autocomplete rules.
    """
    keys = {'phone_digit', 'of_last'} & set(request)
    if not keys:
        return None
    digit, count = request.get('phone_digit'), request.get('of_last')
    low, high = PHONE_DIGIT_BOXES
    if (keys != {'phone_digit', 'of_last'} or type(digit) is not int or type(count) is not int
            or not low <= count <= high or not 1 <= digit <= count or request.get('field') != 'tel'
            or {'field_purpose', 'allow_autocomplete_off'} & set(request)):
        raise CardTargetError()
    return digit - 1, count


class BrowserIdentities(BrowserCards):
    kind = 'identity'
    delivery = DELIVERY
    fields = FILL_FIELDS

    def _pin_variant(self, request):
        digit = digit_spec(request)
        if digit is None:
            return super()._pin_variant(request)
        return {'phone_digit', 'of_last'}, DIGIT_PIN_SCRIPT, (None, dict(index=digit[0], count=digit[1]))

    def capabilities(self):
        return dict(identity_protocol=1, identity_browser_configured=self.configured,
                    **self._receipt())
