"""Phone verification texts: receive SMS codes and fill them without showing them.

A *source* is one phone number that forwards its texts to the broker: the
user's own phone (an iOS Shortcuts automation, ``shortcut``), a virtual number
(``twilio``), or any other service that can POST (``webhook``). Each source
has its own 256-bit webhook token. The broker keeps only the SHA-256 of a
token, in one private state file; the token itself appears only in the
private setup page or is typed straight into a pinned field.

An incoming text is reduced at once to a masked preview (plain words only: no
digits, no links, "[code]" where the chosen code stands) and one verification
code. A text without one unambiguous code is dropped and never kept. Codes
live only in memory, for MESSAGE_TTL seconds, and each can be filled once. No
command returns a code, a token or a message body.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path

PROTOCOL = 1
KINDS = ('shortcut', 'twilio', 'webhook')
MESSAGE_TTL = 600
SETUP_TTL = 3600  # one hour: setting up the iPhone automation takes a while
MAX_MESSAGES = 32
MAX_SOURCES = 16
MAX_WAIT = 300
MAX_WAITERS = 4
# Per source: more texts than this in one minute are refused (HTTP 429).
RATE_LIMIT = 20
MAX_TEXT = 2048
MAX_SENDER = 64
MAX_PREVIEW = 160
# 32 rows must fit one 64 KiB RPC reply, and JSON escapes a character outside
# the BMP as 12 bytes: preview and sender are also bounded in encoded bytes.
PREVIEW_BYTES = 960
SENDER_BYTES = 320
ROUTE_IN = '/sms/in/'
ROUTE_SETUP = '/sms/setup'
ROUTE_SETUP_WAIT = '/sms/setup/wait'
# Why the last text was kept or dropped; never text content.
RESULTS = ('code', 'empty', 'no-code-word', 'no-code', 'several-codes')
NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,31}')
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}')
MESSAGE_ID = re.compile(r'[0-9a-f]{32}')
STATE_LIMIT = 64 * 1024

class SmsError(Exception):
    """A refused SMS request; the message is safe to return."""


def capabilities(configured: int) -> dict:
    return dict(sms_protocol=PROTOCOL, sms_source_kinds=list(KINDS), sms_sources_configured=configured,
                sms_message_ttl=MESSAGE_TTL)


# Words that mark a verification text, in the languages most services use.
KEYWORDS = re.compile(
    r'code|codice|c[oó]digo|kod|otp|pin\b|passcode|password|verif|confirm|'
    r'authenticat|sign[ -]?in|log[ -]?in|one[ -]time|security|2fa|token|'
    r'best[äa]tigung|verifica|v[ée]rification|pr[üu]f|\b(?:m|sms-?|push|chip|photo)tan\b', re.IGNORECASE)

# Reading a text ------------------------------------------------------------
#
# One reader serves the code choice and the preview, so the two can never
# disagree about what a word is. It keeps no list of link forms and no list of
# things that are not a code (card, reference, year, ZIP, currency). It works
# the other way round, from what is known to be safe:
#
# * A WORD is what stands between spaces and line breaks; no link, in any
#   notation, can cross a space. The preview shows a word only when it is
#   PLAIN: letters only, with ordinary punctuation at its ends, and nothing
#   else in its spaced word (a tab, an odd space or a pictograph does not cut
#   a link). A number shows as bullets, the chosen code as "[code]", every
#   other word as a placeholder. A link is hidden because it is not a plain
#   word, not because it was recognised as a link.
# * A CANDIDATE is a number written the way codes are written: one group of 4
#   to 8 digits, or 3+3 / 4+4, alone in its word or glued to one word
#   ("Code:482913", "G-482913"). A text whose only candidate it is gives that
#   code. With several candidates the broker does not judge which numbers are
#   not codes. One of them must stand in a STRICT label position ("code is N",
#   "N is your ... code", "Use N to", "Your code for ... is N") and no other may
#   stand in any label position, however loose. Everything else is dropped.
# * A label's VALUE POSITION holds the code. When it holds something else that
#   is not known to be ordinary (a word such as "HXKQWP", "AB12CD", "123",
#   "12 34 56"), the text has a code that the broker cannot type: the text is
#   dropped, and that word is never shown.
# * Every word list below is an allow-list. A wording it lacks costs one
#   dropped text or one hidden word. It cannot make the broker choose a number
#   or show a word.

_OPEN = '([{<"\'“‘«¿¡【（「『《〈'
_CLOSE = '.,;:!?)]}>"\'”’»。，！？：；、】）」』》〉'
_JOIN = "-‐'’&"                 # inside a plain word: one-time, don't, H&M
_STOP = '.!?;|。！？；'           # ends a sentence
_END = _STOP + ',，、'           # ends a clause
_LINK = '/@?=&%\\'
_DIGITS = '0123456789'
_CUTS = frozenset(map(chr, (0x09, 0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x1F, 0x85)))  # a tab and other gaps inside a word
_OVERRIDES = (chr(0x202D), chr(0x202E))                                       # they reverse what a screen shows
MAX_WORD = 40                   # a longer "word" is not shown
MAX_LETTERS = 24                # nor is one with a longer run of letters
MAX_CLAUSE = 40                 # "Your code for ... is N" spans at most this many words
_o, _c, _j = (re.escape(s) for s in (_OPEN, _CLOSE, _JOIN))
# Patterns over a word's SHAPE: L letter, M mark, 0 digit, 9 other numeral,
# and each punctuation character as itself.
_W = 'L[LM]*'
_G = '[^LM09]'
_PLAIN = re.compile(f'([{_o}]*)({_W}(?:[{_j}]{_W})*)([{_c}]*)')
# One digit group, or two joined by a hyphen, with at most one word glued to each side:
# "482913", "(482913)", "G-482913", "Code:482913", "OTP482913", "482913.Do", "5512-9983".
_BARE = re.compile(f'(?:([{_o}]*)({_W})({_G}{{0,3}})|({_G}*))(0+)(?:-(0+))?(?:({_G}{{1,3}})({_W})([{_c}]*)|({_G}*))')
_NUMERIC = re.compile('[^LM9]*0[^LM9]*')
_SYMBOLIC = re.compile('[^LM09]+')
_LINKISH = re.compile(f'[{re.escape(_LINK)}]|[LM09][.:#][LM09]')
_GLUED = re.compile(f'[{_o}]*({_W})[.!?;,]({_W})([{_c}]*)')  # "out.Use": a full stop without its space
_ALONE = re.compile('(?<![LM09])0{4,8}(?![LM09])')  # a code-sized digit group that stands free inside a word
_PHONE = re.compile(r'\+?[0-9]+(?:-[0-9]+)*')  # a number that can run on into the next word
_SPAN = re.compile('[0-9]{1,3}(?:min|mins|m|h|hr|hrs|s|sec|secs|d|std)')  # "10min": a time, not a code

# Label words, case-folded. Every list is an allow-list.
_SELF = frozenset('otp passcode mtan pushtan chiptan phototan'.split())  # a code whatever stands before it ("TAN" too)
_CODE = frozenset('code codes código codigo codice kod kode kód cod код'.split())  # a code unless modified
_WEAK = frozenset('password pin passwort kennwort contraseña senha clave token passphrase wachtwoord'.split())
_PHRASED = _WEAK - {'pin', 'token'}                                    # their value can be several words
_COMPOUND = ('code', 'kode', 'kod', 'passwort', 'kennwort', 'tan')   # Bestätigungscode, Einmalpasswort, smsTAN
_STRONG = ('verif', 'vérif', 'authenti', 'autenti', 'authori', 'autori', 'secur', 'sécur', 'segur', 'sicher',
           'sicur', 'säkerhet', 'sikker', 'beveilig', 'login', 'log-in', 'logon', 'signin', 'sign-in', 'anmeld',
           'inlog', 'connexion', 'one-time', 'onetime', 'single-use', 'einmal', 'engång', 'engang', 'two-factor',
           'two-step', 'confirm', 'bestätig', 'bestaetig', 'bevestig', 'conferm', 'bekræft', 'bekreft', 'access',
           'acces', 'accès', 'zugang', 'activat', 'activación', 'aktivier', 'freischalt', 'validat', 'approv',
           'identif', 'registr', 'reset', 'recovery', 'temporary', 'unique', 'único', 'unico', 'prüf', 'sms',
           'otp', 'passcode', '2fa', '2sv', '2-step', '2-factor', '3ds', '3d', '3-d')
_STRONG_MIXED = frozenset({'2fa', '2sv', '2-step', '2-factor', '3ds', '3d', '3-d'})  # not plain words, still read
_STRONG_PAIRS = frozenset({('one', 'time'), ('single', 'use'), ('two', 'factor'), ('two', 'step'), ('log', 'in'),
                           ('sign', 'in')})
_FUNCTION = frozenset(
    'a an the this that these your my our its is are was be as at by for from in of on or and to via with use using '
    'enter type input please here new following below above current latest '
    'der die das den dem des ein eine einen ihr ihre ihren dein deine deinen mit und oder ist lautet bitte neuer '
    'neue hier für zum zur el la los las un una tu su este esta con y o es para de le les une votre ton ce cet '
    'cette avec et ou est pour du il lo tuo suo questo e è per di um uma seu sua com é do da het een uw je jouw '
    'met en of voor'.split())
_COPULA = frozenset('is was are be ist war lautet es est è é er är jest'.split())
_IMPERATIVE = frozenset(
    'use enter type input submit insert provide verwenden verwende nutze nutzen benutze benutzen usa utiliza '
    'utilice ingresa ingrese introduce introduzca utilisez utilise saisissez saisis entrez tapez inserisci digita '
    'insira digite utilize gebruik'.split())
_VERIFY = frozenset('verify confirm authenticate approve authorize authorise continue proceed login bestätigen '
                    'bestätige verifizieren verifica confirma vérifiez confirmez'.split())
_WITH = frozenset('with using via mit con avec met'.split())
_PARTICLE = frozenset('to as for in on when if within um zum zur als für para como pour comme per come om'.split())
_OF = frozenset("de di da do du del della des".split())               # "código de verificación"
_AND = frozenset('and or und oder y o et ou e en of'.split())
_BUT = _AND | frozenset('but aber pero mais ma mas maar'.split())
_NEGATION = frozenset('not no never nicht kein keine non ne pas nunca nie'.split())
# "Your code for <phrase> <phrase> is N": each phrase is a preposition, its determiners and one to six other words.
_PREPOSITION = frozenset(
    'for to on of at in with from by via using für zur zum zu mit bei von auf an im am vom beim über para de del con '
    'en por al pour du à au aux avec sur dans chez per di da su della voor met op van bij naar'.split())
_DETERMINER = frozenset(
    'the a an this that these those your my our his her its their der die das den dem des ein eine einen einem einer '
    'ihr ihre ihren ihrem ihrer dein deine mein unser el la los las un una tu su mi este esta le les une votre ton '
    'ce cet cette il lo gli tuo tua suo sua questo questa os as um uma seu teu het een uw je jouw'.split())
# A new clause inside a clause: a conjunction, a subject, a verb form, a negation.
_BREAK = frozenset(
    'and or but nor so if then because while when where that which who whose what why how it they we you i he she '
    'is are was were be been will would can could may might must shall should has have had does do did not no never '
    'und oder aber wenn weil dass ob ist sind war wird wurde kann muss nicht kein y o pero si cuando que porque es '
    'son está et ou mais quand est sont ne pas e ma se quando che è sono non mas é são não of maar als dat zijn '
    'niet'.split())
# Numbers in three known places are not codes: "Reply STOP to 89203", "(c) 2026", "Expires at 1845".
_OPTOUT = frozenset('stop help end quit cancel unsubscribe stopall info baja alto ayuda arret arrêt aide'.split())
_TO = frozenset('to an au al a'.split())
_EXPIRY = frozenset('expires expire expiring expired valid gültig caduca expira vence scade verloopt'.split())
_UNTIL = frozenset('at until till by um bis'.split())
# A small number before one of these is a time or a size, not a code: "valid 10 minutes", "6 digits".
_UNITS = frozenset(
    'minutes minute min mins hours hour hrs hr seconds second secs sec days day digits digit characters chars '
    'minuten stunden stunde sekunden tage tag ziffern stellen minutos minuto horas hora segundos días día dígitos '
    'heures heure secondes jours jour chiffres minuti ore ora secondi giorni cifre dias uur uren seconden dagen '
    'cijfers times attempts mal veces fois volte vezes keer'.split())
# Ordinary words: what a text says next to a code noun when it does not give the code there. First the closed
# classes (articles, pronouns, prepositions, conjunctions, auxiliaries, common adverbs), then what texts say
# about a code ("valid", "expires", "share"), then the few of those that also follow "password is".
_CLOSED = frozenset('''
a an the this that these those my your yours his her hers its our ours their theirs me you him us them i we he she it
they myself yourself itself themselves someone anyone everyone nobody anybody everybody something anything everything
nothing is are was were be been being am do does did done doing have has had having will would shall should can could
may might must isn't aren't wasn't weren't don't doesn't didn't won't wouldn't can't cannot couldn't shouldn't hasn't
haven't it's that's you're we're we'll you'll i'm let's not no never none neither nor and or but if then else so
because as while when where whether than though although unless until till since once before after of in on at by for
from to into onto with without within via per over under above below between among across around about against
through during toward towards upon off out up down near here there now today tonight tomorrow soon later again always
already also just only even still yet too very much more most less least quite really ever often anywhere anytime
all any both each every few many some several other others another such same own next last first second new old
please thanks thank hello hi hey dear sorry yes ok okay who whom whose which what why how one two three four five six
seven eight nine ten fifteen twenty thirty sixty
der die das den dem des ein eine einen einem einer eines ihr ihre ihren ihrem ihrer dein deine deinen mein meine
unser unsere euer sie er wir ich du man sich ihnen uns dich dir mich mir ist sind war waren sein wird werden wurde
wurden hat haben hatte kann können konnte muss müssen soll sollen darf dürfen will wollen lautet nicht kein keine
keinen keinem nie niemals niemand niemandem niemanden nichts und oder aber wenn dann weil als wie dass ob falls bis
seit bevor nachdem sobald von auf bei für mit ohne nach zu zum zur aus über unter vor hinter zwischen durch gegen um
innerhalb im am vom beim hier dort jetzt heute bald später wieder immer schon auch nur noch sehr mehr bitte danke
hallo ab
el la los las un una unos unas tu su mi sus tus nuestro este esta estos estas ese esa esto eso yo tú usted él ella
nosotros se lo le te nos es son era fue ser está están estar ha han hay puede pueden debe deben será nunca nadie nada
ni y o pero si cuando porque como que mientras hasta desde antes después de en al del con sin para por sobre entre
hacia durante aquí ahora hoy pronto siempre ya también solo sólo muy más favor gracias hola
les une des ton ta tes votre vos mon ma notre ce cet cette ces je il elle nous vous ils elles est sont était sera
être ont peut peuvent doit doivent ne pas jamais personne rien et ou mais quand parce comme pendant jusqu depuis
avant après du à au aux dans sur sous avec sans pour par chez vers ici maintenant bientôt toujours déjà aussi
seulement très plus merci bonjour
i gli uno tuo tua suo sua mio nostro questo questa io lei lui noi voi è sono sarà essere hanno può possono deve
devono non mai nessuno niente né e ma se perché che mentre fino da prima dopo di su tra fra senza qui ora oggi presto
sempre già anche molto più grazie ciao
os as um uma seu teu meu nosso isso isto eu você ele nós são estão tem têm pode podem devem não ninguém nem mas
enquanto até depois em do no na com sem aqui agora hoje só muito mais obrigado olá
het een uw je jouw mijn onze dit dat deze ik u hij zij wij ze zijn wordt worden heeft hebben kunnen moet moeten zal
niet geen nooit niets of maar dan omdat tot sinds voor na van op aan met zonder naar uit onder tussen door om binnen
nu vandaag altijd al ook alleen nog zeer meer bedankt like unlike
'''.split()) | _FUNCTION | _COPULA | _PREPOSITION | _DETERMINER | _BREAK | _AND | _NEGATION | _PARTICLE | _WITH | _OF
_SAID = frozenset('''
valid invalid required needed necessary ready expired incorrect wrong correct right confidential secret private
personal unique safe secure important sensitive active inactive available unavailable usable used unused sent
generated requested entered provided received shown displayed listed given attached enclosed following follows
temporary permanent single multiple good bad free true false different able unable sure certain long short case
strictly highly absolutely completely currently immediately automatically shortly directly successfully securely
publicly online verification verified security login access confirmation authentication authorization time
expire share give tell disclose reveal provide send receive request get take make need want keep ignore delete call
contact reply text message verify confirm sign log continue complete finish reset change update create set add
remove check try see look come go work last remain stay arrive help allow let protect authorize authorise
authenticate unlock open link connect activate deactivate register apply approve decline deny cancel stop start begin
end wait return show display appear contain include follow visit click tap press scan copy paste forward ask answer
know think believe find read write save store pay charge transfer withdraw deposit book order ship deliver pick
collect redeem claim join leave unsubscribe subscribe enter type input submit insert use
gültig ungültig erforderlich nötig abgelaufen falsch richtig geheim vertraulich persönlich einmalig sicher wichtig
aktiv läuft verfällt gilt weitergeben teilen eingeben verwenden nutzen benutzen senden erhalten bestätigen anmelden
lang válido inválido requerido necesario caducado incorrecto correcto confidencial secreto único seguro importante
caduca vence expira compartas compartir comparta ingresa usa utiliza valable valide invalide requis nécessaire
expiré confidentiel personnel sûr partagez partager utilisez saisissez valido invalido richiesto necessario scaduto
errato corretto riservato segreto personale unico sicuro scade condividere obrigatório necessário expirado incorreto
correto pessoal compartilhe compartilhar insira digite geldig ongeldig vereist nodig verlopen onjuist juist
vertrouwelijk persoonlijk uniek veilig belangrijk verloopt deel delen gebruik voer
'''.split())
_SAID_OF_SECRET = frozenset(
    'valid invalid required needed expired expire expires expiring incorrect wrong changed reset updated set used '
    'entered shared safe secure confidential secret private personal temporary strictly case sensitive gültig '
    'ungültig erforderlich abgelaufen falsch geheim vertraulich confidencial secreto confidentiel riservato segreto '
    'vertrouwelijk'.split()) | _UNITS


@dataclass
class _Word:
    kind: str              # 'plain', 'punct', 'bare', 'number' or 'hidden'
    text: str              # cleaned characters; shown only through ``shown``
    shown: str             # what the preview shows when the word is not the code
    core: str = ''         # plain: its letters, case-folded
    front: str = ''        # bare: punctuation before the digits, or between "Code" and the digits
    lead: str = ''         # bare: "Code" in "Code:482913"
    groups: tuple = ()     # bare: its one or two digit groups
    close: str = ''        # bare: punctuation after the digits
    trail: str = ''        # bare: "Do" in "482913.Do"
    after: str = ''        # punctuation at the end of the word
    digits: bool = False   # holds a numeral
    doubt: str = ''        # set on a number that may be a code the broker cannot read: it is never chosen
    value: str = ''        # a candidate's digits (on its first word)
    part: bool = False     # the second word of a split candidate


@dataclass(frozen=True)
class Reading:
    code: str | None       # the one verification code, or None
    result: str            # one of RESULTS; never text content
    preview: str           # safe to show the agent


def _clean(raw: str) -> list[tuple[str, bool]]:
    """One spaced word, NFKC, cut at tabs, odd spaces and pictographs; invisible characters removed, never made gaps.

    Each part has a flag: an invisible character stood between two digits, or the word holds a direction
    override. A number in such a part may not read on a screen as its characters say.
    """
    override = any(mark in raw for mark in _OVERRIDES)
    parts, part, odd, gap = [], [], False, False
    for ch in unicodedata.normalize('NFKC', raw):
        category = unicodedata.category(ch)
        if category[0] == 'Z' or category in {'So', 'Sk'} or ch in _CUTS:
            if part:
                parts.append((''.join(part), odd or override))
            part, odd, gap = [], False, False
        elif category[0] == 'C':
            gap = bool(part) and part[-1] in _DIGITS
        else:
            odd, gap = odd or gap and ch in _DIGITS, False
            part.append(ch)
    if part:
        parts.append((''.join(part), odd or override))
    return parts


def _shape(text: str) -> str:
    out = []
    for ch in text:
        category = unicodedata.category(ch)
        if category[0] in 'LM':
            out.append(category[0])
        elif ch in _DIGITS:
            out.append('0')
        elif category[0] == 'N':
            out.append('9')
        else:
            out.append(ch)  # punctuation, a currency sign or a mathematical sign
    return ''.join(out)


def _hidden(text: str, shape: str) -> _Word:
    """A word the preview never shows. Its digits are no candidate; if they may be a code, the word is in doubt."""
    # One free code-sized group and no link sign ("active.G-482913", a missing space): it may be the code.
    alone = len(re.findall('0+', shape)) == 1 and _ALONE.search(shape) and not any(ch in _LINK for ch in shape)
    doubt = '9' in shape or '0M' in shape or alone
    return _Word('hidden', text, '[link]' if _LINKISH.search(shape) else '[hidden]',
                 digits='0' in shape or '9' in shape, after=text[-1] if shape[-1] in _CLOSE else '',
                 doubt='no-code' if doubt else '')


def _classify(text: str) -> _Word:
    shape = _shape(text)
    if len(text) > MAX_WORD:
        return _hidden(text, shape)
    match = _PLAIN.fullmatch(shape)
    if match:
        letters = text[match.start(2):match.end(2)]
        if max(len(run) for run in re.split(f'[{_j}]', letters)) > MAX_LETTERS:
            return _hidden(text, shape)
        return _Word('plain', text, text, core=letters.casefold().replace('‐', '-').replace('’', "'"),
                     after=match.group(3))
    if _SYMBOLIC.fullmatch(shape):
        return _Word('punct', text, text, after=text)
    bullets = ''.join('•' if c in '09' else text[i] for i, c in enumerate(shape))
    match = _BARE.fullmatch(shape)
    if match:
        lead, glue, a, b, trail = (text[match.start(n):match.end(n)] if match.group(n) else ''
                                   for n in (2, 3, 5, 6, 8))
        before, close = match.group(4) or '', match.group(7) or match.group(10) or ''
        if lead and _tier(lead.casefold()) is None and (not glue or glue in '-‐' and len(lead) > 3):
            # "Visa1234", "INR2500", "ABCD-482913": only a code noun may touch its number ("OTP482913"), and
            # only a short prefix may take a hyphen ("G-482913").
            return _hidden(text, shape)
        if not lead and not trail and (before.endswith('+') or '%' in close or any(
                unicodedata.category(ch) == 'Sc' for ch in before + close)):
            return _Word('number', text, bullets, digits=True, after=close)  # a phone number or an amount by its sign
        shown = '•' * len(a) + ('-' + '•' * len(b) if b else '') if lead or trail else bullets
        return _Word('bare', text, shown, front=glue or before, lead=lead.casefold(), groups=(a, b) if b else (a,),
                     close=close, trail=trail.casefold(), after=match.group(9) or '' if trail else close, digits=True)
    if '9' in shape and 'L' not in shape and 'M' not in shape:
        return _Word('number', text, bullets, digits=True, doubt='no-code')  # numerals the broker does not type
    if _NUMERIC.fullmatch(shape):
        return _Word('number', text, bullets, digits=True, after=text[-1] if shape[-1] in _CLOSE else '')
    return _hidden(text, shape)


def _words(text: str) -> list[list[_Word]]:
    """The text as lines of words.

    Only a space ends a spaced word. A tab, an odd space or a pictograph inside it cuts it into parts, which
    are read one by one; but its plain parts show only when every part is plain. So nothing glued to a link, a
    number or loose punctuation is ever shown. A link can also run on across a line break (programs that open
    links drop tabs and line breaks), so the word that starts the line after a link is not shown.
    """
    lines = []
    for line in re.split(r'[\n\r]+', text):
        words = []
        for raw in line.split(' '):
            parts = []
            for part, odd in _clean(raw):
                parts.append(_classify(part))
                if odd and parts[-1].digits:
                    parts[-1].doubt = 'no-code'
            if len(parts) > 1 and any(part.kind == 'hidden' for part in parts):
                joined = ''.join(part.text for part in parts)
                link = any(part.shown == '[link]' for part in parts)
                number = any(part.kind in {'bare', 'number'} or part.doubt for part in parts)
                parts = [_Word('hidden', joined, '[link]' if link else '[hidden]', after=parts[-1].after,
                               digits=any(part.digits for part in parts), doubt='no-code' if number else '')]
            elif len(parts) > 1 and not all(part.kind == 'plain' for part in parts):
                for part in parts:
                    if part.kind == 'plain':
                        part.shown = '[hidden]'
            words.extend(parts)
        if words:
            lines.append(words)
    runs_on = False
    for upper, lower in zip(lines, lines[1:]):
        # After a link, or a link sign, at the end of a line; and on through a line that is one such word.
        last = upper[-1]
        runs_on = (last.shown == '[link]' or last.kind != 'plain' and last.text[-1] in _LINK + '#:'
                   or runs_on and len(upper) == 1 and last.kind == 'plain')
        if runs_on and lower[0].kind == 'plain':
            lower[0].shown = '[hidden]'
    return lines


def _numbers(line: list[_Word]) -> None:
    """Mark the candidates of one line. Digit groups that touch are judged together, never one by one."""
    def joins(word: _Word) -> bool:  # "12.50", "18:30" and "2025-11-24:" are complete in themselves
        return not word.doubt and (word.kind == 'bare' or word.kind == 'number' and _PHONE.fullmatch(word.text))

    index = 0
    while index < len(line):
        run = [line[index]]
        index += 1
        if not joins(run[0]):
            continue
        while (index < len(line) and run[-1].text[-1] in _DIGITS and joins(line[index])
               and line[index].text[0] in _DIGITS):
            run.append(line[index])
            index += 1
        sizes = tuple(len(group) for word in run for group in re.findall('[0-9]+', word.text))
        bare = all(word.kind == 'bare' for word in run)
        if len(run) == 1 and bare and (4 <= sizes[0] <= 8 if len(sizes) == 1 else sizes in {(3, 3), (4, 4)}):
            run[0].value = ''.join(run[0].groups)
        elif len(run) == 2 and bare and sizes == (3, 3):
            run[0].value, run[1].part = run[0].groups[0] + run[1].groups[0], True
        elif len(run) > 1 and '+' not in run[0].text and sum(sizes) <= 8 and max(sizes) >= 4:
            # "1234 5678", "1234 567": one code or two numbers? Not for the broker to guess.
            run[0].doubt = 'several-codes'


def _stream(lines: list[list[_Word]]) -> list[tuple]:
    """The words as label grammar tokens.

    ('w', word) and, for a plain word, the word itself; ('n', word) for a number; ('h', word) for a word the
    broker does not read; (':',) for "Label: N"; ('|', 'stop' / 'comma' / 'line') where a clause ends; ('x',)
    other punctuation.
    """
    out: list[tuple] = []

    def marks(punctuation: str) -> None:
        if ':' in punctuation or '：' in punctuation:
            out.append((':',))
        if any(ch in _END for ch in punctuation):
            out.append(('|', 'stop' if any(ch in _STOP for ch in punctuation) else 'comma'))

    for line in lines:
        for word in line:
            if word.kind == 'plain':
                # "TAN" in capitals is the German code noun; "tan" is a Spanish word.
                out.append(('w', 'mtan' if word.core == 'tan' and word.text.isupper() else word.core, word))
                marks(word.after)
            elif word.kind == 'punct':
                if all(ch in ':-‐–—=>' for ch in word.text):
                    out.append((':',))
                elif any(ch in _END for ch in word.text):
                    out.append(('|', 'stop'))
                else:
                    out.append(('x',))
            elif word.kind == 'bare':
                if word.lead and not (word.value or _tier(word.lead) is not None):
                    pass  # "XK-48": one written word, and no number the broker types
                elif word.lead:
                    out.append(('w', word.lead))
                    if any(ch in _END for ch in word.front):
                        out.append(('|', 'stop'))
                    elif word.front.strip(_OPEN + _CLOSE):
                        out.append((':',))  # "Code:482913", "G-482913", "code=482913"
                else:
                    marks(word.front)
                if not word.part:
                    out.append(('n', word))
                marks(word.close)
                if word.trail:
                    out.append(('w', word.trail))
                    marks(word.after)
            elif word.text.casefold().strip(_OPEN + _CLOSE) in _STRONG_MIXED:
                out.append(('w', word.text.casefold().strip(_OPEN + _CLOSE)))
                marks(word.after)
            elif _GLUED.fullmatch(_shape(word.text)):
                match = _GLUED.fullmatch(_shape(word.text))
                out.extend((('w', word.text[match.start(1):match.end(1)].casefold()), ('|', 'stop'),
                            ('w', word.text[match.start(2):match.end(2)].casefold())))
                marks(match.group(3))
            else:
                out.append(('n' if word.digits else 'h', word))
                marks(word.after)
        out.append(('|', 'line'))
    return out


def _strong(core: str) -> bool:
    return core.startswith(_STRONG)


def _tier(core: str) -> str | None:
    """'self', 'code' or 'weak' for a label noun; None for any other word, "postcode" and "zip-code" included."""
    *modifiers, head = core.split('-')
    tier = 'self' if head in _SELF else 'code' if head in _CODE else 'weak' if head in _WEAK else None
    if tier is None:
        for suffix in _COMPOUND:
            if head.endswith(suffix) and len(head) > len(suffix):
                tier = 'self' if _strong(head[:-len(suffix)]) else None
                break
    if tier is None or not modifiers:
        return tier
    return 'self' if _strong('-'.join(modifiers)) or all(_strong(m) for m in modifiers) else None


def _ordinary(core: str, secret: bool = False) -> bool:
    """A word that texts put next to a code noun without it being the code: "valid", "with", "expires".

    After "password is" (``secret``) only the closed classes and a few words count: a password can be any word.
    """
    parts = [part.strip("'") for part in core.split('-') if part.strip("'")]
    if len(parts) != 1:
        return bool(parts) and all(_ordinary(part, secret) for part in parts)
    core = parts[0]
    if core in _CLOSED or core in _SAID_OF_SECRET:
        return True
    if secret:
        return False
    if core in _SAID or core in _UNITS or _tier(core) is not None:
        return True
    for ending in ('ing', 'ed', 'es', 's', 'd'):  # "expires", "shared", "entering"
        base = core[:-len(ending)]
        if core.endswith(ending) and len(base) > 2 and (
                base in _SAID or base + 'e' in _SAID or base.endswith('i') and base[:-1] + 'y' in _SAID):
            return True
    return False


class _Labels:
    """Where the labels of a token stream point.

    A label is a code noun with what goes with it ("Your Google verification code is", "OTP:"), or an order
    ("Use ... to", "verify with ..."). ``slot`` tells whether a token stands in a label's value position.

    'strict': the noun is a verification code noun that no unknown word modifies, in a fixed sentence form.
    Only a strict label can select a code among several numbers.

    'named': any code noun or secret noun in the same forms ("ZIP code 90210", "Your PIN is", "Your Lyft code
    is"). What stands in such a position is taken for the code that the text gives.

    'loose': also a code noun anywhere before "is N" in the clause, a verification word or an unreadable word
    right before the number, a number listed after another number and a number alone in its sentence. A named
    or loose label never selects a code. It stops another number from being selected.
    """

    def __init__(self, stream: list[tuple], mode: str = 'strict') -> None:
        self.stream, self.mode = stream, mode

    def token(self, i: int) -> tuple:
        return self.stream[i] if 0 <= i < len(self.stream) else ('|', 'line')

    def kind(self, i: int) -> str:
        return self.token(i)[0]

    def word(self, i: int) -> str:
        return self.token(i)[1] if self.kind(i) == 'w' else ''

    def rival(self, i: int) -> bool:
        """Token ``i`` is a candidate or a number in doubt."""
        return self.kind(i) == 'n' and bool(self.token(i)[1].value or self.token(i)[1].doubt)

    def edge(self, i: int) -> bool:
        """Token ``i`` ends a sentence or a line (or the text)."""
        return self.token(i) in (('|', 'stop'), ('|', 'line'))

    def end(self, p: int) -> int:
        """The token that ends the sentence of token ``p``."""
        while not self.edge(p):
            p += 1
        return p

    def back(self, i: int) -> int:
        """The token before ``i``. A line break or a comma is no new start: "postal" still modifies "code"."""
        return i - 2 if self.token(i - 1) in (('|', 'line'), ('|', 'comma')) else i - 1

    def stage(self, i: int) -> int:
        """0 for a function word, 2 for a verification word, 1 for any other word (a name)."""
        word = self.word(i)
        if _strong(word) or (word, self.word(i + 1)) in _STRONG_PAIRS or (self.word(i - 1), word) in _STRONG_PAIRS:
            return 2
        return 0 if word in _FUNCTION else 1

    def strong_before(self, i: int) -> bool:
        """A verification word right before token ``i`` ("verification", "one time")."""
        j = self.back(i)
        return self.kind(j) == 'w' and (_strong(self.word(j)) or _tier(self.word(j)) == 'self'
                                        or (self.word(self.back(j)), self.word(j)) in _STRONG_PAIRS)

    def noun(self, i: int) -> bool:
        """Token ``i`` is a label noun; in strict mode one that an unknown word does not modify ("ZIP code")."""
        tier = _tier(self.word(i))
        if tier is None:
            return False
        if self.mode != 'strict' or tier == 'self' or self.strong_before(i):
            return True
        j = self.back(i)
        return tier == 'code' and (self.kind(j) in '|:' or self.word(j) in _FUNCTION)

    def phrase(self, i: int) -> int:
        """The last token of the noun phrase that starts with noun ``i`` ("código de verificación")."""
        if self.word(i + 1) in _OF and _strong(self.word(i + 2)):
            return i + 2
        return i

    def head(self, i: int) -> int:
        """The noun of the label phrase that ends at token ``i``, or -1."""
        if self.noun(i):
            return i
        if _strong(self.word(i)) and self.word(i - 1) in _OF and _tier(self.word(i - 2)) is not None:
            return i - 2
        if self.mode != 'strict' and self.named(i):
            return i - 1  # "Votre code Example est 482913": the name stands after the noun
        return i if self.mode == 'loose' and _strong(self.word(i)) else -1  # "Verification: 482913"

    def named(self, i: int) -> bool:
        """Token ``i`` is one unknown word right after a label noun, such as a service name."""
        return (self.kind(i) == 'w' and not _ordinary(self.word(i)) and _tier(self.word(i - 1)) is not None
                and self.stage(i) == 1)

    def before(self, p: int) -> tuple | None:
        """("weak" or "strong", noun) when a label ends right before token ``p``.

        Weak: "code 482913". Strong: "code is 482913", "code: 482913", and the same with the value on the next
        line. Ordinary words can stand between the noun and the colon or "is": "code is in this message: 482913",
        "the code you requested is 482913".
        """
        i, strong, colon = p - 1, False, False
        if i > 0 and self.token(i) == ('|', 'line') and (self.kind(i - 1) == ':' or self.word(i - 1) in _COPULA):
            i -= 1  # "Your code is:" and the code on the next line
        if self.kind(i) == ':':
            i, strong, colon = i - 1, True, True
        if self.mode == 'loose' and (self.kind(i) == 'h' or self.rival(i) or self.rival(i - 1) and (
                self.word(i) in _AND or self.token(i) == ('|', 'comma'))):
            return 'weak', -1  # after a word the broker cannot read, or listed after another possible code
        if colon and self.mode == 'named' and _strong(self.word(i)) and self.head(i) < 0:
            return 'strong', i  # "Verification: HXKQWP": a verification word and a colon make a label
        reach, far, name = 0, 6, self.mode != 'strict'  # outside strict mode one unknown word may stand between
        if not colon and self.word(i) in _COPULA:
            i, strong, far = i - 1, True, 3
        while strong and reach < far and self.kind(i) == 'w' and self.head(i) < 0 and (
                _ordinary(self.word(i)) or name) and (colon or self.word(i) not in _BUT):
            i, reach, name = i - 1, reach + 1, name and _ordinary(self.word(i))
        noun = self.head(i)
        return ('strong' if strong else 'weak', noun) if noun >= 0 else None

    def direct(self, p: int) -> bool:
        """Token ``p`` stands right after "<label> is" or "<label>:", with no word between."""
        i = p - 1 - (self.kind(p - 1) == ':')
        return i < p - 1 and self.head(i - (self.word(i) in _COPULA)) >= 0 or (
            self.word(p - 1) in _COPULA and self.head(p - 2) >= 0)

    def after(self, p: int) -> int:
        """The noun when token ``p`` is the subject of "... is your Google verification code", else -1.

        Also "482913 - your Example verification code" when the noun ends the sentence.
        """
        dash = self.kind(p + 1) == ':' and self.mode != 'loose'
        if self.word(p + 1) not in _COPULA and not dash:
            return -1
        stage = 0  # the words up to the noun, in this order: function words, one name, verification words
        for i in range(p + 2, p + 8):
            word = self.word(i)
            if self.kind(i) != 'w' or word in _NEGATION:
                return -1
            if _tier(word) is not None and not (_strong(word) and _tier(self.word(i + 1)) is not None):
                if self.mode == 'loose':
                    return i
                rest = self.phrase(i) + 1
                if dash and not (self.edge(rest) and not self.rival(rest + 1)):
                    return -1  # "Example: your code is 482913", "EXAMPLE - your code" and the code on the next line
                return i if self.noun(i) and (self.kind(rest) != 'w' or self.word(rest) in _FUNCTION) else -1
            now = self.stage(i)
            if self.mode != 'loose' and (now < stage or now == stage == 1):
                return -1
            stage = now
        return -1

    def order(self, p: int) -> bool:
        """"Use 482913 to sign in", "Enter 482913.", "Verify with 482913"."""
        first = last = p
        while self.kind(p) == 'n' and self.kind(first - 1) == 'n':
            first -= 1  # "Use 12 34 56 to verify": the order has the whole run of numbers as its object
        while self.kind(p) == 'n' and self.kind(last + 1) == 'n':
            last += 1
        i = first - 2 if self.kind(first - 1) == ':' else first - 1
        if self.word(i) in _IMPERATIVE:
            return self.mode == 'loose' or self.kind(last + 1) == '|' or self.word(last + 1) in _PARTICLE
        return self.word(i) in _WITH and (self.word(i - 1) in _VERIFY
                                          or (self.word(i - 2), self.word(i - 1)) in _STRONG_PAIRS)

    def phrases(self, k: int, end: int) -> bool:
        """Tokens ``k`` to ``end`` are prepositional phrases and nothing else: "for card ending 4321"."""
        if k >= end:
            return False
        while k < end:
            if self.word(k) not in _PREPOSITION:
                return False
            k += 1
            while k < end and self.word(k) in _DETERMINER:
                k += 1
            content = 0
            while k < end and self.word(k) not in _PREPOSITION:
                if self.word(k) in _DETERMINER or self.word(k) in _BREAK or self.word(k) in _UNITS:
                    return False  # "... and your reference is 1234", "expires in five minutes": a new clause
                k, content = k + 1, content + 1
            if not 1 <= content <= 6:
                return False
        return True

    def predicate(self, p: int) -> int:
        """The noun when the clause is "<label> for ... is <p>" ("Your OTP for card ending 4321 is 482913")."""
        i = p - 2 if self.kind(p - 1) == ':' else p - 1
        if self.word(i) not in _COPULA:
            return -1
        start = i
        while self.kind(start - 1) not in '|:':
            start -= 1
            if i - start > MAX_CLAUSE:
                return -1  # no label reaches that far; and the reading time stays linear
        if self.mode == 'loose':
            return next((j for j in range(start, i) if _tier(self.word(j)) is not None), -1)
        stage = 0
        for j in range(start, i):
            word = self.word(j)
            if self.kind(j) != 'w' or word in _NEGATION:
                return -1
            if _tier(word) is not None and not (_strong(word) and _tier(self.word(j + 1)) is not None):
                return j if self.noun(j) and self.phrases(self.phrase(j) + 1, i) else -1
            now = self.stage(j)
            if now < stage or now == stage == 1:
                return -1
            stage = now
        return -1

    def nextline(self, p: int) -> int:
        """The noun when token ``p`` starts a line and the line before it is a label and nothing else."""
        if self.token(p - 1) != ('|', 'line'):
            return -1
        noun = self.head(p - 2)
        k, stage = noun - 1, 2
        while noun >= 0 and self.kind(k) == 'w':
            now = self.stage(k)
            if self.word(k) in _NEGATION or now > stage or now == stage == 1:
                return -1
            k, stage = k - 1, now
        return noun if noun >= 0 and self.kind(k) == '|' else -1

    def slot(self, p: int) -> tuple | None:
        """(form, strength, noun) when token ``p`` stands in a label's value position."""
        found = self.before(p)
        if found:
            return ('before', *found)
        for form in (self.after, self.predicate, self.nextline):
            noun = form(p)
            if noun >= 0:
                return form.__name__, 'strong', noun
        return ('order', 'order', -1) if self.order(p) else None

    def labelled(self, p: int) -> bool:
        """Number ``p`` has a label of this mode."""
        if self.slot(p):
            return True
        # Loose also: the only thing in its sentence, or what "It is ..." gives.
        return self.mode == 'loose' and (self.edge(p - 1) and self.edge(p + 1) or self.anaphor(p))

    def anaphor(self, p: int) -> bool:
        """"It is <p>", in a text that names a code elsewhere."""
        return self.word(p - 1) in _COPULA and self.word(p - 2) == 'it' or self.word(p - 1) == "it's"

    def explained(self, p: int) -> bool:
        """Candidate ``p`` stands in a known place that is not a code's place."""
        value, before, earlier = self.token(p)[1].value, self.word(p - 1), self.word(p - 2)
        if before in _TO and (earlier in _OPTOUT or earlier == 'all' and self.word(p - 3) in _OPTOUT):
            return True  # "Reply STOP to 89203"
        sign = self.token(p - 1)[2].text if len(self.token(p - 1)) == 3 else '(c)'
        if (before == 'copyright' or before == 'c' and sign.casefold() == '(c)') and re.fullmatch(
                '(?:19|20)[0-9]{2}', value):
            return True  # "(c) 2026 Example Ltd"
        return (before in _UNTIL and earlier in _EXPIRY
                and re.fullmatch('(?:[01][0-9]|2[0-3])[0-5][0-9]', value) is not None)  # "Expires at 1845"


def _fit(text: str, characters: int, encoded: int) -> str:
    """``text`` cut to ``characters`` and to ``encoded`` bytes of JSON (ASCII escapes), with an ellipsis."""
    if len(text) <= characters and len(json.dumps(text)) <= encoded:
        return text
    cut = text[:characters - 1]
    while cut and len(json.dumps(cut + '…')) > encoded:
        cut = cut[:-1]
    return cut + '…'


def _preview(lines: list[list[_Word]], code: str | None) -> str:
    shown = []
    for line in lines:
        for word in line:
            if code is not None and word.value == code:
                shown.append('[code]' + word.close)
            elif code is not None and word.part and shown and shown[-1] == '[code]':
                shown[-1] += word.close
            else:
                shown.append(word.shown)
    text = ' '.join(shown)
    at = text.find('[code]')
    if at > MAX_PREVIEW * 2 // 3:  # keep the chosen code and the words around it in a long text
        text = '…' + text[text.rfind(' ', 0, at - MAX_PREVIEW // 2) + 1:]
    return _fit(text, MAX_PREVIEW, PREVIEW_BYTES)


def read(text: object) -> Reading:
    """Read one text once: its verification code, why (one of RESULTS), and its preview.

    The code is None unless the text has a verification word and either one
    candidate number, or one candidate with a strict label and no other number
    in any label position. Two labelled numbers, a labelled number of unclear
    extent ("code is 1234 5678") and an unlabelled code among other numbers
    give None. So does any label, strict or not, whose value position holds
    something the broker cannot type: "code is HXKQWP", "Your Lyft code is
    AB12CD", "PIN is 123", "Use AB12CD to verify", "password is MapleRiver".
    The text is dropped, never guessed.

    The preview holds plain words, bullets, "[code]" where the chosen code
    stands, and placeholders. It never holds a numeral, nor any character of
    a spaced word that is more than letters and ordinary punctuation, nor an
    unknown word in a label's value position.
    """
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
        return Reading(None, 'empty', '')
    try:
        return _read(text)
    except Exception:  # the text is untrusted: a reader fault drops it and shows nothing
        return Reading(None, 'no-code', '')


def _read(text: str) -> Reading:
    lines = _words(text.lstrip(chr(0xFEFF)).replace('©', ' (c) '))
    for line in lines:
        _numbers(line)
    stream = _stream(lines)
    words = [word for line in lines for word in line]
    code, result = _choose(words, stream)
    return Reading(code, result, _preview(lines, code))


def _harmless(labels: _Labels, p: int, strength: str) -> bool:
    """Number ``p`` stands in a value position but is clearly no code: a link, a time span, a menu choice."""
    word = labels.token(p)[1]
    if word.kind == 'hidden':
        link = any(ch in _LINK for ch in word.text) and not labels.direct(p)  # "Your code: https://...": no code
        return link or bool(_SPAN.fullmatch(word.text.casefold().strip(_OPEN + _CLOSE)))
    if word.kind != 'bare' or word.lead or word.trail or len(word.groups) != 1:
        return False
    size = len(word.groups[0])
    return size <= 3 and labels.word(p + 1) in _UNITS or (
        strength == 'order' and size <= 2 and labels.kind(p + 1) != 'n')  # "Enter 1 to confirm"


def _letters(labels: _Labels, p: int, form: str, strength: str, noun: int, lower: bool) -> str:
    """Grade the word in value position ``p``, and hide it unless it is ordinary.

    '' for an ordinary word ("valid", "with"): the label gives no value there. Otherwise the word may be a code
    in letters. 'marked': written as a value ("HXKQWP", "MapleRiver"); the text gives it as the code. 'firm':
    after "is" or a colon ("code is hxkqwp"); only a number with a strict label stands against it. 'soft':
    right after the noun or an order ("code hxkqwp expires"); a number with no label does not stand against it.
    After "password is" a value can be a phrase ("the quick brown fox"), so the first word that is not a function
    word counts.
    """
    secret = strength == 'strong' and noun >= 0 and _tier(labels.word(noun)) == 'weak'
    phrased = secret and labels.word(noun).split('-')[-1] in _PHRASED
    end = labels.end(p)
    for q in range(p, end if phrased else p + 1):
        token = labels.token(q)
        if token[0] == 'h' and not (any(ch in _LINK for ch in token[1].text) and not labels.direct(q)):
            break  # a link after other words is not a code; any other unread word may be one
        if token[0] == 'w' and not _ordinary(token[1], secret):
            break
        if token[0] == 'w' and token[1] not in _CLOSED:
            return ''  # "password is valid ...": the text says something about it and does not give it
    else:
        return ''
    if q == p and token[0] == 'w' and form == 'before':
        k = p + 1 + (labels.word(p + 1) in _COPULA)
        k += labels.kind(k) == ':'
        if labels.rival(k) and (strength == 'weak' or k > p + 1):
            # "Votre code Example est 482913", "OTP HDFC 482913", "Votre code est prêt : 482913": a name or a
            # word that the lists lack, inside the label; the number that follows is the value.
            return ''
    raw = token[2].text if len(token) == 3 else token[1].text if token[0] == 'h' else token[1]
    capitals = raw.isupper() and sum(ch.isalpha() for ch in raw) > 1
    marked = lower and (capitals or form != 'order' and any(ch.isupper() for ch in raw.lstrip(_OPEN)[1:]))
    if q == p and form == 'after' and not marked and labels.kind(p - 1) not in '|:':
        return ''  # "The following number is your code": the end of a longer subject, not a value
    grade = 'marked' if marked else 'firm' if strength == 'strong' else 'soft'
    for k in range(q, q + 1 if grade == 'soft' else end):
        if len(labels.token(k)) == 3:
            labels.token(k)[2].shown = '[hidden]'  # the value may be several words: none of them is shown
    return grade


def _choose(words: list[_Word], stream: list[tuple]) -> tuple[str | None, str]:
    strict, named, loose = (_Labels(stream, mode) for mode in ('strict', 'named', 'loose'))
    lower = any(len(token) == 3 and token[2].text != token[2].text.upper() for token in stream)
    values: set = set()      # each different number that could be the code
    selected: set = set()    # those with a strict label
    claimed: set = set()     # those with any label
    grades: set = set()      # what stands in value positions and is not a number the broker can type
    late: set = set()        # grades that count only when no number has a strict label
    # Nouns that already give a number ("123456 is your Facebook code"): a word right after such a noun is an
    # app hash or a signature ("... code H29Q+Fsn4Sr"), not the code's value.
    giving = {noun for p, token in enumerate(stream) if token[0] == 'n' and token[1].value
              for labels in (named, loose) for noun in (labels.after(p), labels.predicate(p)) if noun >= 0}
    for p, token in enumerate(stream):
        kind = token[0]
        if kind not in 'nwh':
            continue
        where = named.slot(p)
        if where and kind != 'n' or where and not token[1].value:
            if where[0] == 'before' and where[2] in giving:
                where = None
            elif where[0] == 'nextline' and named.kind(p - 2) != ':' and named.word(p - 2) not in _COPULA:
                # "Enter this code\nExample" after a labelled code: a signature line, unless no number is labelled.
                # "Your code:\nHXKQWP" (a colon or "is" before the line break) is a value and is graded at once.
                late.add(_letters(named, p, *where, lower) if kind != 'n' else 'marked')
                continue
        if kind == 'n' and (token[1].value or token[1].doubt):
            claim = bool(where) or loose.labelled(p)
            if not claim and token[1].value and named.explained(p):
                continue  # an opt-out number, a copyright year, an expiry time
            # A number in doubt ("1234 5678", foreign numerals) competes like a candidate but can never be chosen.
            value = token[1].value or id(token[1])
            values.add(value)
            if strict.slot(p):
                selected.add(value)
            if claim:
                claimed.add(value)
        elif kind == 'n':
            # "code is AB12CD", "PIN is 123", "Use AB12CD to verify", "code is 12 34 56": not typed by the broker.
            if where and not _harmless(named, p, where[1]):
                grades.add('marked')
            elif not where and named.anaphor(p) and not _harmless(named, p, 'weak'):
                grades.add('soft')  # "It is AB12CD"
        elif where or named.anaphor(p):
            grades.add(_letters(named, p, *(where or ('it', 'weak', -1)), lower))
    codes = {value for value in values if isinstance(value, str)}
    # The gate reads the words the labels read: plain words, "Code" in "Code:482913", "2FA". Never a link.
    if not KEYWORDS.search(' '.join(token[1] for token in stream if token[0] == 'w')):
        return None, 'no-code-word'
    if not claimed & codes:
        grades |= late
    if 'marked' in grades or 'firm' in grades and not selected & codes:
        return None, 'no-code'
    if not codes:
        return None, next((word.doubt for word in words if word.doubt), 'no-code')
    if len(values) == 1:
        if 'soft' in grades and not claimed:
            return None, 'no-code'
        return next(iter(codes)), 'code'
    # Several numbers: one must carry a strict label, and no other may stand in any label position.
    if len(selected) == 1 and selected <= codes and not claimed - selected:
        return next(iter(selected)), 'code'
    return None, 'several-codes'


def extract(text: object) -> tuple[str | None, str]:
    """The one verification code in a text and why: (code, 'code'), or (None, reason).

    Reasons: 'empty', 'no-code-word', 'no-code' (no number the broker can
    type as a code) and 'several-codes' (more than one, and no single
    labelled one). They hold no text content. See ``read``.
    """
    reading = read(text)
    return reading.code, reading.result


def extract_code(text: object) -> str | None:
    """The one verification code in a text, or None when there is not exactly one."""
    return read(text).code


def mask(text: object) -> str:
    """A preview that is safe to show the agent; "[code]" marks the chosen code. See ``read``."""
    return read(text).preview


def clean_sender(value: object, code: str | None = None) -> str:
    """The sender for the agent: a phone number or short code as it is, any other sender masked like a text.

    A sender that is not only a number (a name, or the whole message after a
    miswired "from") shows plain words, bullets and placeholders. So does a
    number that holds ``code``.
    """
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        return ''
    try:
        words = [word for line in _words(value) for word in line]
    except Exception:
        return ''
    digits = ''.join(ch for word in words for ch in word.text if ch in _DIGITS)
    number = (words and all(word.kind in {'bare', 'number'} and not word.lead and not word.trail and not word.doubt
                            for word in words)
              and 3 <= len(digits) <= 15 and not (code and code in digits))
    return _fit(' '.join(word.text if number else word.shown for word in words), MAX_SENDER, SENDER_BYTES)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def _iso(seconds: float) -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(seconds))


@dataclass
class Source:
    name: str
    kind: str
    token_sha256: str
    created: str
    received: list[float] = field(default_factory=list)  # monotonic arrival times, last minute only
    last_received: str | None = None
    # In memory only: the last text's extraction result (no content) and how
    # many texts arrived since the broker started.
    last_result: str | None = None
    count: int = 0


@dataclass
class Message:
    id: str
    source: str
    sender: str
    preview: str
    code: str
    arrived: float  # monotonic
    received_at: float  # wall clock

    def metadata(self, now: float) -> dict:
        return dict(id=self.id, source=self.source, sender=self.sender, preview=self.preview,
                    code_length=len(self.code), received_at=_iso(self.received_at),
                    age_seconds=max(0, int(now - self.arrived)))


@dataclass
class Setup:
    source: str
    kind: str
    token: str | None  # None: a test page, which never shows the webhook URL
    token_sha256: str
    expires: float


class SmsInbox:
    """Sources (durable, hashed tokens) and received codes (memory only)."""

    def __init__(self, state_path: Path | None, *, clock=time.monotonic, wall_clock=time.time) -> None:
        self.path = Path(state_path) if state_path is not None else None
        self.clock, self.wall_clock = clock, wall_clock
        self.sources: dict[str, Source] = {}
        self.messages: list[Message] = []
        self.setups: dict[str, Setup] = {}
        self.waiters = 0
        self.condition = threading.Condition()
        # Called with (source, message_id) after a text with a code is kept;
        # the broker sets it to wake SMS webhook subscriptions.
        self.on_text = None
        self._load()

    # Private state file -------------------------------------------------

    def _directory(self) -> int:
        from .runtime import prepare_private_runtime_directory
        assert self.path is not None
        if not self.path.is_absolute() or self.path.name in {'', '.', '..'}:
            raise ValueError('invalid SMS source state path')
        for folder in reversed(self.path.parent.parents):
            try:
                os.mkdir(folder, 0o700)
            except FileExistsError:
                pass
        return prepare_private_runtime_directory(self.path.parent)[1]

    def _read(self) -> bytes | None:
        if os.name == 'nt':
            from . import windows_security
            if not self.path.parent.exists():
                return None
            windows_security.ensure_private_directory(self.path.parent)
            return windows_security.read_private_optional(self.path, limit=STATE_LIMIT)
        if not os.path.lexists(self.path):
            return None  # Nothing saved yet: create and check no folder until a save.
        directory = self._directory()
        try:
            try:
                fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError:
                return None
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > STATE_LIMIT):
                    raise ValueError('invalid SMS source state')
                return os.read(fd, STATE_LIMIT + 1)
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def _load(self) -> None:
        if self.path is None:
            return
        raw = self._read()
        if raw is None:
            return
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('sources'), list):
                raise ValueError
            for row in data['sources'][:MAX_SOURCES]:
                name, kind, digest, created = row['name'], row['kind'], row['token_sha256'], row['created']
                if (not isinstance(name, str) or not NAME.fullmatch(name) or kind not in KINDS
                        or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)
                        or not isinstance(created, str) or len(created) > 32 or name in self.sources):
                    raise ValueError
                last = row.get('last_received')
                if last is not None and (not isinstance(last, str) or len(last) > 32):
                    raise ValueError
                self.sources[name] = Source(name, kind, digest, created, last_received=last)
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            raise ValueError('invalid SMS source state') from None

    def _save(self) -> None:
        if self.path is None:
            return
        data = json.dumps(dict(version=1, sources=[
            dict(name=s.name, kind=s.kind, token_sha256=s.token_sha256, created=s.created,
                 **({'last_received': s.last_received} if s.last_received else {}))
            for s in self.sources.values()]), sort_keys=True).encode()
        if os.name == 'nt':
            from . import windows_security
            windows_security.ensure_private_directory(self.path.parent)
            windows_security.replace_private(self.path, data)
            return
        directory = self._directory()
        name = '.sms-sources-' + uuid.uuid4().hex
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)

    # Sources -----------------------------------------------------------

    def capabilities(self) -> dict:
        with self.condition:
            return capabilities(len(self.sources))

    def prune(self) -> None:
        """Drop expired texts and setup pages; the private server calls it when idle."""
        with self.condition:
            self._prune()

    def _prune(self) -> None:
        now = self.clock()
        self.messages = [m for m in self.messages if now - m.arrived < MESSAGE_TTL]
        for key, setup in list(self.setups.items()):
            if setup.expires <= now:
                del self.setups[key]

    def add_source(self, name: object, kind: object, *, replace: bool = False) -> str:
        """Create (or with ``replace`` rotate) a source; return its new webhook token."""
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise SmsError('source name must be 1-32 lowercase letters, digits or hyphens')
        if kind not in KINDS:
            raise SmsError('source kind must be one of: ' + ', '.join(KINDS))
        if self.path is None:
            raise SmsError('this broker has no SMS source state file')
        token = secrets.token_urlsafe(32)
        with self.condition:
            if name in self.sources and not replace:
                raise SmsError('source exists; use replace to issue a new webhook URL')
            if name not in self.sources and len(self.sources) >= MAX_SOURCES:
                raise SmsError(f'at most {MAX_SOURCES} SMS sources')
            previous = self.sources.get(name)
            self.sources[name] = Source(name, kind, _hash(token), _iso(self.wall_clock()))
            try:
                self._save()
            except Exception:
                if previous is None:
                    del self.sources[name]
                else:
                    self.sources[name] = previous
                raise SmsError('SMS source not saved; nothing changed') from None
            # A rotated source invalidates its earlier setup pages.
            for key, setup in list(self.setups.items()):
                if setup.source == name:
                    del self.setups[key]
        return token

    def remove_source(self, name: object) -> bool:
        with self.condition:
            if not isinstance(name, str) or name not in self.sources:
                return False
            previous = self.sources.pop(name)
            try:
                self._save()
            except Exception:
                self.sources[name] = previous
                raise SmsError('SMS source not removed; nothing changed') from None
            self.messages = [m for m in self.messages if m.source != name]
            for key, setup in list(self.setups.items()):
                if setup.source == name:
                    del self.setups[key]
            return True

    def list_sources(self) -> list[dict]:
        with self.condition:
            return [dict(name=s.name, kind=s.kind, created=s.created,
                         **({'last_received': s.last_received} if s.last_received else {}),
                         **({'last_result': s.last_result} if s.last_result else {}))
                    for s in self.sources.values()]

    def new_setup(self, name: str, token: str) -> str:
        """A private setup-page token that shows this source's webhook URL until it expires."""
        key = secrets.token_urlsafe(32)
        with self.condition:
            self._prune()
            source = self.sources.get(name)
            if source is None or not hmac.compare_digest(source.token_sha256, _hash(token)):
                raise SmsError('unknown SMS source')
            self.setups[key] = Setup(name, source.kind, token, source.token_sha256, self.clock() + SETUP_TTL)
        return key

    def new_test_page(self, name: object) -> str:
        """A private page with only the live test step for a source; it never shows the webhook URL."""
        key = secrets.token_urlsafe(32)
        with self.condition:
            self._prune()
            source = self.sources.get(name) if isinstance(name, str) else None
            if source is None:
                raise SmsError('unknown SMS source')
            self.setups[key] = Setup(name, source.kind, None, source.token_sha256, self.clock() + SETUP_TTL)
        return key

    def setup(self, key: object) -> Setup | None:
        if not isinstance(key, str) or not TOKEN.fullmatch(key):
            return None
        with self.condition:
            self._prune()
            setup = self.setups.get(key)
            source = self.sources.get(setup.source) if setup is not None else None
            if setup is None or source is None or source.token_sha256 != setup.token_sha256:
                return None
            return setup

    def setup_status(self, key: object, after: object = None, timeout: float = 0) -> dict | None:
        """For a setup page's live test: the source's text count and last result.

        Waits up to ``timeout`` seconds for a text after count ``after``. None
        when the setup page is not valid. It never returns text content.
        """
        if not self.setup(key):
            return None
        deadline = self.clock() + max(0.0, min(float(timeout), 10.0))
        with self.condition:
            while True:
                setup = self.setups.get(key)
                source = self.sources.get(setup.source) if setup is not None else None
                if source is None or source.token_sha256 != setup.token_sha256:
                    return None
                if not isinstance(after, int) or source.count > after:
                    return dict(count=source.count, result=source.last_result)
                remaining = deadline - self.clock()
                if remaining <= 0:
                    return dict(count=source.count, result=source.last_result)
                self.condition.wait(remaining)

    # Messages ------------------------------------------------------------

    def source_for(self, token: object) -> Source | None:
        if not isinstance(token, str) or not TOKEN.fullmatch(token):
            return None
        digest = _hash(token)
        found = None
        with self.condition:
            for source in self.sources.values():
                if hmac.compare_digest(source.token_sha256, digest):
                    found = source
        return found

    def receive(self, token: object, sender: object, text: object) -> str:
        """Accept one forwarded text: 'kept', 'dropped', 'limited' or 'unknown'."""
        source = self.source_for(token)
        if source is None:
            return 'unknown'
        now = self.clock()
        with self.condition:
            source.received = [t for t in source.received if now - t < 60]
            if len(source.received) >= RATE_LIMIT:
                return 'limited'
            source.received.append(now)
            source.last_received = _iso(self.wall_clock())
            reading = read(text)
            code, source.last_result = reading.code, reading.result
            source.count += 1
            self.condition.notify_all()
            if code is None:
                return 'dropped'
            self._prune()
            message = Message(secrets.token_hex(16), source.name, clean_sender(sender, code), reading.preview, code,
                              now, self.wall_clock())
            self.messages.append(message)
            del self.messages[:-MAX_MESSAGES]
            self.condition.notify_all()
        if self.on_text is not None:
            try:
                self.on_text(message.source, message.id)
            except Exception:
                pass  # A notification failure never drops a received text.
        return 'kept'

    def newest(self, source: str | None, since: float) -> tuple[str, str] | None:
        """The newest kept text received at or after ``since``: (source, message id), or None."""
        with self.condition:
            self._prune()
            found = self._matching(since, source)
            return (found[-1].source, found[-1].id) if found else None

    def _matching(self, since: float | None, source: str | None) -> list[Message]:
        return [m for m in self.messages
                if (since is None or m.received_at >= since) and (source is None or m.source == source)]

    def wait(self, *, since: object = None, source: object = None, timeout: object = 0, ready=lambda: True) -> list[dict]:
        """Codes received at or after ``since`` (wall-clock seconds), newest first.

        With a timeout, wait up to that many seconds for the first one. This is
        an event wait on the inbox, not a poll of any outside service.
        """
        if since is not None and (isinstance(since, bool) or not isinstance(since, (int, float))):
            raise SmsError('since must be a Unix time in seconds')
        if source is not None and (not isinstance(source, str) or not NAME.fullmatch(source)):
            raise SmsError('unknown SMS source')
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout <= MAX_WAIT:
            raise SmsError(f'timeout must be 0-{MAX_WAIT} seconds')
        deadline = self.clock() + timeout
        with self.condition:
            if source is not None and source not in self.sources:
                raise SmsError('unknown SMS source')
            if timeout and self.waiters >= MAX_WAITERS:
                raise SmsError('too many SMS waits; try again later')
            self.waiters += 1
            try:
                while True:
                    self._prune()
                    found = self._matching(since, source)
                    remaining = deadline - self.clock()
                    if found or remaining <= 0 or not ready():
                        break
                    self.condition.wait(min(remaining, 1.0))
            finally:
                self.waiters -= 1
            now = self.clock()
            return [m.metadata(now) for m in sorted(found, key=lambda m: m.arrived, reverse=True)]

    def restore(self, message: Message) -> None:
        """Put back a message whose fill never started, unless it has expired."""
        with self.condition:
            if self.clock() - message.arrived < MESSAGE_TTL and all(m.id != message.id for m in self.messages):
                self.messages.append(message)
                self.messages.sort(key=lambda m: m.arrived)

    def take(self, message_id: object) -> Message:
        """Remove and return one unexpired message; each code is used once."""
        if not isinstance(message_id, str) or not MESSAGE_ID.fullmatch(message_id):
            raise SmsError('unknown or expired SMS message')
        with self.condition:
            self._prune()
            for index, message in enumerate(self.messages):
                if message.id == message_id:
                    return self.messages.pop(index)
        raise SmsError('unknown or expired SMS message')


def webhook_url(origin: str, token: str) -> str:
    return origin.rstrip('/') + ROUTE_IN + token


# Broker actions ----------------------------------------------------------

COMMANDS = ('sms-add-source', 'sms-remove-source', 'sms-sources', 'sms-wait', 'pin-code-target', 'fill-sms-code',
            'subscribe-sms', 'sms-subscription-status', 'unsubscribe-sms', 'sms-test-page')
FILL_START_TIMEOUT = 4.0


def _failure(started=False, *, kind='code'):
    from .browser_card import failure
    return failure(started, kind=kind)


def _https_url(value: object) -> bool:
    from urllib.parse import urlsplit
    if not isinstance(value, str) or len(value) > 4096:
        return False
    parts = urlsplit(value)
    return parts.scheme == 'https' and bool(parts.hostname) and parts.username is None and parts.password is None


def dispatch(broker, request: dict, delivery_ready) -> dict:
    """SMS actions of an unlocked broker. Responses never hold a code, token or body."""
    action = request.get('action')
    inbox: SmsInbox = broker.sms
    if type(request.get('sms_protocol')) is not int or request['sms_protocol'] != PROTOCOL:
        return dict(ok=False, error='SMS protocol 1 required')
    try:
        if action == 'sms-sources':
            if set(request) != {'action', 'sms_protocol'}:
                raise SmsError('invalid SMS request')
            return dict(ok=True, sources=inbox.list_sources())
        if action == 'sms-remove-source':
            if set(request) != {'action', 'sms_protocol', 'name'}:
                raise SmsError('invalid SMS request')
            return dict(ok=True, removed=inbox.remove_source(request['name']))
        if action == 'sms-add-source':
            return _add_source(broker, request, delivery_ready)
        if action == 'sms-wait':
            if set(request) - {'action', 'sms_protocol', 'since', 'source', 'timeout'}:
                raise SmsError('invalid SMS request')
            return dict(ok=True, messages=inbox.wait(since=request.get('since'), source=request.get('source'),
                                                     timeout=request.get('timeout', 0), ready=delivery_ready))
        if action == 'pin-code-target':
            from . import browser_slots
            from .browser_card import CardTargetError
            from .browser_slots import SlotError
            try:
                pin = {k: v for k, v in request.items() if k != 'sms_protocol'}
                return broker.code_targets.pin({**pin, 'code_protocol': 1})
            except SlotError as exc:
                return dict(ok=False, error=str(exc))
            except (CardTargetError, Exception):
                return _failure()
        if action == 'fill-sms-code':
            return _fill(broker, request, delivery_ready)
        if action == 'subscribe-sms':
            # Under the inbox lock a text kept now is either found by the lookup
            # or published after the subscription exists: none falls between.
            with inbox.condition:
                return broker.sms_notifications.subscribe_text(request, received=inbox.newest)
        if action == 'sms-test-page':
            if set(request) != {'action', 'sms_protocol', 'name'}:
                raise SmsError('invalid SMS request')
            origin = getattr(getattr(broker, 'unlock_link', None), 'origin', None)
            if not isinstance(origin, str) or not origin.startswith('https://'):
                raise SmsError('this broker has no HTTPS private page origin')
            key = inbox.new_test_page(request['name'])
            return dict(ok=True, name=request['name'], private_url=origin + ROUTE_SETUP + '?token=' + key)
        if action in {'sms-subscription-status', 'unsubscribe-sms'}:
            if set(request) != {'action', 'sms_protocol', 'subscription_id'}:
                raise SmsError('invalid SMS request')
            return broker.sms_notifications.status(request['subscription_id'], cancel=action == 'unsubscribe-sms')
    except SmsError as exc:
        return dict(ok=False, error=str(exc))
    return dict(ok=False, error='unknown action')


def _consume_target(broker, request):
    """Spend one native control, Android, DOM field or window pin, including refused pins.

    Each manager pops only its own tokens, so a token is spent once, by its owner.
    """
    from .browser_card import CardTargetError
    token = request.get('target')
    native = broker.native.take(token, 'code')
    if native is not None:
        if type(request.get('target_protocol')) is not int or request['target_protocol'] != 1:
            native.close()
            raise SmsError('invalid target protocol')
        return 'native', native
    android = broker.android.take(token)
    if android is not None:
        if (android.mode != 'sms' or type(request.get('target_protocol')) is not int
                or request['target_protocol'] != 1 or request.get('action') != 'fill-sms-code'):
            android.close()
            raise CardTargetError()
        return 'android', android
    try:
        return 'dom', broker.code_targets.consume(token)
    except CardTargetError:
        pass
    return 'window', broker.targets.consume({'target': token, 'target_protocol': request.get('target_protocol')})


def _close_target(broker, route, pin):
    if route in {'native', 'android'}:
        pin.close()
    elif route == 'dom':
        broker.code_targets._close(pin)


def _android_site_matches(pin, request):
    from .totp import TotpError, https_origin
    try:
        return pin.origin == https_origin(request.get('target_url'))
    except TotpError:
        return False


def _deadline(broker, request):
    deadline = request.get('start_deadline')
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not broker.clock() < deadline <= broker.clock() + FILL_START_TIMEOUT):
        raise SmsError('autofill not started: request expired')
    return deadline


def _deliver(broker, route, pin, value, field, ready, deadline):
    """Type ``value`` through the pinned field or window; a fill receipt."""
    from .target import DELIVERY as WINDOW_DELIVERY, DeliveryError
    if route == 'android':
        try:
            return broker.android.fill_element(pin, value, field, ready, deadline)
        finally:
            pin.close()
    if route in {'native', 'dom'}:
        manager = broker.native if route == 'native' else broker.code_targets
        try:
            return manager.fill(pin, value, field, ready, deadline)
        finally:
            _close_target(broker, route, pin)
    if route != 'window':
        return _failure()
    remaining = deadline - broker.clock()
    if remaining <= 0 or not broker._keyboard_lock.acquire(timeout=remaining):
        return dict(ok=False, error='autofill not started: request expired')
    try:
        if not ready():
            return dict(ok=False, error='autofill not started: request expired')
        broker.typer.deliver(pin, [value], ready)
        return dict(ok=True, filled=field, target_delivery=WINDOW_DELIVERY)
    except DeliveryError as exc:
        from .target import failure
        return failure(exc.started)
    finally:
        broker._keyboard_lock.release()


def _add_source(broker, request, delivery_ready):
    allowed = {'action', 'sms_protocol', 'name', 'kind', 'replace'}
    has_target = 'target' in request
    if has_target:
        allowed |= {'target', 'target_protocol', 'start_deadline'}
    if set(request) - allowed or type(request.get('replace', False)) is not bool:
        raise SmsError('invalid SMS request')
    origin = getattr(getattr(broker, 'unlock_link', None), 'origin', None)
    if not isinstance(origin, str) or not origin.startswith('https://'):
        raise SmsError('this broker has no HTTPS private page origin')
    route = pin = None
    if has_target:
        # Spend the pin first: a refused request never leaves it usable.
        try:
            route, pin = _consume_target(broker, request)
        except Exception:
            return _failure()
        if route != 'dom' or pin['field'] != 'webhook-url':
            _close_target(broker, route, pin)
            return _failure()
    try:
        token = inbox_token = broker.sms.add_source(request.get('name'), request.get('kind'),
                                                    replace=request.get('replace', False))
    except BaseException:
        if pin is not None:
            broker.code_targets._close(pin)
        raise
    receipt = dict(ok=True, name=request['name'], kind=request['kind'])
    if not has_target:
        key = broker.sms.new_setup(request['name'], inbox_token)
        return dict(receipt, private_url=origin + ROUTE_SETUP + '?token=' + key)
    try:
        deadline = _deadline(broker, request)
    except SmsError:
        broker.code_targets._close(pin)
        return dict(receipt, **_failure(), private_url=origin + ROUTE_SETUP + '?token=' + broker.sms.new_setup(request['name'], token))
    result = _deliver(broker, route, pin, webhook_url(origin, token), 'webhook-url',
                      lambda: delivery_ready() and broker.clock() < deadline, deadline)
    if not result.get('ok'):
        # The source exists; its setup page is the fallback.
        result = dict(result, private_url=origin + ROUTE_SETUP + '?token=' + broker.sms.new_setup(request['name'], token))
    return dict(receipt, **result)


def _fill(broker, request, delivery_ready):
    allowed = {'action', 'sms_protocol', 'message', 'target', 'target_protocol', 'target_url', 'start_deadline'}
    if set(request) - allowed:
        raise SmsError('invalid SMS request')
    # The target pin is single use, even when the message is invalid. The
    # message returns to the inbox when no key or value was sent.
    try:
        message = broker.sms.take(request.get('message'))
    except SmsError:
        message = None
    try:
        route, pin = _consume_target(broker, request)
    except Exception:
        if message is not None:
            broker.sms.restore(message)
            return _failure()
        return dict(ok=False, error='unknown or expired SMS message')
    if message is None:
        _close_target(broker, route, pin)
        return dict(ok=False, error='unknown or expired SMS message')
    refusal = None
    if route == 'window' and not _https_url(request.get('target_url')):
        refusal = dict(ok=False, error='autofill not started: window code fill needs --target-url')
    elif route == 'android' and not _android_site_matches(pin, request):
        refusal = dict(ok=False, error='autofill not started: Android SMS fill needs a matching HTTPS target URL')
    elif route == 'native' and 'target_url' in request:
        from .totp import https_origin, TotpError
        try:
            if https_origin(request['target_url']) != pin.origin:
                refusal = _failure()
        except TotpError:
            refusal = _failure()
    elif route == 'dom' and pin['field'] != 'one-time-code':
        refusal = _failure()
    if refusal is None:
        try:
            deadline = _deadline(broker, request)
        except SmsError as exc:
            refusal = dict(ok=False, error=str(exc))
    if refusal is not None:
        _close_target(broker, route, pin)
        broker.sms.restore(message)
        return refusal
    ready = lambda: delivery_ready() and broker.clock() < deadline
    try:
        result = _deliver(broker, route, pin, message.code, 'one-time-code', ready, deadline)
    except Exception:
        return dict(ok=False, error='code fill outcome uncertain; do not retry automatically')
    if not result.get('ok') and 'not started' in str(result.get('error', '')):
        broker.sms.restore(message)
    return result
