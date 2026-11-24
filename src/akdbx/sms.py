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
# disagree about what a word is. It keeps no list of link forms, no list of
# things that are not a code (card, reference, year, ZIP, currency), and it
# does not look for the place where a text may give a code in letters. It
# works the other way round, from what it knows:
#
# * A WORD is what stands between spaces and line breaks; no link, in any
#   notation, can cross a space. A word is PLAIN when it is letters only, with
#   ordinary punctuation at its ends, and nothing else is in its spaced word
#   (a tab, an odd space or a pictograph does not cut a link).
# * The preview shows a plain word only when the reader can ACCOUNT for it:
#   it is a word of the vocabulary below, or it stands where only a name
#   stands ("your Example code", "for Example", "Example: ..."). A number shows
#   as bullets, the chosen code as "[code]", and everything else as a
#   placeholder. After "password" only function words show. So a code or a
#   password in letters is hidden wherever it stands, because it is not a
#   known word, and not because its place was recognised.
# * A CANDIDATE is a number written the way codes are written: one group of 4
#   to 8 digits, or 3+3 / 4+4, alone in its word or glued to one word
#   ("Code:482913", "G-482913"). A text whose only candidate it is gives that
#   code. With several candidates the broker does not judge which numbers are
#   not codes. One of them must stand in a STRICT label position ("code is N",
#   "N is your ... code", "Use N to", "Your code for ... is N") and no other may
#   stand in any label position, however loose.
# * The chosen number must have a label in its own sentence. A number without
#   a label is taken only from a text that the reader accounts for in full:
#   one unknown word, one "AB12CD" or one "12 34 56" anywhere, and the text is
#   dropped, because that may be the code. Two more checks use no place
#   either, only "which sentence": a label that gives no number but has an
#   unknown word right at it, and a sentence that names a code, gives no
#   number and holds a word written as a value (see _choose).
# * Every word list below is an allow-list. A wording it lacks costs one
#   hidden word or one dropped text. It cannot make the broker choose a number
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
_LABEL_GLUED = re.compile(f'[{_o}]*({_W}){_G}{{1,3}}[LM09].*')  # "Code:HXKQWP", "code(AB12CD)": a label and more

# Label words, case-folded. Every list is an allow-list.
_SELF = frozenset('otp passcode mtan pushtan chiptan phototan'.split())  # a code whatever stands before it ("TAN" too)
_CODE = frozenset('code codes código codigo codice kod kode kód cod код'.split())  # a code unless modified
_WEAK = frozenset('password pin passwort kennwort contraseña senha clave token passphrase wachtwoord passe'.split())
_PHRASED = _WEAK - {'pin', 'token'}                                    # a password: any words can be its value
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
    'cijfers times attempts mal veces fois volte vezes keer use uses login logins transaction transactions '
    'device devices session sessions'.split())
# The vocabulary: the words that the reader knows. First the closed classes (articles, pronouns, prepositions,
# conjunctions, auxiliaries, common adverbs), then what texts say about a code ("valid", "expires", "share"),
# then the things that such texts name ("account", "card", "payment").
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
collect redeem claim join leave unsubscribe subscribe enter type input submit insert use safely opt apply
treat near track sharing geben diesen dieser dieses weiter dritte condividerlo comparta including
gültig ungültig erforderlich nötig abgelaufen falsch richtig geheim vertraulich persönlich einmalig sicher wichtig
aktiv läuft verfällt gilt weitergeben teilen eingeben verwenden nutzen benutzen senden erhalten bestätigen anmelden
lang válido inválido requerido necesario caducado incorrecto correcto confidencial secreto único seguro importante
caduca vence expira compartas compartir comparta ingresa usa utiliza valable valide invalide requis nécessaire
expiré confidentiel personnel sûr partagez partager utilisez saisissez valido invalido richiesto necessario scaduto
errato corretto riservato segreto personale unico sicuro scade condividere obrigatório necessário expirado incorreto
correto pessoal compartilhe compartilhar insira digite geldig ongeldig vereist nodig verlopen onjuist juist
vertrouwelijk persoonlijk uniek veilig belangrijk verloopt deel delen gebruik voer
'''.split())
_THINGS = frozenset('''
account accounts phone number numbers device devices app application message messages transaction txn payment purchase
transfer card bank customer team support order request page website site link email mail identity registration
session attempt browser computer mobile service staff employee employees people information details data profile user
username id reference ref booking ticket invoice delivery parcel package ending amount balance login access screen box
field form password security eur usd gbp inr chf rs konto karte zahlung überweisung betrag kunde nachricht gerät
telefon nummer c copyright ltd inc llc plc gmbh fee cuenta tarjeta pago transferencia cliente mensaje teléfono
número compte carte paiement virement client
téléphone numéro conto carta pagamento bonifico messaggio telefono numero conta cartão mensagem telefone rekening kaart
betaling bericht telefoon
'''.split())
# Verification words as whole words (the label grammar uses their stems, _STRONG).
_VERIFYING = frozenset('''
verification verify verified security secure login log-in sign-in signin confirmation confirm authentication
authenticate authorization authorisation one-time two-factor two-step temporary unique reset recovery activation
identification sms bestätigung verifizierung sicherheit anmeldung zugang einmalig verificación seguridad confirmación
acceso vérification sécurité connexion accès verifica sicurezza conferma accesso verificação segurança confirmação
acesso verificatie beveiliging bevestiging
'''.split())
# A number in words. One such word is a word; two or more in a row are a number ("FOUR TWO ONE SIX").
_DIGIT_NAMES = frozenset('''
zero oh one two three four five six seven eight nine null eins zwei drei vier fünf sechs sieben acht neun cero uno dos
tres cuatro cinco seis siete ocho nueve zéro un deux trois quatre cinq sept huit neuf due tre quattro cinque sei sette
otto nove um dois três quatro oito nul een twee drie vijf zes zeven negen
'''.split())
# After these a name stands, not a code: "for Example", "at AMAZON", "from Example Bank", "sign in to Example".
_NAMING = frozenset('for at from on by für bei von auf im am vom beim para de del en por desde pour du chez sur dans '
                    'per di da su della voor bij op van'.split())
_INTO = frozenset('in access login on'.split())
_NAME_GLUE = frozenset('of the and de di du del und y e'.split())  # "Bank of Example"
# "Your code is as follows: N", "Enter the code below: N", "the code you requested is N".
_POINTER = frozenset('as follows following the below here shown displayed listed given this in message text sms unten '
                     'folgt hier wie abajo aquí siguiente suivant sotto seguente abaixo seguinte hieronder '
                     'volgt'.split())
_BETWEEN = frozenset('you we requested need needed asked sent will now today to use enter for this time'.split())
_POSSESSIVE = frozenset('your my our ihr ihre ihren dein deine tu su mi votre ton tuo tua suo sua seu sua teu uw je '
                        'jouw'.split())
_GROUPS = frozenset('staff employee employees team support account app application card bank website site customer '
                    'service ltd inc llc plc gmbh'.split())
_NEVER = frozenset("never doesn't won't cannot can't niemals nunca jamais mai nooit".split())
_DATED = frozenset('on until till by before since am bis vor seit le el il op tot'.split())
_APP_HASH = re.compile('[A-Za-z0-9+/]{11}')  # the last word of a text in the SMS Retriever format


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
    group: int = 0         # which spaced word of its line it belongs to
    note: str = ''         # 'copyright' after "©"; 'phone' in a long run of digit groups


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
        return _Word('bare', text, shown, front=glue or before, lead='mtan' if lead == 'TAN' else lead.casefold(),
                     groups=(a, b) if b else (a,), close=close, trail=trail.casefold(),
                     after=match.group(9) or '' if trail else close, digits=True)
    if '9' in shape and 'L' not in shape and 'M' not in shape:
        return _Word('number', text, bullets, digits=True, doubt='no-code')  # numerals the broker does not type
    if _NUMERIC.fullmatch(shape):
        return _Word('number', text, bullets, digits=True, after=text[-1] if shape[-1] in _CLOSE else '')
    return _hidden(text, shape)


def _words(text: str) -> list[list[_Word]]:
    """The text as lines of words.

    Only a space ends a spaced word, and that decision is made on the text as it came. A tab, an odd space or a
    pictograph inside a spaced word cuts it into parts, which are read one by one; but its plain parts show
    only when every part is plain. So nothing glued to a link, a number or loose punctuation is ever shown. A
    link can also run on across a line break (programs that open links drop tabs and line breaks), so the
    spaced word that starts the line after a link is not shown.
    """
    lines, sign = [], False
    for line in re.split(r'[\n\r]+', text):
        words = []
        for group, raw in enumerate(line.split(' ')):
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
            for part in parts:
                part.group = group
                if (sign or raw.startswith('©')) and part.kind == 'bare':
                    part.note = 'copyright'  # "© 2026", "©2026"
            sign = raw == '©' or sign and not parts
            words.extend(parts)
        if words:
            lines.append(words)
    runs_on = False
    for upper, lower in zip(lines, lines[1:]):
        # After a link, or a link sign, at the end of a line; and on through a line that is one such word.
        last = upper[-1]
        alone = all(word.group == last.group and word.kind == 'plain' for word in upper)
        runs_on = last.shown == '[link]' or last.kind != 'plain' and last.text[-1] in _LINK + '#:' or runs_on and alone
        for word in lower:
            if runs_on and word.group == lower[0].group and word.kind == 'plain':
                word.shown = '[hidden]'
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
        elif len(run) > 1 and ('+' in run[0].text or sum(sizes) >= 9):
            for word in run:
                word.note = 'phone'  # "0800 123 4567": a long number in groups


def _stream(lines: list[list[_Word]]) -> list[tuple]:
    """The words as tokens for the label grammar and the vocabulary check.

    ('w', word, its _Word or None) for a word (None when the word is a piece of a longer written word);
    ('n', _Word) for a number; ('h', _Word) for a word the broker does not read; (':',) for "Label: N";
    ('|', 'stop' / 'comma' / 'paren' / 'line') where a sentence, a clause, a note in brackets or a line ends;
    ('x',) other punctuation.
    """
    out: list[tuple] = []

    def marks(punctuation: str, opened: bool = False) -> None:
        if ':' in punctuation or '：' in punctuation:
            out.append((':',))
        if any(ch in _END for ch in punctuation):
            out.append(('|', 'stop' if any(ch in _STOP for ch in punctuation) else 'comma'))
        elif not opened and any(ch in ')）' for ch in punctuation):
            out.append(('|', 'paren'))

    for line in lines:
        for word in line:
            opened = word.text[0] in '(（'
            if word.kind == 'plain':
                if opened and not any(ch in ')）' for ch in word.after):
                    out.append(('|', 'paren'))  # "(reference is 1234)": a note in brackets is a clause of its own
                # "TAN" in capitals is the German code noun; "tan" is a Spanish word.
                out.append(('w', 'mtan' if word.core == 'tan' and word.text.isupper() else word.core, word))
                marks(word.after, opened)
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
                    out.append(('w', word.lead, None))
                    if any(ch in _END for ch in word.front):
                        out.append(('|', 'stop'))
                    elif word.front.strip(_OPEN + _CLOSE):
                        out.append((':',))  # "Code:482913", "G-482913", "code=482913"
                else:
                    marks(word.front, True)
                if not word.part:
                    out.append(('n', word))
                marks(word.close, opened or '(' in word.front)
                if word.trail:
                    out.append(('w', word.trail, None))
                    marks(word.after)
            elif word.text.casefold().strip(_OPEN + _CLOSE) in _STRONG_MIXED:
                out.append(('w', word.text.casefold().strip(_OPEN + _CLOSE), None))
                marks(word.after)
            elif _GLUED.fullmatch(_shape(word.text)):
                match = _GLUED.fullmatch(_shape(word.text))
                out.extend((('w', word.text[match.start(1):match.end(1)].casefold(), None), ('|', 'stop'),
                            ('w', word.text[match.start(2):match.end(2)].casefold(), None)))
                marks(match.group(3))
            else:
                match = _LABEL_GLUED.fullmatch(_shape(word.text))
                label = word.text[match.start(1):match.end(1)] if match else ''
                if _tier('mtan' if label == 'TAN' else label.casefold()) is not None:
                    # "Code:HXKQWP", "code(AB12CD)", "PIN:AB12": the label, and what it is glued to as its value
                    out.extend((('w', 'mtan' if label == 'TAN' else label.casefold(), None), (':',)))
                out.append(('n' if word.digits else 'h', word))
                marks(word.after)
        out.append(('|', 'line'))
    return out


def _strong(core: str) -> bool:
    return core.startswith(_STRONG)


def _tier(core: str) -> str | None:
    """'self', 'code' or 'weak' when the word is a label noun; None for any other word, "postcode" included."""
    *modifiers, head = core.split('-')
    tier = 'self' if head in _SELF else 'code' if head in _CODE else 'weak' if head in _WEAK else None
    if tier is None:
        for suffix in _COMPOUND:
            if head.endswith(suffix) and len(head) > len(suffix):
                return 'self' if _strong(head[:-len(suffix)]) else None
        return None
    return 'self' if modifiers and not _modified(core) else tier


def _modified(core: str) -> bool:
    """A label noun with a word of another kind joined to it: "ZIP-Code", "Example-Code"."""
    modifiers = core.split('-')[:-1]
    return bool(modifiers) and not (_strong('-'.join(modifiers)) or all(_strong(m) for m in modifiers))


def _known(core: str, closed: bool = False) -> bool:
    """A word of the vocabulary: its place in a text tells nothing more than the word itself.

    With ``closed`` only the closed classes and the label words count (after "password", where any other word
    can be the password).
    """
    parts = [part.strip("'") for part in core.split('-') if part.strip("'")]
    if len(parts) != 1:
        return _tier(core) is not None or bool(parts) and all(_known(part, closed) for part in parts)
    core = parts[0]
    if core in _CLOSED or _tier(core) is not None:
        return True
    if closed:
        return False
    if core in _SAID or core in _THINGS or core in _UNITS or core in _VERIFYING:
        return True
    for ending in ('ing', 'ed', 'es', 's', 'd'):  # "expires", "shared", "entering", "accounts"
        base = core[:-len(ending)]
        forms = (base, base + 'e', base[:-1] + 'y' if base[-1:] == 'i' else base)
        if core.endswith(ending) and len(base) > 2 and any(form in _SAID or form in _THINGS for form in forms):
            return True
    return False


class _Labels:
    """Which numbers of a token stream stand in the value position of a label.

    A label is a code noun with what goes with it ("Your Google verification code is", "OTP:"), or an order
    ("Use ... to", "verify with ...").

    'strict': the noun is a verification code noun that no unknown word modifies, in a fixed sentence form.
    Only a strict label can select a code among several numbers.

    'named': any code noun or secret noun in the same forms ("ZIP code 90210", "Your PIN is", "Your Lyft code
    is", "código de cliente es"). A number with such a label is the number that its own sentence gives.

    'loose': also a code noun anywhere before "is N" in the clause, a verification word or an unreadable word
    right before the number, a number listed after another number and a number alone in its sentence. A named
    or loose label never selects a code among several. It stops another number from being selected.
    """

    def __init__(self, stream: list[tuple], mode: str = 'strict') -> None:
        self.stream, self.mode = stream, mode

    def token(self, i: int) -> tuple:
        return self.stream[i] if 0 <= i < len(self.stream) else ('|', 'stop')

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
        while self.token(p) != ('|', 'stop'):
            p += 1
        return p

    def back(self, i: int) -> int:
        """The token before ``i`` in its sentence. A line break, a comma, a colon or a bracket is no new start:
        "postal" still modifies "code" in "Your postal,<line break>code"."""
        i -= 1
        while self.kind(i) == ':' or self.kind(i) == '|' and self.token(i)[1] != 'stop':
            i -= 1
        return i

    def stage(self, i: int) -> int:
        """0 for a function word, 2 for a verification word, 1 for any other word (a name)."""
        word = self.word(i)
        if _strong(word) or (word, self.word(i + 1)) in _STRONG_PAIRS or (self.word(i - 1), word) in _STRONG_PAIRS:
            return 2
        return 0 if word in _FUNCTION else 1

    def lead_in(self, first: int, noun: int) -> bool:
        """Tokens ``first`` to ``noun`` are function words, then a name of up to three words, then verification
        words: "your Bank of Example verification"."""
        stage = names = 0
        for i in range(first, noun):
            if self.kind(i) != 'w' or self.word(i) in _NEGATION:
                return False
            if stage == 1 and self.word(i) in _NAME_GLUE and self.kind(i + 1) == 'w' and self.stage(i + 1) == 1:
                continue
            now = self.stage(i)
            names += now == 1
            if now < stage or names > 3:
                return False
            stage = now
        return True

    def strong_before(self, i: int) -> bool:
        """A verification word right before token ``i`` ("verification", "one time")."""
        j = self.back(i)
        return self.kind(j) == 'w' and (_strong(self.word(j)) or _tier(self.word(j)) == 'self'
                                        or (self.word(self.back(j)), self.word(j)) in _STRONG_PAIRS)

    def noun(self, i: int) -> bool:
        """Token ``i`` is a label noun. In strict mode no unknown word modifies it: not before it ("ZIP code"),
        not joined to it ("ZIP-Code") and not after it ("código de cliente")."""
        word = self.word(i)
        tier = _tier(word)
        if tier is None or self.mode != 'strict':
            return tier is not None
        if _modified(word) or self.word(i + 1) in _OF and not _strong(self.word(i + 2)):
            return False
        if tier == 'self' or self.strong_before(i):
            return True
        j = self.back(i)
        return tier == 'code' and (self.kind(j) == '|' or self.word(j) in _FUNCTION)

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
        if self.mode != 'strict' and self.kind(i) == 'w' and not _known(self.word(i)) and self.stage(i) == 1:
            if _tier(self.word(i - 1)) is not None:
                return i - 1  # "Votre code Example est 482913": the name stands after the noun
            if _strong(self.word(i - 1)) and self.word(i - 2) in _OF and _tier(self.word(i - 3)) is not None:
                return i - 3  # "Votre code de sécurité Example est 482913"
        return i if self.mode == 'loose' and _strong(self.word(i)) else -1  # "Verification: 482913"

    def before(self, p: int) -> tuple | None:
        """("weak" or "strong", noun) when a label ends right before token ``p``.

        Weak: "code 482913". Strong: "code is 482913", "code: 482913", and the same with the value on the next
        line. A few fixed words can stand in between: "code is as follows: 482913", "the code below: 482913",
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
        if colon and self.mode != 'strict' and _strong(self.word(i)) and self.head(i) < 0:
            return 'strong', i  # "Verification: 482913": a verification word and a colon make a label
        gap, steps = self.mode != 'strict', 0  # outside strict mode one word that the lists lack may stand between
        while colon and steps < 3 and self.kind(i) == 'w' and self.head(i) < 0 and (
                self.word(i) in _POINTER or gap and not _known(self.word(i))):
            gap = gap and self.word(i) in _POINTER
            i, steps = i - 1, steps + 1
        if self.word(i) in _COPULA:
            i, strong, steps = i - 1, True, 0
            while steps < 3 and self.head(i) < 0 and self.word(i) in _BETWEEN:
                i, steps = i - 1, steps + 1
        noun = self.head(i)
        return ('strong' if strong else 'weak', noun) if noun >= 0 else None

    def direct(self, p: int) -> int:
        """The noun when token ``p`` stands right after "<label> is" or "<label>:", on that line or the next."""
        i, linked = p - 1, False
        if i > 0 and self.token(i) == ('|', 'line') and (self.kind(i - 1) == ':' or self.word(i - 1) in _COPULA):
            i -= 1
        if self.kind(i) == ':':
            i, linked = i - 1, True
        if self.word(i) in _COPULA:
            i, linked = i - 1, True
        return self.head(i) if linked else -1

    def after(self, p: int) -> int:
        """The noun when token ``p`` is the subject of "... is your Google verification code", else -1.

        Also "482913 - your Example verification code", "482913 (Example verification code)" and "482913, your
        Example verification code" when the noun ends the clause.
        """
        dash = self.mode != 'loose' and (self.kind(p + 1) == ':' or self.token(p + 1) in (
            ('|', 'paren'), ('|', 'comma')))
        if self.word(p + 1) not in _COPULA and not dash:
            return -1
        for i in range(p + 2, p + 10):
            word = self.word(i)
            if self.kind(i) != 'w' or word in _NEGATION:
                return -1
            if _tier(word) is not None and not (_strong(word) and _tier(self.word(i + 1)) is not None):
                if self.mode == 'loose':
                    return i
                rest = self.phrase(i) + 1
                follows = rest
                while self.kind(follows) == '|' and self.token(follows) != ('|', 'stop'):
                    follows += 1  # past the end of a line or of a note in brackets, inside the sentence
                if dash and (self.kind(rest) != '|' or self.rival(follows)):
                    return -1  # "Example: your code is 482913", "EXAMPLE - your code" and the code on the next line
                fine = self.kind(rest) != 'w' or self.word(rest) in _FUNCTION or not _known(self.word(rest))
                return i if self.noun(i) and self.lead_in(p + 2, i) and fine else -1
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
        """Tokens ``k`` to ``end`` are prepositional phrases and nothing else: "for card ending 4321".

        A phrase is a preposition, its determiners, and names, things and numbers. Any other known word (a
        verb, an adverb, a conjunction, a second determiner) shows that the clause has moved on:
        "expires shortly", "and your reference".
        """
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
                word = self.word(k)
                if self.kind(k) == 'w' and word not in _THINGS and (_known(word) or word in _DETERMINER):
                    return False
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
        while self.kind(start) == 'x':
            start += 1  # "<#> Tu código de Example es 482913"
        for j in range(start, i):
            word = self.word(j)
            if self.kind(j) != 'w':
                return -1
            if _tier(word) is not None and not (_strong(word) and _tier(self.word(j + 1)) is not None):
                fine, rest = self.noun(j) and self.lead_in(start, j), self.phrase(j) + 1
                while _tier(self.word(rest)) is not None:
                    rest += 1  # "password (OTP)": a second name for the same thing
                return j if fine and self.phrases(rest, i) else -1
        return -1

    def nextline(self, p: int) -> int:
        """The noun when token ``p`` starts a line and the line before it is a label and nothing else."""
        if self.token(p - 1) != ('|', 'line'):
            return -1
        noun = self.head(p - 2)
        first = noun
        while noun >= 0 and self.kind(first - 1) == 'w':
            first -= 1
        return noun if noun >= 0 and self.kind(first - 1) in '|:' and self.lead_in(first, noun) else -1

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
        return self.mode == 'loose' and (self.edge(p - 1) and self.edge(p + 1) or self.word(p - 1) in _COPULA and (
            self.word(p - 2) == 'it') or self.word(p - 1) == "it's")

    def explained(self, p: int) -> bool:
        """Candidate ``p`` stands in a known place that is not a code's place."""
        number, before, earlier = self.token(p)[1], self.word(p - 1), self.word(p - 2)
        if before in _TO and (earlier in _OPTOUT or earlier == 'all' and self.word(p - 3) in _OPTOUT):
            return True  # "Reply STOP to 89203"
        sign = self.token(p - 1)[2].text if self.kind(p - 1) == 'w' and self.token(p - 1)[2] else '(c)'
        if (number.note == 'copyright' or before == 'copyright' or before == 'c' and sign.casefold() == '(c)'
                ) and re.fullmatch('(?:19|20)[0-9]{2}', number.value):
            return True  # "(c) 2026 Example Ltd", "© 2026"
        return (before in _UNTIL and earlier in _EXPIRY
                and re.fullmatch('(?:[01][0-9]|2[0-3])[0-5][0-9]', number.value) is not None)  # "Expires at 1845"


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
            elif word.shown != '[hidden]' or not shown or shown[-1] != '[hidden]':
                shown.append(word.shown)  # one placeholder for a run of hidden words
    text = ' '.join(shown)
    at = text.find('[code]')
    if at > MAX_PREVIEW * 2 // 3:  # keep the chosen code and the words around it in a long text
        text = '…' + text[text.rfind(' ', 0, at - MAX_PREVIEW // 2) + 1:]
    return _fit(text, MAX_PREVIEW, PREVIEW_BYTES)


def read(text: object) -> Reading:
    """Read one text once: its verification code, why (one of RESULTS), and its preview.

    The code is None unless the text has a verification word and either one
    candidate number, or one candidate with a strict label and no other number
    in any label position. And the chosen number must have a label in its own
    sentence ("code is N", "N is your Example code", "Use N to"); without one
    it is taken only from a text in which the reader can account for every
    word. So a text that gives its code as "HXKQWP", "AB12CD", "FOUR TWO ONE
    SIX" or in any other form that the reader does not know is dropped,
    wherever in the text that word stands. A text is also dropped when such a
    word stands right after "code is" or "code:" (or before "is your code")
    and that label gives no number, even if another number has a label. And a
    number whose label is not strict ("Your PIN is", "Your ZIP code is") is
    not taken when another sentence names a code, gives no number for it and
    holds a word written as a value ("Your code is now HXKQWP"). Dropped,
    never guessed.

    The preview holds words of a fixed vocabulary, names in the few places
    where only a name stands ("your Example code", "for Example"), bullets,
    "[code]" where the chosen code stands, and placeholders. It never holds a
    numeral, nor a character of a spaced word that is more than letters and
    ordinary punctuation, nor a word that the reader does not know.
    """
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT:
        return Reading(None, 'empty', '')
    try:
        return _read(text)
    except Exception:  # the text is untrusted: a reader fault drops it and shows nothing
        return Reading(None, 'no-code', '')


def _read(text: str) -> Reading:
    lines = _words(text.lstrip(chr(0xFEFF)))
    for line in lines:
        _numbers(line)
    stream = _stream(lines)
    words = [word for line in lines for word in line]
    code, result = _choose(words, stream)
    return Reading(code, result, _preview(lines, code))


def _names(labels: _Labels, unknown: list[bool], gives: list[bool]) -> set[int]:
    """The unknown words that stand where only a name stands. They are shown, and they are no riddle.

    Before a label noun whose sentence gives a number ("482913 is your Bank of Example verification code",
    "Uber code: 4829"; ``gives`` tells that for each token); after "for", "at", "from", "on", "by" and after "in to"
    ("for your Example account", "sign in to Example"); between a label noun and its number ("Votre code
    Example est 482913", "OTP HDFC 482913"); and at the start of a text, before a colon, in brackets or right
    before the number ("Example: ...", "[Example] ...", "Example 482913"), when the first line has a number;
    at the start of a sentence before "never" or "will not" ("Example will never ask"); before "staff", "team",
    "app" or "account" ("Example staff"). A code is not written in these places. A word that is a name in one
    of them is a name everywhere in the text.
    """
    stream, names = labels.stream, set()

    def run(i: int, step: int, limit: int, extra: frozenset) -> list[int]:
        found = []
        while len(found) < limit and labels.kind(i) == 'w' and labels.token(i)[2] is not None and (
                unknown[i] or labels.word(i) in extra):
            found.append(i)
            i += step
        while found and labels.word(found[-1]) in _NAME_GLUE:
            found.pop()  # a name does not end (or start) with a joining word
        return found if any(unknown[k] for k in found) else []

    for i, token in enumerate(stream):
        if token[0] != 'w':
            continue
        word = token[1]
        if _tier(word) is not None:
            first = i
            while labels.kind(first - 1) == 'w' and labels.stage(first - 1) == 2 and _tier(
                    labels.word(first - 1)) is None:
                first -= 1  # "verification", "one time"
            found = run(first - 1, -1, 4, _NAME_GLUE | _THINGS)
            opener = first - 1 - len(found) if found else -1
            if found and gives[i] and (labels.word(opener) in _POSSESSIVE or labels.kind(opener) in '|:x'):
                names.update(found)  # "your Google verification code is"; not "Use the HXKQWP code"
            k = labels.phrase(i) + 1
            found = run(k, 1, 2, frozenset())
            k += len(found) + (labels.word(k + len(found)) in _COPULA)
            k += labels.kind(k) == ':'
            if found and labels.rival(k) and labels.token(k)[1].value:
                names.update(found)  # "Votre code Example est 482913", "OTP HDFC 482913"
        k = i + 1
        while labels.word(k) in _DETERMINER:
            k += 1
        # "in" names only before a determiner ("in the Example app"): "type in HXKQWP" gives a value.
        if word in _NAMING or word in {'into', 'onto'} or word == 'to' and labels.word(i - 1) in _INTO or (
                word == 'in' and k > i + 1):
            names.update(run(k, 1, 4, _NAME_GLUE | _THINGS))  # "for your Example account", "at AMAZON PAY"
        if unknown[i]:
            if labels.word(i + 1) in _GROUPS:
                names.add(i)  # "Example staff", "Example app"
            k = i
            while k < i + 3 and labels.kind(k) == 'w' and (unknown[k] or labels.word(k) in _THINGS):
                k += 1
            if labels.kind(i - 1) == '|' and (labels.word(k) in _NEVER or labels.word(k + 1) in _NEVER
                                              or labels.word(k + 1) in _NEGATION):
                names.update(range(i, k))  # "HDFC Bank never asks for OTP", "Example will never call you"
    start = 0
    while labels.kind(start) == 'x':
        start += 1  # "<#>"
    end = start
    while not labels.edge(end):
        end += 1  # the first line, up to its first full stop
    if any(labels.rival(k) and labels.token(k)[1].value for k in range(start, end)):
        after = start
        while after < start + 3 and labels.kind(after) == 'w' and stream[after][2] is not None and (
                unknown[after] or labels.word(after) in _NAME_GLUE | _THINGS):
            after += 1  # "Example Bank: ..."
        found = [k for k in range(start, after) if unknown[k]]
        bracketed = bool(found) and stream[found[0]][2].text[0] in '[<(【（「' and stream[found[-1]][2].text.rstrip(
            '.,;:!?')[-1] in ']>)】）」'
        if found and (labels.kind(after) == ':' or labels.rival(after) and len(found) <= 2 or bracketed):
            names.update(found)  # "Example: ...", "Example 482913", "[Example] ..."
    said = {labels.word(i) for i in names if unknown[i]}
    return {i for i, token in enumerate(stream) if unknown[i] and token[1] in said}


def _number_known(labels: _Labels, i: int, labelled: bool) -> bool:
    """Number ``i`` is no candidate; is it clearly no code either? A time span, an amount, a date, a phone
    number, a link. In a sentence with a label, any other number may be a code that the broker cannot type:
    "123", "123456789", "12 34 56", "48-29-13", "AB12CD"."""
    word = labels.token(i)[1]
    if word.kind == 'hidden':
        return any(ch in _LINK for ch in word.text) or bool(
            _SPAN.fullmatch(word.text.casefold().strip(_OPEN + _CLOSE)))
    if not labelled or word.note == 'phone':
        return True
    if word.kind == 'number':
        groups = re.findall('[0-9]+', word.text)
        joins = set(re.findall('(?<=[0-9])[^0-9]+(?=[0-9])', word.text))
        spelled = len(joins) == 1 and joins <= {'-', '.', ',', '/'} and len({len(g) for g in groups}) == 1
        dated = labels.word(i - 1) in _DATED  # "until 24.11.26"
        # "48-29-13", "482.913": a code with separators?
        return dated or not (spelled and 4 <= sum(map(len, groups)) <= 8)
    if word.lead or word.trail:
        return False  # "XK-48"
    if len(word.groups) != 1:
        return len(word.groups[0]) != len(word.groups[1])  # "12-34" may be a code; "555-0100" is not
    size = len(word.groups[0])
    if size <= 3:  # "valid 10 minutes", "6 digits", "Enter 1 to confirm"
        return labels.word(i + 1) in _UNITS or size <= 2 and labels.order(i) and labels.kind(i + 1) != 'n'
    return size <= 8  # a part of a run in doubt; a single group of nine digits or more may be a code


def _account(labels: _Labels, sentence: list[int], given: set[int]) -> tuple[set[int], set[int]]:
    """Account for every token: a known word, a name, a number of a known kind, a link. Hide all other words.

    ``sentence`` is the sentence number of each token, and ``given`` holds the sentences that give a number
    with a label. Returns the tokens that the reader cannot account for, and the tokens that are a number in
    words ("FOUR TWO ONE SIX").
    """
    stream = labels.stream
    gives = [number in given for number in sentence]
    # A name joined to the noun ("Example-Code") is a name only where the sentence gives a number.
    unknown = [token[0] == 'w' and token[2] is not None and (
        not _known(token[1]) or _tier(token[1]) is not None and _modified(token[1]) and not gives[i])
        for i, token in enumerate(stream)]
    nouns = [i for i, token in enumerate(stream) if token[0] == 'w' and _tier(token[1]) is not None]
    labelled = {sentence[i] for i in nouns}
    secret: dict[int, int] = {}  # the sentence of a password noun, and where the noun stands
    for i in nouns:
        if stream[i][1].split('-')[-1] in _PHRASED:
            secret.setdefault(sentence[i], i)
    names = _names(labels, unknown, gives)
    last = max((i for i, token in enumerate(stream) if token[0] in 'wnh'), default=-1)
    if last in names and _APP_HASH.fullmatch(stream[last][2].text):
        names.discard(last)  # the app hash that ends a text is no name: "... for Example AbCdEfGhIjk"
    spelled, run = set(), []
    for i, token in enumerate(stream + [('|', 'stop')]):
        if token[0] == 'w' and token[1] in _DIGIT_NAMES:
            run.append(i)
        else:
            if len(run) > 1:
                spelled.update(run)  # "FOUR TWO ONE SIX": a number in words is a number
            run = []
    lost = set()
    for i, token in enumerate(stream):
        kind = token[0]
        if kind == 'w' and token[2] is None:
            lead = labels.kind(i + 1) == 'n' or labels.kind(i + 1) == ':' and labels.kind(i + 2) in 'nh'
            if not (lead or _known(token[1])):
                lost.add(i)  # a piece of a longer written word: "482913.Xq"
        elif kind == 'w':
            if sentence[i] in secret and i > secret[sentence[i]]:
                hide = not _known(token[1], closed=True)  # after "password": any word can be the password
            else:
                hide = unknown[i] and i not in names
            if hide or i in spelled or token[2].shown == '[hidden]':
                token[2].shown = '[hidden]'
                lost.add(i)
        elif kind == 'h' and not any(ch in _LINK for ch in token[1].text):
            lost.add(i)
        elif kind == 'n' and not (token[1].value or token[1].doubt) and not _number_known(
                labels, i, sentence[i] in labelled or labels.order(i)):
            lost.add(i)
    return lost, spelled


def _choose(words: list[_Word], stream: list[tuple]) -> tuple[str | None, str]:
    strict, named, loose = (_Labels(stream, mode) for mode in ('strict', 'named', 'loose'))
    values: set = set()      # each different number that could be the code
    selected: set = set()    # those with a strict label
    claimed: set = set()     # those with any label
    labelled: set = set()    # those with a label in their own sentence
    given: set = set()       # the label nouns that give such a number
    sentence, count = [], 0  # the sentence number of each token
    for token in stream:
        sentence.append(count)
        count += token == ('|', 'stop')
    for p, token in enumerate(stream):
        if token[0] != 'n' or not (token[1].value or token[1].doubt):
            continue
        where = named.slot(p)
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
        if where and token[1].value:
            labelled.add(value)
            given.add(where[2])
    codes = {value for value in values if isinstance(value, str)}
    lost, spelled = _account(named, sentence, {sentence[p] for p, token in enumerate(stream) if (
        token[0] == 'n' and token[1].value in labelled)})
    # The gate reads the words the labels read: plain words, "Code" in "Code:482913", "2FA". Never a link.
    if not KEYWORDS.search(' '.join(token[1] for token in stream if token[0] == 'w')):
        return None, 'no-code-word'
    lower = any(token[0] == 'w' and token[2] and token[2].text != token[2].text.upper() for token in stream)

    def written(p: int) -> bool:
        """Token ``p`` is written as a value and not as a word of a sentence: "HXKQWP", "MapleRiver", "AB12CD"."""
        token = stream[p]
        raw = token[2].text.lstrip(_OPEN) if token[0] == 'w' and token[2] else ''
        return token[0] != 'w' or p in spelled or lower and (
            raw.isupper() and len(token[1]) > 1 or any(ch.isupper() for ch in raw[1:]))

    for p, token in enumerate(stream):
        # "Your verification code is HXKQWP", "AB12CD is your code", "PIN: 123", "Use AB12CD to verify": a label
        # gives something that the broker cannot type, and no number. No other number takes its place.
        if token[0] not in 'wnh' or token[0] == 'n' and (token[1].value or token[1].doubt):
            continue
        unread = token[0] != 'w' and token[1].kind == 'hidden'  # a link also, when it is given as the code
        direct, subject = named.direct(p), named.after(p)
        noun = max(direct, subject)
        # In this place a thing word is a value as well ("Your code is ACCESS"); only function words and what
        # texts say about a code are not ("Your code is valid", "Here is your code").
        thing = token[0] == 'w' and token[1] not in _CLOSED and (token[1] in _THINGS or subject >= 0 > direct)
        # A password or a PIN in letters is another secret: it is hidden, and it does not stop a labelled code.
        if (p in lost or unread or thing) and noun >= 0 and noun not in given and _tier(
                named.word(noun)) != 'weak':
            return None, 'no-code'
        capitals = token[0] == 'w' and bool(token[2]) and lower and token[2].text.isupper() and len(token[1]) > 1
        if p in lost and (token[0] != 'w' or capitals) and named.order(p):
            return None, 'no-code'
    if not codes:
        return None, next((word.doubt for word in words if word.doubt), 'no-code')
    if len(values) == 1:
        code = next(iter(codes))
    elif len(selected) == 1 and selected <= codes and not claimed - selected:
        code = next(iter(selected))  # several numbers: one strict label, and no other number in any label position
    else:
        return None, 'several-codes'
    if code not in labelled and lost:
        return None, 'no-code'  # no label on the number, and a word that the reader cannot account for
    if code not in selected:
        # The label of the number is not strict ("Your PIN is", "Your ZIP code is", "Your Lyft code is"). Then
        # no sentence may name a code, give no number for it, and hold something written as a value: "Your code
        # is now HXKQWP". The app hash at the very end of a text is not such a thing.
        last = max(i for i, token in enumerate(stream) if token[0] in 'wnh')
        open_ = {sentence[i] for i, token in enumerate(stream)
                 if token[0] == 'w' and _tier(token[1]) in ('self', 'code') and i not in given}
        for p in lost:
            tail = p == last and stream[p][0] != 'w' and _APP_HASH.fullmatch(stream[p][1].text) is not None
            if sentence[p] in open_ and written(p) and not tail:
                return None, 'no-code'
    return code, 'code'


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
    """The sender for the agent: a phone number or short code as it is, and a name of up to three words.

    A longer sender is the whole message after a miswired "from": it is shown as the preview of a text, with
    every unknown word hidden. A number that holds ``code`` shows as bullets.
    """
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        return ''
    try:
        lines = _words(value)
        words = [word for line in lines for word in line]
        if len(words) > 3:
            for line in lines:
                _numbers(line)
            _choose(words, _stream(lines))  # hides what a preview hides
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
    """A DOM code pin, or an X11 pin-target pin. Either way the token is spent."""
    from .browser_card import CardTargetError
    token = request.get('target')
    try:
        return 'dom', broker.code_targets.consume(token)
    except CardTargetError:
        pass
    return 'x11', broker.targets.consume({'target': token, 'target_protocol': request.get('target_protocol')})


def _deadline(broker, request):
    deadline = request.get('start_deadline')
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not broker.clock() < deadline <= broker.clock() + FILL_START_TIMEOUT):
        raise SmsError('autofill not started: request expired')
    return deadline


def _deliver(broker, route, pin, value, field, ready, deadline):
    """Type ``value`` through the pinned DOM field or X11 window; a fill receipt."""
    from .target import DELIVERY as X11_DELIVERY, DeliveryError
    if route == 'dom':
        try:
            return broker.code_targets.fill(pin, value, field, ready, deadline)
        finally:
            broker.code_targets._close(pin)
    remaining = deadline - broker.clock()
    if remaining <= 0 or not broker._keyboard_lock.acquire(timeout=remaining):
        return dict(ok=False, error='autofill not started: request expired')
    try:
        if not ready():
            return dict(ok=False, error='autofill not started: request expired')
        broker.typer.deliver(pin, [value], ready)
        return dict(ok=True, filled=field, target_delivery=X11_DELIVERY)
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
            if route == 'dom':
                broker.code_targets._close(pin)
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
    close = (lambda: broker.code_targets._close(pin)) if route == 'dom' else (lambda: None)
    if message is None:
        close()
        return dict(ok=False, error='unknown or expired SMS message')
    refusal = None
    if route == 'x11' and not _https_url(request.get('target_url')):
        refusal = dict(ok=False, error='autofill not started: X11 code fill needs --target-url')
    elif route == 'dom' and pin['field'] != 'one-time-code':
        refusal = _failure()
    else:
        try:
            deadline = _deadline(broker, request)
        except SmsError as exc:
            refusal = dict(ok=False, error=str(exc))
    if refusal is not None:
        close()
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
