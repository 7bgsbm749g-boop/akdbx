"""Private, deliberately narrow group-tag representation equivalence.

KeePassium 2.5.171 TagHelper splits comma/semicolon, trims Foundation whitespace
and drops empty tokens. Preserve order, duplicates, case and every token byte.
Only ASCII space/tab trimming is certified here; other whitespace is retained
conservatively. No quoting, escaping, NFC, case folding or entry-tag set logic.
KeePassXC 2.7.10 has no effective group-tag UI/search consumer: Group stores a
raw scalar and Merger retains it. This explicitly named policy is NOT scalar
identity. Complete raw originals remain in encrypted external snapshots.
"""
import re

VERIFICATION = 'keepassium-2.5.171-sequence-v1'


def sequence(text):
    return tuple(token for part in re.split('[,;]', text or '')
                 if (token := part.strip(' \t')))
