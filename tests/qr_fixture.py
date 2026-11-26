"""A small QR encoder for synthetic test pages: byte mode, error level L, versions 1 to 6.

The tests make a fresh synthetic authenticator key on every run, so they need
their own QR images (no QR library is a test dependency). The algorithm is the
standard one (ISO/IEC 18004): data codewords, Reed-Solomon error correction,
function patterns, the zigzag data placement, mask 0 and the format bits. The
broker's own decoder (the vendored jsQR) reads these codes in the tests; that
proves the encoder too.
"""
import struct
import zlib

# Version: (data codewords per block, number of blocks, error correction codewords per block), level L.
BLOCKS = {1: (19, 1, 7), 2: (34, 1, 10), 3: (55, 1, 15), 4: (80, 1, 20), 5: (108, 1, 26), 6: (68, 2, 18)}
ALIGNMENT = {1: (), 2: (6, 18), 3: (6, 22), 4: (6, 26), 5: (6, 30), 6: (6, 34)}
QUIET = 4


def _multiply(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _multiply(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _multiply(root, 2)
    return result


def _remainder(data, divisor):
    result = [0] * len(divisor)
    for byte in data:
        factor = byte ^ result.pop(0)
        result.append(0)
        for i, coefficient in enumerate(divisor):
            result[i] ^= _multiply(coefficient, factor)
    return result


def _codewords(data, version):
    per_block, blocks, ec = BLOCKS[version]
    capacity = per_block * blocks
    bits = [0, 1, 0, 0] + [(len(data) >> i) & 1 for i in reversed(range(8))]
    for byte in data:
        bits += [(byte >> i) & 1 for i in reversed(range(8))]
    if len(bits) > capacity * 8:
        raise ValueError('text too long for this version')
    bits += [0] * min(4, capacity * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < capacity:
        words.append(pad)
        pad ^= 0xEC ^ 0x11
    divisor = _divisor(ec)
    data_blocks = [words[i * per_block:(i + 1) * per_block] for i in range(blocks)]
    ec_blocks = [_remainder(block, divisor) for block in data_blocks]
    return [b[i] for i in range(per_block) for b in data_blocks] + [b[i] for i in range(ec) for b in ec_blocks]


def matrix(text):
    """The modules of the smallest version that holds the text; True is dark. No quiet zone."""
    data = text.encode('utf-8')
    version = next(v for v in BLOCKS if 4 + 8 + 8 * len(data) <= BLOCKS[v][0] * BLOCKS[v][1] * 8)
    size = 17 + 4 * version
    modules = [[False] * size for _ in range(size)]
    function = [[False] * size for _ in range(size)]

    def put(x, y, dark):
        modules[y][x] = dark
        function[y][x] = True

    for i in range(size):
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                if 0 <= cx + dx < size and 0 <= cy + dy < size:
                    put(cx + dx, cy + dy, max(abs(dx), abs(dy)) not in (2, 4))
    centres = ALIGNMENT[version]
    for cx in centres:
        for cy in centres:
            if (cx, cy) in ((6, 6), (6, centres[-1]), (centres[-1], 6)):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    put(cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)

    def format_bits(mask):
        value = (1 << 3) | mask  # Level L is 01.
        remainder = value
        for _ in range(10):
            remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537)
        bits = ((value << 10) | remainder) ^ 0x5412
        bit = lambda i: (bits >> i) & 1 == 1
        for i in range(6):
            put(8, i, bit(i))
        put(8, 7, bit(6))
        put(8, 8, bit(7))
        put(7, 8, bit(8))
        for i in range(9, 15):
            put(14 - i, 8, bit(i))
        for i in range(8):
            put(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            put(8, size - 15 + i, bit(i))
        put(8, size - 8, True)

    format_bits(0)  # Reserve the format areas before the data goes in.
    words = _codewords(data, version)
    index = 0
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vertical in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vertical if upward else vertical
                if not function[y][x] and index < len(words) * 8:
                    modules[y][x] = (words[index >> 3] >> (7 - (index & 7))) & 1 == 1
                    index += 1
        right -= 2
    for y in range(size):
        for x in range(size):
            if not function[y][x] and (x + y) % 2 == 0:  # Mask 0.
                modules[y][x] = not modules[y][x]
    format_bits(0)
    return modules


def rows(text, quiet=QUIET):
    """The code with its quiet zone, as strings of 0 (light) and 1 (dark), like synthetic_qr.json."""
    code = matrix(text)
    size = len(code) + 2 * quiet
    blank = '0' * size
    return [blank] * quiet + ['0' * quiet + ''.join('1' if m else '0' for m in row) + '0' * quiet for row in code] + [blank] * quiet


def compose(parts, width, height):
    """Pixel rows (scale 1) of several codes on one white image: parts are (rows, module size, left, top)."""
    pixels = [['0'] * width for _ in range(height)]
    for lines, scale, left, top in parts:
        for y in range(len(lines) * scale):
            for x in range(len(lines[0]) * scale):
                pixels[top + y][left + x] = lines[y // scale][x // scale]
    return [''.join(row) for row in pixels]


def png(lines, scale=4, *, invert=False):
    """An 8-bit greyscale PNG of the rows, each module `scale` pixels."""
    dark, light = (255, 0) if invert else (0, 255)
    raw = b''
    for line in lines:
        row = bytes(dark if c == '1' else light for c in line for _ in range(scale))
        raw += (b'\0' + row) * scale
    width = len(lines[0]) * scale

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack('>IIBBBBB', width, len(lines) * scale, 8, 0, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')


def svg(lines, scale=4, kind='rects'):
    """An inline <svg> of the rows, in the shapes real generators write.

    rects: a white ground and one dark rectangle per module (rqrcode, qrcode.js).
    path: one filled path of unit squares in a viewBox of modules (qrcode.react).
    stroke: one stroked path of horizontal runs (node-qrcode, segno).
    styled: rectangles painted by a page style sheet class, not by attributes.
    """
    size, count = len(lines) * scale, len(lines)
    head = f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}"'
    if kind == 'path':
        d = ''.join(f'M{x} {y}h1v1h-1z' for y, line in enumerate(lines) for x, c in enumerate(line) if c == '1')
        return (f'{head} viewBox="0 0 {count} {count}" shape-rendering="crispEdges"><path fill="#FFFFFF" '
                f'd="M0,0 h{count}v{count}H0z"/><path fill="#000000" d="{d}"/></svg>')
    if kind == 'stroke':
        runs = []
        for y, line in enumerate(lines):
            x = 0
            while x < count:
                if line[x] == '1':
                    start = x
                    while x < count and line[x] == '1':
                        x += 1
                    runs.append(f'M{start} {y + .5}h{x - start}')
                else:
                    x += 1
        return (f'{head} viewBox="0 0 {count} {count}" shape-rendering="crispEdges"><path fill="#ffffff" '
                f'd="M0 0h{count}v{count}H0z"/><path stroke="#000000" d="{"".join(runs)}"/></svg>')
    cells = ''.join(f'<rect x="{x * scale}" y="{y * scale}" width="{scale}" height="{scale}"'
                    + (' class="dark"/>' if kind == 'styled' else '/>')
                    for y, line in enumerate(lines) for x, c in enumerate(line) if c == '1')
    if kind == 'styled':
        return f'{head}><rect class="light" width="{size}" height="{size}"/>{cells}</svg>'
    return f'{head} viewBox="0 0 {size} {size}"><rect width="{size}" height="{size}" fill="#fff"/><g fill="#000">{cells}</g></svg>'
