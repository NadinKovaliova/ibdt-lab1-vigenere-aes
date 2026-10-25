"""Шифр AES (Advanced level, п. 2.2 методичних вказівок), реалізація з нуля.

Структура відповідає псевдокоду з методички / FIPS-197:
    Cipher:    AddRoundKey -> (SubBytes, ShiftRows, MixColumns, AddRoundKey) x (Nr-1)
               -> SubBytes, ShiftRows, AddRoundKey
    InvCipher: обернені перетворення у зворотному порядку
    KeyExpansion (GetRoundKeys): Nk = 4/6/8, Nr = 10/12/14, Nb = 4

Стан (state) - масив 4x4 байти, заповнюється по стовпцях: state[r][c] = in[r + 4c].
Зверху над блоковим шифром реалізовано режими ECB та CBC із доповненням PKCS#7.
"""

import os

Nb = 4  # кількість 32-бітних слів у блоці (128 біт)
BLOCK_SIZE = 16


# --------------------------------------------------------------------------
# Арифметика в GF(2^8) та таблиці
# --------------------------------------------------------------------------
def _xtime(a: int) -> int:
    """Множення на x (0x02) у GF(2^8) за модулем x^8+x^4+x^3+x+1 (0x11B)."""
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    """Множення двох елементів GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _build_sbox() -> list[int]:
    """S-box: мультиплікативний обернений елемент + афінне перетворення.

    Отримана таблиця збігається з таблицею з методички (0x63, 0x7c, 0x77, ...).
    """
    sbox = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            inv = next(y for y in range(1, 256) if _gmul(x, y) == 1)
        s = inv
        for shift in range(1, 5):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox[x] = s ^ 0x63
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

_MUL = {n: [_gmul(x, n) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}


# --------------------------------------------------------------------------
# KeyExpansion (GetRoundKeys)
# --------------------------------------------------------------------------
def _sub_word(word: list[int]) -> list[int]:
    return [SBOX[b] for b in word]


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def get_round_keys(key: bytes) -> list[list[int]]:
    """Повертає список із Nb*(Nr+1) слів (кожне слово - 4 байти)."""
    if len(key) not in (16, 24, 32):
        raise ValueError("Довжина ключа має бути 16, 24 або 32 байти")
    nk = len(key) // 4
    nr = nk + 6

    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, Nb * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp)
        w.append([a ^ b for a, b in zip(w[i - nk], temp)])
    return w


# --------------------------------------------------------------------------
# Перетворення стану
# --------------------------------------------------------------------------
def _bytes_to_state(block: bytes) -> list[list[int]]:
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _add_round_key(state, round_key_words) -> None:
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key_words[c][r]


def _sub_bytes(state) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]


def _inv_sub_bytes(state) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]


def _shift_rows(state) -> None:
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def _inv_shift_rows(state) -> None:
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def _mix_columns(state) -> None:
    m2, m3 = _MUL[2], _MUL[3]
    for c in range(4):
        a0, a1, a2, a3 = (state[r][c] for r in range(4))
        state[0][c] = m2[a0] ^ m3[a1] ^ a2 ^ a3
        state[1][c] = a0 ^ m2[a1] ^ m3[a2] ^ a3
        state[2][c] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
        state[3][c] = m3[a0] ^ a1 ^ a2 ^ m2[a3]


def _inv_mix_columns(state) -> None:
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    for c in range(4):
        a0, a1, a2, a3 = (state[r][c] for r in range(4))
        state[0][c] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
        state[1][c] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
        state[2][c] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
        state[3][c] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]


# --------------------------------------------------------------------------
# Шифрування / розшифрування одного блоку
# --------------------------------------------------------------------------
def encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок має бути довжиною 16 байт")
    nr = len(round_keys) // Nb - 1
    state = _bytes_to_state(block)

    _add_round_key(state, round_keys[0:Nb])
    for rnd in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd * Nb:(rnd + 1) * Nb])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[nr * Nb:(nr + 1) * Nb])
    return _state_to_bytes(state)


def decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Блок має бути довжиною 16 байт")
    nr = len(round_keys) // Nb - 1
    state = _bytes_to_state(block)

    _add_round_key(state, round_keys[nr * Nb:(nr + 1) * Nb])
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[rnd * Nb:(rnd + 1) * Nb])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0:Nb])
    return _state_to_bytes(state)


# --------------------------------------------------------------------------
# Доповнення PKCS#7 та режими ECB / CBC
# --------------------------------------------------------------------------
def pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Некоректна довжина даних")
    n = data[-1]
    if not 1 <= n <= BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("Некоректне доповнення (невірний ключ або пошкоджені дані)")
    return data[:-n]


def _blocks(data: bytes):
    for i in range(0, len(data), BLOCK_SIZE):
        yield data[i:i + BLOCK_SIZE]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_ecb(plaintext: bytes, key: bytes, use_padding: bool = True) -> bytes:
    rk = get_round_keys(key)
    data = pad(plaintext) if use_padding else plaintext
    if len(data) % BLOCK_SIZE:
        raise ValueError("Без доповнення довжина даних має бути кратна 16")
    return b"".join(encrypt_block(b, rk) for b in _blocks(data))


def decrypt_ecb(ciphertext: bytes, key: bytes, use_padding: bool = True) -> bytes:
    rk = get_round_keys(key)
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError("Довжина шифртексту має бути кратна 16")
    data = b"".join(decrypt_block(b, rk) for b in _blocks(ciphertext))
    return unpad(data) if use_padding else data


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes | None = None,
                use_padding: bool = True) -> bytes:
    """CBC. Якщо iv не заданий - генерується випадковий і ставиться на початок."""
    rk = get_round_keys(key)
    prepend_iv = iv is None
    iv = os.urandom(BLOCK_SIZE) if iv is None else iv
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV має бути довжиною 16 байт")
    data = pad(plaintext) if use_padding else plaintext
    if len(data) % BLOCK_SIZE:
        raise ValueError("Без доповнення довжина даних має бути кратна 16")
    out, prev = [], iv
    for block in _blocks(data):
        prev = encrypt_block(_xor(block, prev), rk)
        out.append(prev)
    return (iv if prepend_iv else b"") + b"".join(out)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes | None = None,
                use_padding: bool = True) -> bytes:
    """CBC. Якщо iv не заданий - він береться з перших 16 байт шифртексту."""
    rk = get_round_keys(key)
    if iv is None:
        iv, ciphertext = ciphertext[:BLOCK_SIZE], ciphertext[BLOCK_SIZE:]
    if len(iv) != BLOCK_SIZE or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("Некоректна довжина IV або шифртексту")
    out, prev = [], iv
    for block in _blocks(ciphertext):
        out.append(_xor(decrypt_block(block, rk), prev))
        prev = block
    data = b"".join(out)
    return unpad(data) if use_padding else data
