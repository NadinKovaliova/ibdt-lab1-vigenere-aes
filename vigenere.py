"""Шифр Віженера (Basic level, п. 2.1 методичних вказівок).

Ci = (Pi + Kj) mod 26, де Kj - j-та літера ключа, Pi - i-та літера відкритого
тексту, Ci - i-та літера шифртексту. Ключ циклічно повторюється (j = i mod m).

Поведінка збігається з https://cryptii.com/pipes/vigenere-cipher :
 - регістр літер зберігається;
 - символи поза латинським алфавітом залишаються без змін і НЕ "з'їдають"
   літери ключа.
"""

ALPHABET_SIZE = 26


def _key_shifts(key: str) -> list[int]:
    shifts = [ord(c) - ord("a") for c in key.lower() if "a" <= c <= "z"]
    if not shifts:
        raise ValueError("Ключ повинен містити хоча б одну латинську літеру")
    return shifts


def _transform(text: str, key: str, sign: int) -> str:
    shifts = _key_shifts(key)
    m = len(shifts)
    result = []
    j = 0  # індекс у ключі рухається лише на літерах
    for ch in text:
        if "a" <= ch <= "z":
            base = ord("a")
        elif "A" <= ch <= "Z":
            base = ord("A")
        else:
            result.append(ch)
            continue
        shift = sign * shifts[j % m]
        result.append(chr((ord(ch) - base + shift) % ALPHABET_SIZE + base))
        j += 1
    return "".join(result)


def encrypt(plaintext: str, key: str) -> str:
    return _transform(plaintext, key, +1)


def decrypt(ciphertext: str, key: str) -> str:
    return _transform(ciphertext, key, -1)
