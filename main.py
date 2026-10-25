"""CLI для лабораторної роботи 1: шифр Віженера та AES.

Приклади:
    python main.py vigenere enc "ATTACK AT DAWN" LEMON
    python main.py vigenere dec "LXFOPV EF RNHR" LEMON
    python main.py aes enc "Hello, world!" 000102030405060708090a0b0c0d0e0f
    python main.py aes enc "Hello" <hex-ключ> --mode cbc
    python main.py aes dec <hex-шифртекст> <hex-ключ> --mode cbc
Ключ AES - hex-рядок на 16, 24 або 32 байти (AES-128/192/256).
"""

import argparse
import sys

import aes
import vigenere


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cipher", required=True)

    v = sub.add_parser("vigenere", help="шифр Віженера")
    v.add_argument("action", choices=["enc", "dec"])
    v.add_argument("text")
    v.add_argument("key")

    a = sub.add_parser("aes", help="шифр AES")
    a.add_argument("action", choices=["enc", "dec"])
    a.add_argument("text", help="enc: відкритий текст (UTF-8); dec: шифртекст у hex")
    a.add_argument("key", help="ключ у hex (32/48/64 hex-символи)")
    a.add_argument("--mode", choices=["ecb", "cbc"], default="cbc")

    args = p.parse_args(argv)

    try:
        if args.cipher == "vigenere":
            fn = vigenere.encrypt if args.action == "enc" else vigenere.decrypt
            print(fn(args.text, args.key))
            return 0

        key = bytes.fromhex(args.key)
        if args.action == "enc":
            data = args.text.encode("utf-8")
            out = (aes.encrypt_cbc(data, key) if args.mode == "cbc"
                   else aes.encrypt_ecb(data, key))
            print(out.hex())
        else:
            data = bytes.fromhex(args.text)
            out = (aes.decrypt_cbc(data, key) if args.mode == "cbc"
                   else aes.decrypt_ecb(data, key))
            print(out.decode("utf-8"))
    except ValueError as e:
        print(f"Помилка: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
