import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aes  # noqa: E402
import vigenere  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # еталонна бібліотека необов'язкова
    Cipher = None


class VigenereTests(unittest.TestCase):
    def test_classic_vector(self):
        self.assertEqual(vigenere.encrypt("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")
        self.assertEqual(vigenere.decrypt("LXFOPVEFRNHR", "LEMON"), "ATTACKATDAWN")

    def test_case_and_punctuation_preserved(self):
        enc = vigenere.encrypt("Attack at dawn!", "Lemon")
        self.assertEqual(enc, "Lxfopv ef rnhr!")
        self.assertEqual(vigenere.decrypt(enc, "Lemon"), "Attack at dawn!")

    def test_key_does_not_advance_on_non_letters(self):
        self.assertEqual(vigenere.encrypt("A A", "BC"), "B C")

    def test_key_a_is_identity(self):
        self.assertEqual(vigenere.encrypt("Hello", "A"), "Hello")

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            vigenere.encrypt("abc", "123")


class AesTests(unittest.TestCase):
    # FIPS-197, Appendix C
    PT = bytes.fromhex("00112233445566778899aabbccddeeff")
    KEY128 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    KEY192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    KEY256 = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                           "101112131415161718191a1b1c1d1e1f")

    def test_sbox_matches_methodical_table(self):
        self.assertEqual(aes.SBOX[:8], [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
        self.assertEqual(aes.SBOX[0xff], 0x16)
        self.assertEqual(sorted(aes.SBOX), list(range(256)))

    def test_fips197_appendix_c(self):
        cases = [
            (self.KEY128, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (self.KEY192, "dda97ca4864cdfe06eaf70a0ec0d7191"),
            (self.KEY256, "8ea2b7ca516745bfeafc49904b496089"),
        ]
        for key, ct_hex in cases:
            rk = aes.get_round_keys(key)
            ct = aes.encrypt_block(self.PT, rk)
            self.assertEqual(ct.hex(), ct_hex)
            self.assertEqual(aes.decrypt_block(ct, rk), self.PT)

    def test_fips197_appendix_b(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        rk = aes.get_round_keys(key)
        self.assertEqual(aes.encrypt_block(pt, rk).hex(),
                         "3925841d02dc09fbdc118597196a0b32")

    def test_key_expansion_appendix_a1(self):
        w = aes.get_round_keys(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
        self.assertEqual(len(w), 44)
        self.assertEqual(bytes(w[4]).hex(), "a0fafe17")
        self.assertEqual(bytes(w[43]).hex(), "b6630ca6")

    def test_nist_sp800_38a_cbc(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                           "ae2d8a571e03ac9c9eb76fac45af8e51")
        ct = aes.encrypt_cbc(pt, key, iv, use_padding=False)
        self.assertEqual(ct.hex(), "7649abac8119b246cee98e9b12e9197d"
                                   "5086cb9b507219ee95db113a917678b2")
        self.assertEqual(aes.decrypt_cbc(ct, key, iv, use_padding=False), pt)

    def test_roundtrip_modes_and_lengths(self):
        for key in (self.KEY128, self.KEY192, self.KEY256):
            for n in (0, 1, 15, 16, 17, 100):
                data = os.urandom(n)
                self.assertEqual(aes.decrypt_ecb(aes.encrypt_ecb(data, key), key), data)
                self.assertEqual(aes.decrypt_cbc(aes.encrypt_cbc(data, key), key), data)

    def test_wrong_key_detected_or_garbage(self):
        ct = aes.encrypt_cbc(b"secret message", self.KEY128)
        try:
            self.assertNotEqual(aes.decrypt_cbc(ct, self.KEY256[:16][::-1]),
                                b"secret message")
        except ValueError:
            pass

    def test_bad_key_length(self):
        with self.assertRaises(ValueError):
            aes.get_round_keys(b"short")

    @unittest.skipIf(Cipher is None, "бібліотека cryptography не встановлена")
    def test_against_reference_library(self):
        for key in (self.KEY128, self.KEY192, self.KEY256):
            data = os.urandom(48)
            ref = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            expected = ref.update(data) + ref.finalize()
            self.assertEqual(aes.encrypt_ecb(data, key, use_padding=False), expected)


if __name__ == "__main__":
    unittest.main()
