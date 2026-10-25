# Лабораторна робота №1-2. Реалізація криптографічного алгоритму

**Дисципліна:** Інформаційна безпека та децентралізовані технології (F6)
**Варіант 1:** алгоритм шифрування
**Виконано:** Basic level — шифр Віженера (2.1); Advanced level — AES-128/192/256 (2.2)

## Склад

| Файл | Призначення |
|---|---|
| `vigenere.py` | Шифр Віженера: `Ci = (Pi + Kj) mod 26` |
| `aes.py` | AES з нуля: KeyExpansion (`get_round_keys`), SubBytes, ShiftRows, MixColumns, AddRoundKey та обернені; режими ECB і CBC, PKCS#7 |
| `main.py` | Консольний інтерфейс |
| `tests/test_ciphers.py` | Автотести на еталонних векторах |

Зовнішніх залежностей немає (Python 3.10+). Бібліотека `cryptography` використовується
лише в одному необов'язковому тесті як еталон для порівняння.

## Запуск

```bash
python main.py vigenere enc "ATTACK AT DAWN" LEMON      # LXFOPV EF RNHR
python main.py vigenere dec "LXFOPV EF RNHR" LEMON      # ATTACK AT DAWN

python main.py aes enc "Hello, world!" 000102030405060708090a0b0c0d0e0f --mode cbc
python main.py aes dec <hex-шифртекст> 000102030405060708090a0b0c0d0e0f --mode cbc
```

Ключ AES — hex-рядок на 16/24/32 байти. У режимі CBC випадковий IV пишеться на початок шифртексту.

## Тестування

```bash
python -m unittest discover -s tests -v
```

Перевіряється:

- **Віженер:** класичний вектор `ATTACKATDAWN` / `LEMON` → `LXFOPVEFRNHR`; збереження регістру та
  розділових знаків (як у https://cryptii.com/pipes/vigenere-cipher, на який посилається методичка);
  ключ не зсувається на небуквених символах.
- **AES:** FIPS-197 Appendix C (AES-128/192/256), Appendix B, розгортання ключа (Appendix A.1),
  NIST SP 800-38A (CBC), збіг S-box із таблицею з методички, шифрування/розшифрування
  для довжин 0–100 байт, порівняння з еталонною бібліотекою.

## Відповідність методичним вказівкам

- Алгоритми реалізовано за псевдокодом з пп. 2.1 та 2.2 (Cipher, InvCipher, GetRoundKeys).
- Реалізовано і шифрування, і розшифрування.
- Правильність перевірено на референсних векторах.
