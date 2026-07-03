"""
Caesar Cipher (kaydırmalı şifre) mantığı.
Her oda için rastgele bir 'shift' değeri üretilir; bu değer odanın
gizli anahtarı gibi davranır ve sadece odaya bağlanan istemcilere
(join_confirmed üzerinden) gönderilir.
"""

import os

ALPHABET = (
   ' 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZÇĞİÖŞÜabcdefghijklmnopqrstuvwxyzçğıöşü.,!?:;\'"-()\n'
)


def generate_caesar_shift() -> int:
    """1 ile len(ALPHABET)-1 arasında rastgele bir kaydırma değeri üretir."""
    return (os.urandom(1)[0] % (len(ALPHABET) - 1)) + 1


def caesar_encrypt(text: str, shift: int) -> str:
    cipher = ""
    for c in text:
        index = ALPHABET.find(c)
        if index == -1:
            cipher += c
        else:
            cipher += ALPHABET[(index + shift) % len(ALPHABET)]
    return cipher


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)
