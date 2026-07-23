

import os
import hmac
import hashlib


def generate_room_salt() -> str:
    """Oda oluşturulurken çağrılır. Caesar'daki generate_caesar_shift'in
    AES karşılığıdır: odaya özel, rastgele bir salt üretir."""
    return os.urandom(16).hex()


def derive_effective_salt(room_salt_hex: str, server_pepper: str) -> str:
    """
    room_salt (odaya özel, herkese açık) ile server_pepper (.env, gizli)
    değerlerini HMAC-SHA256 ile harmanlayıp istemciye gönderilecek
    'etkin salt' değerini üretir.

    server_pepper asla dışarı gönderilmez; sadece bu fonksiyonun
    ürettiği sonuç (effective_salt) join_confirmed ile istemciye gider.
    """
    return hmac.new(
        server_pepper.encode("utf-8"),
        room_salt_hex.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()