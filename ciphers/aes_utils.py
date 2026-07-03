"""
AES anahtar mantığı.

Gerçek AES şifreleme/çözme işlemi TAMAMEN tarayıcıda,
Web Crypto API (AES-GCM) ile yapılır — bu dosya şifreleme yapmaz.
Bu dosyanın tek görevi, backend ile frontend'in "aynı anahtardan"
konuşmasını sağlayacak salt/pepper mantığını üretmektir:

    oda_şifresi (kullanıcı bilir)  +  etkin_salt (sunucu üretir)
                        |
                        v
              PBKDF2  ->  AES-GCM anahtarı   (tarayıcıda)

'etkin_salt' iki parçadan oluşur:
    1) room_salt  -> odaya özel, rastgele üretilir (Caesar'daki shift gibi)
    2) SERVER_PEPPER -> .env dosyasındaki AES_KEY, hiçbir zaman istemciye
       ham haliyle gönderilmez; sadece HMAC ile room_salt'ı 'imzalamak'
       için kullanılır.

Böylece .env'deki AES_KEY artık gerçekten işlevsel: onu bilmeyen biri
(sunucuya erişimi olmayan biri) doğru etkin_salt'ı üretemez.
"""

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