import os
import random

# Anahtar boyutu: n = p * q, p ve q KEY_BITS/2 bit uzunluğunda üretilir.
# 2048-bit modern, güvenli kabul edilen minimum RSA anahtar boyutudur.
KEY_BITS = 2048

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    """Miller-Rabin olasılıksal asallık testi.
    Büyük (yüzlerce bit) sayılar için pratikte kullanılabilecek tek yöntem;
    klasik 'for i in range(2, sqrt(n))' deneme bölmesi bu boyutlarda
    evrenin ömrü kadar sürer."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p

    # n - 1 = 2^r * d  (d tek sayı)
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits: int) -> int:
    """`bits` uzunluğunda (en üst bit her zaman 1, yani tam `bits` bit)
    rastgele bir asal sayı üretir."""
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a


def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    div, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return div, x, y


def modular_inverse(e: int, phi: int) -> int:
    """e * d ≡ 1 (mod phi) olacak şekilde d'yi bulur."""
    div, x, _ = _extended_gcd(e, phi)
    if div != 1:
        raise ValueError("Modüler ters bulunamadı: e ve phi aralarında asal değil.")
    return x % phi


def generate_rsa_keypair(key_bits: int = KEY_BITS):
    """Odaya özel gerçek boyutlu RSA anahtar çiftini üretir.

    Returns:
        public_key:  (e, n)  -> şifrelemek için kullanılır, herkese açıktır
        private_key: (d, n)  -> şifre çözmek için kullanılır, gizli olmalıdır
    """
    prime_bits = key_bits // 2
    p = generate_large_prime(prime_bits)
    q = generate_large_prime(prime_bits)
    while q == p:
        q = generate_large_prime(prime_bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    # 65537 (0x10001), gerçek dünyada neredeyse tüm RSA implementasyonlarının
    # kullandığı standart genel üstür (hızlı şifreleme + iyi bilinen güvenlik
    # özellikleri). gcd(e, phi) != 1 olması istatistiksel olarak son derece
    # nadirdir; olursa anahtarları yeniden üretiriz.
    e = 65537
    if gcd(e, phi) != 1:
        return generate_rsa_keypair(key_bits)

    d = modular_inverse(e, phi)

    return (e, n), (d, n)


def _byte_length(n: int) -> int:
    return (n.bit_length() + 7) // 8


def encrypt(public_key, plain_text: str):
    """Mesajı UTF-8 byte'lara çevirir, PKCS#1 v1.5 benzeri rastgele dolgu
    ekleyerek bloklara böler ve her bloğu ayrı ayrı şifreler.

    Blok formatı (n_bytes uzunluğunda):
        0x00 | 0x02 | rastgele-sıfır-olmayan-dolgu (PS) | 0x00 | mesaj

    Rastgele dolgu sayesinde aynı mesaj her şifrelemede FARKLI bir
    ciphertext üretir (semantik güvenlik) ve karakter bazlı frekans
    analizi imkansız hale gelir.
    """
    e, n = public_key
    n_bytes = _byte_length(n)
    max_block = n_bytes - 11  # PKCS#1 v1.5: 3 byte başlık + en az 8 byte dolgu
    if max_block <= 0:
        raise ValueError("Anahtar boyutu bu mesajı bloklamak için çok küçük.")

    data = plain_text.encode('utf-8')
    blocks = [data[i:i + max_block] for i in range(0, len(data), max_block)] or [b'']

    cipher_blocks = []
    for chunk in blocks:
        ps_len = n_bytes - 3 - len(chunk)
        ps = bytearray()
        while len(ps) < ps_len:
            byte = os.urandom(1)[0]
            if byte != 0:  # PKCS#1 v1.5 kuralı: dolgu byte'ları asla 0x00 olamaz
                ps.append(byte)

        padded = b'\x00\x02' + bytes(ps) + b'\x00' + chunk
        m = int.from_bytes(padded, 'big')
        c = pow(m, e, n)
        cipher_blocks.append(str(c))

    return cipher_blocks


def decrypt(private_key, cipher_blocks):
    """encrypt() ile üretilmiş blok listesini çözüp orijinal metni döner."""
    d, n = private_key
    n_bytes = _byte_length(n)
    plain_bytes = b''

    for c_str in cipher_blocks:
        c = int(c_str)
        m = pow(c, d, n)
        mb = m.to_bytes(n_bytes, 'big')

        if mb[0] != 0 or mb[1] != 2:
            raise ValueError("Geçersiz PKCS#1 dolgusu (yanlış anahtar veya bozuk veri).")

        try:
            sep_index = mb.index(0, 2)
        except ValueError:
            raise ValueError("Dolgu sonlandırıcı bulunamadı (bozuk veri).")

        plain_bytes += mb[sep_index + 1:]

    return plain_bytes.decode('utf-8')


def serialize_key(key) -> dict:
    """(e veya d, n) tuple'ını JSON üzerinden JS tarafına hassasiyet kaybı
    olmadan taşımak için string alanlı bir sözlüğe çevirir.
    (2048-bit sayılar JS Number tipinin çok üzerindedir; istemci tarafında
    BigInt() ile geri parse edilecek.)"""
    value, n = key
    return {"value": str(value), "n": str(n)}
