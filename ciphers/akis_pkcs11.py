import os
import threading

try:
    import PyKCS11
    from PyKCS11 import PyKCS11Error
    PYKCS11_AVAILABLE = True
except ImportError:
    PYKCS11_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Windows'ta AKİS PKCS#11 kütüphanesinin varsayılan yolu.
# .env içinde AKIS_PKCS11_LIB ile override edilebilir
# (örn. 32-bit Python kullanıyorsan SysWOW64 altındaki sürüm gerekir).
DEFAULT_AKIS_LIB_PATHS = [
    r"C:\Windows\System32\akisp11.dll",
    r"C:\Windows\SysWOW64\akisp11.dll",
]

_lib_lock = threading.Lock()
_pkcs11 = None          # PyKCS11.PyKCS11Lib() singleton
_lib_load_error = None  # yükleme başarısız olduysa hata mesajı burada tutulur

# request.sid -> {'session': PyKCS11.Session, 'slot_id': int}
# Her sekme/bağlantı için ayrı bir PKCS#11 oturumu tutulur.
ACTIVE_SESSIONS = {}


def _resolve_lib_path():
    configured = os.getenv("AKIS_PKCS11_LIB")
    if configured:
        return configured
    for path in DEFAULT_AKIS_LIB_PATHS:
        if os.path.exists(path):
            return path
    # Hiçbiri bulunamadıysa yine de ilk yolu dene; hata mesajı kullanıcıya
    # doğru yolu .env'e yazması gerektiğini söyleyecek.
    return DEFAULT_AKIS_LIB_PATHS[0]


def _get_lib():
    """PyKCS11 kütüphanesini (akisp11.dll) tek seferlik yükler."""
    global _pkcs11, _lib_load_error

    if not PYKCS11_AVAILABLE:
        raise RuntimeError(
            "PyKCS11 package is not installed. To install: pip install PyKCS11"
        )

    with _lib_lock:
        if _pkcs11 is not None:
            return _pkcs11
        if _lib_load_error is not None:
            raise RuntimeError(_lib_load_error)

        lib_path = _resolve_lib_path()
        try:
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(lib_path)
            _pkcs11 = pkcs11
            return _pkcs11
        except Exception as e:
            _lib_load_error = (
                f"Could not load the AKIS PKCS#11 library ({lib_path}). "
                f"Check whether the AKIS Card Software is installed and the card reader is plugged in. "
                f"If it is in a different location, add AKIS_PKCS11_LIB=<full path> to the .env file. "
                f"Details: {e}"
            )
            raise RuntimeError(_lib_load_error)


def _extract_public_key(session):
    """
    Oturumdaki (login gerektirmeyen) X.509 sertifikasından kartın GERÇEK
    RSA public key'ini (e, n) okur. Bu, kartın zaten kullandığı asıl
    şifreleme anahtarıdır — 'akis' oda modu bu anahtarı kullanır.

    Private key hiçbir zaman buradan okunmaz/çıkarılmaz; sadece public
    kısım (e, n) döner ve serialize_key ile aynı JSON biçiminde
    ({'value': str(e), 'n': str(n)}) istemciye gönderilebilir.

    Okunamazsa None döner (arayüz bu durumda 'akis' modunu kullanamaz).
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return None
    try:
        cert_objs = session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
        )
        if not cert_objs:
            return None
        der_bytes = bytes(
            session.getAttributeValue(cert_objs[0], [PyKCS11.CKA_VALUE])[0]
        )
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        public_key = cert.public_key()
        numbers = public_key.public_numbers()
        return {"value": str(numbers.e), "n": str(numbers.n)}
    except Exception:
        return None


def _extract_owner_name(session):
    """
    Oturumdaki (login gerektirmeyen, herkese açık) X.509 sertifikasından
    kart sahibinin adını okumaya çalışır. Sertifikalar PKCS#11'de genelde
    PIN olmadan da okunabilir (public objects).
    Bulamazsa (None, None) döner — arayüz bu durumda kart etiketini gösterir.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return None, None
    try:
        cert_objs = session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
        )
        if not cert_objs:
            return None, None

        der_bytes = bytes(
            session.getAttributeValue(cert_objs[0], [PyKCS11.CKA_VALUE])[0]
        )
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        cn_attr = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not cn_attr:
            return None, None
        full_name = cn_attr[0].value.strip()
        parts = full_name.split(" ", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return full_name, ""
    except Exception:
        return None, None


def list_akis_tokens():
    """
    Şu anda takılı olan TÜM AKİS kartlarını (birden fazla okuyucu/kart
    takılıysa hepsini) listeler. Her biri için PIN gerekmeden okunabilen
    genel bilgiyi (etiket + varsa sertifikadan isim) döner.

    Dönüş: [{ 'slot_id': int, 'label': str, 'owner_first': str|None,
               'owner_last': str|None }]
    """
    pkcs11 = _get_lib()
    slots = pkcs11.getSlotList(tokenPresent=True)

    tokens = []
    for slot_id in slots:
        try:
            token_info = pkcs11.getTokenInfo(slot_id)
            label = token_info.label.strip()
        except Exception:
            label = f"Slot {slot_id}"

        owner_first, owner_last = None, None
        try:
            # Sertifika bilgisini okumak için geçici, login'siz bir oturum aç.
            probe_session = pkcs11.openSession(slot_id, PyKCS11.CKF_SERIAL_SESSION)
            owner_first, owner_last = _extract_owner_name(probe_session)
            probe_session.closeSession()
        except Exception:
            pass

        tokens.append({
            "slot_id": slot_id,
            "label": label,
            "owner_first": owner_first,
            "owner_last": owner_last,
        })

    return tokens


def login(slot_id, pin, sid):
    """
    Verilen slot'taki karta PIN ile giriş yapar (C_Login). Oturumu `sid`
    (socket bağlantı kimliği) altında ACTIVE_SESSIONS içinde saklar ki
    aynı sekme daha sonra logout/decrypt gibi işlemler için tekrar kullanabilsin.

    Başarılı olursa: { 'owner_first', 'owner_last', 'label' } döner.
    Yanlış PIN / kilitli kart gibi durumlarda RuntimeError fırlatır,
    mesajı kullanıcıya gösterilebilecek şekilde Türkçe ve nettir.
    """
    pkcs11 = _get_lib()

    # Aynı sekme için açık bir oturum varsa önce temizle.
    logout(sid)

    try:
        session = pkcs11.openSession(
            slot_id, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
    except Exception as e:
        raise RuntimeError(f"Could not open a session with the card reader: {e}")

    try:
        session.login(pin)
    except PyKCS11Error as e:
        session.closeSession()
        err = str(e)
        if "CKR_PIN_INCORRECT" in err:
            raise RuntimeError("Incorrect PIN.")
        if "CKR_PIN_LOCKED" in err:
            raise RuntimeError("Card PIN is locked. Use the AKIS Card Software to unlock the card.")
        raise RuntimeError(f"Login failed: {err}")
    except Exception as e:
        session.closeSession()
        raise RuntimeError(f"Login failed: {e}")

    owner_first, owner_last = _extract_owner_name(session)
    public_key = _extract_public_key(session)
    try:
        label = pkcs11.getTokenInfo(slot_id).label.strip()
    except Exception:
        label = f"Slot {slot_id}"

    ACTIVE_SESSIONS[sid] = {
        "session": session,
        "slot_id": slot_id,
        "public_key": public_key,
    }

    return {
        "owner_first": owner_first or "AKIS User",
        "owner_last": owner_last or "",
        "label": label,
    }


def logout(sid):
    """Bu sekmeye ait açık PKCS#11 oturumu varsa kapatır (login iptali)."""
    entry = ACTIVE_SESSIONS.pop(sid, None)
    if not entry:
        return
    try:
        entry["session"].logout()
    except Exception:
        pass
    try:
        entry["session"].closeSession()
    except Exception:
        pass


def is_logged_in(sid):
    """Bu socket bağlantısının (sid) şu anda kartla giriş yapmış, aktif bir
    PKCS#11 oturumu var mı? 'akis' oda moduna giriş/oda kurma izni burada
    kontrol edilir."""
    return sid in ACTIVE_SESSIONS


def get_public_key(sid):
    """Bu sid için daha önce login() sırasında karttan okunmuş RSA public
    key'i ({'value','n'}) döner, yoksa None."""
    entry = ACTIVE_SESSIONS.get(sid)
    if not entry:
        return None
    return entry.get("public_key")


def decrypt_with_card(sid, cipher_blocks):
    """
    'akis' odasında bir kullanıcıya sarılmış (kartın public key'iyle RSA
    ile şifrelenmiş) küçük bir veriyi (AES oturum anahtarı), doğrudan
    KART ÜZERİNDE (C_Decrypt, CKM_RSA_PKCS) çözer.

    Private key kart dışına ASLA çıkmaz; bu yüzden bu işlem
    (rsa.py/rsa.js'teki gibi Python/JS içinde değil) sadece kartın
    fiziksel olarak takılı ve oturumun (PIN ile) açık olduğu backend'de
    yapılabilir. Oturum kapalıysa/kart yoksa RuntimeError fırlatılır —
    bu da 'sadece AKİS kartıyla giriş yapanlar mesaj okuyabilir' kuralının
    kriptografik olarak zorlanmasını sağlar.

    Dönüş: çözülmüş ham bayt dizisi (utf-8 metne decode edilebilir).
    """
    entry = ACTIVE_SESSIONS.get(sid)
    if not entry:
        raise RuntimeError("There is no active AKIS card session. Please log in with your card again.")

    public_key = entry.get("public_key")
    if not public_key:
        raise RuntimeError("The card's public key could not be read.")

    n = int(public_key["n"])
    n_bytes = (n.bit_length() + 7) // 8

    session = entry["session"]
    try:
        priv_objs = session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]
        )
        if not priv_objs:
            raise RuntimeError("No private key found on the card.")
        priv_key = priv_objs[0]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS)

        plain_parts = []
        for c_str in cipher_blocks:
            # Ondalık string ciphertext'i, modulus uzunluğunda (n_bytes)
            # büyük-endian bir bayt dizisine çevir (PKCS#11 ham bayt bekler).
            c_bytes = int(c_str).to_bytes(n_bytes, "big")
            decrypted = session.decrypt(priv_key, c_bytes, mechanism)
            plain_parts.append(bytes(decrypted))
        return b"".join(plain_parts)
    except RuntimeError:
        raise
    except PyKCS11Error as e:
        raise RuntimeError(f"Card decryption failed: {e}")
    except Exception as e:
        raise RuntimeError(f"Card decryption failed: {e}")


def get_present_slot_ids():
    """Şu anda fiziksel olarak takılı (token present) tüm slot id'lerini
    döner. Kart çıkarılma algılaması için periyodik olarak çağrılır;
    kütüphane yüklenemezse (okuyucu bağlı değilse vs.) boş küme döner."""
    try:
        pkcs11 = _get_lib()
        return set(pkcs11.getSlotList(tokenPresent=True))
    except Exception:
        return set()


def get_active_sids():
    """Şu anda aktif (login olmuş) bir kart oturumu olan tüm sid'lerin
    anlık bir kopyasını döner."""
    return list(ACTIVE_SESSIONS.keys())


def get_slot_for_sid(sid):
    """Bu sid'in login olduğu slot_id'yi döner, oturum yoksa None."""
    entry = ACTIVE_SESSIONS.get(sid)
    return entry.get("slot_id") if entry else None


def is_available():
    """Sunucu makinesinde AKİS PKCS#11 desteğinin kullanılabilir olup olmadığını
    (kütüphane yüklenebiliyor mu) hızlıca kontrol eder. Hata fırlatmaz."""
    try:
        _get_lib()
        return True, None
    except Exception as e:
        return False, str(e)