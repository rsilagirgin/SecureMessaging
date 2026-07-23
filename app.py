import hashlib
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
from ciphers.caesar import generate_caesar_shift
from ciphers.aes_utils import generate_room_salt
from ciphers.rsa import generate_rsa_keypair, serialize_key
from ciphers import akis_pkcs11

# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret')

socketio = SocketIO(app, cors_allowed_origins="*")

ACTIVE_ROOMS = {}
ROOM_USERS = {}
SID_USER_MAP = {}
# E2EE odalarında kullanıcı adı -> public key (JWK) eşlemesi.
# ÖNEMLİ: burada SADECE public key'ler tutulur. Private key hiçbir zaman
# sunucuya gelmez, bu yüzden sunucu E2EE mesajlarını asla çözemez.
ROOM_PUBKEYS = {}

# 'akis' odalarında kullanıcı adı -> kartın GERÇEK RSA public key'i
# ({'value','n'}), akis_pkcs11.get_public_key() ile karttan okunur.
# Private key hiçbir zaman burada tutulmaz; sadece kartın kendisi
# (PKCS#11 oturumu üzerinden) mesaj çözebilir, bkz. 'akis_decrypt_request'.
ROOM_AKIS_PUBKEYS = {}


@app.route('/')
def index():
    return render_template('index.html')


def broadcast_rooms():
    # Oda listesini herkese yayınlarken şifreyi (password) ASLA gönderme,
    # sadece hash'ini de değil, hiçbirini. Arayüz sadece isim/algo/kurucu/saat gösteriyor.
    safe_rooms = {
        name: {
            'algo': info['algo'],
            'creator': info['creator'],
            'time': info['time'],
        }
        for name, info in ACTIVE_ROOMS.items()
    }
    emit('rooms_list', safe_rooms, broadcast=True)


@socketio.on('get_initial_rooms')
def handle_initial_rooms():
    safe_rooms = {
        name: {
            'algo': info['algo'],
            'creator': info['creator'],
            'time': info['time'],
        }
        for name, info in ACTIVE_ROOMS.items()
    }
    emit('rooms_list', safe_rooms)


# ===========================================================================
# 🪪 AKIS KART İLE GİRİŞ (gerçek donanım — PKCS#11 üzerinden)
#
# Tarayıcı akıllı karta doğrudan erişemediği için bu iş tamamen burada,
# backend'de yapılır. PIN sadece C_Login çağrısında kullanılır, hiçbir
# yerde saklanmaz/loglanmaz. Private key kartın dışına ASLA çıkmaz.
# ===========================================================================

@socketio.on('get_akis_slots')
def handle_get_akis_slots():
    try:
        tokens = akis_pkcs11.list_akis_tokens()
    except Exception as e:
        print(f"[AKIS] Card scan failed: {e}")
        emit('akis_slots_error', {'msg': str(e)})
        return

    print(f"[AKIS] {len(tokens)} kart bulundu.")
    emit('akis_slots', {'tokens': tokens})


@socketio.on('akis_login')
def handle_akis_login(data):
    slot_id = data.get('slot_id')
    pin = data.get('pin', '')

    if slot_id is None or not pin:
        emit('akis_login_result', {'success': False, 'msg': 'Card or PIN missing.'})
        return

    try:
        info = akis_pkcs11.login(slot_id, pin, request.sid)
        print(f"[AKIS] sid={request.sid} slot={slot_id} login successful "
              f"({info['owner_first']} {info['owner_last']}).")
        emit('akis_login_result', {
            'success': True,
            'owner_first': info['owner_first'],
            'owner_last': info['owner_last'],
            'label': info['label'],
        })
    except RuntimeError as e:
        print(f"[AKIS] sid={request.sid} slot={slot_id} login error: {e}")
        emit('akis_login_result', {'success': False, 'msg': str(e)})


@socketio.on('akis_logout')
def handle_akis_logout():
    akis_pkcs11.logout(request.sid)


@socketio.on('akis_decrypt_request')
def handle_akis_decrypt_request(data):
    """
    'akis' odasındaki bir mesajın, GÖNDERİCİ tarafından bizim kartımızın
    public key'iyle sarılmış AES oturum anahtarını, doğrudan kart üzerinde
    (PKCS#11 C_Decrypt) çözer ve sonucu (base64) istemciye döner.

    Bu bir Socket.IO 'ack' (callback) isteğidir: değer return edilerek
    istemcinin socket.emit(..., callback) fonksiyonuna iletilir. Şifre
    çözme işlemi SADECE bu sid için o an açık bir kart oturumu varsa
    başarılı olur — böylece kart çıkarılınca/oturum kapanınca mesajlar
    da otomatik olarak okunamaz hale gelir.
    """
    blocks = (data or {}).get('blocks') or []
    try:
        plain_bytes = akis_pkcs11.decrypt_with_card(request.sid, blocks)
        return {'success': True, 'key_b64': plain_bytes.decode('utf-8')}
    except RuntimeError as e:
        return {'success': False, 'msg': str(e)}
    except Exception as e:
        return {'success': False, 'msg': f'Unexpected error: {e}'}


@socketio.on('leave_hacker_room')
def handle_leave_hacker_room():
    """Kullanıcı Hacker View'dan çıktığında istemci bu olayı gönderir.
    Aksi halde socket bağlantısı (SPA olduğu için sayfa yenilenmez)
    'hacker_room' Socket.IO odasında üye kalmaya devam eder ve kullanıcı
    normal bir sohbet odasına dönse bile hacker_room'a broadcast edilen
    '📡 Traffic Alert' gibi mesajları almaya devam eder."""
    leave_room("hacker_room")
    print(f"[HACKER] sid={request.sid} left 'hacker_room'.")


@socketio.on('create_room')
def handle_create_room(data):
    room_name = data['room_name']
    password = data['password']
    algo = data['algo']
    creator = data.get('username', 'Unknown')

    shift = None
    aes_salt = None
    rsa_public = None
    rsa_private = None

    if algo == "caesar":
        shift = generate_caesar_shift()
    elif algo == "aes":
        aes_salt = generate_room_salt()
    elif algo == "rsa":
        rsa_public, rsa_private = generate_rsa_keypair()
    elif algo == "akis":
        # 'akis' odası, kartın ZATEN sahip olduğu RSA anahtarını kullanır
        # (server burada anahtar üretmez). Bu yüzden sadece o an aktif bir
        # AKİS kart oturumu olan (PIN ile login olmuş) bağlantılar böyle
        # bir oda kurabilir.
        if not akis_pkcs11.is_logged_in(request.sid):
            emit('error', {
                'msg': 'To create an AKIS card room you must first log in with your AKIS card.',
                'side': 'left',
            })
            return

    if room_name in ACTIVE_ROOMS:
        emit('error', {'msg': 'Room already exists!', 'side': 'left'})
        return

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    ACTIVE_ROOMS[room_name] = {
        # 'password': password,
        'password_hash': password_hash,
        'algo': algo,
        'creator': creator,
        'shift': shift,
        'aes_salt': aes_salt,
        'rsa_public': rsa_public,
        'rsa_private': rsa_private,
        'time': datetime.now().strftime("%H:%M")
    }
    print(f"[CREATE_ROOM] Room '{room_name}' created (algo={algo}). "
          f"Active rooms: {list(ACTIVE_ROOMS.keys())}")
    broadcast_rooms()
    emit('room_created_success', {'room_name': room_name})


@socketio.on('join')
def handle_join(data):
    username = data['username']
    room_name = data.get('room_name', 'chat_room')
    is_hacker = data.get('is_hacker', False)
    password = data.get('password', '')
    public_key_jwk = data.get('public_key')  # sadece E2EE odalarında dolu gelir

    if is_hacker:
        join_room("hacker_room")
        emit('status', {
            'msg': f'🕵️ Network tap established. Intercepting packets as "{username}"...',
            'is_hacker_data': True,
        }, room="hacker_room")
        return

    if room_name not in ACTIVE_ROOMS:
        emit('error', {'msg': 'Room does not exist!', 'side': 'right'})
        return

    entered_hash = hashlib.sha256(password.encode()).hexdigest()
    if ACTIVE_ROOMS[room_name]['password_hash'] != entered_hash:
        emit('error', {'msg': 'Wrong room password!', 'side': 'right'})
        return

    # 🪪 'akis' odaları sadece o an aktif bir AKİS kart oturumu (PIN ile
    # login olmuş) olan bağlantılara açıktır. Bu kontrol, kullanıcı
    # ROOM_USERS/ROOM listelerine eklenmeden ÖNCE yapılır ki reddedilen
    # bir bağlantı odada "hayalet" bir üye olarak kalmasın.
    if ACTIVE_ROOMS[room_name].get('algo') == 'akis' and not akis_pkcs11.is_logged_in(request.sid):
        emit('error', {
            'msg': 'This room is AKIS-card only. Please log in with your card to join.',
            'side': 'right',
        })
        return

    # Çakışma önleyici isim motoru
    if room_name not in ROOM_USERS:
        ROOM_USERS[room_name] = []

    internal_name = username
    counter = 2
    while internal_name in ROOM_USERS[room_name]:
        internal_name = f"{username}_{counter}"
        counter += 1

    ROOM_USERS[room_name].append(internal_name)
    SID_USER_MAP[request.sid] = internal_name
    print(f"[JOIN] {internal_name!r} joined the room -> room={room_name!r}, sid={request.sid}. "
          f"ROOM_USERS['{room_name}']={ROOM_USERS[room_name]}")

    join_room(room_name)

    room = ACTIVE_ROOMS[room_name]

    # RSA anahtarları büyük tam sayılar içerebildiğinden (JS Number hassasiyet
    # sınırını aşabilir), istemciye string alanlı sözlük olarak gönderiliyor
    # (bkz. ciphers/rsa_utils.py -> serialize_key, static/js/rsa.js -> parseRSAKey).
    rsa_public_payload = serialize_key(room['rsa_public']) if room.get('rsa_public') else None
    rsa_private_payload = serialize_key(room['rsa_private']) if room.get('rsa_private') else None

    emit('join_confirmed', {
        'unique_username': internal_name,
        'shift': room['shift'],
        'aes_salt': room.get('aes_salt'),
        'rsa_public': rsa_public_payload,
        'rsa_private': rsa_private_payload,
    }, room=request.sid)
    emit('status', {'msg': f'{username} entered the secure chat room.'}, room=room_name)
    emit('status', {
        'msg': f'📡 Traffic Alert: New target ({username}) connected to room: {room_name}.',
        'is_hacker_data': True,
    }, room="hacker_room")

    # --- GERÇEK E2EE: sadece public key kaydedilip dağıtılır, private key
    # hiçbir zaman sunucuya gelmediği için burada da görünmez. ---
    if room.get('algo') == 'e2ee' and public_key_jwk:
        ROOM_PUBKEYS.setdefault(room_name, {})[internal_name] = public_key_jwk
        print(f"[E2EE] {internal_name!r} sent a public key -> room={room_name!r}. "
              f"Total public keys in room: {len(ROOM_PUBKEYS[room_name])}")
        emit('room_pubkeys', ROOM_PUBKEYS[room_name], room=room_name)

    # --- 🪪 AKİS ODASI: gönderen tarayıcı değil, sunucu bu public key'i
    # doğrudan karttan (login sırasında okunmuş haliyle) alır ve odaya
    # dağıtır. Private key hâlâ kart dışına çıkmaz; sadece kart, mesaj
    # çözme isteklerini 'akis_decrypt_request' üzerinden karşılayabilir. ---
    if room.get('algo') == 'akis':
        akis_public_key = akis_pkcs11.get_public_key(request.sid)
        if akis_public_key:
            ROOM_AKIS_PUBKEYS.setdefault(room_name, {})[internal_name] = akis_public_key
            print(f"[AKIS] {internal_name!r} registered their card's public key -> room={room_name!r}. "
                  f"Total in room: {len(ROOM_AKIS_PUBKEYS[room_name])}")
            emit('room_akis_pubkeys', ROOM_AKIS_PUBKEYS[room_name], room=room_name)


@socketio.on('message')
def handle_message(data):
    room_name = data.get('room_name') or data.get('room') or 'chat_room'
    current_time = datetime.now().strftime("%H:%M")
    current_date = datetime.now().strftime("%d.%m.%Y")
    data['time'] = current_time
    data['date'] = current_date
    data['is_hacker_data'] = False
    emit('message', data, room=room_name)

    data['is_hacker_data'] = True
    emit('message', data, room="hacker_room")


@socketio.on('delete_room')
def handle_delete_room(data):
    """Oda kurucusunun, oda kendiliğinden boşalmasını beklemeden odayı
    manuel olarak silmesini sağlar. Sadece ACTIVE_ROOMS[room]['creator']
    ile eşleşen kullanıcı adına izin verilir (diğer olaylarda olduğu gibi
    doğrulama, client'ın gönderdiği username üzerinden yapılır)."""
    room_name = data.get('room_name')
    username = data.get('username')

    if not room_name or room_name not in ACTIVE_ROOMS:
        emit('error', {'msg': 'Room does not exist!', 'side': 'right'})
        return

    if ACTIVE_ROOMS[room_name].get('creator') != username:
        print(f"[DELETE_ROOM] REJECTED: {username!r} is not the creator of '{room_name}' "
              f"(creator={ACTIVE_ROOMS[room_name].get('creator')!r}).")
        emit('error', {'msg': 'Only the room creator can delete this room.', 'side': 'right'})
        return

    print(f"[DELETE_ROOM] Room '{room_name}' is being deleted by its creator ({username}).")

    # Odadaki herkese, oda silinmeden hemen önce haber ver ki istemciler
    # kendi arayüzlerini lobiye döndürebilsin.
    emit('room_deleted', {
        'room_name': room_name,
        'msg': f'🗑️ "{room_name}" room was deleted by its creator.'
    }, room=room_name)

    # Odadaki tüm bağlı soketleri sunucu tarafında da bu socket.io odasından
    # çıkar (sadece kendi sid'imiz değil, odadaki HERKES için).
    for sid, uname in list(SID_USER_MAP.items()):
        if room_name in ROOM_USERS and uname in ROOM_USERS[room_name]:
            leave_room(room_name, sid=sid)

    if room_name in ROOM_USERS:
        del ROOM_USERS[room_name]
    if room_name in ROOM_PUBKEYS:
        del ROOM_PUBKEYS[room_name]
    if room_name in ROOM_AKIS_PUBKEYS:
        del ROOM_AKIS_PUBKEYS[room_name]
    del ACTIVE_ROOMS[room_name]

    print(f"[DELETE_ROOM] Room '{room_name}' deleted. Active rooms: {list(ACTIVE_ROOMS.keys())}")
    broadcast_rooms()


@socketio.on('leave')
def handle_leave(data):
    room = data.get('room_name')
    username = data.get('username')
    print(f"[LEAVE] event received -> room={room!r}, username={username!r}")

    if room:
        if room in ROOM_USERS and username in ROOM_USERS[room]:
            ROOM_USERS[room].remove(username)
            print(f"[LEAVE] {username!r} removed from ROOM_USERS['{room}']. Remaining: {ROOM_USERS.get(room)}")
        else:
            print(f"[LEAVE] WARNING: {username!r} not found in ROOM_USERS['{room}']! "
                  f"Current ROOM_USERS: {ROOM_USERS}")

        # E2EE odasıysa: ayrılan kişinin public key'ini de sözlükten sil ve
        # odada kalanlara güncel (artık o kişiyi içermeyen) listeyi gönder,
        # böylece yeni mesajlar ayrılan kişi için şifrelenmeye çalışılmaz.
        if room in ROOM_PUBKEYS and username in ROOM_PUBKEYS[room]:
            del ROOM_PUBKEYS[room][username]
            if ROOM_PUBKEYS[room]:
                emit('room_pubkeys', ROOM_PUBKEYS[room], room=room)
            else:
                del ROOM_PUBKEYS[room]

        if room in ROOM_AKIS_PUBKEYS and username in ROOM_AKIS_PUBKEYS[room]:
            del ROOM_AKIS_PUBKEYS[room][username]
            if ROOM_AKIS_PUBKEYS[room]:
                emit('room_akis_pubkeys', ROOM_AKIS_PUBKEYS[room], room=room)
            else:
                del ROOM_AKIS_PUBKEYS[room]

        leave_room(room)
        emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

        if room in ROOM_USERS and len(ROOM_USERS[room]) == 0:
            del ROOM_USERS[room]
            if room in ACTIVE_ROOMS:
                del ACTIVE_ROOMS[room]
                print(f"[LEAVE] Room '{room}' deleted because it became empty.")
            if room in ROOM_PUBKEYS:
                del ROOM_PUBKEYS[room]
            if room in ROOM_AKIS_PUBKEYS:
                del ROOM_AKIS_PUBKEYS[room]
            broadcast_rooms()
        else:
            print(f"[LEAVE] Room '{room}' was not deleted because it still has users or "
                  f"is not in ROOM_USERS: {ROOM_USERS.get(room)}")
    else:
        print(f"[LEAVE] WARNING: 'room_name' data was empty! data={data}")


@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid

    # Bağlantı kapanınca, bu sekmeye ait açık bir AKİS oturumu varsa
    # kartı "logout" edip kapatıyoruz — aksi halde kart PIN doğrulanmış
    # durumda kilitli kalabilir.
    akis_pkcs11.logout(sid)

    username = SID_USER_MAP.pop(sid, None)
    print(f"[DISCONNECT] sid={sid} -> username={username!r} "
          f"(SID_USER_MAP size is now: {len(SID_USER_MAP)})")
    if not username:
        print("[DISCONNECT] WARNING: No entry in SID_USER_MAP for this sid "
              "(the user may have never 'join'ed, e.g. closed the tab in the lobby).")
        return

    found = False
    for room in list(ROOM_USERS.keys()):
        if username in ROOM_USERS[room]:
            found = True
            ROOM_USERS[room].remove(username)
            print(f"[DISCONNECT] {username!r} removed from ROOM_USERS['{room}']. "
                  f"Remaining: {ROOM_USERS.get(room)}")
            emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

            if room in ROOM_PUBKEYS and username in ROOM_PUBKEYS[room]:
                del ROOM_PUBKEYS[room][username]
                if ROOM_PUBKEYS[room]:
                    emit('room_pubkeys', ROOM_PUBKEYS[room], room=room)
                else:
                    del ROOM_PUBKEYS[room]

            if room in ROOM_AKIS_PUBKEYS and username in ROOM_AKIS_PUBKEYS[room]:
                del ROOM_AKIS_PUBKEYS[room][username]
                if ROOM_AKIS_PUBKEYS[room]:
                    emit('room_akis_pubkeys', ROOM_AKIS_PUBKEYS[room], room=room)
                else:
                    del ROOM_AKIS_PUBKEYS[room]

            if len(ROOM_USERS[room]) == 0:
                del ROOM_USERS[room]
                if room in ACTIVE_ROOMS:
                    del ACTIVE_ROOMS[room]
                    print(f"[DISCONNECT] Room '{room}' deleted because it became empty.")
                if room in ROOM_PUBKEYS:
                    del ROOM_PUBKEYS[room]
                if room in ROOM_AKIS_PUBKEYS:
                    del ROOM_AKIS_PUBKEYS[room]
                broadcast_rooms()
            break
    if not found:
        print(f"[DISCONNECT] WARNING: {username!r} was not found in any ROOM_USERS list. "
              f"Current ROOM_USERS: {ROOM_USERS}")


# ===========================================================================
# 🪪 AKİS KART ÇIKARILMA ALGILAMASI
#
# Tarayıcı, kartın fiziksel olarak USB okuyucudan çıkarıldığını KENDİSİ
# algılayamaz (bkz. dosyanın başındaki AKIS KART İLE GİRİŞ notu — kart
# tamamen backend'de yönetiliyor). Bu yüzden sunucu, aktif her kart
# oturumunun bağlı olduğu slot'u periyodik olarak yoklar; kart artık o
# slotta değilse:
#   1) PKCS#11 oturumu kapatılır (akis_pkcs11.logout),
#   2) kullanıcı (varsa) bulunduğu 'akis' odasından SUNUCU tarafında da
#      çıkarılır (private key zaten kartla birlikte gitti, mesaj çözmeye
#      devam edemez),
#   3) istemciye 'akis_card_removed' olayıyla haber verilir ki arayüz
#      kullanıcıyı lobiye geri döndürsün.
# ===========================================================================

def _force_leave_akis_room(sid, username, room_name):
    if room_name in ROOM_USERS and username in ROOM_USERS[room_name]:
        ROOM_USERS[room_name].remove(username)

    if room_name in ROOM_AKIS_PUBKEYS and username in ROOM_AKIS_PUBKEYS[room_name]:
        del ROOM_AKIS_PUBKEYS[room_name][username]
        if ROOM_AKIS_PUBKEYS[room_name]:
            socketio.emit('room_akis_pubkeys', ROOM_AKIS_PUBKEYS[room_name], room=room_name)
        else:
            del ROOM_AKIS_PUBKEYS[room_name]

    # flask_socketio.leave_room() bir istek bağlamı (request context) ister;
    # arka plan görevinin bunu yoktur, bu yüzden alt seviye python-socketio
    # server nesnesi doğrudan kullanılır.
    try:
        socketio.server.leave_room(sid, room_name)
    except Exception as e:
        print(f"[AKIS] sid={sid} leave_room error: {e}")

    socketio.emit('status', {'msg': f'ℹ️ {username} left the room (AKIS card removed).'}, room=room_name)
    socketio.emit('akis_card_removed', {'room_name': room_name}, room=sid)

    if room_name in ROOM_USERS and len(ROOM_USERS[room_name]) == 0:
        del ROOM_USERS[room_name]
        if room_name in ACTIVE_ROOMS:
            del ACTIVE_ROOMS[room_name]
            print(f"[AKIS] Room '{room_name}' deleted because it became empty after card removal.")
        if room_name in ROOM_AKIS_PUBKEYS:
            del ROOM_AKIS_PUBKEYS[room_name]
        broadcast_rooms_bg()


def broadcast_rooms_bg():
    """broadcast_rooms() ile aynı işi yapar, ama istek bağlamı olmayan bir
    arka plan görevinden (background task) çağrılabilir."""
    safe_rooms = {
        name: {
            'algo': info['algo'],
            'creator': info['creator'],
            'time': info['time'],
        }
        for name, info in ACTIVE_ROOMS.items()
    }
    socketio.emit('rooms_list', safe_rooms)


def monitor_akis_cards():
    """Sürekli çalışan arka plan görevi: her ~2 saniyede bir, o an aktif
    olan tüm AKİS kart oturumlarının slot'unu, hâlâ fiziksel olarak takılı
    olup olmadığına göre kontrol eder."""
    while True:
        socketio.sleep(2)
        try:
            present_slots = akis_pkcs11.get_present_slot_ids()
        except Exception as e:
            print(f"[AKIS] Card presence check failed: {e}")
            continue

        for sid in akis_pkcs11.get_active_sids():
            slot_id = akis_pkcs11.get_slot_for_sid(sid)
            if slot_id is None or slot_id in present_slots:
                continue

            print(f"[AKIS] sid={sid} slot={slot_id}: card no longer present, ending session.")
            akis_pkcs11.logout(sid)

            username = SID_USER_MAP.get(sid)
            if not username:
                continue

            for room_name in list(ROOM_USERS.keys()):
                if username in ROOM_USERS[room_name] and ACTIVE_ROOMS.get(room_name, {}).get('algo') == 'akis':
                    _force_leave_akis_room(sid, username, room_name)


if __name__ == '__main__':
    socketio.start_background_task(monitor_akis_cards)
    #socketio.run(app, debug=True, port=5000)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    