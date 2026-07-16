# # import hashlib
# # import os
# # from dotenv import load_dotenv
# # from flask import Flask, render_template, request
# # from flask_socketio import SocketIO, emit, join_room, leave_room
# # from datetime import datetime
# # from ciphers.caesar import generate_caesar_shift
# # from ciphers.aes_utils import generate_room_salt
# # from ciphers.rsa import generate_rsa_keypair, serialize_key

# # # .env dosyasını yükle
# # load_dotenv()

# # app = Flask(__name__)
# # app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret')

# # socketio = SocketIO(app, cors_allowed_origins="*")

# # ACTIVE_ROOMS = {}
# # ROOM_USERS = {}
# # SID_USER_MAP = {}


# # @app.route('/')
# # def index():
# #     return render_template('index.html')


# # def broadcast_rooms():
# #     # Oda listesini herkese yayınlarken şifreyi (password) ASLA gönderme,
# #     # sadece hash'ini de değil, hiçbirini. Arayüz sadece isim/algo/kurucu/saat gösteriyor.
# #     safe_rooms = {
# #         name: {
# #             'algo': info['algo'],
# #             'creator': info['creator'],
# #             'time': info['time'],
# #         }
# #         for name, info in ACTIVE_ROOMS.items()
# #     }
# #     emit('rooms_list', safe_rooms, broadcast=True)


# # @socketio.on('get_initial_rooms')
# # def handle_initial_rooms():
# #     safe_rooms = {
# #         name: {
# #             'algo': info['algo'],
# #             'creator': info['creator'],
# #             'time': info['time'],
# #         }
# #         for name, info in ACTIVE_ROOMS.items()
# #     }
# #     emit('rooms_list', safe_rooms)


# # @socketio.on('create_room')
# # def handle_create_room(data):
# #     room_name = data['room_name']
# #     password = data['password']
# #     algo = data['algo']
# #     creator = data.get('username', 'Unknown')

# #     shift = None
# #     aes_salt = None
# #     rsa_public = None
# #     rsa_private = None

# #     if algo == "caesar":
# #         shift = generate_caesar_shift()
# #     elif algo == "aes":
# #         aes_salt = generate_room_salt()
# #     elif algo == "rsa":
# #         rsa_public, rsa_private = generate_rsa_keypair()

# #     if room_name in ACTIVE_ROOMS:
# #         emit('error', {'msg': 'Room already exists!', 'side': 'left'})
# #         return

# #     password_hash = hashlib.sha256(password.encode()).hexdigest()

# #     ACTIVE_ROOMS[room_name] = {
# #         # 'password': password,
# #         'password_hash': password_hash,
# #         'algo': algo,
# #         'creator': creator,
# #         'shift': shift,
# #         'aes_salt': aes_salt,
# #         'rsa_public': rsa_public,
# #         'rsa_private': rsa_private,
# #         'time': datetime.now().strftime("%H:%M")
# #     }
# #     broadcast_rooms()
# #     emit('room_created_success', {'room_name': room_name})


# # @socketio.on('join')
# # def handle_join(data):
# #     username = data['username']
# #     room_name = data.get('room_name', 'chat_room')
# #     is_hacker = data.get('is_hacker', False)
# #     password = data.get('password', '')

# #     if is_hacker:
# #         join_room("hacker_room")
# #         emit('status', {'msg': f'🕵️ Network tap established. Intercepting packets as "{username}"...'}, room="hacker_room")
# #         return

# #     if room_name not in ACTIVE_ROOMS:
# #         emit('error', {'msg': 'Room does not exist!', 'side': 'right'})
# #         return

# #     entered_hash = hashlib.sha256(password.encode()).hexdigest()
# #     if ACTIVE_ROOMS[room_name]['password_hash'] != entered_hash:
# #         emit('error', {'msg': 'Wrong room password!', 'side': 'right'})
# #         return

# #     # Çakışma önleyici isim motoru
# #     if room_name not in ROOM_USERS:
# #         ROOM_USERS[room_name] = []

# #     internal_name = username
# #     counter = 2
# #     while internal_name in ROOM_USERS[room_name]:
# #         internal_name = f"{username}_{counter}"
# #         counter += 1

# #     ROOM_USERS[room_name].append(internal_name)
# #     SID_USER_MAP[request.sid] = internal_name

# #     join_room(room_name)

# #     room = ACTIVE_ROOMS[room_name]

# #     # RSA anahtarları büyük tam sayılar içerebildiğinden (JS Number hassasiyet
# #     # sınırını aşabilir), istemciye string alanlı sözlük olarak gönderiliyor
# #     # (bkz. ciphers/rsa_utils.py -> serialize_key, static/js/rsa.js -> parseRSAKey).
# #     rsa_public_payload = serialize_key(room['rsa_public']) if room.get('rsa_public') else None
# #     rsa_private_payload = serialize_key(room['rsa_private']) if room.get('rsa_private') else None

# #     emit('join_confirmed', {
# #         'unique_username': internal_name,
# #         'shift': room['shift'],
# #         'aes_salt': room.get('aes_salt'),
# #         'rsa_public': rsa_public_payload,
# #         'rsa_private': rsa_private_payload,
# #     }, room=request.sid)
# #     emit('status', {'msg': f'{username} entered the secure chat room.'}, room=room_name)
# #     emit('status', {'msg': f'📡 Traffic Alert: New target ({username}) connected to room: {room_name}.'}, room="hacker_room")


# # @socketio.on('message')
# # def handle_message(data):
# #     room_name = data.get('room_name') or data.get('room') or 'chat_room'
# #     current_time = datetime.now().strftime("%H:%M")
# #     current_date = datetime.now().strftime("%d.%m.%Y")
# #     data['time'] = current_time
# #     data['date'] = current_date
# #     data['is_hacker_data'] = False
# #     emit('message', data, room=room_name)

# #     data['is_hacker_data'] = True
# #     emit('message', data, room="hacker_room")


# # @socketio.on('leave')
# # def handle_leave(data):
# #     room = data.get('room_name')
# #     username = data.get('username')

# #     if room:
# #         if room in ROOM_USERS and username in ROOM_USERS[room]:
# #             ROOM_USERS[room].remove(username)

# #         leave_room(room)
# #         emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

# #         if room in ROOM_USERS and len(ROOM_USERS[room]) == 0:
# #             del ROOM_USERS[room]
# #             if room in ACTIVE_ROOMS:
# #                 del ACTIVE_ROOMS[room]
# #             broadcast_rooms()


# # @socketio.on('disconnect')
# # def handle_disconnect():
# #     sid = request.sid
# #     username = SID_USER_MAP.pop(sid, None)
# #     if not username:
# #         return

# #     for room in list(ROOM_USERS.keys()):
# #         if username in ROOM_USERS[room]:
# #             ROOM_USERS[room].remove(username)
# #             emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

# #             if len(ROOM_USERS[room]) == 0:
# #                 del ROOM_USERS[room]
# #                 if room in ACTIVE_ROOMS:
# #                     del ACTIVE_ROOMS[room]
# #                 broadcast_rooms()
# #             break


# # if __name__ == '__main__':
# #     socketio.run(app, debug=True, port=5000)

# import hashlib
# import os
# from dotenv import load_dotenv
# from flask import Flask, render_template, request
# from flask_socketio import SocketIO, emit, join_room, leave_room
# from datetime import datetime
# from ciphers.caesar import generate_caesar_shift
# from ciphers.aes_utils import generate_room_salt
# from ciphers.rsa import generate_rsa_keypair, serialize_key

# # .env dosyasını yükle
# load_dotenv()

# app = Flask(__name__)
# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret')

# socketio = SocketIO(app, cors_allowed_origins="*")

# ACTIVE_ROOMS = {}
# ROOM_USERS = {}
# SID_USER_MAP = {}


# @app.route('/')
# def index():
#     return render_template('index.html')


# def broadcast_rooms():
#     # Oda listesini herkese yayınlarken şifreyi (password) ASLA gönderme,
#     # sadece hash'ini de değil, hiçbirini. Arayüz sadece isim/algo/kurucu/saat gösteriyor.
#     safe_rooms = {
#         name: {
#             'algo': info['algo'],
#             'creator': info['creator'],
#             'time': info['time'],
#         }
#         for name, info in ACTIVE_ROOMS.items()
#     }
#     emit('rooms_list', safe_rooms, broadcast=True)


# @socketio.on('get_initial_rooms')
# def handle_initial_rooms():
#     safe_rooms = {
#         name: {
#             'algo': info['algo'],
#             'creator': info['creator'],
#             'time': info['time'],
#         }
#         for name, info in ACTIVE_ROOMS.items()
#     }
#     emit('rooms_list', safe_rooms)


# @socketio.on('create_room')
# def handle_create_room(data):
#     room_name = data['room_name']
#     password = data['password']
#     algo = data['algo']
#     creator = data.get('username', 'Unknown')

#     shift = None
#     aes_salt = None
#     rsa_public = None
#     rsa_private = None

#     if algo == "caesar":
#         shift = generate_caesar_shift()
#     elif algo == "aes":
#         aes_salt = generate_room_salt()
#     elif algo == "rsa":
#         rsa_public, rsa_private = generate_rsa_keypair()

#     if room_name in ACTIVE_ROOMS:
#         emit('error', {'msg': 'Room already exists!', 'side': 'left'})
#         return

#     password_hash = hashlib.sha256(password.encode()).hexdigest()

#     ACTIVE_ROOMS[room_name] = {
#         # 'password': password,
#         'password_hash': password_hash,
#         'algo': algo,
#         'creator': creator,
#         'shift': shift,
#         'aes_salt': aes_salt,
#         'rsa_public': rsa_public,
#         'rsa_private': rsa_private,
#         'time': datetime.now().strftime("%H:%M")
#     }
#     print(f"[CREATE_ROOM] Oda '{room_name}' oluşturuldu (algo={algo}). "
#           f"Aktif odalar: {list(ACTIVE_ROOMS.keys())}")
#     broadcast_rooms()
#     emit('room_created_success', {'room_name': room_name})


# @socketio.on('join')
# def handle_join(data):
#     username = data['username']
#     room_name = data.get('room_name', 'chat_room')
#     is_hacker = data.get('is_hacker', False)
#     password = data.get('password', '')

#     if is_hacker:
#         join_room("hacker_room")
#         emit('status', {'msg': f'🕵️ Network tap established. Intercepting packets as "{username}"...'}, room="hacker_room")
#         return

#     if room_name not in ACTIVE_ROOMS:
#         emit('error', {'msg': 'Room does not exist!', 'side': 'right'})
#         return

#     entered_hash = hashlib.sha256(password.encode()).hexdigest()
#     if ACTIVE_ROOMS[room_name]['password_hash'] != entered_hash:
#         emit('error', {'msg': 'Wrong room password!', 'side': 'right'})
#         return

#     # Çakışma önleyici isim motoru
#     if room_name not in ROOM_USERS:
#         ROOM_USERS[room_name] = []

#     internal_name = username
#     counter = 2
#     while internal_name in ROOM_USERS[room_name]:
#         internal_name = f"{username}_{counter}"
#         counter += 1

#     ROOM_USERS[room_name].append(internal_name)
#     SID_USER_MAP[request.sid] = internal_name
#     print(f"[JOIN] {internal_name!r} odaya katıldı -> room={room_name!r}, sid={request.sid}. "
#           f"ROOM_USERS['{room_name}']={ROOM_USERS[room_name]}")

#     join_room(room_name)

#     room = ACTIVE_ROOMS[room_name]

#     # RSA anahtarları büyük tam sayılar içerebildiğinden (JS Number hassasiyet
#     # sınırını aşabilir), istemciye string alanlı sözlük olarak gönderiliyor
#     # (bkz. ciphers/rsa_utils.py -> serialize_key, static/js/rsa.js -> parseRSAKey).
#     rsa_public_payload = serialize_key(room['rsa_public']) if room.get('rsa_public') else None
#     rsa_private_payload = serialize_key(room['rsa_private']) if room.get('rsa_private') else None

#     emit('join_confirmed', {
#         'unique_username': internal_name,
#         'shift': room['shift'],
#         'aes_salt': room.get('aes_salt'),
#         'rsa_public': rsa_public_payload,
#         'rsa_private': rsa_private_payload,
#     }, room=request.sid)
#     emit('status', {'msg': f'{username} entered the secure chat room.'}, room=room_name)
#     emit('status', {'msg': f'📡 Traffic Alert: New target ({username}) connected to room: {room_name}.'}, room="hacker_room")


# @socketio.on('message')
# def handle_message(data):
#     room_name = data.get('room_name') or data.get('room') or 'chat_room'
#     current_time = datetime.now().strftime("%H:%M")
#     current_date = datetime.now().strftime("%d.%m.%Y")
#     data['time'] = current_time
#     data['date'] = current_date
#     data['is_hacker_data'] = False
#     emit('message', data, room=room_name)

#     data['is_hacker_data'] = True
#     emit('message', data, room="hacker_room")


# @socketio.on('leave')
# def handle_leave(data):
#     room = data.get('room_name')
#     username = data.get('username')
#     print(f"[LEAVE] event geldi -> room={room!r}, username={username!r}")

#     if room:
#         if room in ROOM_USERS and username in ROOM_USERS[room]:
#             ROOM_USERS[room].remove(username)
#             print(f"[LEAVE] {username!r} ROOM_USERS['{room}']'dan çıkarıldı. Kalan: {ROOM_USERS.get(room)}")
#         else:
#             print(f"[LEAVE] UYARI: {username!r} ROOM_USERS['{room}'] içinde bulunamadı! "
#                   f"Mevcut ROOM_USERS: {ROOM_USERS}")

#         leave_room(room)
#         emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

#         if room in ROOM_USERS and len(ROOM_USERS[room]) == 0:
#             del ROOM_USERS[room]
#             if room in ACTIVE_ROOMS:
#                 del ACTIVE_ROOMS[room]
#                 print(f"[LEAVE] Oda '{room}' boşaldığı için silindi.")
#             broadcast_rooms()
#         else:
#             print(f"[LEAVE] Oda '{room}' silinmedi çünkü hâlâ kullanıcı var veya "
#                   f"ROOM_USERS içinde yok: {ROOM_USERS.get(room)}")
#     else:
#         print(f"[LEAVE] UYARI: 'room_name' verisi boş geldi! data={data}")


# @socketio.on('disconnect')
# def handle_disconnect():
#     sid = request.sid
#     username = SID_USER_MAP.pop(sid, None)
#     print(f"[DISCONNECT] sid={sid} -> username={username!r} "
#           f"(SID_USER_MAP boyutu şimdi: {len(SID_USER_MAP)})")
#     if not username:
#         print("[DISCONNECT] UYARI: Bu sid için SID_USER_MAP'te kayıt yoktu "
#               "(kullanıcı hiç 'join' etmemiş olabilir, örn. lobide kapattı).")
#         return

#     found = False
#     for room in list(ROOM_USERS.keys()):
#         if username in ROOM_USERS[room]:
#             found = True
#             ROOM_USERS[room].remove(username)
#             print(f"[DISCONNECT] {username!r} ROOM_USERS['{room}']'dan çıkarıldı. "
#                   f"Kalan: {ROOM_USERS.get(room)}")
#             emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

#             if len(ROOM_USERS[room]) == 0:
#                 del ROOM_USERS[room]
#                 if room in ACTIVE_ROOMS:
#                     del ACTIVE_ROOMS[room]
#                     print(f"[DISCONNECT] Oda '{room}' boşaldığı için silindi.")
#                 broadcast_rooms()
#             break
#     if not found:
#         print(f"[DISCONNECT] UYARI: {username!r} hiçbir ROOM_USERS listesinde bulunamadı. "
#               f"Mevcut ROOM_USERS: {ROOM_USERS}")


# if __name__ == '__main__':
#     socketio.run(app, debug=True, port=5000)

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
        print(f"[AKIS] Kart taraması başarısız: {e}")
        emit('akis_slots_error', {'msg': str(e)})
        return

    print(f"[AKIS] {len(tokens)} kart bulundu.")
    emit('akis_slots', {'tokens': tokens})


@socketio.on('akis_login')
def handle_akis_login(data):
    slot_id = data.get('slot_id')
    pin = data.get('pin', '')

    if slot_id is None or not pin:
        emit('akis_login_result', {'success': False, 'msg': 'Kart veya PIN eksik.'})
        return

    try:
        info = akis_pkcs11.login(slot_id, pin, request.sid)
        print(f"[AKIS] sid={request.sid} slot={slot_id} ile giriş başarılı "
              f"({info['owner_first']} {info['owner_last']}).")
        emit('akis_login_result', {
            'success': True,
            'owner_first': info['owner_first'],
            'owner_last': info['owner_last'],
            'label': info['label'],
        })
    except RuntimeError as e:
        print(f"[AKIS] sid={request.sid} slot={slot_id} giriş hatası: {e}")
        emit('akis_login_result', {'success': False, 'msg': str(e)})


@socketio.on('akis_logout')
def handle_akis_logout():
    akis_pkcs11.logout(request.sid)


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
    print(f"[CREATE_ROOM] Oda '{room_name}' oluşturuldu (algo={algo}). "
          f"Aktif odalar: {list(ACTIVE_ROOMS.keys())}")
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
        emit('status', {'msg': f'🕵️ Network tap established. Intercepting packets as "{username}"...'}, room="hacker_room")
        return

    if room_name not in ACTIVE_ROOMS:
        emit('error', {'msg': 'Room does not exist!', 'side': 'right'})
        return

    entered_hash = hashlib.sha256(password.encode()).hexdigest()
    if ACTIVE_ROOMS[room_name]['password_hash'] != entered_hash:
        emit('error', {'msg': 'Wrong room password!', 'side': 'right'})
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
    print(f"[JOIN] {internal_name!r} odaya katıldı -> room={room_name!r}, sid={request.sid}. "
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
    emit('status', {'msg': f'📡 Traffic Alert: New target ({username}) connected to room: {room_name}.'}, room="hacker_room")

    # --- GERÇEK E2EE: sadece public key kaydedilip dağıtılır, private key
    # hiçbir zaman sunucuya gelmediği için burada da görünmez. ---
    if room.get('algo') == 'e2ee' and public_key_jwk:
        ROOM_PUBKEYS.setdefault(room_name, {})[internal_name] = public_key_jwk
        print(f"[E2EE] {internal_name!r} public key gönderdi -> room={room_name!r}. "
              f"Odadaki toplam public key sayısı: {len(ROOM_PUBKEYS[room_name])}")
        emit('room_pubkeys', ROOM_PUBKEYS[room_name], room=room_name)


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


@socketio.on('leave')
def handle_leave(data):
    room = data.get('room_name')
    username = data.get('username')
    print(f"[LEAVE] event geldi -> room={room!r}, username={username!r}")

    if room:
        if room in ROOM_USERS and username in ROOM_USERS[room]:
            ROOM_USERS[room].remove(username)
            print(f"[LEAVE] {username!r} ROOM_USERS['{room}']'dan çıkarıldı. Kalan: {ROOM_USERS.get(room)}")
        else:
            print(f"[LEAVE] UYARI: {username!r} ROOM_USERS['{room}'] içinde bulunamadı! "
                  f"Mevcut ROOM_USERS: {ROOM_USERS}")

        # E2EE odasıysa: ayrılan kişinin public key'ini de sözlükten sil ve
        # odada kalanlara güncel (artık o kişiyi içermeyen) listeyi gönder,
        # böylece yeni mesajlar ayrılan kişi için şifrelenmeye çalışılmaz.
        if room in ROOM_PUBKEYS and username in ROOM_PUBKEYS[room]:
            del ROOM_PUBKEYS[room][username]
            if ROOM_PUBKEYS[room]:
                emit('room_pubkeys', ROOM_PUBKEYS[room], room=room)
            else:
                del ROOM_PUBKEYS[room]

        leave_room(room)
        emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

        if room in ROOM_USERS and len(ROOM_USERS[room]) == 0:
            del ROOM_USERS[room]
            if room in ACTIVE_ROOMS:
                del ACTIVE_ROOMS[room]
                print(f"[LEAVE] Oda '{room}' boşaldığı için silindi.")
            if room in ROOM_PUBKEYS:
                del ROOM_PUBKEYS[room]
            broadcast_rooms()
        else:
            print(f"[LEAVE] Oda '{room}' silinmedi çünkü hâlâ kullanıcı var veya "
                  f"ROOM_USERS içinde yok: {ROOM_USERS.get(room)}")
    else:
        print(f"[LEAVE] UYARI: 'room_name' verisi boş geldi! data={data}")


@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid

    # Bağlantı kapanınca, bu sekmeye ait açık bir AKİS oturumu varsa
    # kartı "logout" edip kapatıyoruz — aksi halde kart PIN doğrulanmış
    # durumda kilitli kalabilir.
    akis_pkcs11.logout(sid)

    username = SID_USER_MAP.pop(sid, None)
    print(f"[DISCONNECT] sid={sid} -> username={username!r} "
          f"(SID_USER_MAP boyutu şimdi: {len(SID_USER_MAP)})")
    if not username:
        print("[DISCONNECT] UYARI: Bu sid için SID_USER_MAP'te kayıt yoktu "
              "(kullanıcı hiç 'join' etmemiş olabilir, örn. lobide kapattı).")
        return

    found = False
    for room in list(ROOM_USERS.keys()):
        if username in ROOM_USERS[room]:
            found = True
            ROOM_USERS[room].remove(username)
            print(f"[DISCONNECT] {username!r} ROOM_USERS['{room}']'dan çıkarıldı. "
                  f"Kalan: {ROOM_USERS.get(room)}")
            emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

            if room in ROOM_PUBKEYS and username in ROOM_PUBKEYS[room]:
                del ROOM_PUBKEYS[room][username]
                if ROOM_PUBKEYS[room]:
                    emit('room_pubkeys', ROOM_PUBKEYS[room], room=room)
                else:
                    del ROOM_PUBKEYS[room]

            if len(ROOM_USERS[room]) == 0:
                del ROOM_USERS[room]
                if room in ACTIVE_ROOMS:
                    del ACTIVE_ROOMS[room]
                    print(f"[DISCONNECT] Oda '{room}' boşaldığı için silindi.")
                if room in ROOM_PUBKEYS:
                    del ROOM_PUBKEYS[room]
                broadcast_rooms()
            break
    if not found:
        print(f"[DISCONNECT] UYARI: {username!r} hiçbir ROOM_USERS listesinde bulunamadı. "
              f"Mevcut ROOM_USERS: {ROOM_USERS}")


if __name__ == '__main__':
    #socketio.run(app, debug=True, port=5000)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)