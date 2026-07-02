# import base64
# import os
# from flask import Flask, render_template, request
# from flask_socketio import SocketIO, emit, join_room
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad
# from datetime import datetime
# from flask_socketio import leave_room
# from dotenv import load_dotenv

# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'crypto_simulator_secret'
# socketio = SocketIO(app, cors_allowed_origins="*")

# AES_KEY = b'1234567890123456'
# ACTIVE_ROOMS = {} 
# ROOM_USERS = {}  # 🆕 Odadaki kullanıcıların tam / gizli isimlerini takip etmek için

# def caesar_encrypt(text, shift=4):
#     result = ""
#     for char in text:
#         if char.isupper(): result += chr((ord(char) + shift - 65) % 26 + 65)
#         elif char.islower(): result += chr((ord(char) + shift - 97) % 26 + 97)
#         else: result += char
#     return result

# def aes_encrypt(text):
#     iv = os.urandom(16)
#     cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
#     padded_text = pad(text.encode('utf-8'), AES.block_size)
#     encrypted_bytes = cipher.encrypt(padded_text)
#     return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

# # 🔑 RSA Asimetrik Şifreleme Simülasyonu
# def rsa_encrypt_sim(text):
#     # Gerçek RSA'i taklit eden, sunumda asimetrik yapıyı göstermek için Base64/Hex tabanlı simüle şifre üretici
#     encoded_text = text.encode('utf-8')
#     hex_fake_rsa = base64.b16encode(encoded_text).decode('utf-8')
#     return f"RSA_PUB_KEY_ENC[{hex_fake_rsa[:24]}...]"

# @app.route('/')
# def index():
#     return render_template('index.html')

# def broadcast_rooms():
#     emit('rooms_list', ACTIVE_ROOMS, broadcast=True)

# @socketio.on('get_initial_rooms')
# def handle_initial_rooms():
#     emit('rooms_list', ACTIVE_ROOMS)

# @socketio.on('create_room')
# def handle_create_room(data):
#     room_name = data['room_name']
#     password = data['password']
#     algo = data['algo']
    
#     if room_name in ACTIVE_ROOMS:
#         emit('error', {'msg': 'Room already exists!', 'side': 'left'})
#         return

#     ACTIVE_ROOMS[room_name] = {
#         'password': password,
#         'algo': algo
#     }

#     broadcast_rooms()
#     emit('room_created_success', {'room_name': room_name})

# # ✅ ÇAKIŞMA ÖNLEYİCİLİ YENİ JOIN FONKSİYONU
# @socketio.on('join')
# def handle_join(data):
#     username = data['username'] # Bu veri "Sıla G" olarak geliyor
#     room_name = data.get('room_name', 'chat_room')
#     is_hacker = data.get('is_hacker', False)
#     password = data.get('password', '')

#     if is_hacker:
#         join_room("hacker_room")
#         emit('status', {'msg': f'🕵️ Network tap established. Intercepting packets as "{username}"...'}, room="hacker_room")
#         return

#     if room_name in ACTIVE_ROOMS:
#         if ACTIVE_ROOMS[room_name]['password'] != password:
#             emit('error', {'msg': 'Wrong room password!', 'side': 'right'})
#             return
#     else:
#         emit('error', {'msg': 'Room does not exist!', 'side': 'right'})
#         return

#     # 🆕 AYNI İSİM ÇAKIŞMA KONTROL MOTORU
#     if room_name not in ROOM_USERS:
#         ROOM_USERS[room_name] = []
    
#     # Eğer bu isim odada zaten varsa, arkada gizli bir sayı türetelim
#     internal_name = username
#     counter = 2
#     while internal_name in ROOM_USERS[room_name]:
#         internal_name = f"{username}_{counter}" # Örn: "Sıla G._2"
#         counter += 1
    
#     # Kullanıcıyı odaya ekle
#     ROOM_USERS[room_name].append(internal_name)

#     join_room(room_name)
#     emit('join_confirmed', {'unique_username': internal_name}, room=request.sid)

#     # Ekranda yine temiz isim ("Sıla G.") gözükecek
#     emit('status', {'msg': f'{username} entered the secure chat room.'}, room=room_name)
#     emit('status', {'msg': f'📡 Traffic Alert: New target ({username}) connected to room: {room_name}.'}, room="hacker_room")
# @socketio.on('message')
# def handle_message(data):
    
#     # Verinin içinden oda bilgisini güvenle çekiyoruz
#     room_name = data.get('room_name') or data.get('room') or 'chat_room'
#     current_time = datetime.now().strftime("%H:%M")
#     data['time'] = current_time
   
#     # Sunucu veriyi açmadan, bozmadan doğrudan odaya paslar
#     data['is_hacker_data'] = False
#     emit('message', data, room=room_name)
    
#     # Hacker odasına gönder
#     data['is_hacker_data'] = True
#     emit('message', data, room="hacker_room")
# if __name__ == '__main__':
#     socketio.run(app, debug=True, port=5000)
#     socketio.run
    

# @socketio.on('leave')
# def handle_leave(data):
#     room = data.get('room_name')
#     username = data.get('username')
#     if room:
#         leave_room(room)
#         emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)
import base64
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime

# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret')

# AES anahtarı .env'den gelir
_raw_key = os.getenv('AES_KEY', '')
if len(_raw_key) < 16:
    raise ValueError("AES_KEY en az 16 karakter olmalı! .env dosyasını kontrol et.")
AES_KEY = _raw_key[:16].encode('utf-8')

socketio = SocketIO(app, cors_allowed_origins="*")

ACTIVE_ROOMS = {}
ROOM_USERS = {}

def caesar_encrypt(text, shift=4):
    result = ""
    for char in text:
        if char.isupper(): result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower(): result += chr((ord(char) + shift - 97) % 26 + 97)
        else: result += char
    return result

def aes_encrypt(text):
    iv = os.urandom(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    padded_text = pad(text.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

def rsa_visual_demo(text):
    """
    ⚠️ Bu gerçek RSA DEĞİLDİR!
    Sadece asimetrik şifreleme mantığını görselleştirmek için yapılmış demo fonksiyondur.
    """
    encoded_text = text.encode('utf-8')
    hex_fake_rsa = base64.b16encode(encoded_text).decode('utf-8')
    return f"RSA_PUB_KEY_ENC[{hex_fake_rsa[:24]}...]"

@app.route('/')
def index():
    return render_template('index.html')

def broadcast_rooms():
    emit('rooms_list', ACTIVE_ROOMS, broadcast=True)

@socketio.on('get_initial_rooms')
def handle_initial_rooms():
    emit('rooms_list', ACTIVE_ROOMS)

@socketio.on('create_room')
def handle_create_room(data):
    room_name = data['room_name']
    password = data['password']
    algo = data['algo']

    if room_name in ACTIVE_ROOMS:
        emit('error', {'msg': 'Room already exists!', 'side': 'left'})
        return

    # Şifreyi hash'leyerek sakla
    import hashlib
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    ACTIVE_ROOMS[room_name] = {
        'password': password,         # Oda listesinde göstermek için (PIN badge)
        'password_hash': password_hash, # Güvenli karşılaştırma için
        'algo': algo
    }

    broadcast_rooms()
    emit('room_created_success', {'room_name': room_name})

@socketio.on('join')
def handle_join(data):
    username = data['username']
    room_name = data.get('room_name', 'chat_room')
    is_hacker = data.get('is_hacker', False)
    password = data.get('password', '')

    if is_hacker:
        join_room("hacker_room")
        emit('status', {'msg': f'🕵️ Network tap established. Intercepting packets as "{username}"...'}, room="hacker_room")
        return

    if room_name not in ACTIVE_ROOMS:
        emit('error', {'msg': 'Room does not exist!', 'side': 'right'})
        return

    # Hash ile karşılaştır
    import hashlib
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

    join_room(room_name)
    emit('join_confirmed', {'unique_username': internal_name}, room=request.sid)
    emit('status', {'msg': f'{username} entered the secure chat room.'}, room=room_name)
    emit('status', {'msg': f'📡 Traffic Alert: New target ({username}) connected to room: {room_name}.'}, room="hacker_room")

@socketio.on('message')
def handle_message(data):
    room_name = data.get('room_name') or data.get('room') or 'chat_room'
    current_time = datetime.now().strftime("%H:%M")
    data['time'] = current_time

    data['is_hacker_data'] = False
    emit('message', data, room=room_name)

    data['is_hacker_data'] = True
    emit('message', data, room="hacker_room")

@socketio.on('leave')
def handle_leave(data):
    room = data.get('room_name')
    username = data.get('username')
    if room:
        # Kullanıcıyı ROOM_USERS listesinden temizle
        if room in ROOM_USERS and username in ROOM_USERS[room]:
            ROOM_USERS[room].remove(username)
        leave_room(room)
        emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)