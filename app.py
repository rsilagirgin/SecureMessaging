import base64
import os
from flask import Flask, render_template
from flask_socketio import SocketIO, emit, join_room
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)
app.config['SECRET_KEY'] = 'crypto_simulator_secret'
socketio = SocketIO(app, cors_allowed_origins="*")

AES_KEY = b'1234567890123456'
ACTIVE_ROOMS = {} 

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

# 🔑 RSA Asimetrik Şifreleme Simülasyonu
def rsa_encrypt_sim(text):
    # Gerçek RSA'i taklit eden, sunumda asimetrik yapıyı göstermek için Base64/Hex tabanlı simüle şifre üretici
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

    ACTIVE_ROOMS[room_name] = {
        'password': password,
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

    if room_name in ACTIVE_ROOMS:
        if ACTIVE_ROOMS[room_name]['password'] != password:
            emit('error', {'msg': 'Wrong room password!', 'side': 'right'})
            return
    else:
        emit('error', {'msg': 'Room does not exist!', 'side': 'right'})
        return

    join_room(room_name)
    emit('status', {'msg': f'{username} entered the secure chat room.'}, room=room_name)
    emit('status', {'msg': f'📡 Traffic Alert: New target ({username}) connected to room: {room_name}.'}, room="hacker_room")

@socketio.on('message')
def handle_message(data):
    # Verinin içinden oda bilgisini güvenle çekiyoruz
    room_name = data.get('room_name') or data.get('room') or 'chat_room'
    
    # Sunucu veriyi açmadan, bozmadan doğrudan odaya paslar
    data['is_hacker_data'] = False
    emit('message', data, room=room_name)
    
    # Hacker odasına gönder
    data['is_hacker_data'] = True
    emit('message', data, room="hacker_room")
if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)