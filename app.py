import hashlib
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
from ciphers.caesar import generate_caesar_shift
from ciphers.aes_utils import generate_room_salt

# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret')

socketio = SocketIO(app, cors_allowed_origins="*")

ACTIVE_ROOMS = {}
ROOM_USERS = {}
SID_USER_MAP = {}


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


@socketio.on('create_room')
def handle_create_room(data):
    room_name = data['room_name']
    password = data['password']
    algo = data['algo']
    creator = data.get('username', 'Unknown')

    shift = None
    aes_salt = None

    if algo == "caesar":
        shift = generate_caesar_shift()
    elif algo == "aes":
        aes_salt = generate_room_salt()

    if room_name in ACTIVE_ROOMS:
        emit('error', {'msg': 'Room already exists!', 'side': 'left'})
        return

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    ACTIVE_ROOMS[room_name] = {
        'password': password,
        'password_hash': password_hash,
        'algo': algo,
        'creator': creator,
        'shift': shift,
        'aes_salt': aes_salt,
        'time': datetime.now().strftime("%H:%M")
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

    join_room(room_name)

    room = ACTIVE_ROOMS[room_name]

    emit('join_confirmed', {
        'unique_username': internal_name,
        'shift': room['shift'],
        'aes_salt': room.get('aes_salt'),
    }, room=request.sid)
    emit('status', {'msg': f'{username} entered the secure chat room.'}, room=room_name)
    emit('status', {'msg': f'📡 Traffic Alert: New target ({username}) connected to room: {room_name}.'}, room="hacker_room")


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

    if room:
        if room in ROOM_USERS and username in ROOM_USERS[room]:
            ROOM_USERS[room].remove(username)

        leave_room(room)
        emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

        if room in ROOM_USERS and len(ROOM_USERS[room]) == 0:
            del ROOM_USERS[room]
            if room in ACTIVE_ROOMS:
                del ACTIVE_ROOMS[room]
            broadcast_rooms()


@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    username = SID_USER_MAP.pop(sid, None)
    if not username:
        return

    for room in list(ROOM_USERS.keys()):
        if username in ROOM_USERS[room]:
            ROOM_USERS[room].remove(username)
            emit('status', {'msg': f'ℹ️ {username} has left the room.'}, room=room)

            if len(ROOM_USERS[room]) == 0:
                del ROOM_USERS[room]
                if room in ACTIVE_ROOMS:
                    del ACTIVE_ROOMS[room]
                broadcast_rooms()
            break


if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
