from dotenv import load_dotenv
import base64
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


# passw.env dosyasındaki değişkenleri çevre değişkeni olarak yükler
load_dotenv(dotenv_path="passw.env")
AES_KEY = os.getenv('AES_KEY').encode()
ACTIVE_ROOMS = {}
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
socketio = SocketIO(app, cors_allowed_origins="*")

users_db = {
    "admin": {
        "password": generate_password_hash("admin123"),
        "is_admin": True
    }
}


AES_KEY = os.getenv('AES_KEY').encode()
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
    hex_fake_rsa = base64.b16encode(text.encode('utf-8')).decode('utf-8')
    return f"RSA_PUB_KEY_ENC[{hex_fake_rsa[:24]}...]"

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
    
    if not username:
        emit('error', {'msg': 'Username required!'})
        return

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
    # --- KULLANICI GİRİŞ ROTASI ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users_db.get(username)
        # Kullanıcı var mı ve yazdığı şifre doğru mu kontrolü
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            session['is_admin'] = user.get('is_admin', False)
            return redirect(url_for('index')) # Doğruysa mesajlaşmaya yönlendir
        else:
            flash('Geçersiz kullanıcı adı veya şifre!')
            
    return render_template('login.html')

# --- ADMİN GİRİŞ ROTASI ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users_db.get(username)
        # Sadece admin yetkisi olanlar girebilir
        if user and user.get('is_admin') and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Hatalı admin kullanıcı adı veya şifre!')
            
    return render_template('admin_login.html')

# --- ADMİN PANELİ (KULLANICI OLUŞTURMA) ---
@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    # Güvenlik Kontrolü: Giriş yapmamış veya admin olmayan biriyse erişimi engelle
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
        
    if request.method == 'POST':
        new_username = request.form.get('new_username')
        new_password = request.form.get('new_password')
        
        if new_username in users_db:
            flash('Bu kullanıcı zaten mevcut!')
        else:
            # Yeni kullanıcıyı şifresini hash'leyerek listeye ekle
            users_db[new_username] = {
                "password": generate_password_hash(new_password),
                "is_admin": False
            }
            flash(f'{new_username} başarıyla oluşturuldu!')
            
    return render_template('admin_dashboard.html', users=users_db)

# --- ÇIKIŞ YAPMA ROTASI ---
@app.route('/logout')
def logout():
    session.clear() # Oturumu sıfırla
    return redirect(url_for('login'))

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)