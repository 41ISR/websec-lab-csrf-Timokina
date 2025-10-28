from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import sqlite3
import uuid
import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['DATABASE'] = 'csrf_lab.db'

def init_db():
    """Инициализация базы данных"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Таблица пользователей
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT,
            bio TEXT,
            balance REAL DEFAULT 100.0,
            status TEXT DEFAULT 'standard',
            avatar_url TEXT,
            privacy_settings TEXT DEFAULT 'public',
            two_fa_enabled BOOLEAN DEFAULT FALSE,
            api_key TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Таблица транзакций
    c.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT NOT NULL,
            amount REAL,
            description TEXT,
            target_user TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Таблица поддержки
    c.execute('''
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            subject TEXT,
            message TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db():
    """Получение соединения с БД"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def add_transaction(user_id, transaction_type, amount=None, description="", target_user=""):
    """Добавление транзакции в историю"""
    db = get_db()
    db.execute(
        'INSERT INTO transactions (user_id, type, amount, description, target_user) VALUES (?, ?, ?, ?, ?)',
        (user_id, transaction_type, amount, description, target_user)
    )
    db.commit()
    db.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('profile'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        db = get_db()
        
        try:
            hashed_password = generate_password_hash(password)
            db.execute(
                'INSERT INTO users (username, password, email, balance) VALUES (?, ?, ?, ?)',
                (username, hashed_password, email, 100.0)
            )
            db.commit()
            
            # Автоматический вход после регистрации
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            add_transaction(user['id'], 'registration_bonus', 100.0, "Стартовый бонус")
            
            return redirect(url_for('profile'))
            
        except sqlite3.IntegrityError:
            return "Пользователь уже существует"
        finally:
            db.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('profile'))
        else:
            return "Неверные учетные данные"
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Получаем историю транзакций
    transactions = db.execute(
        'SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10',
        (session['user_id'],)
    ).fetchall()
    
    db.close()
    
    return render_template('profile.html', user=user, transactions=transactions)

# === УЯЗВИМЫЕ ЭНДПОИНТЫ ===

@app.route('/update-profile', methods=['GET', 'POST'])
def update_profile():
    """Уязвимый эндпоинт - нет CSRF защиты"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        bio = request.form.get('bio')
        
        db = get_db()
        db.execute(
            'UPDATE users SET email = ?, phone = ?, address = ?, bio = ? WHERE id = ?',
            (email, phone, address, bio, session['user_id'])
        )
        db.commit()
        db.close()
        
        add_transaction(session['user_id'], 'profile_update', description="Обновление профиля")
        return redirect(url_for('profile'))
    
    return "Используйте POST запрос"

@app.route('/update-preferences', methods=['POST'])
def update_preferences():
    """Уязвимый эндпоинт - смена статуса аккаунта"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    status = request.form.get('status', 'standard')
    
    db = get_db()
    db.execute(
        'UPDATE users SET status = ? WHERE id = ?',
        (status, session['user_id'])
    )
    db.commit()
    db.close()
    
    add_transaction(session['user_id'], 'status_change', description=f"Смена статуса на {status}")
    return redirect(url_for('profile'))

@app.route('/change-password', methods=['POST'])
def change_password():
    """Уязвимый эндпоинт - смена пароля"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    new_password = request.form.get('new_password')
    
    db = get_db()
    hashed_password = generate_password_hash(new_password)
    db.execute(
        'UPDATE users SET password = ? WHERE id = ?',
        (hashed_password, session['user_id'])
    )
    db.commit()
    db.close()
    
    add_transaction(session['user_id'], 'password_change', description="Смена пароля")
    return "Пароль изменен"

@app.route('/toggle-2fa', methods=['POST'])
def toggle_2fa():
    """Уязвимый эндпоинт - включение/выключение 2FA"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    new_state = not user['two_fa_enabled']
    
    db.execute(
        'UPDATE users SET two_fa_enabled = ? WHERE id = ?',
        (new_state, session['user_id'])
    )
    db.commit()
    db.close()
    
    action = "включена" if new_state else "выключена"
    add_transaction(session['user_id'], '2fa_toggle', description=f"2FA {action}")
    return f"2FA {action}"

@app.route('/transfer', methods=['POST'])
def transfer():
    """Уязвимый эндпоинт - перевод денег"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    amount = float(request.form.get('amount', 0))
    target_user = request.form.get('target_user')
    comment = request.form.get('comment', '')
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['balance'] >= amount:
        # Уменьшаем баланс текущего пользователя
        db.execute(
            'UPDATE users SET balance = balance - ? WHERE id = ?',
            (amount, session['user_id'])
        )
        
        # Увеличиваем баланс целевого пользователя (если существует)
        target = db.execute('SELECT * FROM users WHERE username = ?', (target_user,)).fetchone()
        if target:
            db.execute(
                'UPDATE users SET balance = balance + ? WHERE username = ?',
                (amount, target_user)
            )
        
        db.commit()
        db.close()
        
        add_transaction(session['user_id'], 'transfer_out', -amount, 
                       f"Перевод {target_user}: {comment}", target_user)
        return f"Перевод {amount} руб. пользователю {target_user} выполнен"
    
    db.close()
    return "Недостаточно средств"

@app.route('/add-funds', methods=['POST'])
def add_funds():
    """Уязвимый эндпоинт - пополнение баланса"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    amount = float(request.form.get('amount', 0))
    
    db = get_db()
    db.execute(
        'UPDATE users SET balance = balance + ? WHERE id = ?',
        (amount, session['user_id'])
    )
    db.commit()
    db.close()
    
    add_transaction(session['user_id'], 'add_funds', amount, "Пополнение баланса")
    return f"Баланс пополнен на {amount} руб."

@app.route('/update-avatar', methods=['POST'])
def update_avatar():
    """Уязвимый эндпоинт - обновление аватара"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    avatar_url = request.form.get('avatar_url')
    
    db = get_db()
    db.execute(
        'UPDATE users SET avatar_url = ? WHERE id = ?',
        (avatar_url, session['user_id'])
    )
    db.commit()
    db.close()
    
    add_transaction(session['user_id'], 'avatar_update', description="Смена аватара")
    return "Аватар обновлен"

@app.route('/privacy-settings', methods=['POST'])
def privacy_settings():
    """Уязвимый эндпоинт - настройки приватности"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    privacy = request.form.get('privacy', 'public')
    
    db = get_db()
    db.execute(
        'UPDATE users SET privacy_settings = ? WHERE id = ?',
        (privacy, session['user_id'])
    )
    db.commit()
    db.close()
    
    add_transaction(session['user_id'], 'privacy_change', description=f"Приватность: {privacy}")
    return "Настройки приватности обновлены"

@app.route('/submit-ticket', methods=['POST'])
def submit_ticket():
    """Уязвимый эндпоинт - отправка тикета в поддержку"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    subject = request.form.get('subject')
    message = request.form.get('message')
    
    db = get_db()
    db.execute(
        'INSERT INTO support_tickets (user_id, subject, message) VALUES (?, ?, ?)',
        (session['user_id'], subject, message)
    )
    db.commit()
    db.close()
    
    add_transaction(session['user_id'], 'support_ticket', description=f"Тикет: {subject}")
    return "Тикет отправлен в поддержку"

@app.route('/generate-api-key', methods=['POST'])
def generate_api_key():
    """Уязвимый эндпоинт - генерация API ключа"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    api_key = str(uuid.uuid4())
    
    db = get_db()
    db.execute(
        'UPDATE users SET api_key = ? WHERE id = ?',
        (api_key, session['user_id'])
    )
    db.commit()
    db.close()
    
    add_transaction(session['user_id'], 'api_key_generate', description="Генерация API ключа")
    return f"Новый API ключ: {api_key}"

@app.route('/delete-account', methods=['POST'])
def delete_account():
    """Уязвимый эндпоинт - удаление аккаунта"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (session['user_id'],))
    db.commit()
    db.close()
    
    session.clear()
    return "Аккаунт удален"

# === JSON API ЭНДПОИНТЫ ===

@app.route('/api/profile')
def api_profile():
    """API для получения данных профиля"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    db.close()
    
    return jsonify(dict(user))

@app.route('/api/update-email', methods=['POST'])
def api_update_email():
    """Уязвимый JSON API эндпоинт"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data'}), 400
    
    email = data.get('email')
    
    db = get_db()
    db.execute(
        'UPDATE users SET email = ? WHERE id = ?',
        (email, session['user_id'])
    )
    db.commit()
    db.close()
    
    add_transaction(session['user_id'], 'email_update', description="Смена email через API")
    return jsonify({'status': 'Email updated'})

@app.route('/api/transfer', methods=['POST'])
def api_transfer():
    """Уязвимый JSON API для переводов"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data'}), 400
    
    amount = float(data.get('amount', 0))
    target_user = data.get('target_user')
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['balance'] >= amount:
        db.execute(
            'UPDATE users SET balance = balance - ? WHERE id = ?',
            (amount, session['user_id'])
        )
        db.commit()
        db.close()
        
        add_transaction(session['user_id'], 'transfer_out', -amount, 
                       f"API перевод {target_user}", target_user)
        return jsonify({'status': f'Transfer {amount} to {target_user} completed'})
    
    db.close()
    return jsonify({'error': 'Insufficient funds'}), 400

@app.route('/exploit')
def exploit():
    """Страница с примерами эксплойтов"""
    return render_template('exploit.html')

@app.route('/tasks')
def tasks():
    """Страница с заданиями для студентов"""
    return render_template('tasks.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
