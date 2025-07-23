from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, send_file
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import shutil
import threading
import time
import uuid
from werkzeug.utils import secure_filename
import psutil
from mcrcon import MCRcon
import random
import socket
import datetime
from telegram_bot import send_telegram_notification

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Замени на свой ключ в продакшене
ORDERS_FILE = 'orders.json'
USERS_FILE = 'users.json'

# Загружаем тарифы из файла или используем дефолтные
def load_tariffs():
    """Загрузить тарифы из файла"""
    tariffs_file = 'tariffs.json'
    if os.path.exists(tariffs_file):
        with open(tariffs_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return [
        {'name': 'Бесплатный', 'price': 0, 'ram': '1GB', 'slots': 5},
        {'name': 'Базовый', 'price': 200, 'ram': '2GB', 'slots': 10},
        {'name': 'Стандарт', 'price': 400, 'ram': '4GB', 'slots': 30},
        {'name': 'Премиум', 'price': 800, 'ram': '8GB', 'slots': 100},
    ]

TARIFFS = load_tariffs()

SERVER_BASE_DIR = 'server'
SERVER_JAR = 'server.jar'

# Глобальный словарь для хранения процессов
server_processes = {}

# Глобальный словарь для хранения времени запуска серверов
server_start_times = {}

def load_orders():
    if not os.path.exists(ORDERS_FILE):
        return []
    with open(ORDERS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_order(order):
    orders = load_orders()
    # Добавляю уникальный order_id
    order['order_id'] = str(uuid.uuid4())
    # Добавляю rcon-параметры
    order['rcon'] = {'host': '127.0.0.1', 'port': 25575, 'password': '123qwe'}
    # Назначаем уникальный порт
    order['server_port'] = find_free_port()
    orders.append(order)
    with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(orders, f, ensure_ascii=False, indent=2)

def save_orders(orders):
    with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(orders, f, ensure_ascii=False, indent=2)

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_user(user):
    users = load_users()
    users.append(user)
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def find_user(email):
    users = load_users()
    for u in users:
        if u['email'] == email:
            return u
    return None

def get_order_dir(order):
    return os.path.abspath(os.path.join(SERVER_BASE_DIR, order['order_id']))

def get_server_jar_path(order):
    return os.path.abspath(os.path.join(get_order_dir(order), SERVER_JAR))

def get_pid_path(order):
    return os.path.abspath(os.path.join(get_order_dir(order), 'server.pid'))

def get_log_path(order):
    return os.path.abspath(os.path.join(get_order_dir(order), 'logs', 'latest.log'))

def ensure_server_dir(order):
    order_dir = get_order_dir(order)
    if not os.path.exists(order_dir):
        os.makedirs(order_dir)
    jar_dst = get_server_jar_path(order)
    if not os.path.exists(jar_dst):
        shutil.copyfile(os.path.abspath(os.path.join(SERVER_BASE_DIR, SERVER_JAR)), jar_dst)
    # Создать папку logs, если нет
    logs_dir = os.path.join(order_dir, 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

def get_used_ports():
    orders = load_orders()
    return set(o.get('server_port') for o in orders if o.get('server_port'))

def find_free_port():
    used_ports = get_used_ports()
    for _ in range(100):
        port = random.randint(25566, 30000)
        if port not in used_ports:
            # Проверим, что порт не занят системой
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', port)) != 0:
                    return port
    raise Exception('Не удалось найти свободный порт')

def set_server_port(order, port):
    props_path = os.path.join(get_order_dir(order), 'server.properties')
    lines = []
    if os.path.exists(props_path):
        with open(props_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    found = False
    for i, line in enumerate(lines):
        if line.startswith('server-port='):
            lines[i] = f'server-port={port}\n'
            found = True
            break
    if not found:
        lines.append(f'server-port={port}\n')
    with open(props_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

def start_minecraft_server(order):
    ensure_server_dir(order)
    ram = order['tariff_params']['ram'].replace('GB', 'G')
    jar_path = get_server_jar_path(order)
    order_dir = get_order_dir(order)
    pid_path = get_pid_path(order)
    # Установить нужный порт
    set_server_port(order, order['server_port'])
    # Запуск процесса
    with open(get_log_path(order), 'a', encoding='utf-8') as log_file:
        proc = subprocess.Popen([
            'java', f'-Xmx{ram}', '-jar', jar_path, 'nogui'
        ], cwd=order_dir, stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True)
        with open(pid_path, 'w') as f:
            f.write(str(proc.pid))
        server_processes[order['order_id']] = proc
        server_start_times[order['order_id']] = datetime.datetime.now()
    return proc.pid

def stop_minecraft_server(order):
    pid_path = get_pid_path(order)
    if os.path.exists(pid_path):
        with open(pid_path, 'r') as f:
            pid = int(f.read())
        try:
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], check=True)
        except Exception:
            pass
        os.remove(pid_path)
    server_processes.pop(order['order_id'], None)
    server_start_times.pop(order['order_id'], None)

def is_server_running(order):
    pid_path = get_pid_path(order)
    if not os.path.exists(pid_path):
        return False
    try:
        with open(pid_path, 'r') as f:
            pid = int(f.read())
        proc = subprocess.Popen(['tasklist', '/FI', f'PID eq {pid}'], stdout=subprocess.PIPE)
        out, _ = proc.communicate()
        result = str(pid) in out.decode('cp1251', errors='ignore')
        return result
    except Exception:
        return False

def read_server_log(order, lines=10):
    log_path = get_log_path(order)
    if not os.path.exists(log_path):
        return []
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_lines = f.readlines()
    return log_lines[-lines:]

def get_server_metrics(order):
    """Получить метрики сервера"""
    if not is_server_running(order):
        return {
            'cpu': 0,
            'ram': 0,
            'online': 0,
            'tps': 0,
            'uptime': '0m'
        }
    
    pid_path = get_pid_path(order)
    try:
        with open(pid_path, 'r') as f:
            pid = int(f.read())
        
        # Получаем процесс
        proc = psutil.Process(pid)
        
        # CPU и RAM
        cpu_percent = proc.cpu_percent()
        memory_info = proc.memory_info()
        ram_mb = memory_info.rss / 1024 / 1024
        
        # Время работы
        start_time = server_start_times.get(order['order_id'])
        if start_time:
            uptime_delta = datetime.datetime.now() - start_time
            uptime_minutes = int(uptime_delta.total_seconds() / 60)
            if uptime_minutes < 60:
                uptime = f"{uptime_minutes}m"
            else:
                hours = uptime_minutes // 60
                minutes = uptime_minutes % 60
                uptime = f"{hours}h {minutes}m"
        else:
            uptime = "Unknown"
        
        # Онлайн игроки и TPS через RCON
        online_players = 0
        tps = 20.0
        
        try:
            rcon = order.get('rcon', {'host': '127.0.0.1', 'port': 25575, 'password': '123qwe'})
            with MCRcon(rcon['host'], rcon['password'], port=rcon['port']) as mcr:
                # Получаем список игроков
                list_response = mcr.command('list')
                if 'players online' in list_response.lower():
                    # Парсим "There are 2 of a max of 20 players online"
                    parts = list_response.split()
                    for i, part in enumerate(parts):
                        if part.isdigit() and i > 0:
                            online_players = int(part)
                            break
                
                # Получаем TPS (если доступно)
                try:
                    tps_response = mcr.command('tps')
                    if 'TPS' in tps_response or 'tps' in tps_response.lower():
                        # Парсим TPS из ответа
                        import re
                        tps_match = re.search(r'(\d+\.?\d*)', tps_response)
                        if tps_match:
                            tps = float(tps_match.group(1))
                except:
                    pass
        except:
            pass
        
        return {
            'cpu': round(cpu_percent, 1),
            'ram': round(ram_mb, 1),
            'online': online_players,
            'tps': round(tps, 1),
            'uptime': uptime
        }
        
    except Exception as e:
        return {
            'cpu': 0,
            'ram': 0,
            'online': 0,
            'tps': 0,
            'uptime': 'Error'
        }

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/')
def index():
    return render_template('index.html', tariffs=TARIFFS)

@app.route('/tariffs')
def tariffs():
    return render_template('tariffs.html', tariffs=TARIFFS[1:])

@app.route('/order', methods=['GET', 'POST'])
def order():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        tariff = request.form['tariff']
        save_order({'name': name, 'email': email, 'tariff': tariff})
        return redirect(url_for('index'))
    return render_template('order.html', tariffs=TARIFFS)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if find_user(email):
            flash('Пользователь уже существует!')
            return redirect(url_for('register'))
        user = {
            'email': email,
            'password': generate_password_hash(password),
            'is_admin': False
        }
        save_user(user)
        flash('Регистрация успешна! Теперь войдите.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = find_user(email)
        if user and check_password_hash(user['password'], password):
            session['user'] = user['email']
            session['is_admin'] = user.get('is_admin', False)
            flash('Вход выполнен!')
            return redirect(url_for('index'))
        flash('Неверный email или пароль!')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из аккаунта.')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        flash('Сначала войдите в аккаунт!')
        return redirect(url_for('login'))
    user_email = session['user']
    user = find_user(user_email)
    orders = load_orders()
    user_orders = [o for o in orders if o['email'] == user_email]
    changed = False
    for o in user_orders:
        if 'server_port' not in o:
            o['server_port'] = find_free_port()
            changed = True
        old_status = o.get('status')
        running = is_server_running(o)
        new_status = 'running' if running else 'stopped'
        if old_status != new_status:
            o['status'] = new_status
            changed = True
        if 'log' not in o:
            o['log'] = []
            changed = True
        if 'tariff_params' not in o:
            for t in TARIFFS:
                if t['name'] == o['tariff']:
                    o['tariff_params'] = t
                    break
            changed = True
        if 'order_id' not in o:
            o['order_id'] = str(uuid.uuid4())
            changed = True
        o['real_log'] = read_server_log(o, 10)
    if changed:
        with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(orders, f, ensure_ascii=False, indent=2)
    if request.method == 'POST':
        idx = int(request.form['order_idx'])
        order = user_orders[idx]
        action = request.form['action']
        if action == 'start':
            if not is_server_running(order):
                start_minecraft_server(order)
                order['log'].append('Сервер запущен (реально)')
                send_telegram_notification(f"Сервер {order['order_id']} запущен пользователем {order['email']}")
            else:
                order['log'].append('Сервер уже был запущен')
        elif action == 'stop':
            if is_server_running(order):
                stop_minecraft_server(order)
                order['log'].append('Сервер остановлен (реально)')
                send_telegram_notification(f"Сервер {order['order_id']} остановлен пользователем {order['email']}")
            else:
                order['log'].append('Сервер уже был остановлен')
        elif action == 'restart':
            stop_minecraft_server(order)
            time.sleep(1)
            start_minecraft_server(order)
            order['log'].append('Сервер перезапущен (реально)')
            send_telegram_notification(f"Сервер {order['order_id']} перезапущен пользователем {order['email']}")
        with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(orders, f, ensure_ascii=False, indent=2)
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user, orders=user_orders)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('is_admin'):
        flash('Доступ только для администратора!')
        return redirect(url_for('login'))
    orders = load_orders()
    users = load_users()
    java_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'java' in proc.info['name'].lower():
                java_processes.append(proc.info)
        except Exception:
            continue
    if request.method == 'POST':
        if 'delete_order' in request.form:
            idx = int(request.form['delete_order'])
            if 0 <= idx < len(orders):
                del orders[idx]
                with open(ORDERS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(orders, f, ensure_ascii=False, indent=2)
                flash('Заказ удалён!')
        elif 'make_admin' in request.form:
            email = request.form['make_admin']
            for u in users:
                if u['email'] == email:
                    u['is_admin'] = True
            with open(USERS_FILE, 'w', encoding='utf-8') as f:
                json.dump(users, f, ensure_ascii=False, indent=2)
            flash(f'{email} теперь администратор!')
        elif 'delete_user' in request.form:
            email = request.form['delete_user']
            if email != session['user']:
                users = [u for u in users if u['email'] != email]
                with open(USERS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(users, f, ensure_ascii=False, indent=2)
                flash(f'Пользователь {email} удалён!')
            else:
                flash('Нельзя удалить себя!')
        elif 'kill_java' in request.form:
            pid = int(request.form['kill_java'])
            try:
                p = psutil.Process(pid)
                p.kill()
                flash(f'Java процесс {pid} убит!')
            except Exception as e:
                flash(f'Ошибка при убийстве процесса {pid}: {e}')
    return render_template('admin.html', orders=orders, users=users, java_processes=java_processes, tariffs=TARIFFS)

@app.route('/admin/tariffs', methods=['GET', 'POST'])
def admin_tariffs():
    if not session.get('is_admin'):
        flash('Доступ только для администратора!')
        return redirect(url_for('login'))
    
    global TARIFFS
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update':
            # Обновить существующий тариф
            tariff_idx = int(request.form.get('tariff_idx'))
            if 0 <= tariff_idx < len(TARIFFS):
                TARIFFS[tariff_idx]['name'] = request.form.get('name')
                TARIFFS[tariff_idx]['price'] = int(request.form.get('price'))
                TARIFFS[tariff_idx]['ram'] = request.form.get('ram')
                TARIFFS[tariff_idx]['slots'] = int(request.form.get('slots'))
                flash('Тариф обновлен!')
        
        elif action == 'create':
            # Создать новый тариф
            new_tariff = {
                'name': request.form.get('name'),
                'price': int(request.form.get('price')),
                'ram': request.form.get('ram'),
                'slots': int(request.form.get('slots'))
            }
            TARIFFS.append(new_tariff)
            flash('Новый тариф создан!')
        
        elif action == 'delete':
            # Удалить тариф
            tariff_idx = int(request.form.get('tariff_idx'))
            if 0 <= tariff_idx < len(TARIFFS) and len(TARIFFS) > 1:
                deleted_tariff = TARIFFS.pop(tariff_idx)
                flash(f'Тариф "{deleted_tariff["name"]}" удален!')
            else:
                flash('Нельзя удалить последний тариф!')
        
        # Сохранить тарифы в файл
        save_tariffs()
    
    return render_template('admin_tariffs.html', tariffs=TARIFFS)

def save_tariffs():
    """Сохранить тарифы в файл"""
    tariffs_file = 'tariffs.json'
    with open(tariffs_file, 'w', encoding='utf-8') as f:
        json.dump(TARIFFS, f, ensure_ascii=False, indent=2)

@app.route('/logs/<order_id>')
def get_logs(order_id):
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return {'error': 'not found'}, 404
    real_log = read_server_log(order, 10)
    log = order.get('log', [])[-10:]
    return {'real_log': real_log, 'log': log}

@app.route('/server_status/<order_id>')
def server_status(order_id):
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return {'status': 'not_found'}, 404
    running = is_server_running(order)
    return {'status': 'running' if running else 'stopped'}

@app.route('/server_metrics/<order_id>')
def server_metrics(order_id):
    if 'user' not in session:
        return {'error': 'unauthorized'}, 401
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return {'error': 'not found'}, 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return {'error': 'access denied'}, 403
    
    metrics = get_server_metrics(order)
    return metrics

@app.route('/files/<order_id>/', defaults={'path': ''})
@app.route('/files/<order_id>/<path:path>')
def list_files(order_id, path):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    base_dir = get_order_dir(order)
    abs_path = os.path.abspath(os.path.join(base_dir, path))
    if not abs_path.startswith(base_dir):
        return 'Invalid path', 400
    if os.path.isdir(abs_path):
        files = os.listdir(abs_path)
        file_infos = []
        for f in files:
            fp = os.path.join(abs_path, f)
            file_infos.append({
                'name': f,
                'is_dir': os.path.isdir(fp)
            })
        return render_template('file_browser.html', files=file_infos, order_id=order_id, path=path)
    else:
        return send_file(abs_path, as_attachment=True)

@app.route('/files/<order_id>/edit/<path:path>', methods=['GET', 'POST'])
def edit_file(order_id, path):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    base_dir = get_order_dir(order)
    abs_path = os.path.abspath(os.path.join(base_dir, path))
    if not abs_path.startswith(base_dir):
        return 'Invalid path', 400
    if not os.path.isfile(abs_path):
        return 'Not a file', 400
    if request.method == 'POST':
        content = request.form.get('content', '')
        with open(abs_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return redirect(url_for('list_files', order_id=order_id, path=os.path.dirname(path)))
    else:
        with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return render_template('text_editor.html', content=content, order_id=order_id, path=path)

@app.route('/files/<order_id>/upload', methods=['POST'])
def upload_file(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    base_dir = get_order_dir(order)
    upload_path = request.form.get('path', '')
    abs_path = os.path.abspath(os.path.join(base_dir, upload_path))
    if not abs_path.startswith(base_dir):
        return 'Invalid path', 400
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    filename = secure_filename(file.filename)
    file.save(os.path.join(abs_path, filename))
    return redirect(url_for('list_files', order_id=order_id, path=upload_path))

# Endpoint для отправки команды
@app.route('/send_command/<order_id>', methods=['POST'])
def send_command(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    # Найти процесс
    proc = server_processes.get(order_id)
    if not proc or proc.poll() is not None:
        return 'Server not running', 400
    command = request.form.get('command', '').strip()
    if not command:
        return 'No command', 400
    try:
        proc.stdin.write(command + '\n')
        proc.stdin.flush()
    except Exception as e:
        return f'Error sending command: {e}', 500
    return redirect(url_for('profile'))

@app.route('/rcon_command/<order_id>', methods=['POST'])
def rcon_command(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    rcon = order.get('rcon', {'host': '127.0.0.1', 'port': 25575, 'password': '123qwe'})
    command = request.form.get('command', '').strip()
    if not command:
        return 'No command', 400
    try:
        with MCRcon(rcon['host'], rcon['password'], port=rcon['port']) as mcr:
            resp = mcr.command(command)
    except Exception as e:
        resp = f'Ошибка RCON: {e}'
    return {'response': resp}

@app.route('/server/<order_id>/databases', methods=['GET', 'POST'])
def server_databases(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    # Получить базы данных из заказа
    if 'databases' not in order:
        order['databases'] = [
            {
                'name': 'minecraft_db',
                'user': order_id[:8],
                'host': 'localhost',
                'type': 'SQLite',
                'created': datetime.datetime.now().isoformat()
            }
        ]
        save_orders(load_orders())
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            db_name = request.form.get('db_name', '').strip()
            if db_name:
                database = {
                    'name': db_name,
                    'user': order_id[:8],
                    'host': 'localhost',
                    'type': 'SQLite',
                    'created': datetime.datetime.now().isoformat()
                }
                order['databases'].append(database)
                save_orders(load_orders())
                flash(f'База данных {db_name} создана!')
        
        elif action == 'delete':
            db_name = request.form.get('db_name')
            order['databases'] = [db for db in order['databases'] if db['name'] != db_name]
            save_orders(load_orders())
            flash(f'База данных {db_name} удалена!')
    
    return render_template('server_databases.html', order_id=order_id, databases=order.get('databases', []))

@app.route('/server/<order_id>/schedules', methods=['GET', 'POST'])
def server_schedules(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    # Получить задачи из заказа
    if 'schedules' not in order:
        order['schedules'] = []
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            name = request.form.get('name', '').strip()
            cron = request.form.get('cron', '').strip()
            command = request.form.get('command', '').strip()
            
            if name and cron and command:
                schedule = {
                    'id': str(uuid.uuid4()),
                    'name': name,
                    'cron': cron,
                    'command': command,
                    'active': True,
                    'created': datetime.datetime.now().isoformat()
                }
                order['schedules'].append(schedule)
                save_orders(load_orders())
                flash(f'Задача {name} создана!')
        
        elif action == 'delete':
            schedule_id = request.form.get('schedule_id')
            order['schedules'] = [s for s in order['schedules'] if s.get('id') != schedule_id]
            save_orders(load_orders())
            flash('Задача удалена!')
        
        elif action == 'toggle':
            schedule_id = request.form.get('schedule_id')
            for schedule in order['schedules']:
                if schedule.get('id') == schedule_id:
                    schedule['active'] = not schedule.get('active', True)
                    break
            save_orders(load_orders())
            flash('Статус задачи изменен!')
    
    return render_template('server_schedules.html', order_id=order_id, schedules=order.get('schedules', []))

@app.route('/server/<order_id>/users', methods=['GET', 'POST'])
def server_users(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    whitelist_path = os.path.join(get_order_dir(order), 'whitelist.json')
    ops_path = os.path.join(get_order_dir(order), 'ops.json')
    
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username', '').strip()
        
        if action == 'add_whitelist' and username:
            # Добавить в whitelist
            whitelist = []
            if os.path.exists(whitelist_path):
                with open(whitelist_path, 'r', encoding='utf-8') as f:
                    whitelist = json.load(f)
            
            if not any(p['name'].lower() == username.lower() for p in whitelist):
                whitelist.append({'uuid': str(uuid.uuid4()), 'name': username})
                with open(whitelist_path, 'w', encoding='utf-8') as f:
                    json.dump(whitelist, f, ensure_ascii=False, indent=2)
                flash(f'Игрок {username} добавлен в whitelist!')
        
        elif action == 'remove_whitelist' and username:
            # Удалить из whitelist
            if os.path.exists(whitelist_path):
                with open(whitelist_path, 'r', encoding='utf-8') as f:
                    whitelist = json.load(f)
                whitelist = [p for p in whitelist if p['name'].lower() != username.lower()]
                with open(whitelist_path, 'w', encoding='utf-8') as f:
                    json.dump(whitelist, f, ensure_ascii=False, indent=2)
                flash(f'Игрок {username} удален из whitelist!')
    
    # Загрузить списки пользователей
    whitelist_users = []
    if os.path.exists(whitelist_path):
        with open(whitelist_path, 'r', encoding='utf-8') as f:
            whitelist_users = json.load(f)
    
    ops_users = []
    if os.path.exists(ops_path):
        with open(ops_path, 'r', encoding='utf-8') as f:
            ops_users = json.load(f)
    
    return render_template('server_users.html', order_id=order_id, 
                         whitelist_users=whitelist_users, ops_users=ops_users)

@app.route('/server/<order_id>/backups', methods=['GET', 'POST'])
def server_backups(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    backups_dir = os.path.join(get_order_dir(order), 'backups')
    if not os.path.exists(backups_dir):
        os.makedirs(backups_dir)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            # Проверить тариф - бесплатный тариф не может создавать бэкапы
            tariff_name = order.get('tariff', '')
            if tariff_name.lower() in ['бесплатный', 'free']:
                flash('Создание бэкапов недоступно на бесплатном тарифе. Купите другой хостинг для доступа к бэкапам!')
            else:
                # Создать бэкап
                backup_name = f"backup-{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.zip"
                backup_path = os.path.join(backups_dir, backup_name)
                server_dir = get_order_dir(order)
                
                try:
                    shutil.make_archive(backup_path[:-4], 'zip', server_dir, 
                                      ignore=shutil.ignore_patterns('backups', '*.log', '__pycache__'))
                    flash(f'Бэкап {backup_name} создан!')
                except Exception as e:
                    flash(f'Ошибка создания бэкапа: {e}')
        
        elif action == 'delete':
            backup_name = request.form.get('backup_name')
            backup_path = os.path.join(backups_dir, backup_name)
            if os.path.exists(backup_path):
                os.remove(backup_path)
                flash(f'Бэкап {backup_name} удален!')
    
    # Получить список бэкапов
    backups = []
    if os.path.exists(backups_dir):
        for f in os.listdir(backups_dir):
            if f.endswith('.zip'):
                path = os.path.join(backups_dir, f)
                stat = os.stat(path)
                backups.append({
                    'name': f,
                    'date': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'size': f"{stat.st_size / 1024 / 1024:.1f} MB"
                })
    
    return render_template('server_backups.html', order_id=order_id, backups=backups, order=order)

@app.route('/server/<order_id>/network')
def server_network(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    # Получить информацию о портах
    main_port = order.get('server_port', 25565)
    rcon_port = order.get('rcon', {}).get('port', 25575)
    
    ports = [
        {
            'port': main_port,
            'ip': '127.0.0.1',
            'status': 'Активен' if is_server_running(order) else 'Неактивен',
            'type': 'Minecraft'
        },
        {
            'port': rcon_port,
            'ip': '127.0.0.1', 
            'status': 'Активен' if is_server_running(order) else 'Неактивен',
            'type': 'RCON'
        }
    ]
    
    return render_template('server_network.html', order_id=order_id, ports=ports)

@app.route('/server/<order_id>/startup', methods=['GET', 'POST'])
def server_startup(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    # Получить текущие настройки запуска
    startup_config = order.get('startup_config', {
        'jar_file': 'server.jar',
        'java_args': f"-Xmx{order.get('tariff_params', {}).get('ram', '1GB')} -Xms512M",
        'server_args': 'nogui'
    })
    
    if request.method == 'POST':
        # Сохранить настройки запуска
        startup_config['jar_file'] = request.form.get('jar_file', 'server.jar')
        startup_config['java_args'] = request.form.get('java_args', '')
        startup_config['server_args'] = request.form.get('server_args', 'nogui')
        
        order['startup_config'] = startup_config
        save_orders(load_orders())
        flash('Настройки запуска сохранены!')
        return redirect(url_for('server_startup', order_id=order_id))
    
    # Сформировать полную команду запуска
    ram = order.get('tariff_params', {}).get('ram', '1GB').replace('GB', 'G')
    full_command = f"java {startup_config['java_args']} -jar {startup_config['jar_file']} {startup_config['server_args']}"
    
    return render_template('server_startup.html', order_id=order_id, 
                         startup_config=startup_config, full_command=full_command)

@app.route('/server/<order_id>/settings', methods=['GET', 'POST'])
def server_settings(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    props_path = os.path.join(get_order_dir(order), 'server.properties')
    
    # Дефолтные настройки
    default_props = {
        'server-name': 'ApexNodes Server',
        'motd': 'Добро пожаловать!',
        'white-list': 'false',
        'max-players': str(order.get('tariff_params', {}).get('slots', 20)),
        'difficulty': 'normal',
        'gamemode': 'survival',
        'pvp': 'true',
        'spawn-protection': '16'
    }
    
    if request.method == 'POST':
        # Сохранить настройки
        new_props = {}
        for key in default_props.keys():
            new_props[key] = request.form.get(key, default_props[key])
        
        # Записать в файл
        lines = []
        if os.path.exists(props_path):
            with open(props_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        
        # Обновить существующие или добавить новые
        for key, value in new_props.items():
            found = False
            for i, line in enumerate(lines):
                if line.startswith(f'{key}='):
                    lines[i] = f'{key}={value}\n'
                    found = True
                    break
            if not found:
                lines.append(f'{key}={value}\n')
        
        with open(props_path, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        flash('Настройки сохранены!')
        return redirect(url_for('server_settings', order_id=order_id))
    
    # Загрузить текущие настройки
    current_props = default_props.copy()
    if os.path.exists(props_path):
        with open(props_path, 'r', encoding='utf-8') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    if key in current_props:
                        current_props[key] = value
    
    return render_template('server_settings.html', order_id=order_id, props=current_props)

@app.route('/server/<order_id>/activity')
def server_activity(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    # Получить историю активности из логов заказа
    activity_log = order.get('activity_log', [])
    
    # Добавить базовые события если их нет
    if not activity_log:
        activity_log = [
            {
                'event': 'server:created',
                'description': 'Сервер создан',
                'timestamp': datetime.datetime.now() - datetime.timedelta(days=1)
            }
        ]
    
    # Отсортировать по времени (новые сверху)
    activity_log.sort(key=lambda x: x.get('timestamp', datetime.datetime.now()), reverse=True)
    
    return render_template('server_activity.html', order_id=order_id, activities=activity_log)

@app.route('/server/<order_id>/subdomain', methods=['GET', 'POST'])
def server_subdomain(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    orders = load_orders()
    order = next((o for o in orders if o.get('order_id') == order_id), None)
    if not order:
        return 'Order not found', 404
    if not session.get('is_admin') and order['email'] != session['user']:
        return 'Access denied', 403
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create':
            subdomain = request.form.get('subdomain', '').strip().lower()
            if subdomain and subdomain.isalnum():
                order['subdomain'] = f"{subdomain}.apexnodes.ru"
                save_orders(load_orders())
                flash(f'Поддомен {subdomain}.apexnodes.ru создан!')
            else:
                flash('Неверное имя поддомена! Используйте только буквы и цифры.')
        
        elif action == 'delete':
            order.pop('subdomain', None)
            save_orders(load_orders())
            flash('Поддомен удален!')
    
    current_subdomain = order.get('subdomain')
    server_port = order.get('server_port', 25565)
    
    return render_template('server_subdomain.html', order_id=order_id, 
                         current_subdomain=current_subdomain, server_port=server_port)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0') 