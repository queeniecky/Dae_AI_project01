import os
import sqlite3
import numpy as np
from flask import Flask, request, jsonify, send_file, session, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from sentence_transformers import SentenceTransformer, util
import pdfplumber
import logging
from datetime import timedelta

# 初始化 Flask 應用
app = Flask(__name__, static_folder='static')

# 設置 Flask 會話密鑰和過期時間
app.secret_key = '92278961a025cbe7e996567b149c0f61'
app.permanent_session_lifetime = timedelta(minutes=30)

# 定義文件上傳儲存目錄
UPLOAD_FOLDER = 'Uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 配置日誌系統
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# 定義 SQLite 資料庫路徑（使用絕對路徑）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'file_management.db')

# 初始化 SentenceTransformer 模型
model = SentenceTransformer('all-MiniLM-L6-v2')

# 初始化資料庫
def init_db():
    logging.info(f"Creating database at: {os.path.abspath(DB_PATH)}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            theme TEXT DEFAULT 'light'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            content TEXT,
            embedding BLOB,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_shares (
            file_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (file_id, user_id),
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

# 全局錯誤處理
@app.errorhandler(Exception)
def handle_error(e):
    logging.error(f"Unhandled error: {str(e)}")
    return jsonify({'error': '伺服器錯誤，請稍後重試'}), 500

# 首頁路由
@app.route('/')
def index():
    return render_template('index.html')

# 注冊路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        logging.info(f"Register attempt with data: username={username}, password={'*' * len(password) if password else None}")
        if not username or not password:
            logging.warning("Missing username or password in register request")
            return jsonify({'error': '請提供用戶名和密碼'}), 400
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                logging.warning(f"Username {username} already exists")
                return jsonify({'error': '用戶名已存在'}), 400
            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            cursor.execute('SELECT id, username, theme FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            session.permanent = True
            session['user'] = {'id': user[0], 'username': user[1], 'theme': user[2]}
            logging.info(f"User registered and session set: {session['user']}")
            cursor.close()
            conn.close()
            return redirect(url_for('dashboard'))
        except sqlite3.Error as e:
            logging.error(f"Register error: {str(e)}")
            return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500
    return render_template('register.html')

# 登入路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        logging.info(f"Login attempt for username: {username}")
        if not username or not password:
            logging.warning("Missing username or password in login request")
            return jsonify({'error': '請提供用戶名和密碼'}), 400
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password, theme FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user[2], password):
                session.permanent = True
                session['user'] = {'id': user[0], 'username': user[1], 'theme': user[3]}
                logging.info(f"User logged in and session set: {session['user']}")
                cursor.close()
                conn.close()
                return redirect(url_for('dashboard'))
            logging.warning(f"Invalid username or password for {username}")
            return jsonify({'error': '用戶名或密碼錯誤'}), 401
        except sqlite3.Error as e:
            logging.error(f"Login error: {str(e)}")
            return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500
    return render_template('login.html')

# 登出路由
@app.route('/logout')
def logout():
    logging.info(f"User logged out: {session.get('user')}")
    session.pop('user', None)
    return redirect(url_for('index'))

# 儀表板路由
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        logging.warning("Accessing /dashboard without session, redirecting to /login")
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# 獲取文件列表路由
@app.route('/files')
def get_files():
    if 'user' not in session:
        logging.warning("Accessing /files without session")
        return jsonify({'error': '未登入'}), 401
    search_query = request.args.get('search', '')
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.id, f.name, u.username AS owner, f.owner_id, GROUP_CONCAT(u2.username) AS shared_with
            FROM files f
            LEFT JOIN users u ON f.owner_id = u.id
            LEFT JOIN file_shares fs ON f.id = fs.file_id
            LEFT JOIN users u2 ON fs.user_id = u2.id
            WHERE (f.owner_id = ? OR fs.user_id = ?) AND f.name LIKE ?
            GROUP BY f.id
        ''', (session['user']['id'], session['user']['id'], f'%{search_query}%'))
        files = [dict(row) for row in cursor.fetchall()]
        for file in files:
            file['shared_with'] = file['shared_with'].split(',') if file['shared_with'] else []
            file['current_user_id'] = session['user']['id']
        cursor.close()
        conn.close()
        return jsonify({'files': files, 'theme': session['user']['theme']})
    except sqlite3.Error as e:
        logging.error(f"Get files error: {str(e)}")
        return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500

# 文件上傳路由
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        logging.warning("Accessing /upload without session")
        return jsonify({'error': '未登入'}), 401
    if 'file' not in request.files:
        logging.warning("No file part in request")
        return jsonify({'error': '無文件上傳'}), 400
    file = request.files['file']
    if file.filename == '':
        logging.warning("No file selected")
        return jsonify({'error': '請選擇一個文件'}), 400
    
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    content = ""
    try:
        if file.filename.endswith('.pdf'):
            with pdfplumber.open(file_path) as pdf:
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        content += text + "\n"
        elif file.filename.endswith('.txt'):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        else:
            content = "無法提取內容"
        logging.info(f"Extracted content length for {file.filename}: {len(content)} characters")
    except Exception as e:
        logging.error(f"Content extraction error for {file.filename}: {str(e)}")
        content = "內容提取失敗"

    embedding = model.encode(content).tobytes() if content and content not in ["無法提取內容", "內容提取失敗"] else b''
    logging.info(f"Embedding size for {file.filename}: {len(embedding)} bytes")

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO files (name, owner_id, content, embedding) VALUES (?, ?, ?, ?)',
                      (file.filename, session['user']['id'], content, embedding))
        conn.commit()
        cursor.close()
        conn.close()
        logging.info(f"File uploaded: {file.filename}")
        return redirect(url_for('dashboard'))
    except sqlite3.Error as e:
        logging.error(f"Upload error: {str(e)}")
        return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500

# 文件共享路由
@app.route('/share', methods=['POST'])
def share():
    if 'user' not in session:
        logging.warning("Accessing /share without session")
        return jsonify({'error': '未登入'}), 401
    data = request.get_json()
    file_id = data.get('file_id')
    username = data.get('username')
    if not file_id or not username:
        logging.warning("Missing file_id or username in share request")
        return jsonify({'error': '請提供文件ID和用戶名'}), 400
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': '用戶不存在'}), 400
        cursor.execute('SELECT owner_id FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()
        if not file or file[0] != session['user']['id']:
            return jsonify({'error': '無權限共享此文件'}), 403
        cursor.execute('INSERT OR IGNORE INTO file_shares (file_id, user_id) VALUES (?, ?)', (file_id, user[0]))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        logging.error(f"Share error: {str(e)}")
        return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500

# 文件刪除路由
@app.route('/delete', methods=['POST'])
def delete():
    if 'user' not in session:
        logging.warning("Accessing /delete without session")
        return jsonify({'error': '未登入'}), 401
    data = request.get_json()
    file_id = data.get('file_id')
    if not file_id:
        logging.warning("Missing file_id in delete request")
        return jsonify({'error': '請提供文件ID'}), 400
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT owner_id, name FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()
        if not file or file[0] != session['user']['id']:
            return jsonify({'error': '無權限刪除此文件'}), 403
        file_path = os.path.join(UPLOAD_FOLDER, file[1])
        if os.path.exists(file_path):
            os.remove(file_path)
        cursor.execute('DELETE FROM file_shares WHERE file_id = ?', (file_id,))
        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        logging.error(f"Delete error: {str(e)}")
        return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500

# 文件下載路由
@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user' not in session:
        logging.warning("Accessing /download without session")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT name, owner_id FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()
        if not file:
            return jsonify({'error': '文件不存在'}), 404
        cursor.execute('SELECT user_id FROM file_shares WHERE file_id = ? AND user_id = ?', (file_id, session['user']['id']))
        if file[1] != session['user']['id'] and not cursor.fetchone():
            return jsonify({'error': '無權限下載此文件'}), 403
        file_path = os.path.join(UPLOAD_FOLDER, file[0])
        if not os.path.exists(file_path):
            return jsonify({'error': '文件已丟失'}), 404
        cursor.close()
        conn.close()
        return send_file(file_path, download_name=file[0], as_attachment=True)
    except sqlite3.Error as e:
        logging.error(f"Download error: {str(e)}")
        return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500

# AI 搜尋路由
@app.route('/ai_search', methods=['POST'])
def ai_search():
    if 'user' not in session:
        logging.warning("Accessing /ai_search without session")
        return jsonify({'error': '未登入'}), 401
    query = request.get_json().get('query', '')
    if not query:
        return jsonify({'error': '請輸入搜尋內容'}), 400
    logging.info(f"AI search query: {query}")
    query_embedding = model.encode(query)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.id, f.name, u.username AS owner, f.owner_id, GROUP_CONCAT(u2.username) AS shared_with, f.embedding
            FROM files f
            LEFT JOIN users u ON f.owner_id = u.id
            LEFT JOIN file_shares fs ON f.id = fs.file_id
            LEFT JOIN users u2 ON fs.user_id = u2.id
            WHERE f.owner_id = ? OR fs.user_id = ?
            GROUP BY f.id
        ''', (session['user']['id'], session['user']['id']))
        files = cursor.fetchall()
        results = []
        for file in files:
            if file['embedding']:
                file_embedding = np.frombuffer(file['embedding'], dtype=np.float32)
                similarity = util.cos_sim(query_embedding, file_embedding).item()
                logging.info(f"File {file['name']} similarity: {similarity}")
                if similarity > 0.1:
                    results.append({
                        'id': file['id'],
                        'name': file['name'],
                        'owner': file['owner'],
                        'owner_id': file['owner_id'],
                        'shared_with': file['shared_with'].split(',') if file['shared_with'] else [],
                        'current_user_id': session['user']['id'],
                        'similarity': similarity
                    })
        cursor.close()
        conn.close()
        logging.info(f"AI search returned {len(results)} results")
        return jsonify({'files': results, 'theme': session['user']['theme']})
    except sqlite3.Error as e:
        logging.error(f"AI search error: {str(e)}")
        return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500

# 文件推薦路由
@app.route('/recommend')
def recommend():
    if 'user' not in session:
        logging.warning("Accessing /recommend without session")
        return jsonify({'error': '未登入'}), 401
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, embedding FROM files WHERE owner_id = ? ORDER BY created_at DESC LIMIT 1',
                      (session['user']['id'],))
        recent_file = cursor.fetchone()
        if not recent_file or not recent_file['embedding']:
            logging.info("No recent file or embedding for recommendations")
            return jsonify({'files': [], 'theme': session['user']['theme']})
        recent_embedding = np.frombuffer(recent_file['embedding'], dtype=np.float32)
        cursor.execute('''
            SELECT f.id, f.name, u.username AS owner, f.owner_id, GROUP_CONCAT(u2.username) AS shared_with, f.embedding
            FROM files f
            LEFT JOIN users u ON f.owner_id = u.id
            LEFT JOIN file_shares fs ON f.id = fs.file_id
            LEFT JOIN users u2 ON fs.user_id = u2.id
            WHERE (f.owner_id = ? OR fs.user_id = ?) AND f.id != ?
            GROUP BY f.id
        ''', (session['user']['id'], session['user']['id'], recent_file['id']))
        files = [dict(row) for row in cursor.fetchall()]
        recommendations = []
        for file in files:
            if file['embedding']:
                file_embedding = np.frombuffer(file['embedding'], dtype=np.float32)
                similarity = util.cos_sim(recent_embedding, file_embedding).item()
                logging.info(f"Recommendation for {file['name']}: similarity {similarity}")
                if similarity > 0.1:
                    file['shared_with'] = file['shared_with'].split(',') if file['shared_with'] else []
                    file['current_user_id'] = session['user']['id']
                    file['similarity'] = similarity
                    recommendations.append({
                        'id': file['id'],
                        'name': file['name'],
                        'owner': file['owner'],
                        'owner_id': file['owner_id'],
                        'shared_with': file['shared_with'],
                        'current_user_id': file['current_user_id'],
                        'similarity': file['similarity']
                    })
        cursor.close()
        conn.close()
        logging.info(f"Found {len(recommendations)} recommendations")
        recommendations = sorted(recommendations, key=lambda x: x['similarity'], reverse=True)[:5]
        return jsonify({'files': recommendations, 'theme': session['user']['theme']})
    except sqlite3.Error as e:
        logging.error(f"Recommend error: {str(e)}")
        return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500

# 獲取用戶資訊路由
@app.route('/user_info')
def user_info():
    logging.info(f"Accessing /user_info, session: {session.get('user')}")
    if 'user' not in session:
        logging.warning("No user in session, returning 401")
        return jsonify({'error': '未登入'}), 401
    return jsonify({'username': session['user']['username']})

# 個人化設置路由
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session:
        logging.warning("Accessing /settings without session")
        return redirect(url_for('login'))
    if request.method == 'POST':
        data = request.get_json()
        theme = data.get('theme')
        if not theme:
            return jsonify({'error': '請提供主題設置'}), 400
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET theme = ? WHERE id = ?', (theme, session['user']['id']))
            conn.commit()
            session['user']['theme'] = theme
            cursor.close()
            conn.close()
            return jsonify({'success': True})
        except sqlite3.Error as e:
            logging.error(f"Settings error: {str(e)}")
            return jsonify({'error': f'資料庫錯誤: {str(e)}'}), 500
    return render_template('settings.html')

# 主程式入口
if __name__ == '__main__':
    init_db()
    app.run(debug=True)