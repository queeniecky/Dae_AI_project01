import os
import sqlite3
import numpy as np
from flask import Flask, request, jsonify, send_file, session, redirect, url_for, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from sentence_transformers import SentenceTransformer, util
import pdfplumber
import logging

# 初始化 Flask 應用
# 用途：創建 Flask Web 應用，作為文件管理系統的核心後端，處理 HTTP 請求並與前端模板、資料庫交互。
# 關係：依賴 templates/ 資料夾中的 HTML 文件（index.html, dashboard.html 等）進行頁面渲染。
app = Flask(__name__)

# 設置 Flask 會話密鑰
# 用途：保護用戶會話安全，用於加密 session 數據（如用戶登錄狀態）。
# 備注：應使用隨機生成的密鑰，執行 `python -c "import secrets; print(secrets.token_hex(16))"` 獲取新密鑰。
app.secret_key = '92278961a025cbe7e996567b149c0f61'  # 建議替換為隨機密鑰以增強安全性

# 定義文件上傳儲存目錄
# 用途：指定上傳文件儲存的本地目錄（Uploads/），用於保存用戶上傳的文件。
# 關係：與 /upload 和 /download 路由交互，儲存和檢索文件。Uploads/ 包含在 .gitignore 中，避免版本控制。
UPLOAD_FOLDER = 'Uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 配置日誌系統
# 用途：記錄應用運行時的資訊（INFO）、警告（WARNING）和錯誤（ERROR），便於除錯和監控。
# 關係：日誌輸出到控制台，幫助診斷 /upload、/ai_search、/recommend 等路由的執行情況。
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# 定義 SQLite 資料庫路徑
# 用途：指定資料庫檔案（file_management.db），儲存用戶、文件和共享資訊。
# 關係：與 init_db() 和所有資料庫操作路由（如 /register、/upload）交互，.gitignore 中包含 *.db 避免版本控制。
DB_PATH = 'file_management.db'

# 初始化 SentenceTransformer 模型
# 用途：載入 'all-MiniLM-L6-v2' 模型，用於生成文件內容的嵌入向量（embedding），支持 AI 搜尋和推薦功能。
# 關係：依賴 requirements.txt 中的 sentence-transformers 庫，與 /upload、/ai_search、/recommend 路由交互。
model = SentenceTransformer('all-MiniLM-L6-v2')

# 初始化資料庫
# 用途：創建資料庫結構，包含 users（用戶資訊）、files（文件元數據和嵌入向量）、file_shares（文件共享關係）三張表。
# 關係：由主程式調用，影響所有涉及資料庫的路由（如 /register、/upload、/share）。資料庫檔案為 file_management.db。
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # 創建 users 表：儲存用戶 ID、用戶名、密碼（雜湊）、主題偏好
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            theme TEXT DEFAULT 'light'
        )
    ''')
    # 創建 files 表：儲存文件 ID、名稱、擁有者、創建時間、內容、嵌入向量
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
    # 創建 file_shares 表：儲存文件與用戶的共享關係
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

# 首頁路由
# 用途：顯示應用首頁，提供登入和注冊入口。
# 關係：渲染 templates/index.html，與 /login 和 /register 路由連結。
@app.route('/')
def index():
    return render_template('index.html')

# 注冊路由
# 用途：處理用戶注冊請求（GET 顯示表單，POST 儲存用戶資料），將用戶名和雜湊密碼存入 users 表，自動登錄並跳轉到儀表板。
# 關係：渲染 templates/register.html，與 users 表交互，依賴 werkzeug.security 進行密碼雜湊。
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                return jsonify({'error': '用戶名已存在'})
            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            cursor.execute('SELECT id, username, theme FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            session['user'] = {'id': user[0], 'username': user[1], 'theme': user[2]}
            cursor.close()
            conn.close()
            return redirect(url_for('dashboard'))
        except sqlite3.Error as e:
            logging.error(f"Register error: {str(e)}")
            return jsonify({'error': str(e)})
    return render_template('register.html')

# 登入路由
# 用途：處理用戶登入請求（GET 顯示表單，POST 驗證用戶名和密碼），成功後將用戶資訊存入 session 並跳轉到儀表板。
# 關係：渲染 templates/login.html，與 users 表交互，依賴 werkzeug.security 驗證密碼。
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password, theme FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user[2], password):
                session['user'] = {'id': user[0], 'username': user[1], 'theme': user[3]}
                cursor.close()
                conn.close()
                return redirect(url_for('dashboard'))
            return jsonify({'error': '用戶名或密碼錯誤'})
        except sqlite3.Error as e:
            logging.error(f"Login error: {str(e)}")
            return jsonify({'error': str(e)})
    return render_template('login.html')

# 登出路由
# 用途：清除用戶 session，登出後重定向到首頁。
# 關係：與 session 交互，重定向到 /（index.html）。
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

# 儀表板路由
# 用途：顯示文件管理主介面，供用戶上傳、搜尋、共享和管理文件。
# 關係：渲染 templates/dashboard.html，依賴 session 驗證登錄狀態，與 /files、/upload、/recommend 等路由交互。
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# 獲取文件列表路由
# 用途：返回用戶擁有或被共享的文件列表，支持按文件名搜尋，供前端 dashboard.html 渲染文件清單。
# 關係：查詢 files、users、file_shares 表，返回 JSON 數據給 dashboard.html 的 renderFiles() 函數。
@app.route('/files')
def get_files():
    if 'user' not in session:
        return jsonify({'error': '未登入'})
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
        return jsonify({'error': str(e)})

# 文件上傳路由
# 用途：處理文件上傳，儲存文件到 UPLOAD_FOLDER，提取 PDF/TXT 內容，生成嵌入向量，存入 files 表。
# 關係：與 dashboard.html 的上傳表單交互，依賴 pdfplumber（PDF 提取）、sentence-transformers（嵌入向量生成），影響 /recommend 和 /ai_search。
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return jsonify({'error': '未登入'})
    if 'file' not in request.files:
        logging.warning("No file part in request")
        return jsonify({'error': '無文件上傳'})
    file = request.files['file']
    if file.filename == '':
        logging.warning("No file selected")
        return jsonify({'error': '請選擇一個文件'})
    
    # 保存文件到本地
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # 提取文件內容（僅支持 PDF 和 TXT）
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

    # 生成嵌入向量（僅對有效內容）
    embedding = model.encode(content).tobytes() if content and content not in ["無法提取內容", "內容提取失敗"] else b''
    logging.info(f"Embedding size for {file.filename}: {len(embedding)} bytes")

    # 儲存文件元數據到資料庫
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
        return jsonify({'error': str(e)})

# 文件共享路由
# 用途：允許文件擁有者將文件共享給其他用戶，記錄共享關係到 file_shares 表。
# 關係：與 dashboard.html 的共享功能（openShare() 和 shareFile()）交互，查詢 users 表驗證用戶，更新 file_shares 表。
@app.route('/share', methods=['POST'])
def share():
    if 'user' not in session:
        return jsonify({'error': '未登入'})
    data = request.get_json()
    file_id = data['file_id']
    username = data['username']
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': '用戶不存在'})
        cursor.execute('SELECT owner_id FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()
        if not file or file[0] != session['user']['id']:
            return jsonify({'error': '無權限共享此文件'})
        cursor.execute('INSERT OR IGNORE INTO file_shares (file_id, user_id) VALUES (?, ?)', (file_id, user[0]))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        logging.error(f"Share error: {str(e)}")
        return jsonify({'error': str(e)})

# 文件刪除路由
# 用途：允許文件擁有者刪除文件，從 UPLOAD_FOLDER 和 files 表中移除，並清除 file_shares 表中的共享記錄。
# 關係：與 dashboard.html 的刪除按鈕（deleteFile()）交互，影響 files 和 file_shares 表。
@app.route('/delete', methods=['POST'])
def delete():
    if 'user' not in session:
        return jsonify({'error': '未登入'})
    data = request.get_json()
    file_id = data['file_id']
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT owner_id, name FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()
        if not file or file[0] != session['user']['id']:
            return jsonify({'error': '無權限刪除此文件'})
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
        return jsonify({'error': str(e)})

# 文件下載路由
# 用途：允許文件擁有者或被共享者下載文件，從 UPLOAD_FOLDER 提供文件下載。
# 關係：與 dashboard.html 的下載按鈕（<a href="/download/${file.id}">）交互，查詢 files 和 file_shares 表驗證權限。
@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT name, owner_id FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()
        if not file:
            return jsonify({'error': '文件不存在'})
        cursor.execute('SELECT user_id FROM file_shares WHERE file_id = ? AND user_id = ?', (file_id, session['user']['id']))
        if file[1] != session['user']['id'] and not cursor.fetchone():
            return jsonify({'error': '無權限下載此文件'})
        file_path = os.path.join(UPLOAD_FOLDER, file[0])
        if not os.path.exists(file_path):
            return jsonify({'error': '文件已丟失'})
        cursor.close()
        conn.close()
        return send_file(file_path, download_name=file[0], as_attachment=True)
    except sqlite3.Error as e:
        logging.error(f"Download error: {str(e)}")
        return jsonify({'error': str(e)})

# AI 搜尋路由
# 用途：根據用戶輸入的查詢詞，計算其嵌入向量與文件嵌入向量的相似度，返回相似度 > 0.1 的文件列表。
# 關係：與 dashboard.html 的 AI 搜尋功能（aiSearch()）交互，依賴 sentence-transformers 和 numpy，查詢 files、users、file_shares 表。
@app.route('/ai_search', methods=['POST'])
def ai_search():
    if 'user' not in session:
        return jsonify({'error': '未登入'})
    query = request.get_json().get('query', '')
    if not query:
        return jsonify({'error': '請輸入搜尋內容'})
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
                if similarity > 0.1:  # 相似度閾值
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
        return jsonify({'error': str(e)})

# 文件推薦路由
# 用途：根據用戶最近上傳文件的嵌入向量，推薦相似度 > 0.1 的其他文件（最多 5 個），供用戶發現相關內容。
# 關係：與 dashboard.html 的推薦區塊（renderRecommendations()）交互，依賴 sentence-transformers 和 numpy，查詢 files、users、file_shares 表。
@app.route('/recommend')
def recommend():
    if 'user' not in session:
        return jsonify({'error': '未登入'})
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        # 選擇用戶最近上傳的文件
        cursor.execute('SELECT id, name, embedding FROM files WHERE owner_id = ? ORDER BY created_at DESC LIMIT 1',
                      (session['user']['id'],))
        recent_file = cursor.fetchone()
        if not recent_file or not recent_file['embedding']:
            logging.info("No recent file or embedding for recommendations")
            return jsonify({'files': [], 'theme': session['user']['theme']})
        recent_embedding = np.frombuffer(recent_file['embedding'], dtype=np.float32)
        # 查詢其他文件（排除最近文件）
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
                if similarity > 0.1:  # 相似度閾值
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
        return jsonify({'error': str(e)})

# 個人化設置路由
# 用途：處理用戶主題偏好設置（GET 顯示表單，POST 更新 users 表中的 theme 欄位）。
# 關係：渲染 templates/settings.html，與 users 表交互，影響 dashboard.html 和 settings.html 的主題顯示。
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        data = request.get_json()
        theme = data['theme']
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
            return jsonify({'error': str(e)})
    return render_template('settings.html')

# 主程式入口
# 用途：初始化資料庫並啟動 Flask 應用（調試模式）。
# 關係：調用 init_db() 創建資料庫結構，啟動 Web 服務器，監聽 http://127.0.0.1:5000。
if __name__ == '__main__':
    init_db()
    app.run(debug=True)