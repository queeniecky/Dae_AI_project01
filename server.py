import sqlite3
import os
import logging
import jwt
import bcrypt
import numpy as np
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from sentence_transformers import SentenceTransformer, util
import pdfplumber

app = Flask(__name__, static_folder='public')
CORS(app)
PORT = 3000
JWT_SECRET = 'your_jwt_secret_key'
UPLOAD_FOLDER = 'Uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf'}

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize SentenceTransformer model
model = SentenceTransformer('all-MiniLM-L6-v2')

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
    ''')
    # Files table with shared_with_all column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_id INTEGER NOT NULL, -- Fixed: Removed extra "NOT"
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            content TEXT,
            embedding BLOB,
            shared_with_all INTEGER DEFAULT 0,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')
    # File shares table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_shares (
            file_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (file_id, user_id),
            FOREIGN KEY (file_id) REFERENCES files(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()
    logger.info("Database initialized")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text(file_path):
    try:
        ext = file_path.rsplit('.', 1)[1].lower()
        if ext == 'txt':
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        elif ext == 'pdf':
            with pdfplumber.open(file_path) as pdf:
                text = ''.join(page.extract_text() or '' for page in pdf.pages)
                return text
        return "內容提取失敗"
    except Exception as e:
        logger.error(f"Text extraction error: {str(e)}")
        return "內容提取失敗"

# Register route
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if not username or not password or not email:
            return jsonify({'error': '請填寫所有必填字段'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            (username, hashed_password, email)
        )
        conn.commit()
        conn.close()

        return jsonify({'message': '用戶注冊成功'}), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': '用戶名或郵箱已存在'}), 400
    except Exception as e:
        logger.error(f"Register error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Login route
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': '請填寫用戶名和密碼'}), 400

        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return jsonify({'error': '用戶名或密碼錯誤'}), 401

        token = jwt.encode({
            'userId': user['id'],
            'username': user['username'],
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, JWT_SECRET, algorithm='HS256')

        return jsonify({
            'token': token,
            'message': '登入成功',
            'redirectTo': '/dashboard.html'
        })

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Update email route
@app.route('/api/update-email', methods=['POST'])
def update_email():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        data = request.get_json()
        new_email = data.get('email')

        if not new_email:
            return jsonify({'error': '請提供新郵箱'}), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET email = ? WHERE id = ?',
            (new_email, decoded['userId'])
        )
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': '用戶不存在'}), 404

        conn.commit()
        conn.close()
        return jsonify({'message': '郵箱更新成功'}), 200

    except sqlite3.IntegrityError:
        return jsonify({'error': '新郵箱已存在'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Update email error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Protected route
@app.route('/api/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT username, email FROM users WHERE id = ?', (decoded['userId'],))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({'error': '用戶不存在'}), 404

        return jsonify({
            'message': '訪問保護資源成功',
            'user': {
                'userId': decoded['userId'],
                'username': user['username'],
                'email': user['email']
            }
        })
    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Protected route error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# File upload route
@app.route('/api/upload', methods=['POST'])
def upload_file():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if 'file' not in request.files:
            return jsonify({'error': '未選擇文件'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '文件名為空'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': '僅支援 TXT 和 PDF 格式'}), 400

        # Save file
        filename = f"{decoded['userId']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        # Extract text and generate embedding
        content = extract_text(file_path)
        embedding = model.encode(content).tobytes() if content != "內容提取失敗" else b''

        # Store in database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO files (name, owner_id, content, embedding) VALUES (?, ?, ?, ?)',
            (file.filename, decoded['userId'], content, embedding)
        )
        conn.commit()
        conn.close()

        return jsonify({'message': '文件上傳成功'}), 201

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# AI Search route
@app.route('/api/ai_search', methods=['POST'])
def ai_search():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        data = request.get_json()
        query = data.get('query')
        if not query:
            return jsonify({'error': '請提供搜尋詞'}), 400

        # Generate query embedding
        query_embedding = model.encode(query)

        # Fetch files accessible to user (owned, shared, or shared with all)
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.id, f.name, u.username AS owner, f.embedding, f.shared_with_all,
                   GROUP_CONCAT(u2.username) AS shared_with
            FROM files f
            JOIN users u ON f.owner_id = u.id
            LEFT JOIN file_shares fs ON f.id = fs.file_id
            LEFT JOIN users u2 ON fs.user_id = u2.id
            WHERE f.owner_id = ? OR fs.user_id = ? OR f.shared_with_all = 1
            GROUP BY f.id
        ''', (decoded['userId'], decoded['userId']))
        files = cursor.fetchall()
        conn.close()

        # Calculate similarities
        results = []
        for file in files:
            if file['embedding']:
                embedding = np.frombuffer(file['embedding'], dtype=np.float32)
                similarity = util.cos_sim(query_embedding, embedding).item()
                if similarity > 0.1:  # Threshold
                    results.append({
                        'id': file['id'],
                        'name': file['name'],
                        'owner': file['owner'],
                        'shared_with': file['shared_with'] or '',
                        'shared_with_all': bool(file['shared_with_all']),
                        'similarity': similarity
                    })

        # Sort by similarity
        results.sort(key=lambda x: x['similarity'], reverse=True)
        return jsonify({'results': results}), 200

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"AI Search error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Recommendation route
@app.route('/api/recommend', methods=['GET'])
def recommend():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

        # Fetch latest file
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, embedding
            FROM files
            WHERE owner_id = ?
            ORDER BY created_at DESC
            LIMIT 1
        ''', (decoded['userId'],))
        recent_file = cursor.fetchone()

        if not recent_file or not recent_file['embedding']:
            conn.close()
            return jsonify({'results': []}), 200

        recent_embedding = np.frombuffer(recent_file['embedding'], dtype=np.float32)

        # Fetch other accessible files (owned, shared, or shared with all)
        cursor.execute('''
            SELECT f.id, f.name, u.username AS owner, f.embedding, f.shared_with_all
            FROM files f
            JOIN users u ON f.owner_id = u.id
            LEFT JOIN file_shares fs ON f.id = fs.file_id
            WHERE (f.owner_id = ? OR fs.user_id = ? OR f.shared_with_all = 1) AND f.id != ?
        ''', (decoded['userId'], decoded['userId'], recent_file['id']))
        files = cursor.fetchall()
        conn.close()

        # Calculate similarities
        results = []
        for file in files:
            if file['embedding']:
                embedding = np.frombuffer(file['embedding'], dtype=np.float32)
                similarity = util.cos_sim(recent_embedding, embedding).item()
                if similarity > 0.1:  # Threshold
                    results.append({
                        'id': file['id'],
                        'name': file['name'],
                        'owner': file['owner'],
                        'shared_with_all': bool(file['shared_with_all']),
                        'similarity': similarity
                    })

        # Sort and limit to top 5
        results.sort(key=lambda x: x['similarity'], reverse=True)
        return jsonify({'results': results[:5]}), 200

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Recommendation error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Delete file route
@app.route('/api/delete_file/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

        # Check if user owns the file
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT name, owner_id FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()

        if not file:
            conn.close()
            return jsonify({'error': '文件不存在'}), 404

        if file['owner_id'] != decoded['userId']:
            conn.close()
            return jsonify({'error': '無權限刪除此文件'}), 403

        # Delete file from storage
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(f"{file['owner_id']}_") and filename.endswith(file['name']):
                os.remove(os.path.join(UPLOAD_FOLDER, filename))
                break

        # Delete file from database
        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
        cursor.execute('DELETE FROM file_shares WHERE file_id = ?', (file_id,))
        conn.commit()
        conn.close()

        return jsonify({'message': '文件刪除成功'}), 200

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Delete file error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Rename file route
@app.route('/api/rename_file/<int:file_id>', methods=['POST'])
def rename_file(file_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        data = request.get_json()
        new_name = data.get('new_name')

        if not new_name or not allowed_file(new_name):
            return jsonify({'error': '無效的文件名或格式'}), 400

        # Check if user owns the file
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT name, owner_id FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()

        if not file:
            conn.close()
            return jsonify({'error': '文件不存在'}), 404

        if file['owner_id'] != decoded['userId']:
            conn.close()
            return jsonify({'error': '無權限重命名此文件'}), 403

        # Rename file in storage
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(f"{file['owner_id']}_") and filename.endswith(file['name']):
                old_path = os.path.join(UPLOAD_FOLDER, filename)
                timestamp = filename.split('_')[1]
                new_filename = f"{file['owner_id']}_{timestamp}_{new_name}"
                new_path = os.path.join(UPLOAD_FOLDER, new_filename)
                os.rename(old_path, new_path)
                break

        # Update file name in database
        cursor.execute('UPDATE files SET name = ? WHERE id = ?', (new_name, file_id))
        conn.commit()
        conn.close()

        return jsonify({'message': '文件重命名成功'}), 200

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Rename file error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Share file with all users route
@app.route('/api/share_file_all/<int:file_id>', methods=['POST'])
def share_file_all(file_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

        # Check if user owns the file
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT owner_id, shared_with_all FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()

        if not file:
            conn.close()
            return jsonify({'error': '文件不存在'}), 404

        if file['owner_id'] != decoded['userId']:
            conn.close()
            return jsonify({'error': '無權限共享此文件'}), 403

        # Toggle shared_with_all status
        new_status = 1 if not file['shared_with_all'] else 0
        cursor.execute('UPDATE files SET shared_with_all = ? WHERE id = ?', (new_status, file_id))
        conn.commit()
        conn.close()

        return jsonify({
            'message': '文件共享設置更新成功',
            'shared_with_all': bool(new_status)
        }), 200

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Share file all error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Download file route
@app.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

        # Check access (owned, shared, or shared with all)
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.name, f.owner_id, f.shared_with_all
            FROM files f
            LEFT JOIN file_shares fs ON f.id = fs.file_id
            WHERE f.id = ? AND (f.owner_id = ? OR fs.user_id = ? OR f.shared_with_all = 1)
        ''', (file_id, decoded['userId'], decoded['userId']))
        file = cursor.fetchone()
        conn.close()

        if not file:
            return jsonify({'error': '文件不存在或無權限'}), 403

        # Find file in uploads
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(f"{file['owner_id']}_") and filename.endswith(file['name']):
                return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

        return jsonify({'error': '文件未找到'}), 404

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Get user's uploaded files route
@app.route('/api/my_files', methods=['GET'])
def get_my_files():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

        # Fetch files owned by the user
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.id, f.name, u.username AS owner, f.shared_with_all
            FROM files f
            JOIN users u ON f.owner_id = u.id
            WHERE f.owner_id = ?
        ''', (decoded['userId'],))
        files = cursor.fetchall()
        conn.close()

        # Format response
        file_list = [{
            'id': file['id'],
            'name': file['name'],
            'owner': file['owner'],
            'shared_with_all': bool(file['shared_with_all'])
        } for file in files]

        return jsonify({'files': file_list}), 200

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"My files error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Get publicly shared files route
@app.route('/api/public_files', methods=['GET'])
def get_public_files():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

        # Fetch all publicly shared files
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.id, f.name, u.username AS owner, f.shared_with_all
            FROM files f
            JOIN users u ON f.owner_id = u.id
            WHERE f.shared_with_all = 1
        ''')
        files = cursor.fetchall()
        conn.close()

        # Format response
        file_list = [{
            'id': file['id'],
            'name': file['name'],
            'owner': file['owner'],
            'shared_with_all': bool(file['shared_with_all'])
        } for file in files]

        return jsonify({'files': file_list}), 200

    except jwt.InvalidTokenError:
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Public files error: {str(e)}")
        return jsonify({'error': '服務器錯誤'}), 500

# Serve index.html for root path
@app.route('/')
def serve_index():
    logger.debug("Serving index.html for root path")
    return send_from_directory('public', 'index.html')

# Serve index.html explicitly
@app.route('/index.html')
def serve_index_html():
    logger.debug("Serving index.html explicitly")
    return send_from_directory('public', 'index.html')

# Serve other static files, fallback to index.html for SPA
@app.route('/<path:path>')
def serve_static(path):
    logger.debug(f"Attempting to serve static file: {path}")
    if os.path.exists(os.path.join('public', path)):
        return send_from_directory('public', path)
    logger.debug("Static file not found, falling back to index.html")
    return send_from_directory('public', 'index.html')

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        init_db()
    logger.info(f"Starting Flask server on port {PORT}")
    app.run(port=PORT, debug=True)