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

# Configure logging with file output for persistence
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize SentenceTransformer model
try:
    model = SentenceTransformer('all-MiniLM-L6-v2')
    logger.info("SentenceTransformer model loaded successfully")
except Exception as e:
    logger.error(f"Failed to load SentenceTransformer model: {str(e)}", exc_info=True)
    raise

# Ensure upload folder exists with correct permissions
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    os.chmod(UPLOAD_FOLDER, 0o775)
    logger.info(f"Created {UPLOAD_FOLDER} directory")

def init_db():
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                content TEXT,
                embedding BLOB,
                shared_with_all INTEGER DEFAULT 0,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        ''')
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
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}", exc_info=True)
        raise
    finally:
        conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text(file_path):
    try:
        ext = file_path.rsplit('.', 1)[1].lower()
        logger.debug(f"Extracting text from {file_path} (extension: {ext})")
        if ext == 'txt':
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                logger.debug(f"Extracted {len(content)} characters from text file")
                return content
        elif ext == 'pdf':
            with pdfplumber.open(file_path) as pdf:
                text = ''.join(page.extract_text() or '' for page in pdf.pages)
                logger.debug(f"Extracted {len(text)} characters from PDF")
                return text
        logger.warning(f"Unsupported file extension: {ext}")
        return "內容提取失敗"
    except Exception as e:
        logger.error(f"Text extraction error for {file_path}: {str(e)}", exc_info=True)
        return "內容提取失敗"

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if not username or not password or not email:
            logger.warning("Registration failed: Missing required fields")
            return jsonify({'error': '請填寫所有必填字段'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            (username, hashed_password, email)
        )
        conn.commit()
        logger.info(f"User registered: {username}")
        return jsonify({'message': '用戶注冊成功'}), 201
    except sqlite3.IntegrityError:
        logger.warning("Registration failed: Username or email already exists")
        return jsonify({'error': '用戶名或郵箱已存在'}), 400
    except Exception as e:
        logger.error(f"Register error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            logger.warning("Login failed: Missing username or password")
            return jsonify({'error': '請填寫用戶名和密碼'}), 400

        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            logger.warning(f"Login failed for {username}: Invalid credentials")
            return jsonify({'error': '用戶名或密碼錯誤'}), 401

        token = jwt.encode({
            'userId': user['id'],
            'username': user['username'],
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, JWT_SECRET, algorithm='HS256')

        logger.info(f"User logged in: {username}")
        return jsonify({
            'token': token,
            'message': '登入成功',
            'redirectTo': '/dashboard.html'
        })
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/update-email', methods=['POST'])
def update_email():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Update email failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        data = request.get_json()
        new_email = data.get('email')

        if not new_email:
            logger.warning("Update email failed: No email provided")
            return jsonify({'error': '請提供新郵箱'}), 400

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET email = ? WHERE id = ?',
            (new_email, decoded['userId'])
        )
        if cursor.rowcount == 0:
            logger.warning(f"Email update failed: User ID {decoded['userId']} not found")
            return jsonify({'error': '用戶不存在'}), 404

        conn.commit()
        logger.info(f"Email updated for user ID {decoded['userId']}")
        return jsonify({'message': '郵箱更新成功'}), 200
    except sqlite3.IntegrityError:
        logger.warning("Email update failed: Email already exists")
        return jsonify({'error': '新郵箱已存在'}), 400
    except jwt.InvalidTokenError:
        logger.warning("Update email failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Update email error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Protected route failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT username, email FROM users WHERE id = ?', (decoded['userId'],))
        user = cursor.fetchone()

        if not user:
            logger.warning(f"Protected route failed: User ID {decoded['userId']} not found")
            return jsonify({'error': '用戶不存在'}), 404

        logger.debug(f"Protected route accessed by user: {user['username']}")
        return jsonify({
            'message': '訪問保護資源成功',
            'user': {
                'userId': decoded['userId'],
                'username': user['username'],
                'email': user['email']
            }
        })
    except jwt.InvalidTokenError:
        logger.warning("Protected route failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Protected route error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/upload', methods=['POST'])
def upload_file():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Upload failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        logger.debug(f"Decoded token: userId={decoded['userId']}")
        if 'file' not in request.files:
            logger.warning("Upload failed: No file selected")
            return jsonify({'error': '未選擇文件'}), 400

        file = request.files['file']
        if file.filename == '':
            logger.warning("Upload failed: Empty filename")
            return jsonify({'error': '文件名為空'}), 400

        if not allowed_file(file.filename):
            logger.warning(f"Upload failed: Unsupported file type {file.filename}")
            return jsonify({'error': '僅支援 TXT 和 PDF 格式'}), 400

        # Validate user exists
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE id = ?', (decoded['userId'],))
        if not cursor.fetchone():
            logger.warning(f"Upload failed: User ID {decoded['userId']} not found")
            return jsonify({'error': '用戶不存在'}), 404

        # Save file
        filename = f"{decoded['userId']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
        file_path = os.path.join(UPLOAD_FOLDER, filename.replace('/', '_').replace('\\', '_'))
        logger.debug(f"Saving file to: {file_path}")
        file.save(file_path)

        # Verify file was saved
        if not os.path.exists(file_path):
            logger.error(f"File save failed: {file_path} does not exist")
            return jsonify({'error': '文件保存失敗'}), 500

        # Extract text and generate embedding
        logger.debug("Extracting text from file")
        content = extract_text(file_path)
        logger.debug(f"Extracted content length: {len(content)}")
        embedding = b''
        if content != "內容提取失敗":
            try:
                embedding = model.encode(content).tobytes()
                logger.debug(f"Generated embedding size: {len(embedding)}")
            except Exception as e:
                logger.error(f"Embedding generation error: {str(e)}", exc_info=True)
                embedding = b''

        # Store in database
        logger.debug("Inserting file into database")
        cursor.execute(
            'INSERT INTO files (name, owner_id, content, embedding) VALUES (?, ?, ?, ?)',
            (file.filename, decoded['userId'], content, embedding)
        )
        conn.commit()
        logger.info(f"File uploaded successfully: {file.filename} by user ID {decoded['userId']}")
        return jsonify({'message': '文件上傳成功'}), 201
    except jwt.InvalidTokenError:
        logger.warning("Upload failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Upload error: {str(e)}", exc_info=True)
        return jsonify({'error': f'服務器錯誤: {str(e)}'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/ai_search', methods=['POST'])
def ai_search():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("AI search failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        data = request.get_json()
        query = data.get('query')
        if not query:
            logger.warning("AI search failed: No query provided")
            return jsonify({'error': '請提供搜尋詞'}), 400

        query_embedding = model.encode(query)

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

        results = []
        for file in files:
            if file['embedding']:
                embedding = np.frombuffer(file['embedding'], dtype=np.float32)
                similarity = util.cos_sim(query_embedding, embedding).item()
                if similarity > 0.1:
                    results.append({
                        'id': file['id'],
                        'name': file['name'],
                        'owner': file['owner'],
                        'shared_with': file['shared_with'] or '',
                        'shared_with_all': bool(file['shared_with_all']),
                        'similarity': similarity
                    })

        results.sort(key=lambda x: x['similarity'], reverse=True)
        logger.debug(f"AI search completed for query: {query}")
        return jsonify({'results': results}), 200
    except jwt.InvalidTokenError:
        logger.warning("AI search failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"AI search error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/recommend', methods=['GET'])
def recommend():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Recommend failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

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
            return jsonify({'results': []}), 200

        recent_embedding = np.frombuffer(recent_file['embedding'], dtype=np.float32)

        cursor.execute('''
            SELECT f.id, f.name, u.username AS owner, f.embedding, f.shared_with_all
            FROM files f
            JOIN users u ON f.owner_id = u.id
            LEFT JOIN file_shares fs ON f.id = fs.file_id
            WHERE (f.owner_id = ? OR fs.user_id = ? OR f.shared_with_all = 1) AND f.id != ?
        ''', (decoded['userId'], decoded['userId'], recent_file['id']))
        files = cursor.fetchall()

        results = []
        for file in files:
            if file['embedding']:
                embedding = np.frombuffer(file['embedding'], dtype=np.float32)
                similarity = util.cos_sim(recent_embedding, embedding).item()
                if similarity > 0.1:
                    results.append({
                        'id': file['id'],
                        'name': file['name'],
                        'owner': file['owner'],
                        'shared_with_all': bool(file['shared_with_all']),
                        'similarity': similarity
                    })

        results.sort(key=lambda x: x['similarity'], reverse=True)
        logger.debug(f"Recommendations generated for user ID {decoded['userId']}")
        return jsonify({'results': results[:5]}), 200
    except jwt.InvalidTokenError:
        logger.warning("Recommend failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Recommendation error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/delete_file/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Delete file failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT name, owner_id FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()

        if not file:
            logger.warning(f"Delete file failed: File ID {file_id} not found")
            return jsonify({'error': '文件不存在'}), 404

        if file['owner_id'] != decoded['userId']:
            logger.warning(f"Delete file failed: User ID {decoded['userId']} not owner of file {file_id}")
            return jsonify({'error': '無權限刪除此文件'}), 403

        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(f"{file['owner_id']}_") and filename.endswith(file['name']):
                os.remove(os.path.join(UPLOAD_FOLDER, filename))
                logger.debug(f"Deleted file: {filename}")
                break

        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
        cursor.execute('DELETE FROM file_shares WHERE file_id = ?', (file_id,))
        conn.commit()
        logger.info(f"File deleted: ID {file_id} by user ID {decoded['userId']}")
        return jsonify({'message': '文件刪除成功'}), 200
    except jwt.InvalidTokenError:
        logger.warning("Delete file failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Delete file error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/rename_file/<int:file_id>', methods=['POST'])
def rename_file(file_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Rename file failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        data = request.get_json()
        new_name = data.get('new_name')

        if not new_name or not allowed_file(new_name):
            logger.warning(f"Rename file failed: Invalid new name {new_name}")
            return jsonify({'error': '無效的文件名或格式'}), 400

        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT name, owner_id FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()

        if not file:
            logger.warning(f"Rename file failed: File ID {file_id} not found")
            return jsonify({'error': '文件不存在'}), 404

        if file['owner_id'] != decoded['userId']:
            logger.warning(f"Rename file failed: User ID {decoded['userId']} not owner of file {file_id}")
            return jsonify({'error': '無權限重命名此文件'}), 403

        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(f"{file['owner_id']}_") and filename.endswith(file['name']):
                old_path = os.path.join(UPLOAD_FOLDER, filename)
                timestamp = filename.split('_')[1]
                new_filename = f"{file['owner_id']}_{timestamp}_{new_name}"
                new_path = os.path.join(UPLOAD_FOLDER, new_filename)
                os.rename(old_path, new_path)
                logger.debug(f"Renamed file from {filename} to {new_filename}")
                break

        cursor.execute('UPDATE files SET name = ? WHERE id = ?', (new_name, file_id))
        conn.commit()
        logger.info(f"File renamed: ID {file_id} to {new_name} by user ID {decoded['userId']}")
        return jsonify({'message': '文件重命名成功'}), 200
    except jwt.InvalidTokenError:
        logger.warning("Rename file failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Rename file error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/share_file_all/<int:file_id>', methods=['POST'])
def share_file_all(file_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Share file failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT owner_id, shared_with_all FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()

        if not file:
            logger.warning(f"Share file failed: File ID {file_id} not found")
            return jsonify({'error': '文件不存在'}), 404

        if file['owner_id'] != decoded['userId']:
            logger.warning(f"Share file failed: User ID {decoded['userId']} not owner of file {file_id}")
            return jsonify({'error': '無權限共享此文件'}), 403

        new_status = 1 if not file['shared_with_all'] else 0
        cursor.execute('UPDATE files SET shared_with_all = ? WHERE id = ?', (new_status, file_id))
        conn.commit()
        logger.info(f"File share status updated: ID {file_id} to shared_with_all={new_status} by user ID {decoded['userId']}")
        return jsonify({
            'message': '文件共享設置更新成功',
            'shared_with_all': bool(new_status)
        }), 200
    except jwt.InvalidTokenError:
        logger.warning("Share file failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Share file error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/download/<int:file_id>', methods=['GET'])
def download_file(file_id):
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Download failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

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

        if not file:
            logger.warning(f"Download failed: File ID {file_id} not found or no permission for user ID {decoded['userId']}")
            return jsonify({'error': '文件不存在或無權限'}), 403

        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.startswith(f"{file['owner_id']}_") and filename.endswith(file['name']):
                logger.debug(f"Downloading file: {filename}")
                return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

        logger.warning(f"Download failed: File {file['name']} not found in {UPLOAD_FOLDER}")
        return jsonify({'error': '文件未找到'}), 404
    except jwt.InvalidTokenError:
        logger.warning("Download failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Download error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/my_files', methods=['GET'])
def get_my_files():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("My files failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

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

        file_list = [{
            'id': file['id'],
            'name': file['name'],
            'owner': file['owner'],
            'shared_with_all': bool(file['shared_with_all'])
        } for file in files]

        logger.debug(f"Fetched {len(file_list)} files for user ID {decoded['userId']}")
        return jsonify({'files': file_list}), 200
    except jwt.InvalidTokenError:
        logger.warning("My files failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"My files error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/public_files', methods=['GET'])
def get_public_files():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        logger.warning("Public files failed: No token provided")
        return jsonify({'error': '未提供token'}), 401

    token = token.split(' ')[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])

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

        file_list = [{
            'id': file['id'],
            'name': file['name'],
            'owner': file['owner'],
            'shared_with_all': bool(file['shared_with_all'])
        } for file in files]

        logger.debug(f"Fetched {len(file_list)} public files")
        return jsonify({'files': file_list}), 200
    except jwt.InvalidTokenError:
        logger.warning("Public files failed: Invalid token")
        return jsonify({'error': '無效的token'}), 401
    except Exception as e:
        logger.error(f"Public files error: {str(e)}", exc_info=True)
        return jsonify({'error': '服務器錯誤'}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/')
def serve_index():
    logger.debug("Serving index.html for root path")
    return send_from_directory('public', 'index.html')

@app.route('/index.html')
def serve_index_html():
    logger.debug("Serving index.html explicitly")
    return send_from_directory('public', 'index.html')

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