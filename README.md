# 安裝網站流程
1. 安裝 Python
https://www.python.org/downloads/
2. 在項目目錄中創建一個 Python 虛擬環境
python -m venv .venv
3. 激活虛擬環境
source .venv/Scripts/activate
4. 在虛擬環境中，使用 pip 安裝所需的 Python 包
pip install -r requirements.txt
5. 直接運行 app.py
python app.py

# AI功能介紹
## AI 內容搜尋(AI Search)
能查出有可能相關的文件, 僅適用於文件(e.g. txt/pdf)
例子: AI搜尋時輸入cat, 會得出以下結果
Dog.txt
擁有者: sam
共享給: 無
相似度: 19.49%
## 文件推薦(Recommendation)
上載最新文件時, 會自動推薦較相似的文件(e.g. txt/pdf)
例子: 上載W Gundam.txt, 會得出以下結果
Gundam.txt
相似度: 81.86%

### 網站介紹
**文件管理系統** 是一個基於 Web 的應用程式，允許用戶上傳、搜尋、共享、下載和管理文件，並提供 AI 搜尋和文件推薦功能。用戶可通過註冊/登入進行身份驗證，管理個人文件並與他人共享，同時支援淺色/深色主題切換。

### 運作原理
1. **前端（templates/）**：
   - 使用 HTML 和 Tailwind CSS 構建響應式介面（`index.html` 首頁，`login.html` 登入，`register.html` 註冊，`dashboard.html` 文件管理，`settings.html` 主題設置）。
   - JavaScript 處理動態交互（如文件上傳、搜尋、共享、刪除），通過 `fetch` 與後端 API 通信。
   - `dashboard.html` 提供文件列表、AI 搜尋（基於內容）和推薦功能，動態渲染文件和主題。

2. **後端（app.py）**：
   - 使用 **Flask** 框架處理 HTTP 請求，路由包括：
     - `/`（首頁）、`/login`（登入）、`/register`（註冊）、`/logout`（登出）。
     - `/dashboard`（文件管理介面）、`/upload`（上傳文件）、`/files`（獲取文件列表）。
     - `/ai_search`（AI 搜尋）、`/recommend`（文件推薦）、`/share`（共享）、`/delete`（刪除）、`/download`（下載）。
     - `/settings`（主題設置）。
   - **SQLite** 資料庫（`file_management.db`）儲存用戶資訊（`users` 表）、文件元數據和嵌入向量（`files` 表）以及共享關係（`file_shares` 表）。
   - **Session** 管理用戶登錄狀態，確保權限控制（如僅文件擁有者可共享或刪除）。

3. **AI 功能**：
   - 使用 **SentenceTransformer**（`all-MiniLM-L6-v2`）生成文件內容的嵌入向量，儲存於 `files` 表的 `embedding` 欄位。
   - **AI 搜尋**：計算用戶查詢詞與文件嵌入向量的餘弦相似度，返回相似度 > 0.1 的文件。
   - **文件推薦**：根據用戶最新上傳文件的嵌入向量，推薦相似度 > 0.1 的其他文件（最多 5 個）。

4. **文件處理**：
   - 上傳文件儲存於 `Uploads/` 資料夾（列入 `.gitignore`），支援 PDF 和 TXT 格式。
   - 使用 **pdfplumber** 提取 PDF 內容，TXT 文件直接讀取，內容用於生成嵌入向量。

### 相關技術
- **前端**：HTML, Tailwind CSS, JavaScript（`fetch` API 實現非同步請求）。
- **後端**：Flask（Web 框架）、Werkzeug（密碼雜湊和 session 管理）。
- **資料庫**：SQLite（輕量級關係型資料庫）。
- **AI 功能**：SentenceTransformer（生成嵌入向量）、NumPy（向量計算）、pdfplumber（PDF 內容提取）。
- **依賴**：列於 `requirements.txt`，包括 Flask 2.3.3、sentence-transformers 2.2.2、torch 2.1.0、pdfplumber 0.11.4、numpy 1.24.3 等。

### 執行流程
1. 用戶通過 `/login` 或 `/register` 登錄/註冊，session 記錄用戶資訊。
2. 進入 `/dashboard`，顯示文件列表（`/files`）和推薦文件（`/recommend`）。
3. 用戶可上傳文件（`/upload`），觸發內容提取和嵌入向量生成。
4. 文件名稱搜尋（`/files?search=`）和 AI 搜尋（`/ai_search`）動態更新文件列表。
5. 用戶可共享（`/share`）、刪除（`/delete`）或下載（`/download`）文件，僅擁有者可執行共享和刪除。
6. 主題設置（`/settings`）儲存於 `users` 表，動態應用於前端。

### 總結
該系統結合 Flask 的輕量級後端、SQLite 的簡單資料庫管理和 SentenceTransformer 的 AI 能力，提供高效的文件管理和智能化搜尋/推薦功能，適合小型文件共享與管理場景。