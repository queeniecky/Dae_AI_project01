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
能查出有可能相關的文件, 僅適用於文件(e.g. txt)
例子: AI搜尋時輸入cat, 會得出以下結果
Dog.txt
擁有者: sam
共享給: 無
相似度: 19.49%
## 文件推薦(Recommendation)
上載最新文件時, 會自動推薦較相似的文件(e.g. txt)
例子: 上載W Gundam.txt, 會得出以下結果
Gundam.txt
相似度: 81.86%