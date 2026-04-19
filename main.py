import os
import re
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import google.generativeai as genai
from Decipher.pt_crypto import decrypt_pkt

# 1. 初始化
app = FastAPI()

# 強制開啟 CORS，確保前端能調用
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

# 從環境變數讀取 API KEY，避免洩漏到 GitHub
API_KEY = os.environ.get("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

model = genai.GenerativeModel('gemini-3.1-flash-lite-preview')

@app.get("/")
async def read_index():
    return FileResponse('index.html')

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        # A. 讀取並解密
        pka_bytes = await file.read()
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')

        # B. 暴力脫水 (移除圖片與 GUI 雜訊，這是解析成功的關鍵)
        content = re.sub(r'<PIXMAPBANK>.*?</PIXMAPBANK>', '', content, flags=re.DOTALL)
        content = re.sub(r'<GUI_DATA>.*?</GUI_DATA>', '', content, flags=re.DOTALL)

        # C. 提取 Network 區塊 (忽略大小寫，跨行抓取)
        network_blocks = re.findall(r'<NETWORK.*?</NETWORK>', content, re.IGNORECASE | re.DOTALL)
        
        if not network_blocks:
            debug_info = content[:50].replace('<', '&lt;')
            return {"status": "error", "message": f"無法解析 PKA 結構。解密開頭：{debug_info}"}
            
        # 取得最後一個 Network 區塊 (通常是答案區)
        answer_block = network_blocks[-1]
        
        # D. 提取 LINE 指令
        raw_lines = re.findall(r'<LINE>(.*?)</LINE>', answer_block, re.IGNORECASE | re.DOTALL)
        clean_cmds = [l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&') for l in raw_lines]
        all_cmds_text = "\n".join(clean_cmds)
        
        if not all_cmds_text:
             return {"status": "error", "message": "已定位到 Network 區塊，但內部沒有任何指令標籤"}

        # E. 呼叫 Gemini 整理
        prompt = f"你是一個專業 Cisco 教官，請將以下原始指令按 hostname 分類，並依正確順序排列成乾淨的配置腳本：\n\n{all_cmds_text}"
        response = model.generate_content(prompt)
        
        return {"status": "success", "data": response.text}

    except Exception as e:
        return {"status": "error", "message": f"系統錯誤: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    # 本地測試時可以使用：$ env GEMINI_API_KEY=your_key uvicorn main:app --reload
    uvicorn.run(app, host="0.0.0.0", port=8080)