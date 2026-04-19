import os
import re
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
from fastapi.responses import FileResponse
from Decipher.pt_crypto import decrypt_pkt

# 1. 初始化
app = FastAPI()

@app.get("/")
async def read_index():
    return FileResponse('index.html')

# 強制開啟 CORS，否則 Vercel 會連不進來
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

# 填入你的 Gemini API KEY
genai.configure(api_key="AIzaSyCSDsMvOh7vtMxO262Zi0rZl1D86X2IAC0")
model = genai.GenerativeModel('gemini-3.1-flash-lite-preview')

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        # A. 讀取並解密
        pka_bytes = await file.read()
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')

        # B. 提取指令 (改用正規表達式忽略大小寫，解決 NETWORK vs Network 問題)
        # 使用 re.IGNORECASE 確保大小寫通殺，re.DOTALL 確保跨行抓取
        network_blocks = re.findall(r'<NETWORK.*?</NETWORK>', content, re.IGNORECASE | re.DOTALL)
        
        if not network_blocks:
            # 如果連標籤都找不到，回傳解密內容前 50 字偵鎖 (看是否解密失敗變亂碼)
            debug_info = content[:50].replace('<', '&lt;')
            return {"status": "error", "message": f"無法解析 PKA 結構。解密開頭：{debug_info}"}
            
        # 取得最後一個 Network 區塊 (通常是答案區)
        answer_block = network_blocks[-1]
        
        # 提取 LINE 指令 (同樣忽略大小寫)
        raw_lines = re.findall(r'<LINE>(.*?)</LINE>', answer_block, re.IGNORECASE | re.DOTALL)
        clean_cmds = [l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&') for l in raw_lines]
        all_cmds_text = "\n".join(clean_cmds)
        
        if not all_cmds_text:
             return {"status": "error", "message": "已定位到 Network 區塊，但內部沒有任何 LINE 指令標籤"}

        # C. 呼叫 Gemini 整理
        prompt = f"你是一個專業 Cisco 教官，請將以下原始指令按 hostname 分類，並依正確順序排列成乾淨的配置腳本：\n\n{all_cmds_text}"
        response = model.generate_content(prompt)
        
        return {"status": "success", "data": response.text}

    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)