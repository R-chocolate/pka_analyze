import os
import re
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
from Decipher.pt_crypto import decrypt_pkt

# 1. 初始化
app = FastAPI()

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

        # B. 提取指令 (利用你之前驗證過的 LINE 標籤提取法) 
        start_idx = content.rfind("<NETWORK")
        end_idx = content.find("</NETWORK>", start_idx)
        if start_idx == -1 or end_idx == -1:
            return {"status": "error", "message": "無法解析 PKA 結構"}
            
        answer_block = content[start_idx : end_idx + 10]
        raw_lines = re.findall(r'<LINE>(.*?)</LINE>', answer_block)
        clean_cmds = [l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&') for l in raw_lines]
        all_cmds_text = "\n".join(clean_cmds)
        
        if not all_cmds_text:
            return {"status": "error", "message": "此檔案內無配置指令"}

        # C. 呼叫 Gemini 整理
        prompt = f"你是一個專業 Cisco 教官，請將以下原始指令按 hostname 分類，並依正確順序排列成乾淨的配置腳本：\n\n{all_cmds_text}"
        response = model.generate_content(prompt)
        
        return {"status": "success", "data": response.text}

    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)