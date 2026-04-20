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

        # E. 呼叫 Gemini 整理 (加入設備存活檢查與防截斷指令)
        prompt = f"""
        你是一位 Cisco 專家。這是一份從 PKA XML 中提取的原始數據流。
        
        ### 🚨 重要：強制性完整輸出要求
        1. 【主機清查】：首先掃描原始數據中出現的所有不同 'hostname'（例如 R1, S1, ISP 等）。
        2. 【嚴禁截斷】：你必須完整輸出清查到的「每一台」主機配置。禁止因為內容重複或長度原因省略任何一台設備。
        3. 【重點核對】：特別注意 R1（或路由器）的子介面 (sub-interfaces, 如 G0/1.10)，這些是 Inter-VLAN Routing 的核心答案，絕對不能漏掉。

        ### 🛠️ 高效合併與過濾規則 (Unit 1-8 標準):
        - 【Range 合併】：所有配置完全相同的連續介面（如 Access Vlan 10, Port-fast）「必須」合併為 `interface range`。
        - 【精簡顯示】：
            - 排除所有 '!'、XML 標籤、標記、以及 version, timestamps 等系統預設指令。
            - 排除狀態為 shutdown 且「完全沒有」任何 IP、VLAN 或描述設定的介面。
        - 【功能保留】：保留 enable secret, banner motd, VLAN 命名, encapsulation dot1Q, Static Route, DHCP Pool, VTY SSH。

        ### 📋 輸出結構：
        - 格式：## [HOSTNAME]
        - 設備間分隔線：'------'
        - 僅輸出 CLI 指令，嚴禁任何解釋或 Markdown 語法外的文字。

        原始數據：
        {all_cmds_text}
        """

        # 這裡的 generation_config 是防止截斷的關鍵
        response = model.generate_content(
            prompt,
            generation_config={
                "max_output_tokens": 4096,
                "temperature": 0, # 設為 0 以獲得最穩定、最不懶惰的結果
                "top_p": 1
            }
        )
        
        return {"status": "success", "data": response.text}

    except Exception as e:
        return {"status": "error", "message": f"系統錯誤: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    # 本地測試時可以使用：$ env GEMINI_API_KEY=your_key uvicorn main:app --reload
    uvicorn.run(app, host="0.0.0.0", port=8080)