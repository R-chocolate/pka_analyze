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

        # C. 提取 Network 區塊 (修改版：合併所有區塊以防遺漏設備)
        network_blocks = re.findall(r'<NETWORK.*?</NETWORK>', content, re.IGNORECASE | re.DOTALL)
        
        if not network_blocks:
            # 如果連標籤都找不到，回傳解密內容前 50 字偵錯
            debug_info = content[:50].replace('<', '&lt;')
            return {"status": "error", "message": f"無法解析 PKA 結構：找不到 NETWORK 標籤。解密開頭：{debug_info}"}
            
        # 關鍵修改：不只取 [-1]，我們取所有區塊並合併 (通常答案分布在最後 1-2 個 NETWORK 區塊)
        # 合併所有 block，讓 AI 自己去判斷哪些是重複的
        answer_block = "\n".join(network_blocks) 
        
        # D. 提取所有 LINE 指令 (這時會包含 R1, S1 等所有設備)
        raw_lines = re.findall(r'<LINE>(.*?)</LINE>', answer_block, re.IGNORECASE | re.DOTALL)
        clean_cmds = [l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&') for l in raw_lines]
        all_cmds_text = "\n".join(clean_cmds)
        
        if not all_cmds_text:
             return {"status": "error", "message": "已定位到 Network 區塊，但內部沒有任何指令標籤"}

        # E. 呼叫 Gemini 整理 (加入設備存活檢查與防遺漏指令)
        prompt = f"""
        你是一位 Cisco 網路教官。我將提供從 PKA XML 中提取的原始 Running-config。
        請嚴格執行以下多階段處理邏輯：

        ### 第一階段：設備存活清查 (必做)
        - 請先掃描原始數據中出現的所有不同 'hostname'。
        - 你必須意識到：如果忽略了路由器（如 R1）的子介面配置，這份答案就是 0 分。
        - 強制要求：你必須輸出原始數據中出現過的「每一台」主機配置，嚴禁截斷或省略。

        ### 第二階段：指令壓縮與合併 (Unit 1-8 標準)
        - 【Range 合併】：所有配置完全相同的連續介面（例如 F0/11-17 全是 Access VLAN 10），必須合併為 `interface range`。
        - 【精簡噪音】：
            - 移除所有 '!' 符號與 XML 殘留標籤。
            - 移除 version, timestamps, ip classless 等系統自動生成的冗餘行。
            - 排除沒有任何 IP 或 VLAN 配置且處於 shutdown 狀態的介面。

        ### 第三階段：重點功能保留
        - 保留 enable secret、VLAN 命名、子介面 (sub-interfaces) 封裝指令 (encapsulation dot1Q)、Static Route 與 DHCP 設定。

        ### 輸出格式：
        - 格式：## [HOSTNAME]
        - 分隔線：'------'
        - 僅輸出純淨的 CLI 指令，嚴禁任何 Markdown 區塊外的文字解釋。

        原始數據：
        {all_cmds_text}
        """

        # 增加 max_output_tokens 以確保空間，temperature 設為 0 以保持穩定
        response = model.generate_content(
            prompt,
            generation_config={
                "max_output_tokens": 4096,
                "temperature": 0,
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