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

        # E. 呼叫 Gemini 整理 (萬用模式識別與壓縮 Prompt)
        prompt = f"""
        你是一位 Cisco 網路架構師。請解析以下原始數據，並生成一份乾淨、完整且高效的配置清單。

        ### 任務目標：
        1. 【全設備掃描】：掃描數據中出現的所有 'hostname'。不論名稱為何，請確保每一台設備的配置都必須被完整輸出，嚴禁遺漏。
        2. 【模式合併 (Range 邏輯)】：
           - 掃描所有 interface 配置。若連續介面的配置參數（如 switchport mode, access vlan, port-security）完全相同，必須合併為 `interface range` 指令。
           - 這是為了提高輸出效率並縮短長度，確保所有主機都能被塞進輸出結果。
        3. 【功能保留原則】：根據 CCNA 標準教材（Unit 1-8），保留以下關鍵配置：
           - [基礎]：enable secret, username, banner motd, line 密碼與 SSH 設定。
           - [交換]：VLAN 創建與命名、Trunk 設定 (native vlan, allowed vlan)、STP (port-fast, root primary)。
           - [路由]：所有子介面 (sub-interfaces)、encapsulation dot1Q、Static Route、動態路由宣告 (OSPF/RIP)。
           - [服務]：DHCP Pool、Excluded-addresses、IP Default-gateway。

        ### 排除規則 (Noise Filter)：
        - 移除所有 '!' 與 XML 標籤。
        - 移除 version, service timestamps, ip classless 等系統預設靜態指令。
        - 移除狀態為 shutdown 且沒有任何特殊配置（無 IP, 無 VLAN）的介面。

        ### 輸出格式：
        - 標題：'## [HOSTNAME]'。
        - 分隔：設備間以 '------' 區隔。
        - 僅輸出 CLI 指令，嚴禁任何解釋或 Markdown 代碼塊以外的廢話。

        原始數據流：
        {all_cmds_text}
        """

        # 增加 max_output_tokens 確保長度充足，temperature 設低確保精準度
        response = model.generate_content(
            prompt,
            generation_config={
                "max_output_tokens": 4096,
                "temperature": 0.1,
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