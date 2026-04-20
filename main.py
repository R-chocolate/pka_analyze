import os
import re
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import google.generativeai as genai
from Decipher.pt_crypto import decrypt_pkt

# 1. 初始化
app = FastAPI()

# 強制開啟 CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

# 從環境變數讀取 API KEY
API_KEY = os.environ.get("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

model = genai.GenerativeModel('gemini-3.1-flash-lite-preview')

@app.get("/")
async def read_index():
    return FileResponse('index.html')

@app.get("/ping")
async def ping():
    return {"status": "alive"}

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        print(f"收到檔案: {file.filename}")
        pka_bytes = await file.read()
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')

        # A. 暴力脫水 (先拿掉巨大的圖片與 GUI 資料)
        content = re.sub(r'<(PIXMAPBANK|GUI_DATA)>.*?</\1>', '', content, flags=re.DOTALL)

        # B. 結構化導向提取：DEVICE -> NAME -> RUNNINGCONFIG -> LINE
        print("正在執行結構化路徑提取...")
        device_blocks = re.findall(r'<DEVICE.*?>.*?</DEVICE>', content, re.DOTALL | re.IGNORECASE)
        
        extracted_blocks = []
        for block in device_blocks:
            # 1. 抓取設備名稱 (優先找 NAME, 備選 SYS_NAME)
            name_match = re.search(r'<NAME[^>]*?>(.*?)</NAME>', block, re.IGNORECASE | re.DOTALL)
            if not name_match:
                name_match = re.search(r'<SYS_NAME>(.*?)</SYS_NAME>', block, re.IGNORECASE | re.DOTALL)
            
            dev_name = name_match.group(1).strip() if name_match else "Unknown_Device"

            # 2. 僅提取該設備下的 RUNNINGCONFIG 區塊
            config_match = re.search(r'<RUNNINGCONFIG>(.*?)</RUNNINGCONFIG>', block, re.IGNORECASE | re.DOTALL)
            if config_match:
                config_body = config_match.group(1)
                lines = re.findall(r'<LINE>(.*?)</LINE>', config_body, re.DOTALL | re.IGNORECASE)
                
                clean_lines = [l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').strip() for l in lines]
                useful_lines = [l for l in clean_lines if l and l != "!"]
                
                if useful_lines:
                    extracted_blocks.append(f"--- DEVICE: {dev_name} ---\n" + "\n".join(useful_lines))

        # C. 備援機制：如果依照結構抓不到東西，啟動全域 LINE 掃描
        all_cmds_text = "\n\n".join(extracted_blocks)
        if len(all_cmds_text) < 100:
            print("結構化提取字數不足，啟動全域掃描...")
            raw_lines = re.findall(r'<LINE>(.*?)</LINE>', content, re.DOTALL | re.IGNORECASE)
            all_cmds_text = "\n".join([l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').strip() for l in raw_lines])

        print(f"提取指令完成，總長度: {len(all_cmds_text)}")
        
        if not all_cmds_text:
             return {"status": "error", "message": "無法在檔案中定位到任何有效的配置指令"}

        # D. 提示詞：CCIE 專家整理
        prompt = f"""
        你是一位 Cisco CCIE 專家。我提供了從 PKA 結構中提取出的原始配置。
        
        ### 任務：
        1. 【整理與合併】：請根據 `DEVICE` 標記整理配置，輸出格式為 ## [HOSTNAME]。
        2. 【完整性】：確保 4.1.3.5 等實驗中的 IPv4/IPv6 與子介面配置完整，嚴禁刪除關鍵指令。
        3. 【Range 壓縮】：多個相同配置的連續介面必須合併為 `interface range` 指令。
        4. 【精簡】：移除所有 '!' 與系統冗餘行 (如 version, timestamps 等)。

        ### 輸出格式：
        - 標題：## [HOSTNAME]
        - 分隔線：'------'
        - 僅輸出純淨 CLI 指令，嚴禁解釋文字。

        原始數據：
        {all_cmds_text}
        """

        response = model.generate_content(
            prompt,
            generation_config={"max_output_tokens": 4096, "temperature": 0}
        )
        
        return {"status": "success", "data": response.text}

    except Exception as e:
        print(f"發生系統錯誤: {str(e)}")
        return {"status": "error", "message": f"系統錯誤: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)