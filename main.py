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

@app.get("/ping")
async def ping():
    """用來給 Cloud Scheduler 定時敲醒伺服器用"""
    return {"status": "alive"}

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        print(f"收到檔案: {file.filename}")
        pka_bytes = await file.read()
        print("正在解密 PKA...")
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')
        print(f"解密完成，長度: {len(content)}")

        # A. 暴力脫水 (先拿掉巨大的圖片資料，否則 Regex 會跑不動)
        print("正在移除 XML 雜訊 (PIXMAP/GUI)...")
        content = re.sub(r'<(PIXMAPBANK|GUI_DATA)>.*?</\1>', '', content, flags=re.DOTALL)
        print(f"脫水完成，剩餘長度: {len(content)}")

        # B. 結構化提取：尋找所有可能的「設備容器」
        # 同時找 DEVICE, RUNNINGCONFIG, SYS_NAME 這些關鍵標籤
        print("正在執行多維容器掃描 (Device/RunningConfig/SysName)...")
        containers = re.findall(r'<(DEVICE|RUNNINGCONFIG|SYS_NAME).*?>(.*?)</\1>', content, re.DOTALL | re.IGNORECASE)
        
        extracted_blocks = []
        for tag, body in containers:
            # 在每個盒子裡找 LINE 指令
            lines = re.findall(r'<LINE>(.*?)</LINE>', body, re.DOTALL | re.IGNORECASE)
            if lines:
                clean_lines = [l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').strip() for l in lines]
                # 簡單整理：過濾掉重複驚嘆號或空行
                useful_lines = [l for l in clean_lines if l and l != "!"]
                if useful_lines:
                    block_text = f"--- BLOCK_TYPE: {tag} ---\n" + "\n".join(useful_lines)
                    extracted_blocks.append(block_text)

        # C. 備援機制：如果依照結構抓不到足夠內容，才啟動全域暴力提取
        all_cmds_text = "\n\n".join(extracted_blocks)
        if len(all_cmds_text) < 100:
            print("結構化提取字數不足，啟動全域暴力提取模式...")
            raw_lines = re.findall(r'<LINE>(.*?)</LINE>', content, re.DOTALL | re.IGNORECASE)
            all_cmds_text = "\n".join([l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').strip() for l in raw_lines])

        print(f"提取指令完成，總長度: {len(all_cmds_text)}")
        
        if not all_cmds_text:
             print("錯誤: 找不到任何指令內容")
             return {"status": "error", "message": "無法在檔案中定位到任何有效的配置指令標籤"}

        # D. 提示詞微調：回歸通用高強度模式，適配所有實驗類型
        prompt = f"""
        你是一位 Cisco CCIE 專家。我提供了從 PKA 結構中提取出的原始配置流。
        
        ### 任務：
        1. 【精確分類】：根據 `hostname` 指令和 `BLOCK_TYPE` 標籤，將配置重新整理為 ## [HOSTNAME]。
        2. 【指令完整性】：確保所有核心配置完整。特別注意路由器子介面 (sub-interfaces)、IPv4/IPv6 雙疊加配置、靜態路由與封裝指令，嚴禁截斷或省略。
        3. 【Range 壓縮】：所有配置完全相同的連續介面必須合併為 `interface range` 指令，大幅提高可讀性。
        4. 【專業整理】：移除所有 '!' 與冗餘系統行 (如 version, timestamp, service timestamps 等)。

        ### 輸出格式：
        - 標題：## [HOSTNAME]
        - 設備間分隔線：'------'
        - 僅輸出純淨的 CLI 指令，嚴禁 Markdown 區塊外的文字解釋。

        原始數據：
        {all_cmds_text}
        """

        # 保持穩定性
        print("正在等待 Gemini 回應...")
        response = model.generate_content(
            prompt,
            generation_config={"max_output_tokens": 4096, "temperature": 0}
        )
        print("Gemini 分析完畢！")
        
        return {"status": "success", "data": response.text}

    except Exception as e:
        print(f"發生系統錯誤: {str(e)}")
        return {"status": "error", "message": f"系統錯誤: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)