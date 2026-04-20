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

def clean_xml_tag(text):
    """移除 XML 轉義字元"""
    if not text: return ""
    return text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').replace('&quot;', '"').replace('&apos;', "'").strip()

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        print(f"收到檔案: {file.filename}")
        pka_bytes = await file.read()
        print("正在解密 PKA...")
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')
        print(f"解密完成，長度: {len(content)}")

        # A. 深度脫水 (移除圖片與大量無用 Session 資料，防止 Regex 回溯失敗)
        print("正在進行深度脫水...")
        content = re.sub(r'<(PIXMAPBANK|GUI_DATA|SESSION_DATA|COMMAND_HISTORY)>.*?</\1>', '', content, flags=re.DOTALL | re.IGNORECASE)
        print(f"脫水完成，剩餘長度: {len(content)}")

        # B. 線性掃描與全設備解析邏輯
        print("正在執行線性路徑掃描...")
        device_data = {} # {name: [lines]}

        # 策略 1：掃描所有配置塊 (RUNNINGCONFIG, STARTUPCONFIG, IOS_CONFIG)
        config_blocks = re.finditer(r'<(RUNNINGCONFIG|STARTUPCONFIG|IOS_CONFIG)>(.*?)</\1>', content, re.DOTALL | re.IGNORECASE)
        for match in config_blocks:
            block_content = match.group(2)
            # 向前回溯 30000 字元尋找最近的設備名稱
            lookback_area = content[max(0, match.start()-30000) : match.start()]
            name_match = re.findall(r'<(SYS_NAME|NAME)[^>]*?>(.*?)</\1>', lookback_area, re.IGNORECASE | re.DOTALL)
            
            dev_name = "Unknown_Device"
            if name_match:
                # 拿最後一個 (也就是最近的一個)
                dev_name = clean_xml_tag(name_match[-1][1])

            if dev_name not in device_data: device_data[dev_name] = []
            
            lines = re.findall(r'<LINE>(.*?)</LINE>', block_content, re.DOTALL | re.IGNORECASE)
            for l in lines:
                l_clean = clean_xml_tag(l)
                if l_clean and l_clean != "!":
                    device_data[dev_name].append(l_clean)

        # 策略 2：掃描所有設備標籤下的獨立定址資訊 (針對 PC/Server)
        print("正在掃描設備靜態定址資訊...")
        devices = re.finditer(r'<DEVICE.*?>.*?</DEVICE>', content, re.DOTALL | re.IGNORECASE)
        for dev_match in devices:
            dev_block = dev_match.group(0)
            # 取得名稱
            n_match = re.search(r'<(SYS_NAME|NAME)[^>]*?>(.*?)</\1>', dev_block, re.IGNORECASE | re.DOTALL)
            name = clean_xml_tag(n_match.group(2)) if n_match else None
            if not name: continue

            if name not in device_data: device_data[name] = []
            
            # 抓取常見定址標籤 (IP, Gateway, IPv6)
            # 這裡我們用簡單的 findall 抓取所有這類標籤的「內容」
            addr_tags = ["IP_ADDRESS", "GATEWAY", "SUBNET_MASK", "IPV6_ADDRESS", "IPV6_PORT_GATEWAY", "IPV6_LINK_LOCAL"]
            for tag in addr_tags:
                matches = re.findall(f'<{tag}[^>]*?>(.*?)</{tag}>', dev_block, re.IGNORECASE | re.DOTALL)
                for val in matches:
                    val_clean = clean_xml_tag(val)
                    if val_clean and val_clean != "0.0.0.0" and len(val_clean) > 2:
                        device_data[name].append(f"{tag}: {val_clean}")

        # C. 彙整數據
        extracted_blocks = []
        for dev, lines in device_data.items():
            if lines:
                # 簡單去重
                unique_lines = []
                seen = set()
                for l in lines:
                    if l not in seen:
                        unique_lines.append(l)
                        seen.add(l)
                extracted_blocks.append(f"### DEVICE: {dev}\n" + "\n".join(unique_lines))

        all_cmds_text = "\n\n".join(extracted_blocks)
        print(f"提取完成，總長度: {len(all_cmds_text)}，設備數: {len(device_data)}")

        if len(all_cmds_text) < 50:
            return {"status": "error", "message": "無法在檔案中定位到任何有效的配置或定址資訊"}

        # D. 提示詞：CCIE 專家級彙整
        prompt = f"""
        你是一位 Cisco CCIE 專家教官。我提供了從 PKA 中提取的混和定址資訊與 CLI 配置。
        
        ### 任務：
        1. 【全向彙整】：請根據 `DEVICE` 標記，將配置整理為 ## [HOSTNAME]。如果是 PC 設備，請特別列出其 IP、Gateway 與 IPv6 位址。
        2. 【深度核對】：確保 4.1.3.5 等挑戰實驗中的 IPv4/IPv6、子介面、封裝指令 (dot1Q) 與靜態路由完整呈現。
        3. 【Range 特化】：路由器/交換器的相同連續介面配置，必須合併為 `interface range` 指令。
        4. 【純淨輸出】：移除所有 '!' 與 version, timestamps 等系統冗餘訊息。

        ### 輸出格式：
        - 標題：## [HOSTNAME]
        - 設備間分隔線：'------'
        - 僅輸出純淨 CLI 指令或端點定址參數，嚴禁 Markdown 區塊外的文字解釋。

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