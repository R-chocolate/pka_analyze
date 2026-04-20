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

def fast_extract_tags(content, tag_name):
    """高效提取標籤內容，避開正則表達式的回溯問題"""
    results = []
    start_tag = f"<{tag_name}"
    end_tag = f"</{tag_name}>"
    
    start_pos = 0
    while True:
        start_idx = content.find(start_tag, start_pos)
        if start_idx == -1: break
        
        header_end = content.find('>', start_idx)
        if header_end == -1: break
        
        end_idx = content.find(end_tag, header_end)
        if end_idx == -1: break
        
        results.append(content[header_end + 1 : end_idx])
        start_pos = end_idx + len(end_tag)
    return results

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        print(f"收到檔案: {file.filename}")
        pka_bytes = await file.read()
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')

        # A. 數據脫水 (保持基本清理)
        content = re.sub(r'<(PIXMAPBANK|GUI_DATA|SESSION_DATA)>.*?</\1>', '', content, flags=re.DOTALL | re.IGNORECASE)

        # B. 高性能線性提取
        device_data = {} # {name: [lines]}
        seen_configs = set() # 用於防止完全重複的配置塊 (如 Running 與 Startup 相同時)

        # 1. 提取所有配置標籤
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG", "IOS_CONFIG"]:
            configs = fast_extract_tags(content, tag)
            for config_body in configs:
                # 區塊級去重：如果這個配置內容完全看過了，就不重複處理
                config_hash = hash(config_body)
                if config_hash in seen_configs: continue
                seen_configs.add(config_hash)

                # 定位主人
                body_pos = content.find(config_body)
                lookback = content[max(0, body_pos-30000) : body_pos]
                name_match = re.findall(r'<(SYS_NAME|NAME)[^>]*?>(.*?)</\1>', lookback, re.IGNORECASE | re.DOTALL)
                dev_name = clean_xml_tag(name_match[-1][1]) if name_match else "Unknown"
                
                if dev_name not in device_data: device_data[dev_name] = []
                
                lines = re.findall(r'<LINE>(.*?)</LINE>', config_body, re.DOTALL | re.IGNORECASE)
                for l in lines:
                    l_clean = clean_xml_tag(l)
                    # 預過濾掉完全沒用的噪音，但保留結構指令
                    if l_clean and l_clean != "!" and not l_clean.startswith("Building configuration"):
                        device_data[dev_name].append(l_clean)

        # 2. 提取 PC/Server 屬性
        device_blocks = fast_extract_tags(content, "DEVICE")
        for dev_block in device_blocks:
            n_match = re.search(r'<(SYS_NAME|NAME)[^>]*?>(.*?)</\1>', dev_block, re.IGNORECASE | re.DOTALL)
            name = clean_xml_tag(n_match.group(2)) if n_match else "Unknown"
            if name not in device_data: device_data[name] = []
            
            for tag in ["IP_ADDRESS", "GATEWAY", "IPV6_ADDRESS"]:
                vals = re.findall(f'<{tag}[^>]*?>(.*?)</{tag}>', dev_block, re.IGNORECASE | re.DOTALL)
                for v in vals:
                    v_clean = clean_xml_tag(v)
                    if v_clean and v_clean != "0.0.0.0" and len(v_clean) > 2:
                        # 標註這是靜態設定，避免與 CLI 混淆
                        info = f"[Static] {tag}: {v_clean}"
                        if info not in device_data[name]:
                            device_data[name].append(info)

        # C. 數據整合 (移除不合理的「行級去重」，因為 no shutdown 等指令可能會重複出現)
        extracted_blocks = []
        for dev, lines in device_data.items():
            if lines:
                extracted_blocks.append(f"### DEVICE: {dev}\n" + "\n".join(lines))

        all_cmds_text = "\n\n".join(extracted_blocks)
        
        if not all_cmds_text:
             return {"status": "error", "message": "無法在檔案中定位到任何配置"}

        # D. 提示詞恢復：CCIE 專家強度
        prompt = f"""
        你是一位 Cisco CCIE 專家，現在正在審核一份 Packet Tracer 實驗的配置數據。
        
        ### 任務：
        1. 【精確整理】：根據 `DEVICE` 標記整理配置，輸出格式為 ## [HOSTNAME]。
        2. 【完整性守護】：這是一項極其嚴肅的任務。必須確保 4.1.3.5 等實驗中的 IPv4/IPv6、子介面配置、封裝格式 (encapsulation dot1Q) 以及關鍵的路由協議 (OSPF/EIGRP) 完整無缺。**嚴禁漏掉任何一行介面指令。**
        3. 【PC 定址】：如果數據包含 `[Static]` 開頭的定址資訊，請在該設備標題下優先列出。
        4. 【Range 合併】：多個相同配置的連續介面，必須合併為 `interface range` 以提升腳本可讀性。
        5. 【精簡雜訊】：移除所有單獨的 '!'、version 號、timestamps 等不屬於實驗要求的垃圾訊息。

        ### 輸出格式：
        - 標題：## [HOSTNAME]
        - 分隔線：'------'
        - 僅輸出純淨 CLI 指令，嚴禁在 Markdown 區塊外進行任何文字說明或解釋。

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