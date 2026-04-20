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

        # A. 數據脫水
        content = re.sub(r'<(PIXMAPBANK|GUI_DATA|SESSION_DATA)>.*?</\1>', '', content, flags=re.DOTALL | re.IGNORECASE)

        # B. 高性能線性提取
        device_data = {} # {name: [lines]}
        seen_configs = set()

        # 1. 提取所有配置標籤
        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG", "IOS_CONFIG"]:
            configs = fast_extract_tags(content, tag)
            for config_body in configs:
                config_hash = hash(config_body)
                if config_hash in seen_configs: continue
                seen_configs.add(config_hash)

                body_pos = content.find(config_body)
                lookback = content[max(0, body_pos-40000) : body_pos]
                name_match = re.findall(r'<(SYS_NAME|NAME)[^>]*?>(.*?)</\1>', lookback, re.IGNORECASE | re.DOTALL)
                dev_name = clean_xml_tag(name_match[-1][1]) if name_match else "Unknown"
                
                if dev_name not in device_data: device_data[dev_name] = []
                
                lines = re.findall(r'<LINE>(.*?)</LINE>', config_body, re.DOTALL | re.IGNORECASE)
                for l in lines:
                    l_clean = clean_xml_tag(l)
                    # 預先清理 Cisco 系統訊息
                    if l_clean and l_clean != "!" and not l_clean.startswith("Building configuration"):
                        device_data[dev_name].append(l_clean)

        # 2. 提取 PC/Server 靜態屬性
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
                        info = f"[Static] {tag}: {v_clean}"
                        if info not in device_data[name]:
                            device_data[name].append(info)

        # C. 數據彙整
        extracted_blocks = []
        for dev, lines in device_data.items():
            if lines:
                extracted_blocks.append(f"### DEVICE: {dev}\n" + "\n".join(lines))

        all_cmds_text = "\n\n".join(extracted_blocks)
        
        if not all_cmds_text:
             return {"status": "error", "message": "無法在檔案中定位到任何有效的配置"}

        # D. 應用強制執行版萬用 Prompt
        prompt = f"""
        你是一位 Cisco CCIE 專業教官。請解析原始 PKA 數據，並將其整理為標準化、可直接執行的配置腳本。
        
        ### 🚨 強制執行規則 (不可遺漏任何一項)：
        1. 【設備身分識別】：
           - 必須提取 `hostname`、`ip domain-name` (例如 ccna-lab.com)。
           - 必須保留 `username ... secret ...` 使用者帳號指令。
           - 必須包含 `crypto key generate rsa` 並註明係數 (如 1024)。
        
        2. 【安全與管理加固】：
           - 必須包含 `enable secret`、`service password-encryption` 與 `no ip domain-lookup`。
           - 必須包含 `banner motd` 法律聲明內容。
           - Line 設定：Console 與 VTY 必須包含 `exec-timeout 6 0` 與 `logging synchronous`。
           - SSH 設定：VTY 線路必須包含 `login local` 與 `transport input ssh`。

        3. 【交換機優化 (Range 邏輯)】：
           - 凡是「配置完全相同」的連續埠口，務必合併為 `interface range` 指令，嚴禁逐行輸出。
        
        4. 【路由與定址】：
           - 完整保留所有實體介面、子介面 (sub-interfaces) 的 IP 與封裝配置。
           - 保留靜態路由 (`ip route`) 與動態路由協議 (如 `router ospf`)。

        ### 📋 輸出格式：
        - 標題：## [HOSTNAME]
        - 分隔：設備間以 '------' 分隔。
        - 移除所有 '!' 符號，僅保留 CLI 指令。

        待處理原始數據流：
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