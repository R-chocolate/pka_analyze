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

        # A. 數據脫水 (移除超大無用標籤)
        content = re.sub(r'<(PIXMAPBANK|GUI_DATA|SESSION_DATA)>.*?</\1>', '', content, flags=re.DOTALL | re.IGNORECASE)

        # B. 暴力提取設備 Context
        all_device_blocks = fast_extract_tags(content, "DEVICE")
        
        device_contexts = []
        for block in all_device_blocks:
            n_match = re.search(r'<(SYS_NAME|NAME)[^>]*?>(.*?)</\1>', block, re.IGNORECASE | re.DOTALL)
            dev_name = clean_xml_tag(n_match.group(2)) if n_match else "Unknown"
            
            # 去除雜項標籤，保留配置核心
            clean_block = re.sub(r'<(COMMAND_HISTORY|SNMP_DATA|USER_DATA|IMAGE)>.*?</\1>', '', block, flags=re.DOTALL | re.IGNORECASE)
            device_contexts.append(f"--- DEVICE BLOCK: {dev_name} ---\n{clean_block.strip()}")

        all_context_text = "\n\n".join(device_contexts)
        
        if not all_context_text:
             return {"status": "error", "message": "無法在檔案中定位到任何設備數據"}

        # C. 強化版「格式嚴格執行」Prompt
        prompt = f"""
        你是一位 Cisco 網路配置專家。你的任務是從提供的 RAW XML 上下文塊中提取指令，並生成標準、乾淨的 CLI 配置腳本。
        
        ### 📖 核心指令指南 (必須核對並準確還原)：
        1. 【管理與安全】：hostname, enable secret, service password-encryption, ip domain-name, crypto key, username secret, line vty, login local, logging synchronous, exec-timeout。
        2. 【VLAN 與交換】：vlan (ID/Name), switchport mode, switchport access vlan, native vlan, nonegotiate, spanning-tree (portfast/bpduguard), port-security。
        3. 【路由與定址】：interface, encapsulation dot1q, ip address, ipv6 address, ipv6 unicast-routing, ip route, router ospf, network。
        4. 【進階服務】：ip dhcp pool, network, default-router, ip helper-address, ipv6 nd。

        ### 🚨 格式與清理規範 (死指令)：
        1. 【移除所有標籤】：嚴禁在輸出中保留任何 XML 標籤 (如 <LINE>, <NAME> 等)。你必須從標籤中提取純文字內容。
        2. 【Range 合併】：凡是「配置完全相同」的連續埠口 (例如 F0/1 號到 F0/24 號)，必須合併為 `interface range` 指令輸出。
        3. 【無噪音輸出】：移除所有 '!' 符號、`Building configuration`、`Current configuration` 以及任何系統版本、時間戳資訊。
        4. 【設備分隔】：每個設備使用 ## [HOSTNAME] 作為標題，設備間以 '------' 分隔。
        5. 【純淨腳本】：僅輸出 CLI 指令，嚴禁在 Markdown 代碼塊外進行任何解釋或問候。

        ### 🎯 目標：
        - 完整性：凡是指南中提到的配置，只要在區塊中出現，就必須準確還原。
        - 簡潔性：通過 interface range 縮減行數。

        原始 RAW 數據流：
        {all_context_text}
        """

        response = model.generate_content(
            prompt,
            generation_config={"max_output_tokens": 8192, "temperature": 0}
        )
        
        return {"status": "success", "data": response.text}

    except Exception as e:
        print(f"發生系統錯誤: {str(e)}")
        return {"status": "error", "message": f"系統錯誤: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)