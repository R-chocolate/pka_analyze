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

        for tag in ["RUNNINGCONFIG", "STARTUPCONFIG", "IOS_CONFIG"]:
            configs = fast_extract_tags(content, tag)
            for config_body in configs:
                config_hash = hash(config_body)
                if config_hash in seen_configs: continue
                seen_configs.add(config_hash)

                body_pos = content.find(config_body)
                lookback = content[max(0, body_pos-50000) : body_pos]
                name_match = re.findall(r'<(SYS_NAME|NAME)[^>]*?>(.*?)</\1>', lookback, re.IGNORECASE | re.DOTALL)
                dev_name = clean_xml_tag(name_match[-1][1]) if name_match else "Unknown"
                
                if dev_name not in device_data: device_data[dev_name] = []
                
                lines = re.findall(r'<LINE>(.*?)</LINE>', config_body, re.DOTALL | re.IGNORECASE)
                for l in lines:
                    l_clean = clean_xml_tag(l)
                    # 預先清理真正的系統垃圾
                    if l_clean and l_clean != "!" and not l_clean.startswith("Building configuration") and not l_clean.startswith("Current configuration"):
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
                        info = f"ip address {v_clean}"
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

        # D. 參照指令表驅動 Prompt
        prompt = f"""
        你是一位 Cisco 網路專家。你的任務是從數據流中提取指令，並參考「核心指令指南」進行「有限判斷」的整理。
        
        ### 📖 核心指令指南 (出現相關關鍵字必須保留)：
        1. 【管理與安全】：hostname, enable secret, service password-encryption, ip domain-name, crypto key, username secret, line vty, login local, logging synchronous, exec-timeout。
        2. 【VLAN 與交換】：vlan (ID/Name), switchport mode (access/trunk), switchport access vlan, native vlan, nonegotiate, spanning-tree (portfast/bpduguard), port-security (maximum/sticky/violation)。
        3. 【路由與定址】：interface (實體/子介面), encapsulation dot1q, ip address, ipv6 address, ipv6 unicast-routing, ip routing, ip route, router ospf, network。
        4. 【進階服務】：ip dhcp pool, network, default-router, ip helper-address, ipv6 nd (managed-config-flag/other-config-flag)。

        ### 🎯 有限判斷原則：
        - 【優先保護】：只要原始數據中包含上述指南中的關鍵字，必須 100% 準確還原。
        - 【去蕪存菁】：刪除所有 '!' 符號、系統 Banner、版本編號、時間戳以及 `Building configuration` 等廢話。
        - 【介面歸類】：確保所有介面指令（如 ip address, description）精確歸類到對應的 ## [HOSTNAME] 下。
        - 【連續合併】：相同的連續介面配置請合併為 `interface range` 指令。

        ### 📋 格式規範：
        - 標題：## [HOSTNAME]
        - 分隔：設備間以 '------' 分隔。
        - 僅輸出 CLI 腳本，嚴禁任何解釋或問候語。

        原始數據流：
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