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

        # A. 數據脫水 (移除全域超大噪音)
        content = re.sub(r'<(PIXMAPBANK|GUI_DATA|SESSION_DATA)>.*?</\1>', '', content, flags=re.DOTALL | re.IGNORECASE)

        # B. 暴力提取：獲取所有設備的「完整上下文區塊」
        all_device_blocks = fast_extract_tags(content, "DEVICE")
        
        device_contexts = []
        for block in all_device_blocks:
            # 1. 取得名稱以便識別 (Optional for tracking)
            n_match = re.search(r'<(SYS_NAME|NAME)[^>]*?>(.*?)</\1>', block, re.IGNORECASE | re.DOTALL)
            dev_name = clean_xml_tag(n_match.group(2)) if n_match else "Unknown"
            
            # 2. 二次脫水：移除設備塊內的巨大多餘標籤，保留屬性與指令
            # 我們移除 COMMAND_HISTORY 等可能造成干擾的重複歷史
            clean_block = re.sub(r'<(COMMAND_HISTORY|SNMP_DATA|USER_DATA)>.*?</\1>', '', block, flags=re.DOTALL | re.IGNORECASE)
            
            # 3. 封裝這個設備的完整 Context
            device_contexts.append(f"--- [DEVICE CONTEXT BLOCK: {dev_name}] ---\n{clean_block.strip()}")

        all_context_text = "\n\n".join(device_contexts)
        
        if not all_context_text:
             return {"status": "error", "message": "無法在檔案中定位到任何設備數據"}

        # C. 指令表驅動 + 上下文解析 Prompt
        prompt = f"""
        你是一位 Cisco 網路配置專家。我為你提供了 PKA 檔案中所有設備的原始 XML 上下文區塊 (DEVICE CONTEXT BLOCK)。
        請從這些區塊中的屬性標籤與 RUNNINGCONFIG 標籤中，提取出所有正確的配置指令。

        ### 📖 核心指令參照指南 (必須優先核對並準確還原)：
        1. 【管理與安全】：hostname, enable secret, service password-encryption, ip domain-name, crypto key generate rsa, username secret, line vty, login local, logging synchronous, exec-timeout。
        2. 【VLAN 與交換】：vlan (ID/Name), switchport mode (access/trunk), switchport access vlan, native vlan, nonegotiate, spanning-tree (portfast/bpduguard), port-security (maximum/sticky/violation)。
        3. 【路由與定址】：interface (實體/子介面), encapsulation dot1q, ip address, ipv6 address, ipv6 unicast-routing, ip routing, ip route, router ospf, network。
        4. 【進階服務】：ip dhcp pool, network, default-router, ip helper-address, ipv6 nd (managed-config-flag/other-config-flag)。

        ### 🎯 任務規則：
        - 【深度解析】：請仔細檢查每個設備區塊。除了 `RUNNINGCONFIG` 裡的 `<LINE>` 標記，也要觀察標籤屬性 (如 IP_ADDRESS) 是否包含漏掉的定址資訊。
        - 【有限判斷】：只要發現與上述指南相關的關鍵字，請 100% 準確整理為 CLI 腳本。
        - 【去蕪存菁】：刪除所有與 Cisco 配置無關的 XML 標籤外殼、時間戳以及 `Building configuration` 等報文。
        - 【格式規範】：每個設備使用 ## [HOSTNAME] 作為標題，設備間以 '------' 分隔。

        原始 RAW 數據流：
        {all_context_text}
        """

        # 發送給 Gemini 進行分析 (由於上下文變大，使用更高的 Token 限制)
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