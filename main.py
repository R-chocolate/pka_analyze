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

def broad_dehydrate(content):
    """
    極致脫水：移除全域 XML 中體積最大的二進位/圖形區塊。
    保留所有剩餘的文字結構與屬性。
    """
    heavy_tags = ['PIXMAPBANK', 'GUI_DATA', 'SESSION_DATA', 'IMAGE', 'PIXMAP', 'VISUAL_DATA']
    for tag in heavy_tags:
        pattern = re.compile(f'<{tag}[^>]*?>.*?</{tag}>', re.DOTALL | re.IGNORECASE)
        content = pattern.sub('', content)
    
    useless_tags = ['COMMAND_HISTORY', 'SNMP_DATA', 'USER_DATA']
    for tag in useless_tags:
        pattern = re.compile(f'<{tag}[^>]*?>.*?</{tag}>', re.DOTALL | re.IGNORECASE)
        content = pattern.sub('', content)
        
    return content

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        print(f"收到檔案: {file.filename}")
        pka_bytes = await file.read()
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')

        # A. 全域極致脫水
        clean_xml = broad_dehydrate(content)
        
        network_match = re.search(r'<NETWORK[^>]*?>(.*?)</NETWORK>', clean_xml, re.DOTALL | re.IGNORECASE)
        context_data = network_match.group(1) if network_match else clean_xml
        
        if not context_data.strip():
             return {"status": "error", "message": "檔案脫水後為空，無法定位網路配置數據。"}

        # B. 新世代語義合成 Prompt (加入自動 Exit 與全域置頂邏輯)
        prompt = f"""
        你是一位 Cisco 網路配置專家。我提供了一份 Packet Tracer PKA 檔案的「脫水全量 XML」內容。
        你的任務是通盤解析這份 XML，將所有設定還原為乾淨、可以直接「一次性全選貼上」到設備终端的 CLI 配置腳本。
        
        ### 📖 核心指令指南 (必須核對並準確還原)：
        1. 【管理與安全】：hostname, enable secret, service password-encryption, ip domain-name, crypto key, username secret, line vty, login local, logging synchronous, exec-timeout。
        2. 【VLAN 與交換】：vlan (ID/Name), switchport mode, switchport access vlan, native vlan, nonegotiate, spanning-tree (portfast/bpduguard), port-security。
        3. 【路由與定址】：interface, encapsulation dot1q, ip address, ipv6 address, ipv6 unicast-routing, ip route, router ospf, network。
        4. 【進階服務】：ip dhcp pool, network, default-router, dns-server, ip helper-address, ipv6 nd。

        ### 🔍 深度解析策略 (重要)：
        1. 【尋寶模式】：Packet Tracer 不一定把配置寫在 `<LINE>` 裡。你必須檢查 XML 裡的屬性標籤 (例如 `<IP>`, `<SUBNET>`, `<IP_DHCP_POOL_LIST>`, `<VLAN_LIST>`)。
        2. 【屬性合成 CLI】：如果你在屬性中看到了如 `<IP>10.1.1.2</IP>` 與 `<SUBNET>255.255.255.252</SUBNET>`，你必須人工將其轉換為 `ip address 10.1.1.2 255.255.255.252` 並放入對應的 interface 下。
        3. 【DHCP 重建】：搜索全域的 `<IP_DHCP_POOL_LIST>`。將其中的 `NETWORK_ADDRESS`, `SUBNET_MASK`, `DEFAULT_GATEWAY` 等屬性還原成完整的 `ip dhcp pool` 腳本結構，並放置在正確的設備標籤下。

        ### 🚨 格式嚴格規範 (死指令)：
        1. 【禁止 XML 殘留】：嚴禁在輸出中保留任何 `<`、`>` 或是 XML 標籤外殼。
        2. 【模式退出 (EXIT)】：為了讓腳本可以直接一次貼上執行，在完成任何子模式 (如 `interface`, `router`, `line`, `ip dhcp pool`, `vlan`) 的配置後，**必須加上一行 `exit` 指令**，確保回到全域模式。
        3. 【全域排版優先】：像 `hostname`, `enable secret`, `spanning-tree` 這種全域指令，必須排在腳本的最開頭位置，絕不能放在 `interface` 等子模式裡面。
        4. 【Range 合併】：凡是「配置完全相同」的連續埠口，必須合併為 `interface range` 指令。
        5. 【無噪音輸出】：移除所有 '!' 符號、`Building configuration` 等報文。
        6. 【設備分隔】：每個設備使用 ## [HOSTNAME] 作為標題，設備間以 '------' 分隔。
        7. 【純淨腳本】：僅輸出 CLI 指令，嚴禁解釋文字。

        原始全量脫水數據：
        {context_data}
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