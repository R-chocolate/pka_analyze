import os
import re
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import google.generativeai as genai
from Decipher.pt_crypto import decrypt_pkt

# 1. 初始化
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.environ.get("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

# 由於 context 可能非常長，建議使用 gemini-1.5-flash 或 gemini-2.0-flash 來獲得更好的遵循度與長文本能力
model = genai.GenerativeModel('gemini-1.5-flash')

@app.get("/")
async def read_index():
    return FileResponse('index.html')

@app.get("/ping")
async def ping():
    return {"status": "alive"}

def broad_dehydrate(content):
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

        # 1. 提取黃金標準答案：ASSESS_TREE
        assess_match = re.search(r'<ASSESS_TREE[^>]*?>(.*?)</ASSESS_TREE>', content, re.DOTALL | re.IGNORECASE)
        assess_data = assess_match.group(1).strip() if assess_match else ""

        # 2. 提取網路現狀並脫水：NETWORK
        clean_xml = broad_dehydrate(content)
        network_match = re.search(r'<NETWORK[^>]*?>(.*?)</NETWORK>', clean_xml, re.DOTALL | re.IGNORECASE)
        network_data = network_match.group(1).strip() if network_match else clean_xml
        
        if not network_data:
             return {"status": "error", "message": "檔案脫水後為空，無法定位網路配置數據。"}

        # 3. 組合「雙軌上下文」
        context_data = ""
        if assess_data:
            context_data += f"--- [ASSESSMENT / ANSWER KEY TREE (滿分標準答案對照表)] ---\n{assess_data}\n\n"
        context_data += f"--- [CURRENT NETWORK CONFIGURATION (設備現有屬性)] ---\n{network_data}"

        # 4. 新世代 Prompt (答案樹絕對主導模式)
        prompt = f"""
        你是一位 Cisco 網路配置專家，受命根據 Packet Tracer 的「滿分解答樹 (ASSESSMENT)」來生成最完美的 CLI 腳本。
        
        ### 🎯 最高行動準則 (ASSESSMENT 絕對主導)：
        1. 【照抄得滿分】：`[ASSESSMENT / ANSWER KEY TREE]` 是唯一的真實標準。所有出現在這棵樹裡的配置需求 (如所有的 VLAN ID 與名稱、要求設定的 port access/trunk、所有的 interface IP 等) **必須 100% 寫入腳本中，絕對不能遺漏任何一個！(例如看到 5 個 VLAN 就必須在 switch 上生成 5 個 VLAN 的全域宣告)**
        2. 【過濾非考點】：如果 `[CURRENT NETWORK CONFIGURATION]` 裡有一些設備預設產生的指令 (例如 `spanning-tree mode pvst` 或 `duplex auto` 或 `speed auto`)，只要 `[ASSESSMENT]` 裡根本沒有考核這些東西，請**直接忽略它們，絕對不要寫出！** (除非答案表裡有明確要求設定 spanning-tree)。
        3. 【屬性合成為 CLI】：如果答案樹裡要求了某個 IP，請參考 `NETWORK` 裡的 `<SUBNET>` 等屬性將其合成為標準指令 (如 `ip address ...`)。

        ### 📖 核心指令排版參考 (僅用於決定輸出 CLI 語法)：
        1. 管理與安全：hostname, enable secret, service password-encryption, ip domain-name, crypto key, username secret, line vty, login local, logging synchronous, exec-timeout。
        2. VLAN 與交換：vlan (ID/Name), switchport mode, switchport access vlan, switchport trunk native vlan, nonegotiate, port-security。
        3. 路由與定址：interface, encapsulation dot1q, ip address, ipv6 address, ipv6 unicast-routing, ip route, router ospf, network。
        4. 進階服務：ip dhcp pool, default-router, dns-server, ip helper-address。

        ### 🚨 格式嚴格規範 (死指令)：
        1. 【禁止 XML 殘留】：嚴禁在輸出中保留任何 XML 標籤外殼 `< >`。你只能輸出純命令。
        2. 【模式退出 (EXIT)】：為了讓腳本可以直接一次貼上執行，在完成任何子模式 (如 `interface`, `router`, `line`, `ip dhcp pool`, `vlan`) 的配置後，**必須加上一行 `exit` 指令**，確保回到全域模式。
        3. 【全域排版優先】：像 `hostname` 這種全域指令，必須排在某台設備腳本的最開頭位置，絕不能夾雜在 `interface` 或 `vlan` 子模式裡面。
        4. 【Range 合併】：凡是「被 ASSESSMENT 考核且配置完全相同」的連續埠口，必須盡可能合併為 `interface range` 指令。
        5. 【無噪音輸出】：移除所有 '!' 符號、`Building configuration` 等報文。
        6. 【設備分隔】：每個設備使用 ## [HOSTNAME] 作為標題，設備間以 '------' 分隔。
        7. 【純淨腳本】：僅輸出 CLI 指令，嚴禁解釋文字。

        雙軌數據流 (滿分解答卷 + 現有屬性)：
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