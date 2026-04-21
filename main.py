import os
import re
import xml.etree.ElementTree as ET
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

model = genai.GenerativeModel('gemini-3.1-flash-lite-preview')

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

def format_assess_tree(node, depth=0):
    s = ""
    for child in node:
        if child.tag == 'TEXT' and child.text:
            s += '  ' * depth + '- ' + child.text + '\n'
        else:
            s += format_assess_tree(child, depth + 1)
    return s

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        print(f"收到檔案: {file.filename}")
        pka_bytes = await file.read()
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')

        # 1. 提取黃金標準答案 (ASSESS_TREE)
        assess_match = re.search(r'<ASSESS_TREE[^>]*?>(.*?)</ASSESS_TREE>', content, re.DOTALL | re.IGNORECASE)
        assess_data = ""
        if assess_match:
            tree_raw = '<ROOT>' + assess_match.group(1) + '</ROOT>'
            try:
                root = ET.fromstring(tree_raw)
                assess_data = format_assess_tree(root)
            except Exception as e:
                text_tags = re.findall(r'<TEXT>(.*?)</TEXT>', assess_match.group(1), re.IGNORECASE)
                assess_data = "\n".join(["- " + t for t in text_tags])

        # 2. 提取網路現狀並脫水：NETWORK
        clean_xml = broad_dehydrate(content)
        network_match = re.search(r'<NETWORK[^>]*?>(.*?)</NETWORK>', clean_xml, re.DOTALL | re.IGNORECASE)
        network_data = network_match.group(1).strip() if network_match else clean_xml
        
        if not network_data:
             return {"status": "error", "message": "檔案脫水後為空，無法定位網路配置數據。"}

        # 3. 組合「雙軌上下文」：網路現狀必須完整保留，答案樹作為「防漏網」加置於末尾
        context_data = f"--- [CURRENT NETWORK CONFIGURATION] ---\n{network_data}\n\n"
        if assess_data:
            context_data += f"--- [ASSESSMENT SCORE KEY] ---\n{assess_data}"

        # 4. 回退為通用的穩定版本 Prompt，不再一味強制抹除設備本身特有的設定。融合「現狀」與「考試要求」的互補特性。
        prompt = f"""
        你是一位 Cisco 網路配置專家。我提供了一份 Packet Tracer PKA 檔案的脫水全量 XML（包含 `CURRENT NETWORK CONFIGURATION` 與 `ASSESSMENT SCORE KEY`）。
        你的任務是通盤解析這兩份數據，將所有網路設定還原為乾淨、可以直接「一次性全選貼上」到設備终端的 CLI 配置腳本。
        
        ### 📖 核心指令指南 (必須核對並準確還原)：
        1. 【管理與安全】：hostname, enable secret, service password-encryption, ip domain-name, crypto key, username secret, line vty, login local, logging synchronous, exec-timeout。
        2. 【VLAN 與交換】：vlan, switchport mode, switchport access vlan, switchport trunk native vlan, nonegotiate, spanning-tree (portfast/bpduguard), port-security。
        3. 【路由與定址】：interface, encapsulation dot1q, ip address, ipv6 address, ipv6 unicast-routing, ip route, router ospf, network。
        4. 【進階服務】：ip dhcp pool, network, default-router, dns-server, ip helper-address, ipv6 nd。

        ### 🔍 深度解析策略 (綜合互補原則)：
        1. `[CURRENT NETWORK CONFIGURATION]` 包含了許多設備深層設定（如 XML 標籤 `<IP>`, `<SUBNET>`, `<IP_DHCP_POOL_LIST>`, 以及既有的 VLAN Name）。如果這些標籤存在，你必須人工將其轉換為正確的 `ip address` 或 `vlan name`。
        2. `[ASSESSMENT SCORE KEY]` (如果有的話) 是考試的必做清單。**這兩邊的資料是互補的**：如果考卷上寫了你要建 `VLAN 100 Native` 和 `VLAN 999 Blackhole`，即使這兩個 VLAN 沒被綁定在任何 Port 上，你也**必須**乖乖為該交換機建立這兩個 VLAN。只要是出現在這兩邊其中一邊的要求，你都得輸出！

        ### 🚨 格式嚴格規範 (死指令)：
        1. 【禁止 XML 殘留】：嚴禁在輸出中保留任何 `<`、`>` 或 YAML 符號。你只能輸出純命令。
        2. 【模式退出 (EXIT)】：為了讓腳本可以直接一次貼上執行，在完成任何子模式 (如 `interface`, `router`, `line`, `ip dhcp pool`, `vlan`) 的配置後，**必須加上一行 `exit` 指令**，確保回到全域模式。
        3. 【全域排版優先】：像 `hostname`, `enable secret`, `spanning-tree` 這種全域指令，必須排在整個設備腳本的最開頭位置，絕不能夾雜在介面底下。
        4. 【Range 合併】：凡是「配置完全相同」的連續埠口，請必須合併為 `interface range` 指令，例如 `interface range f0/10-20` 或是 `interface range g1/0/1-2`，這對提升貼上效率非常重要。
        5. 【無噪音輸出】：移除所有 '!' 符號、`Building configuration` 等報文。
        6. 【設備分隔】：每個設備使用 ## [HOSTNAME] 作為標題，設備間以 '------' 分隔。不准遺漏任何一台設備！
        7. 【純淨腳本】：僅輸出 CLI 指令，嚴禁解釋文字。

        全量網路屬性與配置數據：
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