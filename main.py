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
    """
    將繁雜的 XML 給分樹轉化為清晰俐落的 YAML 式層級清單
    讓前端 Lite AI 模型能夠精確對應設備與指令，而不發生錯頻或漏看。
    """
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

        # 1. 提取黃金標準答案 (ASSESS_TREE) 並進行「結構化扁平」
        assess_match = re.search(r'<ASSESS_TREE[^>]*?>(.*?)</ASSESS_TREE>', content, re.DOTALL | re.IGNORECASE)
        assess_data = ""
        if assess_match:
            tree_raw = '<ROOT>' + assess_match.group(1) + '</ROOT>'
            try:
                root = ET.fromstring(tree_raw)
                assess_data = format_assess_tree(root)
            except Exception as e:
                print(f"ASSESS_TREE XML 解析失敗: {e}")
                # 退回舊版正則提取
                text_tags = re.findall(r'<TEXT>(.*?)</TEXT>', assess_match.group(1), re.IGNORECASE)
                assess_data = "\n".join(["- " + t for t in text_tags])

        # 2. 提取網路現狀並脫水：NETWORK
        clean_xml = broad_dehydrate(content)
        network_match = re.search(r'<NETWORK[^>]*?>(.*?)</NETWORK>', clean_xml, re.DOTALL | re.IGNORECASE)
        network_data = network_match.group(1).strip() if network_match else clean_xml
        
        if not network_data:
             return {"status": "error", "message": "檔案脫水後為空，無法定位網路配置數據。"}

        # 3. 組合「雙軌上下文」
        context_data = ""
        if assess_data:
            context_data += f"--- [ASSESSMENT SCORE KEY (結構化滿分解答卷)] ---\n{assess_data}\n\n"
        context_data += f"--- [CURRENT NETWORK CONFIGURATION (設備現狀)] ---\n{network_data}"

        # 4. Lite 最終防雷專用 Prompt
        prompt = f"""
        你是一位 Cisco 網路配置專家，受命根據 Packet Tracer 的「滿分解答作弊紙 (ASSESSMENT SCORE KEY)」來生成最完美的 CLI 腳本。
        
        ### 🎯 最高行動準則 (對帳單絕對主導)：
        1. 【照抄得滿分】：請仔細看 `[ASSESSMENT SCORE KEY]`，現在它已被整理成附帶縮排的層級結構。例如 `S1` 底下如果有 5 個 `VLAN`，你就**必須在 S1 身上宣告整整 5 個 VLAN，一個都不准漏掉！絕對不可以因為數量多就擅自省略！**
        2. 【全設備巡查】：請確保你為 `[ASSESSMENT SCORE KEY]` 裡面出現的**每一台設備 (如 S1, S2, S3 或 R1, R2, R3)** 都生成了對應的配置腳本。絕不能只寫第一台就停下來！
        3. 【過濾非考點】：如果 `[CURRENT NETWORK CONFIGURATION]` 裡有一些原本設備自動生成的指令 (如 `spanning-tree mode pvst`, `duplex auto` 等)，但 `[ASSESSMENT SCORE KEY]` 裡根本沒有考它，**請直接把它們當作空氣，絕對不要寫出來！**
        4. 【屬性合成為 CLI】：如果答案樹裡要求設定某個特定 IP，請回去看 `[CURRENT NETWORK CONFIGURATION]` 的 `<SUBNET>` 來拼湊出完整的 `ip address` 指令。

        ### 📖 核心指令排版參考 (僅用於決定輸出 CLI 語法)：
        1. 管理與安全：hostname, enable secret, service password-encryption, ip domain-name, crypto key, username secret, line vty, login local, logging synchronous, exec-timeout。
        2. VLAN 與交換：vlan (ID/Name), switchport mode, switchport access vlan, switchport trunk native vlan, nonegotiate, port-security。
        3. 路由與定址：interface, encapsulation dot1q, ip address, ipv6 address, ipv6 unicast-routing, ip route, router ospf, network。
        4. 進階服務：ip dhcp pool, default-router, dns-server, ip helper-address。

        ### 🚨 格式嚴格規範 (死指令)：
        1. 【禁止殘留】：嚴禁在輸出中保留任何 `< >` 標籤或 YAML 的 `-` 符號。你只能輸出純 Cisco 設備命令。
        2. 【模式退出】：寫完任何子模式 (如 `interface`, `router`, `vlan` 等) 後，能在行尾**加上一單行 `exit` 指令**。
        3. 【全域排版優先】：`hostname` 這種全域指令排在最前面，不要夾在介面下。
        4. 【Range 合併】：多個需要相同設定的埠口 (有出現在 ASSESSMENT 中)，能合併則合併為 `interface range` 指令。
        5. 【設備分隔】：每個設備使用 ## [HOSTNAME] 作為標題，設備間以 '------' 分隔。

        數據流：
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