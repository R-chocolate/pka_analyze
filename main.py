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

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        print(f"收到檔案: {file.filename}")
        pka_bytes = await file.read()
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')

        # 1. 提取黃金標準答案 (ASSESS_TREE) 並進行「終極濃縮」
        assess_match = re.search(r'<ASSESS_TREE[^>]*?>(.*?)</ASSESS_TREE>', content, re.DOTALL | re.IGNORECASE)
        assess_data = ""
        if assess_match:
            tree_content = assess_match.group(1)
            # 只抽出 TEXT 元素，捨棄肥大的結構層級，讓 Lite 模型不會眼花漏看重點
            text_tags = re.findall(r'<TEXT>.*?</TEXT>', tree_content, re.IGNORECASE)
            assess_data = "\n".join(text_tags)

        # 2. 提取網路現狀並脫水：NETWORK
        clean_xml = broad_dehydrate(content)
        network_match = re.search(r'<NETWORK[^>]*?>(.*?)</NETWORK>', clean_xml, re.DOTALL | re.IGNORECASE)
        network_data = network_match.group(1).strip() if network_match else clean_xml
        
        if not network_data:
             return {"status": "error", "message": "檔案脫水後為空，無法定位網路配置數據。"}

        # 3. 組合「雙軌上下文」
        context_data = ""
        if assess_data:
            context_data += f"--- [ASSESSMENT SCORE KEY (濃縮版滿分解答)] ---\n{assess_data}\n\n"
        context_data += f"--- [CURRENT NETWORK CONFIGURATION (設備現有屬性)] ---\n{network_data}"

        # 4. Lite 模型防呆專用 Prompt 
        prompt = f"""
        你是一位 Cisco 網路配置專家，受命根據 Packet Tracer 的「滿分解答作弊紙 (ASSESSMENT SCORE KEY)」來生成完美的 CLI 腳本。
        
        ### 🎯 最高行動準則 (ASSESSMENT 絕對主導)：
        1. 【照抄得滿分】：`[ASSESSMENT SCORE KEY]` 裡列出了得分重點考驗項目。例如你看到裡面寫了 `<TEXT>VLAN 100</TEXT>` 和 `<TEXT>Name: Native</TEXT>`，這代表在該設備下，這就是標準答案！**你必須 100% 把作弊紙上紀錄的所有 VLAN 都生成出來，一個都不准漏掉！絕對不可以因為數量多就擅自省略！**
        2. 【過濾非考點】：`[CURRENT NETWORK CONFIGURATION]` 裡會有一大堆垃圾預設值 (例如 `spanning-tree mode pvst`, `duplex auto`, `speed auto` 等)。**請記住一條鐵則：如果 `[ASSESSMENT SCORE KEY]` 裡面根本沒有提到這些指令，請直接把它們當作空氣，絕對不要寫進腳本中！**
        3. 【屬性合成為 CLI】：如果答案樹裡要求設定某個特定 IP，請再去 `NETWORK` 裡的 `<SUBNET>` 屬性合成為標準 `ip address` 指令。

        ### 📖 核心指令排版參考 (僅用於決定輸出 CLI 語法)：
        1. 管理與安全：hostname, enable secret, service password-encryption, ip domain-name, crypto key, username secret, line vty, login local, logging synchronous, exec-timeout。
        2. VLAN 與交換：vlan (ID/Name), switchport mode, switchport access vlan, switchport trunk native vlan, nonegotiate, port-security。
        3. 路由與定址：interface, encapsulation dot1q, ip address, ipv6 address, ipv6 unicast-routing, ip route, router ospf, network。
        4. 進階服務：ip dhcp pool, default-router, dns-server, ip helper-address。

        ### 🚨 格式嚴格規範 (死指令)：
        1. 【禁止殘留】：嚴禁在輸出中保留任何 `< >` 標籤。
        2. 【模式退出】：寫完任何子模式 (如 `interface`, `router`, `vlan` 等) 後，能在行尾**加上一單行 `exit` 指令**。
        3. 【全域排版優先】：`hostname` 這種全域指令排在最前面，不要夾在介面下。
        4. 【Range 合併】：多個需要相同設定的埠口 (有出現在 ASSESSMENT 中)，盡量合併為 `interface range` 指令。
        5. 【無噪音輸出】：移除所有 '!' 符號。每個設備使用 ## [HOSTNAME] 作為標題。
        6. 【純淨腳本】：僅輸出 CLI 指令，嚴禁解釋文字。

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