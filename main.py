import os
import re
import xml.etree.ElementTree as ET
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from Decipher.pt_crypto import decrypt_pkt

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

API_KEY = os.environ.get("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

model = genai.GenerativeModel('gemini-3.5-flash')

safety_settings = {
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

PHYSICAL_ONLY_BLACKLIST = {
    "Device Model", "Device Type", "Custom Device Model", "BIA", "MAC Address", 
    "Port Type", "In Physical Shape", "In Logical Shape", "Power", 
    "Physical Location", "wattage", "cost", "Tx Ring Limit"
}

@app.get("/")
async def read_index():
    return FileResponse('index.html')

def clean_xml_string(xml_str):
    xml_str = re.sub(r'[^\x09\x0A\x0D\x20-\uD7FF\xE000-\uFFFD\U00010000-\U0010FFFF]', '', xml_str)
    xml_str = re.sub(r'&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)', '&amp;', xml_str)
    return xml_str

def extract_pka_data(xml_content):
    try:
        xml_content = clean_xml_string(xml_content)
        root = ET.fromstring(xml_content)
        
        # 動態提取 Packet Tracer 實驗變數 (Variable Manager)
        vars_dict = {}
        var_mgr = root.find(".//VARIABLE_MANAGER")
        if var_mgr is not None:
            for el in var_mgr.iter():
                if el.tag.endswith("_VAR"):
                    n = el.find("NAME")
                    v = el.find("VALUE")
                    if n is not None and v is not None and n.text and v.text:
                        vars_dict[f"[[{n.text}]]"] = v.text

        device_configs = {}
        for device in root.findall(".//NETWORK/DEVICE"):
            name = device.find("NAME").text
            config = device.find("STARTUPCONFIG").text or ""
            device_configs[name] = config

        assessment_tree = {}
        comparisons = root.find(".//COMPARISONS")
        if comparisons is not None:
            for dev_node in comparisons.find("NODE").findall("NODE"):
                dev_name = dev_node.find("ID").text
                items = []
                dev_model = "Unknown"
                def traverse(node, path=[]):
                    nonlocal dev_model
                    name_tag = node.find("NAME")
                    if name_tag is not None:
                        label = name_tag.text
                        if label == "Device Model": dev_model = name_tag.get("nodeValue")
                        if name_tag.get("variableEnabled") == "true" and label not in PHYSICAL_ONLY_BLACKLIST:
                            val = name_tag.get("nodeValue")
                            # 進行動態變數替換 (解決如 192.168.10.0 變 192.168.16.0 的問題)
                            var_str = name_tag.get("variableName")
                            if var_str:
                                for k, v in vars_dict.items():
                                    var_str = var_str.replace(k, v)
                                val = var_str

                            pts = node.find("POINTS").text
                            if pts != "0":
                                items.append({"path": "->".join(path+[label]), "target": val, "points": pts})
                        for child in node.findall("NODE"): traverse(child, path+[label])
                traverse(dev_node)
                if items: assessment_tree[dev_name] = {"model": dev_model, "initial_config": device_configs.get(dev_name, ""), "items": items}
        return assessment_tree
    except: return None

@app.post("/upload")
def analyze_pka(file: UploadFile = File(...), model_choice: str = Form("auto")):
    try:
        pka_bytes = file.file.read()
        content = decrypt_pkt(pka_bytes).decode('utf-8', errors='ignore')
        structured_data = extract_pka_data(content)
        if not structured_data: return {"status": "error", "message": "fail"}
        
        context_str = ""
        for name, data in structured_data.items():
            context_str += f"DEVICE: {name} ({data['model']})\nINIT:\n{data['initial_config']}\nGOALS:\n"
            for it in data['items']: context_str += f"- {it['path']} -> {it['target']}\n"
            context_str += "\n"

        prompt = f"""
        你是一位 Cisco 權威專家。請生成最優化、標準的 Cisco CLI 配置腳本。

        ### 🚨 格式與執行規則：
        1. 每個設備必須以 enable, configure terminal 開始，並以 exit 結束全域配置。
        2. 配置進入任何子環境（例如：介面 interface、DHCP Pool、VLAN 等）後，必須在該環境完成指令，並在最後加上「exit」退出該環境，才可進入下一個環境。
        3. 嚴禁 Markdown 格式的 ``` 符號。

        ### ⚡ 通用配置與優化原則：
        1. 【介面合併 (interface range)】：
           凡是偵測到多個埠口（例如連續的 F0/1 到 F0/10）擁有完全相同的配置目標，你「必須」自動將它們合併使用 interface range 指令（例如：interface range FastEthernet0/1-10）進行批次配置，以簡化指令並避免貼上超時。
        2. 【全域優先，介面在後】：
           * 全域設定（例如：建立並命名 VLAN、啟用全域 DHCP Snooping、定義 DHCP Pools、設定靜態路由/NAT Pool/ACL 列表）必須先在全域模式下配置完成。
           * 介面設定（例如：介面劃入 VLAN、開啟 Snooping Trust/限速、介面啟用 DHCP 服務、套用 ACL 規則或 NAT 內外部）必須在全域設定完畢後，再進入介面進行綁定。
        3. 【雙疊構支持】：
           完美支持 IPv4 與 IPv6 雙疊構共存。
        4. 【確保完整】：
           確保數據內容中所有的 GOALS 目標都有對應的指令生成，絕不能有任何遺漏。

        ### 🛠️ 課程學習指令集參考（請根據以下指令集的標準語法進行配置，確保名稱與參數完全對應）：
        - **基礎初始與安全設定**:
          * 特權模式: `enable` / `configure terminal`
          * 設定設備名稱: `hostname [名稱]`
          * 停用 DNS 域名解析: `no ip domain-lookup`
          * 設定特權密碼 (明文): `enable password [密碼]`
          * 設定特權密碼 (加密): `enable secret [密碼]`
          * 進入主控台線路與設定密碼: `line console 0` -> `password [密碼]` -> `login` 或 `login local`
          * 進入遠端虛擬終端與設定密碼: `line vty 0 4` 或 `line vty 0 15` -> `password [密碼]` -> `login` 或 `login local`
          * 本地加密帳戶: `username [帳號] secret [密碼]`
          * 加密所有明文密碼: `service password-encryption`
          * 設定交換器預設閘道: `ip default-gateway [閘道IP]`
          * 開啟交換器雙疊構(IPv4/IPv6): `sdm prefer dual-ipv4-and-ipv6 default`

        - **網卡介面基本配置**:
          * 進入實體介面: `interface [介面名稱]` (例如 FastEthernet0/1, GigabitEthernet0/0, Serial0/1/0)
          * 同時選取多個不連續埠口: `interface range [介面1] , [介面2]` (例如 `interface range f0/1 ,f0/5`)
          * 批次選取連續實體埠口: `interface range [介面1] - [介面2]` (例如 `interface range f0/1 - 5`)
          * 配置 IPv4 位址與遮罩: `ip address [IP位址] [子網路遮罩]`
          * 配置 IPv6 位址與前綴: `ipv6 address [IPv6位址/前綴長度]` (例如 `ipv6 address 2001:db8:acad:1::1/64`)
          * 配置 IPv6 Link-Local 位址: `ipv6 address [FE80位址] link-local` (例如 `ipv6 address fe80::1 link-local`)
          * 自動產生 IPv6 本地鏈路位址: `ipv6 enable`
          * 介面描述: `description [描述文字]`
          * 啟用介面: `no shutdown`
          * 關閉介面: `shutdown`

        - **VLAN 與 VLAN 間路由 (Inter-VLAN)**:
          * 建立並進入 VLAN: `vlan [VLAN識別碼]`
          * 命名 VLAN: `name [VLAN名稱]`
          * 設定埠口為存取模式: `switchport mode access`
          * 將埠口劃分至 VLAN: `switchport access vlan [VLAN識別碼]`
          * 設定埠口為中繼模式: `switchport mode trunk`
          * 停用 DTP 動態中繼協商: `switchport nonegotiate`
          * 修改中繼鏈路原生 VLAN: `switchport trunk native vlan [VLAN識別碼]`
          * 限制中繼特定 VLAN 通過: `switchport trunk allowed vlan [VLAN列表]` (例如 `switchport trunk allowed vlan 10,20,30`)
          * 在中繼增補 VLAN 通過: `switchport trunk allowed vlan add [VLAN識別碼]`
          * 建立單臂路由子介面: `interface [實體介面.子介面號碼]` (例如 `interface gigabitEthernet 0/0.10`)
          * 子介面封裝 802.1Q 並對應 VLAN: `encapsulation dot1Q [VLAN識別碼]`
          * 指定子介面為原生 VLAN: `encapsulation dot1Q [VLAN識別碼] native`
          * 啟用三層交換器路由功能: `ip routing`
          * 將三層交換器埠切換為路由埠: `no switchport`
          * 建立交換器管理虛擬介面: `interface vlan [VLAN識別碼]`

        - **生成樹防護與最佳化 (STP / RSTP)**:
          * 切換為 PVST+ 模式: `spanning-tree mode pvst`
          * 切換為 Rapid-PVST+ 模式: `spanning-tree mode rapid-pvst`
          * 設定為主根橋接器: `spanning-tree vlan [VLAN識別碼] root primary`
          * 設定為備援根橋接器: `spanning-tree vlan [VLAN識別碼] root secondary`
          * 修改 STP 優先權: `spanning-tree vlan [VLAN識別碼] priority [優先權數值]` (4096 的倍數)
          * 手動修改埠口 STP 路徑成本: `spanning-tree cost [數值]`
          * 開啟邊緣埠 PortFast 快速轉發: `spanning-tree portfast`
          * 全域啟用所有存取埠 PortFast: `spanning-tree portfast default`
          * 在特定埠口啟用 BPDU 防護: `spanning-tree bpduguard enable`
          * 全域啟用 PortFast 埠 BPDU 防護: `spanning-tree bpduguard default`
          * 指定鏈路類型為點對點: `spanning-tree link-type point-to-point`

        - **區域網路安全防禦 (Port Security)**:
          * 啟用埠口安全機制 (必先輸入): `switchport port-security`
          * 設定埠口最大安全 MAC 數量: `switchport port-security maximum [數量]`
          * 啟用 Sticky 黏性 MAC 學習: `switchport port-security mac-address sticky`
          * 手動綁定安全實體 MAC 位址: `switchport port-security mac-address [MAC位址]` (格式為 `xxxx.xxxx.xxxx`)
          * 違規懲罰為關閉埠口: `switchport port-security violation shutdown`
          * 違規懲罰為限制並記錄: `switchport port-security violation restrict`
          * 違規懲罰為僅丟棄不記錄: `switchport port-security violation protect`

        - **DHCP 動態服務與中繼 (DHCP Service)**:
          * 排除發放單一 IP: `ip dhcp excluded-address [IP位址]`
          * 排除發放指定 IP 區段: `ip dhcp excluded-address [起始IP位址] [結束IP位址]`
          * 建立並命名 DHCP 位址池: `ip dhcp pool [位址池名稱]`
          * 宣告發放網段與遮罩: `network [網段IP] [子網路遮罩]`
          * 指定預設閘道: `default-router [閘道IP]`
          * 指定 DNS 伺服器: `dns-server [DNS_IP]`
          * 指定網域名稱: `domain-name [網域名稱]`
          * 設定租約期限: `lease [天] [小時] [分鐘]` 或 `lease infinite`
          * 配置 DHCP 中繼代理: `ip helper-address [中繼伺服器IP]`
          * 啟用/停用設備的 DHCP 服務: `service dhcp` / `no service dhcp`

        - **路由與動態路由 (Routing)**:
          * 設定 IPv4 靜態路由 (下一跳): `ip route [目標網段] [遮罩] [下一跳IP]`
          * 設定 IPv4 靜態路由 (本地出介面): `ip route [目標網段] [遮罩] [出介面名稱]`
          * 設定 IPv4 預設靜態路由: `ip route 0.0.0.0 0.0.0.0 [下一跳IP 或 出介面]`
          * 設定浮動靜態路由 (備援): `ip route [目標網段] [遮罩] [下一跳IP] [管理距離]`
          * 設定 IPv6 靜態路由: `ipv6 route [目標IPv6網段] [下一跳IPv6位址]`
          * 設定 IPv6 出介面預設路由: `ipv6 route ::/0 [出介面名稱]`
          * 啟用 OSPF 協定: `router ospf [程序代碼]`
          * 設定 OSPF 路由器識別碼: `router-id [Router_ID_IP]`
          * 宣告網段與反向遮罩加入 OSPF 區域: `network [網段IP] [反向遮罩] area [區域ID]`
          * 阻止傳送 OSPF 封包 (被動介面): `passive-interface [介面名稱]`
          * 注入並傳播預設路由: `default-information originate`
          * 修改介面 OSPF 成本值: `ip ospf cost [數值]`

        - **存取控制清單 (ACL)**:
          * 標準 ACL 允許指定網段: `access-list [1-99] permit [來源IP] [反向遮罩]`
          * 標準 ACL 拒絕單一主機: `access-list [1-99] deny host [主機IP]`
          * 標準 ACL 允許其餘所有流量: `access-list [1-99] permit any`
          * 延伸 ACL 允許網段存取特定協定與埠號 (例如網頁/SSH): `access-list [100-199] permit tcp [來源IP] [反向遮罩] host [目的IP] eq [連接埠號]` (例如 `eq 80` 或 `eq 22`)
          * 延伸 ACL 拒絕特定協定 (如 ICMP ping): `access-list [100-199] deny icmp any any`
          * 進入具名標準 ACL 模式: `ip access-list standard [名稱]`
          * 進入具名延伸 ACL 模式: `ip access-list extended [名稱]`
          * 具名模式下允許 SSH 流量: `permit tcp [來源] [反向遮罩] any eq 22`
          * 具名模式下拒絕特定 DNS 查詢: `deny udp any host [DNS_IP] eq 53`
          * 使用序號插入/刪除 ACL 明細: `[序號] permit host [主機IP]` / `no [序號]`
          * 在介面套用 ACL (入口/出口): `ip access-group [ACL編號或名稱] [in|out]`
          * 將 ACL 套用於 VTY 虛擬終端登入管制: `access-class [ACL編號] in`

        - **網路位址轉換 (NAT / PAT)**:
          * 定義內部私人側介面: `ip nat inside`
          * 定義外部公用側介面: `ip nat outside`
          * 設定靜態一對一固定 NAT 轉譯: `ip nat inside source static [內部IP] [外部IP]`
          * 建立公有位址池: `ip nat pool [位址池名稱] [起始公有IP] [結束公有IP] netmask [子網路遮罩]`
          * 結合動態 ACL 與位址池實作動態 NAT: `ip nat inside source list [ACL編號] pool [位址池名稱]`
          * 結合動態 ACL 與外部介面進行連接埠多對一 PAT 轉換: `ip nat inside source list [ACL編號] interface [外部介面] overload`

        ### ✅ 正確範例：
        == R1 ==
        enable
        configure terminal
        vlan 10
         name Staff
         exit
        interface G0/0
         ip address 10.1.1.1 255.255.255.0
         no shutdown
         exit
        interface range F0/1-10
         switchport mode access
         switchport access vlan 10
         exit
        ip route 0.0.0.0 0.0.0.0 G0/0
        exit

        數據內容：
        {context_str}
        """
        
        # 根據前端選擇或預設值決定執行模式
        if model_choice == "pro":
            target_model = "gemini-3.1-pro-preview"
            use_fallback = False
        elif model_choice == "flash":
            target_model = "gemini-3.5-flash"
            use_fallback = False
        else: # "auto" 智能雙階段
            target_model = "gemini-3.5-flash"
            use_fallback = True

        if not use_fallback:
            # 直接呼叫指定的模型
            m = genai.GenerativeModel(target_model)
            res = m.generate_content(
                prompt,
                generation_config={"temperature": 0},
                safety_settings=safety_settings,
                request_options={"timeout": 300}
            )
            return {"status": "success", "data": res.text}
        else:
            # 智能雙階段：先試 Flash，逾時或失敗則自動啟用 Pro
            try:
                # Flash 模型設定 150 秒超時，避免等待過久
                m_flash = genai.GenerativeModel("gemini-3.5-flash")
                res = m_flash.generate_content(
                    prompt,
                    generation_config={"temperature": 0},
                    safety_settings=safety_settings,
                    request_options={"timeout": 150}
                )
                return {"status": "success", "data": res.text}
            except Exception as e:
                # Flash 失敗或逾時，自動轉入 Pro 備援
                fallback_header = "⚠️ [系統提示：3.5 Flash 模式分析超時或發生錯誤，已自動啟用 3.1 Pro 備援模型進行分析]\n\n"
                try:
                    m_pro = genai.GenerativeModel("gemini-3.1-pro-preview")
                    res_pro = m_pro.generate_content(
                        prompt,
                        generation_config={"temperature": 0},
                        safety_settings=safety_settings,
                        request_options={"timeout": 150}
                    )
                    return {"status": "success", "data": fallback_header + res_pro.text}
                except Exception as inner_e:
                    return {"status": "error", "message": f"分析失敗 (Flash & Pro 均異常): {inner_e}"}
    except Exception as e: return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)