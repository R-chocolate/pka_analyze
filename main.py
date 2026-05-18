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

model = genai.GenerativeModel('gemini-3.1-pro-preview')

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
                            pts = node.find("POINTS").text
                            if pts != "0":
                                items.append({"path": "->".join(path+[label]), "target": val, "points": pts})
                        for child in node.findall("NODE"): traverse(child, path+[label])
                traverse(dev_node)
                if items: assessment_tree[dev_name] = {"model": dev_model, "initial_config": device_configs.get(dev_name, ""), "items": items}
        return assessment_tree
    except: return None

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...), model_choice: str = Form("auto")):
    try:
        pka_bytes = await file.read()
        content = decrypt_pkt(pka_bytes).decode('utf-8', errors='ignore')
        structured_data = extract_pka_data(content)
        if not structured_data: return {"status": "error", "message": "fail"}
        
        context_str = ""
        for name, data in structured_data.items():
            context_str += f"DEVICE: {name} ({data['model']})\nINIT:\n{data['initial_config']}\nGOALS:\n"
            for it in data['items']: context_str += f"- {it['path']} -> {it['target']}\n"
            context_str += "\n"

        prompt = f"""
        你是一位 Cisco 權威專家。請生成配置腳本。
        
        ### 🚨 規則：
        1. 每個設備必須以 enable, configure terminal 開始。
        2. 每配置完一個介面必須加 exit。
        3. 進入下一個介面或輸入全域指令前必須先 exit。
        4. 禁止 Markdown ```。
        
        ### ✅ 正確範例：
        == R1 ==
        enable
        configure terminal
        interface G0/0
         ip address 10.1.1.1 255.255.255.0
         no shutdown
         exit
        interface G0/1
         ip address 10.1.2.1 255.255.255.0
         no shutdown
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
            target_model = "gemini-3.1-flash-lite-preview"
            use_fallback = False
        else: # "auto" 智能雙階段
            target_model = "gemini-3.1-pro-preview"
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
            # 智能雙階段：先試 Pro，逾時或失敗則自動啟用 Flash
            try:
                # Pro 模型設定 150 秒超時，避免等待過久
                m_pro = genai.GenerativeModel("gemini-3.1-pro-preview")
                res = m_pro.generate_content(
                    prompt,
                    generation_config={"temperature": 0},
                    safety_settings=safety_settings,
                    request_options={"timeout": 150}
                )
                return {"status": "success", "data": res.text}
            except Exception as e:
                # Pro 失敗或逾時，自動轉入 Flash 備援
                fallback_header = "⚠️ [系統提示：Pro 模式分析超時或發生錯誤，已自動啟用 Flash 備援模型進行分析]\n\n"
                try:
                    m_flash = genai.GenerativeModel("gemini-3.1-flash-lite-preview")
                    res_flash = m_flash.generate_content(
                        prompt,
                        generation_config={"temperature": 0},
                        safety_settings=safety_settings,
                        request_options={"timeout": 60}
                    )
                    return {"status": "success", "data": fallback_header + res_flash.text}
                except Exception as inner_e:
                    return {"status": "error", "message": f"分析失敗 (Pro & Flash 均異常): {inner_e}"}
    except Exception as e: return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)