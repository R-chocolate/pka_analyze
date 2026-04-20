import os
import re
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import google.generativeai as genai
from Decipher.pt_crypto import decrypt_pkt

# 1. 初始化
app = FastAPI()

# 強制開啟 CORS，確保前端能調用
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

# 從環境變數讀取 API KEY，避免洩漏到 GitHub
API_KEY = os.environ.get("GEMINI_API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)

model = genai.GenerativeModel('gemini-3.1-flash-lite-preview')

@app.get("/")
async def read_index():
    return FileResponse('index.html')

@app.get("/ping")
async def ping():
    """用來給 Cloud Scheduler 定時敲醒伺服器用"""
    return {"status": "alive"}

@app.post("/upload")
async def analyze_pka(file: UploadFile = File(...)):
    try:
        print(f"收到檔案: {file.filename}")
        # 步驟 1: 讀取並解密 
        pka_bytes = await file.read()
        print("正在解密 PKA...")
        raw_xml_data = decrypt_pkt(pka_bytes)
        content = raw_xml_data.decode('utf-8', errors='ignore')
        print(f"解密完成，長度: {len(content)}")

        # 步驟 2: 暴力脫水 (移除圖片與雜訊)
        print("正在移除 XML 雜訊 (PIXMAP/GUI)...")
        content = re.sub(r'<PIXMAPBANK>.*?</PIXMAPBANK>', '', content, flags=re.DOTALL)
        content = re.sub(r'<GUI_DATA>.*?</GUI_DATA>', '', content, flags=re.DOTALL)
        print(f"脫水完成，剩餘長度: {len(content)}")

        # C. 升級版提取：改用 DEVICE 區塊掃描 (這是 Challenge 實驗的唯一解)
        # 尋找所有設備塊，不論它在哪個 NETWORK 層級下
        device_blocks = re.findall(r'<DEVICE.*?>.*?</DEVICE>', content, re.IGNORECASE | re.DOTALL)
        
        if not device_blocks:
            # 備援機制：如果真的找不到 DEVICE，就退回原本的 Network 提取方式
            network_blocks = re.findall(r'<NETWORK.*?</NETWORK>', content, re.IGNORECASE | re.DOTALL)
            if not network_blocks:
                # 如果連標籤都找不到，回傳解密內容前 50 字偵錯
                debug_info = content[:50].replace('<', '&lt;')
                return {"status": "error", "message": f"無法解析 PKA 結構：找不到 DEVICE 或 NETWORK 標籤。解密開頭：{debug_info}"}
            answer_block = "\n".join(network_blocks)
        else:
            # 將每個設備的指令獨立提取並打上分隔符號，強迫 AI 注意到不同設備
            processed_devices = []
            for block in device_blocks:
                lines = re.findall(r'<LINE>(.*?)</LINE>', block, re.IGNORECASE | re.DOTALL)
                if lines:
                    clean_lines = [l.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').strip() for l in lines]
                    processed_devices.append("\n".join(clean_lines))
            
            # 使用明確的分隔標記，防止 AI 忽視後方的設備配置
            answer_block = "\n\n--- [NEXT_DEVICE_START] ---\n\n".join(processed_devices)

        # D. 生成最終餵給 AI 的文字流
        all_cmds_text = answer_block 
        print(f"提取指令完成，準備傳送至 AI，總長度: {len(all_cmds_text)}")
        
        if not all_cmds_text:
             print("錯誤: 找不到任何指令內容")
             return {"status": "error", "message": "已定位到 Network 區塊，但內部沒有任何指令標籤"}

        # E. 呼叫 Gemini 整理 (加入設備存活檢查與防遺漏指令)
        prompt = f"""
        你是一位 Cisco 網路教官。我將提供從 PKA XML 中提取的原始 Running-config。
        請嚴格執行以下多階段處理邏輯：

        ### 第一階段：設備存活清查 (必做)
        - 請先掃描原始數據中出現的所有不同 'hostname'。
        - 你必須意識到：如果忽略了路由器（如 R1）的子介面配置，這份答案就是 0 分。
        - 強制要求：你必須輸出原始數據中出現過的「每一台」主機配置，嚴禁截斷或省略。

        ### 第二階段：指令壓縮與合併 (Unit 1-8 標準)
        - 【Range 合併】：所有配置完全相同的連續介面（例如 F0/11-17 全是 Access VLAN 10），必須合併為 `interface range`決策。
        - 【精簡噪音】：
            - 移除所有 '!' 符號與 XML 殘留標籤。
            - 移除 version, timestamps, ip classless 等系統自動生成的冗餘行。
            - 排除沒有任何 IP 或 VLAN 配置且處於 shutdown 狀態的介面。

        ### 第三階段：重點功能保留
        - 保留 enable secret、VLAN 命名、子介面 (sub-interfaces) 封裝指令 (encapsulation dot1Q)、Static Route 與 DHCP 設定。

        ### 輸出格式：
        - 格式：## [HOSTNAME]
        - 分隔線：'------'
        - 僅輸出純淨的 CLI 指令，嚴禁任何 Markdown 區塊外的文字解釋。

        原始數據：
        {all_cmds_text}
        """

        # 增加 max_output_tokens 以確保空間，temperature 設為 0 以保持穩定
        print("正在等待 Gemini 回應...")
        response = model.generate_content(
            prompt,
            generation_config={
                "max_output_tokens": 4096,
                "temperature": 0,
                "top_p": 1
            }
        )
        print("Gemini 分析完畢！")
        
        return {"status": "success", "data": response.text}

    except Exception as e:
        return {"status": "error", "message": f"系統錯誤: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    # 本地測試時可以使用：$ env GEMINI_API_KEY=your_key uvicorn main:app --reload
    uvicorn.run(app, host="0.0.0.0", port=8080)