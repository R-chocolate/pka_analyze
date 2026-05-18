import sys
import os
from Decipher.pt_crypto import decrypt_pkt

def decrypt_pka_to_xml(pka_path):
    if not os.path.exists(pka_path):
        print(f"錯誤：找不到檔案 {pka_path}")
        return
    
    print(f"正在讀取並解密：{pka_path} ...")
    with open(pka_path, "rb") as f:
        pka_bytes = f.read()
    
    try:
        decrypted_bytes = decrypt_pkt(pka_bytes)
        xml_content = decrypted_bytes.decode('utf-8', errors='ignore')
        
        output_xml_path = os.path.splitext(pka_path)[0] + "_decrypted.xml"
        with open(output_xml_path, "w", encoding="utf-8") as out_f:
            out_f.write(xml_content)
        
        print(f"解密成功！已將解密後的 XML 儲存至：{output_xml_path}")
    except Exception as e:
        print(f"解密失敗：{e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("使用方式: python decrypt_helper.py <pka_file_path>")
        print("例如: python decrypt_helper.py 4135.pka")
    else:
        decrypt_pka_to_xml(sys.argv[1])
