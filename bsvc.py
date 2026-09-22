import json
import hashlib
import urllib3
import requests
from typing import Optional, Tuple, Dict
from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_yuumari_secret_key() -> Tuple[Optional[str], Optional[Dict[str, str]]]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "X-Meow": bytes.fromhex("6d69e175").decode('latin-1')
    }
    
    try:
        res = requests.get("https://api.yuumari.com/ex-alb-centre/_/", headers=headers, verify=False, timeout=10)
        res.raise_for_status()
        config = res.json()
        
        encrypted_key_hex = config.get('access_key')
        accept_domains = config.get('accept_domains')
        
        if not encrypted_key_hex or not accept_domains:
            return None, None
            
        encrypted_bytes = bytes.fromhex(encrypted_key_hex)
        iv, ciphertext, tag = encrypted_bytes[:12], encrypted_bytes[12:-16], encrypted_bytes[-16:]
        
        php_ser = f"a:{len(accept_domains)}:{{" + "".join([f"i:{i};s:{len(d.encode('utf-8'))}:\"{d}\";" for i, d in enumerate(accept_domains)]) + "}"
        php_ser_obj = f"O:8:\"stdClass\":{len(accept_domains)}:{{" + "".join([f"i:{i};s:{len(d.encode('utf-8'))}:\"{d}\";" for i, d in enumerate(accept_domains)]) + "}"
        
        candidates = [
            json.dumps(accept_domains, separators=(',', ':')),
            php_ser,
            php_ser_obj,
            ",".join(accept_domains),
            json.dumps(accept_domains)
        ]

        for candidate in candidates:
            try:
                aes_key = hashlib.sha256(candidate.encode('utf-8')).digest()
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
                return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8'), headers
            except ValueError:
                continue
                
        return None, None
    except (requests.exceptions.RequestException, ValueError):
        return None, None

def bsvc_bypass(target_url: str) -> Optional[str]:
    secret_key, headers = get_yuumari_secret_key()
    
    if not secret_key or not headers:
        print("Failed to retrieve secret key.")
        return None
        
    payload = {"l": target_url, "u": secret_key}
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    
    try:
        res = requests.post("https://api.yuumari.com/ex-alb-centre/", data=payload, headers=headers, verify=False, timeout=15)
        res.raise_for_status()
        return res.json().get("result")
    except requests.exceptions.RequestException as e:
        print(f"Network error occurred: {e}")
        return None
    except ValueError:
        print("Expected JSON format from server was not received.")
        return None

if __name__ == "__main__":
    short_url = "http://bc.vc/2Xxf758"
    clean_url = bsvc_bypass(short_url)
    if clean_url:
        print(f"{clean_url}")