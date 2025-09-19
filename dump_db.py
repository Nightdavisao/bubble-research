from hashlib import pbkdf2_hmac
import re
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import json, requests, csv
import os

BASE_URL = 'https://bubble.io'

def encode_garbage(query: str, appname: str) -> dict:
    v2 = '1'
    cur_timestamp = str(int(time.time() * 1000))
    timestamp_version = f"{cur_timestamp}_{v2}"
    key2 = appname + cur_timestamp
    iv = timestamp_version + appname
    return {
        'z': encode_data(key2, iv, query, appname),
        'y': encode_data(appname, 'po9', timestamp_version, appname),
        'x': encode_data(appname, 'fl1', iv, appname)
    }
    
def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext
    
def encode_data(key2: str, iv: str, text3: str, appname: str) -> str:
    derived_key = pbkdf2_hmac('md5', key2.encode(), appname.encode(), 7, dklen=32)
    derived_iv = pbkdf2_hmac('md5', iv.encode(), appname.encode(), 7, dklen=16)
    output = encrypt_cbc(text3.encode(), derived_key, derived_iv)
    return base64.b64encode(output).decode('utf-8')

def get_dynamic_js():
    req = requests.get(BASE_URL)
    html_content = req.text
    pattern = r'<script[^>]+src="([^"]+)"'
    matches = re.findall(pattern, html_content)
    for src in matches:
        if 'dynamic_js' in src:
            print("Found dynamic_js file:", f'{BASE_URL}{src}')
            return requests.get(f'{BASE_URL}{src}').text
    raise Exception("dynamic_js file not found")

def get_appinfo():
    dynamic_js = get_dynamic_js()
    pattern = r'const\s+app\s*=\s*JSON\.parse\(\s*\'(.+?)\'\s*\);\s*(?=window.app\s*=\s*app;)'
    match = re.search(pattern, dynamic_js, re.DOTALL)
    
    if match:
        appinfo_str = match.group(1)
        #print("Raw appinfo string:", appinfo_str)
        appinfo_str = appinfo_str.encode().decode('unicode_escape')
        return json.loads(appinfo_str)
    else:
        raise Exception("App info not found in dynamic_js")
    
def query_db(appname: str, app_version: str, user_type: str):
    results = []
    offset = 0
    while True:
        data = {
            "appname": appname,
            "app_version": app_version,
            "searches": [
                {
                    "appname": appname,
                    "app_version": app_version,
                    "type": f"custom.{user_type}" if user_type != 'user' else user_type,
                    "constraints": [],
                    "sorts_list": [],
                    "from": offset,
                    "search_path": "{\"constructor_name\":\"State\",\"args\":[{\"type\":\"json\",\"value\":\"%p3.bTGbC.%el.cnvDO2.%el.cntLz1.%el.cntRQ.%el.cntTS.%el.cntNC1.%s.0\"}]}",
                    "situation": "initial search",
                    "n": 1000
                }
            ]
        }
        
        garbage = encode_garbage(json.dumps(data), appname)

        req = requests.post(f'{BASE_URL}/elasticsearch/msearch', json=garbage, headers={
            'Content-Type': 'application/json'
        })
        
        res = req.json()
        
        hits = res['responses'][0]['hits']['hits']
        if not hits:
            break
        results.extend([hit['_source'] for hit in hits])
        offset += len(hits)
        print(f"Fetched {len(hits)} records, total so far: {len(results)}")

    return results

if __name__ == "__main__":
    appinfo = get_appinfo()
    print("App Info:", appinfo)
    
    user_types = appinfo['user_types']
    appname = appinfo['_id']
    app_version = appinfo['app_version']
    
    # write the appinfo to a json file
    os.makedirs('output_json', exist_ok=True)
    with open(f'output_json/{appname}_appinfo.json', 'w') as f:
        json.dump(appinfo, f, indent=4)
    print(f"App info saved to output_json/{appname}_appinfo.json")
    
    print("User Types:", user_types)
    
    for key, value in user_types.items():
        print(f"Querying DB for user type: {key}")
        try:
            results = query_db(appname, app_version, key)
            print(f"Found {len(results)} records for user type {key}")
            output_dir = "output_csv"
            os.makedirs(output_dir, exist_ok=True)
            csv_path = os.path.join(output_dir, f'{appname}_{key}.csv')
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                if results:
                    fieldnames = list(value['%f3'].keys())
                    fieldnames += ['Created By', 'Modified By', '_type', '_version', 'Created Date', 'Modified Date', '_id', 'Slug']
                    if key == 'user':
                        fieldnames += [
                            'user_signed_up', 'authentication'
                        ]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results)
                else:
                    csvfile.write("No data found")
            print(f"Data saved to {csv_path}")
        except Exception as e:
            print(f"Error processing user type {key}: {e}")