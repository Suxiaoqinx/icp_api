import base64
import json
import requests
import hashlib
import time
import os
from urllib import parse
import uuid
from flask import Flask, request, jsonify ,Response
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from crack import Crack  # 假设 Crack 是一个你自己实现的类

app = Flask(__name__)

CACHE_DIR = './cache'  # 缓存文件目录

# 创建缓存目录（如果不存在）
if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)


def auth():
    t = str(round(time.time()))
    data = {
        "authKey": hashlib.md5(("testtest" + t).encode()).hexdigest(),
        "timeStamp": t
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://beian.miit.gov.cn/",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn"
    }
    try:
        resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth", headers=headers,
                             data=parse.urlencode(data)).text
        return json.loads(resp)["params"]["bussiness"]
    except Exception:
        time.sleep(5)
        resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth", headers=headers,
                             data=parse.urlencode(data)).text
        return json.loads(resp)["params"]["bussiness"]


def getImage(token):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://beian.miit.gov.cn/",
        "Token": token,
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn"
    }
    payload = {
        "clientUid": "point-" + str(uuid.uuid4())
    }
    try:
        resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint",
                             headers=headers, json=payload).json()
        return resp["params"], payload["clientUid"]
    except Exception:
        time.sleep(5)
        resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint",
                             headers=headers, json=payload).json()
        return resp["params"], payload["clientUid"]


def aes_ecb_encrypt(plaintext: bytes, key: bytes, block_size=16):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    padding_length = block_size - (len(plaintext) % block_size)
    plaintext_padded = plaintext + bytes([padding_length]) * padding_length

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode('utf-8')


def generate_pointjson(big_img, small_img, secretKey):
    crack = Crack()  # 假设 Crack 是一个你实现的类
    boxes = crack.detect(big_img)
    if boxes:
        print("文字检测成功")
    else:
        print("文字检测失败,请重试")
        raise Exception("文字检测失败,请重试")
    points = crack.siamese(small_img, boxes)
    print("文字匹配成功")
    new_points = [[p[0] + 20, p[1] + 20] for p in points]
    pointJson = [{"x": p[0], "y": p[1]} for p in new_points]
    enc_pointJson = aes_ecb_encrypt(json.dumps(pointJson).replace(" ", "").encode(), secretKey.encode())
    return enc_pointJson


def checkImage(uuid_token, secretKey, clientUid, pointJson, token):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://beian.miit.gov.cn/",
        "Token": token,
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn"
    }
    data = {
        "token": uuid_token,
        "secretKey": secretKey,
        "clientUid": clientUid,
        "pointJson": pointJson
    }
    resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/checkImage", headers=headers,
                         json=data).json()
    if resp["code"] == 200:
        return resp["params"]["sign"]
    return False


def query(sign, uuid_token, domain, token):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://beian.miit.gov.cn/",
        "Token": token,
        "Sign": sign,
        "Uuid": uuid_token,
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn",
        "Content-Type": "application/json",
        "Cookie": "__jsluid_s=" + str(uuid.uuid4().hex[:32])
    }
    data = {"pageNum": "", "pageSize": "", "unitName": domain, "serviceType": 1}
    resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition",
                         headers=headers, data=json.dumps(data).replace(" ", "")).text
    return resp


def save_to_cache(domain, data):
    """保存数据到缓存文件"""
    cache_path = os.path.join(CACHE_DIR, f"{domain}.json")
    with open(cache_path, 'w', encoding='utf-8') as f:
        json.dump(data, f)


def load_from_cache(domain):
    """从缓存文件中加载数据"""
    cache_path = os.path.join(CACHE_DIR, f"{domain}.json")
    if os.path.exists(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


@app.route('/query', methods=['GET'])
def query_api():
    try:
        # 从 URL 查询参数中获取 domain 和 type
        domain = request.args.get('domain')
        query_type = request.args.get('type', '')  # 默认为空字符串
        
        if not domain:
            return jsonify({"status": "failed", "message": "Missing 'domain' parameter"}), 400
        
        # 如果 type=cache，则检查缓存
        if query_type == 'cache':
            cached_data = load_from_cache(domain)
            if cached_data:
                json_data = json.dumps({"status": "successful", "data": cached_data})
                return Response(json_data, content_type='application/json')

        # 如果没有缓存，或未指定 type=cache，则继续进行查询
        crack = Crack()
        token = auth()
        time.sleep(0.1)
        params, clientUid = getImage(token)
        pointjson = generate_pointjson(params["bigImage"], params["smallImage"], params["secretKey"])
        time.sleep(0.5)
        sign = checkImage(params["uuid"], params["secretKey"], clientUid, pointjson, token)
        time.sleep(0.5)

        if sign:
            result = query(sign, params["uuid"], domain, token)
            response = json.loads(result)
            json_data = json.dumps({"status": "successful", "data": response['params']['list']})

            # 如果 type=cache，则将查询结果缓存
            if query_type == 'cache':
                save_to_cache(domain, response['params']['list'])

            return Response(json_data, content_type='application/json')

        else:
            return jsonify({"status": "failed", "message": "Captcha verification failed"}), 400
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
