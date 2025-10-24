'''
https://github.com/lxdklp
https://github.com/kelvinfs0
'''

import re
import requests
import json
import time
from urllib.parse import quote
from Crypto.PublicKey import RSA


# 配置常量
MAX_RETRIES = 3
TIMEOUT = 10
RETRY_DELAY = 2  # 秒
uninput = input("用户名：")
upsw = input("密码：")

# 从HTML内容中提取重定向URL
def extract_redirect_url(html_content):
    pattern = r"top\.self\.location\.href\s*=\s*['\"]([^'\"]+)['\"]"
    match = re.search(pattern, html_content)
    if match:
        url = match.group(1)
        # 将HTML实体 &amp; 替换为 &
        url = url.replace('&amp;', '&')
        return url
    return None

# 请求指定URL并提取重定向链接
def fetch_and_extract_redirect(target_url, retries=MAX_RETRIES):
    for attempt in range(retries):
        try:
            headers = {
                'Host': '123.123.123.123',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9'
            }
            print(f"尝试连接 {target_url} (第 {attempt + 1}/{retries} 次)...")
            response = requests.get(target_url, headers=headers, timeout=TIMEOUT)
            response.encoding = 'utf-8'
            response.raise_for_status()
            redirect_url = extract_redirect_url(response.text)
            if redirect_url:
                print(f"成功提取到重定向URL:")
                print(redirect_url)
                return redirect_url
            else:
                print("未找到重定向URL")
                return None
        except requests.exceptions.ConnectTimeout:
            print(f"✗ 连接超时 ({TIMEOUT}秒)")
            if attempt < retries - 1:
                print(f"等待 {RETRY_DELAY} 秒后重试...")
                time.sleep(RETRY_DELAY)
            else:
                print(f"\n错误,无法连接到 {target_url}")
                return None
        except requests.exceptions.ConnectionError as e:
            print(f"✗ 连接错误: {e}")
            if attempt < retries - 1:
                print(f"等待 {RETRY_DELAY} 秒后重试...")
                time.sleep(RETRY_DELAY)
            else:
                return None
        except requests.exceptions.RequestException as e:
            print(f"✗ 请求失败: {e}")
            return None
    return None

# 请求提取到的重定向URL
def request_redirect_url(redirect_url, referer="http://123.123.123.123/", retries=MAX_RETRIES):
    for attempt in range(retries):
        try:
            headers = {
                'Host': '10.228.9.7',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Referer': referer,
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Cookie': 'EPORTAL_COOKIE_PASSWORD=; EPORTAL_COOKIE_USERNAME=; EPORTAL_COOKIE_OPERATORPWD=; EPORTAL_COOKIE_SERVER=; EPORTAL_COOKIE_SERVER_NAME=; EPORTAL_COOKIE_NEWV=; EPORTAL_AUTO_LAND=; EPORTAL_USER_GROUP=STU1; JSESSIONID=6F83E3286CA5CB22A7FF78EC85AB74B4'
            }
            response = requests.get(redirect_url, headers=headers, timeout=TIMEOUT)
            response.encoding = 'utf-8'
            response.raise_for_status()
            print(f"JSP请求成功")
            print(f"状态码: {response.status_code}")
            print(f"响应内容长度: {len(response.text)} 字符")
            print(f"响应部分内容预览:")
            print(response.text[:500])
            return response
        except requests.exceptions.Timeout:
            print(f"请求超时 (第 {attempt + 1}/{retries} 次)")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
        except requests.exceptions.RequestException as e:
            print(f"JSP请求失败: {e}")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
            else:
                return None
    return None

# 将大整数转换为十六进制字符串
def _bi_to_hex_from_int(x: int):
    if x == 0:
        return "0"
    digits = []
    while x > 0:
        digits.append(x & 0xFFFF)
        x >>= 16
    def digit_to_hex(n):
        s = ""
        for _ in range(4):
            s += "0123456789abcdef"[n & 0xF]
            n >>= 4
        return s[::-1]
    result = []
    for i in range(len(digits) - 1, -1, -1):
        result.append(digit_to_hex(digits[i]))
    hex_str = "".join(result)
    if hex_str.startswith("0") and len(hex_str) % 4 != 0:
        hex_str = hex_str.lstrip("0")
    return hex_str

# 使用RSA公钥加密密码
def encrypt_password_for_login(password, public_key_e, public_key_n, query_string=None):
    mac_string = "111111111"
    if query_string:
        m = re.search(r'(?:^|[?&])mac=([^&]+)', query_string)
        if m:
            mac_string = m.group(1)
    print("获取到的MAC:", mac_string)
    print("-" * 20)
    plain = password + '>' + mac_string
    print("拼接的密码:", plain)
    print("-" * 20)
    reversed_str = plain[::-1]
    e = int(public_key_e, 16)
    n = int(public_key_n, 16)
    num_digits = (n.bit_length() + 15) // 16
    chunk_size = 2 * (num_digits - 1)
    a = [ord(c) for c in reversed_str]
    while len(a) % chunk_size != 0:
        a.append(0)
    encrypted_chunks = []
    for i in range(0, len(a), chunk_size):
        chunk = a[i:i + chunk_size]
        m_int = 0
        digit_index = 0
        for k in range(0, len(chunk), 2):
            val = chunk[k] + (chunk[k + 1] << 8)
            m_int |= val << (digit_index * 16)
            digit_index += 1
        c_int = pow(m_int, e, n)
        encrypted_chunks.append(_bi_to_hex_from_int(c_int))
    return " ".join(encrypted_chunks)

# 请求pageInfo接口获取公钥信息
def get_page_info(redirect_url, retries=MAX_RETRIES):
    for attempt in range(retries):
        try:
            referer = redirect_url
            query_string = redirect_url.split('?')[1] if '?' in redirect_url else ""
            print(f"请求pageInfo接口, 使用referer: {referer} , queryString: {query_string}")
            headers = {
                'Host': '10.228.9.7',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Accept': '*/*',
                'Origin': 'http://10.228.9.7',
                'Referer': referer,
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Cookie': 'EPORTAL_COOKIE_PASSWORD=; EPORTAL_COOKIE_USERNAME=; EPORTAL_COOKIE_OPERATORPWD=; EPORTAL_COOKIE_SERVER=; EPORTAL_COOKIE_SERVER_NAME=; EPORTAL_COOKIE_NEWV=; EPORTAL_AUTO_LAND=; EPORTAL_USER_GROUP=STU1; JSESSIONID=6F83E3286CA5CB22A7FF78EC85AB74B4'
            }
            data = {
                'queryString': query_string
            }
            url = "http://10.228.9.7/eportal/InterFace.do?method=pageInfo"
            response = requests.post(url, headers=headers, data=data, timeout=TIMEOUT)
            response.encoding = 'utf-8'
            response.raise_for_status()
            print(f"pageInfo请求成功")
            print(f"状态码: {response.status_code}")
            print(f"\n原始响应内容:")
            print(f"{response.text}")
            try:
                data = response.json()
                print(f"\n完整的PageInfo数据:")
                print("=" * 60)
                print(json.dumps(data, indent=2, ensure_ascii=False))
                print("=" * 60)
                public_key_exponent = data.get('publicKeyExponent', '')
                public_key_modulus = data.get('publicKeyModulus', '')
                print(f"\n提取到的公钥信息:")
                print(f"publicKeyExponent: {public_key_exponent}")
                print(f"publicKeyModulus: {public_key_modulus}")
                return {
                    'publicKeyExponent': public_key_exponent,
                    'publicKeyModulus': public_key_modulus,
                    'full_data': data
                }
            except json.JSONDecodeError:
                print("响应不是有效的JSON格式")
                print(f"响应内容: {response.text}")
                return None
        except requests.exceptions.Timeout:
            print(f"✗ pageInfo请求超时 (第 {attempt + 1}/{retries} 次)")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
        except requests.exceptions.RequestException as e:
            print(f"pageInfo请求失败: {e}")
            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)
            else:
                return None
    return None

# 执行登录请求
def do_login(redirect_url, username, encrypted_password, query_string):
    try:
        encoded_query_string = quote(query_string, safe='')
        # 登录数据
        login_data = {
            'userId': username,
            'password': encrypted_password,
            'service': '',
            'queryString': encoded_query_string,
            'operatorPwd': '',
            'operatorUserId': '',
            'validcode': '',
            'passwordEncrypt': 'true'
        }
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Cookie': 'EPORTAL_COOKIE_PASSWORD=; EPORTAL_COOKIE_USERNAME=; EPORTAL_COOKIE_OPERATORPWD=; EPORTAL_COOKIE_SERVER=; EPORTAL_COOKIE_SERVER_NAME=; EPORTAL_COOKIE_NEWV=; EPORTAL_AUTO_LAND=; EPORTAL_USER_GROUP=STU1; JSESSIONID=6F83E3286CA5CB22A7FF78EC85AB74B4',
            'Host': '10.228.9.7',
            'Origin': 'http://10.228.9.7',
            'Referer': redirect_url,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0'
        }
        url = "http://10.228.9.7/eportal/InterFace.do?method=login"
        print(f"\n发送登录请求...")
        print(f"用户名: {username}")
        print(f"密码(加密): {encrypted_password[:60]}...")
        print(f"queryString(编码后): {encoded_query_string[:80]}...")
        response = requests.post(url, data=login_data, headers=headers, timeout=10)
        response.encoding = 'utf-8'
        response.raise_for_status()
        print(f"\n登录请求响应:")
        print(f"状态码: {response.status_code}")
        try:
            result = response.json()
            print(f"\n登录结果:")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            if result.get('result') == 'success':
                print(f"\n✓ 登录成功")
                print(f"userIndex: {result.get('userIndex', 'N/A')}")
            else:
                print(f"\n✗ 登录失败")
                print(f"消息: {result.get('message', 'N/A')}")
            return result
        except json.JSONDecodeError:
            print("响应不是有效的JSON格式")
            print(f"响应内容: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"登录请求失败: {e}")
        return None

# 主程序入口
if __name__ == "__main__":
    print("=" * 80)
    print("开始运行登录脚本 ver114514")
    print("=" * 80)
    target_url = "http://123.123.123.123"
    print(f"\n1. 正在请求: {target_url}")
    print("-" * 80)
    redirect_url = fetch_and_extract_redirect(target_url)
    if not redirect_url:
        print("\n" + "=" * 80)
        print("无法获取重定向URL")
        print("=" * 80)
        exit(1)
    print("-" * 80)
    print(f"提取结果: {redirect_url}")
    print("\n" + "=" * 80)
    print(f"2. 正在请求提取到的URL")
    print("=" * 80)
    request_redirect_url(redirect_url)
    print("\n" + "=" * 80)
    print(f"3. 正在请求pageInfo接口")
    print("=" * 80)
    page_info = get_page_info(redirect_url)
    if page_info:
        print("\n" + "=" * 80)
        print("所有请求完成")
        print("=" * 80)
        print("\n" + "=" * 80)
        print("4. 密码加密")
        print("=" * 80)
        password = upsw
        query_string = redirect_url.split('?')[1] if '?' in redirect_url else ""
        encrypted_password = encrypt_password_for_login(
            password,
            page_info['publicKeyExponent'],
            page_info['publicKeyModulus'],
            query_string,
        )
        print("\n" + "=" * 80)
        print("加密结果:")
        print("=" * 80)
        print(f"明文密码: {password}")
        print(f"加密密码: {encrypted_password}")
        print("=" * 80)
        print("\n" + "=" * 80)
        print("5. 执行登录")
        print("=" * 80)
        username = uninput
        login_result = do_login(
            redirect_url,
            username,
            encrypted_password,
            query_string
        )
        if login_result and login_result.get('result') == 'success':
            print("\n" + "=" * 80)
            print("登录完成")
            print("=" * 80)
        else:
            print("\n" + "=" * 80)
            print("登录流程结束，请检查用户名和密码")
            print("=" * 80)
