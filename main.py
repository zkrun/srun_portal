import requests
import hashlib
import json
import base64
import time
import hmac
import re
import subprocess
import socket
from test import *
import subprocess
from urllib import request
url_challenge = 'http://{ip}/cgi-bin/get_challenge'
url_api = 'http://{ip}/cgi-bin/srun_portal'
#url_cas_auth='http://{ip}/v1/srun_portal_cas'
url_log_out='http://{ip}/cgi-bin/srun_portal?'
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.57',
    'Accept': 'text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01',
    'Cookie':'lang=zh-CN',


}
url_userinfo='http://{ip}/cgi-bin/rad_user_info'

ac_id = '1'
enc = "srun_bx1"
callback = 'jQuery112404857598766409059_'

n = '200'
type = '1'

def get_local_ip():
    try:
        # 创建一个UDP套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 连接到一个公共的IP地址（例如百度服务器），并获取本机IP地址
        sock.connect(('baidu.com', 80))
        # 获取本机IP地址
        local_ip = sock.getsockname()[0]
        return local_ip
    except socket.error:
        return '无法获取本机IP地址'

# 调用函数获取本机IP地址

def get_challenge():
    timestamp = int(time.time() * 1000)
    params = {'_': timestamp, 'callback': callback + '_' + str(timestamp),'ip':ip,'username':username}
    response = requests.get(url=url_challenge, params=params, headers=headers)
    response_text = response.text
    json_data = response_text.split('(', 1)[1].rsplit(')', 1)[0]

    # 解析 JSON 数据
    data = json.loads(json_data)

    print(data)
    # 提取 challenge 值
    challenge = data["challenge"]

    return challenge


def md5_encrypt(data, token):
    return hmac.new(token.encode(), data.encode(), hashlib.md5).hexdigest()


def x_encode(data, key):
    return key + data


def do_chksum(chkstr):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(chkstr.encode('utf-8'))
    return sha1_hash.hexdigest()


def get_info(username, password, challenge):
    info_data = {
        'username': username,
        'password': password,
        'ip': ip ,#,or '172.16.154.130',
        'acid': ac_id,
        'enc_ver': enc
    }
   #
    i = re.sub("'", '"', str(info_data))
    i = re.sub(" ", '', i)
    return i

def login(username, password):
    challenge = get_challenge()
    hmd5 = md5_encrypt(password,challenge)
    i = get_info(username, password, challenge)
    i = "{SRBX1}" + get_base64(get_xencode(i, challenge))
    chkstr = challenge + username + challenge + hmd5 + challenge + str(ac_id) + challenge + ip + challenge + str(n) + challenge + str(type) + challenge + i
    chksum = get_sha1(chkstr)
    password = "{MD5}" + hmd5
    login_params = {
        'callback': callback  + str(int(time.time() * 1000)),
        'action': 'login',
        'username': username,
        'password': password,
        'ac_id':ac_id,
        'ip': ip,
        'chksum': chksum,
        'info': i,
        'n': n,
        'type': type,
        'os': 'windows+10',
        'name': 'windows',
        'double_stack': '0',
        '_': int(time.time() * 1000)
    }
    print(login_params)
    response = requests.get(url_api, params=login_params,headers=headers)
    print('--------------------------------')

    print("url_api get:")
    print(response.text)
    success_pattern=r"E0000.*"
    success=re.search(success_pattern,response.text)
    if success:
        print("\033[31m",success.group(),"\033[0m")
    else:
        print("\033[31m","login is not successful","\033[0m")
    print("userinfo:")
    response1 = requests.get(url_userinfo, params=login_params, headers=headers)
    print(response1.text)


def log_out(username,ip):

    logout_params = {
        'callback': callback + str(int(time.time() * 1000)),
        'action': 'logout',
        'username': username+'@test',
        'ac_id': ac_id,
        'ip': ip,
        '_': str(int(time.time() * 1000))
    }
    print(logout_params)
    log_out_res=requests.get(url=url_log_out,params=logout_params,headers=headers)
    print("logout.........................")
    print("\033[31m",log_out_res.text,"\033[0m")
def get_authurl():
    pattern = r"默认网关\. . . . . . . . . . . . . : (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    output = subprocess.Popen(["ipconfig", "/all"], stdout=subprocess.PIPE).communicate()[0].decode("gbk")
    dataway = re.search(pattern, output)
    if dataway:
        default_gateway_ip = dataway.group(1)
        print("默认网关IP地址:(请不要挂代理或已认证，会导致识别认证网址失败)", default_gateway_ip)
        url = 'http://'+str(default_gateway_ip)
        r=request.urlopen(url)
        print(r.geturl())
        auth_url=r.geturl()
        auth_pattern=r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        authurl=re.search(auth_pattern,auth_url)
        if authurl:
            print(authurl.group(1))
            return authurl.group(1)
        else:
            print("未找到认证ip地址")
    else:
        print("未找到默认网关IP地址")



if __name__ == '__main__':
    ip_address = get_local_ip()
    print("本机IP地址:", ip_address)
    ip=ip_address
    choose=input("是否要使用默认网关 y/n(选择是将会自动识别网关并认证，如果认证失败请选否)")
    if choose in ['y', '\n','']:
        authurl=get_authurl()
        host_ip=authurl
        if host_ip:
            print("目标认证主机:",host_ip)
        else:
            print("无法识别")
    else:
        host_ip = input("请输入校园网认证IP地址(格式:172.16.154.130)：")
    url_challenge = url_challenge.format(ip=host_ip)
    url_userinfo = url_userinfo.format(ip=host_ip)
    url_api = url_api.format(ip=host_ip)
    url_log_out = url_log_out.format(ip=host_ip)
    username = input("username:")
    password = input("password:")
    print(username)
    print(password)
    login(username, password)
    #log_out(username, ip)#登出，放在login后面
