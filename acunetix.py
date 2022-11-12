#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import requests
import argparse

from datetime import datetime, timedelta
'''
import requests.packages.urllib3.util.ssl_
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

or 

pip install requests[security]
'''
requests.packages.urllib3.disable_warnings()

tarurl = "https://127.0.0.1:3443/"
apikey="1986ad8c0a5b3df4d7028d5f3c06e936c99f41123b1694bcd891d3397251d697e"
headers = {"X-Auth":apikey,"content-type": "application/json"}
# proxies = {"http":"http://127.0.0.1:8080","https":"https://127.0.0.1:8080"}
proxies = {}
group_name = None
group_id = None
max_concurrence_scans = 5

class Target:
    def __init__(self, url) -> None:
        self.url = url
        self.target_id = None
        self.group_name = None
        self.group_id = None

def get_args():
    parser = argparse.ArgumentParser(description='Acunetix API Automator')
    parser.add_argument('-t', help='Target', default=None, type=str)
    parser.add_argument('-l', help='Target list', default=None, type=str)
    parser.add_argument('-g', help='Group name', default=None, type=str)
    parser.add_argument('-w', help='Time wait between scans', default=2, type=int)
    return parser.parse_args()

def getgroupidfromname(name=''):
    try:
        response = requests.get(tarurl + '/api/v1/target_groups',headers=headers,timeout=30,verify=False,proxies=proxies)
        result = json.loads(response.content)
        for group in result["groups"]:
            if group["name"] == name:
                return group["group_id"]
        print(f"Cant find group with name {name}")
        return None
    except Exception as e:
        print(str(e))
        return

def addgroup():
    global group_name
    group_name = f'{(datetime.now() + timedelta(hours=11)).strftime("%d-%m-%Y")} {group_name}'
    data = {"name": group_name}
    try:
        response = requests.post(tarurl + '/api/v1/target_groups',json=data,headers=headers,timeout=30,verify=False,proxies=proxies)
        result = json.loads(response.content)
        if response.ok:
            return result["group_id"]
        else:
            if response.status_code == 409:
                group_id = getgroupidfromname()
                return group_id
            else:

                return None
    except Exception as e:
        print(str(e))
        return

def addtarget(url=''):
    #添加任务
    data = {"address":url,"description":url,"criticality":"30","type":"default"}
    try:
        response = requests.post(tarurl+"/api/v1/targets",data=json.dumps(data),headers=headers,timeout=30,verify=False,proxies=proxies)
        result = json.loads(response.content)
        return result['target_id']
    except Exception as e:
        print(str(e))
        return None

def addtarget2group(target_id=None):
    data = {"remove":[],"add":[target_id]}
    try:
        response = requests.patch(tarurl+f"/api/v1/target_groups/{group_id}/targets",json=data,headers=headers,timeout=30,verify=False,proxies=proxies)
        return response.ok
    except Exception as e:
        print(str(e))
        return None

def startscan(target_id, waittime=0):
    # 先获取全部的任务.避免重复
    # 添加任务获取target_id
    # 开始扫描
    '''
    11111111-1111-1111-1111-111111111112    High Risk Vulnerabilities          
    11111111-1111-1111-1111-111111111115    Weak Passwords        
    11111111-1111-1111-1111-111111111117    Crawl Only         
    11111111-1111-1111-1111-111111111116    Cross-site Scripting Vulnerabilities       
    11111111-1111-1111-1111-111111111113    SQL Injection Vulnerabilities         
    11111111-1111-1111-1111-111111111118    quick_profile_2 0   {"wvs": {"profile": "continuous_quick"}}            
    11111111-1111-1111-1111-111111111114    quick_profile_1 0   {"wvs": {"profile": "continuous_full"}}         
    11111111-1111-1111-1111-111111111111    Full Scan   1   {"wvs": {"profile": "Default"}}         
    '''
    startdate = datetime.now() + timedelta(hours=waittime+11)
    data = {"target_id":target_id,"profile_id":"11111111-1111-1111-1111-111111111111","schedule": {"disable": False,"start_date":str(startdate),"time_sensitive": False}}
    try:
        response = requests.post(tarurl+"/api/v1/scans",data=json.dumps(data),headers=headers,timeout=30,verify=False,proxies=proxies)
        # result = json.loads(response.content)
        # return result['target_id']
        if response.ok:
            print(f'Scan scheduled, start time: {str(startdate)}')
        else:
            print(f'Something when wrong creating scan for target {target_id}')
        return
    except Exception as e:
        print(str(e))
        return

def getstatus(scan_id):
    # 获取scan_id的扫描状况
    try:
        response = requests.get(tarurl+"/api/v1/scans/"+str(scan_id),headers=headers,timeout=30,verify=False,proxies=proxies)
        result = json.loads(response.content)
        status = result['current_session']['status']
        #如果是completed 表示结束.可以生成报告
        if status == "completed":
            # return getreports(scan_id) => notify
            pass
        else:
            return result['current_session']['status']
    except Exception as e:
        print(str(e))
        return

def delete_scan(scan_id):
    # 删除scan_id的扫描
    try:
        response = requests.delete(tarurl+"/api/v1/scans/"+str(scan_id),headers=headers,timeout=30,verify=False,proxies=proxies)
        #如果是204 表示删除成功
        if response.status_code == "204":
            return True
        else:
            return False
    except Exception as e:
        print(str(e))
        return

def delete_target(target_id):
    # 删除scan_id的扫描
    try:
        response = requests.delete(tarurl+"/api/v1/targets/"+str(target_id),headers=headers,timeout=30,verify=False,proxies=proxies)
    except Exception as e:
        print(str(e))
        return    
    
def stop_scan(scan_id):
    # 停止scan_id的扫描
    try:
        response = requests.post(tarurl+"/api/v1/scans/"+str(scan_id+"/abort"),headers=headers,timeout=30,verify=False,proxies=proxies)
        #如果是204 表示停止成功
        if response.status_code == "204":
            return True
        else:
            return False
    except Exception as e:
        print(str(e))
        return          
        
def config(url):
    target_id = addtarget(url)
    addtarget2group(target_id)
    #获取全部的扫描状态
    data = {
            "excluded_paths":[],
            "user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
            "custom_headers":["Accept: */*","Referer:"+url,"Connection: Keep-alive"],
            "custom_cookies":[],
            "scan_speed":"moderate",#sequential/slow/moderate/fast more and more fast
            "technologies":[],#ASP,ASP.NET,PHP,Perl,Java/J2EE,ColdFusion/Jrun,Python,Rails,FrontPage,Node.js
            #代理
            #无验证码登录
            }
    try:
        res = requests.patch(tarurl+"/api/v1/targets/"+str(target_id)+"/configuration",data=json.dumps(data),headers=headers,timeout=30*4,verify=False,proxies=proxies)
        if res.ok:
            return target_id
        else:
            return None
    except Exception as e:
        raise e
        
def getscan():
    #获取全部的扫描状态
    targets = []
    try:
        response = requests.get(tarurl+"/api/v1/scans",headers=headers,timeout=30,verify=False,proxies=proxies)
        results = json.loads(response.content)
        for result in results['scans']:
            targets.append(result['target']['address'])
            print(result['scan_id'],result['target']['address'],getstatus(result['scan_id']))#,result['target_id']
        return list(set(targets))
    except Exception as e:
        raise e

def schedule(targets=()):
    global group_id
    group_id_tmp = addgroup()
    if "-" not in group_id_tmp:
        group_id = f'{group_id_tmp[:8]}-{group_id_tmp[8:12]}-{group_id_tmp[12:16]}-{group_id_tmp[16:20]}-{group_id_tmp[20:]}'
    else:
        group_id = group_id_tmp
    for id, target in enumerate(targets):
        target_id = config(target)
        waittime = int(id/max_concurrence_scans)*timeinterval
        startscan(target_id,waittime)



if __name__ == '__main__':
    argsObj = get_args()
    targets = set()
    target_list = argsObj.l
    target = argsObj.t
    timeinterval = argsObj.w
    if target:
        targets.add(target)
    if target_list:
        tmp_tarlist = open(target_list,'r').read().splitlines()
        targets.update(tmp_tarlist)
    
    group_name = argsObj.g

    schedule(targets)
    # print(config('http://testhtml5.vulnweb.com/'))
