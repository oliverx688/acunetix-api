#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import requests
import argparse

from time import sleep
from pathlib import Path

from datetime import datetime, timedelta

from icecream import ic

"""
import requests.packages.urllib3.util.ssl_
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

or 

pip install requests[security]
"""
requests.packages.urllib3.disable_warnings()

tarurl = "https://127.0.0.1:3443/"
apikey = "1986ad8c0a5b3df4d7028d5f3c06e936cf0987ff302df4b15ab8a141992a18783"
headers = {"X-Auth": apikey, "content-type": "application/json"}
# proxies = {"http":"http://127.0.0.1:8080","https":"https://127.0.0.1:8080"}
proxies = {}
MAX_CONCUREENCE_SCANS = 5

PATH_FILE = "targets.txt"


def add_target(url=""):
    data = {"address": url, "description": url, "criticality": "30", "type": "default"}
    try:
        response = requests.post(
            tarurl + "/api/v1/targets",
            data=json.dumps(data),
            headers=headers,
            timeout=30,
            verify=False,
            proxies=proxies,
        )
        result = json.loads(response.content)
        return result["target_id"]
    except Exception as e:
        ic(str(e))
        return None


def start_scan(target_id):
    """
    11111111-1111-1111-1111-111111111112    High Risk Vulnerabilities
    11111111-1111-1111-1111-111111111115    Weak Passwords
    11111111-1111-1111-1111-111111111117    Crawl Only
    11111111-1111-1111-1111-111111111116    Cross-site Scripting Vulnerabilities
    11111111-1111-1111-1111-111111111113    SQL Injection Vulnerabilities
    11111111-1111-1111-1111-111111111118    quick_profile_2 0   {"wvs": {"profile": "continuous_quick"}}
    11111111-1111-1111-1111-111111111114    quick_profile_1 0   {"wvs": {"profile": "continuous_full"}}
    11111111-1111-1111-1111-111111111111    Full Scan   1   {"wvs": {"profile": "Default"}}
    """
    startdate = datetime.now() + timedelta(seconds=10)
    data = {
        "target_id": target_id,
        "profile_id": "11111111-1111-1111-1111-111111111111",
        "schedule": {
            "disable": False,
            "start_date": str(startdate),
            "time_sensitive": False,
        },
    }
    try:
        response = requests.post(
            tarurl + "/api/v1/scans",
            data=json.dumps(data),
            headers=headers,
            timeout=30,
            verify=False,
            proxies=proxies,
        )
        # result = json.loads(response.content)
        # return result['target_id']
        if response.ok:
            scan_id = response.json().get("scan_id", "")
            ic(f"{scan_id} => Scan scheduled, start time: {str(startdate)}")
        else:
            scan_id = ""
            ic(f"Something when wrong creating scan for target {target_id}")
        return scan_id
    except Exception as e:
        ic(str(e))
        return ""


def get_scan_status(scan_id):
    try:
        response = requests.get(
            tarurl + "/api/v1/scans/" + str(scan_id),
            headers=headers,
            timeout=30,
            verify=False,
            proxies=proxies,
        )
        result = json.loads(response.content)
        status = result["current_session"]["status"]
        return status

        # 如果是completed 表示结束.可以生成报告
        if status == "completed":
            # return getreports(scan_id) => notify
            pass
        else:
            return result["current_session"]["status"]
    except Exception as e:
        print(str(e))
        return


def delete_scan(scan_id):
    try:
        response = requests.delete(
            tarurl + "/api/v1/scans/" + str(scan_id),
            headers=headers,
            timeout=30,
            verify=False,
            proxies=proxies,
        )
        if response.status_code == "204":
            return True
        else:
            return False
    except Exception as e:
        print(str(e))
        return


def delete_target(target_id):
    try:
        response = requests.delete(
            tarurl + "/api/v1/targets/" + str(target_id),
            headers=headers,
            timeout=30,
            verify=False,
            proxies=proxies,
        )
    except Exception as e:
        print(str(e))
        return


def stop_scan(scan_id):
    try:
        response = requests.post(
            tarurl + "/api/v1/scans/" + str(scan_id + "/abort"),
            headers=headers,
            timeout=30,
            verify=False,
            proxies=proxies,
        )
        if response.status_code == "204":
            return True
        else:
            return False
    except Exception as e:
        print(str(e))
        return


def config(url):
    target_id = add_target(url)
    data = {
        "excluded_paths": [],
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
        "custom_headers": ["Accept: */*", "Referer:" + url, "Connection: Keep-alive"],
        "custom_cookies": [],
        "scan_speed": "moderate",  # sequential/slow/moderate/fast more and more fast
        "technologies": [],  # ASP,ASP.NET,PHP,Perl,Java/J2EE,ColdFusion/Jrun,Python,Rails,FrontPage,Node.js
    }
    try:
        res = requests.patch(
            tarurl + "/api/v1/targets/" + str(target_id) + "/configuration",
            data=json.dumps(data),
            headers=headers,
            timeout=30 * 4,
            verify=False,
            proxies=proxies,
        )
        if res.ok:
            return target_id
        else:
            return None
    except Exception as e:
        raise e


def get_active_scans_count():
    active_scan = 0
    try:
        response = requests.get(
            tarurl + "/api/v1/scans",
            headers=headers,
            timeout=30,
            verify=False,
            proxies=proxies,
        )
        results = json.loads(response.content)
        for result in results["scans"]:
            if get_scan_status(result["scan_id"]) != "completed":
                active_scan += 1

    except Exception as e:
        ic(e)

    ic(active_scan)
    return active_scan


def get_targets() -> list:
    try:
        with open("targets.txt", "r") as f:
            targets = f.readlines()
        targets = [target.strip("\n").strip() for target in targets]

        return targets
    except Exception as e:
        ic(e)
        return []


def main():
    targets = get_targets()
    for target in targets:
        target_id = config(target)

        while get_active_scans_count() >= MAX_CONCUREENCE_SCANS:
            sleep(1 * 60)

        start_scan(target_id)


def test():
    targets = ["http://testphp.vulnweb.com/"]
    # schedule(targets)
    # print(config('http://testhtml5.vulnweb.com/'))
    # sleep(10)
    ic(get_active_scans_count())


if __name__ == "__main__":
    main()
    # test()
