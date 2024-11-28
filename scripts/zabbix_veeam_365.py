#!/usr/bin/python3

import urllib3
import json
import requests
import base64
import argparse
from datetime import datetime
from dateutil import parser
from pyzabbix import ZabbixMetric, ZabbixSender

def GenerateVeeamRestSession(veeamIp, veeamPort, user, password):
    headers = {'content-Type': 'application/x-www-form-urlencoded'}
    payload = {'grant_type': 'password',
    'username':  user,
    'password':  password}
    url = "https://" + veeamIp + ":" + veeamPort + "/v4/Token"
    r = requests.post(url, headers=headers, data=payload, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Failed authenticating to Veeam")
    res = json.loads(r.text)['access_token']
    return res

def EndVeeamRestSession(veeamIp, veeamPort, sessionId):
    headers = {'content-Type': 'application/x-www-form-urlencoded'}
    url = "https://" + veeamIp + ":" + veeamPort + "/v4/Token"
    res = requests.delete(url, headers=headers, verify=False)
    return res

def GetVeeamRepoDiscovery(veeamIp, veeamPort, sessionId):
    url = "https://" + veeamIp + ":" + veeamPort + "/v4/BackupRepositories"
    headers = {'Authorization': 'Bearer ' + sessionId,
    'content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data:
        if d["capacityBytes"] != -1:
            item = dict()
            item["{#NAME}"] = d["name"]
            result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def PrintVeeamRepoData(veeamIp, veeamPort, sessionId):
    url = "https://" + veeamIp + ":" + veeamPort + "/v4/BackupRepositories"
    headers = {'Authorization': 'Bearer ' + sessionId,
    'content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    for d in data:
        for key, value in d.items():
            print("%s = %s" % (key, value))
        print("\n")
    return 0

def GetVeeamRepoData(veeamIp, veeamPort, sessionId, host, server):
    url = "https://" + veeamIp + ":" + veeamPort + "/v4/BackupRepositories"
    headers = {'Authorization': 'Bearer ' + sessionId,
    'content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data:
        if d["capacityBytes"] != -1:
            key = "Repository.CapacityBytes[" + d["name"] + "]"
            result.append(ZabbixMetric(host, key, d["capacityBytes"]))
            key = "Repository.FreeSpaceBytes[" + d["name"] + "]"
            result.append(ZabbixMetric(host, key, d["freeSpaceBytes"]))
            if d["capacityBytes"] > 0:
                FreeSpacePercentage = float(100 * d["freeSpaceBytes"] / d["capacityBytes"])
                key = "Repository.FreeSpacePercentage[" + d["name"] + "]"
                result.append(ZabbixMetric(host, key, FreeSpacePercentage))
    try:
        print(ZabbixSender(server).send(result))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0

def GetVeeamJobDiscovery(veeamIp, veeamPort, sessionId):
    url = "https://" + veeamIp + ":" + veeamPort + "/v4/Jobs"
    headers = {'Authorization': 'Bearer ' + sessionId,
    'content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data:
        item = dict()
        item["{#NAME}"] = d["name"]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def PrintVeeamJobData(veeamIp, veeamPort, sessionId):
    url = "https://" + veeamIp + ":" + veeamPort + "/v4/Jobs"
    headers = {'Authorization': 'Bearer ' + sessionId,
    'content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    for d in data:
        for key, value in d.items():
            print("%s = %s" % (key, value))
        print("\n")
    return 0

def GetVeeamJobData(veeamIp, veeamPort, sessionId, host, server):
    url = "https://" + veeamIp + ":" + veeamPort + "/v4/Jobs"
    headers = {'Authorization': 'Bearer ' + sessionId,
    'content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    jobs = []
    resultValue = {'None': 0, 'Success': 1 ,'Warning': 2 ,'Failed': 3, 'Running': 4, 'Stopped': 5}
    for d in data:
        if not d["name"] in jobs:
            jobs.append(d["name"])
            LastRun = parser.parse(d["lastRun"])
            key = "Backup.LastRun[" + d["name"] + "]"
            result.append(ZabbixMetric(host, key, LastRun))
            key = "Backup.LastStatus[" + d["name"] + "]"
            result.append(ZabbixMetric(host, key, resultValue[d["lastStatus"]]))
    try:
        print(ZabbixSender(server).send(result))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', '-z', action="store",
                        help="Hostname", required=True)
    parser.add_argument('--ip', '-i', action="store",
                        help="IP Address", required=True)
    parser.add_argument('--port', '-o', action="store",
                        help="IP Address", required=True)
    parser.add_argument('--username', '-u', action="store",
                        help="Username", required=True)
    parser.add_argument('--password', '-p', action="store",
                        help="Password", required=True)
    parser.add_argument('--authtype', '-a', action="store",
                        help="Authorization Type [vcenter|windows]",
                        default="vcenter")
    parser.add_argument('--server', '-s', action="store",
                        help="Zabbix Server", default="localhost")
    parser.add_argument('--discoverrepo', '-dr', action="store_true",
                        help="Discover")
    parser.add_argument('--getrepo', '-gr', action="store_true",
                        help="Statistics")
    parser.add_argument('--printrepo', '-pr', action="store_true",
                        help="Print")
    parser.add_argument('--discoverjob', '-dj', action="store_true",
                        help="Discover")
    parser.add_argument('--getjob', '-gj', action="store_true",
                        help="Statistics")
    parser.add_argument('--printjob', '-pj', action="store_true",
                        help="Print")
    args = parser.parse_args()

    urllib3.disable_warnings()

    session_id = GenerateVeeamRestSession(
       args.ip, args.port, args.username, args.password)

    if args.discoverrepo:
        result = GetVeeamRepoDiscovery(args.ip, args.port, session_id)
    elif args.printrepo:
        result = PrintVeeamRepoData(args.ip, args.port, session_id)
    elif args.getrepo:
        result = GetVeeamRepoData(args.ip, args.port, session_id, args.host, args.server)
    elif args.discoverjob:
        result = GetVeeamJobDiscovery(args.ip, args.port, session_id)
    elif args.printjob:
        result = PrintVeeamJobData(args.ip, args.port, session_id)
    elif args.getjob:
        result = GetVeeamJobData(args.ip, args.port, session_id, args.host, args.server)


    end = EndVeeamRestSession(args.ip, args.port, session_id)
    return result

if __name__ == "__main__":
    main()