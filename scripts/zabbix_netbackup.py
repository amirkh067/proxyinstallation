#!/usr/bin/python3

import urllib3
import json
import requests
import base64
import argparse
from datetime import datetime, timedelta
from pyzabbix import ZabbixMetric, ZabbixSender

def GenerateNetbackupRestSession(netbackupIp, netbackupPort, user, password):
    headers = {'content-type': 'application/vnd.netbackup+json;version=1.0' }
    payload = {'userName' : user, 'password' : password }
    url = "https://" + netbackupIp + ":" + netbackupPort + "/netbackup/login"
    r = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
    if r.status_code != requests.codes.created:
        raise Exception("Failed authenticating to NetBackup")
    rjson = r.json()
    res = (rjson['token'])
    return res

def EndNetbackupRestSession(netbackupIp, netbackupPort, sessionId):
    url = "https://" + netbackupIp + ":" + netbackupPort + "/netbackup/logout"
    headers = {'Accept': 'application/vnd.netbackup+json;version=1.0',
               'Authorization': sessionId }
    res = requests.post(url, headers=headers, verify=False)
    return res

def GetNetbackupJobDiscovery(netbackupIp, netbackupPort, sessionId):
    startDate = (datetime.utcnow() - timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    url = "https://" + netbackupIp + ":" + netbackupPort + "/netbackup/admin/jobs"
    headers = {'Accept': 'application/vnd.netbackup+json;version=1.0',
               'Authorization': sessionId }
    query_params = {
        "sort" : "-endTime",
        "page[limit]" : 100,
        "filter" : "endTime ge " + startDate + " and state eq 'DONE' and status ge 1",
    }
    r = requests.get(url, headers=headers, params=query_params, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Netbackup failed")
    data = json.loads(r.text)
    result = []
    for d in data["data"]:
        attributes = d["attributes"]
        item = dict()
        item["{#CLIENTNAME}"] = attributes["clientName"]
        item["{#JOBID}"] = attributes["jobId"]
        item["{#POLICYNAME}"] = attributes["policyName"]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def PrintNetbackupJobData(netbackupIp, netbackupPort, sessionId):
    startDate = (datetime.utcnow() - timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    url = "https://" + netbackupIp + ":" + netbackupPort + "/netbackup/admin/jobs"
    headers = {'Accept': 'application/vnd.netbackup+json;version=1.0',
               'Authorization': sessionId }
    query_params = {
        "sort" : "-endTime",
        "page[limit]" : 100,
        "filter" : "endTime ge " + startDate + " and state eq 'DONE' and status ge 1",
    }
    r = requests.get(url, headers=headers, params=query_params, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Netbackup failed")
    data = json.loads(r.text)
    result = []
    for d in data["data"]:
        attributes = d["attributes"]
        for key, value in attributes.items():
            print("%s = %s" % (key, value))
        print("\n")
    return 0

def GetNetbackupJobData(netbackupIp, netbackupPort, sessionId, host, server):
    startDate = (datetime.utcnow() - timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    url = "https://" + netbackupIp + ":" + netbackupPort + "/netbackup/admin/jobs"
    headers = {'Accept': 'application/vnd.netbackup+json;version=1.0',
               'Authorization': sessionId }
    query_params = {
        "sort" : "-endTime",
        "page[limit]" : 100,
        "filter" : "endTime ge " + startDate + " and state eq 'DONE' and status ge 1",
    }
    r = requests.get(url, headers=headers, params=query_params, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Netbackup failed")
    data = json.loads(r.text)
    result = []
    for d in data["data"]:
        attributes = d["attributes"]
        if attributes["state"] != "DONE":
            continue
        startTime = datetime.strptime(attributes["startTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
        endTime = datetime.strptime(attributes["endTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
        duration = (endTime - startTime).total_seconds()
        key = "startTime[" + str(attributes["jobId"]) + "]"
        result.append(ZabbixMetric(host, key, startTime))
        key = "endTime[" + str(attributes["jobId"]) + "]"
        result.append(ZabbixMetric(host, key, endTime))
        key = "status[" + str(attributes["jobId"]) + "]"
        result.append(ZabbixMetric(host, key, attributes["status"]))
        key = "duration[" + str(attributes["jobId"]) + "]"
        result.append(ZabbixMetric(host, key, duration))
        key = "jobType[" + str(attributes["jobId"]) + "]"
        result.append(ZabbixMetric(host, key, attributes["jobType"]))

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
    parser.add_argument('--jobType', '-j', action="store",
                        help="JobType [Backup|BackupCopy|Replica")
    parser.add_argument('--server', '-s', action="store",
                        help="Zabbix Server", default="localhost")
    parser.add_argument('--discoverjob', '-dj', action="store_true",
                        help="Discover")
    parser.add_argument('--getjob', '-gj', action="store_true",
                        help="Statistics")
    parser.add_argument('--printjob', '-pj', action="store_true",
                        help="Print")
    args = parser.parse_args()

    urllib3.disable_warnings()

    session_id = GenerateNetbackupRestSession(
       args.ip, args.port, args.username, args.password)

    if args.discoverjob:
        result = GetNetbackupJobDiscovery(args.ip, args.port, session_id)
    elif args.printjob:
        result = PrintNetbackupJobData(args.ip, args.port, session_id)
    elif args.getjob:
        result = GetNetbackupJobData(args.ip, args.port, session_id, args.host, args.server)

    end = EndNetbackupRestSession(args.ip, args.port, session_id)
    return result



if __name__ == "__main__":
    main()



