#!/usr/bin/python3

import urllib3
import json
import requests
import base64
import argparse
from dateutil.parser import parse
from datetime import datetime , timezone
from pyzabbix import ZabbixMetric, ZabbixSender

def GenerateVeeamRestSession(veeamIp, veeamPort, user, password):
    credStr = user + ":" + password
    encodedCredStr = "Basic " + base64.b64encode(credStr.encode('ascii')).decode("utf-8")
    headers = {'Authorization': encodedCredStr}
    url = "http://" + veeamIp + ":" + veeamPort + "/api/sessionMngr/?v=v1_7"
    r = requests.post(url, headers=headers, verify=False)
    if r.status_code != requests.codes.created:
        raise Exception("Failed authenticating to Veeam")
    res = r.headers.get('X-RestSvcSessionId')
    return res

def EndVeeamRestSession(veeamIp, veeamPort, sessionId):
    url = "http://" + veeamIp + ":" + veeamPort + "/api/sessionMngr/?v=v1_7"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json'}
    res = requests.delete(url, headers=headers, verify=False)
    return res

def GetVeeamRepoDiscovery(veeamIp, veeamPort, sessionId):
    url = "http://" + veeamIp + ":" + veeamPort + "/api/repositories?format=Entity"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data["Repositories"]:
        if d["Capacity"] != -1:
            item = dict()
            item["{#NAME}"] = d["Name"]
            result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def PrintVeeamRepoData(veeamIp, veeamPort, sessionId):
    url = "http://" + veeamIp + ":" + veeamPort + "/api/repositories?format=Entity"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data["Repositories"]:
        for key, value in d.items():
            print("%s = %s" % (key, value))
        print("\n")
    return 0

def GetVeeamRepoData(veeamIp, veeamPort, sessionId, host, server):
    url = "http://" + veeamIp + ":" + veeamPort + "/api/repositories?format=Entity"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data["Repositories"]:
        if d["Capacity"] != -1:
            key = "Repository.Capacity[" + d["Name"] + "]"
            result.append(ZabbixMetric(host, key, d["Capacity"]))
            key = "Repository.FreeSpace[" + d["Name"] + "]"
            result.append(ZabbixMetric(host, key, d["FreeSpace"]))
            if d["Capacity"] > 0:
                FreeSpacePercentage = float(100 * d["FreeSpace"] / d["Capacity"])
                key = "Repository.FreeSpacePercentage[" + d["Name"] + "]"
                result.append(ZabbixMetric(host, key, FreeSpacePercentage))
    try:
        print(ZabbixSender(server).send(result))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0

def GetVeeamJobDiscovery(veeamIp, veeamPort, sessionId, jobType):
    url = "http://" + veeamIp + ":" + veeamPort + "/api/query?type=Job&filter=JobType==" + jobType + "&format=entities"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data["Entities"]["Jobs"]["Jobs"]:
        item = dict()
        item["{#NAME}"] = d["Name"]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def PrintVeeamJobData(veeamIp, veeamPort, sessionId, jobType):
    jobPrefix = "Replica" if jobType == "Replica" else "Backup"
    url = "http://" + veeamIp + ":" + veeamPort + "/api/query?type=" + jobPrefix + "JobSession&filter=JobType==" + jobType + "&sortDesc=CreationTime&pageSize=100&format=entities"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data["Entities"][jobPrefix+"JobSessions"][jobPrefix+"JobSessions"]:
        for key, value in d.items():
            print("%s = %s" % (key, value))
        print("\n")
    return 0

def GetVeeamJobData(veeamIp, veeamPort, sessionId, host, server, jobType):
    jobPrefix = "Replica" if jobType == "Replica" else "Backup"
    url = "http://" + veeamIp + ":" + veeamPort + "/api/query?type=" + jobPrefix + "JobSession&filter=JobType==" + jobType + "&sortDesc=CreationTime&pageSize=100&format=entities"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    jobs = []
    resultValue = {'None': 0, 'Success': 1 ,'Warning': 2 ,'Failed': 3 }
    for d in data["Entities"][jobPrefix+"JobSessions"][jobPrefix+"JobSessions"]:
        if not d["JobName"] in jobs:
            jobs.append(d["JobName"])
            CreationTime = parse(d["CreationTimeUTC"])
            if not "EndTimeUTC" in d:
                if d["State"] == "Working":
                    EndTime = datetime.now(timezone.utc)
                else:
                    EndTime = CreationTime
            else:
                EndTime = parse(d["EndTimeUTC"])
            Duration = (EndTime - CreationTime).total_seconds()
            key = jobType + ".CreateTime[" + d["JobName"] + "]"
            result.append(ZabbixMetric(host, key, CreationTime))
            key = jobType + ".EndTime[" + d["JobName"] + "]"
            result.append(ZabbixMetric(host, key, EndTime))
            key = jobType + ".State[" + d["JobName"] + "]"
            result.append(ZabbixMetric(host, key, d["State"]))
            key = jobType + ".Result[" + d["JobName"] + "]"
            result.append(ZabbixMetric(host, key, resultValue[d["Result"]]))
            key = jobType + ".Progress[" + d["JobName"] + "]"
            result.append(ZabbixMetric(host, key, d["Progress"]))
            key = jobType + ".Duration[" + d["JobName"] + "]"
            result.append(ZabbixMetric(host, key, Duration))
    try:
        print(ZabbixSender(server).send(result))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0
    
def GetVeeamRestoreDiscovery(veeamIp, veeamPort, sessionId):
    url = "http://" + veeamIp + ":" + veeamPort + "/api/restoreSessions?format=Entity"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data["RestoreSessions"]:
        item = dict()
        item["{#NAME}"] = d["VmDisplayName"]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def PrintVeeamRestoreData(veeamIp, veeamPort, sessionId):
    url = "http://" + veeamIp + ":" + veeamPort + "/api/restoreSessions?format=Entity"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    for d in data["RestoreSessions"]:
        for key, value in d.items():
            print("%s = %s" % (key, value))
        print("\n")
    return 0

def GetVeeamRestoreData(veeamIp, veeamPort, sessionId, host, server):
    url = "http://" + veeamIp + ":" + veeamPort + "/api/restoreSessions?format=Entity"
    headers = {'X-RestSvcSessionId': sessionId,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Veeam failed")
    data = json.loads(r.text)
    result = []
    jobs = []
    resultValue = {'None': 0, 'Success': 1 ,'Warning': 2 ,'Failed': 3 }
    for d in data["RestoreSessions"]:
        if not d["VmDisplayName"] in jobs:
            jobs.append(d["VmDisplayName"])
            CreationTime = parse(d["CreationTimeUTC"])
            if not "EndTimeUTC" in d:
                if d["State"] == "Working":
                    EndTime = datetime.now(timezone.utc)
                else:
                    EndTime = CreationTime
            else:
                EndTime = parse(d["EndTimeUTC"])
            Duration = (EndTime - CreationTime).total_seconds()
            key = "Restore.CreateTime[" + d["VmDisplayName"] + "]"
            result.append(ZabbixMetric(host, key, CreationTime))
            key = "Restore.EndTime[" + d["VmDisplayName"] + "]"
            result.append(ZabbixMetric(host, key, EndTime))
            key = "Restore.State[" + d["VmDisplayName"] + "]"
            result.append(ZabbixMetric(host, key, d["State"]))
            key = "Restore.Result[" + d["VmDisplayName"] + "]"
            result.append(ZabbixMetric(host, key, resultValue[d["Result"]]))
            key = "Restore.Progress[" + d["VmDisplayName"] + "]"
            result.append(ZabbixMetric(host, key, d["Progress"]))
            key = "Restore.Duration[" + d["VmDisplayName"] + "]"
            result.append(ZabbixMetric(host, key, Duration))
    try:
        print(ZabbixSender(server).send(result))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0

###

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
    parser.add_argument('--jobType', '-j', action="store",
                        help="JobType [Backup|BackupCopy|Replica")
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
    parser.add_argument('--discoverrestore', '-drs', action="store_true",
                        help="Discover")
    parser.add_argument('--getrestore', '-grs', action="store_true",
                        help="Statistics")
    parser.add_argument('--printrestore', '-prs', action="store_true",
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
        result = GetVeeamJobDiscovery(args.ip, args.port, session_id, args.jobType)
    elif args.printjob:
        result = PrintVeeamJobData(args.ip, args.port, session_id, args.jobType)
    elif args.getjob:
        result = GetVeeamJobData(args.ip, args.port, session_id, args.host, args.server, args.jobType)
    elif args.discoverrestore:
        result = GetVeeamRestoreDiscovery(args.ip, args.port, session_id)
    elif args.printrestore:
        result = PrintVeeamRestoreData(args.ip, args.port, session_id)
    elif args.getrestore:
        result = GetVeeamRestoreData(args.ip, args.port, session_id, args.host, args.server)


    end = EndVeeamRestSession(args.ip, args.port, session_id)
    return result

if __name__ == "__main__":
    main()
