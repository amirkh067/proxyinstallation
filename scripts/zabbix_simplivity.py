#!/usr/bin/python3

import urllib3
import json
import requests
import base64
import argparse
import time
from dateutil.parser import parse
from datetime import datetime , timezone
from pyzabbix import ZabbixMetric, ZabbixSender

def GenerateSimplivitySession(host,user, password): 
    url = "https://simplivity@" + host + "/api/oauth/token"
    
    r = requests.post(url, verify=False, auth=('simplivity', ''), data={
        'grant_type': 'password',
        'username': user,
        'password': password})
    if r.status_code != requests.codes.ok:
        raise Exception("Failed authenticating to Simplivity REST API")
    res = r.json()['access_token']
    return res

def DiscoverySimplivityCluster(host, access_token, hosttype):
    url = "https://" + host + ":" + "/api/" + hosttype
    headers = {'Authorization':  'Bearer ' + access_token,
     'Accept' : 'application/vnd.simplivity.v1+json'}

    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Simplivity REST API failed")
    data = json.loads(r.text)
    result = []

    for d in data[hosttype]:
        if d["id"] != -1:
            item = dict()
            item["{#NAME}"] = d["name"]
            item["{#ID}"] = d["id"]
            result.append(item)
        else:
            result = "No data found"
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def GetSimplivityOmniData(host, access_token, hosttype, server, id):
    url = "https://" + host + ":" + "/api/" + hosttype + "/" + id
    headers = {'Authorization':  'Bearer ' + access_token,
     'Accept' : 'application/vnd.simplivity.v1+json'}

    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Simplivity REST API failed")
    data = json.loads(r.text)
    result = []

    if data["omnistack_cluster"]:
     d = data["omnistack_cluster"]

     key = "FreeSpace[" + id + "]"
     result.append(ZabbixMetric(host, key, d["free_space"]))
     key = "UsedSpace[" + id + "]"
     result.append(ZabbixMetric(host, key, d["used_capacity"]))
     key = "PhysicalSpace[" + id + "]"
     result.append(ZabbixMetric(host, key, d["allocated_capacity"]))
     key = "SpaceSaved[" + id + "]"
     result.append(ZabbixMetric(host, key,d["capacity_savings"]))
     key = "CompressionRatio[" + id + "]"
     result.append(ZabbixMetric(host, key, d["compression_ratio"]))
     key = "DeduplicationRatio[" + id + "]"
     result.append(ZabbixMetric(host, key, d["deduplication_ratio"]))

    else:
        result = "No data found"

    try:
        print(ZabbixSender(server).send(result))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0

def GetSimplivityMetricData(host, access_token, hosttype, server, id):
    url = "https://" + host + ":" + "/api/" + hosttype + "/" + id + "/metrics?range=60&resolution=SECOND"
    headers = {'Authorization':  'Bearer ' + access_token,
     'Accept' : 'application/vnd.simplivity.v1+json'}

    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Simplivity REST API failed")
    data = json.loads(r.text)
    result = []

    for d in data.items():
        if d[1]:
            for metrics in d[1]:
                for value in metrics['data_points']:
                    date = time.mktime(datetime.strptime(value['date'], '%Y-%m-%dT%H:%M:%SZ').timetuple())
                    key = metrics['name'] + ".Read[" + id + "]"
                    result.append(ZabbixMetric(host, key, value['reads'], date))
                    key = metrics['name'] + ".Write[" + id + "]"
                    result.append(ZabbixMetric(host, key, value['writes'], date))

        else:
            result = "No data found" 
    try:
        print(ZabbixSender(server).send(result))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0

def PrintSimplivityData(host, access_token, hosttype, id):
    url = "https://" + host + ":" + "/api/" + hosttype + "/" + id
    headers = {'Authorization':  'Bearer ' + access_token,
     'Accept' : 'application/vnd.simplivity.v1+json'}

    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Simplivity REST API failed")
    data = json.loads(r.text)
    result = []
    print(json.dumps({"data": data}, indent=4, separators=(',', ': ')))

    return 0

def PrintSimplivityMetricData(host, access_token, hosttype, id):
    url = "https://" + host + ":" + "/api/" + hosttype + "/" + id + "/metrics?range=60&resolution=SECOND"
    headers = {'Authorization':  'Bearer ' + access_token,
     'Accept' : 'application/vnd.simplivity.v1+json'}

    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to Simplivity REST API failed")
    data = json.loads(r.text)
    result = []
    print(json.dumps({"data": data}, indent=4, separators=(',', ': ')))

    return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', '-z', action="store",
                        help="Hostname", required=True)
    parser.add_argument('--username', '-u', action="store",
                        help="Username", required=True)
    parser.add_argument('--password', '-p', action="store",
                        help="Password", required=True)
    parser.add_argument('--hosttype', '-t', action="store",
                        help="Host Type [omnistack_clusters|hosts|virtual_machines")
    parser.add_argument('--id', '-i', action="store",
                        help="Host Id  [omnistack_clusters|hosts|virtual_machines")                    
    parser.add_argument('--server', '-s', action="store",
                        help="Zabbix Server", default="localhost")
    parser.add_argument('--discover', '-D', action="store_true",
                        help="Discover")
    parser.add_argument('--get', '-G', action="store_true",
                        help="General Data")
    parser.add_argument('--getMetric', '-GM', action="store_true",
                        help="Metrics")
    parser.add_argument('--print', '-P', action="store_true",
                        help="Print")
    parser.add_argument('--printMetric', '-PM', action="store_true",
                        help="Print Metric")
    args = parser.parse_args()

    urllib3.disable_warnings()

    access_token = GenerateSimplivitySession(
       args.host, args.username, args.password)

    if args.discover:
        result = DiscoverySimplivityCluster(args.host, access_token,args.hosttype)
    elif args.print:
        result = PrintSimplivityData(args.host, access_token,args.hosttype, args.id)
    elif args.printMetric:
        result = PrintSimplivityMetricData(args.host, access_token,args.hosttype, args.id)
    elif args.get:
        result = GetSimplivityOmniData(args.host, access_token, args.hosttype, args.server, args.id)
    elif args.getMetric:
        result = GetSimplivityMetricData(args.host, access_token, args.hosttype, args.server, args.id)

    return result

if __name__ == "__main__":
    main()
