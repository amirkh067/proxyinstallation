#!/usr/bin/python3

import urllib3
import json
import requests
import base64
import argparse
from dateutil.parser import parse
from datetime import datetime , timezone
from pyzabbix import ZabbixMetric, ZabbixSender


def GenerateAuth(soIP, user, password):
    credStr = user + ":" + password
    encodedCredStr = "Basic " + base64.b64encode(credStr.encode('ascii')).decode("utf-8")
    return encodedCredStr

def DiscoverStatus(soIP, encodedCredStr):
    url = "http://" + soIP + "/storeonceservices/cluster/"
    headers = {'Authorization': encodedCredStr,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to SO Api failed")
    data = json.loads(r.text)
    result = []
    for d in data["cluster"]["properties"]:
        item = dict()
        item["{#NAME}" ] = d["applianceName"]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def PrintStatus(soIP, encodedCredStr):
    url = "http://" + soIP + "/storeonceservices/cluster/"
    headers = {'Authorization': encodedCredStr,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to SO Api failed")
    data = json.loads(r.text)
    result = []
    for d in data["cluster"]["properties"]:
        item = dict()
        fields = (dict.keys(d))
        for value_field in fields:
            if value_field in fields:
                item["%s" % value_field] = d[value_field]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def GetStatus(soIP, encodedCredStr, host, server):
    url = "http://" + soIP + "/storeonceservices/cluster/"
    headers = {'Authorization': encodedCredStr,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to SO Api failed")
    data = json.loads(r.text)
    result = []

    for d in data["cluster"]["properties"]:
        key = "HealthLevel[" + d["applianceName"] + "]"
        result.append(ZabbixMetric(host, key, d["healthLevel"]))
        key = "Status[" + d["applianceName"] + "]"
        result.append(ZabbixMetric(host, key, d["status"]))

        if "capacity" in d:

            key = "TotalCapacity[" + d["applianceName"] + "]"
            result.append(ZabbixMetric(host, key, ('%.4f' % float(d["capacity"]))))
            key = "FreeSpace[" + d["applianceName"] + "]"
            result.append(ZabbixMetric(host, key, ('%.4f' % float(d["freeSpace"]))))
            key = "UsedSpace[" + d["applianceName"] + "]"
            result.append(ZabbixMetric(host, key, ('%.4f' % float(d["sizeOnDisk"]))))
            key = "UsedDataWritten[" + d["applianceName"] + "]"
            result.append(ZabbixMetric(host, key, ('%.4f' % float(d["userDataStored"]))))

            if float(d["capacity"]) > 0:
                FreeSpacePercentage = float(100 * float(d["freeSpace"]) / float(d["capacity"]))
                key = "FreeSpacePercentage[" + d["applianceName"] + "]"
                result.append(ZabbixMetric(host, key, FreeSpacePercentage))

        else:

            key = "TotalCapacity[" + d["applianceName"] + "]"
            result.append(ZabbixMetric(host, key, ( d["combinedCapacityBytes"])))
            key = "FreeSpace[" + d["applianceName"] + "]"
            result.append(ZabbixMetric(host, key, ( d["combinedFreeBytes"])))
            key = "UsedSpace[" + d["applianceName"] + "]"
            result.append(ZabbixMetric(host, key, ( d["combinedDiskBytes"])))
            key = "UsedDataWritten[" + d["applianceName"] + "]"
            result.append(ZabbixMetric(host, key, ( d["combinedUserBytes"])))

            if float(d["combinedCapacityBytes"]) > 0:
                FreeSpacePercentage = float(100 * float(d["combinedFreeBytes"]) / float(d["combinedCapacityBytes"]))
                key = "FreeSpacePercentage[" + d["applianceName"] + "]"
                result.append(ZabbixMetric(host, key, FreeSpacePercentage))
    try:
        print(ZabbixSender(server).send(result))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0


###

def DiscoverServiceStatus(soIP, encodedCredStr):
    url = "http://" + soIP + "/storeonceservices/cluster/servicesets/1"
    headers = {'Authorization': encodedCredStr,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to SO Api failed")
    data = json.loads(r.text)
    result = []
    for d in data["servicesets"]["serviceset"]["services"]:
        item = dict()
        item["{#NAME}" ] = d["id"]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def PrintServiceStatus(soIP, encodedCredStr):
    url = "http://" + soIP + "/storeonceservices/cluster/servicesets/1/"
    headers = {'Authorization': encodedCredStr,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to SO Api failed")
    data = json.loads(r.text)
    result = []
    for d in data["servicesets"]["serviceset"]["services"]:
        item = dict()
        fields = (dict.keys(d))
        for value_field in fields:
            if value_field in fields:
                item["%s" % value_field] = d[value_field]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0

def GetServiceStatus(soIP, encodedCredStr, host, server):
    url = "http://" + soIP + "/storeonceservices/cluster/servicesets/1/"
    headers = {'Authorization': encodedCredStr,
               'content-type': 'application/json',
               'Accept': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to SO Api failed")
    data = json.loads(r.text)
    result = []

    for d in data["servicesets"]["serviceset"]["services"]:
        key = "summaryHealthLevel[" + d["id"] + "]"
        result.append(ZabbixMetric(host, key, d["summaryHealthLevel"]))
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
    parser.add_argument('--username', '-u', action="store",
                        help="Username", required=True)
    parser.add_argument('--password', '-p', action="store",
                        help="Password", required=True)
    parser.add_argument('--value_fields', '-v', action="store",
                        help="Value fields for status")
    parser.add_argument('--server', '-s', action="store",
                        help="Zabbix Server", default="localhost")
    parser.add_argument('--discoverstatus', '-ds', action="store_true",
                        help="Discover")
    parser.add_argument('--getstatus', '-gs', action="store_true",
                        help="Statistics")
    parser.add_argument('--printstatus', '-ps', action="store_true",
                        help="Print")
    parser.add_argument('--discoverservicestatus', '-dss', action="store_true",
                        help="Discover")
    parser.add_argument('--getservicestatus', '-gss', action="store_true",
                        help="Statistics")
    parser.add_argument('--printservicestatus', '-pss', action="store_true",
                        help="Print")

    args = parser.parse_args()

    urllib3.disable_warnings()

    encodedCredStr = GenerateAuth(args.ip, args.username, args.password)

    if args.discoverstatus:
        result = DiscoverStatus(args.ip, encodedCredStr)
    elif args.printstatus:
        result = PrintStatus(args.ip, encodedCredStr)
    elif args.getstatus:
        result = GetStatus(args.ip, encodedCredStr, args.host, args.server)
    elif args.discoverservicestatus:
        result = DiscoverServiceStatus(args.ip, encodedCredStr)
    elif args.printservicestatus:
        result = PrintServiceStatus(args.ip, encodedCredStr)
    elif args.getservicestatus:
        result = GetServiceStatus(args.ip, encodedCredStr, args.host, args.server)
    return result

if __name__ == "__main__":
    main()
