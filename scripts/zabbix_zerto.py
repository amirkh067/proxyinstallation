#!/usr/bin/python3

import urllib3
import json
import requests
import base64
import argparse
from pyzabbix import ZabbixMetric, ZabbixSender

def GenerateZertoRestSession_VcenterAuthentication(zvmIp, user, password):
    credStr = user + ":" + password
    encodedCredStr = "Basic " + base64.b64encode(credStr.encode('ascii')).decode("utf-8")
    payload = {"AuthenticationMethod": 1}
    dataval = json.dumps(payload)
    headers = {'Authorization': encodedCredStr, 'content-type': 'application/json'}
    url = "https://" + zvmIp + ":9669/v1/session/add"
    r = requests.post(url, data=dataval, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Failed authenticating to ZVM")
    res = r.headers.get('x-zerto-session')
    return res


def GenerateZertoRestSession_WindowsAuthentication(zvmIp, user, password):
    credStr = user + ":" + password
    encodedCredStr = "Basic " + base64.b64encode(credStr.encode('ascii')).decode("utf-8")
    headers = {'Authorization': encodedCredStr}
    url = "https://" + zvmIp + ":9669/v1/session/add"
    r = requests.post(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Failed authenticating to ZVM")
    res = r.headers.get('x-zerto-session')
    return res


def EndZertoRestSession(zvmIp, sessionId):
    url = "https://" + zvmIp + ":9669/v1/session"
    headers = {'x-zerto-session': sessionId,
               'content-type': 'application/json'}
    res = requests.delete(url, headers=headers, verify=False)
    return res


def GetZertoVPGDiscovery(zvmIp, sessionId):
    url = "https://" + zvmIp + ":9669/v1/vpgs"
    headers = {'x-zerto-session': sessionId,
               'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to ZVM failed")
    vpgData = json.loads(r.text)
    result = []
    for vpg in vpgData:
        item = dict()
        item["{#%s}" % "VpgIdentifier".upper()] = vpg["VpgIdentifier"]
        item["{#%s}" % "VpgName".upper()] = vpg["VpgName"]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0


def PrintZertoVPGData(zvmIp, sessionId, value_fields):
    url = "https://" + zvmIp + ":9669/v1/vpgs"
    headers = {'x-zerto-session': sessionId,
               'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to ZVM failed")
    vpgData = json.loads(r.text)
    for vpg in vpgData:
        for value_field in value_fields.split(","):
            print("%s = %s" % (value_field, vpg[value_field]))
        print("\n")
    return 0


def GetZertoVPGData(zvmIp, sessionId, value_fields, host, server):
    url = "https://" + zvmIp + ":9669/v1/vpgs"
    headers = {'x-zerto-session': sessionId,
               'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to ZVM failed")
    vpgData = json.loads(r.text)
    packet = []
    for vpg in vpgData:
        for value_field in value_fields.split(","):
            key = "%s[%s]" % (value_field, vpg["VpgIdentifier"])
            packet.append(ZabbixMetric(host, key, vpg[value_field]))
    try:
        print(ZabbixSender(server).send(packet))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0

def GetZertoAlertsDiscovery(zvmIp, sessionId):
    url = "https://" + zvmIp + ":9669/v1/alerts"
    headers = {'x-zerto-session': sessionId,
               'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to ZVM failed")
    alertData = json.loads(r.text)
    result = []
    for alert in alertData:
        item = dict()
        item["{#%s}" % "HelpIdentifier".upper()] = alert["HelpIdentifier"]
        item["{#%s}" % "Description".upper()] = alert["Description"][:200]
        item["{#%s}" % "Level".upper()] = alert["Level"]
        item["{#%s}" % "ID".upper()] = alert["Link"]["identifier"]
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0


def PrintZertoAlertsData(zvmIp, sessionId, value_fields):
    url = "https://" + zvmIp + ":9669/v1/alerts"
    headers = {'x-zerto-session': sessionId,
               'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to ZVM failed")
    alertData = json.loads(r.text)
    for alert in alertData:
        for value_field in value_fields.split(","):
            print("%s = %s" % (value_field, alert[value_field]))
        print("\n")
    return 0


def GetZertoAlertsData(zvmIp, sessionId, value_fields, host, server):
    url = "https://" + zvmIp + ":9669/v1/alerts"
    headers = {'x-zerto-session': sessionId,
               'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    if r.status_code != requests.codes.ok:
        raise Exception("Call to ZVM failed")
    alertData = json.loads(r.text)
    packet = []
    for alert in alertData:
        for value_field in value_fields.split(","):
            key = "%s[%s]" % (value_field, alert["Link"]["identifier"])
            packet.append(ZabbixMetric(host, key, alert[value_field]))
    try:
        print(ZabbixSender(server).send(packet))
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
    parser.add_argument('--username', '-u', action="store",
                        help="Username", required=True)
    parser.add_argument('--password', '-p', action="store",
                        help="Password", required=True)
    parser.add_argument('--authtype', '-a', action="store",
                        help="Authorization Type [vcenter|windows]",
                        default="vcenter")
    parser.add_argument('--value_fields', '-v', action="store",
                        help="Comma Seperated Values")
    parser.add_argument('--server', '-s', action="store",
                        help="Zabbix Server", default="localhost")
    parser.add_argument('--discovery', '-D', action="store_true",
                        help="Discover")
    parser.add_argument('--statistics', '-S', action="store_true",
                        help="Statistics")
    parser.add_argument('--print', '-P', action="store_true",
                        help="Print")
    parser.add_argument('--discoveryalerts', '-DA', action="store_true",
                        help="Discover")
    parser.add_argument('--statisticsalerts', '-SA', action="store_true",
                        help="Statistics")
    parser.add_argument('--printalerts', '-PA', action="store_true",
                        help="Print")
    args = parser.parse_args()

    urllib3.disable_warnings()

    if args.authtype == "vcenter":
        session_id = GenerateZertoRestSession_VcenterAuthentication(
            args.ip, args.username, args.password)
    else:
        session_id = GenerateZertoRestSession_WindowsAuthentication(
            args.ip, args.username, args.password)

    if args.discovery:
        result = GetZertoVPGDiscovery(args.ip, session_id)

    elif args.statistics:
        result = GetZertoVPGData(args.ip, session_id, args.value_fields,
                                 args.host, args.server)
    elif args.print:
        result = PrintZertoVPGData(args.ip, session_id, args.value_fields)

    elif args.discoveryalerts:
        result = GetZertoAlertsDiscovery(args.ip, session_id)

    elif args.statisticsalerts:
        result = GetZertoAlertsData(args.ip, session_id, args.value_fields,
                                 args.host, args.server)
    elif args.printalerts:
        result = PrintZertoAlertsData(args.ip, session_id, args.value_fields)

    end = EndZertoRestSession(args.ip, session_id)

    return result

if __name__ == "__main__":
    main()


