#!/usr/bin/python3
import json
import argparse
import atexit
from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyzabbix import ZabbixMetric, ZabbixSender


def vmware_connect(ip, port, username, password):
    si = SmartConnectNoSSL(host=ip,
                           user=username,
                           pwd=password,
                           port=port)
    atexit.register(Disconnect, si)
    return si


def vmware_discovery(si, alerts, warnings):
    result = []
    i = 1
    if si.content.searchIndex:
        alarms = si.content.rootFolder.triggeredAlarmState
        for alarm in alarms:
            item = dict()
            item["{#ALARMID}"] = alarm.key
            item["{#ALARMNAME}"] = alarm.alarm.info.name
            item["{#ALARMDESC}"] = alarm.alarm.info.description
            item["{#ENTITY}"] = alarm.entity.name
            if(alerts and str(alarm.overallStatus) == 'red') or \
                    (warnings and str(alarm.overallStatus) == 'yellow'):
                result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0


def wmware_alarms(si, host, server):
    packet = []
    if si.content.searchIndex:
        alarms = si.content.rootFolder.triggeredAlarmState
        for alarm in alarms:
            if str(alarm.overallStatus) == 'red':
                key = "Alert[%s]" % alarm.key
            else:
                key = "Warning[%s]" % alarm.key
            packet.append(ZabbixMetric(host, key, 1))
    try:
        print(ZabbixSender(server).send(packet))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0

def wmware_alarm_print(si):
    if si.content.searchIndex:
        alarms = si.content.rootFolder.triggeredAlarmState
        for alarm in alarms:
            print("ALARMID: " + alarm.key)
            print("ALARMNAME: " + alarm.alarm.info.name)
            print("ALARMDESC: " + alarm.alarm.info.description)
            print("ENTITY: " + alarm.entity.name)
            print("STATUS: " + alarm.overallStatus +"\n")
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
    parser.add_argument('--port', '-x', action="store",
                        help="Port", default=443)
    parser.add_argument('--server', '-s', action="store",
                        help="Zabbix Server", default="localhost")
    parser.add_argument('--alert', '-a', action="store_true",
                        help="Alert")
    parser.add_argument('--warning', '-w', action="store_true",
                        help="Warning")
    parser.add_argument('--discovery', '-D', action="store_true",
                        help="Discover")
    parser.add_argument('--alarms', '-A', action="store_true",
                        help="Get Alarms")
    parser.add_argument('--print', '-P', action="store_true",
                        help="Print")
    args = parser.parse_args()

    si = vmware_connect(args.ip, args.port, args.username, args.password)

    if args.discovery:
        result = vmware_discovery(si, args.alert, args.warning)
    elif args.alarms:
        result = wmware_alarms(si, args.host, args.server)
    elif args.print:
        result = wmware_alarm_print(si)

    return result


if __name__ == "__main__":
    main()

