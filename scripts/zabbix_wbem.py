#!/usr/bin/python3

import os
from datetime import datetime
import json
import pywbem
import argparse
from pyzabbix import ZabbixMetric, ZabbixSender


def wbem_connect(protocol, ip, port, username, password, namespace):
    url = "%s://%s:%s" % (protocol, ip, port)
    return pywbem.WBEMConnection(url, (username, password),
                                 default_namespace=namespace,
                                 no_verification=True)

def wbem_get_value(row, value_field):
    if value_field not in row.properties:
        return 'not_found'
    value = row.properties[value_field].value
    if isinstance(value, list) and value:
        value = value[0]
    elif isinstance(value, bool):  # zabbix cannot recognize boolean
        value = "true" if value else "false"
    return value

def wbem_print(connection, class_name, value_fields):
    rows = connection.EnumerateInstances(class_name)
    for row in rows:
        if value_fields == '*':
            for property_name in row.properties:
                print("%s = %s" %
                      (property_name, wbem_get_value(row, property_name)))
        else:
            for value_field in value_fields.split(","):
                print("%s = %s" %
                      (value_field, wbem_get_value(row, value_field)))
        print("\n")
    return 0


def wbem_discovery(connection, class_name, value_fields):
    result = []
    rows = connection.EnumerateInstances(class_name)
    for row in rows:
        item = dict()
        for value_field in value_fields.split(","):
            item["{#%s}" % value_field.upper()] = \
                wbem_get_value(row, value_field)
        result.append(item)
    print(json.dumps({"data": result}, indent=4, separators=(',', ': ')))
    return 0


def wbem_status(connection, class_name, key_field, value_fields, host, server):
    packet = []
    rows = connection.EnumerateInstances(class_name)
    for row in rows:
        device_id = wbem_get_value(row, key_field)
        for value_field in value_fields.split(","):
            if value_field in row.properties:
                key = "%s.%s[%s]" % (class_name, value_field, device_id)
                value = wbem_get_value(row, value_field)
                if value != 'not_found':
                    packet.append(ZabbixMetric(host, key, value))
    try:
        print(ZabbixSender(server).send(packet))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0


def wbem_statistics(connection, class_name, key_field, time_field,
                    element_type_field, value_fields, host, server):
    stats_data = {}
    packet = []
    last_file = "/tmp/%s_%s.tmp" % (host, class_name)
    time_key = "%s.%s" % (class_name, time_field)
    rows = connection.EnumerateInstances(class_name)
    for row in rows:
        data = {}
        device_id = wbem_get_value(row, key_field)
        value = wbem_get_value(row, time_field)
        data[time_key] = str(value)[:14]
        for value_field in value_fields.split(","):
            type = wbem_get_value(row, element_type_field)
            key = "%s.%s.%s" % (class_name, value_field, type)
            value = wbem_get_value(row, value_field)
            if value and value != 'not_found':
                data[key] = value
        stats_data[device_id] = data
    if os.path.isfile(last_file):
        try:
            with open(last_file) as f:
                last_stats_data = json.loads(f.readline())
                for device_id in stats_data:
                    if device_id in last_stats_data:
                        data = stats_data[device_id]
                        last_data = last_stats_data[device_id]
                        if time_key in data.keys():
                            begin = datetime.strptime(
                                last_data[time_key], "%Y%m%d%H%M%S")
                            end = datetime.strptime(
                                data[time_key], "%Y%m%d%H%M%S")
                            delta = (end - begin).total_seconds()
                            if delta > 0:
                                for key in data:
                                    if key != time_key and key in last_data:
                                        diff = data[key] - last_data[key]
                                        value = int(diff / delta)
                                        full_key = key + '[' + device_id + ']'
                                        packet.append(ZabbixMetric(
                                            host, full_key, value))
            print(ZabbixSender(server).send(packet))
        except ConnectionRefusedError as error:
            print('Cannot Send Metrics! - ' + str(error))
            exit(1)
        except json.decoder.JSONDecodeError as error:
            print('Cannot Decode File! - ' + str(error))
            os.remove(last_file)
            exit(1)
    with open(last_file, "w") as f:
        f.write(json.dumps(stats_data))
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--protocol', '-x', action="store",
                        help="Protocol [http|https]", default="https")
    parser.add_argument('--host', '-z', action="store",
                        help="Hostname", required=True)
    parser.add_argument('--ip', '-i', action="store",
                        help="IP Address", required=True)
    parser.add_argument('--port', '-y', action="store",
                        help="Port Number", default="5989")
    parser.add_argument('--username', '-u', action="store",
                        help="Username", required=True)
    parser.add_argument('--password', '-p', action="store",
                        help="Password", required=True)
    parser.add_argument('--namespace', '-n', action="store",
                        help="Namespace", required=True)
    parser.add_argument('--classname', '-c', action="store",
                        help="Class", required=True)
    parser.add_argument('--time_field', '-t', action="store",
                        help="Time Field Name", default="StatisticTime")
    parser.add_argument('--element_type_field', '-e', action="store",
                        help="Element Type Field Name", default="ElementType")
    parser.add_argument('--key_field', '-k', action="store",
                        help="Key Field Name (Device)", default="ElementName")
    parser.add_argument('--value_fields', '-v', action="store",
                        help="Comma Seperated Values", required=True)
    parser.add_argument('--server', '-s', action="store",
                        help="Zabbix Server", default="localhost")
    parser.add_argument('--discovery', '-D', action="store_true",
                        help="Discover")
    parser.add_argument('--status', '-S', action="store_true",
                        help="Status")
    parser.add_argument('--statistics', '-T', action="store_true",
                        help="Statistics")
    parser.add_argument('--print', '-P', action="store_true",
                        help="Print")
    args = parser.parse_args()
    conn = wbem_connect(args.protocol, args.ip, args.port,
                              args.username, args.password, args.namespace)
    if args.print:
        result = wbem_print(conn, args.classname, args.value_fields)
    elif args.discovery:
        result = wbem_discovery(conn, args.classname, args.value_fields)
    elif args.status:
        result = wbem_status(conn, args.classname, args.key_field,
                             args.value_fields, args.host, args.server)
    elif args.statistics:
        result = wbem_statistics(conn, args.classname, args.key_field,
                                 args.time_field, args.element_type_field,
                                 args.value_fields, args.host, args.server)
    return result


if __name__ == "__main__":
    main()

