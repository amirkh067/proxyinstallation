#!/usr/bin/env python
#
# zbxwmi : discovery and bulk checks of WMI items with Zabbix
# Requires impacket (python pkg) 
# version 0.1
#
# Author:
#  Vitaly Chekryzhev (13hakta@gmail.com)

import argparse, sys, os
from pyzabbix import ZabbixMetric, ZabbixSender

import socket
from contextlib import closing

def main():
    parser = argparse.ArgumentParser(add_help = True, description = "Zabbix WMI connector v0.1")
    parser.add_argument('cls', action='store', help='<WMI Class>')
    parser.add_argument('username', action='store', help='<username>')
    parser.add_argument('password', action='store', help='<password>')
    parser.add_argument('domain', action='store', help='<domain>')
    parser.add_argument('target', action='store', help='<target host or ip>')
    parser.add_argument('hostname', action='store', help='<hostname>')

    parser.add_argument('-action', action='store', default='get', help='The action to take. Possible values : get, bulk, json, discover, both')
    parser.add_argument('-namespace', action='store', default='//./root/cimv2', help='namespace name (default //./root/cimv2)')

    parser.add_argument('-key', action='store', help='Key')
    parser.add_argument('-fields', action='store', help='Field list delimited by comma')
    parser.add_argument('-filter', action='store', default='', help='Filter')
    parser.add_argument('-item', action='store', default='', help='Selected item')

    parser.add_argument('-server', action='store', default='127.0.0.1', help='Zabbix server')

    group = parser.add_argument_group('authentication')

    group.add_argument('-dc-ip', action='store',metavar = "ip address",    help='IP Address of the domain controller. If '
                                         'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-rpc-auth-level', choices=['integrity', 'privacy','default'], nargs='?', default='default',
                                         help='default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy '
                                                    '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM path "root/MSCluster" would require '
                                                    'privacy level by default)')

    if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

    options = parser.parse_args()

    # Extract the arguments
    emulatekey = False

    if options.key:
        key = options.key
    else:
        key = 'Name'
        emulatekey = True

    if (options.action == 'get' and options.fields and len(options.fields.split(',')) != 1):
        print "action 'get' requires only one item"
        exit(1)

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((options.target, 135)) != 0:
            exit(1)

    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_NONE

    try:
        dcom = DCOMConnection(options.target, options.username, options.password, options.domain, '', '', '', oxidResolver=True,
                                                    doKerberos=False, kdcHost=options.dc_ip)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin(options.namespace, NULL, NULL)
        if options.rpc_auth_level == 'privacy':
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        elif options.rpc_auth_level == 'integrity':
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

        iWbemLevel1Login.RemRelease()

        # Construct the query
        query = "SELECT "

        if options.fields is None:
            options.fields = key
            query += key
        else:
            query += key + ',' + options.fields

        query += " FROM " + options.cls

        # Conditional request
        if options.filter or options.item:
            query += " WHERE "
            wheres = []

            if options.filter:
                wheres.append(options.filter)

            if options.item:
                wheres.append(key + '="' + options.item + '"')

            query += ' AND '.join(wheres)

        response = []

        try:
            iEnum = iWbemServices.ExecQuery(query)

            while True:
                try:
                    pEnum = iEnum.Next(0xffffffff, 1)[0]
                    record = pEnum.getProperties()

                    j = {}

                    for k in record:
                        if type(record[k]['value']) is list:
                            j[k] = []
                            for item in record[k]['value']:
                                j[k].append(item)
                        else:
                            j[k] = record[k]['value']
                    response.append(j) # the response output
                except Exception as e:
                    if str(e).find('S_FALSE') < 0:
                        raise
                    else:
                        break

            iEnum.RemRelease()
        except Exception as e:
            print "An error occured: " + str(e)

        iWbemServices.RemRelease()
        dcom.disconnect()

        # What to do with the results ?
        if options.action == 'get':
            print str(response[0][options.fields])
        elif options.action == 'bulk':
            send2zabbix(response, key, options.hostname, options.server)
        elif options.action == 'json':
            send2zabbix_json(response)
        elif options.action == 'discover':
            discovery_json(response)
        elif options.action == 'both': # Discover + bulk
            send2zabbix(response, key, options.hostname, options.server)
            discovery_json(response)
        else:
            print "Invalid action."
            exit(1)
    except Exception as e:
        print "An error occured : " + str(e)
        exit(1)
        try:
            dcom.disconnect()
        except:
            pass
        exit(1)

def discovery_json(data):

    """
    Display a JSON-formatted index for Zabbix LLD discovery

    """

    output = []

    for eachItem in data:
        res = []
        for k in eachItem:
            key = '{#WMI.' + k.upper() + '}'
            res.append('"' + key + '": "' + str(eachItem[k]) + '"')
        output.append('{' + ', '.join(res) + '}')

    print '{ "data": [', ', '.join(output), '] }'

def send2zabbix_json(data):

    """
    Display a JSON-formatted index for Zabbix bulk

    """

    output = []

    for eachItem in data:
        res = []
        for k in eachItem:
            res.append('"' + k + '": "' + str(eachItem[k]).replace("\\", r"\\") + '"')
        output.append('{' + ', '.join(res) + '}')

    print "[" + ','.join(output) + "]"


def send2zabbix(data, key, host, server):

    """
    Bulk inserts data into Zabbix

    """

    packet = []
    #output = ""
    for eachItem in data:
        val = "[" + str(eachItem.pop(key)) + "]"
        for k in eachItem:
            #output += host + " " + k + val + str(eachItem[k]) + "\n"
            value = str(eachItem[k])
            #print "%s-%s-%s" % (host, k+val, value)
            packet.append(ZabbixMetric(host, k+val, value))

    #exit(0)

    try:
        print(ZabbixSender(server).send(packet))
    except ConnectionRefusedError as error:
        print('Cannot Send Metrics! - ' + str(error))
        exit(1)
    return 0

if __name__ == '__main__':
    main()

                                          
