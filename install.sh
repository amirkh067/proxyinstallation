#!/bin/bash
/tmp/proxyinstallation/postgresinstall.sh
sleep 1
/tmp/proxyinstallation/zabbixproxyinstall.sh
sleep 1
/tmp/proxyinstallation/snmptrapsandpsk.sh
sleep 1
/tmp/proxyinstallation/odbcdriver.sh
sleep 1
/tmp/proxyinstallation/snmptrapdservicefix.sh
sleep 1
mv /etc/zabbix/zabbix/zabbix_proxy.conf /etc/zabbix/zabbix/zabbix_proxy.conf_orig
cp /tmp/proxyinstallation/zabbix_proxy.conf /etc/zabbix/zabbix/zabbix_proxy.conf
/tmp/proxyinstallation/customscriptscommand.sh
sleep 1
/tmp/proxyinstallation/enableservices.sh
