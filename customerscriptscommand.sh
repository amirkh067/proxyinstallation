#!/bin/bash
docker cp 8d4c9a15ccce:/usr/lib/zabbix/externalscripts /usr/lib/zabbix/externalscripts/
cd /usr/lib/zabbix/externalscripts/
chown -R zabbix:zabbix /usr/lib/zabbix/externalscripts/*
chmod u+x /usr/lib/zabbix/externalscripts/*
mv /usr/lib/zabbix/externalscripts/externalscripts/* .
rm -rf usr/lib/zabbix/externalscripts/externalscripts
apt install python3-pip
pip3 install urllib3==1.25.11 pyvmomi==7.0.3 requests==2.22 cryptography==3.4.8 py-zabbix python-dateutil pywbem
for file in *.py; do  ./"$file"; done
