#!/bin/bash
systemctl enable postgresql
systemctl start postgresql
systemctl status postgresql
sytemctl enable snmptrapd
sytemctl start snmptrapd
sytemctl status snmptrapd
systemctl enable zabbix-proxy
systemctl start zabbix-proxy
systemctl status zabbix-proxy
