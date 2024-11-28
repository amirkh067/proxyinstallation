#!/bin/bash
systemctl start postgresql
systemctl status postgresql
systemctl start snmptrapd
systemctl status snmptrapd
systemctl start zabbix-proxy
systemctl status zabbix-proxy
