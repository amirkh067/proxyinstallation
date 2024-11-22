#!/bin/bash
systemctl enable postgresql
systemctl status postgresql
sytemctl enable snmptrapd
sytemctl status snmptrapd
systemctl enable zabbix-proxy
systemctl status zabbix-proxy
