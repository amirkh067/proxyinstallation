#!/bin/bash
systemctl enable postgresql
systemctl start postgresql
systemctl status postgresql
systemctl enable snmptrapd
systemctl start snmptrapd
systemctl status snmptrapd
systemctl enable zabbix-proxy
systemctl start zabbix-proxy
systemctl status zabbix-proxy
