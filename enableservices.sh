#!/bin/bash
systemctl enable postgresql
systemctl enable snmptrapd
systemctl enable zabbix-proxy
systemctl status postgresql
systemctl status snmptrapd
systemctl status zabbix-proxy
