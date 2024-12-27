cp -r /tmp/proxyinstallation/scripts /etc/zabbix
for file in /etc/zabbix/scripts/*.py; do [ -f "$file" ] && sed -i '1s|^#!/usr/bin/python3|#!/opt/zabbix-env/bin/python3|' "$file"; done
