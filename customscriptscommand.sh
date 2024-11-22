#!/bin/bash

# Get the container ID of the Zabbix proxy container
proxycontainerid=$(docker ps | grep zabbix-proxy | grep 10051 | awk '{print $1}')

# Check if a container ID was found
if [ -z "$proxycontainerid" ]; then
  echo "Error: No Zabbix proxy container found on port 10051."
  exit 1
fi

# Ensure the destination directory exists
mkdir -p /usr/lib/zabbix/externalscripts/

# Copy the external scripts from the container to the host
docker cp "$proxycontainerid:/usr/lib/zabbix/externalscripts" /usr/lib/zabbix/externalscripts/

echo "External scripts copied successfully from container $proxycontainerid to /usr/lib/zabbix/externalscripts/"

cd /usr/lib/zabbix/externalscripts/
chown -R zabbix:zabbix /usr/lib/zabbix/externalscripts/*
chmod u+x /usr/lib/zabbix/externalscripts/*
mv /usr/lib/zabbix/externalscripts/externalscripts/* .
rm -rf /usr/lib/zabbix/externalscripts/externalscripts
apt install python3-pip
pip3 install urllib3==1.25.11 pyvmomi==7.0.3 requests==2.22 cryptography==3.4.8 py-zabbix python-dateutil pywbem
for file in  /usr/lib/zabbix/externalscripts/*.py; do "$file"; done
