#!/bin/bash

# Find the container ID for the Zabbix Proxy
container_id=$(docker ps | grep zabbix-proxy-mysql | grep 10051 | awk '{print $1}')

if [ -z "$container_id" ]; then
  echo "Error: Zabbix Proxy container not found."
  exit 1
fi

echo "Found Zabbix Proxy container: $container_id"

# Execute commands inside the container
docker exec -it -u 0 "$container_id"
sleep 1


apt-get update
apt-get install -y python3 python3-pip python3-venv
python3 -m venv /opt/zabbix-env
source /opt/zabbix-env/bin/activate
pip install urllib3==1.25.11 pyvmomi==7.0.3 requests==2.22 cryptography==3.4.8 py-zabbix python-dateutil pywbem purestorage
pip install --upgrade requests urllib3 chardet
echo 'Python environment and dependencies installed successfully.'


for file in  /usr/lib/zabbix/externalscripts/*.py; do "$file"; done


echo "Setup complete for container: $container_id"
exit
