#!/bin/bash

# Check the Ubuntu version using lsb_release
VERSION=$(lsb_release -r | awk '{print $2}')

# Based on the version, download the appropriate Zabbix release package
if [[ "$VERSION" == "22.04" ]]; then
    # Ubuntu 22.04 (Jammy)
    echo "Ubuntu 22.04 detected. Installing Zabbix Proxy..."


elif [[ "$VERSION" == "24.04" ]]; then
    # Ubuntu 24.04 (Noble - Placeholder, not yet released)
    echo "Ubuntu 24.04 detected. Installing Zabbix Proxy..."

elif [[ "$VERSION" == "20.04" ]]; then
    # Ubuntu 20.04 (Focal)
    echo "Ubuntu 20.04 detected. Installing Zabbix Agent..."
    wget https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest_7.0+ubuntu20.04_all.deb
    dpkg -i zabbix-release_latest_7.0+ubuntu20.04_all.deb

else
    echo "Unsupported Ubuntu version: $VERSION"
    exit 1
fi



# Step 3: Update apt package list
apt update -y

apt install zabbix-agent

systemctl restart zabbix-agent
systemctl enable zabbix-agent 
systemctl status zabbix-agent
