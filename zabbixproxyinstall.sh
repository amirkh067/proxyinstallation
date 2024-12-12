#!/bin/bash

# Check the Ubuntu version using lsb_release
VERSION=$(lsb_release -r | awk '{print $2}')

# Based on the version, download the appropriate Zabbix release package
if [[ "$VERSION" == "22.04" ]]; then
    # Ubuntu 22.04 (Jammy)
    echo "Ubuntu 22.04 detected. Installing Zabbix Proxy..."
    wget https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest+ubuntu22.04_all.deb
    dpkg -i zabbix-release_latest+ubuntu22.04_all.deb

elif [[ "$VERSION" == "24.04" ]]; then
    # Ubuntu 24.04 (Noble - Placeholder, not yet released)
    echo "Ubuntu 24.04 detected. Installing Zabbix Proxy..."
    wget https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest+ubuntu24.04_all.deb
    dpkg -i zabbix-release_latest+ubuntu24.04_all.deb

elif [[ "$VERSION" == "20.04" ]]; then
    # Ubuntu 20.04 (Focal)
    echo "Ubuntu 20.04 detected. Installing Zabbix Proxy..."
    wget https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/zabbix-release_latest+ubuntu20.04_all.deb
    dpkg -i zabbix-release_latest+ubuntu20.04_all.deb

else
    echo "Unsupported Ubuntu version: $VERSION"
    exit 1
fi

# Step 3: Update apt package list
apt update

# Step 4: Install Zabbix Proxy for PostgreSQL and Zabbix SQL scripts
apt install zabbix-proxy-pgsql zabbix-sql-scripts -y

echo "MonSer09Zbx34Prx"

# Step 5: Create Zabbix user in PostgreSQL with a password prompt
sudo -u postgres createuser --pwprompt zabbix

# Step 6: Create the Zabbix proxy database
sudo -u postgres createdb -O zabbix zabbix_proxy

# Step 7: Import the PostgreSQL SQL schema for Zabbix Proxy
cat /usr/share/zabbix-sql-scripts/postgresql/proxy.sql | sudo -u zabbix psql zabbix_proxy

# Step 8: Set password for Zabbix user in PostgreSQL
su - postgres -c "psql -c \"ALTER USER zabbix PASSWORD 'MonSer09Zbx34Prx';\""

echo "Zabbix Proxy with PostgreSQL setup completed."
