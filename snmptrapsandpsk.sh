#!/bin/bash

# Generate a PSK (Pre-Shared Key) using OpenSSL and save it to /etc/zabbix/proxy.psk
openssl rand -hex 32 > /etc/zabbix/proxy.psk

# Display the generated key
echo "The generated PSK key is:"
cat /etc/zabbix/proxy.psk

# Create the required folder
mkdir -p /var/log/snmptrap/
touch /var/log/snmptrap/snmptrap.log

# Download the Zabbix Trap Receiver script and make it executable
wget https://git.zabbix.com/projects/ZBX/repos/zabbix/raw/misc/snmptrap/zabbix_trap_receiver.pl -O /usr/bin/zabbix_trap_receiver.pl
chmod a+x /usr/bin/zabbix_trap_receiver.pl

# Install necessary SNMP packages
sudo apt update
sudo apt install snmp snmp-mibs-downloader snmptrapd -y
apt-get install perl libxml-simple-perl libsnmp-perl -y

# Edit /etc/snmp/snmptrapd.conf to add the configuration for SNMP traps
echo "authCommunity execute eclitizleme" | sudo tee -a /etc/snmp/snmptrapd.conf > /dev/null
echo "perl do \"/usr/bin/zabbix_trap_receiver.pl\";" | sudo tee -a /etc/snmp/snmptrapd.conf > /dev/null

# Edit /etc/snmp/snmp.conf to comment out the 'mibs' line
sudo sed -i 's/^mibs :$/#mibs :/' /etc/snmp/snmp.conf

# Edit /usr/bin/zabbix_trap_receiver.pl to change the trap file location
sudo sed -i "s|\$SNMPTrapperFile = '/tmp/zabbix_traps.tmp'|\$SNMPTrapperFile = '/var/log/snmptrap/snmptrap.log'|" /usr/bin/zabbix_trap_receiver.pl

sudo setcap 'cap_net_bind_service=+ep' /usr/sbin/snmptrapd

# Restart SNMP service to apply the changes
sudo systemctl restart snmptrapd

echo "Zabbix SNMP trap configuration completed."
