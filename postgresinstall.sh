#!/bin/bash

# Step 1: Add PostgreSQL repository to sources list
sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'

# Step 2: Import PostgreSQL repository key
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

# Step 3: Update apt-get package list
apt-get update

# Step 4: Install PostgreSQL and PostgreSQL client
apt install postgresql-15 postgresql-client -y

# Step 5: Switch to the postgres user
su - postgres -c "psql -c \"ALTER USER postgres PASSWORD 'MonSer09Zbx34Prx';\""

# Step 7: Check PostgreSQL service status
systemctl enable postgresql
systemctl status postgresql
