#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <username> <password> <host>"
    exit 1
fi

# Read arguments
USERNAME=$1
PASSWORD=$2
HOST=$3

# Generate the Base64-encoded credentials
AUTH=$(echo -n "${USERNAME}:${PASSWORD}" | base64)

# Make the API request using curl
curl -s -X GET -H "Authorization: Basic ${AUTH}" -H "Accept: application/json" "https://${HOST}/storeonceservices/cluster/" -k

