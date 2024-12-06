#!/usr/bin/python3

import requests
import json
import argparse
import socket
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_token(auth_url, username, password):
    """
    Fetch the authentication token.
    """
    payload = {
        "data": {
            "username": username,
            "password": password
        }
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(auth_url, json=payload, headers=headers, verify=False)
    response.raise_for_status()

    # Parse the response JSON
    try:
        token_data = response.json()
    except json.JSONDecodeError:
        print(f"Invalid JSON response: {response.text}")
        raise

    # Extract session_token
    if "data" in token_data and "session_token" in token_data["data"]:
        return token_data["data"]["session_token"]

    # Handle unexpected response structure
    print(f"Unexpected response structure: {json.dumps(token_data, indent=4)}")
    raise KeyError("Authentication session_token not found in response")




def fetch_disk_ids(base_url, headers):
    """
    Fetch all disk IDs from the API.
    """
    response = requests.get(base_url, headers=headers, verify=False)
    response.raise_for_status()
    disk_data = response.json()
    return [disk["id"] for disk in disk_data.get("data", [])]


def fetch_disk_details(base_url, disk_id, headers):
    """
    Fetch detailed information for a specific disk by its ID.
    """
    url = f"{base_url}/{disk_id}"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()


def send_to_zabbix(zabbix_server, zabbix_port, host, key, value):
    """
    Send a single metric to the Zabbix server.
    """
    payload = json.dumps({
        "request": "sender data",
        "data": [
            {
                "host": host,
                "key": key,
                "value": value
            }
        ]
    })
    header = "ZBXD\1"
    length = len(payload)
    data = header.encode() + length.to_bytes(8, 'little') + payload.encode()

    print(f"Sending to Zabbix: host={host}, key={key}, value={value}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((zabbix_server, zabbix_port))
        sock.sendall(data)
        response = sock.recv(1024)
        print(f"Zabbix Response: {response}")


def wbem_discovery(base_url, headers):
    """
    Discover disks and return them in Zabbix discovery format.
    """
    disks = []
    disk_ids = fetch_disk_ids(base_url, headers)
    for disk_id in disk_ids:
        disk_details = fetch_disk_details(base_url, disk_id, headers)
        disks.append({
            "{#DISKID}": disk_details.get("data", {}).get("id"),
            "{#ARRAYNAME}": disk_details.get("data", {}).get("array_name"),
            "{#SERIAL}": disk_details.get("data", {}).get("serial")
        })
    print(json.dumps({"data": disks}, indent=4, separators=(',', ': ')))


def wbem_status(base_url, headers, key_field, value_fields, host, zabbix_server, zabbix_port):
    """
    Send disk details as metrics to Zabbix.
    """
    disk_ids = fetch_disk_ids(base_url, headers)
    for disk_id in disk_ids:
        disk_details = fetch_disk_details(base_url, disk_id, headers)
        disk_data = disk_details.get("data", {})
        for value_field in value_fields.split(","):
            key = f"disk.{value_field}[{disk_data.get(key_field)}]"
            value = disk_data.get(value_field, "not_found")
            if value != "not_found":
                print(f"Sending to Zabbix: host={host}, key={key}, value={value}")
                send_to_zabbix(zabbix_server, zabbix_port, host, key, value)



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--auth_url', '-a', action="store", help="Authentication URL for the API", required=True)
    parser.add_argument('--username', '-u', action="store", help="API Username", required=True)
    parser.add_argument('--password', '-p', action="store", help="API Password", required=True)
    parser.add_argument('--base_url', '-b', action="store", help="Base URL for the API", required=True)
    parser.add_argument('--host', '-z', action="store", help="Zabbix Hostname (Required for status mode)")
    parser.add_argument('--zabbix_server', '-s', action="store", help="Zabbix Server", default="localhost")
    parser.add_argument('--zabbix_port', '-P', action="store", help="Zabbix Server Port", type=int, default=10051)
    parser.add_argument('--key_field', '-k', action="store", help="Key Field for Zabbix Items", default="id")
    parser.add_argument('--value_fields', '-v', action="store", help="Comma-separated value fields (Required for status mode)")
    parser.add_argument('--discovery', '-D', action="store_true", help="Discover disks")
    parser.add_argument('--status', '-S', action="store_true", help="Send status metrics")
    args = parser.parse_args()

    # Fetch the token
    token = fetch_token(args.auth_url, args.username, args.password)

    # Set headers with the fetched token
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }

    if args.discovery:
        wbem_discovery(args.base_url, headers)
    elif args.status:
        wbem_status(args.base_url, headers, args.key_field,
                    args.value_fields, args.host, args.zabbix_server, args.zabbix_port)


if __name__ == "__main__":
    main()
