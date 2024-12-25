#!/usr/bin/python3

import requests
import argparse
import json
import urllib3

# Disable warnings for SSL verification
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

    token_data = response.json()
    return token_data["data"].get("session_token")

def fetch_all_storage_pools(headers, storagepool_url):
    """
    Fetch all storage pools from the API.
    """
    url = f"{storagepool_url}"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.json().get("data", [])

def fetch_storage_pool_details(pool_id, headers, storagepool_url):
    """
    Fetch details for a specific storage pool and calculate space in bytes.
    """
    url = f"{storagepool_url}/{pool_id}"
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    data = response.json().get("data", {})

    # Extract relevant data
    total_size = data.get("capacity", 0)  # Total size in bytes
    used_space = data.get("usage", 0)  # Used space in bytes
    free_space = data.get("free_space", 0)  # Free space in bytes

    return {
        "id": pool_id,
        "name": data.get("name", "Unknown"),
        "total_size": total_size,
        "used_space": used_space,
        "free_space": free_space,
    }

def fetch_and_display_storage_pool_spaces(headers, storagepool_url, space_type):
    """
    Fetch and display storage pool spaces based on the specified type.
    """
    pools = fetch_all_storage_pools(headers, storagepool_url)

    # Initialize total percentage sum for UsedPercent
    total_percentage_sum = 0
    total_pools = len(pools)

    for pool in pools:
        pool_id = pool.get("id")
        pool_info = fetch_storage_pool_details(pool_id, headers, storagepool_url)

        # Calculate percentage if required
        if pool_info['total_size'] > 0:
            used_percentage = (pool_info['used_space'] / pool_info['total_size']) * 100
        else:
            used_percentage = 0

        # Fetch the relevant value based on the type
        if space_type == "Total":
            value = pool_info['total_size']
            label = "Total Size (Bytes)"
        elif space_type == "Used":
            value = pool_info['used_space']
            label = "Used Space (Bytes)"
        elif space_type == "Free":
            value = pool_info['free_space']
            label = "Free Space (Bytes)"
        elif space_type == "UsedPercent":
            value = used_percentage
            label = "Used Percent (%)"
            total_percentage_sum += used_percentage
        else:
            raise ValueError(f"Invalid space type: {space_type}")

        # Print individual pool details
        #print(f"Storage Pool Name: {pool_info['name']}")
        #print(f"{label}: {round(value, 2)}\n")
        #print({round(value, 2)})

    # Print total sum or average percentage
    if space_type == "UsedPercent":
        average_percentage = total_percentage_sum / total_pools if total_pools > 0 else 0
        print(round(average_percentage, 2))
    else:
        print(round(value, 2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--auth_url', '-a', required=True, help="Authentication URL for the API")
    parser.add_argument('--username', '-u', required=True, help="API Username")
    parser.add_argument('--password', '-p', required=True, help="API Password")
    parser.add_argument('--storagepool_url', '-b', required=True, help="Base URL for the API")
    parser.add_argument('--type', required=True, choices=["Total", "Used", "Free", "UsedPercent"], help="Type of space to display (Total, Used, Free, UsedPercent)")
    args = parser.parse_args()

    # Fetch authentication token
    token = fetch_token(args.auth_url, args.username, args.password)
    headers = {"X-Auth-Token": token}

    # Fetch and display storage pool spaces based on the specified type
    fetch_and_display_storage_pool_spaces(headers, args.storagepool_url, args.type)

if __name__ == "__main__":
    main()
