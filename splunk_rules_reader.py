#!/usr/bin/env python3
"""
Splunk Detection Rules Reader
Connects to Splunk REST API and pulls all saved searches (detection rules)
"""

import requests
import json
import os
import urllib3
from dotenv import load_dotenv

load_dotenv("config.env")

# Disable SSL warnings for local dev
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Splunk connection settings
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", 8089))
SPLUNK_USER = os.getenv("SPLUNK_USER")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"


def get_session_key():
    """Authenticate and get session key"""
    url = f"{BASE_URL}/services/auth/login"
    data = {
        "username": SPLUNK_USER,
        "password": SPLUNK_PASS,
        "output_mode": "json"
    }
    
    response = requests.post(url, data=data, verify=False)
    
    if response.status_code == 200:
        return response.json()["sessionKey"]
    else:
        raise Exception(f"Auth failed: {response.status_code} - {response.text}")


def get_saved_searches(session_key):
    """Pull all saved searches (detection rules)"""
    url = f"{BASE_URL}/services/saved/searches"
    
    headers = {
        "Authorization": f"Splunk {session_key}"
    }
    
    params = {
        "output_mode": "json",
        "count": 0  # 0 = return all
    }
    
    response = requests.get(url, headers=headers, params=params, verify=False)
    
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to get saved searches: {response.status_code}")


def parse_rules(saved_searches_response):
    """Extract relevant info from saved searches"""
    rules = []
    
    for entry in saved_searches_response.get("entry", []):
        content = entry.get("content", {})
        
        rule = {
            "name": entry.get("name"),
            "search": content.get("search"),
            "description": content.get("description", ""),
            "cron_schedule": content.get("cron_schedule", ""),
            "is_scheduled": content.get("is_scheduled", False),
            "alert_type": content.get("alert_type", ""),
            "alert_threshold": content.get("alert_threshold", ""),
            "disabled": content.get("disabled", False),
            "app": entry.get("acl", {}).get("app", ""),
        }
        
        rules.append(rule)
    
    return rules


def main():
    print("=" * 60)
    print("SPLUNK DETECTION RULES READER")
    print("=" * 60)
    
    # Authenticate
    print("\n[1] Authenticating to Splunk...")
    try:
        session_key = get_session_key()
        print("    ✓ Authentication successful")
    except Exception as e:
        print(f"    ✗ {e}")
        return
    
    # Get saved searches
    print("\n[2] Fetching saved searches...")
    try:
        response = get_saved_searches(session_key)
        print(f"    ✓ Retrieved {len(response.get('entry', []))} saved searches")
    except Exception as e:
        print(f"    ✗ {e}")
        return
    
    # Parse rules
    print("\n[3] Parsing detection rules...")
    rules = parse_rules(response)
    
    # Display rules
    print("\n" + "=" * 60)
    print("DETECTION RULES FOUND")
    print("=" * 60)
    
    for i, rule in enumerate(rules, 1):
        print(f"\n--- Rule {i}: {rule['name']} ---")
        print(f"App: {rule['app']}")
        print(f"Scheduled: {rule['is_scheduled']}")
        print(f"Disabled: {rule['disabled']}")
        if rule['description']:
            print(f"Description: {rule['description'][:100]}...")
        print(f"Search Query:")
        print(f"  {rule['search'][:200]}..." if rule['search'] and len(rule['search']) > 200 else f"  {rule['search']}")
    
    # Save to JSON for later use
    output_file = "splunk_rules.json"
    with open(output_file, "w") as f:
        json.dump(rules, f, indent=2)
    print(f"\n[4] Rules saved to {output_file}")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total rules: {len(rules)}")
    print(f"Scheduled: {sum(1 for r in rules if r['is_scheduled'])}")
    print(f"Disabled: {sum(1 for r in rules if r['disabled'])}")
    

if __name__ == "__main__":
    main()
