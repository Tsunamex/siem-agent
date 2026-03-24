#!/usr/bin/env python3
"""
Create detection rules in Splunk for BOTSv1 attack scenarios
"""

import requests
import os
import urllib3
from dotenv import load_dotenv

load_dotenv("config.env")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", 8089))
SPLUNK_USER = os.getenv("SPLUNK_USER")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

DETECTION_RULES = [
    {
        "name": "Brute Force Login Attempts",
        "search": 'index=botsv1 sourcetype="WinEventLog:Security" EventCode=4625 | stats count by src_ip, user | where count > 5',
        "description": "Detects multiple failed login attempts from same source IP",
    },
    {
        "name": "Web Vulnerability Scanner Detected",
        "search": 'index=botsv1 sourcetype=iis OR sourcetype=suricata "vulnerability scanner" OR "nikto" OR "sqlmap" OR "nessus" | stats count by src_ip',
        "description": "Detects web vulnerability scanning activity",
    },
    {
        "name": "PowerShell Encoded Command Execution",
        "search": 'index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*") | table _time, Computer, User, CommandLine',
        "description": "Detects PowerShell running with encoded commands",
    },
]

def get_session_key():
    url = f"{BASE_URL}/services/auth/login"
    data = {"username": SPLUNK_USER, "password": SPLUNK_PASS, "output_mode": "json"}
    response = requests.post(url, data=data, verify=False)
    if response.status_code == 200:
        return response.json()["sessionKey"]
    raise Exception(f"Auth failed: {response.status_code}")

def create_saved_search(session_key, rule):
    url = f"{BASE_URL}/services/saved/searches"
    headers = {"Authorization": f"Splunk {session_key}"}
    
    data = {
        "name": rule["name"],
        "search": rule["search"],
        "description": rule["description"],
        "output_mode": "json"
    }
    
    response = requests.post(url, headers=headers, data=data, verify=False)
    return response.status_code, response.text

def main():
    print("Authenticating...")
    session_key = get_session_key()
    
    print("\nCreating detection rules...\n")
    
    for rule in DETECTION_RULES:
        status, response = create_saved_search(session_key, rule)
        if status == 201:
            print(f"✓ Created: {rule['name']}")
        elif status == 409:
            print(f"- Exists: {rule['name']}")
        else:
            print(f"✗ Failed: {rule['name']} - {status} - {response[:200]}")
    
    print("\nDone!")

if __name__ == "__main__":
    main()
