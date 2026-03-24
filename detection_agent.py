#!/usr/bin/env python3
"""
AI Detection Agent - Analyzes Splunk rules and suggests improvements
"""

import requests
import urllib3
import json
import os
from dotenv import load_dotenv

load_dotenv("config.env")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", 8089))
SPLUNK_USER = os.getenv("SPLUNK_USER")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")
BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

def get_splunk_session():
    url = f"{BASE_URL}/services/auth/login"
    data = {"username": SPLUNK_USER, "password": SPLUNK_PASS, "output_mode": "json"}
    response = requests.post(url, data=data, verify=False)
    return response.json()["sessionKey"]

def get_detection_rules(session_key):
    url = f"{BASE_URL}/services/saved/searches"
    headers = {"Authorization": f"Splunk {session_key}"}
    params = {"output_mode": "json", "count": 0}
    response = requests.get(url, headers=headers, params=params, verify=False)
    
    rules = []
    for entry in response.json().get("entry", []):
        content = entry.get("content", {})
        search = content.get("search", "")
        # Only include rules that query botsv1 (our security rules)
        if "botsv1" in search:
            rules.append({
                "name": entry.get("name"),
                "search": search,
                "description": content.get("description", "")
            })
    return rules

def analyze_with_claude(rules):
    """Send rules to Claude for analysis"""
    
    prompt = f"""You are a senior SOC analyst and detection engineer. Analyze these Splunk detection rules and provide:

1. **Coverage Assessment**: What MITRE ATT&CK techniques do these rules cover?
2. **Gaps Identified**: What common attack techniques are NOT covered?
3. **Rule Improvements**: How can each existing rule be improved? (reduce false positives, catch more variants)
4. **New Rules Needed**: Suggest 3 specific new detection rules with full SPL queries for attacks not currently covered.

Current Detection Rules:
{json.dumps(rules, indent=2)}

The environment has BOTSv1 dataset which includes:
- Windows Event Logs (Security, System, Application)
- Sysmon data (process creation, network connections)
- Suricata IDS alerts
- IIS web server logs
- Fortigate firewall logs
- Network stream data (HTTP, DNS, SMB)

Provide actionable, specific recommendations with ready-to-use SPL queries."""

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "content-type": "application/json",
            "anthropic-version": "2023-06-01"
        },
        json={
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        }
    )
    
    if response.status_code == 200:
        return response.json()["content"][0]["text"]
    else:
        return f"Error: {response.status_code} - {response.text}"

def main():
    print("=" * 60)
    print("AI DETECTION AGENT")
    print("=" * 60)
    
    print("\n[1] Connecting to Splunk...")
    session_key = get_splunk_session()
    print("    ✓ Connected")
    
    print("\n[2] Fetching detection rules...")
    rules = get_detection_rules(session_key)
    print(f"    ✓ Found {len(rules)} security detection rules")
    
    for r in rules:
        print(f"       - {r['name']}")
    
    print("\n[3] Analyzing with Claude...")
    print("    (This may take 30-60 seconds)\n")
    
    analysis = analyze_with_claude(rules)
    
    print("=" * 60)
    print("ANALYSIS RESULTS")
    print("=" * 60)
    print(analysis)
    
    # Save analysis
    with open("detection_analysis.md", "w") as f:
        f.write(analysis)
    print("\n\n[4] Analysis saved to detection_analysis.md")

if __name__ == "__main__":
    main()
