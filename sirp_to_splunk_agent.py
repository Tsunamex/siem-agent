#!/usr/bin/env python3
"""
SIRP to Splunk Detection Agent
Pulls incident from SIRP, checks Splunk coverage, creates rules if missing
"""

import requests
import urllib3
import json
import sys
import os
from dotenv import load_dotenv

load_dotenv("config.env")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SIRP Config
SIRP_BASE_URL = os.getenv("SIRP_BASE_URL")
SIRP_API_KEY = os.getenv("SIRP_API_KEY")

# Splunk Config
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", 8089))
SPLUNK_USER = os.getenv("SPLUNK_USER")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")
SPLUNK_BASE = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

# LLM Config
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://192.9.178.195:8000")
LLM_MODEL = os.getenv("LLM_MODEL", "meta-llama/Llama-4-Scout-17B-16E-Instruct")


def get_sirp_incident(incident_id):
    """Pull incident from SIRP"""
    url = f"{SIRP_BASE_URL}/api/v1/cases-advisory/{incident_id}"
    headers = {
        "accept": "application/json",
        "x-api-key": SIRP_API_KEY
    }
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"SIRP API failed: {response.status_code} - {response.text}")


def get_splunk_session():
    """Authenticate to Splunk"""
    url = f"{SPLUNK_BASE}/services/auth/login"
    data = {"username": SPLUNK_USER, "password": SPLUNK_PASS, "output_mode": "json"}
    response = requests.post(url, data=data, verify=False)
    return response.json()["sessionKey"]


def get_splunk_rules(session_key):
    """Get all Splunk detection rules"""
    url = f"{SPLUNK_BASE}/services/saved/searches"
    headers = {"Authorization": f"Splunk {session_key}"}
    params = {"output_mode": "json", "count": 0}
    response = requests.get(url, headers=headers, params=params, verify=False)
    
    rules = []
    for entry in response.json().get("entry", []):
        content = entry.get("content", {})
        search = content.get("search", "")
        if "botsv1" in search:
            rules.append({
                "name": entry.get("name"),
                "search": search,
                "description": content.get("description", "")
            })
    return rules


def check_coverage(incident, rules):
    """Check if any Splunk rule covers this incident's technique"""
    technique = incident.get("data", {}).get("iti_mitre_techniques") or ""
    subtechnique = incident.get("data", {}).get("iti_mitre_subtechniques") or ""

    # If no technique info, we can't confirm coverage — generate a new rule
    if not technique.strip() and not subtechnique.strip():
        return False, None

    # Look for technique ID in rule descriptions or searches
    for rule in rules:
        rule_text = f"{rule['name']} {rule['description']} {rule['search']}".lower()
        if technique.lower() in rule_text or subtechnique.lower() in rule_text:
            return True, rule['name']

    return False, None


def generate_rule_with_llm(incident):
    """Use LLM to generate a Splunk detection rule"""
    data = incident.get("data", {})

    instructions = "You are a detection engineer. Output a single JSON object only — no markdown, no code fences, no explanations. The first character must be { and the last must be }."

    input_text = f"""Create a Splunk SPL detection rule for this incident.

INCIDENT DETAILS:
- Subject: {data.get('iti_subject')}
- Description: {data.get('iti_description')}
- MITRE Tactic: {data.get('iti_mitre_tactics')}
- MITRE Technique: {data.get('iti_mitre_techniques')}
- MITRE Subtechnique: {data.get('iti_mitre_subtechniques')}
- Severity: {data.get('iti_attack_severity')}

PAYLOAD CONTEXT (key IOCs):
{data.get('iti_payload_full', '')[:2000]}

REQUIREMENTS:
1. Create a detection rule that would catch this attack pattern
2. Use index=botsv1 (our test dataset has Windows logs, Sysmon, IIS, Suricata, network streams)
3. Focus on behavioral detection, not just IOC matching
4. Include risk scoring

OUTPUT FORMAT (JSON only, no markdown):
{{
    "name": "Rule name here",
    "description": "Description here",
    "search": "Full SPL query here"
}}"""

    response = requests.post(
        f"{LLM_BASE_URL}/v1/responses",
        headers={"Content-Type": "application/json"},
        json={
            "model": LLM_MODEL,
            "instructions": instructions,
            "input": input_text,
            "max_output_tokens": 2048,
            "temperature": 0.2,
        }
    )

    if response.status_code == 200:
        text = response.json()["output"][0]["content"][0]["text"].strip()
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(lines[1:-1]).strip()
        return json.loads(text)
    else:
        raise Exception(f"LLM API failed: {response.status_code} - {response.text}")


def create_splunk_rule(session_key, rule):
    """Push rule to Splunk"""
    url = f"{SPLUNK_BASE}/services/saved/searches"
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
    if len(sys.argv) < 2:
        print("Usage: python3 sirp_to_splunk_agent.py <incident_id>")
        print("Example: python3 sirp_to_splunk_agent.py 259976")
        sys.exit(1)
    
    incident_id = sys.argv[1]
    
    print("=" * 60)
    print("SIRP → SPLUNK DETECTION AGENT")
    print("=" * 60)
    
    # Step 1: Pull incident from SIRP
    print(f"\n[1] Fetching incident {incident_id} from SIRP...")
    incident = get_sirp_incident(incident_id)
    data = incident.get("data", {})
    print(f"    ✓ {data.get('iti_subject')[:60]}...")
    print(f"    Technique: {data.get('iti_mitre_techniques')} / {data.get('iti_mitre_subtechniques')}")
    print(f"    Tactic: {data.get('iti_mitre_tactics')}")
    
    # Step 2: Connect to Splunk
    print("\n[2] Connecting to Splunk...")
    session_key = get_splunk_session()
    print("    ✓ Connected")
    
    # Step 3: Get existing rules
    print("\n[3] Checking existing detection coverage...")
    rules = get_splunk_rules(session_key)
    print(f"    Found {len(rules)} detection rules")
    
    # Step 4: Check coverage
    covered, rule_name = check_coverage(incident, rules)
    
    if covered:
        print(f"\n[4] ✓ Already covered by: {rule_name}")
        print("\n    No new rule needed.")
        return
    
    print(f"\n[4] ✗ No existing rule covers {data.get('iti_mitre_techniques')}")
    
    # Step 5: Generate new rule
    print("\n[5] Generating detection rule with LLM...")
    new_rule = generate_rule_with_llm(incident)
    print(f"    ✓ Generated: {new_rule['name']}")
    print(f"\n    SPL Query:")
    print(f"    {new_rule['search'][:200]}...")
    
    # Step 6: Push to Splunk
    print("\n[6] Pushing rule to Splunk...")
    status, response = create_splunk_rule(session_key, new_rule)
    
    if status == 201:
        print(f"    ✓ Rule created successfully!")
    elif status == 409:
        print(f"    - Rule already exists")
    else:
        print(f"    ✗ Failed: {status} - {response[:200]}")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Incident: {data.get('iti_subject')[:50]}...")
    print(f"Technique: {data.get('iti_mitre_techniques')} ({data.get('iti_mitre_tactics')})")
    print(f"New Rule: {new_rule['name']}")
    print(f"Status: {'Created' if status == 201 else 'Exists' if status == 409 else 'Failed'}")


if __name__ == "__main__":
    main()
