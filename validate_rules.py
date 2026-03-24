#!/usr/bin/env python3
"""
Validate Detection Rules against BOTSv1
Runs each botsv1 detection rule as a search job and reports hit counts
"""

import requests
import urllib3
import json
import time
import os
from dotenv import load_dotenv

load_dotenv("config.env")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", 8089))
SPLUNK_USER = os.getenv("SPLUNK_USER")
SPLUNK_PASS = os.getenv("SPLUNK_PASS")
BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}"

POLL_INTERVAL = 2   # seconds between status checks
MAX_WAIT = 120      # max seconds to wait per search job


def get_splunk_session():
    url = f"{BASE_URL}/services/auth/login"
    data = {"username": SPLUNK_USER, "password": SPLUNK_PASS, "output_mode": "json"}
    response = requests.post(url, data=data, verify=False)
    response.raise_for_status()
    return response.json()["sessionKey"]


def get_detection_rules(session_key):
    """Fetch only botsv1 detection rules from Splunk"""
    url = f"{BASE_URL}/services/saved/searches"
    headers = {"Authorization": f"Splunk {session_key}"}
    params = {"output_mode": "json", "count": 0}
    response = requests.get(url, headers=headers, params=params, verify=False)
    response.raise_for_status()

    rules = []
    for entry in response.json().get("entry", []):
        content = entry.get("content", {})
        search = content.get("search", "")
        if "botsv1" in search:
            rules.append({
                "name": entry.get("name"),
                "search": search,
                "description": content.get("description", ""),
            })
    return rules


def submit_search(session_key, spl):
    """Submit a search job and return the job sid"""
    url = f"{BASE_URL}/services/search/jobs"
    headers = {"Authorization": f"Splunk {session_key}"}
    data = {
        "search": spl,
        "output_mode": "json",
        "earliest_time": "0",   # all-time search across BOTSv1
        "latest_time": "now",
    }
    response = requests.post(url, headers=headers, data=data, verify=False)
    response.raise_for_status()
    return response.json()["sid"]


def poll_job(session_key, sid):
    """Poll until the search job is done, return final status dict"""
    url = f"{BASE_URL}/services/search/jobs/{sid}"
    headers = {"Authorization": f"Splunk {session_key}"}
    params = {"output_mode": "json"}

    elapsed = 0
    while elapsed < MAX_WAIT:
        response = requests.get(url, headers=headers, params=params, verify=False)
        response.raise_for_status()
        entry = response.json()["entry"][0]["content"]
        state = entry.get("dispatchState", "")

        if state in ("DONE", "FAILED"):
            return entry

        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

    raise TimeoutError(f"Search job {sid} did not finish within {MAX_WAIT}s")


def get_result_count(session_key, sid):
    """Return the number of results from a completed job"""
    url = f"{BASE_URL}/services/search/jobs/{sid}/results"
    headers = {"Authorization": f"Splunk {session_key}"}
    params = {"output_mode": "json", "count": 0}
    response = requests.get(url, headers=headers, params=params, verify=False)
    response.raise_for_status()
    data = response.json()
    return len(data.get("results", []))


def validate_rules(session_key, rules):
    results = []

    for i, rule in enumerate(rules, 1):
        print(f"  [{i}/{len(rules)}] {rule['name']} ... ", end="", flush=True)

        try:
            sid = submit_search(session_key, rule["search"])
            job = poll_job(session_key, sid)

            if job.get("dispatchState") == "FAILED":
                status = "ERROR"
                hit_count = 0
                detail = job.get("messages", [{}])[0].get("text", "Unknown error")
            else:
                hit_count = get_result_count(session_key, sid)
                status = "FIRING" if hit_count > 0 else "SILENT"
                detail = ""

        except Exception as e:
            status = "ERROR"
            hit_count = 0
            detail = str(e)

        label = {
            "FIRING": "FIRING",
            "SILENT": "SILENT - 0 hits",
            "ERROR":  f"ERROR - {detail[:80]}",
        }[status]

        print(label)

        results.append({
            "name": rule["name"],
            "status": status,
            "hit_count": hit_count,
            "detail": detail,
            "search": rule["search"],
        })

    return results


def print_report(results):
    firing = [r for r in results if r["status"] == "FIRING"]
    silent = [r for r in results if r["status"] == "SILENT"]
    errors = [r for r in results if r["status"] == "ERROR"]

    print("\n" + "=" * 60)
    print("VALIDATION REPORT")
    print("=" * 60)

    print(f"\nFIRING ({len(firing)}) — rules with hits in BOTSv1:")
    for r in firing:
        print(f"  ✓  {r['name']}  [{r['hit_count']} results]")

    print(f"\nSILENT ({len(silent)}) — rules with 0 results:")
    for r in silent:
        print(f"  ✗  {r['name']}")

    if errors:
        print(f"\nERRORS ({len(errors)}) — rules that failed to run:")
        for r in errors:
            print(f"  !  {r['name']}: {r['detail'][:100]}")

    print(f"\nSUMMARY: {len(firing)} firing / {len(silent)} silent / {len(errors)} errors out of {len(results)} rules")


def main():
    print("=" * 60)
    print("DETECTION RULE VALIDATOR")
    print("=" * 60)

    print("\n[1] Connecting to Splunk...")
    session_key = get_splunk_session()
    print("    Connected")

    print("\n[2] Fetching botsv1 detection rules...")
    rules = get_detection_rules(session_key)
    print(f"    Found {len(rules)} rules")

    print(f"\n[3] Running each rule against BOTSv1 (all-time)...")
    results = validate_rules(session_key, rules)

    print_report(results)

    # Save results to JSON
    output_file = "validation_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[4] Full results saved to {output_file}")


if __name__ == "__main__":
    main()
