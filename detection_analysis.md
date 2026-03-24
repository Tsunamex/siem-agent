# SOC Detection Rules Analysis

## 1. Coverage Assessment (MITRE ATT&CK Techniques)

**Current rules cover:**
- **T1110.001** - Brute Force: Password Guessing (Rule 1)
- **T1059.001** - Command and Scripting Interpreter: PowerShell (Rule 2)
- **T1595.001** - Active Scanning: Scanning IP Blocks (Rule 3)
- **T1595.002** - Active Scanning: Vulnerability Scanning (Rule 3)

## 2. Gaps Identified

**Critical missing coverage:**
- Lateral Movement (T1021.*)
- Credential Dumping (T1003.*)
- Defense Evasion (T1070.*, T1055.*)
- Data Exfiltration (T1041, T1048.*)
- Persistence mechanisms (T1053.*, T1547.*)
- Command & Control (T1071.*, T1105)
- Discovery techniques (T1082, T1016, T1057)

## 3. Rule Improvements

### Rule 1: Brute Force Login Attempts
**Issues:** No time window, ignores successful attempts after failures, no account lockout correlation

**Improved version:**
```splunk
index=botsv1 sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) 
| bucket _time span=10m 
| stats count(eval(EventCode=4625)) as failed_attempts, 
        count(eval(EventCode=4624)) as successful_attempts, 
        dc(user) as unique_users by src_ip, _time 
| where failed_attempts >= 5 AND successful_attempts < 2
| eval risk_score = case(
    failed_attempts > 20, "High",
    failed_attempts > 10, "Medium", 
    1=1, "Low"
)
| table _time, src_ip, failed_attempts, successful_attempts, unique_users, risk_score
```

### Rule 2: PowerShell Encoded Command Execution
**Issues:** Missing obfuscation variants, no command decoding, lacks context

**Improved version:**
```splunk
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
(CommandLine="*-enc*" OR CommandLine="*-e *" OR CommandLine="*-encodedcommand*" 
OR CommandLine="*-EncodedCommand*" OR CommandLine="*powershell*" CommandLine="*frombase64string*"
OR CommandLine="*invoke-expression*" OR CommandLine="*iex*")
| regex CommandLine="(?i)(enc|encodedcommand|frombase64|iex|invoke-expression)"
| eval decoded_command = if(match(CommandLine, "(?i)-enc\w*\s+([A-Za-z0-9+/=]+)"), "Base64_Detected", "Obfuscated")
| eval parent_process = coalesce(ParentCommandLine, "Unknown")
| eval risk_score = case(
    match(CommandLine, "(?i)(downloadstring|downloadfile|invoke-webrequest)"), "High",
    match(CommandLine, "(?i)(bypass|unrestricted|hidden)"), "Medium",
    1=1, "Low"
)
| table _time, Computer, User, CommandLine, parent_process, decoded_command, risk_score
```

### Rule 3: Web Vulnerability Scanner
**Issues:** Static signature matching, no rate-based detection, missing user agents

**Improved version:**
```splunk
index=botsv1 (sourcetype=iis OR sourcetype=suricata OR sourcetype=stream:http) 
| eval is_scanner = case(
    match(cs_User_Agent, "(?i)(nikto|sqlmap|nessus|openvas|nmap|burp|zap|acunetix)"), 1,
    match(cs_uri_stem, "(?i)(\.\.\/|union\s+select|<script|etc\/passwd|admin\/|phpmyadmin)"), 1,
    sc_status IN (404, 403, 500) AND match(cs_uri_stem, "(?i)\.(php|asp|jsp|cgi)"), 1,
    1=1, 0
)
| where is_scanner=1
| bucket _time span=5m
| stats count as requests, 
        dc(cs_uri_stem) as unique_paths,
        dc(sc_status) as status_codes,
        values(cs_User_Agent) as user_agents by src_ip, _time
| where requests > 10 OR unique_paths > 5
| eval confidence = case(
    requests > 50 AND unique_paths > 20, "High",
    requests > 20 AND unique_paths > 10, "Medium",
    1=1, "Low"
)
| table _time, src_ip, requests, unique_paths, status_codes, confidence
```

## 4. New Rules Needed

### Rule A: Credential Dumping Detection (T1003.001/002)
```splunk
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(CommandLine="*lsass*" OR CommandLine="*procdump*" OR CommandLine="*mimikatz*" 
OR CommandLine="*sekurlsa*" OR CommandLine="*hashdump*" OR CommandLine="*pwdump*"
OR CommandLine="*gsecdump*" OR Image="*\\lsass.exe")
OR (sourcetype="WinEventLog:Security" EventCode=4656 ObjectName="*\\lsass.exe" AccessMask="0x1010")
OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 
    TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010", "0x1fffff", "0x143a"))
| eval technique = case(
    match(CommandLine, "(?i)(procdump.*lsass|lsass.*dump)"), "LSASS_Dump",
    match(CommandLine, "(?i)mimikatz"), "Mimikatz",
    EventCode=10, "Process_Access",
    1=1, "Credential_Access"
)
| eval risk_level = case(
    technique="Mimikatz", "Critical",
    technique="LSASS_Dump", "High",
    1=1, "Medium"
)
| table _time, Computer, User, technique, CommandLine, SourceImage, TargetImage, risk_level
```

### Rule B: Lateral Movement via SMB (T1021.002)
```splunk
index=botsv1 (sourcetype="WinEventLog:Security" EventCode=4624 LogonType=3)
OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
    DestinationPort IN (445, 139))
OR (sourcetype=stream:smb)
| eval auth_event = if(EventCode=4624, 1, 0)
| eval network_conn = if(EventCode=3, 1, 0)
| bucket _time span=2m
| stats sum(auth_event) as authentications,
        sum(network_conn) as smb_connections,
        dc(Computer) as unique_hosts,
        dc(dest_ip) as unique_destinations by src_ip, user, _time
| where authentications > 0 AND unique_hosts > 2 AND _time > relative_time(now(), "-1h")
| eval lateral_movement_score = (unique_hosts * 2) + authentications
| where lateral_movement_score > 5
| eval severity = case(
    unique_hosts > 5, "High",
    unique_hosts > 3, "Medium",
    1=1, "Low"
)
| table _time, src_ip, user, unique_hosts, authentications, smb_connections, severity
```

### Rule C: DNS Tunneling Detection (T1071.004)
```splunk
index=botsv1 sourcetype=stream:dns OR sourcetype="suricata"
| eval query_length = len(query)
| eval subdomain_count = (len(query) - len(replace(query, ".", "")))
| eval entropy = case(
    match(query, "[0-9a-f]{8,}"), 3,
    match(query, "[a-z0-9]{15,}"), 2,
    1=1, 1
)
| where query_length > 50 OR subdomain_count > 5 OR entropy >= 2
| bucket _time span=5m
| stats count as dns_queries,
        avg(query_length) as avg_length,
        max(query_length) as max_length,
        dc(query) as unique_queries,
        values(query) as sample_queries by src_ip, dest_ip, _time
| where dns_queries > 10 AND (avg_length > 40 OR max_length > 100)
| eval tunneling_score = case(
    avg_length > 80 AND dns_queries > 50, "High",
    avg_length > 60 AND dns_queries > 20, "Medium",
    1=1, "Low"
)
| table _time, src_ip, dest_ip, dns_queries, avg_length, max_length, unique_queries, tunneling_score
```

## Implementation Recommendations

1. **Deploy rules in test mode first** - Monitor for false positives over 48 hours
2. **Set up correlation searches** - Link related events across different data sources
3. **Create response playbooks** - Define escalation procedures for each rule
4. **Schedule regular reviews** - Weekly tuning sessions to adjust thresholds
5. **Implement risk-based scoring** - Use enterprise security framework for consistent scoring

These improvements will provide comprehensive coverage across the cyber kill chain while minimizing analyst fatigue through intelligent filtering and risk-based prioritization.