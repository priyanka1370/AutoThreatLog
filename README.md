# 🔍 AutoThreatLog

**AutoThreatLog** is a lightweight Python tool that scans macOS and Linux system logs for suspicious activity using regex-based detection rules.  
It converts raw log data into structured, actionable insights — a mini version of a real Detection & Response pipeline.

---

## Features

- **Regex-based detection** for keywords such as failed logins, invalid users, and firewall blocks  
- **Severity tagging** (Low, Medium, High) for quick triage  
- **Structured JSON output** for further analysis or dashboarding  
- **Zero dependencies** — runs anywhere with Python 3.10+  
- Tested on **macOS system logs** and custom simulated log files  

---

## Project Structure
```
AutoThreatLog/
│
├── autothreatlog.py # main detection engine
├── sample_logs/
│ └── auth.log # example log file
├── output/
│ └── threat_report.json # generated report
├── README.md
└── requirements.txt
```

---

## 🧩 Quick Start

```

Clone the repo and run it on your own logs:

```bash
git clone https://github.com/priyanka1370/AutoThreatLog.git
cd AutoThreatLog
python3 autothreatlog.py sample_logs/auth.log
```
```
Example output:
Detections:
  - Failed password: 3 (severity: medium)
  - Invalid user: 1 (severity: high)
  - App Firewall.*Blocked: 1 (severity: high)

Wrote report -> output/threat_report.json

```

## Test with macOS logs

AutoThreatLog works directly with macOS’s native logging system.



• Capture the last 200 lines of your system log

```
sudo tail -n 200 /var/log/system.log > sample_logs/mac_system_tail.log
```

• Scan it
```
python3 autothreatlog.py sample_logs/mac_system_tail.log
```

• Or, use the Unified Logging system:

```
log show --style syslog --last 1h --predicate 'eventMessage CONTAINS "auth" OR eventMessage CONTAINS "login"' > sample_logs/mac_auth.log
python3 autothreatlog.py sample_logs/mac_auth.log
```
___
## Extend Detection Rules
Rules live inside autothreatlog.py under RULES:

```
RULES = {
    r"Failed password": "medium",
    r"Invalid user": "high",
    r"\bAccepted password\b": "low",
    r"App Firewall.*Blocked": "high",
    r"denied|unauthorized|error": "medium"
}
```
Just add new patterns and rerun the script — no configuration files required.

License
MIT License © 2025 Priyanka Ankammagari

Author
Priyanka Ankammagari