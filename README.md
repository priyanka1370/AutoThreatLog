# 💻 AutoThreatLog

**AutoThreatLog** is a lightweight Python-based log analysis tool that scans macOS and Linux system logs for suspicious activity using rule-based detection.  
It automatically identifies potential threats such as failed logins, unauthorized access, and firewall events — producing both structured JSON reports and visual analytics.  

---

## Features

- **Regex-based detection** for key security indicators (e.g., failed passwords, unauthorized users, firewall denials)  
- **Risk scoring system** using severity weights (Low, Medium, High)  
- **Automated visualization** with bar charts showing detection frequency  
- **Human-readable executive summaries** for quick situational awareness  
- **IP address aggregation** to highlight repeated malicious sources  
- **Zero dependencies except matplotlib** — runs anywhere with Python 3.10+  

---

## Project Structure

```
AutoThreatLog/
│
├── autothreatlog.py          # Main detection engine (v3.0)
├── sample_logs/
│   └── auth.log              # Sample log file
├── output/
│   ├── threat_report.json    # Generated structured report
│   └── threat_chart.png      # Visualization 
└── requirements.txt
```

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/priyanka1370/AutoThreatLog.git
   cd AutoThreatLog
   ```

2. (Optional) Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run AutoThreatLog on any system log file:

```bash
python3 autothreatlog.py sample_logs/auth.log
```

### Example Output

```
——— Detections ———
Failed password                     3 (medium)
Invalid user                        1 (high)
error                               1 (low)
denied                              1 (high)
unauthorized                        2 (high)
firewall                            2 (medium)

——— Top Suspicious IP Addresses ———
192.168.1.10          4 hits
10.0.0.5              2 hits
192.168.1.15          1 hits
172.16.0.7            1 hits

Overall Risk Score: 27 —> High

Summary:
- 10 total detections across 6 rule types.
- Most frequent: 'Failed password' (3 occurrences).
- 4 unique suspicious IPs observed.
- Overall risk level assessed as High.
```

After execution, AutoThreatLog produces:

- **JSON report:** `output/threat_report.json`  
- **Visualization:** `output/threat_chart.png`

---

## How It Works

1. Reads each line of the provided log file.  
2. Applies regex-based detection rules to find suspicious patterns.  
3. Aggregates results by event type and source IP.  
4. Calculates a severity-weighted risk score.  
5. Generates a text summary, structured JSON report, and visual chart.

The detection logic mirrors simplified SOC (Security Operations Center) workflows — turning unstructured log data into actionable intelligence.

---

## Detection Rules (v3.0)

| Pattern | Description | Severity |
|----------|--------------|-----------|
| `Failed password` | Repeated authentication failures | Medium |
| `Invalid user` | Login attempts with non-existent users | High |
| `error` | General error messages | Low |
| `denied` | Access denial indicators | High |
| `unauthorized` | Unauthorized activity | High |
| `firewall` | Firewall or network filtering events | Medium |

---

## Example JSON Report

```json
{
  "detections": {
    "Failed password": { "count": 3, "severity": "medium" },
    "Invalid user": { "count": 1, "severity": "high" },
    "error": { "count": 1, "severity": "low" },
    "denied": { "count": 1, "severity": "high" },
    "unauthorized": { "count": 2, "severity": "high" },
    "firewall": { "count": 2, "severity": "medium" }
  },
  "ip_hits": {
    "192.168.1.10": 4,
    "10.0.0.5": 2,
    "192.168.1.15": 1,
    "172.16.0.7": 1
  },
  "risk_score": 27,
  "risk_level": "High",
  "summary": "- 10 total detections across 6 rule types.\n- Most frequent: 'Failed password' (3 occurrences).\n- 4 unique suspicious IPs observed.\n- Overall risk level assessed as High."
}
```

---

## Visualization Example

The generated chart (`output/threat_chart.png`) shows detection frequencies:

```
Failed password  ████████ (3)
unauthorized     ████     (2)
firewall         ████     (2)
Invalid user     ██       (1)
error            ██       (1)
denied           ██       (1)
```

---

## Future Scope

AutoThreatLog is a WIP.  
Planned improvements include:

### **Real-Time Detection**
> Introduce a live monitoring mode to tail system logs in real time (using `subprocess` or `watchdog`), allowing AutoThreatLog to detect and report threats as they happen.

### **Configurable Rules**
> Move detection logic into an external configuration file (e.g., `rules.json` or `rules.yaml`), allowing custom detection patterns and severity levels without modifying the codebase.

---

## License

MIT License © 2025 Priyanka Ankammagari

---

## Author

**Priyanka Ankammagari**  
B.S. Cybersecurity, Purdue University  
[LinkedIn](https://www.linkedin.com/in/priyanka-ankammagari/)

---
