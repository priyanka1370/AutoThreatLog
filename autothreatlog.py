from os import name
import pathlib
import sys
from pathlib import Path
import re
import json

def main():
    if len(sys.argv) < 2: #accepting a path
        print("Usage: python autothreatlog.py [path/to/log/file] *ensure you are in the correct directory")
        sys.exit()
    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print("Error: file not found:", log_path)
        sys.exit()

    with log_path.open("r", encoding="utf-8", errors = "ignore") as f: #safely read lines
        lines = f.readlines()
    print("Success: read", len(lines), "from", log_path)

    RULES = {
    r"Failed password": "medium",
    r"Invalid user": "high",
    r"error": "low",
    r"denied": "high",
    r"unauthorized": "high",
    r"firewall": "medium"
}
 #rules/metrics

    results = {} #structure for results
    for line in lines:
        for pattern, severity in RULES.items():
            if re.search(pattern, line, flags=re.IGNORECASE):
                if pattern not in results:
                    results[pattern] = {"count":0, "severity": severity}
                results[pattern]["count"] += 1
    
    with open("output/threat_report.json", "w") as out:
        json.dump(results, out, indent=4) #to export report




if __name__ == "__main__":
    main()
