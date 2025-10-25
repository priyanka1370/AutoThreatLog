from os import name
import pathlib
import sys
from pathlib import Path
import re
import json
import argparse
from collections import defaultdict
from collections import Counter
import matplotlib.pyplot as plt



RULES = {
    r"Failed password": "medium",
    r"Invalid user": "high",
    r"error": "low",
    r"denied": "high",
    r"unauthorized": "high",
    r"firewall": "medium"
}
 #rules/metrics

SEVERITIES = {"low": 1, "medium": 2, "high": 3}

def parse_args():
    p = argparse.ArgumentParser(description="AutoThreatLog v3.0 – visual and summary reporting")
    p.add_argument("logfile", help="Path to log file")
    p.add_argument("--out", default="output/threat_report.json", help="Output JSON path")
    p.add_argument("--chart", default="output/threat_chart.png", help="Path to chart image")  # ← add this line
    return p.parse_args()

def extract_ip(line):
    m = re.search("r(\d{1,3}(?:\.\d{1,3}){3})", line)
    return m.group(1) if m else None


def main():
    args = parse_args()
    log_path = Path(args.logfile)
    if not log_path.exists():
        print("Error: file not found:", log_path)
        sys.exit(1)
    
    results = defaultdict(lambda: {"count": 0, "severity": None})
    ip_hits = Counter()

    with log_path.open("r", encoding="utf-8", errors = "ignore") as f: #safely read lines
        for line in f:
            for pattern, severity in RULES.items():
                if re.search(pattern, line, flags=re.IGNORECASE):
                    results[pattern]["count"] += 1
                    results[pattern]["severity"] = severity
                    ip = extract_ip(line)
                    if ip:
                        ip_hits[ip] += 1
    
    risk_score = sum(v["count"] * SEVERITIES[v["severity"]] for v in results.values())
    risk_level = (
        "Low" if risk_score < 10 else
        "Moderate" if risk_score < 25 else
        "High"    )

    if results: #summary
        print("——— Detections ———")
        for pattern, info in results.items():
            print(f"{pattern:35s} {info['count']:>3d} ({info['severity']})")
        print ("——— Top Suspicious IP Addresses ———")
        for ip, count in ip_hits.most_common(5):
            print(f"\nOverall Risk Score: {risk_score} —> {risk_level}")
    else:
        ("no detections have been found")
    
    total_events = sum(info["count"] for info in results.values())
    if total_events > 0:
        top_pattern = max(results, key=lambda k: results[k]["count"])
        summary = (
            f"\nSummary:\n"
            f"- {total_events} total detections across {len(results)} rule types.\n"
            f"- Most frequent: '{top_pattern}' ({results[top_pattern]['count']} occurences).\n"
            f"- {len(ip_hits)} unique suspicious IPs observed.\n"
            f"- Overall risk level assesses as {risk_level}.\n"
        )
        print(summary)
    else:
        summary = "Summary: non suspcious activity found.\n"
        print (summary)
    
    if results:
        patterns =  list(results.keys())
        counts = [info["count"] for info in results.values()]

        plt.figure(figsize=(8,4)) #visualizations
        plt.barh(patterns, counts)
        plt.xlabel("Count")
        plt.title("AutoThreatLog Detections")
        plt.tight_layout()

        chart_path = Path(args.chart)
        chart_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(chart_path)
        plt.close()
        print(f"Chart saved to {chart_path.resolve()}")

    out = {
        "detections": results,
        "ip_hits": dict(ip_hits),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary":summary.strip(),
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as o:
        json.dump(out, o, indent=2)
    
    print(f"SUCCESS: Report saved to {out_path.resolve()}")


if __name__ == "__main__":
    main()
