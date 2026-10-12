#!/usr/bin/env python3
"""
Digital Evidence Timeline Generator
=====================================
Collects artifacts from multiple sources (filesystem, event logs,
network, user activity) and merges them into a unified, chronological
timeline for forensic analysis.

Outputs:
  - timeline.html  (interactive forensic report)
  - timeline.json  (structured)
  - timeline.csv   (Excel-friendly)

Author: batool jameel
License: MIT
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from collectors import file_system, event_log, network, user_activity


# --------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------

def banner(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def write_csv(path, rows, fieldnames=None):
    if not rows:
        return
    if fieldnames is None:
        fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


# --------------------------------------------------------------------
# Core logic
# --------------------------------------------------------------------

COLLECTORS = {
    "filesystem":   ("filesystem.json",  file_system.collect,   "File System"),
    "eventlog":     ("events.json",      event_log.collect,     "Windows Event Log"),
    "network":      ("network.json",     network.collect,       "Network"),
    "useractivity": ("users.json",       user_activity.collect, "User Activity"),
}


def collect_all(sample_dir):
    """Run all collectors on the sample_evidence directory."""
    all_events = []
    stats = {}

    for key, (filename, func, label) in COLLECTORS.items():
        filepath = os.path.join(sample_dir, filename)
        events = func(filepath)
        stats[key] = {
            "label": label,
            "file": filename,
            "count": len(events),
        }
        all_events.extend(events)
        print(f"  [+] {label:<20} {len(events):>4} events")

    return all_events, stats


def normalize_and_sort(events):
    """Parse timestamps and sort chronologically."""
    for e in events:
        ts = e.get("timestamp", "")
        try:
            e["_dt"] = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            e["_dt"] = None

    # Sort: events with valid timestamp first
    events.sort(key=lambda x: (x["_dt"] is None, x["_dt"] or datetime.max))
    return events


def build_summary(events, stats):
    """Build overview statistics."""
    suspicious = sum(
        1 for e in events if e.get("details", {}).get("suspicious")
    )

    # Time range
    valid = [e["_dt"] for e in events if e.get("_dt")]
    time_range = {}
    if valid:
        time_range = {
            "start": min(valid).isoformat(timespec="seconds"),
            "end":   max(valid).isoformat(timespec="seconds"),
            "span_hours": round(
                (max(valid) - min(valid)).total_seconds() / 3600, 2
            ),
        }

    # Sources breakdown
    sources = {}
    for e in events:
        src = e.get("source", "Unknown")
        sources[src] = sources.get(src, 0) + 1

    return {
        "total_events": len(events),
        "suspicious_events": suspicious,
        "sources": sources,
        "time_range": time_range,
        "collector_stats": stats,
    }


def generate_report(events, summary, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    json_events = [{k: v for k, v in e.items() if k != "_dt"} for e in events]
    write_json(output_dir / "timeline.json", {
        "summary": summary,
        "events": json_events,
    })

    # CSV
    csv_rows = []
    for e in events:
        csv_rows.append({
            "timestamp": e.get("timestamp", ""),
            "source": e.get("source", ""),
            "artifact": e.get("artifact", ""),
            "event": e.get("event", ""),
            "interpretation": e.get("interpretation", ""),
            "suspicious": e.get("details", {}).get("suspicious", False),
        })
    write_csv(output_dir / "timeline.csv", csv_rows)

    # HTML
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("timeline_template.html")

    html = template.render(
        events=json_events,
        summary=summary,
        generated_at=datetime.now().isoformat(timespec="seconds"),
    )

    with open(output_dir / "timeline.html", "w", encoding="utf-8") as f:
        f.write(html)

    return output_dir


# --------------------------------------------------------------------
# Entry Point
# --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Digital Evidence Timeline Generator"
    )
    parser.add_argument(
        "sample_dir",
        nargs="?",
        default="sample_evidence",
        help="Directory containing evidence JSON files",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output directory (default: output/timeline_YYYYMMDD_HHMMSS)"
    )
    args = parser.parse_args()

    if not os.path.isdir(args.sample_dir):
        print(f"[!] Directory not found: {args.sample_dir}")
        sys.exit(1)

    if args.output is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"output/timeline_{ts}"
    else:
        output_dir = args.output

    print("\n" + "=" * 60)
    print("  DIGITAL EVIDENCE TIMELINE GENERATOR")
    print("=" * 60)
    print(f"  Evidence dir: {args.sample_dir}")
    print(f"  Output:       {output_dir}")
    print(f"  Started:      {datetime.now().isoformat(timespec='seconds')}")

    # 1) Collect
    banner("[1/4] Collecting artifacts")
    events, stats = collect_all(args.sample_dir)

    if not events:
        print("\n[!] No events collected. Check evidence files.")
        sys.exit(0)

    # 2) Normalize & sort
    banner("[2/4] Normalizing & sorting")
    events = normalize_and_sort(events)
    print(f"  [+] Total events:      {len(events)}")

    # 3) Build summary
    banner("[3/4] Building summary")
    summary = build_summary(events, stats)
    print(f"  [+] Suspicious events: {summary['suspicious_events']}")
    if summary["time_range"]:
        print(f"  [+] Time range:        {summary['time_range']['start']}")
        print(f"                         → {summary['time_range']['end']}")
        print(f"  [+] Span:              {summary['time_range']['span_hours']} hours")

    # 4) Generate report
    banner("[4/4] Generating report")
    out = generate_report(events, summary, output_dir)
    print(f"  [+] HTML:  {out}/timeline.html")
    print(f"  [+] JSON:  {out}/timeline.json")
    print(f"  [+] CSV:   {out}/timeline.csv")

    banner("DONE")
    print(f"  Completed at {datetime.now().isoformat(timespec='seconds')}")
    print(f"  Open the report: {out}\\timeline.html\n")


if __name__ == "__main__":
    main()