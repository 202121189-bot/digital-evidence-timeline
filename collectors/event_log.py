"""
Event Log Collector
====================
Reads Windows Event Log artifacts (JSON) and normalizes into timeline events.

Expected input format (JSON list):
[
  {
    "event_id": 4624,
    "timestamp": "2026-10-12T08:25:45",
    "user": "admin",
    "source_ip": "192.168.1.10",
    "computer": "WORKSTATION01"
  },
  ...
]

Key Windows Security Event IDs:
  4624 - Successful logon
  4625 - Failed logon
  4634 - Logoff
  4648 - Logon with explicit credentials
  4672 - Special privileges assigned
  4720 - User account created
  4726 - User account deleted
  4728 - User added to security group
  4732 - User added to local group
  1102 - Audit log cleared
"""

import os
import json


# --------------------------------------------------------------------
# Event ID catalog
# --------------------------------------------------------------------

EVENT_CATALOG = {
    4624: ("logon_success", "Successful logon"),
    4625: ("logon_failed",  "Failed logon attempt"),
    4634: ("logoff",        "User logoff"),
    4648: ("logon_explicit","Logon with explicit credentials"),
    4672: ("privilege",     "Special privileges assigned"),
    4720: ("user_created",  "User account created"),
    4726: ("user_deleted",  "User account deleted"),
    4728: ("group_add",     "User added to global group"),
    4732: ("localgroup_add","User added to local group"),
    1102: ("log_cleared",   "Audit log was cleared"),
}

SUSPICIOUS_IDS = {1102, 4720, 4726, 4728, 4732, 4648}


def _interpret(event_id):
    """Return (event_type, description, is_suspicious)."""
    if event_id in EVENT_CATALOG:
        etype, desc = EVENT_CATALOG[event_id]
        suspicious = event_id in SUSPICIOUS_IDS
        return etype, desc, suspicious
    return "unknown", f"Unmapped event ID {event_id}", False


def collect(filepath):
    """Read event log JSON and return normalized events."""
    if not os.path.exists(filepath):
        return []

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for item in data:
        ts = item.get("timestamp", "")
        if not ts:
            continue

        event_id = item.get("event_id")
        user = item.get("user", "")
        source_ip = item.get("source_ip", "")

        etype, desc, suspicious = _interpret(event_id)

        # Artifact label
        artifact = f"EventID:{event_id}"
        if user:
            artifact += f" / {user}"

        # Build interpretation
        interpretation = desc
        if source_ip:
            interpretation += f" from {source_ip}"
        if suspicious:
            interpretation = "[!] " + interpretation

        events.append({
            "timestamp": ts,
            "artifact": artifact,
            "source": "EventLog",
            "event": etype,
            "interpretation": interpretation,
            "details": {
                "event_id": event_id,
                "user": user,
                "source_ip": source_ip,
                "computer": item.get("computer", ""),
                "suspicious": suspicious,
            },
        })

    return events