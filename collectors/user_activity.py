"""
User Activity Collector
========================
Reads user activity artifacts (JSON) and normalizes into timeline events.

Expected input format (JSON list):
[
  {
    "timestamp": "2026-10-12T09:00:00",
    "user": "admin",
    "event": "logon",
    "session_id": "S-1-5-21-...",
    "computer": "WS01"
  },
  ...
]

Supported events:
  - logon
  - logoff
  - session_start
  - session_end
  - password_change
  - account_locked
  - privilege_use
"""

import os
import json


INTERPRETATIONS = {
    "logon":           "User logon — legitimate or suspicious",
    "logoff":          "User logoff",
    "session_start":   "Session started",
    "session_end":     "Session ended",
    "password_change": "Password changed",
    "account_locked":  "Account locked out — possible brute force",
    "privilege_use":   "Privileged action performed",
}

SUSPICIOUS_EVENTS = {"account_locked", "privilege_use", "password_change"}


def _interpret(event_type, user):
    suspicious = event_type in SUSPICIOUS_EVENTS
    base = INTERPRETATIONS.get(event_type, f"User event: {event_type}")
    if user:
        base = f"[{user}] {base}"
    if suspicious:
        base = "[!] " + base
    return base, suspicious


def collect(filepath):
    """Read user activity JSON and return normalized events."""
    if not os.path.exists(filepath):
        return []

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for item in data:
        ts = item.get("timestamp", "")
        if not ts:
            continue

        user = item.get("user", "")
        event_type = item.get("event", "").lower()
        interpretation, suspicious = _interpret(event_type, user)

        artifact = user or "unknown-user"

        events.append({
            "timestamp": ts,
            "artifact": artifact,
            "source": "UserActivity",
            "event": event_type,
            "interpretation": interpretation,
            "details": {
                "user": user,
                "session_id": item.get("session_id", ""),
                "computer": item.get("computer", ""),
                "suspicious": suspicious,
            },
        })

    return events