"""
File System Collector
======================
Reads a JSON file containing filesystem artifacts and normalizes
them into timeline events.

Expected input format (JSON list):
[
  {
    "path": "C:/Users/admin/document.docx",
    "event": "modified",
    "timestamp": "2026-10-12T08:15:23",
    "size": 45678,
    "hash": "abc123..."
  },
  ...
]

Supported events:
  - created
  - modified
  - accessed
  - deleted
"""

import os
import json


# --------------------------------------------------------------------
# Interpretation rules
# --------------------------------------------------------------------

INTERPRETATIONS = {
    "created": "File created — possible new artifact",
    "modified": "File modified — possible tampering or update",
    "accessed": "File accessed — possible reconnaissance or exfiltration",
    "deleted": "File deleted — possible anti-forensics",
}


def _interpret(event_type, path):
    """Return a short human interpretation of the event."""
    base = INTERPRETATIONS.get(event_type, "Unknown filesystem event")

    # Add path-based hints
    lower = path.lower()
    if any(x in lower for x in [".exe", ".dll", ".bat", ".ps1", ".vbs"]):
        base += " (executable/script file)"
    elif any(x in lower for x in [".log", ".txt", ".csv"]):
        base += " (text/log file)"
    elif any(x in lower for x in [".jpg", ".png", ".pdf", ".docx"]):
        base += " (document/media file)"

    return base


def collect(filepath):
    """Read filesystem artifact JSON and return normalized events."""
    if not os.path.exists(filepath):
        return []

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for item in data:
        path = item.get("path", "")
        event_type = item.get("event", "").lower()
        timestamp = item.get("timestamp", "")

        if not timestamp:
            continue

        events.append({
            "timestamp": timestamp,
            "artifact": os.path.basename(path) or path,
            "full_path": path,
            "source": "Filesystem",
            "event": event_type,
            "interpretation": _interpret(event_type, path),
            "details": {
                "size": item.get("size"),
                "hash": item.get("hash", ""),
            },
        })

    return events