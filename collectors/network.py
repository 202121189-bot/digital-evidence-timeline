"""
Network Collector
==================
Reads network artifacts (JSON) and normalizes into timeline events.

Expected input format (JSON list):
[
  {
    "timestamp": "2026-10-12T08:20:01",
    "event": "connection",
    "src_ip": "192.168.1.10",
    "dst_ip": "185.220.101.5",
    "dst_port": 22,
    "protocol": "TCP",
    "bytes": 4096
  },
  ...
]

Supported events:
  - connection
  - disconnection
  - dns_query
  - http_request
  - port_scan
"""

import os
import json


# --------------------------------------------------------------------
# Port → service mapping (common ports)
# --------------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 27017: "MongoDB",
}

SUSPICIOUS_PORTS = {23, 135, 139, 445, 1433, 3389, 5900}

# Known-bad IP patterns (private + loopback are OK for demo)
PRIVATE_RANGES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.",
)


def _is_private(ip):
    return any(ip.startswith(p) for p in PRIVATE_RANGES)


def _interpret(event_type, dst_port, dst_ip):
    """Return human interpretation + suspicious flag."""
    suspicious = False
    base = ""

    if event_type == "connection":
        base = "Network connection"
    elif event_type == "disconnection":
        base = "Network disconnection"
    elif event_type == "dns_query":
        base = "DNS query"
    elif event_type == "http_request":
        base = "HTTP request"
    elif event_type == "port_scan":
        base = "Port scan detected"
        suspicious = True
    else:
        base = f"Network event: {event_type}"

    # Add port/service info
    if dst_port:
        try:
            port = int(dst_port)
            service = COMMON_PORTS.get(port, "")
            if service:
                base += f" to port {port} ({service})"
            else:
                base += f" to port {port}"
            if port in SUSPICIOUS_PORTS:
                suspicious = True
                base += " [!] suspicious port"
        except (ValueError, TypeError):
            pass

    # External IP hint
    if dst_ip and not _is_private(dst_ip):
        base += " — external IP"

    return base, suspicious


def collect(filepath):
    """Read network JSON and return normalized events."""
    if not os.path.exists(filepath):
        return []

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    events = []
    for item in data:
        ts = item.get("timestamp", "")
        if not ts:
            continue

        event_type = item.get("event", "connection").lower()
        dst_ip = item.get("dst_ip", "")
        dst_port = item.get("dst_port", 0)

        interpretation, suspicious = _interpret(event_type, dst_port, dst_ip)

        # Artifact label: "src → dst:port"
        src = item.get("src_ip", "")
        artifact = ""
        if src and dst_ip:
            artifact = f"{src} → {dst_ip}"
            if dst_port:
                artifact += f":{dst_port}"
        elif dst_ip:
            artifact = dst_ip

        events.append({
            "timestamp": ts,
            "artifact": artifact or "network-event",
            "source": "Network",
            "event": event_type,
            "interpretation": interpretation,
            "details": {
                "src_ip": src,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": item.get("protocol", ""),
                "bytes": item.get("bytes"),
                "suspicious": suspicious,
            },
        })

    return events