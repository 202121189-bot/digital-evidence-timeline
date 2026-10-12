# 🕵️ Digital Evidence Timeline Generator

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Domain](https://img.shields.io/badge/Domain-DFIR-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A DFIR (Digital Forensics & Incident Response) tool that merges artifacts from multiple evidence sources into a unified, chronological timeline for forensic analysis.

## ✨ Features

- 📁 **Filesystem Collector** — file create/modify/access/delete events
- 📋 **Event Log Collector** — Windows Security events (4624, 4625, 4720, 1102...)
- 🌐 **Network Collector** — connections, DNS, port scans, suspicious ports
- 👤 **User Activity Collector** — logons, sessions, privilege use
- 🔀 **Unified Timeline** — chronologically sorted, cross-source correlation
- 🚨 **Auto Interpretation** — human-readable meaning for each event
- ⚠️ **Suspicious Flagging** — highlights suspicious events with visual markers
- 🎨 **Beautiful HTML Report** — dark theme, timeline visualization
- 📊 **Multi-format Output** — HTML, JSON, CSV

## 🛠️ Requirements

- Python 3.8+
- `jinja2`

Install:

```bash
pip install -r requirements.txt