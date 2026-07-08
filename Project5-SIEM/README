# Project 5 — Mini SIEM

A lightweight Security Information and Event Management tool built entirely with the Python standard library. It ingests logs from multiple sources, correlates events against rules mapped to MITRE ATT&CK, and raises alerts.

## What it does

- Ingests three log sources: authentication (`auth.log`), Apache web-server (`other_vhosts_access.log`), and firewall (UFW)
- Applies five correlation rules mapped to **MITRE ATT&CK** techniques:
  - T1110 — Brute Force
  - T1046 — Network Service Discovery
  - T1595 — Active Scanning
  - T1190 — Exploit Public-Facing Application
- Aggregates related events to avoid alert flooding
- Raises structured alerts with technique attribution

## Validation

Processed **7,537 events** and generated **14 alerts**. Validated end-to-end against a live multi-stage attack chain: a Hydra brute-force, a Nikto web scan, and a PowerShell port sweep — each correctly detected and mapped to its ATT&CK technique. An alert-aggregation fix was applied to prevent Nikto's rapid requests from flooding the alert output.

## Usage

```bash
# Run the SIEM against the configured log sources
python3 siem.py
```

## Environment

Kali Linux, standard-library Python only (no external dependencies), isolated lab.

## Files

- `siem.py` — the SIEM tool
- `CEH_Project5_Mini_SIEM_Report.pdf` — full technical report

## Stack

Python 3 (stdlib only) · log correlation · MITRE ATT&CK mapping

---
*Performed in an authorized lab environment for educational purposes.*
