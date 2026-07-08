# Project 1 — Advanced Port Scanner

A multi-threaded TCP port scanner built from Python's standard library. It scans a target host, grabs service banners, fingerprints the OS, maps open ports to known CVEs, and generates an HTML dashboard and CSV export.

## What it does

- Multi-threaded scanning with `ThreadPoolExecutor` (200 concurrent threads)
- TCP connect scanning via `socket.connect_ex()`
- Service and banner identification (HTTP, FTP, SMTP probes)
- OS fingerprinting from TTL and banner signatures
- Built-in CVE database keyed on port number
- HTML report + CSV export generation

## Key finding

Scanned against a Windows 10 VM, the tool found 39 open ports and flagged two **critical** CVEs on SMB (port 445): **EternalBlue (CVE-2017-0144)** and **SMBGhost (CVE-2020-0796)**. Cross-validation with Nmap `-sV` revealed that most of the 39 ports were a **KFSensor honeypot** simulating services — the analysis separates those decoy ports from the genuine, exploitable SMB exposure.

## Usage

```bash
# Basic verbose scan
python3 scanner_v2.py -t <target-ip> -p 1-1024 -v

# With HTML report and CSV export (200 threads)
python3 scanner_v2.py -t <target-ip> -p 1-1024 -v -T 200 --report --csv
```

## Environment

Kali Linux (attacker) → Windows 10 VM (target), VMware Workstation, isolated lab.

## Files

- `scanner_v2.py` — the scanner source
- `Project1_Port_Scanner_v2.pdf` — full technical report

## Stack

Python 3 · `socket`, `threading`, `concurrent.futures`, `argparse`, `csv` · Nmap (validation)

---
*Performed in an authorized lab environment for educational purposes.*
