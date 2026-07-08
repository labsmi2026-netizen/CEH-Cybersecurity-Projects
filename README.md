# CEH Cybersecurity Final Projects

**Student:** Anwar  
**Program:** Certified Ethical Hacker (CEH) Practical Training  
**Deadline:** July 15, 2026  
**Environment:** Kali Linux + Windows 10 (VMware Workstation)

---

## Project Overview

This repository contains all 5 final cybersecurity projects completed as part of the CEH practical training program. Each project demonstrates real hands-on skills in networking, scripting, security monitoring, and ethical hacking.

---

## Projects

### Project 1 — Advanced Port Scanner
- **Language:** Python 3
- **Features:** Multi-threaded TCP scanning, banner grabbing, OS fingerprinting, CVE lookup, HTML report generation
- **Target:** Windows 10 VM (real VMware environment)
- **Result:** Discovered 3 open ports with 2 critical CVEs (EternalBlue, SMBGhost)

### Project 2 — Linux Backup Automation
- **Language:** Bash Shell Script
- **Features:** rsync backup, tar.gz compression, SHA-256 checksums, backup rotation, cron scheduling
- **Result:** Backed up 505,744 files, 43G archive, automated daily at 02:00 AM

### Project 3 — Multi-Router OSPF Network
- **Tool:** Cisco Packet Tracer
- **Features:** 4-router ring topology, OSPFv2, WIC-2T serial modules, full adjacency, end-to-end ping
- **Result:** OSPF FULL adjacency on all routers, 0% packet loss across all LANs

### Project 4 — Brute Force Detection Tool
- **Language:** Python 3
- **Features:** Real-time SSH log monitoring, Hydra attack simulation, iptables auto-blocking, alert logging
- **Result:** Successfully detected and blocked real brute
