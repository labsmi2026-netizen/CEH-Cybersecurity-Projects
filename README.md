# CEH Cybersecurity Final Projects

**Student:** Anwar
**Program:** Certified Ethical Hacker (CEH) — Practical Training
**Environment:** Kali Linux + Windows 10 (VMware Workstation) · Cisco Packet Tracer

---

## Overview

This repository contains five hands-on final projects completed for the Certified Ethical Hacker practical program. Each project pairs working code or a device configuration with a full technical report, and demonstrates a distinct area of offensive and defensive security: network scanning, secure automation, routing, attack detection, and log correlation.

Every report documents the objective, methodology, live results (with screenshots), a security-hardening discussion, and a defense Q&A.

---

## Projects

| # | Project | Focus | Stack | Report |
|---|---------|-------|-------|--------|
| 1 | [Advanced Port Scanner](Project1-Port-Scanner) | Multi-threaded TCP port scanning and service/CVE identification | Python | [PDF](Project1-Port-Scanner/Project1_Port_Scanner_v2.pdf) |
| 2 | [Linux Backup Automation](Project2-Linux-Backup) | Scheduled system backups with integrity verification | Bash | [PDF](Project2-Linux-Backup/Project2_Backup_Report.pdf) |
| 3 | [Multi-Router OSPF Network](Project3-OSPF-Network) | Redundant-ring OSPFv2 network hardened with MD5 authentication | Cisco IOS / Packet Tracer | [PDF](Project3-OSPF-Network/OSPF_Project3_Report.pdf) |
| 4 | [Brute-Force Detection](Project4-Brute-Force-Detection) | Real-time SSH brute-force detection and automated blocking | Python | [PDF](Project4-Brute-Force-Detection/Project4_BruteForce_Detection_.pdf) |
| 5 | [Mini SIEM](Project5-SIEM) | Multi-source log correlation mapped to MITRE ATT&CK | Python | [PDF](Project5-SIEM/CEH_Project5_Mini_SIEM_Report.pdf) |

---

## Project Details

### Project 1 — Advanced Port Scanner
A multi-threaded TCP port scanner written in Python. It scans a target host, identifies open ports and running services, and flags known vulnerabilities (including EternalBlue and SMBGhost on SMB/445). Tested against a Windows VM in an isolated lab.

### Project 2 — Linux Backup Automation
A Bash script that backs up critical system directories (`/etc`, `/var/log`), generates SHA-256 checksums for integrity verification, and runs on a schedule via cron. The report covers a real disk-fill incident and the exclusion fix that resolved it.

### Project 3 — Multi-Router OSPF Network
A four-router ring topology built in Cisco Packet Tracer running OSPFv2 in a single backbone area. Full adjacency, complete route distribution, and end-to-end connectivity were verified, then the control plane was hardened with MD5 neighbor authentication to defend against spoofed-LSA injection.

### Project 4 — Brute-Force Detection
A Python tool that parses SSH authentication logs in real time to detect brute-force attempts, with an automated blocking mode using iptables. Validated against a live Hydra attack, with regex tuned for modern OpenSSH log formats.

### Project 5 — Mini SIEM
A lightweight SIEM built with the Python standard library. It ingests authentication, web-server, and firewall logs, applies correlation rules mapped to MITRE ATT&CK techniques (T1110, T1046, T1595, T1190), and raises alerts. Validated end-to-end against a live multi-stage attack chain.

---

## Skills Demonstrated

- **Offensive:** port scanning, service enumeration, brute-force attacks, vulnerability identification
- **Defensive:** intrusion detection, automated response, log correlation, SIEM design, MITRE ATT&CK mapping
- **Networking:** OSPF design and verification, subnetting, routing-protocol hardening
- **Automation & scripting:** Python (multi-threading, log parsing, stdlib tooling), Bash, cron
- **Tooling & environment:** Kali Linux, Cisco Packet Tracer, VMware, iptables, Hydra, Nikto

---

## Repository Structure

```
CEH-Cybersecurity-Projects/
├── Project1-Port-Scanner/
├── Project2-Linux-Backup/
├── Project3-OSPF-Network/
├── Project4-Brute-Force-Detection/
├── Project5-SIEM/
└── README.md
```

---

*All work was performed in an isolated, authorized lab environment for educational purposes.*
