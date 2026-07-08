# Project 4 — Brute-Force Detection

A Python tool that parses SSH authentication logs in real time to detect brute-force attacks, with an automated blocking mode using iptables. Validated against a live Hydra attack.

## What it does

- Parses SSH authentication logs to detect repeated failed login attempts
- Flags source IPs that exceed a configurable failure threshold
- Optional `--block` mode automatically blocks offending IPs via iptables
- Tuned regex handles modern OpenSSH 9.8+ log formats (ISO 8601 timestamps, `sshd-session`, optional `invalid user` prefix)

## Validation

Tested against a **live Hydra brute-force attack** launched against the Kali host itself. To generate attack traffic from a distinct source, a loopback alias (`127.0.0.2`) was used with `ssh -b` for source binding. The detector correctly identified the attack and, in block mode, added an iptables rule to stop it.

## Usage

```bash
# Detection only
python3 detector.py

# Detection with automatic blocking (requires privileges for iptables)
sudo python3 detector.py --block
```

## Environment

Kali Linux (both attacker and target, for a self-contained test), OpenSSH 9.8+, isolated lab.

## Files

- `detector.py` — the detection tool
- `Project4_BruteForce_Detection_.pdf` — full technical report (with Q&A and reproduction playbook appendices)

## Stack

Python 3 · regex log parsing · iptables · Hydra (attack simulation)

---
*Performed in an authorized lab environment for educational purposes.*
