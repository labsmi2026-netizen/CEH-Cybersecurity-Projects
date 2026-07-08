# Project 3 — Multi-Router OSPF Network

A four-router ring network built in Cisco Packet Tracer, running OSPFv2 in a single backbone area and hardened with MD5 authentication against spoofed-route attacks.

## What it demonstrates

- Four Cisco 2811 routers in a redundant ring (R1–R2–R3–R4–R1)
- OSPFv2 in a single backbone area (Area 0)
- Structured addressing: /30 point-to-point serial links, /24 LANs, loopback router-IDs
- DCE/DTE clocking on serial links (`clock rate 64000`)
- Passive interfaces on LANs to suppress unnecessary hello traffic

## Verification

- All OSPF adjacencies confirmed in the **FULL** state
- Every router learned the complete network via OSPF
- End-to-end connectivity confirmed with a zero-loss ping and traceroute across the ring
- Equal-cost dual paths in the routing table demonstrate the ring's redundancy

## Security hardening

The OSPF control plane was hardened with **MD5 message-digest authentication** on every serial link. This defends against a real control-plane threat: an attacker injecting forged LSAs to redirect or blackhole traffic. After matching keys were applied, `show ip ospf interface` confirmed authentication enabled while adjacencies stayed FULL.

## Files

- `OSPF_Project3_Report.pdf` — full technical report (topology diagrams, verification screenshots, full router configs, and a professor defense Q&A)

## Stack

Cisco IOS · OSPFv2 · Cisco Packet Tracer · MD5 authentication

---
*Performed in a simulated lab environment for educational purposes.*
