#!/usr/bin/env python3
# =====================================================================
#  Mini SIEM  -  CEH Final Project 5
#  Author: Anwar  (kalibaba@Kalibaba)
# ---------------------------------------------------------------------
#  What this tool does:
#    1. COLLECTS logs from SSH, Apache and the Firewall (UFW)
#    2. NORMALISES every log line into one common event format
#    3. CORRELATES events with detection rules (brute force, port
#       scan, web scan, web attack, successful brute force)
#    4. MAPS every alert to a MITRE ATT&CK tactic + technique
#    5. GENERATES a professional HTML dashboard report
#
#  No external libraries needed - pure Python 3 standard library.
#  Run it with sudo so it can read the log files in /var/log.
# =====================================================================

import os
import re
import sys
import html
import socket
from urllib.parse import unquote_plus
from collections import defaultdict, Counter
from datetime import datetime

# ---------------------------------------------------------------------
#  CONFIGURATION  (easy to explain to the professor - all rules here)
# ---------------------------------------------------------------------
CURRENT_YEAR = datetime.now().year

# Where we read the real logs from on Kali.
LOG_SOURCES = {
    "ssh":      ["/var/log/auth.log"],
    "apache":   ["/var/log/apache2/other_vhosts_access.log", "/var/log/apache2/access.log"],
    "firewall": ["/var/log/ufw.log", "/var/log/kern.log"],
}

# Detection thresholds - how many events before we raise an alert.
SSH_BRUTE_THRESHOLD   = 5    # failed SSH logins from one IP
PORTSCAN_PORT_COUNT   = 10   # different ports one IP was blocked hitting
WEB_SCAN_404_COUNT    = 15   # 404 responses from one IP (dir busting)

# User-agent strings that mean an automated scanning tool.
SCANNER_AGENTS = ["nikto", "sqlmap", "nmap", "dirb", "gobuster",
                  "masscan", "wpscan", "hydra", "nessus", "acunetix"]

# Patterns inside a URL that mean an active web attack.
WEB_ATTACK_PATTERNS = [
    (r"union\s+select",        "SQL Injection (UNION)"),
    (r"'\s*or\s*'?1'?\s*=\s*'?1", "SQL Injection (OR 1=1)"),
    (r"\.\./\.\./",            "Path Traversal"),
    (r"/etc/passwd",           "Path Traversal (/etc/passwd)"),
    (r"<script>",              "Cross-Site Scripting (XSS)"),
    (r";\s*(cat|id|whoami|uname)", "Command Injection"),
]

# MITRE ATT&CK reference table - the heart of the mapping step.
MITRE = {
    "ssh_brute_force":     {"tactic": "Credential Access",  "id": "T1110",   "name": "Brute Force"},
    "brute_force_success": {"tactic": "Credential Access",  "id": "T1110",   "name": "Brute Force (Successful)"},
    "port_scan":           {"tactic": "Discovery",          "id": "T1046",   "name": "Network Service Discovery"},
    "web_scan":            {"tactic": "Reconnaissance",     "id": "T1595",   "name": "Active Scanning"},
    "web_attack":          {"tactic": "Initial Access",     "id": "T1190",   "name": "Exploit Public-Facing Application"},
}

OUTPUT_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "siem_dashboard.html")

# ---------------------------------------------------------------------
#  Small helpers
# ---------------------------------------------------------------------
SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")

def parse_syslog_time(line):
    """Turn a 'Jul  4 17:23:45' syslog prefix into a datetime."""
    m = SYSLOG_TS.match(line)
    if not m:
        return None, ""
    raw = m.group(1)
    try:
        dt = datetime.strptime(f"{CURRENT_YEAR} {raw}", "%Y %b %d %H:%M:%S")
        return dt, raw
    except ValueError:
        return None, raw

def read_lines(paths):
    """Read the first log file in the list that exists and is readable."""
    for p in paths:
        if os.path.isfile(p):
            if not os.access(p, os.R_OK):
                print(f"[!] Cannot read {p} - try running with: sudo python3 siem.py")
                continue
            try:
                with open(p, "r", errors="ignore") as f:
                    return p, f.readlines()
            except Exception as e:
                print(f"[!] Error reading {p}: {e}")
    return None, []

# ---------------------------------------------------------------------
#  STEP 1 + 2 : COLLECT and NORMALISE
#  Every parser returns events in ONE common schema (a dict).
# ---------------------------------------------------------------------
def event(ts, ts_raw, source, etype, src_ip, detail, severity, raw):
    return {"ts": ts, "ts_raw": ts_raw, "source": source, "etype": etype,
            "src_ip": src_ip, "detail": detail, "severity": severity,
            "raw": raw.strip()}

RE_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
RE_SSH_OK   = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")

def parse_ssh(lines):
    events = []
    for line in lines:
        if "sshd" not in line:
            continue
        ts, ts_raw = parse_syslog_time(line)
        m = RE_SSH_FAIL.search(line)
        if m:
            events.append(event(ts, ts_raw, "ssh", "auth_failure", m.group(2),
                                 f"Failed SSH login for user '{m.group(1)}'", "low", line))
            continue
        m = RE_SSH_OK.search(line)
        if m:
            events.append(event(ts, ts_raw, "ssh", "auth_success", m.group(2),
                                 f"Successful SSH login for user '{m.group(1)}'", "info", line))
    return events

RE_APACHE = re.compile(
    r'^(?:\S+:\d+\s+)?(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\S+)\s+"[^"]*"\s+"([^"]*)"')

def parse_apache(lines):
    events = []
    for line in lines:
        m = RE_APACHE.match(line)
        if not m:
            continue
        ip, ts_raw, method, path, status, size, agent = m.groups()
        try:
            ts = datetime.strptime(ts_raw.split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            ts = None
        # Decode %27 / %20 / + so encoded sqlmap-style payloads are visible.
        path_decoded = unquote_plus(path)
        detail = f'{method} {path} -> {status}  (UA: {agent[:60]})'
        sev = "medium" if status.startswith(("4", "5")) else "info"
        ev = event(ts, ts_raw, "apache", "http_request", ip, detail, sev, line)
        ev["status"] = status
        ev["path"]   = path_decoded
        ev["agent"]  = agent
        events.append(ev)
    return events

RE_FW = re.compile(r"SRC=(\d+\.\d+\.\d+\.\d+).*?(?:DPT=(\d+))?")
def parse_firewall(lines):
    events = []
    for line in lines:
        if "UFW BLOCK" not in line and "IPTABLES" not in line and "[UFW" not in line:
            continue
        ts, ts_raw = parse_syslog_time(line)
        m_src = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
        m_dpt = re.search(r"DPT=(\d+)", line)
        m_proto = re.search(r"PROTO=(\S+)", line)
        if not m_src:
            continue
        dpt = m_dpt.group(1) if m_dpt else "?"
        proto = m_proto.group(1) if m_proto else "?"
        ev = event(ts, ts_raw, "firewall", "fw_block", m_src.group(1),
                   f"Firewall blocked {proto} packet to port {dpt}", "low", line)
        ev["dpt"] = dpt
        events.append(ev)
    return events

def collect_events():
    all_events = []
    used_sources = {}
    parsers = {"ssh": parse_ssh, "apache": parse_apache, "firewall": parse_firewall}
    for source, paths in LOG_SOURCES.items():
        path, lines = read_lines(paths)
        used_sources[source] = path if path else "(not found)"
        if lines:
            evs = parsers[source](lines)
            all_events.extend(evs)
            print(f"[+] {source:9s}: read {len(lines):5d} lines from {path}  ->  {len(evs)} events")
        else:
            print(f"[-] {source:9s}: no readable log found in {paths}")
    return all_events, used_sources

# ---------------------------------------------------------------------
#  STEP 3 + 4 : CORRELATE and MAP TO MITRE
# ---------------------------------------------------------------------
def make_alert(rule_key, src_ip, count, detail, severity, evidence):
    m = MITRE[rule_key]
    return {"rule": rule_key, "src_ip": src_ip, "count": count, "detail": detail,
            "severity": severity, "mitre_id": m["id"], "mitre_name": m["name"],
            "tactic": m["tactic"], "evidence": evidence[:3]}

def correlate(events):
    alerts = []

    fails_by_ip   = defaultdict(list)
    success_by_ip = set()
    fw_by_ip      = defaultdict(list)
    web404_by_ip  = defaultdict(list)
    web_by_ip     = defaultdict(list)

    for e in events:
        if e["etype"] == "auth_failure":
            fails_by_ip[e["src_ip"]].append(e)
        elif e["etype"] == "auth_success":
            success_by_ip.add(e["src_ip"])
        elif e["etype"] == "fw_block":
            fw_by_ip[e["src_ip"]].append(e)
        elif e["etype"] == "http_request":
            web_by_ip[e["src_ip"]].append(e)
            if e.get("status", "").startswith("4"):
                web404_by_ip[e["src_ip"]].append(e)

    # Rule 1 - SSH brute force
    for ip, evs in fails_by_ip.items():
        if len(evs) >= SSH_BRUTE_THRESHOLD:
            alerts.append(make_alert("ssh_brute_force", ip, len(evs),
                f"{len(evs)} failed SSH logins from {ip}", "high", [x["raw"] for x in evs]))
            # Rule 2 - successful login after a burst of failures = cracked!
            if ip in success_by_ip:
                alerts.append(make_alert("brute_force_success", ip, len(evs),
                    f"Successful SSH login from {ip} after {len(evs)} failures - possible account compromise",
                    "critical", [x["raw"] for x in evs]))

    # Rule 3 - port scan (one IP blocked hitting many different ports)
    for ip, evs in fw_by_ip.items():
        ports = {e.get("dpt", "?") for e in evs}
        if len(ports) >= PORTSCAN_PORT_COUNT:
            alerts.append(make_alert("port_scan", ip, len(ports),
                f"{ip} was blocked probing {len(ports)} different ports", "high",
                [x["raw"] for x in evs]))

    # Rule 4 - web scanning (scanner user-agent OR lots of 404s)
    for ip, evs in web_by_ip.items():
        agent_hit = next((a for e in evs for a in SCANNER_AGENTS
                          if a in e.get("agent", "").lower()), None)
        n404 = len(web404_by_ip.get(ip, []))
        if agent_hit:
            alerts.append(make_alert("web_scan", ip, len(evs),
                f"{ip} used a known scanning tool (user-agent contains '{agent_hit}')",
                "high", [x["raw"] for x in evs]))
        elif n404 >= WEB_SCAN_404_COUNT:
            alerts.append(make_alert("web_scan", ip, n404,
                f"{ip} generated {n404} '404 Not Found' responses (directory brute forcing)",
                "medium", [x["raw"] for x in web404_by_ip[ip]]))

    # Rule 5 - web attack payloads (AGGREGATED per IP + attack type).
    web_attacks = defaultdict(lambda: {"count": 0, "sample": "", "evidence": []})
    for ip, evs in web_by_ip.items():
        for e in evs:
            path = e.get("path", "").lower()
            for pattern, label in WEB_ATTACK_PATTERNS:
                if re.search(pattern, path):
                    rec = web_attacks[(ip, label)]
                    rec["count"] += 1
                    if not rec["sample"]:
                        rec["sample"] = e.get("path", "")[:80]
                    if len(rec["evidence"]) < 3:
                        rec["evidence"].append(e["raw"])
                    break
    for (ip, label), rec in web_attacks.items():
        n = rec["count"]
        times = f" (x{n} requests)" if n > 1 else ""
        alerts.append(make_alert("web_attack", ip, n,
            f"{label} from {ip}{times} - e.g. {rec['sample']}",
            "critical", rec["evidence"]))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    alerts.sort(key=lambda a: order.get(a["severity"], 9))
    return alerts

# ---------------------------------------------------------------------
#  STEP 5 : GENERATE HTML DASHBOARD  (navy / blue professional theme)
# ---------------------------------------------------------------------
SEV_COLOR = {"critical": "#b00020", "high": "#e65100",
             "medium": "#f9a825", "low": "#2e7d32", "info": "#607d8b"}

def esc(x):
    return html.escape(str(x))

def build_dashboard(events, alerts, used_sources, hostname):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_events = len(events)
    total_alerts = len(alerts)
    crit_high = sum(1 for a in alerts if a["severity"] in ("critical", "high"))
    unique_ips = len({e["src_ip"] for e in events if e["src_ip"]})

    by_source = Counter(e["source"] for e in events)
    top_ips   = Counter(e["src_ip"] for e in events if e["src_ip"]).most_common(8)

    # --- summary cards ---
    cards = [
        ("Total Events", total_events, "#1565c0"),
        ("Alerts Raised", total_alerts, "#e65100"),
        ("Critical / High", crit_high, "#b00020"),
        ("Unique Source IPs", unique_ips, "#00695c"),
    ]
    cards_html = "".join(
        f'<div class="card" style="border-top:4px solid {c}">'
        f'<div class="cardnum">{v}</div><div class="cardlbl">{esc(l)}</div></div>'
        for l, v, c in cards)

    # --- alerts table ---
    if alerts:
        rows = ""
        for a in alerts:
            color = SEV_COLOR.get(a["severity"], "#607d8b")
            evidence = "<br>".join(esc(x) for x in a["evidence"])
            rows += (
                f'<tr>'
                f'<td><span class="pill" style="background:{color}">{esc(a["severity"].upper())}</span></td>'
                f'<td>{esc(a["detail"])}</td>'
                f'<td><code>{esc(a["src_ip"])}</code></td>'
                f'<td><b>{esc(a["mitre_id"])}</b><br>{esc(a["mitre_name"])}</td>'
                f'<td>{esc(a["tactic"])}</td>'
                f'<td class="evidence">{evidence}</td>'
                f'</tr>')
        alerts_table = (
            '<table><thead><tr>'
            '<th>Severity</th><th>Alert</th><th>Source IP</th>'
            '<th>MITRE ATT&amp;CK</th><th>Tactic</th><th>Evidence (sample)</th>'
            '</tr></thead><tbody>' + rows + '</tbody></table>')
    else:
        alerts_table = '<p class="ok">No alerts triggered - no suspicious activity detected in the collected logs.</p>'

    # --- source + top IP tables ---
    src_rows = "".join(
        f'<tr><td>{esc(s)}</td><td><code>{esc(used_sources.get(s,""))}</code></td>'
        f'<td>{by_source.get(s,0)}</td></tr>'
        for s in ("ssh", "apache", "firewall"))
    ip_rows = "".join(
        f'<tr><td><code>{esc(ip)}</code></td><td>{n}</td></tr>'
        for ip, n in top_ips) or '<tr><td colspan="2">No events</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mini SIEM Dashboard - CEH Project 5</title>
<style>
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:'Segoe UI',Arial,sans-serif; background:#eef1f5; color:#1a2130; }}
  header {{ background:linear-gradient(135deg,#0f1e3d,#1a2942); color:#fff; padding:26px 34px; }}
  header h1 {{ margin:0; font-size:24px; letter-spacing:.5px; }}
  header p {{ margin:6px 0 0; color:#9fb3d1; font-size:13px; }}
  .wrap {{ max-width:1150px; margin:0 auto; padding:24px 20px 60px; }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin:22px 0; }}
  .card {{ flex:1; min-width:180px; background:#fff; border-radius:8px; padding:18px 20px;
           box-shadow:0 1px 4px rgba(0,0,0,.08); }}
  .cardnum {{ font-size:34px; font-weight:700; color:#0f1e3d; }}
  .cardlbl {{ font-size:12px; text-transform:uppercase; letter-spacing:1px; color:#66748c; margin-top:4px; }}
  h2 {{ color:#0f1e3d; border-left:4px solid #1565c0; padding-left:10px; margin-top:34px; font-size:18px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:8px;
           overflow:hidden; box-shadow:0 1px 4px rgba(0,0,0,.08); font-size:13px; }}
  th {{ background:#1a2942; color:#fff; text-align:left; padding:10px 12px; font-weight:600; }}
  td {{ padding:9px 12px; border-top:1px solid #e5e9f0; vertical-align:top; }}
  tr:hover td {{ background:#f5f8fc; }}
  code {{ background:#eef1f5; padding:1px 5px; border-radius:3px; font-family:Consolas,monospace; font-size:12px; }}
  .pill {{ color:#fff; padding:3px 9px; border-radius:12px; font-size:11px; font-weight:700; }}
  .evidence {{ font-family:Consolas,monospace; font-size:11px; color:#555; max-width:340px; word-break:break-all; }}
  .ok {{ background:#e8f5e9; color:#2e7d32; padding:14px; border-radius:8px; }}
  footer {{ text-align:center; color:#8894a8; font-size:12px; margin-top:40px; }}
</style></head>
<body>
<header>
  <h1>&#128737; Mini SIEM Dashboard</h1>
  <p>CEH Final Project 5 &nbsp;&bull;&nbsp; Host: {esc(hostname)} &nbsp;&bull;&nbsp; Generated: {esc(now)}</p>
</header>
<div class="wrap">
  <div class="cards">{cards_html}</div>

  <h2>Security Alerts &amp; MITRE ATT&amp;CK Mapping</h2>
  {alerts_table}

  <h2>Log Sources Collected</h2>
  <table><thead><tr><th>Source</th><th>Log File</th><th>Events Parsed</th></tr></thead>
  <tbody>{src_rows}</tbody></table>

  <h2>Top Source IP Addresses</h2>
  <table><thead><tr><th>Source IP</th><th>Event Count</th></tr></thead>
  <tbody>{ip_rows}</tbody></table>

  <footer>Generated by Mini SIEM &bull; CEH Final Project 5 &bull; kalibaba@Kalibaba</footer>
</div>
</body></html>"""

# ---------------------------------------------------------------------
#  MAIN
# ---------------------------------------------------------------------
def main():
    hostname = socket.gethostname()
    print("=" * 60)
    print("  Mini SIEM  -  CEH Final Project 5")
    print("=" * 60)

    print("\n[ STEP 1+2 ]  Collecting and normalising logs...")
    events, used_sources = collect_events()

    print("\n[ STEP 3+4 ]  Correlating events and mapping to MITRE ATT&CK...")
    alerts = correlate(events)
    print(f"[+] {len(alerts)} alert(s) generated from {len(events)} event(s).")
    for a in alerts:
        print(f"    [{a['severity'].upper():8s}] {a['mitre_id']:6s} {a['detail']}")

    print("\n[ STEP 5 ]  Building HTML dashboard...")
    html_out = build_dashboard(events, alerts, used_sources, hostname)
    with open(OUTPUT_HTML, "w") as f:
        f.write(html_out)
    print(f"[+] Dashboard written to: {OUTPUT_HTML}")
    print("\n[ DONE ]  Open the dashboard in a browser:")
    print(f"    firefox {OUTPUT_HTML} &")

if __name__ == "__main__":
    main()
