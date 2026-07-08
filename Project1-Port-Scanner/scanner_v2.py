#!/usr/bin/env python3
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
import csv
from datetime import datetime

# Predefined banner signatures for OS detection
OS_SIGNATURES = {
    b"microsoft": "Windows",
    b"msrpc": "Windows",
    b"iis": "Windows",
    b"ubuntu": "Linux",
    b"debian": "Linux",
    b"apache": "Linux",
    b"cisco": "Cisco iOS",
    b"ssh-2.0-openssh": "Linux"
}

# Local mapping for the critical CVE vulnerabilities discovered on Port 445 (SMB)
CVE_DATABASE = {
    445: [
        {"id": "CVE-2017-0144", "severity": "CRITICAL", "desc": "EternalBlue — Microsoft SMBv1 remote code execution vulnerability exploited by WannaCry ransomware."},
        {"id": "CVE-2020-0796", "severity": "CRITICAL", "desc": "SMBGhost — Microsoft SMBv3 pre-auth remote code execution. Allows a remote attacker to execute code."}
    ]
}

class AdvancedScanner:
    def __init__(self, target, ports, threads, verbose):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.verbose = verbose
        self.results = []
        self.detected_os = "Unknown"
        self.start_time = None
        self.duration = 0.0

    def grab_banner(self, sock, port):
        try:
            sock.settimeout(1.0)
            if port == 80 or port == 8080:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
            else:
                sock.sendall(b"\r\n")
            banner = sock.recv(1024)
            return banner.strip()
        except:
            return b""

    def inspect_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        status = sock.connect_ex((self.target, port))
        
        if status == 0:
            try:
                service = socket.getservbyport(port).upper()
            except:
                if port == 135: service = "MSRPC"
                elif port == 139: service = "NETBIOS-SSN"
                elif port == 445: service = "SMB"
                else: service = "UNKNOWN"

            banner = self.grab_banner(sock, port)
            
            # OS detection from banner
            for sig, os_name in OS_SIGNATURES.items():
                if sig in banner.lower():
                    self.detected_os = os_name
                    break
            
            cves = CVE_DATABASE.get(port, [])
            
            port_data = {
                "port": f"{port}/tcp",
                "state": "OPEN",
                "service": service,
                "banner": banner.decode('utf-8', errors='ignore') if banner else "None",
                "cves": cves
            }
            self.results.append(port_data)
            
            if self.verbose:
                print(f"[+] Port {port}/tcp OPEN - {service}")
                if cves:
                    for cve in cves:
                        print(f"    [!] {cve['id']} - {cve['severity']}")
        sock.close()

    def execute_scan(self):
        self.start_time = datetime.now()
        print(f"[+] Scanning {self.target}...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.inspect_port, self.ports)
        end_time = datetime.now()
        self.duration = round((end_time - self.start_time).total_seconds(), 2)
        
        # Fallback OS detection if banner failed but we see typical Windows ports
        if self.detected_os == "Unknown" and any(p['port'] == '445/tcp' for p in self.results):
            self.detected_os = "Windows"
        
        print(f"[+] Scan completed in {self.duration} seconds")
        print(f"[+] Found {len(self.results)} open ports")

    def generate_html_report(self, filename=None):
        """Generate an HTML report of the scan results"""
        if not filename:
            filename = f"scan_report_{self.target.replace('.', '_')}.html"
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Advanced Port Scanner Report</title>
    <style>
        body {{ background: #1a1a2e; color: #e0e0e0; font-family: Arial, sans-serif; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; }}
        .summary {{ background: #16213e; padding: 20px; border-radius: 10px; margin: 20px 0; }}
        .metrics {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .metric {{ background: #0f3460; padding: 15px; border-radius: 8px; flex: 1; min-width: 150px; }}
        .metric-value {{ font-size: 24px; color: #00d4ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #00d4ff; color: #1a1a2e; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #333; }}
        .critical {{ color: #ff6b6b; font-weight: bold; }}
        .medium {{ color: #ffd93d; }}
        .cve-box {{ background: #2d2d44; padding: 10px; border-radius: 5px; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Advanced Port Scanner Report</h1>
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="metrics">
                <div class="metric"><strong>Target</strong><br><span class="metric-value">{self.target}</span></div>
                <div class="metric"><strong>Open Ports</strong><br><span class="metric-value">{len(self.results)}</span></div>
                <div class="metric"><strong>Scan Duration</strong><br><span class="metric-value">{self.duration}s</span></div>
                <div class="metric"><strong>OS Detected</strong><br><span class="metric-value">{self.detected_os}</span></div>
            </div>
        </div>
        <h2>📊 Discovered Ports</h2>
        <table>
            <tr><th>Port</th><th>Service</th><th>CVEs</th><th>Risk Level</th></tr>
"""
        for result in self.results:
            cves_html = ""
            risk = "LOW"
            if result['cves']:
                for cve in result['cves']:
                    cves_html += f"<div class='cve-box'><strong>{cve['id']}</strong> - {cve['desc']}</div>"
                    risk = "CRITICAL"
            elif result['service'] in ["MSRPC", "NETBIOS-SSN"]:
                risk = "MEDIUM"
            
            risk_class = "critical" if risk == "CRITICAL" else "medium"
            html_content += f"""
            <tr>
                <td><strong>{result['port']}</strong></td>
                <td>{result['service']}</td>
                <td>{cves_html if cves_html else "None"}</td>
                <td class="{risk_class}">{risk}</td>
            </tr>
"""
        html_content += """
        </table>
        <div style="margin-top: 40px; color: #888; font-size: 12px; border-top: 1px solid #333; padding-top: 20px;">
            Generated by Advanced Port Scanner v2.0 | Date: """ + datetime.now().strftime("%B %d, %Y") + """
        </div>
    </div>
</body>
</html>
"""
        with open(filename, 'w') as f:
            f.write(html_content)
        print(f"[+] HTML report saved: {filename}")

    def generate_csv(self, filename=None):
        """Generate a CSV export of the scan results"""
        if not filename:
            filename = f"scan_{self.target.replace('.', '_')}.csv"
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Port', 'State', 'Service', 'Banner', 'CVEs', 'Severity'])
            for result in self.results:
                cve_ids = ", ".join([cve['id'] for cve in result['cves']])
                severity = "CRITICAL" if result['cves'] else "MEDIUM" if result['service'] in ["MSRPC", "NETBIOS-SSN"] else "LOW"
                writer.writerow([
                    result['port'],
                    result['state'],
                    result['service'],
                    result['banner'][:100],  # Truncate long banners
                    cve_ids,
                    severity
                ])
        print(f"[+] CSV saved: {filename}")


def parse_port_range(port_str):
    """Parse port range like '1-1024' or list like '80,443,8080'"""
    if '-' in port_str:
        start, end = port_str.split('-')
        return list(range(int(start), int(end) + 1))
    elif ',' in port_str:
        return [int(p.strip()) for p in port_str.split(',')]
    else:
        return [int(port_str)]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Threaded Vulnerability Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--ports", required=True, help="Port range to scan (e.g., 1-1024)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-T", "--threads", type=int, default=200, help="Number of threads (default: 200)")
    parser.add_argument("--report", action="store_true", help="Generate HTML report")
    parser.add_argument("--csv", action="store_true", help="Generate CSV export")
    args = parser.parse_args()

    # Parse ports
    ports_to_scan = parse_port_range(args.ports)
    
    # Create and run scanner
    scanner = AdvancedScanner(args.target, ports_to_scan, args.threads, args.verbose)
    scanner.execute_scan()
    
    # Generate reports if requested
    if args.report:
        scanner.generate_html_report()
    if args.csv:
        scanner.generate_csv()
