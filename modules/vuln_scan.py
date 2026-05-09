import requests
from colorama import Fore, Style, init
import json
import time

init(autoreset=True)

class VulnScanner:
    def __init__(self, target, verbose=False):
        self.target = target
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    def check_open_ports_vulns(self, open_ports):
        # Simple check for common vulnerable ports
        vuln_ports = {
            21: "FTP - Check for anonymous login",
            23: "Telnet - Insecure, use SSH",
            25: "SMTP - Check for open relay",
            53: "DNS - Check for zone transfer",
            80: "HTTP - Check for outdated software",
            443: "HTTPS - Check SSL/TLS",
            3306: "MySQL - Check for weak passwords",
            3389: "RDP - Exposed remote desktop",
        }

        print(Fore.BLUE + "\n[PORT VULNERABILITIES]")
        for port in open_ports:
            if port in vuln_ports:
                print(Fore.RED + f"[!] Port {port} ({vuln_ports[port]}) - Potential vulnerability")
            else:
                print(Fore.GREEN + f"[+] Port {port} - No known issues")

    def check_web_vulns(self):
        # Check for common web vulns
        checks = [
            ('/crossdomain.xml', 'Flash cross-domain policy'),
            ('/clientaccesspolicy.xml', 'Silverlight policy'),
            ('/robots.txt', 'Robots file'),
            ('/sitemap.xml', 'Sitemap'),
        ]

        print(Fore.BLUE + "\n[WEB VULNERABILITIES]")
        for path, desc in checks:
            try:
                url = f"{self.target}{path}"
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    print(Fore.YELLOW + f"[INFO] {desc} found: {url}")
                elif self.verbose:
                    print(Fore.GREEN + f"[SAFE] {desc}: {response.status_code}")
            except Exception as e:
                if self.verbose:
                    print(Fore.RED + f"[ERROR] {desc}: {e}")

    def check_ssl_vulns(self):
        # Simple SSL check
        try:
            import ssl
            import socket
            context = ssl.create_default_context()
            with socket.create_connection((self.target.replace('https://', '').replace('http://', ''), 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target.replace('https://', '').replace('http://', '')) as ssock:
                    cert = ssock.getpeercert()
                    expiry = cert['notAfter']
                    print(Fore.BLUE + f"[SSL] Certificate expires: {expiry}")
        except Exception as e:
            print(Fore.RED + f"[SSL ERROR] {e}")

    def scan(self, open_ports=None):
        print(Fore.CYAN + "[GENERAL VULN SCAN STARTED]")
        if open_ports:
            self.check_open_ports_vulns(open_ports)
        self.check_web_vulns()
        if self.target.startswith('https'):
            self.check_ssl_vulns()
        print(Fore.CYAN + "[GENERAL VULN SCAN COMPLETED]")

def vuln_scan(target, open_ports=None, verbose=False):
    scanner = VulnScanner(target, verbose)
    scanner.scan(open_ports)