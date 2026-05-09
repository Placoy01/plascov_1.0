import requests
from colorama import Fore, Style, init
import re
import time

init(autoreset=True)

class WebVulnScanner:
    def __init__(self, target, verbose=False):
        # Add schema if missing
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.session.verify = False

    def check_server_info(self):
        try:
            response = self.session.get(self.target, timeout=10)
            server = response.headers.get('Server', 'Unknown')
            print(Fore.BLUE + f"[SERVER] {server}")
            return server
        except Exception as e:
            print(Fore.RED + f"[ERROR] Could not get server info: {e}")
            return None

    def check_common_vulns(self):
        vulns = [
            ('/admin/', 'Admin panel exposed'),
            ('/phpinfo.php', 'PHP info exposed'),
            ('/.git/', 'Git repository exposed'),
            ('/.env', 'Environment file exposed'),
            ('/wp-admin/', 'WordPress admin'),
            ('/wp-login.php', 'WordPress login'),
            ('/administrator/', 'Joomla admin'),
            ('/login', 'Generic login page'),
        ]

        for path, desc in vulns:
            try:
                url = f"{self.target}{path}"
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    print(Fore.RED + f"[VULN] {desc} - {url} ({response.status_code})")
                elif self.verbose:
                    print(Fore.GREEN + f"[SAFE] {desc} - {url} ({response.status_code})")
            except Exception as e:
                if self.verbose:
                    print(Fore.YELLOW + f"[INFO] {desc} - Error: {e}")

    def check_headers(self):
        try:
            response = self.session.get(self.target, timeout=10)
            headers = response.headers

            security_headers = [
                'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                'Strict-Transport-Security', 'Content-Security-Policy'
            ]

            print(Fore.BLUE + "\n[SECURITY HEADERS]")
            for header in security_headers:
                if header in headers:
                    print(Fore.GREEN + f"[+] {header}: {headers[header]}")
                else:
                    print(Fore.RED + f"[-] {header}: Missing")

        except Exception as e:
            print(Fore.RED + f"[ERROR] Header check failed: {e}")

    def check_sql_injection(self):
        payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1"]
        vuln_found = False

        for payload in payloads:
            try:
                url = f"{self.target}?id={payload}"
                response = self.session.get(url, timeout=5)
                if re.search(r'sql|mysql|syntax|error', response.text, re.IGNORECASE):
                    print(Fore.RED + f"[SQLI] Potential SQL injection: {url}")
                    vuln_found = True
            except Exception as e:
                if self.verbose:
                    print(Fore.YELLOW + f"[INFO] SQLi check error: {e}")

        if not vuln_found:
            print(Fore.GREEN + "[SQLI] No obvious SQL injection vulnerabilities found")

    def check_xss(self):
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        vuln_found = False

        for payload in payloads:
            try:
                url = f"{self.target}?q={payload}"
                response = self.session.get(url, timeout=5)
                if payload in response.text:
                    print(Fore.RED + f"[XSS] Potential XSS: {url}")
                    vuln_found = True
            except Exception as e:
                if self.verbose:
                    print(Fore.YELLOW + f"[INFO] XSS check error: {e}")

        if not vuln_found:
            print(Fore.GREEN + "[XSS] No obvious XSS vulnerabilities found")

    def scan(self):
        print(Fore.CYAN + "[WEB VULN SCAN STARTED]")
        self.check_server_info()
        self.check_common_vulns()
        self.check_headers()
        self.check_sql_injection()
        self.check_xss()
        print(Fore.CYAN + "[WEB VULN SCAN COMPLETED]")

def web_vuln_scan(target, verbose=False):
    scanner = WebVulnScanner(target, verbose)
    scanner.scan()