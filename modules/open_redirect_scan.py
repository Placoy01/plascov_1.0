import requests
from colorama import Fore, Style, init

init(autoreset=True)

def open_redirect_scan(target, verbose=False):
    print(Fore.CYAN + "[OPEN REDIRECT SCAN STARTED]")
    
    # Add schema if missing
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    payloads = [
        "//evil.com",
        "http://evil.com",
        "https://evil.com",
        "//evil.com%2f%2e%2e",
        "http://evil.com%2f%2e%2e"
    ]

    vuln_found = False

    for payload in payloads:
        try:
            url = f"{target.rstrip('/')}?url={payload}"
            response = session.get(url, timeout=5, allow_redirects=False, verify=False)
            if response.status_code in [301, 302] and 'evil.com' in response.headers.get('Location', ''):
                print(Fore.RED + f"[OPEN REDIRECT VULN] {url}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[OPEN REDIRECT] No vulnerabilities found")
    print(Fore.CYAN + "[OPEN REDIRECT SCAN COMPLETED]")