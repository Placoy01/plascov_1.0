import requests
from colorama import Fore, Style, init
import json

init(autoreset=True)

def api_scan(target, verbose=False):
    print(Fore.CYAN + "[API SCAN STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    endpoints = [
        '/api/v1/users',
        '/api/v1/admin',
        '/api/v1/config',
        '/api/v1/debug',
        '/graphql',
        '/api/swagger.json'
    ]

    vuln_found = False

    for endpoint in endpoints:
        try:
            url = f"{target.rstrip('/')}{endpoint}"
            response = session.get(url, timeout=5)
            if response.status_code == 200:
                print(Fore.YELLOW + f"[API ENDPOINT] {url} - {response.status_code}")
                if 'admin' in endpoint.lower() or 'config' in endpoint.lower():
                    print(Fore.RED + f"[API VULN] Sensitive endpoint exposed: {url}")
                    vuln_found = True
            elif response.status_code == 401:
                print(Fore.BLUE + f"[API AUTH] {url} requires authentication")
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[API] No obvious vulnerabilities found")
    print(Fore.CYAN + "[API SCAN COMPLETED]")