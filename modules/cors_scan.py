import requests
from colorama import Fore, Style, init

init(autoreset=True)

def cors_scan(target, verbose=False):
    print(Fore.CYAN + "[CORS SCAN STARTED]")
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0',
        'Origin': 'https://evil.com'
    })

    try:
        response = session.get(target, timeout=10)
        cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials']

        for header in cors_headers:
            if header in response.headers:
                value = response.headers[header]
                if value == '*' or 'evil.com' in value:
                    print(Fore.RED + f"[CORS VULN] {header}: {value}")
                else:
                    print(Fore.GREEN + f"[CORS OK] {header}: {value}")

        if not any(h in response.headers for h in cors_headers):
            print(Fore.GREEN + "[CORS] No CORS headers found")

    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")

    print(Fore.CYAN + "[CORS SCAN COMPLETED]")