import requests
from colorama import Fore, Style, init
import json

init(autoreset=True)

def cve_checker(target, verbose=False):
    print(Fore.CYAN + "[CVE CHECKER STARTED]")
    # This is a simplified version. In reality, you'd integrate with NVD API
    # For demo, we'll check some known CVEs

    known_cves = {
        'Apache': ['CVE-2021-41773', 'CVE-2021-42013'],
        'nginx': ['CVE-2021-23017'],
        'OpenSSL': ['CVE-2022-0778', 'CVE-2022-2068']
    }

    try:
        response = requests.get(target, timeout=10)
        server = response.headers.get('Server', '')

        for software, cves in known_cves.items():
            if software.lower() in server.lower():
                print(Fore.RED + f"[CVE ALERT] {software} detected. Check CVEs: {', '.join(cves)}")

    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")

    print(Fore.CYAN + "[CVE CHECKER COMPLETED]")