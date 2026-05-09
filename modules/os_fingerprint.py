import requests
from colorama import Fore, Style, init
import re

init(autoreset=True)

def os_fingerprint(target, verbose=False):
    print(Fore.CYAN + "[OS FINGERPRINT STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    try:
        response = session.get(target, timeout=10)
        server = response.headers.get('Server', '').lower()

        os_hints = {
            'windows': ['iis', 'microsoft', 'windows'],
            'linux': ['apache', 'nginx', 'ubuntu', 'debian', 'centos'],
            'unix': ['freebsd', 'openbsd', 'netbsd'],
            'macos': ['macos', 'darwin']
        }

        detected_os = None
        for os_name, hints in os_hints.items():
            if any(hint in server for hint in hints):
                detected_os = os_name
                break

        if detected_os:
            print(Fore.BLUE + f"[OS DETECTED] {detected_os.upper()}")
        else:
            print(Fore.YELLOW + "[OS] Could not determine OS")

    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")

    print(Fore.CYAN + "[OS FINGERPRINT COMPLETED]")