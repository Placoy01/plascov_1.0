import requests
from colorama import Fore, Style, init
import base64

init(autoreset=True)

def deserialization_scan(target, verbose=False):
    print(Fore.CYAN + "[DESERIALIZATION SCAN STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    # Simple check for common deserialization patterns
    payloads = [
        'O:8:"stdClass":0:{}',  # PHP
        'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eHiBZG9Y2N8LAQABeHAAAAACdAAQZ3Jvd3M=',  # Java
    ]

    vuln_found = False

    for payload in payloads:
        try:
            url = f"{target.rstrip('/')}?data={payload}"
            response = session.get(url, timeout=5)
            if 'Exception' in response.text or 'error' in response.text.lower():
                print(Fore.RED + f"[DESERIAL VULN] {url}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[DESERIAL] No vulnerabilities found")
    print(Fore.CYAN + "[DESERIALIZATION SCAN COMPLETED]")