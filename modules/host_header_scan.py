import requests
from colorama import Fore, Style, init

init(autoreset=True)

def host_header_scan(target, verbose=False):
    print(Fore.CYAN + "[HOST HEADER SCAN STARTED]")
    session = requests.Session()

    malicious_hosts = [
        'evil.com',
        '127.0.0.1',
        'localhost',
        'evil.com:80'
    ]

    vuln_found = False

    for host in malicious_hosts:
        try:
            session.headers.update({'Host': host})
            response = session.get(target, timeout=5)
            if 'evil.com' in response.text or 'localhost' in response.text:
                print(Fore.RED + f"[HOST HEADER VULN] Host: {host}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] Host {host} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[HOST HEADER] No vulnerabilities found")

    print(Fore.CYAN + "[HOST HEADER SCAN COMPLETED]")