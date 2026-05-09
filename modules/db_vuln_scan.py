import requests
from colorama import Fore, Style, init

init(autoreset=True)

def db_vuln_scan(target, verbose=False):
    print(Fore.CYAN + "[DATABASE VULNERABILITY SCAN STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    db_endpoints = [
        '/phpmyadmin/', '/adminer/', '/db/', '/database/', '/sql/',
        '/mysql/', '/postgres/', '/mongo/', '/redis/'
    ]

    vuln_found = False

    for endpoint in db_endpoints:
        try:
            url = f"{target.rstrip('/')}{endpoint}"
            response = session.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302]:
                print(Fore.RED + f"[DB VULN] Database interface exposed: {url}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[DB] No database interfaces exposed")
    print(Fore.CYAN + "[DATABASE VULNERABILITY SCAN COMPLETED]")