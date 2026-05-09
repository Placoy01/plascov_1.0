import requests
from colorama import Fore, Style, init
from bs4 import BeautifulSoup

init(autoreset=True)

def csrf_scan(target, verbose=False):
    print(Fore.CYAN + "[CSRF SCAN STARTED]")
    
    # Add schema if missing
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    try:
        response = session.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all('form')
        vuln_found = False

        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}) and not form.find('input', {'name': 'token'}):
                action = form.get('action', '')
                print(Fore.RED + f"[CSRF VULN] Form without CSRF token: {action}")
                vuln_found = True

        if not vuln_found:
            print(Fore.GREEN + "[CSRF] No obvious vulnerabilities found")

    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")

    print(Fore.CYAN + "[CSRF SCAN COMPLETED]")