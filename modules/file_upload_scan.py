import requests
from colorama import Fore, Style, init
from bs4 import BeautifulSoup

init(autoreset=True)

def file_upload_scan(target, verbose=False):
    print(Fore.CYAN + "[FILE UPLOAD SCAN STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    try:
        response = session.get(target, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')

        upload_forms = soup.find_all('input', {'type': 'file'})

        if upload_forms:
            print(Fore.YELLOW + f"[INFO] Found {len(upload_forms)} file upload forms")
            for form in upload_forms:
                print(Fore.BLUE + f"[FORM] {form.get('name', 'unnamed')}")
                # In a real scanner, you'd test for vulnerabilities like RCE via upload
                print(Fore.RED + "[VULN POTENTIAL] File upload detected - check for RCE vulnerabilities")
        else:
            print(Fore.GREEN + "[SAFE] No file upload forms found")

    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")

    print(Fore.CYAN + "[FILE UPLOAD SCAN COMPLETED]")