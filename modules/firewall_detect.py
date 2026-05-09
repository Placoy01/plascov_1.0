import requests
from colorama import Fore, Style, init
import time

init(autoreset=True)

def firewall_detect(target, verbose=False):
    print(Fore.CYAN + "[FIREWALL DETECTION STARTED]")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    # Simple firewall detection by checking response times and patterns
    try:
        start = time.time()
        response = session.get(target, timeout=10)
        end = time.time()

        response_time = end - start

        if response_time > 5:
            print(Fore.YELLOW + f"[FIREWALL] Slow response time: {response_time:.2f}s - possible WAF")

        waf_headers = ['X-WAF', 'X-Firewall', 'X-Mod-Security', 'X-Sucuri-ID']
        for header in waf_headers:
            if header in response.headers:
                print(Fore.RED + f"[FIREWALL DETECTED] {header}: {response.headers[header]}")

        if 'cloudflare' in response.text.lower():
            print(Fore.RED + "[FIREWALL] Cloudflare detected")

    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")

    print(Fore.CYAN + "[FIREWALL DETECTION COMPLETED]")