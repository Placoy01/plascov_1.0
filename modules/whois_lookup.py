import requests
from colorama import Fore, Style, init
import json

init(autoreset=True)

def whois_lookup(target, verbose=False):
    print(Fore.CYAN + "[WHOIS LOOKUP STARTED]")
    domain = target.replace('http://', '').replace('https://', '').split('/')[0]

    try:
        # Using a free WHOIS API
        url = f"https://api.ip2whois.com/v2?key=demo&domain={domain}"
        response = requests.get(url, timeout=5)  # Add timeout
        data = response.json()

        print(Fore.BLUE + f"[DOMAIN] {data.get('domain', 'N/A')}")
        print(Fore.BLUE + f"[REGISTRAR] {data.get('registrar', 'N/A')}")
        print(Fore.BLUE + f"[CREATED] {data.get('create_date', 'N/A')}")
        print(Fore.BLUE + f"[EXPIRES] {data.get('expire_date', 'N/A')}")
        print(Fore.BLUE + f"[NAMESERVERS] {', '.join(data.get('nameservers', []))}")

    except Exception as e:
        print(Fore.RED + f"[ERROR] WHOIS lookup failed: {e}")

    print(Fore.CYAN + "[WHOIS LOOKUP COMPLETED]")