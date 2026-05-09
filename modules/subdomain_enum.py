import requests
from colorama import Fore, Style, init

init(autoreset=True)

def subdomain_enum(target, verbose=False):
    print(Fore.CYAN + "[SUBDOMAIN ENUMERATION STARTED]")
    domain = target.replace('http://', '').replace('https://', '').split('/')[0]

    subdomains = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app', 'blog',
        'shop', 'store', 'news', 'forum', 'support', 'help', 'docs', 'wiki',
        'staging', 'beta', 'demo', 'portal', 'secure', 'login', 'auth'
    ]

    found = []

    try:
        import dns.resolver
        for sub in subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                answers = dns.resolver.resolve(subdomain, 'A', lifetime=2)
                for rdata in answers:
                    print(Fore.GREEN + f"[FOUND] {subdomain} -> {rdata}")
                    found.append(subdomain)
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[NOT FOUND] {sub}.{domain} - {e}")
    except ImportError:
        print(Fore.YELLOW + "[MODULE UNAVAILABLE] dnspython not installed")

    print(Fore.BLUE + f"[TOTAL] Found {len(found)} subdomains")
    print(Fore.CYAN + "[SUBDOMAIN ENUMERATION COMPLETED]")