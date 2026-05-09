#!/usr/bin/env python3
"""
Clickjacking Detection (X-Frame-Options and CSP)
"""

import requests
from colorama import Fore, init

init(autoreset=True)

def clickjacking_scan(target, verbose=False):
    """
    Detect clickjacking vulnerabilities
    """
    print(Fore.CYAN + "[CLICKJACKING SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        response = session.get(target, timeout=5)
        headers = response.headers
        
        # Check X-Frame-Options header
        x_frame_options = headers.get('X-Frame-Options', None)
        
        if not x_frame_options:
            print(Fore.RED + "[CLICKJACKING VULN] X-Frame-Options header is missing")
            vuln_found = True
        elif x_frame_options.upper() == 'ALLOW-FROM':
            print(Fore.RED + "[CLICKJACKING VULN] X-Frame-Options uses deprecated ALLOW-FROM")
            vuln_found = True
        elif x_frame_options.upper() in ['DENY', 'SAMEORIGIN']:
            print(Fore.GREEN + f"[CLICKJACKING] X-Frame-Options: {x_frame_options}")
        
        # Check Content-Security-Policy
        csp = headers.get('Content-Security-Policy', None)
        if csp and 'frame-ancestors' in csp.lower():
            print(Fore.GREEN + f"[CLICKJACKING] CSP frame-ancestors set: {csp[:100]}")
        elif not x_frame_options:
            print(Fore.RED + "[CLICKJACKING VULN] No CSP frame-ancestors and no X-Frame-Options")
        
        # Check other security headers
        headers_to_check = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'NOSNIFF',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer Policy'
        }
        
        print(Fore.BLUE + "[CLICKJACKING] Additional Security Headers:")
        for header, name in headers_to_check.items():
            value = headers.get(header, 'Missing')
            status = Fore.RED if value == 'Missing' else Fore.GREEN
            print(status + f"  {name}: {value}")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Clickjacking scan failed: {e}")
    
    print(Fore.CYAN + "[CLICKJACKING SCAN COMPLETED]")
    return vuln_found
