#!/usr/bin/env python3
"""
Advanced CORS Misconfiguration Testing
"""

import requests
from colorama import Fore, init

init(autoreset=True)

def cors_adv_scan(target, verbose=False):
    """
    Advanced CORS misconfiguration detection
    """
    print(Fore.CYAN + "[CORS ADVANCED SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        # Test various origins
        test_origins = [
            'http://attacker.com',
            'https://attacker.com',
            'http://localhost:3000',
            'https://localhost:3000',
            'null',
            target.replace('https://', 'http://'),
            target.replace('http://', 'https://'),
            target + '.attacker.com'
        ]
        
        print(Fore.BLUE + "[CORS] Testing various origins...")
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = session.get(target, headers=headers, timeout=5)
                
                cors_allow_origin = response.headers.get('Access-Control-Allow-Origin', None)
                cors_allow_creds = response.headers.get('Access-Control-Allow-Credentials', None)
                
                if cors_allow_origin:
                    if cors_allow_origin == '*':
                        if cors_allow_creds == 'true':
                            print(Fore.RED + "[CORS VULN] Access-Control-Allow-Origin: * with credentials")
                            vuln_found = True
                        else:
                            print(Fore.YELLOW + f"[CORS] Open CORS (no credentials): Origin {origin}")
                    elif cors_allow_origin == origin:
                        print(Fore.RED + f"[CORS VULN] Allows arbitrary origin: {origin}")
                        vuln_found = True
                    elif 'attacker.com' in origin and cors_allow_origin == origin:
                        print(Fore.RED + f"[CORS VULN] Trusts attacker domain: {origin}")
                        vuln_found = True
                
                # Check other CORS headers
                if cors_allow_origin:
                    methods = response.headers.get('Access-Control-Allow-Methods', 'N/A')
                    headers_allowed = response.headers.get('Access-Control-Allow-Headers', 'N/A')
                    print(Fore.BLUE + f"[CORS] Origin: {origin}")
                    print(Fore.BLUE + f"  Allow-Origin: {cors_allow_origin}")
                    print(Fore.BLUE + f"  Allow-Methods: {methods}")
                    print(Fore.BLUE + f"  Allow-Headers: {headers_allowed[:100]}")
            
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] Error testing {origin}: {e}")
        
        if not vuln_found:
            print(Fore.GREEN + "[CORS] No critical CORS misconfigurations found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] CORS scan failed: {e}")
    
    print(Fore.CYAN + "[CORS ADVANCED SCAN COMPLETED]")
    return vuln_found
