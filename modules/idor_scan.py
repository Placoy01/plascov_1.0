#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) Detection
"""

import requests
from colorama import Fore, init

init(autoreset=True)

def idor_scan(target, verbose=False):
    """
    Test for IDOR vulnerabilities by modifying ID parameters
    """
    print(Fore.CYAN + "[IDOR SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        # Test common ID parameters
        id_params = ['id', 'user_id', 'order_id', 'account_id', 'post_id', 'product_id']
        test_ids = ['1', '2', '100', '999', '0']
        
        for param in id_params:
            responses = []
            for test_id in test_ids:
                try:
                    params = {param: test_id}
                    response = session.get(target, params=params, timeout=5)
                    
                    # Store response status and length for comparison
                    responses.append({
                        'id': test_id,
                        'status': response.status_code,
                        'length': len(response.text),
                        'content': response.text[:200]
                    })
                    
                except Exception as e:
                    if verbose:
                        print(Fore.YELLOW + f"[INFO] Error: {e}")
            
            # Analyze responses for different content
            if len(set(r['status'] for r in responses)) > 1:
                print(Fore.YELLOW + f"[POSSIBLE IDOR] Parameter '{param}' returns different status codes")
                for r in responses:
                    print(Fore.YELLOW + f"  ID {r['id']}: {r['status']} ({r['length']} bytes)")
                vuln_found = True
            
            elif len(set(r['length'] for r in responses)) > 2:
                print(Fore.RED + f"[IDOR VULN] Parameter '{param}' returns different content for different IDs")
                for r in responses:
                    print(Fore.RED + f"  ID {r['id']}: {r['length']} bytes")
                vuln_found = True
        
        if not vuln_found:
            print(Fore.GREEN + "[IDOR] No IDOR vulnerabilities detected")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] IDOR scan failed: {e}")
    
    print(Fore.CYAN + "[IDOR SCAN COMPLETED]")
    return vuln_found
