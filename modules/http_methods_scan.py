#!/usr/bin/env python3
"""
HTTP Methods Scanner - Test PUT, DELETE, TRACE, OPTIONS
"""

import requests
from colorama import Fore, init

init(autoreset=True)

def http_methods_scan(target, verbose=False):
    """
    Test for enabled HTTP methods that shouldn't be available
    """
    print(Fore.CYAN + "[HTTP METHODS SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        safe_methods = ['GET', 'POST', 'HEAD', 'OPTIONS']
        
        # Test each method
        for method in safe_methods + dangerous_methods:
            try:
                if method == 'GET':
                    response = session.get(target, timeout=5)
                elif method == 'POST':
                    response = session.post(target, timeout=5)
                elif method == 'HEAD':
                    response = session.head(target, timeout=5)
                elif method == 'PUT':
                    response = session.put(target, timeout=5)
                elif method == 'DELETE':
                    response = session.delete(target, timeout=5)
                elif method == 'TRACE':
                    response = requests.request('TRACE', target, timeout=5)
                elif method == 'CONNECT':
                    response = requests.request('CONNECT', target, timeout=5)
                elif method == 'OPTIONS':
                    response = requests.request('OPTIONS', target, timeout=5)
                
                # Check response
                if response.status_code < 500:  # Not method not allowed
                    if method in dangerous_methods:
                        print(Fore.RED + f"[HTTP VULN] {method} method is enabled (Status: {response.status_code})")
                        vuln_found = True
                    else:
                        print(Fore.GREEN + f"[HTTP] {method} method: {response.status_code}")
                
                # Check for TRACE method vulnerability
                if method == 'TRACE' and 'TRACE' in response.text:
                    print(Fore.RED + "[HTTP VULN] TRACE method enabled - Potential XST vulnerability")
                    vuln_found = True
                
                # Check Allow header
                if 'Allow' in response.headers:
                    allowed = response.headers['Allow'].split(',')
                    print(Fore.BLUE + f"[HTTP] Allowed methods: {', '.join([m.strip() for m in allowed])}")
            
            except requests.exceptions.Timeout:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] {method} request timeout")
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] {method} error: {e}")
        
        if not vuln_found:
            print(Fore.GREEN + "[HTTP] No dangerous HTTP methods detected")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] HTTP methods scan failed: {e}")
    
    print(Fore.CYAN + "[HTTP METHODS SCAN COMPLETED]")
    return vuln_found
