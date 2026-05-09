#!/usr/bin/env python3
"""
Directory Listing Detection
"""

import requests
from colorama import Fore, init

init(autoreset=True)

def dir_listing_scan(target, verbose=False):
    """
    Detect directory listing vulnerabilities
    """
    print(Fore.CYAN + "[DIRECTORY LISTING SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        # Common directories to test
        dirs = [
            '/',
            '/admin/',
            '/uploads/',
            '/files/',
            '/static/',
            '/public/',
            '/assets/',
            '/download/',
            '/media/',
            '/backup/'
        ]
        
        for dir_path in dirs:
            try:
                url = target.rstrip('/') + dir_path
                response = session.get(url, timeout=5)
                
                # Check for directory listing indicators
                listing_indicators = [
                    'Index of',
                    '<title>Index of',
                    '[ICO]',
                    '<h1>Index of',
                    '| Parent Directory',
                    'Name Last modified'
                ]
                
                is_listing = any(indicator in response.text for indicator in listing_indicators)
                
                if is_listing:
                    print(Fore.RED + f"[DIR LISTING VULN] {url}")
                    vuln_found = True
                    
                    # Extract file listing
                    lines = response.text.split('\n')
                    for line in lines:
                        if '<a href=' in line:
                            print(Fore.RED + f"  └─ {line.strip()}")
                elif response.status_code == 200 and verbose:
                    print(Fore.GREEN + f"[OK] {url} - No directory listing")
            
            except requests.exceptions.Timeout:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] Timeout: {url}")
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] Error: {e}")
        
        if not vuln_found:
            print(Fore.GREEN + "[DIR] No directory listing vulnerabilities found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Directory listing scan failed: {e}")
    
    print(Fore.CYAN + "[DIRECTORY LISTING SCAN COMPLETED]")
    return vuln_found
