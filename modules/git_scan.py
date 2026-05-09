#!/usr/bin/env python3
"""
Git Repository Detection
"""

import requests
from colorama import Fore, init

init(autoreset=True)

def git_scan(target, verbose=False):
    """
    Detect exposed .git directories
    """
    print(Fore.CYAN + "[GIT SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        # Common git paths
        git_paths = [
            '/.git/',
            '/.git/config',
            '/.git/HEAD',
            '/.gitignore',
            '/.github/',
            '/.git/objects/',
            '/.git/refs/',
            '/.git/logs/'
        ]
        
        for git_path in git_paths:
            try:
                url = target.rstrip('/') + git_path
                response = session.head(url, timeout=5)
                
                if response.status_code == 200:
                    print(Fore.RED + f"[GIT VULN] Exposed: {url}")
                    vuln_found = True
                    
                    # Try to get content
                    try:
                        content_response = session.get(url, timeout=5)
                        if content_response.status_code == 200:
                            content = content_response.text[:500]
                            print(Fore.RED + f"  Content: {content}")
                    except:
                        pass
                
                elif response.status_code == 403:
                    print(Fore.YELLOW + f"[INFO] {url}: Forbidden (path exists)")
            
            except requests.exceptions.Timeout:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] Timeout: {url}")
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] Error: {e}")
        
        if not vuln_found:
            print(Fore.GREEN + "[GIT] No exposed .git directories found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Git scan failed: {e}")
    
    print(Fore.CYAN + "[GIT SCAN COMPLETED]")
    return vuln_found
