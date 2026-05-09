#!/usr/bin/env python3
"""
Backup Files Detection
"""

import requests
from colorama import Fore, init

init(autoreset=True)

def backup_scan(target, verbose=False):
    """
    Search for common backup files
    """
    print(Fore.CYAN + "[BACKUP FILES SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        # Common backup extensions
        backup_extensions = [
            '.bak', '.backup', '.old', '.tar', '.tar.gz', '.zip',
            '.sql', '.sql.gz', '.db', '.sqlite', '.rar',
            '.7z', '.bz2', '~', '.tmp', '.swp', '.swo',
            '.orig', '.backup', '-old', '.copy', '.1', '.2'
        ]
        
        # Common backup locations
        base_paths = ['/', '/backup/', '/backups/', '/downloads/']
        common_files = ['backup', 'database', 'config', 'admin', 'wp-config', 'index']
        
        for base_path in base_paths:
            for file_name in common_files:
                for ext in backup_extensions:
                    try:
                        url = target.rstrip('/') + base_path.rstrip('/') + '/' + file_name + ext
                        response = session.head(url, timeout=3)
                        
                        if response.status_code == 200:
                            print(Fore.RED + f"[BACKUP VULN] Found: {url}")
                            vuln_found = True
                        elif response.status_code != 404 and verbose:
                            print(Fore.YELLOW + f"[INFO] {url}: {response.status_code}")
                    
                    except requests.exceptions.Timeout:
                        pass
                    except Exception as e:
                        if verbose:
                            print(Fore.YELLOW + f"[INFO] Error: {e}")
        
        if not vuln_found:
            print(Fore.GREEN + "[BACKUP] No common backup files found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Backup scan failed: {e}")
    
    print(Fore.CYAN + "[BACKUP FILES SCAN COMPLETED]")
    return vuln_found
