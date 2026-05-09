#!/usr/bin/env python3
"""
Environment File Detection
"""

import requests
from colorama import Fore, init

init(autoreset=True)

def env_scan(target, verbose=False):
    """
    Detect exposed environment files
    """
    print(Fore.CYAN + "[ENV SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        # Common env files
        env_files = [
            '/.env',
            '/.env.local',
            '/.env.prod',
            '/.env.production',
            '/.env.development',
            '/config/.env',
            '/config/env.php',
            '/.env.backup',
            '/web.config',
            '/web.config.bak',
            '/web.config.old',
            '/.htaccess',
            '/.htpasswd',
            '/config.php',
            '/database.yml',
            '/config/database.yml',
            '/Gemfile.lock'
        ]
        
        for env_file in env_files:
            try:
                url = target.rstrip('/') + env_file
                response = session.get(url, timeout=5)
                
                if response.status_code == 200:
                    print(Fore.RED + f"[ENV VULN] Exposed: {url}")
                    vuln_found = True
                    
                    # Check content for sensitive data
                    content = response.text[:1000]
                    
                    sensitive_keys = [
                        'PASSWORD', 'SECRET', 'API_KEY', 'TOKEN',
                        'DATABASE', 'USERNAME', 'USER', 'KEY',
                        'PRIVATE', 'CREDENTIAL', 'AUTH'
                    ]
                    
                    if any(key in content.upper() for key in sensitive_keys):
                        print(Fore.RED + "[ENV VULN] Contains sensitive data!")
                        print(Fore.RED + f"  Preview: {content[:200]}")
                    else:
                        print(Fore.YELLOW + f"  Content preview: {content[:200]}")
            
            except requests.exceptions.Timeout:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] Timeout: {url}")
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] Error: {e}")
        
        if not vuln_found:
            print(Fore.GREEN + "[ENV] No exposed environment files found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Env scan failed: {e}")
    
    print(Fore.CYAN + "[ENV SCAN COMPLETED]")
    return vuln_found
