#!/usr/bin/env python3
"""
JavaScript Analysis - Extract endpoints, comments, and sensitive data
"""

import requests
from colorama import Fore, init
import re
import json

init(autoreset=True)

def js_analysis_scan(target, verbose=False):
    """
    Analyze JavaScript files for secrets and endpoints
    """
    print(Fore.CYAN + "[JAVASCRIPT ANALYSIS SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    findings = {
        'endpoints': [],
        'api_keys': [],
        'comments': [],
        'variables': []
    }
    
    try:
        response = session.get(target, timeout=5)
        
        # Extract script sources
        script_pattern = r'<script[^>]*src=["\']([^"\']+)'
        scripts = re.findall(script_pattern, response.text)
        
        print(Fore.BLUE + f"[JS] Found {len(scripts)} script files")
        
        for script in scripts[:5]:  # Analyze first 5 scripts
            try:
                # Construct full URL if relative
                if script.startswith('http'):
                    script_url = script
                elif script.startswith('/'):
                    base = target.split('?')[0].rsplit('/', 1)[0]
                    script_url = base + script
                else:
                    base = target.split('?')[0]
                    script_url = base.rstrip('/') + '/' + script
                
                script_response = session.get(script_url, timeout=5)
                script_content = script_response.text
                
                # Extract API endpoints
                api_pattern = r'["\']([/a-zA-Z0-9_-]+/[a-zA-Z0-9_/:-]+)["\']'
                apis = re.findall(api_pattern, script_content)
                findings['endpoints'].extend(apis)
                
                # Extract potential API keys
                key_pattern = r'([a-zA-Z_]*key[a-zA-Z_]*)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']'
                keys = re.findall(key_pattern, script_content, re.IGNORECASE)
                findings['api_keys'].extend(keys)
                
                # Extract comments
                comment_pattern = r'//\s*(.+)'
                comments = re.findall(comment_pattern, script_content)
                findings['comments'].extend(comments[:10])  # First 10 comments
                
                print(Fore.BLUE + f"[JS] Analyzed: {script}")
            
            except Exception as e:
                if verbose:
                    print(Fore.YELLOW + f"[INFO] Could not analyze {script}: {e}")
        
        # Extract endpoints from inline scripts
        inline_pattern = r'fetch\(["\']([^"\']+)'
        inline_apis = re.findall(inline_pattern, response.text)
        findings['endpoints'].extend(inline_apis)
        
        # Remove duplicates
        findings['endpoints'] = list(set(findings['endpoints']))
        findings['api_keys'] = list(set(findings['api_keys']))
        findings['comments'] = list(set(findings['comments']))
        
        # Display findings
        if findings['endpoints']:
            print(Fore.GREEN + f"[JS] Discovered {len(findings['endpoints'])} API endpoints:")
            for endpoint in findings['endpoints'][:10]:
                print(Fore.GREEN + f"  - {endpoint}")
        
        if findings['api_keys']:
            print(Fore.RED + f"[JS] Found potential API keys:")
            for key_name, key_value in findings['api_keys'][:5]:
                print(Fore.RED + f"  - {key_name}: {key_value[:20]}...")
        
        if findings['comments']:
            print(Fore.BLUE + f"[JS] Sample comments:")
            for comment in findings['comments'][:5]:
                print(Fore.BLUE + f"  - {comment[:100]}")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] JS analysis failed: {e}")
    
    print(Fore.CYAN + "[JAVASCRIPT ANALYSIS SCAN COMPLETED]")
    return len(findings['endpoints']) > 0 or len(findings['api_keys']) > 0
