#!/usr/bin/env python3
"""
Cookie Analysis - Analyze cookie security
"""

import requests
from colorama import Fore, init
import http.cookies

init(autoreset=True)

def cookie_analysis_scan(target, verbose=False):
    """
    Analyze cookies for security vulnerabilities
    """
    print(Fore.CYAN + "[COOKIE ANALYSIS SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        response = session.get(target, timeout=5)
        
        # Parse Set-Cookie headers
        cookies_list = response.headers.getlist('Set-Cookie') if hasattr(response.headers, 'getlist') else []
        
        # Try alternative parsing
        if not cookies_list:
            raw_cookies = response.headers.get('Set-Cookie', '')
            if raw_cookies:
                cookies_list = [raw_cookies]
        
        # Parse cookies from session
        session_cookies = list(session.cookies)
        
        print(Fore.BLUE + f"[COOKIES] Found {len(session_cookies)} cookies")
        
        for cookie in session_cookies:
            print(Fore.YELLOW + f"\nCookie: {cookie.name}")
            print(Fore.BLUE + f"  Value: {cookie.value[:50] if len(cookie.value) > 50 else cookie.value}")
            print(Fore.BLUE + f"  Domain: {cookie.domain}")
            print(Fore.BLUE + f"  Path: {cookie.path}")
            
            # Check for security flags
            if hasattr(cookie, 'secure'):
                if cookie.secure:
                    print(Fore.GREEN + f"  Secure: Yes")
                else:
                    print(Fore.RED + f"  Secure: No (VULN - transmitted over HTTP)")
                    vuln_found = True
            
            if hasattr(cookie, 'has_nonstandard_attr'):
                if cookie.has_nonstandard_attr('HttpOnly'):
                    print(Fore.GREEN + f"  HttpOnly: Yes")
                else:
                    print(Fore.RED + f"  HttpOnly: No (VULN - accessible to JavaScript)")
                    vuln_found = True
            
            if hasattr(cookie, 'has_nonstandard_attr'):
                if cookie.has_nonstandard_attr('SameSite'):
                    print(Fore.GREEN + f"  SameSite: Yes")
                else:
                    print(Fore.YELLOW + f"  SameSite: Not set (Possible CSRF vulnerability)")
                    vuln_found = True
            
            # Check cookie value length and entropy
            if len(cookie.value) < 16:
                print(Fore.YELLOW + f"  [WARNING] Cookie value too short (< 16 chars)")
                vuln_found = True
            
            # Check for common session cookie names
            session_names = ['PHPSESSID', 'JSESSIONID', 'SESSIONID', 'sid', 'session']
            if any(name in cookie.name.lower() for name in session_names):
                if not cookie.secure:
                    print(Fore.RED + f"  [VULN] Session cookie not marked as Secure")
                    vuln_found = True
        
        if not session_cookies:
            print(Fore.YELLOW + "[COOKIES] No cookies found")
        
        if not vuln_found:
            print(Fore.GREEN + "\n[COOKIES] No major cookie vulnerabilities found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] Cookie analysis failed: {e}")
    
    print(Fore.CYAN + "[COOKIE ANALYSIS SCAN COMPLETED]")
    return vuln_found
