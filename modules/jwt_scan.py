#!/usr/bin/env python3
"""
JWT (JSON Web Token) Analysis
"""

import requests
import json
import base64
from colorama import Fore, init

init(autoreset=True)

def jwt_scan(target, verbose=False):
    """
    Analyze JWT tokens for vulnerabilities
    """
    print(Fore.CYAN + "[JWT SCAN STARTED]")
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    session.verify = False
    
    vuln_found = False
    
    try:
        response = session.get(target, timeout=5)
        
        # Check for JWT in cookies
        jwt_found = False
        for cookie in session.cookies:
            if len(cookie.value) > 20 and '.' in cookie.value:
                if cookie.value.count('.') == 2:
                    print(Fore.YELLOW + f"[INFO] Potential JWT found in cookie: {cookie.name}")
                    jwt_found = True
                    analyze_jwt(cookie.value, verbose)
        
        # Check for JWT in Authorization header
        if 'Authorization' in response.headers:
            auth_header = response.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.replace('Bearer ', '')
                if token.count('.') == 2:
                    print(Fore.YELLOW + f"[INFO] JWT found in Authorization header")
                    jwt_found = True
                    analyze_jwt(token, verbose)
        
        # Check for JWT in response body
        if 'token' in response.text or 'jwt' in response.text.lower():
            print(Fore.YELLOW + f"[INFO] Response contains 'token' or 'jwt' keywords")
            try:
                data = response.json()
                for key, value in data.items():
                    if isinstance(value, str) and value.count('.') == 2:
                        print(Fore.YELLOW + f"[INFO] Analyzing token in '{key}' field")
                        analyze_jwt(value, verbose)
                        jwt_found = True
            except:
                pass
        
        if not jwt_found:
            print(Fore.GREEN + "[JWT] No JWT tokens found")
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] JWT scan failed: {e}")
    
    print(Fore.CYAN + "[JWT SCAN COMPLETED]")
    return vuln_found

def analyze_jwt(token, verbose=False):
    """
    Analyze JWT token structure and vulnerabilities
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return
        
        # Decode header
        header_b64 = parts[0]
        payload_b64 = parts[1]
        signature_b64 = parts[2]
        
        # Add padding if necessary
        header_b64 += '=' * (4 - len(header_b64) % 4)
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        print(Fore.BLUE + f"[JWT HEADER] {header}")
        print(Fore.BLUE + f"[JWT PAYLOAD] {payload}")
        
        # Check for vulnerabilities
        if header.get('alg') == 'none':
            print(Fore.RED + "[JWT VULN] Algorithm set to 'none' - Token can be forged!")
        
        if header.get('alg') == 'HS256' and verbose:
            print(Fore.YELLOW + "[INFO] Using HS256 - Ensure secret key is strong")
        
        if 'exp' in payload:
            print(Fore.BLUE + f"[JWT] Token expires at: {payload.get('exp')}")
        else:
            print(Fore.RED + "[JWT VULN] No expiration time - Token is valid indefinitely!")
        
        if 'iat' in payload:
            print(Fore.BLUE + f"[JWT] Token issued at: {payload.get('iat')}")
    
    except Exception as e:
        if verbose:
            print(Fore.YELLOW + f"[INFO] Could not analyze JWT: {e}")
