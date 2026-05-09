#!/usr/bin/env python3
"""
External Tools Integration
Gobuster, ffuf, Nmap, WhatWeb
"""

import subprocess
import os
import sys
from colorama import Fore, init

init(autoreset=True)

def check_tool_installed(tool_name):
    """Check if a tool is installed"""
    try:
        subprocess.run(
            [tool_name, '--version'] if tool_name != 'nmap' else ['nmap', '-V'],
            capture_output=True,
            timeout=5
        )
        return True
    except:
        return False

def run_gobuster(target, wordlist=None, threads=10, verbose=False):
    """
    Run Gobuster for directory brute forcing
    """
    print(Fore.CYAN + "[GOBUSTER SCAN STARTED]")
    
    if not check_tool_installed('gobuster'):
        print(Fore.RED + "[ERROR] Gobuster not installed")
        print(Fore.YELLOW + "Install: apt-get install gobuster")
        return False
    
    try:
        # Clean target URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        # Default wordlist
        if not wordlist:
            wordlist = '/usr/share/wordlists/dirb/common.txt'
        
        if not os.path.exists(wordlist):
            print(Fore.YELLOW + f"[INFO] Wordlist not found: {wordlist}")
            print(Fore.YELLOW + "Using default Gobuster wordlist")
            cmd = [
                'gobuster', 'dir',
                '-u', target,
                '-t', str(threads),
                '-q'  # Quiet mode
            ]
        else:
            cmd = [
                'gobuster', 'dir',
                '-u', target,
                '-w', wordlist,
                '-t', str(threads),
                '-q'
            ]
        
        print(Fore.BLUE + f"[GOBUSTER] Running: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.stdout:
            print(Fore.GREEN + "[GOBUSTER] Results:")
            for line in result.stdout.split('\n'):
                if line.strip() and '/' in line:
                    print(Fore.GREEN + f"  {line}")
        
        if result.returncode != 0 and verbose:
            print(Fore.YELLOW + f"[INFO] Gobuster stderr: {result.stderr[:200]}")
        
        print(Fore.CYAN + "[GOBUSTER SCAN COMPLETED]")
        return True
    
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[INFO] Gobuster timed out")
        return False
    except Exception as e:
        print(Fore.RED + f"[ERROR] Gobuster error: {e}")
        return False

def run_ffuf(target, wordlist=None, threads=40, verbose=False):
    """
    Run ffuf for fast fuzzing
    """
    print(Fore.CYAN + "[FFUF SCAN STARTED]")
    
    if not check_tool_installed('ffuf'):
        print(Fore.RED + "[ERROR] ffuf not installed")
        print(Fore.YELLOW + "Install: apt-get install ffuf (or build from source)")
        return False
    
    try:
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        if not wordlist:
            wordlist = '/usr/share/wordlists/dirb/common.txt'
        
        # ffuf syntax: ffuf -u URL/FUZZ -w wordlist
        url_with_fuzz = target.rstrip('/') + '/FUZZ'
        
        cmd = [
            'ffuf',
            '-u', url_with_fuzz,
            '-w', wordlist,
            '-t', str(threads),
            '-c',  # Colored output
            '-s'   # Silent mode (only show results)
        ]
        
        print(Fore.BLUE + f"[FFUF] Running fuzzing...")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.stdout:
            print(Fore.GREEN + "[FFUF] Results:")
            for line in result.stdout.split('\n'):
                if line.strip():
                    print(Fore.GREEN + f"  {line}")
        
        print(Fore.CYAN + "[FFUF SCAN COMPLETED]")
        return True
    
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[INFO] ffuf timed out")
        return False
    except Exception as e:
        print(Fore.RED + f"[ERROR] ffuf error: {e}")
        return False

def run_nmap(target, scan_type='-sV', verbose=False):
    """
    Run Nmap for port and service scanning
    """
    print(Fore.CYAN + "[NMAP SCAN STARTED]")
    
    if not check_tool_installed('nmap'):
        print(Fore.RED + "[ERROR] Nmap not installed")
        print(Fore.YELLOW + "Install: apt-get install nmap")
        return False
    
    try:
        # Extract host from URL if needed
        import re
        host_match = re.match(r'https?://([^/:?]+)', target)
        if host_match:
            host = host_match.group(1)
        else:
            host = target.split('/')[0]
        
        cmd = [
            'nmap',
            host,
            scan_type,
            '-oG', '-'  # Output to stdout
        ]
        
        print(Fore.BLUE + f"[NMAP] Scanning {host}...")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.stdout:
            print(Fore.GREEN + "[NMAP] Results:")
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('#'):
                    print(Fore.GREEN + f"  {line}")
        
        if result.returncode != 0:
            print(Fore.YELLOW + f"[INFO] Nmap returned code {result.returncode}")
            if 'not allowed' in result.stderr.lower():
                print(Fore.YELLOW + "Note: Some Nmap features require root privileges")
        
        print(Fore.CYAN + "[NMAP SCAN COMPLETED]")
        return True
    
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[INFO] Nmap timed out")
        return False
    except Exception as e:
        print(Fore.RED + f"[ERROR] Nmap error: {e}")
        return False

def run_whatweb(target, verbose=False):
    """
    Run WhatWeb for technology detection
    """
    print(Fore.CYAN + "[WHATWEB SCAN STARTED]")
    
    if not check_tool_installed('whatweb'):
        print(Fore.RED + "[ERROR] WhatWeb not installed")
        print(Fore.YELLOW + "Install: apt-get install whatweb")
        return False
    
    try:
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        cmd = [
            'whatweb',
            target,
            '-q',  # Quiet mode
            '-a', '3'  # Aggression level
        ]
        
        print(Fore.BLUE + f"[WHATWEB] Scanning {target}...")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.stdout:
            print(Fore.GREEN + "[WHATWEB] Results:")
            print(Fore.GREEN + result.stdout)
        
        print(Fore.CYAN + "[WHATWEB SCAN COMPLETED]")
        return True
    
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[INFO] WhatWeb timed out")
        return False
    except Exception as e:
        print(Fore.RED + f"[ERROR] WhatWeb error: {e}")
        return False

def run_all_external_tools(target, threads=10):
    """
    Run all available external tools
    """
    print(Fore.MAGENTA + "\n[EXTERNAL TOOLS SUITE]")
    
    available_tools = []
    
    if check_tool_installed('gobuster'):
        print(Fore.GREEN + "[OK] Gobuster available")
        available_tools.append('gobuster')
    
    if check_tool_installed('ffuf'):
        print(Fore.GREEN + "[OK] ffuf available")
        available_tools.append('ffuf')
    
    if check_tool_installed('nmap'):
        print(Fore.GREEN + "[OK] Nmap available")
        available_tools.append('nmap')
    
    if check_tool_installed('whatweb'):
        print(Fore.GREEN + "[OK] WhatWeb available")
        available_tools.append('whatweb')
    
    if not available_tools:
        print(Fore.RED + "[ERROR] No external tools installed")
        return False
    
    print(Fore.BLUE + f"[INFO] Running {len(available_tools)} tools...")
    
    if 'gobuster' in available_tools:
        run_gobuster(target, threads=threads)
    
    if 'ffuf' in available_tools:
        run_ffuf(target, threads=threads)
    
    if 'nmap' in available_tools:
        run_nmap(target)
    
    if 'whatweb' in available_tools:
        run_whatweb(target)
    
    return True
