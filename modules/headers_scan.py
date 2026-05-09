import requests
import json
import re
import sys
import time
from colorama import init, Fore, Style

init(autoreset=True)

SECURITY_HEADERS = {
    "Content-Security-Policy": "Protection against XSS and content injection",
    "Strict-Transport-Security": "Force HTTPS usage",
    "X-Frame-Options": "Protection against clickjacking",
    "X-Content-Type-Options": "Prevent MIME sniffing",
    "Referrer-Policy": "Control referrer sending",
    "Permissions-Policy": "Control browser APIs",
    "X-XSS-Protection": "Basic XSS protection",
    "Feature-Policy": "Legacy permissions control",
    "Expect-CT": "Certificate Transparency enforcement",
    "Cross-Origin-Resource-Policy": "Cross-origin resource blocking",
    "Origin-Agent-Cluster": "Isolate origins",
    "Clear-Site-Data": "Clear data on navigation",
    "Server-Timing": "Performance metrics",
    "Timing-Allow-Origin": "Cross-origin timing controls",
    "Cross-Origin-Embedder-Policy": "Secure embedding",
    "Cross-Origin-Opener-Policy": "Isolate browsing contexts",
    "Cross-Origin-Resource-Policy": "Control cross-origin access",
    "Access-Control-Allow-Origin": "CORS origin control",
    "Access-Control-Allow-Methods": "CORS method control",
    "Access-Control-Allow-Headers": "CORS header control",
    "Access-Control-Allow-Credentials": "CORS credentials control",
    "Access-Control-Max-Age": "CORS preflight caching",
    "Vary": "Cache control for vary headers",
    "Cache-Control": "HTTP caching control",
    "Pragma": "HTTP caching control",
    "Expires": "HTTP cache expiration",
    "Last-Modified": "Resource modification date",
    "ETag": "Resource identifier",
    "X-UA-Compatible": "IE compatibility mode",
    "X-Content-Security-Policy": "Legacy CSP support",
    "X-WebKit-CSP": "Legacy WebKit CSP support"
}

# Expanded security rules for CSP analysis
CSP_DIRECTIVES = {
    "default-src": "Default source policy",
    "script-src": "Script execution policy",
    "style-src": "Style loading policy",
    "img-src": "Image loading policy",
    "connect-src": "Connection policy",
    "font-src": "Font loading policy",
    "media-src": "Media loading policy",
    "object-src": "Object loading policy",
    "child-src": "Child frame policy",
    "frame-src": "Frame loading policy",
    "worker-src": "Worker script policy",
    "manifest-src": "Manifest loading policy",
    "prefetch-src": "Prefetch policy",
    "form-action": "Form submission policy",
    "frame-ancestors": "Allowed parent frames",
    "navigate-to": "Navigation policy",
    "report-uri": "Reporting endpoint",
    "report-to": "Reporting group",
    "sandbox": "Sandbox restrictions",
    "upgrade-insecure-requests": "Upgrade insecure requests",
    "block-all-mixed-content": "Block mixed content",
    "require-trusted-types-for": "Require trusted types",
    "trusted-types": "Trusted types policy",
    "base-uri": "Base URL policy",
    "plugin-types": "Plugin type restrictions",
    "form-action": "Form action restrictions",
    "frame-ancestors": "Frame ancestors restrictions",
    "navigate-to": "Navigate to restrictions",
    "reflected-xss": "Reflected XSS filtering",
    "require-trusted-types": "Require trusted types",
    "trusted-types": "Trusted types policy",
    "unsafe-inline": "Allow inline scripts/styles",
    "unsafe-eval": "Allow eval() calls",
    "unsafe-hashes": "Allow unsafe hashes",
    "unsafe-redirects": "Allow unsafe redirects",
    "strict-dynamic": "Strict dynamic loading",
    "self": "Self sources only",
    "none": "No sources allowed",
    "*": "All sources allowed (dangerous)",
    "'none'": "No sources allowed (safe)",
    "'self'": "Self sources only (safe)",
    "'unsafe-inline'": "Allow inline scripts/styles (unsafe)",
    "'unsafe-eval'": "Allow eval() calls (unsafe)",
    "'unsafe-hashes'": "Allow unsafe hashes (unsafe)",
    "'unsafe-redirects'": "Allow unsafe redirects (unsafe)",
    "'strict-dynamic'": "Strict dynamic loading (advanced)"
}

# Additional security check functions
def analyze_csp(value):
    """Analyze Content-Security-Policy directives with advanced checks"""
    if not value:
        return "No CSP policy"
    
    issues = []
    # Check for dangerous directives
    dangerous_directives = ["*", "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'unsafe-redirects'"]
    for directive in dangerous_directives:
        if directive in value:
            issues.append(f"Potentially dangerous directive: {directive}")
    
    # Check for strict-dynamic without nonce/SHA
    if "strict-dynamic" in value and not ("nonce-" in value or "sha" in value):
        issues.append("strict-dynamic requires nonce or SHA for secure loading")
    
    # Check for base-uri without proper restriction
    if "base-uri" in value and "*" in value:
        issues.append("base-uri with * is dangerous")
    
    # Check for plugin-types with dangerous plugins
    if "plugin-types" in value and "application/pdf" in value:
        issues.append("plugin-types should restrict PDF viewers")
    
    # Check for form-action restrictions
    if "form-action" in value and "*" in value:
        issues.append("form-action with * allows all domains")
    
    # Check for frame-ancestors restrictions
    if "frame-ancestors" in value and "*" in value:
        issues.append("frame-ancestors with * allows any domain")
    
    # Check for report-uri/report-to presence
    if "report-uri" in value or "report-to" in value:
        issues.append("CSP reporting enabled")
    else:
        issues.append("CSP reporting disabled")
    
    return issues if issues else ["Strong CSP policy"]

def analyze_ssp(value):
    """Analyze Strict-Transport-Security directives"""
    if not value:
        return "No HSTS policy"
    
    issues = []
    max_age_match = re.search(r'max-age=(\d+)', value)
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:  # Less than 1 year
            issues.append(f"Max-Age too short: {max_age} seconds")
    
    include_subdomains = "includeSubDomains" in value
    preload = "preload" in value
    
    if not include_subdomains:
        issues.append("Missing includeSubDomains directive")
    
    if not preload:
        issues.append("Missing preload directive")
    
    return issues if issues else ["Valid HSTS policy"]

def analyze_xfo(value):
    """Analyze X-Frame-Options values"""
    if not value:
        return "No X-Frame-Options set"
    
    valid_values = ["DENY", "SAMEORIGIN"]
    if value.upper() not in valid_values:
        return [f"Invalid X-Frame-Options value: {value}"]
    
    return ["Valid X-Frame-Options"]

def analyze_xcto(value):
    """Analyze X-Content-Type-Options values"""
    if not value:
        return "No X-Content-Type-Options set"
    
    valid_values = ["nosniff"]
    if value.lower() not in valid_values:
        return [f"Invalid X-Content-Type-Options value: {value}"]
    
    return ["Valid X-Content-Type-Options"]

def analyze_referrer(value):
    """Analyze Referrer-Policy values"""
    if not value:
        return "No Referrer-Policy set"
    
    valid_values = [
        "no-referrer", "no-referrer-when-downgrade", "origin",
        "origin-when-cross-origin", "same-origin", "strict-origin",
        "strict-origin-when-cross-origin", "unsafe-url"
    ]
    
    if value.lower() not in valid_values:
        return [f"Invalid Referrer-Policy value: {value}"]
    
    return ["Valid Referrer-Policy"]

def analyze_permissions(value):
    """Analyze Permissions-Policy values"""
    if not value:
        return "No Permissions-Policy set"
    
    valid_features = [
        "accelerometer", "ambient-light-sensor", "autoplay", "battery",
        "camera", "clipboard-read", "clipboard-write", "display-capture",
        "document-domain", "encrypted-media", "execution-while-not-rendered",
        "execution-while-out-of-viewport", "fullscreen", "gamepad",
        "geolocation", "gyroscope", "hid", "idle-detection", "keyboard-lock",
        "local-fonts", "microphone", "midi", "navigation-override",
        "payment", "picture-in-picture", "publickey-credentials-get",
        "screen-wake-lock", "serial", "speaker-selection", "storage-access",
        "sync-xhr", "top-level-storage-access", "usb", "vertical-scroll",
        "web-share", "xr-spatial-tracking"
    ]
    
    issues = []
    policies = value.split(';')
    
    for policy in policies:
        policy = policy.strip()
        if not policy:
            continue
            
        feature = policy.split('=')[0].strip()
        if feature not in valid_features:
            issues.append(f"Unknown permission feature: {feature}")
    
    return issues if issues else ["Valid Permissions-Policy"]

def analyze_header(name, value):
    """Analyze specific header and provide recommendations"""
    if name == "Content-Security-Policy":
        return analyze_csp(value)
    elif name == "Strict-Transport-Security":
        return analyze_ssp(value)
    elif name == "X-Frame-Options":
        return analyze_xfo(value)
    elif name == "X-Content-Type-Options":
        return analyze_xcto(value)
    elif name == "Referrer-Policy":
        return analyze_referrer(value)
    elif name == "Permissions-Policy":
        return analyze_permissions(value)
    return []

def scan_headers(url, output_format="text"):
    """Enhanced header scanning with multiple output formats"""
    print("\nPLASCOV HEADER ANALYZER")
    print(Fore.CYAN + "="*60)
    print(Fore.YELLOW + f"Analyzing: {url}")
    print(Fore.CYAN + "="*60)
    
    start_time = time.time()
    
    try:
        r = requests.get(url, timeout=5)
        response_time = time.time() - start_time
        
        print(Fore.GREEN + f"Response time: {response_time:.2f}s")
        print(Fore.GREEN + f"Status code: {r.status_code}")
        print(Fore.GREEN + f"Content length: {len(r.content)} bytes")
        
    except Exception as e:
        print(Fore.RED + f"Error accessing site: {e}")
        return

    headers = r.headers
    
    print("\nSecurity Headers Analysis\n")
    
    security_issues = []
    missing_headers = []
    
    for header, desc in SECURITY_HEADERS.items():
        if header in headers:
            value = headers[header]
            print(Fore.GREEN + f"[OK] {header}")
            print(Fore.YELLOW + f"   value: {value}")
            
            analysis = analyze_header(header, value)
            if analysis:
                for issue in analysis:
                    print(Fore.RED + f"   {issue}")
                    security_issues.append(f"{header}: {issue}")
            else:
                print(Fore.GREEN + f"   Valid configuration")
        else:
            print(Fore.RED + f"[FAIL] {header} missing")
            print(Fore.YELLOW + f"   {desc}")
            missing_headers.append(header)
    
    print("\nServer Headers\n")
    
    server_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    for h in server_headers:
        if h in headers:
            print(Fore.GREEN + f"{h}: {headers[h]}")
    
    print("\nHeader Recommendations\n")
    
    if missing_headers:
        print(Fore.YELLOW + "Missing security headers:")
        for h in missing_headers:
            print(Fore.YELLOW + f"- {h}: {SECURITY_HEADERS[h]}")
    
    if security_issues:
        print(Fore.RED + "Security issues found:")
        for issue in security_issues:
            print(Fore.RED + f"- {issue}")
    else:
        print(Fore.GREEN + "All security headers configured correctly!")
    
    print("\nAll Headers\n")
    print(Fore.CYAN + json.dumps(dict(headers), indent=2))
    
    total_time = time.time() - start_time
    print(Fore.CYAN + f"\nAnalysis completed in {total_time:.2f}s")
    
    # Output additional metrics
    print("\nAdditional Metrics\n")
    print(Fore.CYAN + f"Total headers: {len(headers)}")
    print(Fore.CYAN + f"Security headers: {len(SECURITY_HEADERS)}")
    print(Fore.CYAN + f"Security issues: {len(security_issues)}")
    print(Fore.CYAN + f"Missing headers: {len(missing_headers)}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_headers(sys.argv[1])
    else:
        scan_headers("https://www.google.com")
