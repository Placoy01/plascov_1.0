from colorama import Fore, Style, init
import json
import datetime

init(autoreset=True)

def report_gen(target, findings, verbose=False):
    print(Fore.CYAN + "[REPORT GENERATION STARTED]")

    report = {
        'target': target,
        'scan_date': datetime.datetime.now().isoformat(),
        'findings': findings,
        'summary': {
            'total_vulnerabilities': len(findings),
            'severity_levels': {'high': 0, 'medium': 0, 'low': 0}
        }
    }

    # Simple severity classification
    for finding in findings:
        if 'VULN' in finding.upper():
            if 'SQLI' in finding or 'XSS' in finding or 'RCE' in finding:
                report['summary']['severity_levels']['high'] += 1
            elif 'HEADER' in finding or 'CORS' in finding:
                report['summary']['severity_levels']['medium'] += 1
            else:
                report['summary']['severity_levels']['low'] += 1

    print(Fore.BLUE + f"[REPORT] Target: {target}")
    print(Fore.BLUE + f"[REPORT] Scan Date: {report['scan_date']}")
    print(Fore.BLUE + f"[REPORT] Total Findings: {len(findings)}")
    print(Fore.BLUE + f"[REPORT] High: {report['summary']['severity_levels']['high']}")
    print(Fore.BLUE + f"[REPORT] Medium: {report['summary']['severity_levels']['medium']}")
    print(Fore.BLUE + f"[REPORT] Low: {report['summary']['severity_levels']['low']}")

    # Save to file
    filename = f"report_{target.replace('http://', '').replace('https://', '').replace('/', '_')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)

    print(Fore.GREEN + f"[REPORT SAVED] {filename}")
    print(Fore.CYAN + "[REPORT GENERATION COMPLETED]")