# PLASCOV Security Framework

A comprehensive vulnerability scanner that combines the best features of nmap, nikto, and gobuster, plus more.

## Features

- **Port Scanning**: Discover open ports and services
- **TLS/SSL Analysis**: Check protocols, ciphers, and certificates
- **Technology Detection**: Identify web technologies and frameworks
- **Header Analysis**: Inspect HTTP security headers
- **DNS Enumeration**: Gather DNS information
- **Directory Brute Forcing**: Find hidden directories and files (like gobuster)
- **Web Vulnerability Scanning**: Check for common web vulnerabilities (like nikto)
- **General Vulnerability Checks**: Port-based and SSL checks
- **Full Scan**: Run all scans at once

## Installation

1. Create a virtual environment:
   ```bash
   python3 -m venv plascoy_env
   source plascoy_env/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
python plascoy.py -u <target> [options]
```

### Options

- `-h, --help`: Show help message
- `-u, --url`: Specify target URL or IP
- `--tls`: Scan TLS/SSL
- `--ports`: Scan ports
- `--tech`: Detect technologies
- `--headers`: Analyze headers
- `--dns`: DNS scan
- `--dirbrute`: Directory brute force
- `--webvuln`: Web vulnerabilities
- `--vuln`: General vulnerabilities
- `--all`: Full scan
- `--verbose`: Verbose output

### Examples

```bash
# Full scan
python plascoy.py -u example.com --all

# Specific scans
python plascoy.py -u example.com --ports --webvuln

# Verbose directory brute force
python plascoy.py -u example.com --dirbrute --verbose
```

## Requirements

- Python 3.6+
- Dependencies listed in requirements.txt

## Disclaimer

This tool is for educational and authorized security testing only. Use responsibly and with permission.