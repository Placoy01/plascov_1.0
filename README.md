---

# 🧩 Complete Functions & Modules

## 🌐 Reconnaissance & Enumeration

| Function | Description |
|----------|-------------|
| `--dns` | Perform DNS enumeration |
| `--subdomain` | Discover subdomains |
| `--whois` | WHOIS lookup |
| `--ports` | Scan ports (1-1024) |
| `--services` | Detect running services |
| `--os` | OS fingerprinting |
| `--firewall` | Detect firewall/WAF |
| `--tech` | Detect technologies/frameworks |
| `--headers` | Analyze HTTP security headers |

---

# 🔐 SSL/TLS Modules

| Function | Description |
|----------|-------------|
| `--tls` | TLS versions & ciphers scan |
| `--testssl` | Full SSL/TLS analysis using testssl.sh |

---

# 🛡️ Web Vulnerability Modules

| Function | Description |
|----------|-------------|
| `--webvuln` | Web vulnerability scan |
| `--vuln` | General vulnerability scan |
| `--sqli` | SQL Injection detection |
| `--xss` | Cross-Site Scripting scan |
| `--csrf` | CSRF vulnerability scan |
| `--lfi` | Local/Remote File Inclusion |
| `--cmdinj` | Command Injection scan |
| `--redirect` | Open Redirect testing |
| `--upload` | File upload vulnerability testing |
| `--cors` | CORS misconfiguration scan |
| `--hostheader` | Host Header Injection |
| `--ssrf` | SSRF vulnerability scan |
| `--xxe` | XML External Entity injection |
| `--deserial` | Deserialization vulnerabilities |
| `--api` | API security testing |
| `--cve` | CVE vulnerability checker |

---

# 🚨 Advanced Vulnerability Modules

| Function | Description |
|----------|-------------|
| `--ssti` | Server-Side Template Injection |
| `--idor` | IDOR vulnerability scan |
| `--jwt` | JWT token analysis |
| `--http-methods` | HTTP methods analysis |
| `--dirlisting` | Detect directory listing |
| `--backup` | Find backup files |
| `--git` | Detect exposed .git repositories |
| `--env` | Detect exposed environment files |
| `--robots` | robots.txt analysis |
| `--sitemap` | sitemap.xml analysis |
| `--clickjacking` | Clickjacking vulnerability testing |
| `--cors-adv` | Advanced CORS exploitation tests |
| `--params` | Parameter mining |
| `--js` | JavaScript endpoint analysis |
| `--cookies` | Cookie security analysis |

---

# ⚔️ Fuzzing Engine

| Function | Description |
|----------|-------------|
| `--fuzz xss` | XSS fuzzing |
| `--fuzz sqli` | SQLi fuzzing |
| `--fuzz lfi` | LFI fuzzing |
| `--fuzz xxe` | XXE fuzzing |
| `--fuzz all` | Full fuzzing suite |
| `--fuzz random` | Random payload fuzzing |

---

# 🛰️ CMS & Infrastructure

| Function | Description |
|----------|-------------|
| `--cms` | CMS detection |
| `--db` | Database vulnerability checks |
| `--services` | Running services detection |
| `--firewall` | Firewall/WAF detection |

---

# ⚡ External Tools Integration

| Function | Description |
|----------|-------------|
| `--gobuster` | Run Gobuster |
| `--ffuf` | Run ffuf fuzzing |
| `--nmap` | Run Nmap scan |
| `--whatweb` | Run WhatWeb |

---

# 🚀 Advanced Features

| Function | Description |
|----------|-------------|
| `--crawl` | Crawl website endpoints |
| `--threads <n>` | Set threads number |
| `--output <format>` | Export reports |
| `--report` | Generate report summary |
| `--report-gen` | Create JSON findings report |
| `--external` | Run all external tools |
| `--recon` | Full reconnaissance suite |
| `--audit` | Fast security audit |
| `--all` | Complete full scan |

---

# 📊 Output Formats

| Format | Description |
|--------|-------------|
| `json` | JSON report |
| `html` | HTML report |
| `csv` | CSV export |
| `txt` | Plain text output |

---
```bash
git clone 

# 🔥 Example Advanced Commands

## Full Recon + Vulnerability Scan

```bash
./plascoy -u target.com --recon --sqli --xss --csrf --report
```

---

## Aggressive Full Scan

```bash
./plascoy -u target.com --all --threads 100 --verbose
```

---

## Full External Tools Scan

```bash
./plascoy -u target.com --external --output html
```

---

## Crawl + Fuzzing

```bash
./plascoy -u target.com --crawl --fuzz all
```

---

## Generate Professional HTML Report

```bash
./plascoy -u target.com --audit --report --output html
```

---
