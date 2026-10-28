# NOXPWN - All-in-One Bug Bounty Reconnaissance & Vulnerability Engine

<p align="center">
  <img src="https://img.shields.io/badge/version-1.3.0-blue.svg" alt="Version 1.3.0">
  <img src="https://img.shields.io/badge/python-3.7%2B-brightgreen.svg" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg" alt="Cross-Platform">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/Bug%20Bounty-Ready%20%26%20Throttled-red.svg" alt="Bug Bounty Ready">
</p>

```
  _  _  ___  _  _ ___  _    _ _  _ 
| \| |/ _ \| \/ | _ \| |  | | \| |
| .` | (_) |>  <|  _/| |/\| | .` |
|_|\_|\___//_/\_|_|  |__/\__|_|\_|
```

> **19 Phases · 32 Tools · Smart Rate Limiting & Throttling · Built-in Fallbacks · Zero-Error Cross-Platform Engine**

**NOXPWN** is an automated reconnaissance and vulnerability scanning framework designed specifically for bug bounty hunters and penetration testers. It chains industry-standard tools (including **subfinder**, **httpx**, **linkfinder**, **mantra**, **katana**, **ffuf**, **nuclei**, **dalfox**, and **sqlmap**) into an end-to-end automated pipeline while delivering findings **live to your terminal in real time**.

---

## 🔥 What's New in v1.3.0

- 🛡️ **Bug Bounty Safe Throttling & Rate Limiting**:
  - Configure maximum requests per second (`-rl`, `--rate-limit`).
  - Control concurrency and workers (`-t`, `--threads`).
  - Set custom delays between requests (`-d`, `--delay`).
  - Dynamically injected into all underlying tools (`httpx`, `nuclei`, `katana`, `ffuf`, `feroxbuster`, `dalfox`, `sqlmap`, `dnsx`, `naabu`, `gospider`).
- ⚡ **Real-Time Findings Stream**: Vulnerabilities, exposed keys, endpoints, and live hosts are streamed to the console with color-coded severity badges immediately as they are discovered.
- 🔄 **Built-in Python Fallback Engine**: If an external tool (e.g. `httpx`, `linkfinder`, `mantra`, `dalfox`) is missing, NOXPWN doesn't crash—it seamlessly activates built-in Python probers, JS regex endpoint/secret extractors, and parameter reflection tests.
- 💻 **Full Cross-Platform Support (Windows, Linux, macOS)**: Native subprocess pipes replace fragile Unix-only shell constructs (`cat file | cmd`), with automatic Go/Cargo environment path discovery and PowerShell/CMD compatibility.
- 📦 **Non-Interactive Auto-Install**: Use `--auto-install` to detect and install missing dependencies automatically.

---

## 📋 19 Automated Phases

| Phase | Phase Name | Primary Tools & Fallback | Output Directory |
|:-----:|:-----------|:-------------------------|:-----------------|
| **01** | Subdomain Discovery | `subfinder`, `assetfinder`, `amass`, `knockpy`, `crt.sh`, `dnsx`, `puredns`, `gotator` | `01-subdomain-discovery/` |
| **02** | Port & Service Scanning | `naabu`, `nmap` | `02-port-scanning/` |
| **03** | Live Host Detection | `httpx` (Fallback: Python SSL-tolerant prober + title/server detector) | `03-live-hosts/` |
| **04** | Subdomain Takeover | `subzy`, `nuclei` (takeover templates) | `04-subdomain-takeover/` |
| **05** | WAF Fingerprinting | `wafw00f` (with throttled host probes) | `05-waf-detection/` |
| **06** | Screenshot Triage | `gowitness` (smart triage for high-value targets) | `06-screenshots/` |
| **07** | URL Collection | `katana`, `gau`, `waybackurls`, `hakrawler`, `gospider` | `07-urls/` |
| **08** | JavaScript Analysis | `subjs`, `jsleak`, `LinkFinder`, `mantra` (Fallback: regex secrets + endpoint engine) | `08-js-analysis/` |
| **09** | Directory & API Fuzzing | `ffuf`, `feroxbuster` (cross-platform SecLists / local wordlists) | `09-directories/` |
| **10** | Parameter Discovery | `arjun`, `x8` | `10-parameters/` |
| **11** | API & GraphQL Discovery | `nuclei` (api/swagger/graphql) + Python introspection probe | `11-api/` |
| **12** | Parameterized URL Filtering | `httpx` status-code filtering | `12-param-urls/` |
| **13** | Vulnerability Pattern Matching | `gf` (9 pattern categories) / Regex classifier fallback | `13-pattern-classification/` |
| **14** | CORS Misconfiguration | `CorsMe` / Python origin reflection probe | `14-cors/` |
| **15** | Vulnerability Scanning | `nuclei` (General, CVE, Exposures, Misconfigs) | `15-vulnerability-scan/` |
| **16** | XSS Analysis | `dalfox` / Python parameter reflection verification | `16-xss/` |
| **17** | SQL Injection Analysis | `sqlmap` (batch, automated risk/level heuristics) | `17-sqli/` |
| **18** | Open Redirect Detection | `nuclei` + Python redirect header prober | `18-open-redirect/` |
| **19** | Exposed Files & Secrets | `nuclei` + Python sensitive file detector (git, env, backup, aws) | `19-exposed-files/` |

---

## 🚀 Installation

### 1. Clone & Set Up

```bash
git clone https://github.com/Egzozzz/noxpwn.git
cd noxpwn
```

### 2. Install Package

**On Linux / macOS:**
```bash
chmod +x noxpwn
pip install -e .
```

**On Windows:**
```cmd
pip install -e .
```
*(Or use `noxpwn.cmd` directly without pip)*

### 3. Check & Install Security Tools

Check which tools are currently installed:
```bash
noxpwn --list-tools
```

Install all missing tools automatically:
```bash
noxpwn --install-all
```

---

## 🎯 Usage Examples

### 1. Safe Bug Bounty Scan (Respect Program Rate Limits)
Limit requests per second to avoid WAF IP bans or overwhelming the target:
```bash
noxpwn -u https://example.com --rate-limit 5 --threads 5 --delay 0.2
```

### 2. Full Recon & Scan (Standard Mode)
```bash
noxpwn -u https://example.com -o ./target_results
```

### 3. Quick Reconnaissance Mode
Skips deep brute-force scans (`ffuf`, `feroxbuster`, `nuclei` full passes) for quick triage:
```bash
noxpwn -u https://example.com --quick -rl 10
```

### 4. Non-Interactive / CI-CD Auto-Install
Detects missing tools and automatically installs them without interactive prompts:
```bash
noxpwn -u https://example.com --auto-install
```

### 5. Resume from Specific Phase
Resume a scan from a specific phase number (e.g., jump directly to JavaScript analysis Phase 8):
```bash
noxpwn -u https://example.com --from-phase 8
```

### 6. Exclude Slow or Heavy Tools
```bash
noxpwn -u https://example.com --skip-tools amass,gospider,feroxbuster
```

### 7. Self-Update
Keep noxpwn up-to-date with the latest templates and improvements:
```bash
noxpwn --update
```

---

## ⚙️ Command-Line Options

```
Options:
  -h, --help            Show this help message and exit
  -u URL, --url URL     Target URL (e.g. https://example.com)
  -o OUTPUT, --output   Output directory (default: ./noxpwn_output)
  -rl RATE, --rate-limit
                        Rate limit: max requests per second across tools (e.g. 5, 10)
  -t THREADS, --threads
                        Concurrency / thread count for tools (default: 10)
  -d SEC, --delay SEC   Delay between requests in seconds (e.g. 0.2, 0.5, 1.0)
  --auto-install        Automatically install missing tools without prompt
  --skip-install        Skip tool installation check
  --list-tools          List all tools and their installation status
  --install-all         Install all missing tools and exit
  --quick               Quick mode (skips slow brute-force and full vulnerability scans)
  --verbose             Verbose output with detailed tracebacks
  -v, --version         Show noxpwn version and exit
  --from-phase NUM      Start scanning from specific phase number (1-19)
  -st, --skip-tools LIST, --skip-tool LIST
                        Exclude specific tools with alias support (e.g. -st cors nuclei or --skip-tools ffuf,arjun)
  --update              Update noxpwn to the latest version from GitHub
```

---

## 📁 Output Directory Hierarchy

```
noxpwn_output/
└── example.com/
    ├── 01-subdomain-discovery/    # all_subs.txt, crt_sh.txt, subfinder.txt, resolved.txt
    ├── 02-port-scanning/          # naabu_ports.txt, nmap_scan.txt
    ├── 03-live-hosts/             # live_urls.txt, live_hosts.txt, technologies.txt
    ├── 04-subdomain-takeover/     # subzy_results.txt, nuclei_takeover.txt
    ├── 05-waf-detection/          # waf_summary.txt
    ├── 06-screenshots/            # gowitness captures
    ├── 07-urls/                   # all_urls.txt, discovered_params.txt
    ├── 08-js-analysis/            # downloaded_js/, endpoints.txt, secrets.txt
    ├── 09-directories/            # found_paths.txt, ffuf_*.json
    ├── 10-parameters/             # arjun_*.json, x8_*.txt
    ├── 11-api/                    # api_findings.txt, graphql_endpoints.txt
    ├── 12-param-urls/             # param_urls.txt, live_param_urls.txt
    ├── 13-pattern-classification/ # xss_candidates.txt, sqli_candidates.txt, lfi, ssrf
    ├── 14-cors/                   # cors_findings.txt
    ├── 15-vulnerability-scan/     # all_nuclei_findings.txt, cves.txt, exposures.txt
    ├── 16-xss/                    # dalfox_results.txt, xss_candidates.txt
    ├── 17-sqli/                   # sqlmap/ findings and logs
    ├── 18-open-redirect/          # open_redirects.txt, redirect_params_found.txt
    ├── 19-exposed-files/          # exposed_files.txt
    └── report/                    # scan_report.txt (comprehensive summary)
```

---

## 🧪 Testing

NOXPWN includes an automated test suite verifying cross-platform command execution, rate-limit flag construction, engine lifecycle, and phase error isolation:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## ⚖️ Disclaimer

**NOXPWN is intended strictly for authorized penetration testing, security auditing, and bug bounty programs where explicit written permission has been granted.** Scanning targets without prior consent is illegal. The author and contributors assume no liability for misuse of this tool.

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.
