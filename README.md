# 🔥 NOXPWN - Auto Bug Bounty Engine

> **17 Phases · 25+ Tools · Fully Automated Reconnaissance & Vulnerability Scanning**

NOXPWN is an automated bug bounty and penetration testing tool that chains 25+ industry-standard security tools into a single pipeline. Inspired by bbot and reconftw, it handles everything from subdomain discovery to vulnerability scanning with zero manual intervention.

---

## ✨ Features

| Phase | Module | Tools Used |
|-------|--------|------------|
| 01 | Subdomain Discovery | subfinder, assetfinder, amass |
| 02 | Port Scanning | naabu, nmap |
| 03 | Live Host Detection | httpx + tech-detect |
| 04 | Subdomain Takeover | subzy, nuclei |
| 05 | WAF Detection | wafw00f |
| 06 | Screenshots | gowitness (smart mode) |
| 07 | URL Collection | katana, hakrawler, gospider, waybackurls |
| 08 | JavaScript Analysis | subjs, LinkFinder, SecretFinder, mantra |
| 09 | Directory Bruteforce | ffuf, feroxbuster |
| 10 | Parameter Discovery | arjun |
| 11 | API & GraphQL | kiterunner, graphw00f |
| 12 | Parameterized URLs | httpx filtering |
| 13 | Pattern Classification | gf (xss/sqli/lfi/ssrf/rce) |
| 14 | CORS Misconfiguration | corsy |
| 15 | Vulnerability Scan | nuclei (critical/high/medium) |
| 16 | XSS Report | dalfox suggestions |
| 17 | SQLi Report | sqlmap suggestions |

**Smart Features:**
- 🧠 **Smart Screenshots**: Full screenshot mode only when critical findings are discovered
- 🔍 **XSS/SQLi Detection**: Flags potential vulnerabilities with manual testing commands
- 📦 **Auto-Install**: Detects and installs missing tools automatically
- ⚡ **Quick Mode**: Skips slow scans for rapid recon
- 🚫 **Skip Tools**: Exclude specific tools with `--skip-tools`
- 🔄 **Self-Update**: Update to latest version with `--update`
- 📊 **Detailed Report**: Generates comprehensive scan reports

---

## 🚀 Installation

### Prerequisites
- Python 3.7+
- Go (for Go-based tools)
- Linux/WSL/Kali environment (recommended)

### Quick Install (run directly, no setup needed)
```bash
# Clone the repository
git clone https://github.com/Egzozzz/noxpwn.git
cd noxpwn

# Make the entry point executable
chmod +x noxpwn

# Run directly
./noxpwn --help
./noxpwn -u https://example.com
```

### Full Install (system-wide)
```bash
pip install -e .
noxpwn -u https://example.com
```

### Install All Tools
```bash
./noxpwn --install-all
```

### List Available Tools
```bash
./noxpwn --list-tools
```

---

## 📖 Usage

### Basic Scan
```bash
./noxpwn -u https://target.com
```

### Quick Mode (skip slow scans)
```bash
./noxpwn -u https://target.com --quick
```

### Custom Output Directory
```bash
./noxpwn -u https://target.com -o ./my_results
```

### Start from Specific Phase
```bash
./noxpwn -u https://target.com --from-phase 8
```

### Skip Specific Tools
```bash
./noxpwn -u https://target.com --skip-tools amass,gospider,ffuf
```

### Skip Tool Installation Check
```bash
./noxpwn -u https://target.com --skip-install
```

### Install All Dependencies
```bash
./noxpwn --install-all
```

### Update noxpwn (from GitHub)
```bash
./noxpwn --update
```

---

## 📁 Output Structure

```
noxpwn_output/
└── target.com/
    ├── 01-subdomains/        # Subdomain lists
    ├── 02-ports/             # Port scan results
    ├── 03-live-hosts/        # Live hosts + tech stack
    ├── 04-takeover/          # Subdomain takeover findings
    ├── 05-waf/               # WAF detection results
    ├── 06-screenshots/       # Gowitness screenshots
    ├── 07-urls/              # Collected URLs
    ├── 08-js-analysis/       # JS files, endpoints, secrets
    ├── 09-directories/       # Discovered paths
    ├── 10-parameters/        # Arjun parameter findings
    ├── 11-api/               # API endpoints
    ├── 12-param-urls/        # Parameterized URLs
    ├── 13-patterns/          # GF pattern matches
    ├── 14-cors/              # CORS findings
    ├── 15-nuclei/            # Nuclei scan results
    └── report/               # Scan report
```

---

## 🔧 Requirements

### Required Tools (auto-installable)
| Tool | Installation | Purpose |
|------|-------------|---------|
| subfinder | go install | Subdomain discovery |
| httpx | go install | Live host detection |
| naabu | go install | Port scanning |
| nuclei | go install | Vulnerability scanning |
| katana | go install | URL crawling |
| subzy | go install | Takeover detection |
| gf | go install | Pattern matching |
| ffuf | go install | Directory bruteforce |
| assetfinder | go install | Subdomain discovery |
| waybackurls | go install | URL collection |
| gowitness | go install | Screenshots |
| dalfox | go install | XSS scanning |
| kiterunner | go install | API bruteforce |
| gospider | go install | URL crawling |
| hakrawler | go install | URL crawling |
| wafw00f | pip install | WAF detection |
| arjun | pip install | Parameter discovery |
| corsy | pip install | CORS checking |
| nmap | apt install | Port scanning |
| sqlmap | pip install | SQLi detection |

### Optional Tools
| Tool | Installation | Purpose |
|------|-------------|---------|
| amass | go install | Subdomain discovery |
| graphw00f | pip install (GitHub) | GraphQL detection |
| secretfinder | pip install (GitHub) | JS secret discovery |
| linkfinder | pip install (GitHub) | JS endpoint discovery |
| subjs | go install | JS file discovery |
| feroxbuster | apt install | Directory bruteforce |
| mantra | go install | JS secret analysis |
| unfurl | go install | URL parsing |

---

## 🛡️ Supported Attack Types

- Subdomain Enumeration
- Live Host Discovery
- Port & Service Detection
- Subdomain Takeover
- WAF Fingerprinting
- URL Crawling & Collection
- JavaScript Analysis & Secret Discovery
- Directory & File Bruteforce
- Parameter Discovery
- API & GraphQL Endpoint Discovery
- XSS Pattern Detection
- SQLi Pattern Detection
- CORS Misconfiguration
- General Vulnerability Scanning
- Screenshot Triage

---

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Use only on systems you own or have explicit permission to test. Unauthorized use may violate applicable laws.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

## 🙏 Credits

NOXPWN chains together 25+ open-source security tools created by the amazing security community. Special thanks to all tool authors.
