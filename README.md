# NOXPWN - Auto Bug Bounty Engine

> **17 Phases · 31 Tools · Fully Automated Reconnaissance & Vulnerability Scanning**

NOXPWN is an automated bug bounty and penetration testing tool that chains 31 industry-standard security tools into a single pipeline. It handles everything from subdomain discovery to vulnerability scanning with zero manual intervention.

---

## Features

| Phase | Module | Tools Used |
|-------|--------|------------|
| 01 | Subdomain Discovery | subfinder, assetfinder, amass, crt.sh, dnsx, gotator, puredns |
| 02 | Port Scanning | naabu, nmap |
| 03 | Live Host Detection | httpx + tech-detect |
| 04 | Subdomain Takeover | subzy, nuclei (takeover tags) |
| 05 | WAF Detection | wafw00f |
| 06 | Screenshots | gowitness (smart mode) |
| 07 | URL Collection | katana, gau, waybackurls, hakrawler, gospider |
| 08 | JavaScript Analysis | subjs, jsleak, LinkFinder, mantra, gf |
| 09 | Directory Bruteforce | ffuf, feroxbuster |
| 10 | Parameter Discovery | arjun, x8 |
| 11 | API & GraphQL | x8, nuclei (graphql/api/swagger tags), curl |
| 12 | Parameterized URLs | httpx filtering |
| 13 | Pattern Classification | gf (9 patterns), regex secrets |
| 14 | CORS Misconfiguration | CorsMe, curl fallback |
| 15 | Vulnerability Scan | nuclei (critical/high/medium) |
| 16 | XSS Report | dalfox suggestions |
| 17 | SQLi Report | sqlmap suggestions |

**Smart Features:**
- Smart Screenshots: Full screenshot mode only when critical findings are discovered
- XSS/SQLi Detection: Flags potential vulnerabilities with manual testing commands
- Auto-Install: Detects and installs missing tools automatically
- Quick Mode: Skips slow scans for rapid recon
- Skip Tools: Exclude specific tools with `--skip-tools`
- Self-Update: Update to latest version with `--update`
- Per-Phase Error Isolation: One crash doesn't stop the pipeline
- Detailed Report: Generates comprehensive scan reports

---

## Installation

### Prerequisites
- Python 3.7+
- Go (for Go-based tools)
- Rust/Cargo (for x8)
- Linux/Kali environment (recommended)

### Quick Install (run directly, no setup needed)
```bash
git clone https://github.com/Egzozzz/noxpwn.git
cd noxpwn
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

---

## Usage

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

## Output Structure

```
noxpwn_output/
└── target.com/
    ├── 01-subdomain-discovery/    # Subdomain lists
    ├── 02-port-scanning/          # Port scan results
    ├── 03-live-hosts/             # Live hosts + tech stack
    ├── 04-subdomain-takeover/     # Takeover findings
    ├── 05-waf-detection/          # WAF results
    ├── 06-screenshots/            # Gowitness screenshots
    ├── 07-urls/                   # Collected URLs
    ├── 08-js-analysis/            # JS files, endpoints, secrets
    ├── 09-directories/            # Discovered paths
    ├── 10-parameters/             # Parameter findings
    ├── 11-api/                    # API endpoints
    ├── 12-param-urls/             # Parameterized URLs
    ├── 13-pattern-classification/ # GF pattern matches
    ├── 14-cors/                   # CORS findings
    ├── 15-vulnerability-scan/     # Nuclei scan results
    └── report/                    # Scan report
```

---

## Tools

### Required (25 tools)

| Tool | Type | Purpose |
|------|------|---------|
| subfinder | go | Subdomain discovery |
| assetfinder | go | Subdomain discovery |
| dnsx | go | DNS resolution |
| naabu | go | Port scanning |
| nmap | apt | Service/script scanning |
| httpx | go | Live host detection + tech |
| subzy | go | Subdomain takeover |
| wafw00f | pip | WAF detection |
| gowitness | go | Screenshots |
| katana | go | URL crawling |
| gau | go | URL collection |
| hakrawler | go | URL crawling |
| gospider | go | URL crawling |
| waybackurls | go | URL collection |
| subjs | go | JS file discovery |
| jsleak | go | JS endpoint extraction |
| ffuf | go | Directory bruteforce |
| arjun | pip | Parameter discovery |
| x8 | cargo | Hidden parameter discovery |
| gf | go | Pattern matching |
| CorsMe | go | CORS misconfiguration |
| nuclei | go | Vulnerability scanning |
| dalfox | go | XSS scanning |
| sqlmap | pip | SQLi detection |
| mantra | go | JS secret analysis |

### Optional (6 tools)

| Tool | Type | Purpose |
|------|------|---------|
| amass | go | Deep subdomain discovery |
| gotator | go | Subdomain permutation |
| puredns | go | DNS resolution |
| linkfinder | git+pip | JS endpoint extraction |
| feroxbuster | apt | Directory bruteforce |
| unfurl | go | URL parsing |

---

## Supported Attack Types

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

## Disclaimer

This tool is for **authorized security testing only**. Use only on systems you own or have explicit permission to test. Unauthorized use may violate applicable laws.

---

## License

MIT License - see [LICENSE](LICENSE) file.

---

## Credits

NOXPWN chains together 31 open-source security tools created by the amazing security community. Special thanks to all tool authors.
