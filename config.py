import os
from pathlib import Path


WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
]

TOOL_CONFIG = {
    "subfinder": {"timeout": 300, "flags": "-silent"},
    "assetfinder": {"timeout": 300, "flags": "--subs-only"},
    "amass": {"timeout": 600, "flags": "-passive"},
    "naabu": {"timeout": 600, "flags": "-silent"},
    "nmap": {"timeout": 900, "flags": "-sV -T4"},
    "httpx": {"timeout": 600, "flags": "-silent -tech-detect -status-code"},
    "subzy": {"timeout": 300, "flags": "--hide_fails --vuln"},
    "nuclei": {"timeout": 900, "flags": "-silent"},
    "wafw00f": {"timeout": 60, "flags": "-a"},
    "gowitness": {"timeout": 300, "flags": "--no-http"},
    "katana": {"timeout": 600, "flags": "-silent"},
    "hakrawler": {"timeout": 300, "flags": "-silent -depth 2"},
    "gospider": {"timeout": 600, "flags": "--no-redirect -c 10 -d 1"},
    "waybackurls": {"timeout": 300, "flags": ""},
    "subjs": {"timeout": 120, "flags": ""},
    "linkfinder": {"timeout": 60, "flags": "-o cli"},
    "mantra": {"timeout": 120, "flags": ""},
    "ffuf": {"timeout": 300, "flags": "-mc 200,301,302,401,403 -t 50"},
    "feroxbuster": {"timeout": 300, "flags": "-t 30 --silent"},
    "arjun": {"timeout": 300, "flags": "--quiet"},
    "kiterunner": {"timeout": 600, "flags": ""},
    "graphw00f": {"timeout": 60, "flags": "-d"},
    "corsy": {"timeout": 120, "flags": ""},
    "gf": {"timeout": 60, "flags": ""},
    "dalfox": {"timeout": 300, "flags": "--pipe"},
    "sqlmap": {"timeout": 600, "flags": "--batch --risk=3 --level=3"},
}

GRAPHQL_PATHS = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/gql", "/query"]
KITERUNNER_WORDLISTS = [
    "/usr/share/kiterunner/routes-large.kite",
    "/usr/share/kiterunner/routes-small.kite",
]


def find_wordlist():
    for p in WORDLIST_PATHS:
        if os.path.exists(p):
            return p
    return None


def find_kiterunner_wordlist():
    for p in KITERUNNER_WORDLISTS:
        if os.path.exists(p):
            return p
    return None
