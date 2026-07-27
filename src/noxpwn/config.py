import os
from pathlib import Path


WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/common.txt",
]

API_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
]

PARAM_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
]

TOOL_CONFIG = {
    "subfinder": {"timeout": 300, "flags": "-silent -all"},
    "assetfinder": {"timeout": 300, "flags": "--subs-only"},
    "amass": {"timeout": 600, "flags": "-passive"},
    "dnsx": {"timeout": 300, "flags": "-silent"},
    "naabu": {"timeout": 600, "flags": "-silent -top-ports 1000"},
    "nmap": {"timeout": 900, "flags": "-sV -sC -T4"},
    "httpx": {"timeout": 600, "flags": "-silent -tech-detect -status-code -content-length -title -web-server"},
    "subzy": {"timeout": 300, "flags": "--hide_fails --vuln"},
    "nuclei": {"timeout": 900, "flags": "-silent"},
    "wafw00f": {"timeout": 60, "flags": "-a"},
    "gowitness": {"timeout": 300, "flags": "--no-http"},
    "katana": {"timeout": 600, "flags": "-silent -recursion -depth 3 -jc -kf all"},
    "gau": {"timeout": 300, "flags": "--subs"},
    "hakrawler": {"timeout": 300, "flags": "-silent -depth 3 -insecure"},
    "gospider": {"timeout": 600, "flags": "--recursive -d 3 --no-redirect -c 20 -t 10"},
    "waybackurls": {"timeout": 300, "flags": ""},
    "subjs": {"timeout": 120, "flags": ""},
    "jsleak": {"timeout": 120, "flags": ""},
    "trufflehog": {"timeout": 120, "flags": "--no-update"},
    "linkfinder": {"timeout": 60, "flags": "-o cli"},
    "mantra": {"timeout": 120, "flags": ""},
    "ffuf": {"timeout": 300, "flags": "-mc all -fc 404,403 -t 50 -recursion -recursion-depth 3"},
    "feroxbuster": {"timeout": 300, "flags": "-d 3 -t 30 --auto-bat --silent"},
    "arjun": {"timeout": 300, "flags": "--passive --get --quiet"},
    "x8": {"timeout": 300, "flags": "--silent"},
    "CorsMe": {"timeout": 120, "flags": ""},
    "gf": {"timeout": 60, "flags": ""},
    "dalfox": {"timeout": 300, "flags": "--pipe"},
    "sqlmap": {"timeout": 600, "flags": "--batch --risk=3 --level=3"},
    "gotator": {"timeout": 300, "flags": "-depth 1 -numbers 5 -mindup -silent"},
    "puredns": {"timeout": 300, "flags": ""},
}

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/gql", "/query", "/graph",
    "/api/v1/graphql", "/api/v2/graphql", "/graphql/console",
]

KITERUNNER_WORDLISTS = [
    "/usr/share/kiterunner/routes-large.kite",
    "/usr/share/kiterunner/routes-small.kite",
]


def find_wordlist():
    for p in WORDLIST_PATHS:
        if os.path.exists(p):
            return p
    return None


def find_api_wordlist():
    for p in API_WORDLIST_PATHS:
        if os.path.exists(p):
            return p
    return None


def find_param_wordlist():
    for p in PARAM_WORDLIST_PATHS:
        if os.path.exists(p):
            return p
    return None


def find_kiterunner_wordlist():
    for p in KITERUNNER_WORDLISTS:
        if os.path.exists(p):
            return p
    return None
