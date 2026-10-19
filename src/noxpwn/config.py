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
    os.path.expanduser("~/wordlists/common.txt"),
    os.path.expanduser("~/seclists/Discovery/Web-Content/common.txt"),
    os.path.expanduser("~\\wordlists\\common.txt"),
    os.path.expanduser("~\\seclists\\Discovery\\Web-Content\\common.txt"),
]

API_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
    os.path.expanduser("~/seclists/Discovery/Web-Content/api/api-endpoints.txt"),
    os.path.expanduser("~\\seclists\\Discovery\\Web-Content\\api\\api-endpoints.txt"),
]

PARAM_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    os.path.expanduser("~/seclists/Discovery/Web-Content/burp-parameter-names.txt"),
    os.path.expanduser("~\\seclists\\Discovery\\Web-Content\\burp-parameter-names.txt"),
]

TOOL_CONFIG = {
    "subfinder": {"timeout": 300, "flags": "-silent -all"},
    "assetfinder": {"timeout": 300, "flags": "--subs-only"},
    "amass": {"timeout": 600, "flags": "-passive"},
    "dnsx": {"timeout": 300, "flags": "-silent"},
    "naabu": {"timeout": 600, "flags": "-silent -top-ports 1000"},
    "nmap": {"timeout": 900, "flags": "-sV -sC -T4"},
    "httpx": {"timeout": 600, "flags": "-silent -tech-detect -status-code -content-length -title -web-server"},
    "subzy": {"timeout": 300, "flags": "--hide_fails"},
    "nuclei": {"timeout": 900, "flags": "-silent"},
    "wafw00f": {"timeout": 60, "flags": "-a"},
    "gowitness": {"timeout": 300, "flags": "scan file"},
    "katana": {"timeout": 600, "flags": "-silent -recursion -depth 3 -jc -kf all"},
    "gau": {"timeout": 300, "flags": "--subs"},
    "hakrawler": {"timeout": 300, "flags": "-d 3 -insecure"},
    "gospider": {"timeout": 600, "flags": "-d 3 --no-redirect -c 20 -t 10"},
    "waybackurls": {"timeout": 300, "flags": ""},
    "subjs": {"timeout": 120, "flags": ""},
    "jsleak": {"timeout": 120, "flags": ""},
    "linkfinder": {"timeout": 60, "flags": "-o cli"},
    "mantra": {"timeout": 120, "flags": ""},
    "ffuf": {"timeout": 300, "flags": "-mc all -fc 404,403 -recursion -recursion-depth 3 -s"},
    "feroxbuster": {"timeout": 300, "flags": "-d 3 --auto-tune --silent"},
    "arjun": {"timeout": 300, "flags": "--passive -m GET --quiet"},
    "x8": {"timeout": 300, "flags": "--disable-progress-bar -v 0"},
    "CorsMe": {"timeout": 120, "flags": ""},
    "gf": {"timeout": 60, "flags": ""},
    "dalfox": {"timeout": 300, "flags": "--pipe"},
    "sqlmap": {"timeout": 600, "flags": "--batch --risk=3 --level=3"},
    "gotator": {"timeout": 300, "flags": "-depth 1 -numbers 5 -mindup -silent"},
    "puredns": {"timeout": 300, "flags": ""},
    "knockpy": {"timeout": 600, "flags": "--recon --silent"},
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


def get_rate_limit_flags(tool_name, rate_limit=None, threads=None, delay=None):
    """
    Generate appropriate rate-limiting, concurrency, and delay CLI flags for a given tool.
    Bug bounty programs require throttling to prevent server overload or WAF banning.
    """
    flags = []
    t = tool_name.lower()

    if t == "httpx":
        if rate_limit is not None and rate_limit > 0:
            flags.append(f"-rate-limit {rate_limit}")
        if threads is not None and threads > 0:
            flags.append(f"-threads {threads}")

    elif t == "nuclei":
        if rate_limit is not None and rate_limit > 0:
            flags.append(f"-rate-limit {rate_limit}")
        if threads is not None and threads > 0:
            flags.append(f"-concurrency {threads}")

    elif t == "katana":
        if rate_limit is not None and rate_limit > 0:
            flags.append(f"-rate-limit {rate_limit}")
        if threads is not None and threads > 0:
            flags.append(f"-concurrency {threads}")
        if delay is not None and delay > 0:
            flags.append(f"-delay {delay}")

    elif t == "ffuf":
        if rate_limit is not None and rate_limit > 0:
            flags.append(f"-rate {rate_limit}")
        if threads is not None and threads > 0:
            flags.append(f"-t {threads}")
        elif rate_limit is not None and rate_limit > 0:
            # If rate limit is set, default ffuf threads to low to respect rate
            flags.append("-t 10")
        else:
            flags.append("-t 50")

    elif t == "feroxbuster":
        if rate_limit is not None and rate_limit > 0:
            flags.append(f"--rate-limit {rate_limit}")
        if threads is not None and threads > 0:
            flags.append(f"-t {threads}")

    elif t == "gospider":
        if threads is not None and threads > 0:
            flags.append(f"-t {threads} -c {min(threads, 10)}")
        if delay is not None and delay > 0:
            flags.append(f"--delay {delay}")

    elif t == "naabu":
        if rate_limit is not None and rate_limit > 0:
            flags.append(f"-rate {rate_limit}")

    elif t == "dnsx":
        if rate_limit is not None and rate_limit > 0:
            flags.append(f"-rate-limit {rate_limit}")
        if threads is not None and threads > 0:
            flags.append(f"-t {threads}")

    elif t == "subfinder":
        if threads is not None and threads > 0:
            flags.append(f"-t {threads}")

    elif t == "dalfox":
        if threads is not None and threads > 0:
            flags.append(f"--worker {threads}")
        if delay is not None and delay > 0:
            flags.append(f"--delay {int(delay * 1000) if delay < 1 else int(delay)}")

    elif t == "sqlmap":
        if threads is not None and threads > 0:
            flags.append(f"--threads={threads}")
        if delay is not None and delay > 0:
            flags.append(f"--delay={delay}")

    elif t == "corsme":
        if threads is not None and threads > 0:
            flags.append(f"-t {threads}")

    return " ".join(flags)
