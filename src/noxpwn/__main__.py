#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path

from .utils import banner, info, warn, error, good, c, check_tool as util_check_tool
from .installer import auto_install_missing, REQUIRED_TOOLS, OPTIONAL_TOOLS, ALL_TOOLS, install_tool
from .engine import NoxPwnEngine
from . import __version__ as VERSION


TOOL_ALIASES = {
    "cors": "corsme",
    "corsme": "corsme",
    "crt": "crt.sh",
    "crtsh": "crt.sh",
    "crt.sh": "crt.sh",
    "lf": "linkfinder",
    "linkfinder": "linkfinder",
    "wf": "wafw00f",
    "waf": "wafw00f",
    "wafw00f": "wafw00f",
    "sub": "subfinder",
    "subfinder": "subfinder",
    "asset": "assetfinder",
    "assetfinder": "assetfinder",
    "katana": "katana",
    "gospider": "gospider",
    "dalfox": "dalfox",
    "xss": "dalfox",
    "sqlmap": "sqlmap",
    "sqli": "sqlmap",
    "nuclei": "nuclei",
    "cve": "nuclei",
    "ffuf": "ffuf",
    "ferox": "feroxbuster",
    "feroxbuster": "feroxbuster",
    "arjun": "arjun",
    "x8": "x8",
    "params": "arjun",
    "paramspider": "paramspider",
    "qsreplace": "qsreplace",
    "anew": "anew",
    "httpx": "httpx",
    "naabu": "naabu",
    "nmap": "nmap",
    "dnsx": "dnsx",
    "amass": "amass",
    "gau": "gau",
    "wayback": "waybackurls",
    "waybackurls": "waybackurls",
    "hakrawler": "hakrawler",
    "graphql": "graphql",
    "gql": "graphql",
    "subjs": "subjs",
    "jsleak": "jsleak",
    "knockpy": "knockpy",
    "subzy": "subzy",
    "gowitness": "gowitness",
}


def normalize_skip_tools(skip_args):
    """Normalize and expand skip_tools tokens including aliases and separators."""
    if not skip_args:
        return set()

    raw_tokens = []
    for part in skip_args:
        # Split on commas and spaces
        for item in str(part).replace(",", " ").split():
            clean = item.strip().lower()
            if clean:
                raw_tokens.append(clean)

    expanded = set()
    for tok in raw_tokens:
        expanded.add(tok)
        canonical = TOOL_ALIASES.get(tok)
        if canonical:
            expanded.add(canonical)
        # Also add all alias keys pointing to the same canonical
        for alias_name, target in TOOL_ALIASES.items():
            if target == tok or (canonical and target == canonical):
                expanded.add(alias_name)

    return expanded


def update_noxpwn():
    print(banner())
    info("Checking for updates...")
    repo_dir = Path(__file__).resolve().parent.parent.parent
    if not (repo_dir / ".git").exists():
        error("Not a git repository. Clone manually:")
        error("  git clone https://github.com/Egzozzz/noxpwn.git")
        return
    info(f"Repository: {repo_dir}")
    from .utils import run_cmd
    rc, out, err = run_cmd(f"cd \"{repo_dir}\" && git fetch origin && git pull origin", timeout=60, live=True)
    if rc == 0:
        good("noxpwn updated successfully!")
        rc2, ver, _ = run_cmd(f"cd \"{repo_dir}\" && git describe --tags 2>/dev/null || git log --oneline -1", timeout=10)
        if rc2 == 0 and ver:
            info(f"Version: {ver.strip()[:60]}")
    else:
        error("Update failed. Try manually:")
        error(f"  cd {repo_dir} && git pull")


def main():
    parser = argparse.ArgumentParser(
        description="noxpwn - Automated Bug Bounty & Pentesting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  noxpwn -u https://example.com
  noxpwn -u https://example.com -o ./results
  noxpwn -u https://example.com --rate-limit 5 --threads 5    # Safe bug bounty throttling
  noxpwn -u https://example.com -rl 10 -t 5 -d 0.2           # Rate limit + delay
  noxpwn -u https://example.com --quick
  noxpwn -u https://example.com --skip-install
  noxpwn -u https://example.com --auto-install
  noxpwn -u https://example.com --skip-tools amass,gospider
  noxpwn --list-tools
  noxpwn --install-all
  noxpwn --update
        """,
    )

    parser.add_argument("-u", "--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output", default="./noxpwn_output", help="Output directory (default: ./noxpwn_output)")
    parser.add_argument("-rl", "--rate-limit", type=int, default=None, help="Rate limit: max requests per second across tools (e.g. 5 or 10)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrency / threads for tools (default: 10)")
    parser.add_argument("-d", "--delay", type=float, default=None, help="Delay between requests in seconds (e.g. 0.2, 0.5, 1)")
    parser.add_argument("--auto-install", action="store_true", help="Automatically install missing tools without prompt")
    parser.add_argument("--skip-install", action="store_true", help="Skip tool installation check")
    parser.add_argument("--list-tools", action="store_true", help="List all tools used by noxpwn")
    parser.add_argument("--install-all", action="store_true", help="Install all tools and exit")
    parser.add_argument("--quick", action="store_true", help="Quick mode (skip slow scans)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("--from-phase", type=int, default=1, help="Start from specific phase number")
    parser.add_argument("-st", "--skip-tools", "--skip-tool", dest="skip_tools", nargs="+", default=[], help="Tools to skip (e.g. -st corsme nuclei or --skip-tools ffuf,arjun)")
    parser.add_argument("--update", action="store_true", help="Update noxpwn to latest version from GitHub")

    args = parser.parse_args()

    if args.version:
        print(f"noxpwn v{VERSION}")
        return

    if args.update:
        update_noxpwn()
        return

    skip_tools = normalize_skip_tools(args.skip_tools)

    if args.list_tools:
        print(banner())
        print(f" {c('REQUIRED TOOLS:', 'bold')}")
        for name, info_data in REQUIRED_TOOLS.items():
            status = c("[+]", "green") if util_check_tool(name) else c("[-]", "red")
            print(f"  {status} {name} ({info_data['type']})")
        print(f"\n {c('OPTIONAL TOOLS:', 'bold')}")
        for name, info_data in OPTIONAL_TOOLS.items():
            status = c("[+]", "green") if util_check_tool(name) else c("[-]", "red")
            print(f"  {status} {name} ({info_data['type']})")
        return

    if args.install_all:
        print(banner())
        info("Installing all tools...")
        for name in ALL_TOOLS:
            if not util_check_tool(name):
                if install_tool(name):
                    good(f"{name} installed")
                else:
                    warn(f"{name} installation failed")
        return

    if not args.url:
        parser.print_help()
        sys.exit(1)

    if not args.skip_install:
        info("Checking required tools...")
        all_tool_names = list(REQUIRED_TOOLS.keys()) + list(OPTIONAL_TOOLS.keys())
        if skip_tools:
            all_tool_names = [t for t in all_tool_names if t.lower() not in skip_tools]
            info(f"Skipping excluded tools: {', '.join(skip_tools)}")
        auto_install_missing(all_tool_names, non_interactive=args.auto_install)

    config = {
        "quick": args.quick,
        "verbose": args.verbose,
        "from_phase": args.from_phase,
        "skip_tools": skip_tools,
        "rate_limit": args.rate_limit,
        "threads": args.threads,
        "delay": args.delay,
    }

    engine = NoxPwnEngine(args.url, args.output, config)
    engine.run()


if __name__ == "__main__":
    main()
