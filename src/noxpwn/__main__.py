#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path

from .utils import banner, info, warn, error, good, c, check_tool as util_check_tool
from .installer import auto_install_missing, REQUIRED_TOOLS, OPTIONAL_TOOLS, ALL_TOOLS, install_tool
from .engine import NoxPwnEngine
from . import __version__ as VERSION


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
  noxpwn -u https://example.com --quick
  noxpwn -u https://example.com --skip-install
  noxpwn -u https://example.com --skip-tools amass,gospider
  noxpwn --list-tools
  noxpwn --install-all
  noxpwn --update
        """,
    )

    parser.add_argument("-u", "--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output", default="./noxpwn_output", help="Output directory (default: ./noxpwn_output)")
    parser.add_argument("--skip-install", action="store_true", help="Skip tool installation check")
    parser.add_argument("--list-tools", action="store_true", help="List all tools used by noxpwn")
    parser.add_argument("--install-all", action="store_true", help="Install all tools and exit")
    parser.add_argument("--quick", action="store_true", help="Quick mode (skip slow scans)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("--from-phase", type=int, default=1, help="Start from specific phase number")
    parser.add_argument("--skip-tools", nargs="+", help="Tools to skip (space or comma separated, e.g. --skip-tools ffuf feroxbuster arjun)")
    parser.add_argument("--update", action="store_true", help="Update noxpwn to latest version from GitHub")

    args = parser.parse_args()

    if args.version:
        print(f"noxpwn v{VERSION}")
        return

    if args.update:
        update_noxpwn()
        return

    skip_tools = []
    if args.skip_tools:
        for part in args.skip_tools:
            skip_tools.extend(t.strip().lower() for t in part.split(",") if t.strip())

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
        auto_install_missing(all_tool_names)

    config = {
        "quick": args.quick,
        "verbose": args.verbose,
        "from_phase": args.from_phase,
        "skip_tools": skip_tools,
    }

    engine = NoxPwnEngine(args.url, args.output, config)
    engine.run()


if __name__ == "__main__":
    main()
