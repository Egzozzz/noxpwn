#!/usr/bin/env python3
import sys
import argparse
import os
from pathlib import Path

from .utils import banner, info, warn, error, good, c, check_tool as util_check_tool
from .installer import auto_install_missing, REQUIRED_TOOLS, OPTIONAL_TOOLS, ALL_TOOLS
from .engine import NoxPwnEngine


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
  noxpwn --list-tools
  noxpwn --install-all
        """,
    )

    parser.add_argument("-u", "--url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-o", "--output", default="./noxpwn_output", help="Output directory (default: ./noxpwn_output)")
    parser.add_argument("--skip-install", action="store_true", help="Skip tool installation check")
    parser.add_argument("--list-tools", action="store_true", help="List all tools used by noxpwn")
    parser.add_argument("--install-all", action="store_true", help="Install all tools and exit")
    parser.add_argument("--quick", action="store_true", help="Quick mode (skip slow scans)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--from-phase", type=int, default=1, help="Start from specific phase number")

    args = parser.parse_args()

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
            from .installer import install_tool
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
        auto_install_missing(all_tool_names)

    config = {
        "quick": args.quick,
        "verbose": args.verbose,
        "from_phase": args.from_phase,
    }

    engine = NoxPwnEngine(args.url, args.output, config)
    engine.run()


if __name__ == "__main__":
    main()
