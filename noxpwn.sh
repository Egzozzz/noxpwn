#!/bin/bash
# noxpwn - Bug Bounty Automation Tool
# Usage: ./noxpwn.sh -u https://target.com

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$DIR/noxpwn" "$@"
