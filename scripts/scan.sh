#!/usr/bin/env bash
# Take a dated Nmap service scan of a network YOU OWN or are authorized to scan.
#
# Usage: ./scripts/scan.sh 192.168.56.0/24
set -euo pipefail

TARGET="${1:?usage: $0 <cidr-or-host>}"
mkdir -p scans
OUT="scans/$(date +%F).xml"

# -sV: detect service versions, -T3: normal timing, -oX: XML output for scan_diff.py
nmap -sV -T3 -oX "$OUT" "$TARGET"
echo "Saved $OUT"
