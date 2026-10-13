#!/usr/bin/env python3
"""Compare two Nmap XML scans and report attack-surface drift: new hosts, new/closed ports, version changes.

Usage:
    python scan_diff.py sample/baseline.xml sample/current.xml
    python scan_diff.py scans/last-week.xml scans/today.xml --out drift.md

Exit code: 0 = no high-risk drift, 2 = at least one HIGH finding (handy for cron jobs and CI).
"""
import argparse
import sys
import xml.etree.ElementTree as ET

# Ports that should rarely appear on a fresh exposure. Opening one is flagged HIGH.
RISKY = {
    21: "FTP (cleartext credentials)",
    23: "Telnet (cleartext remote shell)",
    445: "SMB (lateral movement, ransomware)",
    2375: "Docker API (often unauthenticated)",
    3306: "MySQL",
    3389: "RDP (brute force, ransomware)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch (often unauthenticated)",
    27017: "MongoDB (often unauthenticated)",
}
ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def load(path: str) -> dict:
    """Parse an Nmap XML file into {ip: {(proto, port): 'service product version'}} for hosts that are up."""
    hosts = {}
    for host in ET.parse(path).getroot().findall("host"):
        status = host.find("status")
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None or (status is not None and status.get("state") != "up"):
            continue
        ports = {}
        for port in host.findall("ports/port"):
            if port.find("state").get("state") != "open":
                continue
            svc = port.find("service")
            desc = " ".join(filter(None, (svc.get("name"), svc.get("product"), svc.get("version")))) if svc is not None else "unknown"
            ports[(port.get("protocol"), int(port.get("portid")))] = desc
        hosts[addr.get("addr")] = ports
    return hosts


def diff(old: dict, new: dict) -> list[tuple]:
    findings = []  # (severity, host, message)
    for ip in sorted(new.keys() - old.keys()):
        findings.append(("MEDIUM", ip, "New host appeared"))
        for (proto, port), desc in sorted(new[ip].items()):
            sev = "HIGH" if port in RISKY else "MEDIUM"
            note = f" - {RISKY[port]}" if port in RISKY else ""
            findings.append((sev, ip, f"Open {port}/{proto} ({desc}){note}"))
    for ip in sorted(old.keys() - new.keys()):
        findings.append(("INFO", ip, "Host no longer responding"))
    for ip in sorted(old.keys() & new.keys()):
        before, after = old[ip], new[ip]
        for key in sorted(after.keys() - before.keys()):
            port, proto = key[1], key[0]
            sev = "HIGH" if port in RISKY else "MEDIUM"
            note = f" - {RISKY[port]}" if port in RISKY else ""
            findings.append((sev, ip, f"Newly open {port}/{proto} ({after[key]}){note}"))
        for key in sorted(before.keys() - after.keys()):
            findings.append(("INFO", ip, f"Port {key[1]}/{key[0]} closed ({before[key]})"))
        for key in sorted(before.keys() & after.keys()):
            if before[key] != after[key]:
                findings.append(("INFO", ip, f"{key[1]}/{key[0]} changed: {before[key]} -> {after[key]}"))
    return sorted(findings, key=lambda f: (ORDER[f[0]], f[1]))


def render(findings: list[tuple], old_path: str, new_path: str) -> str:
    counts = {s: sum(1 for f in findings if f[0] == s) for s in ORDER}
    lines = [
        "# Attack Surface Drift Report",
        "",
        f"Baseline `{old_path}` vs current `{new_path}`  ",
        f"**HIGH:** {counts['HIGH']}  **MEDIUM:** {counts['MEDIUM']}  **INFO:** {counts['INFO']}",
        "",
    ]
    if not findings:
        return "\n".join(lines + ["No drift detected."])
    lines += ["| Severity | Host | Finding |", "|---|---|---|"]
    lines += [f"| {sev} | {ip} | {msg} |" for sev, ip, msg in findings]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("baseline", help="older Nmap XML scan (nmap -oX)")
    ap.add_argument("current", help="newer Nmap XML scan")
    ap.add_argument("--out", help="write the report to a file instead of stdout")
    args = ap.parse_args()

    findings = diff(load(args.baseline), load(args.current))
    report = render(findings, args.baseline, args.current)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print(f"Wrote {args.out}")
    else:
        print(report)
    sys.exit(2 if any(f[0] == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
