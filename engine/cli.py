#!/usr/bin/env python3
"""
Cyber Sudarshan CLI — Command Line Scanner
Usage: python cli.py <target_url> [--output report.pdf] [--json] [--fail-on CRITICAL]
"""

import sys
import json
import argparse
import time
from datetime import datetime

def emit(phase, progress, finding=None):
    bar_len  = 30
    filled   = int(bar_len * progress / 100)
    bar      = "█" * filled + "░" * (bar_len - filled)
    print(f"\r[{bar}] {progress:3d}% | {phase[:60]}", end="", flush=True)
    if finding:
        sev = finding.get("severity","Info")
        colors = {
            "Critical": "\033[91m",
            "High":     "\033[93m",
            "Medium":   "\033[94m",
            "Low":      "\033[92m",
            "Info":     "\033[96m",
        }
        reset = "\033[0m"
        color = colors.get(sev, "")
        print(f"\n  {color}[{sev:8}]{reset} {finding.get('type','')} — {finding.get('url','')[:60]}")

def print_banner():
    print("""
\033[91m
   ___      _               ____            _            _
  / __|_  _| |__  ___ _ _  / ___|_   _  __| | __ _ _ __(_)___ ___  __ _ _ __
 | (__| || | '_ \/ -_) '_| \___ \ | | |/ _` |/ _` | '__| / __/ __|/ _` | '_ \\
  \___|\_, |_.__/\___|_|   |___/ |_,_|\__,_|\__,_|_| |_\___\___|\__,_| .__/
       |__/                                                              |_|
\033[0m
  Web Vulnerability Scanner — APCSIP Project
  ─────────────────────────────────────────────────────
""")

def main():
    parser = argparse.ArgumentParser(
        description="Cyber Sudarshan — Web Vulnerability Scanner CLI"
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--output", "-o", default=None,
                        help="Output PDF path (default: report_<timestamp>.pdf)")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output findings as JSON")
    parser.add_argument("--fail-on", "-f", default=None,
                        choices=["Critical","High","Medium","Low"],
                        help="Exit with code 1 if severity found (for CI/CD)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress banner and progress output")
    parser.add_argument("--phases", "-p", default="all",
                        help="Phases to run: all, recon, crawl, attack")

    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    target_url = args.url.strip()
    if not target_url.startswith("http://") and \
       not target_url.startswith("https://"):
        target_url = "https://" + target_url

    scan_id = f"cli_{int(time.time())}"

    if not args.quiet:
        print(f"  Target  : {target_url}")
        print(f"  Scan ID : {scan_id}")
        print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  ─────────────────────────────────────────────────────\n")

    all_findings = []

    def cli_emit(phase, progress, finding=None):
        if not args.quiet:
            emit(phase, progress, finding)
        if finding:
            all_findings.append(finding)

    try:
        from phases.recon    import run as recon
        from phases.crawler  import run as crawl
        from phases.attack   import run as attack
        from phases.poc      import run as poc
        from phases.reporter import run as report

        # Phase A
        cli_emit("Phase A: Recon", 5)
        recon_data = recon(target_url, cli_emit)
        for f in recon_data.get("findings", []):
            all_findings.append(f)
            cli_emit("Phase A: Recon", 24, finding=f)

        # Phase B
        cli_emit("Phase B: Crawling", 25)
        crawl_data = crawl(target_url, recon_data, cli_emit)
        crawl_data["subdomains"] = recon_data.get("subdomains", [])
        crawl_data["recon_data"] = recon_data

        # Phase C
        cli_emit("Phase C: Attack", 45)
        attack_findings = attack(target_url, crawl_data, cli_emit)
        for f in attack_findings:
            all_findings.append(f)

        # Phase D
        cli_emit("Phase D: PoC", 80)
        all_findings = poc(all_findings, cli_emit)

        # Phase E
        output_path = args.output or f"report_{scan_id}.pdf"
        cli_emit("Phase E: Reporting", 95)
        report(scan_id, target_url, all_findings, recon_data, cli_emit)

        print("\n")

    except KeyboardInterrupt:
        print("\n\n  Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n  ERROR: {e}")
        sys.exit(1)

    # Summary
    counts = {k:0 for k in ["Critical","High","Medium","Low","Info"]}
    for f in all_findings:
        counts[f.get("severity","Info")] = counts.get(f.get("severity","Info"),0)+1

    deductions = (counts["Critical"]*200 + counts["High"]*100 +
                  counts["Medium"]*40 + counts["Low"]*10)
    score = max(0, min(1000, 1000 - deductions))

    if score >= 900: grade = "A+"
    elif score >= 800: grade = "A"
    elif score >= 700: grade = "B"
    elif score >= 600: grade = "B-"
    elif score >= 500: grade = "C"
    elif score >= 300: grade = "D"
    else: grade = "F"

    if not args.quiet:
        print(f"""
  ─────────────────────────────────────────────────────
  SCAN COMPLETE — SUMMARY
  ─────────────────────────────────────────────────────
  Cyber Score : {score}/1000 (Grade: {grade})
  Critical    : {counts['Critical']}
  High        : {counts['High']}
  Medium      : {counts['Medium']}
  Low         : {counts['Low']}
  Info        : {counts['Info']}
  Total       : {len(all_findings)}
  Report      : {args.output or f'report_{scan_id}.pdf'}
  ─────────────────────────────────────────────────────
""")

    # JSON output
    if args.json:
        print(json.dumps({
            "target":    target_url,
            "score":     score,
            "grade":     grade,
            "counts":    counts,
            "findings":  all_findings
        }, indent=2))

    # CI/CD fail-on check
    if args.fail_on:
        severity_order = ["Info","Low","Medium","High","Critical"]
        fail_idx = severity_order.index(args.fail_on)
        for f in all_findings:
            f_idx = severity_order.index(f.get("severity","Info"))
            if f_idx >= fail_idx:
                print(f"  CI/CD: FAILED — {f['severity']} vulnerability found: {f['type']}")
                sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()