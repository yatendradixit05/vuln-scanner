"""
test_recon.py — Run Phase A independently to verify it works.
Usage:  python test_recon.py https://example.com
"""

import sys
import json
from phases.recon import run

def emit(phase, progress, finding=None):
    prefix = "  [FINDING]" if finding else f"  [{progress:>3}%]"
    print(f"{prefix} {phase}")
    if finding:
        print(f"           Type:     {finding['type']}")
        print(f"           Severity: {finding['severity']}")
        print(f"           Detail:   {finding['description'][:80]}")

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(f"\n{'='*60}")
    print(f"  CYBER SUDARSHAN — Phase A Recon")
    print(f"  Target: {url}")
    print(f"{'='*60}\n")

    result = run(url, emit)

    print(f"\n{'='*60}")
    print("  RECON SUMMARY")
    print(f"{'='*60}")
    print(f"  Domain       : {result['domain']}")
    print(f"  Status Code  : {result['status_code']}")
    print(f"  Final URL    : {result['final_url']}")
    print(f"  Server       : {result['server']}")
    print(f"  Powered By   : {result['powered_by']}")

    print(f"\n  Subdomains found ({len(result['subdomains'])}):")
    for s in result['subdomains']:
        print(f"    • {s['subdomain']}  →  {', '.join(s['ips'])}")
    if not result['subdomains']:
        print("    (none)")

    print(f"\n  Tech Stack ({len(result['tech_stack'])}):")
    for t in result['tech_stack']:
        print(f"    • {t}")
    if not result['tech_stack']:
        print("    (nothing identified)")

    print(f"\n  WAF / Firewall:")
    for w in result['waf']:
        print(f"    • {w}")

    audit = result['header_audit']
    print(f"\n  Security Headers: {audit['score']}/{audit['max_score']}")
    print(f"  Present  ({len(audit['present'])}):")
    for h in audit['present']:
        print(f"    ✓ {h}")
    print(f"  Missing  ({len(audit['missing'])}):")
    for h in audit['missing']:
        print(f"    ✗ {h}")
    if audit['leaky']:
        print(f"  Leaking info ({len(audit['leaky'])}):")
        for h, v in audit['leaky'].items():
            print(f"    ! {h}: {v}")

    print(f"\n  Auto-generated findings: {len(result['findings'])}")
    for f in result['findings']:
        print(f"    [{f['severity']:8}] {f['type']} — {f['description'][:60]}...")

    print(f"\n{'='*60}\n")