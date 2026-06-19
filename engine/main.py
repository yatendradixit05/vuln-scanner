import sys
import json

def emit(phase, progress, finding=None):
    msg = {"phase": phase, "progress": progress}
    if finding:
        msg["finding"] = finding
    print(json.dumps(msg), flush=True)

def run_scan(target_url, scan_id):
    if not target_url.startswith("http://") and \
       not target_url.startswith("https://"):
        target_url = "https://" + target_url

    from phases.dorking        import run as dork
    from phases.recon          import run as recon
    from phases.crawler        import run as crawl
    from phases.attack         import run as attack
    from phases.attack_chain   import run as chain_attack
    from phases.behavior_analysis import run as behavior
    from phases.osint          import run as osint
    from phases.poc            import run as poc
    from phases.reporter       import run as report

    all_findings = []

    # Phase 0: Dorking
    emit("Phase 0: Google Dorking", 1)
    dork_data = dork(target_url, emit)
    for f in dork_data.get("findings", []):
        all_findings.append(f)
        emit("Phase 0: Dorking", 4, finding=f)

    # Phase A: Recon
    emit("Phase A: Recon", 5)
    recon_data = recon(target_url, emit)
    ct_subs = [{"subdomain": s, "ips":[], "status":"ct_log"}
               for s in dork_data.get("ct_subdomains",[])]
    recon_data["subdomains"] = recon_data.get("subdomains",[]) + ct_subs
    for f in recon_data.get("findings", []):
        all_findings.append(f)
        emit("Phase A: Recon", 24, finding=f)

    # Phase B: Crawling
    emit("Phase B: Crawling", 25)
    crawl_data = crawl(target_url, recon_data, emit)
    crawl_data["subdomains"] = recon_data.get("subdomains", [])
    crawl_data["recon_data"] = recon_data

    # Phase C: Attack
    emit("Phase C: Attack Engine", 45)
    attack_findings = attack(target_url, crawl_data, emit)
    for f in attack_findings:
        all_findings.append(f)
        emit("Phase C: Attack Engine", 78, finding=f)

    # Phase C+: Attack Chains
    emit("Phase C+: Attack Chain Simulation", 79)
    chain_findings = chain_attack(target_url, crawl_data, emit)
    for f in chain_findings:
        all_findings.append(f)
        emit("Phase C+: Attack Chains", 80, finding=f)

    # Phase C++: Behavior Analysis
    emit("Phase C++: Behavior Anomaly Detection", 80)
    behavior_findings = behavior(target_url, crawl_data, emit)
    for f in behavior_findings:
        all_findings.append(f)
        emit("Phase C++: Behavior Analysis", 82, finding=f)

    # Phase C+++: OSINT
    emit("Phase C+++: OSINT & Social Layer", 83)
    osint_findings = osint(target_url, crawl_data, emit)
    for f in osint_findings:
        all_findings.append(f)
        emit("Phase C+++: OSINT", 85, finding=f)

    # Phase D: PoC
    emit("Phase D: Proof of Concept", 86)
    all_findings = poc(all_findings, emit)

    # Phase E: Reporting
    emit("Phase E: Reporting", 95)
    report(scan_id, target_url, all_findings, recon_data, emit)

    emit("Complete", 100)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: main.py <target_url> <scan_id>"}),
              flush=True)
        sys.exit(1)
    target_url = sys.argv[1]
    scan_id    = sys.argv[2]
    run_scan(target_url, scan_id)