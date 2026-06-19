import dns.resolver
import requests
import concurrent.futures
from urllib.parse import urlparse

SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","admin","api","dev","staging","test","beta","portal",
    "app","dashboard","login","auth","secure","vpn","remote","cdn","static",
    "assets","media","images","blog","shop","store","pay","payment","checkout",
    "cart","support","help","docs","wiki","forum","community","chat","m",
    "mobile","old","new","v2","v3","demo","sandbox","uat","qa","preprod",
    "prod","internal","intranet","corp","smtp","pop","imap","ns1","ns2",
    "dns","cpanel","webmail","crm","erp","jira","gitlab","git","jenkins",
    "ci","monitor","status","grafana","kibana","search","db","database",
    "mysql","redis","mongo","backup","files","upload","uploads","download",
    "proxy","node","worker","queue","ws","websocket","analytics","tracking",
    "ads","affiliate","partner","client","clients","customer","account",
    "billing","admin2","administrator","superadmin","panel","control","sys",
]

TECH_SIGNATURES = {
    "WordPress":     {"body": ["wp-content","wp-includes","wp-json"]},
    "Drupal":        {"body": ["Drupal.settings","/sites/default/files"]},
    "Joomla":        {"body": ["/components/com_","Joomla!"]},
    "Laravel":       {"cookies": ["laravel_session"]},
    "Django":        {"cookies": ["csrftoken"]},
    "React":         {"body": ["__REACT_DEVTOOLS","react-root"]},
    "Angular":       {"body": ["ng-version","ng-app"]},
    "Vue.js":        {"body": ["__vue__","data-v-"]},
    "jQuery":        {"body": ["jquery.min.js"]},
    "Bootstrap":     {"body": ["bootstrap.min.css"]},
    "PHP":           {"body": [".php"]},
    "ASP.NET":       {"headers": ["X-Powered-By: ASP.NET"],"cookies": ["ASP.NET_SessionId"]},
    "Next.js":       {"body": ["__NEXT_DATA__","_next/static"]},
    "Nginx":         {"headers": ["Server: nginx"]},
    "Apache":        {"headers": ["Server: Apache"]},
    "IIS":           {"headers": ["Server: Microsoft-IIS"]},
    "Cloudflare":    {"headers": ["CF-RAY","Server: cloudflare"]},
}

WAF_SIGNATURES = {
    "Cloudflare":        ["CF-RAY","cf-cache-status"],
    "AWS WAF":           ["x-amzn-RequestId"],
    "Akamai":            ["X-Check-Cacheable"],
    "Sucuri":            ["x-sucuri-id"],
    "Imperva Incapsula": ["X-Iinfo","incap_ses"],
    "F5 BIG-IP":         ["X-WA-Info","BigIP"],
    "ModSecurity":       ["Mod_Security"],
    "Wordfence":         ["wordfence_verifiedHuman"],
}

SECURITY_HEADERS = {
    "Content-Security-Policy":    "Prevents XSS by restricting resource loading",
    "Strict-Transport-Security":  "Forces HTTPS (HSTS)",
    "X-Frame-Options":            "Prevents clickjacking",
    "X-Content-Type-Options":     "Prevents MIME sniffing",
    "Referrer-Policy":            "Controls referrer information leakage",
    "Permissions-Policy":         "Restricts browser feature access",
    "X-XSS-Protection":           "Legacy XSS filter (older browsers)",
    "Cross-Origin-Opener-Policy": "Isolates browsing context",
    "Cross-Origin-Resource-Policy":"Restricts cross-origin resource reads",
}


def check_subdomain(sub, domain, resolver):
    fqdn = f"{sub}.{domain}"
    try:
        answers = resolver.resolve(fqdn, "A")
        return {"subdomain": fqdn, "ips": [str(r) for r in answers], "status": "live"}
    except Exception:
        return None

def brute_force_subdomains(domain, emit):
    emit(f"Phase A: Recon — Brute-forcing {len(SUBDOMAIN_WORDLIST)} subdomains on {domain}", 8)
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 2
    resolver.lifetime = 2
    resolver.nameservers = ["8.8.8.8","1.1.1.1"]
    found = []
    total = len(SUBDOMAIN_WORDLIST)
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_subdomain, sub, domain, resolver): sub
                   for sub in SUBDOMAIN_WORDLIST}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            result = future.result()
            if result:
                found.append(result)
                emit(f"Phase A: Recon — Found: {result['subdomain']}", int(8 + (done/total)*12))
    if not found:
        emit(f"Phase A: Recon — No subdomains found", 20)
    return found

def fingerprint_tech(response):
    detected = []
    body    = response.text.lower()
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    cookies = [c.lower() for c in response.cookies.keys()]
    for tech, sigs in TECH_SIGNATURES.items():
        matched = False
        for p in sigs.get("body",[]):
            if p.lower() in body: matched = True; break
        if not matched:
            for p in sigs.get("headers",[]):
                k, _, v = p.lower().partition(": ")
                if v in headers.get(k,"") or (not v and k in headers):
                    matched = True; break
        if not matched:
            for p in sigs.get("cookies",[]):
                if any(p.lower() in c for c in cookies):
                    matched = True; break
        if matched:
            detected.append(tech)
    return detected

def detect_waf(response):
    detected = []
    header_str = " ".join(f"{k}: {v}" for k,v in response.headers.items()).lower()
    cookie_str = " ".join(response.cookies.keys()).lower()
    for waf, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in header_str or sig.lower() in cookie_str:
                detected.append(waf); break
    try:
        probe = requests.get(response.url + "/?id=1'%20OR%20'1'='1",
                             timeout=8, allow_redirects=True)
        if probe.status_code in [403,406,429,503] and not detected:
            detected.append("Unknown WAF (blocked suspicious request)")
    except Exception:
        pass
    return detected if detected else ["None detected"]

def audit_headers(response):
    present, missing, leaky = {}, {}, {}
    rl = {k.lower(): v for k,v in response.headers.items()}
    for header, desc in SECURITY_HEADERS.items():
        if header.lower() in rl:
            present[header] = rl[header.lower()]
        else:
            missing[header] = desc
    for h in ["server","x-powered-by","x-aspnet-version"]:
        if h in rl:
            leaky[h] = rl[h]
    return {"present": present, "missing": missing, "leaky": leaky,
            "score": len(present), "max_score": len(SECURITY_HEADERS)}

def run(target_url, emit):
    emit("Phase A: Recon — Starting intelligence gathering", 5)
    parsed = urlparse(target_url)
    domain = (parsed.netloc or parsed.path).replace("www.","")

    emit("Phase A: Recon — Fetching target", 6)
    response = None
    try:
        response = requests.get(target_url, timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSudarshan/1.0)"},
            allow_redirects=True)
    except Exception as e:
        emit(f"Phase A: Recon — ERROR: {str(e)[:60]}", 6)
        return {"domain":domain,"status_code":0,"final_url":"","subdomains":[],
                "tech_stack":[],"waf":["Unknown"],
                "header_audit":{"present":{},"missing":{},"leaky":{},"score":0,"max_score":9},
                "findings":[],"server":"Unknown","powered_by":"Unknown"}

    subdomains   = brute_force_subdomains(domain, emit)
    emit("Phase A: Recon — Fingerprinting technology stack", 21)
    tech_stack   = fingerprint_tech(response)
    emit(f"Phase A: Recon — Detected: {', '.join(tech_stack) or 'Nothing identified'}", 22)
    emit("Phase A: Recon — Detecting WAF", 23)
    wafs         = detect_waf(response)
    emit(f"Phase A: Recon — WAF: {', '.join(wafs)}", 23)
    emit("Phase A: Recon — Auditing security headers", 24)
    header_audit = audit_headers(response)
    emit(f"Phase A: Recon — Header score: {header_audit['score']}/{header_audit['max_score']}", 24)

    findings = []
    for header, desc in header_audit["missing"].items():
        findings.append({
            "type": "Missing Security Header", "severity": "Medium",
            "url": target_url,
            "description": f"Header '{header}' is missing. {desc}.",
            "proof": "", "fixSnippet": f"Add to server config: {header}: <value>"
        })
    for header, value in header_audit["leaky"].items():
        findings.append({
            "type": "Information Disclosure", "severity": "Low",
            "url": target_url,
            "description": f"Header '{header}' reveals server info: '{value}'",
            "proof": "", "fixSnippet": f"Remove or obscure '{header}' in server config."
        })

    emit("Phase A: Recon — Complete", 24)
    return {
        "domain": domain, "status_code": response.status_code,
        "final_url": response.url, "subdomains": subdomains,
        "tech_stack": tech_stack, "waf": wafs,
        "header_audit": header_audit, "findings": findings,
        "server": response.headers.get("Server","Unknown"),
        "powered_by": response.headers.get("X-Powered-By","Unknown"),
    }