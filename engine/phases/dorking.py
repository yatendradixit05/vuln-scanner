"""
Google Dorking Module — Passive reconnaissance
Searches Google, Shodan-style queries without touching the target.
"""

import requests
import time
from urllib.parse import urlparse, quote

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}

GOOGLE_DORKS = [
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:sql',
    'site:{domain} filetype:log',
    'site:{domain} filetype:bak',
    'site:{domain} filetype:env',
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} inurl:config',
    'site:{domain} inurl:backup',
    'site:{domain} inurl:db',
    'site:{domain} inurl:passwd',
    'site:{domain} intitle:"index of"',
    'site:{domain} intitle:"phpMyAdmin"',
    'site:{domain} "DB_PASSWORD"',
    'site:{domain} "API_KEY"',
    'site:{domain} "aws_secret"',
    'site:{domain} ext:php inurl:?id=',
    'site:{domain} inurl:.git',
    'site:{domain} inurl:.env',
    'site:{domain} "error" "mysql" OR "sql"',
    '"@{domain}" email list',
    'site:{domain} inurl:wp-content',
    'site:{domain} inurl:wp-admin',
]

SHODAN_DORKS = [
    'hostname:{domain}',
    'ssl:{domain}',
    'http.title:"{company}"',
    'http.html:"{domain}"',
]


def search_google_dorks(domain, emit):
    """Search Google for dork results using SerpAPI-compatible approach."""
    results = []
    emit(f"Dorking — Generating Google dork queries for {domain}", 2)

    dork_queries = [d.replace("{domain}", domain) for d in GOOGLE_DORKS]

    # Try DuckDuckGo HTML (no API key needed)
    for dork in dork_queries[:10]:
        try:
            url = f"https://html.duckduckgo.com/html/?q={quote(dork)}"
            resp = requests.get(url, headers=HEADERS, timeout=10)

            if resp.status_code == 200:
                # Parse results
                import re
                links = re.findall(
                    r'class="result__url"[^>]*>([^<]+)<',
                    resp.text
                )
                titles = re.findall(
                    r'class="result__title"[^>]*>.*?<a[^>]*>([^<]+)<',
                    resp.text
                )

                if links:
                    results.append({
                        "dork":    dork,
                        "results": links[:3],
                        "titles":  titles[:3],
                        "risk":    classify_dork_risk(dork)
                    })
                    emit(f"Dorking — Found results for: {dork[:50]}", 3)

            time.sleep(1.5)  # Be respectful
        except Exception:
            pass

    return results


def check_wayback_machine(domain, emit):
    """Check Wayback Machine for historical sensitive files."""
    emit(f"Dorking — Checking Wayback Machine for {domain}", 4)
    results = []

    sensitive_patterns = [
        "*.env", "*.sql", "*.bak", "*.log",
        "*admin*", "*config*", "*backup*",
        "*.php.bak", "wp-config*"
    ]

    for pattern in sensitive_patterns[:5]:
        try:
            url = (f"http://web.archive.org/cdx/search/cdx"
                   f"?url={domain}/{pattern}&output=json"
                   f"&limit=5&fl=original,timestamp&filter=statuscode:200")
            resp = requests.get(url, timeout=10, headers=HEADERS)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:  # First row is header
                    for row in data[1:4]:
                        results.append({
                            "url":       row[0],
                            "timestamp": row[1],
                            "pattern":   pattern,
                            "source":    "Wayback Machine"
                        })
                        emit(f"Dorking — Wayback: {row[0][:60]}", 4)
        except Exception:
            pass

    return results


def check_certificate_transparency(domain, emit):
    """Check crt.sh for certificate transparency logs — finds subdomains."""
    emit(f"Dorking — Checking certificate transparency for {domain}", 5)
    subdomains = []

    try:
        url  = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15, headers=HEADERS)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[:50]:
                name = entry.get("name_value","")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub and sub not in subdomains and domain in sub:
                        subdomains.append(sub)
        emit(f"Dorking — Found {len(subdomains)} subdomains via CT logs", 5)
    except Exception:
        pass

    return list(set(subdomains))[:20]


def check_github_exposure(domain, company, emit):
    """Search GitHub for exposed secrets related to domain."""
    emit(f"Dorking — Checking GitHub public repos for {domain}", 6)
    results = []

    github_queries = [
        f"{domain} password",
        f"{domain} api_key",
        f"{domain} secret",
        f"{domain} DB_PASSWORD",
        f'"{domain}" "BEGIN RSA PRIVATE KEY"',
    ]

    # Use GitHub search API (public, no auth for basic)
    for query in github_queries[:3]:
        try:
            url = (f"https://api.github.com/search/code"
                   f"?q={quote(query)}&per_page=3")
            resp = requests.get(url, headers={
                **HEADERS,
                "Accept": "application/vnd.github.v3+json"
            }, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                if items:
                    results.append({
                        "query":   query,
                        "count":   data.get("total_count", 0),
                        "samples": [i.get("html_url","") for i in items[:2]],
                        "risk":    "High" if "password" in query.lower()
                                          or "secret" in query.lower()
                                          else "Medium"
                    })
                    emit(f"Dorking — GitHub: {data.get('total_count',0)} results "
                         f"for '{query[:40]}'", 6)
            time.sleep(2)
        except Exception:
            pass

    return results


def classify_dork_risk(dork):
    if any(x in dork for x in ["passwd","password","DB_","secret","aws","private"]):
        return "Critical"
    elif any(x in dork for x in ["admin","login","config","backup","sql","env"]):
        return "High"
    elif any(x in dork for x in ["filetype","inurl","intitle"]):
        return "Medium"
    return "Low"


def generate_dork_findings(dork_results, wayback_results,
                           ct_subdomains, github_results, target_url):
    """Convert dorking results to scanner findings format."""
    findings = []

    for result in dork_results:
        if result["results"]:
            findings.append({
                "type":        "Google Dork Exposure",
                "severity":    result["risk"],
                "url":         target_url,
                "description": f"Google dork '{result['dork']}' returned "
                               f"{len(result['results'])} results. "
                               f"Sensitive info may be indexed publicly.",
                "proof":       f"URLs found: {', '.join(result['results'][:2])}",
                "fixSnippet":  "Use robots.txt to prevent sensitive paths from indexing. "
                               "Remove sensitive files from production servers."
            })

    for wb in wayback_results:
        findings.append({
            "type":        "Wayback Machine Exposure",
            "severity":    "High",
            "url":         wb["url"],
            "description": f"Sensitive file '{wb['pattern']}' found in Wayback Machine "
                           f"archive (captured: {wb['timestamp'][:8]}). "
                           "Historical sensitive data may be accessible.",
            "proof":       f"Archive URL: {wb['url']}",
            "fixSnippet":  "Request removal from Wayback Machine at "
                           "https://archive.org/about/exclude.php"
        })

    if ct_subdomains:
        findings.append({
            "type":        "Certificate Transparency Exposure",
            "severity":    "Info",
            "url":         target_url,
            "description": f"{len(ct_subdomains)} subdomains found via certificate "
                           f"transparency logs: {', '.join(ct_subdomains[:5])}{'...' if len(ct_subdomains)>5 else ''}",
            "proof":       f"Source: crt.sh. Subdomains: {ct_subdomains[:5]}",
            "fixSnippet":  "Review if all subdomains are intentional and secure."
        })

    for gh in github_results:
        if gh["count"] > 0:
            findings.append({
                "type":        "GitHub Secret Exposure",
                "severity":    gh["risk"],
                "url":         target_url,
                "description": f"GitHub search '{gh['query']}' found {gh['count']} "
                               f"public code results. Credentials or API keys may be exposed.",
                "proof":       f"Sample URLs: {', '.join(gh['samples'][:2])}",
                "fixSnippet":  "Use GitHub secret scanning. Rotate exposed credentials. "
                               "Use environment variables, never hardcode secrets."
            })

    return findings


def run(target_url, emit):
    """Main dorking entry point — called before Phase A."""
    emit("Dorking — Starting passive reconnaissance", 1)

    parsed  = urlparse(target_url)
    domain  = parsed.hostname or ""
    company = domain.replace("www.","").split(".")[0]

    emit(f"Dorking — Target domain: {domain}", 1)

    # 1. Google Dorks
    dork_results = search_google_dorks(domain, emit)

    # 2. Wayback Machine
    wayback_results = check_wayback_machine(domain, emit)

    # 3. Certificate Transparency
    ct_subdomains = check_certificate_transparency(domain, emit)

    # 4. GitHub Exposure
    github_results = check_github_exposure(domain, company, emit)

    # Convert to findings
    findings = generate_dork_findings(
        dork_results, wayback_results,
        ct_subdomains, github_results, target_url
    )

    emit(f"Dorking — Complete. {len(findings)} passive findings.", 7)

    return {
        "findings":      findings,
        "dork_results":  dork_results,
        "wayback":       wayback_results,
        "ct_subdomains": ct_subdomains,
        "github":        github_results,
    }