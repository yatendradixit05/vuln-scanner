"""
OSINT Engine — Social & Human Layer Attack Surface Mapping
Detects: Email exposure, phishing surface, employee mapping,
         breach data indicators, social engineering vectors
"""

import requests
import re
import time
import socket
from urllib.parse import urlparse

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; CyberSudarshan/1.0)"}
TIMEOUT = 10

def safe_get(url, params=None, headers=None):
    try:
        h = {**HEADERS, **(headers or {})}
        return requests.get(url, params=params, headers=h,
                            timeout=TIMEOUT, verify=False,
                            allow_redirects=True)
    except Exception:
        return None

def finding(vuln_type, severity, url, description, proof=""):
    return {
        "type":        vuln_type,
        "severity":    severity,
        "url":         url,
        "description": description,
        "proof":       proof,
        "fixSnippet":  get_fix(vuln_type),
    }

def get_fix(t):
    fixes = {
        "Email Exposure":
            "Remove email addresses from public pages. "
            "Use contact forms instead of direct email links.",
        "Phishing Surface":
            "Register similar domain names. Monitor for phishing sites. "
            "Enable DMARC, SPF, DKIM for email authentication.",
        "Employee OSINT":
            "Limit employee information on public pages. "
            "Train staff on social engineering awareness.",
        "Sensitive Document Exposure":
            "Remove sensitive documents from public access. "
            "Audit web server for unintended file exposure.",
        "Breach Indicator":
            "Rotate all credentials. Enable breach monitoring. "
            "Implement password manager policies.",
        "DNS Misconfiguration":
            "Review DNS records. Remove unused records. "
            "Enable DNSSEC for integrity.",
        "SPF/DMARC Missing":
            "Configure SPF: v=spf1 include:_spf.google.com ~all\n"
            "Configure DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
        "Subdomain Exposure":
            "Audit all subdomains. Remove unused ones. "
            "Monitor certificate transparency logs.",
    }
    return fixes.get(t, "Review and remediate the identified exposure.")


# ─────────────────────────────────────────────
# 1. EMAIL HARVESTING
# ─────────────────────────────────────────────

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

def harvest_emails(base_url, pages_visited, findings):
    emails_found = set()
    domain = urlparse(base_url).hostname or ""

    pages_to_check = list(pages_visited)[:15]
    pages_to_check += [
        base_url.rstrip("/") + p for p in
        ["/contact","/about","/team","/staff",
         "/support","/about-us","/our-team","/contact-us"]
    ]

    for url in pages_to_check:
        resp = safe_get(url)
        if not resp or resp.status_code != 200:
            continue

        emails = EMAIL_PATTERN.findall(resp.text)
        for email in emails:
            if domain in email or "example" not in email:
                emails_found.add(email)

    if emails_found:
        email_list = list(emails_found)[:20]
        findings.append(finding(
            "Email Exposure", "Medium", base_url,
            f"{len(email_list)} email addresses found publicly. "
            f"Exposed emails can be used for phishing, spam, "
            f"and credential stuffing attacks.",
            f"Emails: {', '.join(email_list[:5])}"
            f"{'...' if len(email_list) > 5 else ''}"
        ))

    return list(emails_found)


# ─────────────────────────────────────────────
# 2. PHISHING SURFACE DETECTION
# ─────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "login","signin","sign-in","account","secure","verify",
    "update","confirm","bank","paypal","amazon","microsoft",
    "google","apple","netflix","facebook","instagram",
]

def detect_phishing_surface(domain, findings):
    base_domain = domain.replace("www.","")
    parts       = base_domain.split(".")
    name        = parts[0] if parts else base_domain

    similar_domains = []
    typos = [
        # Typosquatting patterns
        name[:-1],           # Drop last char
        name + "s",          # Add s
        name + "-login",
        name + "-secure",
        name + "-verify",
        name + "-official",
        "login-" + name,
        "secure-" + name,
        "my" + name,
        name + "online",
        name.replace("o","0"),
        name.replace("l","1"),
        name.replace("i","1"),
    ]

    for typo in typos:
        for tld in [".com",".net",".org",".co",".io"]:
            test_domain = typo + tld
            if test_domain == base_domain:
                continue
            try:
                ip = socket.gethostbyname(test_domain)
                similar_domains.append({
                    "domain": test_domain,
                    "ip":     ip
                })
            except Exception:
                pass
        time.sleep(0.05)

    if similar_domains:
        findings.append(finding(
            "Phishing Surface", "High",
            f"https://{base_domain}",
            f"{len(similar_domains)} similar/typosquat domains found registered. "
            "These may be used for phishing attacks targeting your users.",
            f"Similar domains: " +
            ", ".join([d["domain"] for d in similar_domains[:5]])
        ))

    return similar_domains


# ─────────────────────────────────────────────
# 3. EMPLOYEE / PEOPLE OSINT
# ─────────────────────────────────────────────

EMPLOYEE_PATTERNS = [
    re.compile(r'(?i)(?:CEO|CTO|CFO|COO|Director|Manager|Engineer|Developer'
               r'|Designer|Analyst|Founder|President|VP|Head of)\s*:?\s*'
               r'([A-Z][a-z]+ [A-Z][a-z]+)'),
    re.compile(r'(?i)(?:by|author|written by|posted by)\s+([A-Z][a-z]+ [A-Z][a-z]+)'),
]

def harvest_employees(base_url, pages_visited, findings):
    employees = set()
    pages = list(pages_visited)[:10] + [
        base_url.rstrip("/") + p
        for p in ["/about","/team","/staff","/about-us","/our-team"]
    ]

    for url in pages:
        resp = safe_get(url)
        if not resp or resp.status_code != 200:
            continue
        for pattern in EMPLOYEE_PATTERNS:
            matches = pattern.findall(resp.text)
            for match in matches:
                if len(match) > 4:
                    employees.add(match.strip())

    if employees:
        emp_list = list(employees)[:15]
        findings.append(finding(
            "Employee OSINT", "Low",
            base_url,
            f"{len(emp_list)} employee names found on public pages. "
            "Names + company domain can be used to guess corporate emails "
            "for spear phishing and credential attacks.",
            f"Names found: {', '.join(emp_list[:5])}"
        ))

    return list(employees)


# ─────────────────────────────────────────────
# 4. SENSITIVE DOCUMENT DISCOVERY
# ─────────────────────────────────────────────

SENSITIVE_DOCS = [
    "/sitemap.xml",
    "/robots.txt",
    "/humans.txt",
    "/.well-known/security.txt",
    "/wp-json/wp/v2/users",
    "/api/v1/users",
    "/api/users",
]

DOC_EXTENSIONS = [
    ".pdf",".doc",".docx",".xls",".xlsx",
    ".ppt",".pptx",".csv",".txt",".rtf",
]

SENSITIVE_DOC_KEYWORDS = [
    "salary","payroll","invoice","contract","agreement",
    "confidential","private","internal","employee","budget",
    "financial","quarterly","annual report","merger","acquisition",
]

def discover_sensitive_docs(base_url, pages_visited, findings):
    base = base_url.rstrip("/")

    # Check known paths
    for path in SENSITIVE_DOCS:
        resp = safe_get(base + path)
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            if path == "/wp-json/wp/v2/users":
                # WordPress user enumeration
                try:
                    users = resp.json()
                    if isinstance(users, list) and len(users) > 0:
                        usernames = [u.get("name","") for u in users[:5]]
                        findings.append(finding(
                            "Employee OSINT", "Medium",
                            base + path,
                            f"WordPress user enumeration: {len(users)} users exposed. "
                            f"Usernames: {', '.join(usernames)}",
                            f"GET {path} → {len(users)} users"
                        ))
                except Exception:
                    pass

    # Find doc links in pages
    doc_links = []
    for url in list(pages_visited)[:10]:
        resp = safe_get(url)
        if not resp:
            continue
        for ext in DOC_EXTENSIONS:
            links = re.findall(
                rf'href=["\']([^"\']*{re.escape(ext)}[^"\']*)["\']',
                resp.text, re.IGNORECASE
            )
            doc_links.extend(links[:3])

    sensitive_docs = []
    for link in doc_links[:20]:
        for keyword in SENSITIVE_DOC_KEYWORDS:
            if keyword in link.lower():
                sensitive_docs.append(link)
                break

    if sensitive_docs:
        findings.append(finding(
            "Sensitive Document Exposure", "High",
            base_url,
            f"{len(sensitive_docs)} potentially sensitive documents found linked. "
            "Documents with financial, HR, or confidential data may be accessible.",
            f"Documents: {', '.join(sensitive_docs[:3])}"
        ))


# ─────────────────────────────────────────────
# 5. DNS / EMAIL SECURITY
# ─────────────────────────────────────────────

def check_email_security(domain, findings):
    base_domain = domain.replace("www.","")

    # Check SPF
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8","1.1.1.1"]
        resolver.timeout = 3

        spf_found   = False
        dmarc_found = False
        dkim_found  = False

        try:
            answers = resolver.resolve(base_domain, "TXT")
            for rdata in answers:
                txt = str(rdata)
                if "v=spf1" in txt:
                    spf_found = True
                if "v=DMARC1" in txt.upper():
                    dmarc_found = True
        except Exception:
            pass

        try:
            answers = resolver.resolve(f"_dmarc.{base_domain}", "TXT")
            for rdata in answers:
                if "v=DMARC1" in str(rdata).upper():
                    dmarc_found = True
        except Exception:
            pass

        try:
            resolver.resolve(f"default._domainkey.{base_domain}", "TXT")
            dkim_found = True
        except Exception:
            pass

        missing = []
        if not spf_found:   missing.append("SPF")
        if not dmarc_found: missing.append("DMARC")
        if not dkim_found:  missing.append("DKIM")

        if missing:
            findings.append(finding(
                "SPF/DMARC Missing", "High",
                f"https://{base_domain}",
                f"Email security records missing: {', '.join(missing)}. "
                "Domain can be spoofed for phishing emails. "
                "Attackers can send emails appearing to be from your domain.",
                f"Missing: {', '.join(missing)}"
            ))

    except ImportError:
        pass
    except Exception:
        pass


# ─────────────────────────────────────────────
# 6. BREACH DATA INDICATOR
# ─────────────────────────────────────────────

def check_breach_indicators(emails, domain, findings):
    if not emails:
        return

    # Check HaveIBeenPwned API (public, no key needed for domain check)
    try:
        domain_clean = domain.replace("www.","")
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain_clean}",
            headers={**HEADERS, "hibp-api-key": ""},
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                findings.append(finding(
                    "Breach Indicator", "Critical",
                    f"https://{domain_clean}",
                    f"Domain '{domain_clean}' found in {len(data)} known data breaches. "
                    "Employee/user credentials may be compromised.",
                    f"Breach count: {len(data)}"
                ))
    except Exception:
        pass


# ─────────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────────

def run(target_url, crawl_data, emit):
    findings_list = []
    pages_visited = crawl_data.get("pages_visited", [])
    domain = urlparse(target_url).hostname or ""

    emit("OSINT — Email harvesting", 91)
    emails = harvest_emails(target_url, pages_visited, findings_list)

    emit("OSINT — Phishing surface detection", 91)
    detect_phishing_surface(domain, findings_list)

    emit("OSINT — Employee OSINT mapping", 92)
    harvest_employees(target_url, pages_visited, findings_list)

    emit("OSINT — Sensitive document discovery", 92)
    discover_sensitive_docs(target_url, pages_visited, findings_list)

    emit("OSINT — Email security (SPF/DMARC/DKIM)", 93)
    check_email_security(domain, findings_list)

    emit("OSINT — Breach data indicators", 93)
    check_breach_indicators(emails, domain, findings_list)

    emit(f"OSINT — Complete. {len(findings_list)} social/human findings.", 93)
    return findings_list