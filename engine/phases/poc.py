from playwright.sync_api import sync_playwright
import os, re

SCREENSHOTS_DIR = os.path.join(os.path.dirname(__file__), "..", "screenshots")

SEVERITY_BASE = {"Critical":9.5,"High":7.5,"Medium":5.0,"Low":3.0,"Info":1.0}

EXPLOITABILITY = {
    "SQL Injection":              {"ease":"Low",    "impact":"Full DB compromise",        "mod":+1.0},
    "XSS":                        {"ease":"Medium", "impact":"Session hijack/defacement", "mod":+0.5},
    "Command Injection":          {"ease":"Low",    "impact":"Full server takeover",      "mod":+1.5},
    "Sensitive File Exposed":     {"ease":"None",   "impact":"Info disclosure",           "mod":+0.3},
    "Open Redirect":              {"ease":"Medium", "impact":"Phishing/redirect",         "mod": 0.0},
    "CORS Misconfiguration":      {"ease":"Medium", "impact":"Cross-origin data leak",    "mod":+0.2},
    "Missing Security Header":    {"ease":"High",   "impact":"Increases attack surface",  "mod":-1.0},
    "Information Disclosure":     {"ease":"None",   "impact":"Tech stack revealed",       "mod":-0.5},
}

PRIORITY = {
    "Critical":"Patch immediately — within 24 hours",
    "High":    "Patch within 7 days",
    "Medium":  "Patch within 30 days",
    "Low":     "Address in next release cycle",
    "Info":    "Review and document",
}

SCREENSHOT_WORTHY = ["SQL Injection","XSS","Command Injection",
                     "Sensitive File Exposed","Open Redirect","CORS Misconfiguration"]

def score(f):
    base = SEVERITY_BASE.get(f.get("severity","Medium"), 5.0)
    mod  = EXPLOITABILITY.get(f.get("type",""), {}).get("mod", 0.0)
    return round(min(10.0, max(0.0, base + mod)), 1)

def enrich(f):
    expl = EXPLOITABILITY.get(f.get("type",""), {})
    s    = score(f)
    if s >= 9.0:   sev = "Critical"
    elif s >= 7.0: sev = "High"
    elif s >= 4.0: sev = "Medium"
    elif s >= 1.0: sev = "Low"
    else:          sev = "Info"
    f["severity"]             = sev
    f["cvss_score"]           = s
    f["ease_of_exploit"]      = expl.get("ease","Unknown")
    f["impact"]               = expl.get("impact","Unknown")
    f["remediation_priority"] = PRIORITY.get(sev,"Review")
    return f

def screenshot(url, filename, payload=None):
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            page    = browser.new_page(ignore_https_errors=True)
            target  = url if "?" in url else url + ("?q=" + payload[:80] if payload else "")
            page.goto(target, timeout=12000, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
            page.screenshot(path=filepath, full_page=False)
            browser.close()
            return filepath
    except Exception:
        return None

def run(findings, emit):
    emit("Phase D: PoC — Scoring findings with CVSS algorithm", 81)
    enriched = []
    sc = 0
    for f in findings:
        f = enrich(f)
        if f["type"] in SCREENSHOT_WORTHY and sc < 5:
            emit(f"Phase D: PoC — Screenshot: {f['type']} @ {f['url'][:50]}", 83)
            name    = re.sub(r"[^a-z0-9]","_",f["type"].lower())
            payload = f.get("proof","").replace("Payload used: ","")
            path    = screenshot(f["url"], f"{name}_{sc+1}.png", payload or None)
            if path:
                f["screenshot"] = path
                sc += 1
        enriched.append(f)

    enriched.sort(key=lambda x: x.get("cvss_score",0), reverse=True)
    counts = {k:0 for k in ["Critical","High","Medium","Low","Info"]}
    for f in enriched:
        counts[f.get("severity","Info")] += 1

    emit(f"Phase D: PoC — Done. Critical:{counts['Critical']} High:{counts['High']} "
         f"Medium:{counts['Medium']} Low:{counts['Low']} Screenshots:{sc}", 88)
    return enriched