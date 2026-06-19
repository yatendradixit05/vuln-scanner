"""
Behavior Analysis Engine — Anomaly-based unknown vulnerability detection
Detects behavioral anomalies without relying on known signatures.
"""

import requests
import time
import random
import string
import statistics
from urllib.parse import urlparse

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; CyberSudarshan/1.0)"}
TIMEOUT = 12

def safe_get(url, params=None, headers=None):
    try:
        h = {**HEADERS, **(headers or {})}
        start = time.time()
        resp  = requests.get(url, params=params, headers=h,
                             timeout=TIMEOUT, verify=False,
                             allow_redirects=False)
        elapsed = time.time() - start
        return resp, elapsed
    except Exception:
        return None, 0

def safe_post(url, data=None, headers=None):
    try:
        h = {**HEADERS, **(headers or {})}
        start = time.time()
        resp  = requests.post(url, data=data, headers=h,
                              timeout=TIMEOUT, verify=False,
                              allow_redirects=False)
        elapsed = time.time() - start
        return resp, elapsed
    except Exception:
        return None, 0

def finding(vuln_type, severity, url, description, proof=""):
    return {
        "type":        vuln_type,
        "severity":    severity,
        "url":         url,
        "description": description,
        "proof":       proof,
        "fixSnippet":  "Investigate anomalous server behavior. "
                       "Implement input validation and consistent error handling.",
    }

def random_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


# ─────────────────────────────────────────────
# 1. TIME-BASED ANOMALY DETECTION
# ─────────────────────────────────────────────

def detect_time_anomalies(injectable_urls, findings):
    for inj in injectable_urls[:10]:
        base   = inj["url"].split("?")[0]
        params = inj["params"]
        if not params:
            continue

        param = params[0]
        baseline_times = []

        # Baseline: 5 normal requests
        for _ in range(5):
            _, t = safe_get(base, {param: random_str()})
            if t > 0:
                baseline_times.append(t)
            time.sleep(0.1)

        if len(baseline_times) < 3:
            continue

        avg_baseline = statistics.mean(baseline_times)

        # Test time-based payloads
        time_payloads = [
            "' OR SLEEP(3)--",
            "1; WAITFOR DELAY '0:0:3'--",
            "' AND SLEEP(3) AND '1'='1",
            "|sleep 3",
            "$(sleep 3)",
            "`sleep 3`",
        ]

        for payload in time_payloads:
            _, t = safe_get(base, {param: payload})
            if t > avg_baseline + 2.5:  # 2.5s more than baseline
                findings.append(finding(
                    "Blind Time-Based Injection (Anomaly)",
                    "Critical", f"{base}?{param}=<payload>",
                    f"Time-based anomaly detected in param '{param}'. "
                    f"Baseline: {avg_baseline:.2f}s, "
                    f"With payload: {t:.2f}s (+{t-avg_baseline:.2f}s). "
                    "Possible blind SQL injection or command injection.",
                    f"Payload: {payload} | Time delta: +{t-avg_baseline:.2f}s"
                ))
                return


# ─────────────────────────────────────────────
# 2. RESPONSE SIZE ANOMALY
# ─────────────────────────────────────────────

def detect_size_anomalies(injectable_urls, findings):
    for inj in injectable_urls[:10]:
        base   = inj["url"].split("?")[0]
        params = inj["params"]
        if not params:
            continue

        param = params[0]

        # Baseline sizes
        baseline_sizes = []
        for i in range(5):
            resp, _ = safe_get(base, {param: random_str(8)})
            if resp:
                baseline_sizes.append(len(resp.text))

        if len(baseline_sizes) < 3:
            continue

        avg_size = statistics.mean(baseline_sizes)

        # Anomaly payloads
        anomaly_payloads = [
            "' OR 1=1--",
            "admin' --",
            "1 UNION SELECT 1,2,3--",
            "../../../etc/passwd",
            "{{7*7}}",
            "<script>",
            "' OR 'x'='x",
        ]

        for payload in anomaly_payloads:
            resp, _ = safe_get(base, {param: payload})
            if not resp:
                continue

            size = len(resp.text)
            diff = abs(size - avg_size)

            # Significant size difference = anomaly
            if diff > avg_size * 0.5 and diff > 500:
                findings.append(finding(
                    "Response Size Anomaly (Unknown Vuln)",
                    "High", f"{base}?{param}=<payload>",
                    f"Significant response size change with payload. "
                    f"Baseline: {int(avg_size)} bytes, "
                    f"With payload: {size} bytes (Δ{int(diff)} bytes). "
                    "Possible injection or data disclosure.",
                    f"Payload: {payload} | Size delta: {int(diff)} bytes"
                ))
                return


# ─────────────────────────────────────────────
# 3. ERROR PATTERN ANALYSIS
# ─────────────────────────────────────────────

ERROR_LEAK_PATTERNS = [
    # Stack traces
    r"at\s+\w+\.\w+\s*\(",
    r"Traceback \(most recent",
    r"Exception in thread",
    r"NullPointerException",
    r"StackOverflowError",
    # File paths
    r"[C-Z]:\\[^\s<>\"]+\.\w{2,4}",
    r"/var/www/[^\s<>\"]+",
    r"/home/[^\s<>\"]+\.php",
    r"/usr/local/[^\s<>\"]+",
    # DB errors
    r"mysql_connect\(\)",
    r"pg_connect\(\)",
    r"ORA-\d{5}",
    r"Microsoft OLE DB",
    # Source code
    r"<\?php",
    r"#!/usr/bin",
]

def detect_error_patterns(injectable_urls, forms, findings):
    import re

    chaos_payloads = [
        "'\"`;<>{}[]|\\",
        "NULL",
        "undefined",
        "NaN",
        "Infinity",
        "-Infinity",
        "0x00",
        "%00",
        "\x00",
        "A" * 10000,
        "1e999",
        "'",
    ]

    for inj in injectable_urls[:10]:
        base   = inj["url"].split("?")[0]
        params = inj["params"]

        for param in params[:2]:
            for payload in chaos_payloads[:6]:
                resp, _ = safe_get(base, {param: payload})
                if not resp:
                    continue

                for pattern in ERROR_LEAK_PATTERNS:
                    match = re.search(pattern, resp.text)
                    if match:
                        findings.append(finding(
                            "Verbose Error / Info Disclosure (Anomaly)",
                            "High", f"{base}?{param}=<payload>",
                            f"Error pattern detected in response to chaos input. "
                            f"Pattern: '{pattern}'. "
                            "Stack traces or file paths may be leaking.",
                            f"Payload: {payload[:50]} | "
                            f"Pattern: {pattern} | "
                            f"Match: {match.group()[:60]}"
                        ))
                        return


# ─────────────────────────────────────────────
# 4. HEADER REFLECTION ANOMALY
# ─────────────────────────────────────────────

def detect_header_reflection(base_url, findings):
    injection_headers = {
        "X-Forwarded-For":     f"<script>alert(1)</script>",
        "User-Agent":          f"' OR 1=1--",
        "Referer":             f"javascript:alert(1)",
        "Accept-Language":     f"{{{{7*7}}}}",
        "X-Custom-Header":     f"../../../etc/passwd",
        "X-Original-URL":      f"/admin",
        "X-Http-Method-Override": "DELETE",
    }

    for header, payload in injection_headers.items():
        try:
            resp = requests.get(base_url,
                headers={**HEADERS, header: payload},
                timeout=TIMEOUT, verify=False)
            if resp and payload in resp.text:
                findings.append(finding(
                    "Header Injection Reflected (Anomaly)",
                    "Medium", base_url,
                    f"HTTP header '{header}' value reflected in response body. "
                    "May enable header injection or XSS via header reflection.",
                    f"Header: {header}: {payload[:40]}"
                ))
                return
        except Exception:
            pass


# ─────────────────────────────────────────────
# 5. DIFFERENTIAL ANALYSIS
# ─────────────────────────────────────────────

def differential_analysis(injectable_urls, findings):
    """
    Compare responses to semantically similar but different inputs.
    Large differences suggest injection points.
    """
    for inj in injectable_urls[:8]:
        base   = inj["url"].split("?")[0]
        params = inj["params"]

        for param in params[:2]:
            # Pair 1: True vs False condition
            pairs = [
                ("1 AND 1=1", "1 AND 1=2"),
                ("' OR '1'='1", "' OR '1'='2"),
                ("true",  "false"),
                ("1",     "0"),
                ("admin", "xxxxxxxxnotexist"),
            ]

            for true_val, false_val in pairs:
                r1, _ = safe_get(base, {param: true_val})
                r2, _ = safe_get(base, {param: false_val})

                if not r1 or not r2:
                    continue

                size_diff = abs(len(r1.text) - len(r2.text))
                status_diff = r1.status_code != r2.status_code

                if status_diff and r1.status_code == 200:
                    findings.append(finding(
                        "Differential Response (Boolean Injection)",
                        "High", f"{base}?{param}=<payload>",
                        f"Different HTTP status codes for true/false inputs. "
                        f"True: {r1.status_code}, False: {r2.status_code}. "
                        "Boolean-based injection likely.",
                        f"True: {true_val} → {r1.status_code}, "
                        f"False: {false_val} → {r2.status_code}"
                    ))
                    return

                if size_diff > 200:
                    findings.append(finding(
                        "Differential Response (Possible Injection)",
                        "Medium", f"{base}?{param}=<payload>",
                        f"Response size differs by {size_diff} bytes for "
                        f"semantically opposite inputs ({true_val} vs {false_val}). "
                        "Injection or conditional logic difference detected.",
                        f"Size diff: {size_diff} bytes"
                    ))
                    return


# ─────────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────────

def run(target_url, crawl_data, emit):
    findings_list = []
    inj_urls = crawl_data.get("injectable_urls", [])
    forms    = crawl_data.get("forms", [])

    emit("Behavior Analysis — Time-based anomaly detection", 91)
    detect_time_anomalies(inj_urls, findings_list)

    emit("Behavior Analysis — Response size anomalies", 91)
    detect_size_anomalies(inj_urls, findings_list)

    emit("Behavior Analysis — Error pattern analysis", 92)
    detect_error_patterns(inj_urls, forms, findings_list)

    emit("Behavior Analysis — Header reflection anomalies", 92)
    detect_header_reflection(target_url, findings_list)

    emit("Behavior Analysis — Differential analysis", 93)
    differential_analysis(inj_urls, findings_list)

    emit(f"Behavior Analysis — Done. {len(findings_list)} anomalies found.", 93)
    return findings_list