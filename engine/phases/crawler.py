from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
from urllib.parse import urlparse, parse_qs, urlunparse

MAX_PAGES  = 25
MAX_DEPTH  = 3
TIMEOUT_MS = 15000

def same_domain(base_url, url):
    return urlparse(base_url).netloc == urlparse(url).netloc

def normalize(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))

def extract_params(url):
    return list(parse_qs(urlparse(url).query).keys())

def setup_ajax(page, ajax_list):
    def handle(req):
        if req.resource_type in ["xhr","fetch"] and req.url not in ajax_list:
            ajax_list.append(req.url)
    page.on("request", handle)

def analyze_page(page, base_url):
    data = {"links":[], "forms":[], "url_params":[]}
    try:
        data["links"] = [a for a in page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.href)")
            if a.startswith("http") and same_domain(base_url, a)]
    except Exception:
        pass
    try:
        data["forms"] = page.eval_on_selector_all("form", """
            forms => forms.map(f => ({
                action: f.action || window.location.href,
                method: (f.method || 'GET').toUpperCase(),
                inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                    .map(i => ({name:i.name||i.id||'',type:i.type||'text',value:i.value||''}))
                    .filter(i => i.name)
            }))
        """)
    except Exception:
        pass
    data["url_params"] = extract_params(page.url)
    return data

def run(target_url, recon_data, emit):
    emit("Phase B: Crawling — Launching headless browser", 26)
    visited, to_visit = set(), [(target_url, 0)]
    all_links, all_forms, all_ajax, injectable = [], [], [], []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True,
            args=["--no-sandbox","--disable-setuid-sandbox"])
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            ignore_https_errors=True)
        page = context.new_page()
        setup_ajax(page, all_ajax)

        while to_visit and len(visited) < MAX_PAGES:
            url, depth = to_visit.pop(0)
            norm = normalize(url)
            if norm in visited or depth > MAX_DEPTH:
                continue
            visited.add(norm)
            emit(f"Phase B: Crawling — [{len(visited)}/{MAX_PAGES}] {url[:65]}", 27)
            try:
                page.goto(url, timeout=TIMEOUT_MS, wait_until="domcontentloaded")
                page.wait_for_timeout(1200)
            except Exception:
                continue

            pd = analyze_page(page, target_url)
            for form in pd["forms"]:
                form["source_url"] = url
                if form not in all_forms:
                    all_forms.append(form)
            if pd["url_params"]:
                injectable.append({"url": url, "params": pd["url_params"]})
            for link in pd["links"]:
                norm_l = normalize(link)
                if norm_l not in visited:
                    to_visit.append((link, depth+1))
                    all_links.append(link)
                if "?" in link and same_domain(target_url, link):
                    params = extract_params(link)
                    if params:
                        injectable.append({"url": link, "params": params})

        for sub in recon_data.get("subdomains",[])[:3]:
            sub_url = f"http://{sub['subdomain']}"
            try:
                page.goto(sub_url, timeout=8000, wait_until="domcontentloaded")
                page.wait_for_timeout(800)
                for form in analyze_page(page, sub_url)["forms"]:
                    form["source_url"] = sub_url
                    all_forms.append(form)
            except Exception:
                pass
        browser.close()

    seen, deduped = set(), []
    for item in injectable:
        key = item["url"].split("?")[0]
        if key not in seen:
            seen.add(key); deduped.append(item)

    emit(f"Phase B: Crawling — Done. Pages:{len(visited)} Forms:{len(all_forms)} Injectable:{len(deduped)}", 40)
    return {"pages_visited":list(visited),"links":list(set(all_links)),
            "forms":all_forms,"ajax_endpoints":all_ajax,"injectable_urls":deduped}