#!/usr/bin/env python3
# Web Vulnerability Scanner v2
# Usage: python web_vuln_scanner.py <url>
# Only scan systems you own or have permission to test.

import requests
import sys
import urllib.parse
import socket
from colorama import Fore, init

init(autoreset=True)

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}

# ── Payloads ───────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    '" OR "1"="1',
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate", "sql syntax", "syntax error",
    "microsoft ole db", "odbc sql server driver",
    "pg_query()", "sqlite3",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert(1)</script>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "////evil.com",
    "https:evil.com",
]

REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "returnurl", "return_url",
    "goto", "dest", "destination", "redir", "redirect_uri",
    "continue", "target", "location", "forward",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../windows/win.ini",
]

TRAVERSAL_SIGS = [
    "root:x:0:0", "/bin/bash", "[fonts]", "[extensions]",
]

SECURITY_HEADERS = {
    "Content-Security-Policy":   "Prevents XSS & injection",
    "X-Content-Type-Options":    "Stops MIME sniffing",
    "X-Frame-Options":           "Blocks clickjacking",
    "X-XSS-Protection":          "Legacy XSS filter",
    "Strict-Transport-Security": "Forces HTTPS",
    "Referrer-Policy":           "Limits referrer leakage",
    "Permissions-Policy":        "Restricts browser APIs",
    "Cache-Control":             "Prevents sensitive caching",
}

SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "app", "vpn", "blog", "shop", "secure", "webmail",
    "cdn", "static", "support", "login", "dashboard", "beta",
    "old", "internal", "corp", "ns1", "ns2", "media",
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def ok(m):   print(Fore.GREEN  + f"  [✓] {m}")
def bad(m):  print(Fore.RED    + f"  [✗] {m}")
def info(m): print(Fore.BLUE   + f"  [i] {m}")
def warn(m): print(Fore.YELLOW + f"  [!] {m}")

def section(title):
    print(f"\n{Fore.CYAN}{'─' * 52}\n  {title}\n{'─' * 52}")

def get_forms(url, session):
    from html.parser import HTMLParser

    class FP(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms, self._form, self._inputs = [], None, []

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower()}
                self._inputs = []
            elif tag == "input" and self._form:
                self._inputs.append({"name": a.get("name", "f"), "type": a.get("type", "text"), "value": a.get("value", "")})

        def handle_endtag(self, tag):
            if tag == "form" and self._form:
                self._form["inputs"] = self._inputs
                self.forms.append(self._form)
                self._form, self._inputs = None, []

    try:
        p = FP()
        p.feed(session.get(url, headers=HEADERS, timeout=TIMEOUT).text)
        return p.forms
    except Exception:
        return []

def form_data(inputs, payload):
    skip = ("submit", "button", "image", "reset", "file")
    return {i["name"]: payload if i["type"] not in skip else i["value"] for i in inputs}

def full_url(base, action):
    return urllib.parse.urljoin(base, action) if action else base

def root_domain(url):
    d = urllib.parse.urlparse(url).netloc.split(":")[0]
    return d[4:] if d.startswith("www.") else d

# ── Checks ─────────────────────────────────────────────────────────────────────

def check_headers(url, session):
    section("1 · Security Headers")
    missing, present = [], []
    try:
        resp = {k.lower(): v for k, v in session.get(url, headers=HEADERS, timeout=TIMEOUT).headers.items()}
        for h, desc in SECURITY_HEADERS.items():
            if h.lower() in resp:
                ok(f"{h}")
                present.append(h)
            else:
                bad(f"Missing {h} — {desc}")
                missing.append(h)
    except Exception as e:
        warn(str(e))
    return {"missing": missing, "present": present}


def check_sqli(url, session):
    section("2 · SQL Injection")
    found = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if params:
        for param in params:
            for payload in SQLI_PAYLOADS:
                p = {k: v[0] for k, v in params.items()}
                p[param] = payload
                try:
                    r = session.get(parsed._replace(query=urllib.parse.urlencode(p)).geturl(), headers=HEADERS, timeout=TIMEOUT)
                    if any(e in r.text.lower() for e in SQLI_ERRORS):
                        bad(f"SQLi in '{param}' → {payload!r}")
                        found.append(param)
                        break
                except Exception:
                    pass

    for i, form in enumerate(get_forms(url, session), 1):
        action = full_url(url, form["action"])
        for payload in SQLI_PAYLOADS:
            data = form_data(form["inputs"], payload)
            try:
                fn = session.post if form["method"] == "post" else session.get
                r = fn(action, **{"data" if form["method"] == "post" else "params": data}, headers=HEADERS, timeout=TIMEOUT)
                if any(e in r.text.lower() for e in SQLI_ERRORS):
                    bad(f"SQLi in form #{i} ({form['method'].upper()} {action})")
                    found.append(f"form{i}")
                    break
            except Exception:
                pass

    if not found:
        ok("No SQLi found.")
    return found


def check_xss(url, session):
    section("3 · Cross-Site Scripting")
    found = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if params:
        for param in params:
            for payload in XSS_PAYLOADS:
                p = {k: v[0] for k, v in params.items()}
                p[param] = payload
                try:
                    r = session.get(parsed._replace(query=urllib.parse.urlencode(p)).geturl(), headers=HEADERS, timeout=TIMEOUT)
                    if payload in r.text:
                        bad(f"XSS in '{param}'")
                        found.append(param)
                        break
                except Exception:
                    pass

    for i, form in enumerate(get_forms(url, session), 1):
        action = full_url(url, form["action"])
        for payload in XSS_PAYLOADS:
            data = form_data(form["inputs"], payload)
            try:
                fn = session.post if form["method"] == "post" else session.get
                r = fn(action, **{"data" if form["method"] == "post" else "params": data}, headers=HEADERS, timeout=TIMEOUT)
                if payload in r.text:
                    bad(f"XSS in form #{i}")
                    found.append(f"form{i}")
                    break
            except Exception:
                pass

    if not found:
        ok("No XSS found. (Stored/DOM XSS needs manual testing)")
    return found


def check_redirect(url, session):
    section("4 · Open Redirect")
    found = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    targets = [p for p in params if p.lower() in REDIRECT_PARAMS] or REDIRECT_PARAMS[:5]
    info(f"Testing params: {targets}")

    for param in targets:
        for payload in REDIRECT_PAYLOADS:
            p = {k: v[0] for k, v in params.items()}
            p[param] = payload
            try:
                r = session.get(parsed._replace(query=urllib.parse.urlencode(p)).geturl(),
                                headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc or payload in loc:
                        bad(f"Redirect via '{param}' → {loc}")
                        found.append(param)
            except Exception:
                pass

    if not found:
        ok("No open redirects found.")
    return found


def check_traversal(url, session):
    section("5 · Directory Traversal")
    found = []
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    file_kw = ["file", "path", "page", "include", "doc", "folder", "load", "read", "template"]
    targets = [p for p in params if any(k in p.lower() for k in file_kw)] or list(params.keys())

    if not targets:
        ok("No parameters to test.")
        return found

    for param in targets:
        for payload in TRAVERSAL_PAYLOADS:
            p = {k: v[0] for k, v in params.items()}
            p[param] = payload
            try:
                r = session.get(parsed._replace(query=urllib.parse.urlencode(p)).geturl(), headers=HEADERS, timeout=TIMEOUT)
                if any(sig.lower() in r.text.lower() for sig in TRAVERSAL_SIGS):
                    bad(f"Traversal in '{param}' → {payload!r}")
                    found.append(param)
                    break
            except Exception:
                pass

    if not found:
        ok("No directory traversal found.")
    return found


def check_csrf(url, session):
    section("6 · CSRF Token Detection")
    issues = []
    forms = get_forms(url, session)

    if not forms:
        info("No forms found.")
        return issues

    csrf_kw = ["csrf", "token", "_token", "xsrf", "nonce", "authenticity_token"]

    for i, form in enumerate(forms, 1):
        if form["method"] != "post":
            ok(f"Form #{i} — GET, CSRF N/A")
            continue
        hidden = [f for f in form["inputs"] if f["type"] == "hidden"]
        has_token = any(any(k in f["name"].lower() for k in csrf_kw) for f in hidden)

        if has_token:
            ok(f"Form #{i} — CSRF token present")
        elif not hidden:
            bad(f"Form #{i} POST to '{form['action']}' — no CSRF token")
            issues.append(f"form{i}")
        else:
            warn(f"Form #{i} — hidden fields but no recognised token: {[h['name'] for h in hidden]}")
            issues.append(f"form{i}")

    if not issues:
        ok("All POST forms have CSRF protection.")
    return issues


def check_subdomains(url):
    section("7 · Subdomain Enumeration")
    found = []
    domain = root_domain(url)
    info(f"Checking {len(SUBDOMAINS)} subdomains for {domain} ...")

    for sub in SUBDOMAINS:
        host = f"{sub}.{domain}"
        try:
            ips = list(set(r[4][0] for r in socket.getaddrinfo(host, None)))
            ok(f"{host} → {', '.join(ips)}")
            found.append({"host": host, "ips": ips})
        except socket.gaierror:
            pass

    if not found:
        ok("No subdomains found.")
    return found

# ── Summary ────────────────────────────────────────────────────────────────────

def summary(hdr, sqli, xss, redir, trav, csrf, subs):
    section("Scan Summary")
    rows = [
        ("Missing headers",    len(hdr["missing"])),
        ("SQL Injection",      len(sqli)),
        ("XSS",                len(xss)),
        ("Open Redirect",      len(redir)),
        ("Dir Traversal",      len(trav)),
        ("CSRF Issues",        len(csrf)),
        ("Subdomains found",   len(subs)),
    ]
    print()
    for label, n in rows:
        print(f"  {label:<22} {Fore.RED + str(n) if n else Fore.GREEN + str(n)}")
    total = sum(n for _, n in rows)
    print(f"\n  {'─' * 36}")
    print(f"  {'Total':<22} {Fore.RED + str(total) if total else Fore.GREEN + str(total)}")
    if total:
        print(f"\n{Fore.YELLOW}  Verify findings manually. Only test systems you have permission to scan.")
    else:
        print(f"\n{Fore.GREEN}  Clean scan.")
    print()

# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    print(Fore.CYAN + "\n  Web Vulnerability Scanner v2\n")

    if len(sys.argv) < 2:
        print(f"  Usage: python {sys.argv[0]} <url>")
        sys.exit(1)

    target = sys.argv[1].strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    print(f"  Target : {Fore.CYAN}{target}")
    print(f"  {Fore.YELLOW}Only scan systems you own or have permission to test.\n")

    with requests.Session() as s:
        hdr  = check_headers(target, s)
        sqli = check_sqli(target, s)
        xss  = check_xss(target, s)
        redir = check_redirect(target, s)
        trav  = check_traversal(target, s)
        csrf  = check_csrf(target, s)

    subs = check_subdomains(target)
    summary(hdr, sqli, xss, redir, trav, csrf, subs)


if __name__ == "__main__":
    main()
