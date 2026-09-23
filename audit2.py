#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SiteAuditor v4.0 - professional web security and exposure audit for one target.

Grades security headers BY VALUE, audits TLS end to end, checks SPF/DMARC/DKIM/
CAA/DNSSEC, verifies exposed files at byte level, inspects cookies, CORS, mixed
content, redirects, technology disclosure, directory listing and TCP port state.
Emits a themed multi-page PDF (executive summary, score breakdown, per-finding
impact and remediation with copy-paste config plus RFC/OWASP references, and
technical appendices) together with machine-readable JSON.

Non-destructive only: GET/HEAD/OPTIONS, one TCP connect per probed port and
ordinary DNS lookups. No payloads, no exploitation, no authentication bypass.
Use it only against assets you own or are authorised in writing to test.

Termux / Android, no root:   pip install requests reportlab
Optional extras:             pip install dnspython certifi cryptography
Persian report (sitefa.py):  pip install arabic-reshaper python-bidi

  audit example.com                    # bilingual CLI (siteaudit.py)
  audit example.com --lang fa|en|both  # choose the report language(s)
  audit example.com --json out.json --pdf report.pdf
  audit --render-json out.json --pdf report.pdf      # offline re-render

This module is the scanning engine plus the English report. The `audit`
command installed by Code.py is siteaudit.py, which runs one scan and emits
an English PDF (this file) and a Persian RTL PDF (sitefa.py); running this
file directly still produces the English report only.
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import socket
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

VERSION, TOOL = "4.0.0", "SiteAuditor v4.0"

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests\n  Termux:  pip install requests")
try:
    from reportlab.graphics.shapes import Circle, Drawing, Rect, Wedge
    from reportlab.graphics.shapes import String as DStr
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak,
                                    PageTemplate, Paragraph, Spacer, Table,
                                    TableStyle, XPreformatted)
except ImportError:
    sys.exit("Missing dependency: reportlab\n  Termux:  pip install reportlab")
try:
    import dns.flags
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False
try:
    import certifi
    CAFILE = certifi.where()
except ImportError:
    CAFILE = None
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

NAVY, INK, SLATE = "#0b1220", "#0f172a", "#334155"
MUTED, FAINT, LINE = "#64748b", "#94a3b8", "#e2e8f0"
BG, WHITE, TRACK, ACCENT = "#f8fafc", "#ffffff", "#eef2f7", "#4f46e5"
SEV_COLOR = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#d97706",
             "LOW": "#0891b2", "INFO": "#64748b", "OK": "#15803d"}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# header -> (short name, scoring weight, how to send it, why it matters, reference)
HEADERS = {
    "Strict-Transport-Security": ("HSTS", 10,
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "Forces HTTPS for a year and defeats SSL-strip downgrades.",
        "RFC 6797 / OWASP HSTS Cheat Sheet"),
    "Content-Security-Policy": ("CSP", 14,
        "Content-Security-Policy: default-src 'self'; script-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        "The primary in-browser control against XSS and injected frames.",
        "OWASP CSP Cheat Sheet / W3C CSP3"),
    "X-Frame-Options": ("XFO", 7, "X-Frame-Options: DENY",
        "Stops clickjacking; superseded by CSP frame-ancestors.", "RFC 7034"),
    "X-Content-Type-Options": ("XCTO", 6, "X-Content-Type-Options: nosniff",
        "Blocks MIME sniffing that turns uploads into scripts.",
        "WHATWG Fetch / OWASP Secure Headers"),
    "Referrer-Policy": ("REF", 6, "Referrer-Policy: strict-origin-when-cross-origin",
        "Keeps paths and query strings out of third-party logs.",
        "W3C Referrer Policy"),
    "Permissions-Policy": ("PERM", 5,
        "Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()",
        "Disables powerful browser features for embedded content.",
        "W3C Permissions Policy"),
    "Cross-Origin-Opener-Policy": ("COOP", 4, "Cross-Origin-Opener-Policy: same-origin",
        "Isolates the browsing context against cross-window attacks.",
        "HTML Standard / COOP"),
    "Cross-Origin-Resource-Policy": ("CORP", 3, "Cross-Origin-Resource-Policy: same-origin",
        "Stops other origins embedding your responses (Spectre hardening).",
        "W3C Fetch / CORP"),
}
HEADER_WEIGHT = float(sum(v[1] for v in HEADERS.values()))
DISCLOSURE = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Runtime",
              "X-Drupal-Cache", "X-Varnish", "X-Served-By", "X-Backend-Server", "Via",
              "X-Debug-Token", "Alt-Svc", "X-XSS-Protection", "X-Turbo-Charged-By"]

PATHS = ["/.env", "/.env.local", "/.env.production", "/.env.backup", "/.git/HEAD",
         "/.git/config", "/.svn/entries", "/.DS_Store", "/.htaccess", "/.htpasswd",
         "/.aws/credentials", "/.docker/config.json", "/.terraform.tfstate", "/id_rsa",
         "/sftp-config.json", "/config.json", "/config.yml", "/config.php.bak",
         "/wp-config.php.bak", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
         "/dump.sql", "/database.sql", "/server-status", "/server-info", "/nginx_status",
         "/phpinfo.php", "/info.php", "/debug.log", "/error.log",
         "/storage/logs/laravel.log", "/actuator/env", "/actuator/health",
         "/swagger.json", "/openapi.json", "/package.json", "/composer.json",
         "/composer.lock", "/Dockerfile", "/docker-compose.yml", "/web.config",
         "/crossdomain.xml", "/wp-json/wp/v2/users", "/xmlrpc.php"]
LISTING = ["/uploads/", "/images/", "/img/", "/files/", "/backup/", "/backups/", "/logs/",
           "/tmp/", "/data/", "/assets/", "/static/", "/media/", "/private/", "/old/"]
SUBS = ["www", "mail", "webmail", "smtp", "imap", "pop", "ftp", "cpanel", "webdisk",
        "autodiscover", "admin", "portal", "dashboard", "api", "dev", "staging", "stage",
        "test", "testing", "qa", "uat", "beta", "demo", "sandbox", "preview", "vpn",
        "remote", "gateway", "git", "gitlab", "jenkins", "ci", "build", "blog", "shop",
        "store", "support", "help", "docs", "wiki", "cdn", "static", "assets", "media",
        "files", "download", "db", "mysql", "redis", "ns1", "ns2", "mx", "status",
        "monitor", "intranet", "internal", "old", "new"]
PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 5900, 6379, 8080,
         8443, 27017]
PORTS_FULL = [135, 139, 445, 993, 995, 1433, 1521, 2222, 8000, 8888, 9090, 9200, 10000,
              11211]
PNAME = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
         110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
         1433: "MSSQL", 1521: "Oracle", 2222: "SSH-alt", 3306: "MySQL", 3389: "RDP",
         5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-alt",
         8443: "HTTPS-alt", 8888: "HTTP-alt", 9090: "App", 9200: "Elasticsearch",
         10000: "Webmin", 11211: "Memcached", 27017: "MongoDB"}
DB_PORTS = (23, 445, 3306, 5432, 6379, 27017, 9200, 11211, 1433, 1521)
ADMIN_PORTS = (21, 3389, 5900, 10000)
ALT_PORTS = (2222, 8080, 8000, 8888, 9090)
RISK_PORTS = {23: ("CRITICAL", "Telnet sends credentials in clear text"),
              445: ("CRITICAL", "SMB exposed to the internet invites ransomware"),
              3306: ("CRITICAL", "A database is reachable from the internet"),
              5432: ("CRITICAL", "A database is reachable from the internet"),
              6379: ("CRITICAL", "Redis ships without authentication"),
              27017: ("CRITICAL", "MongoDB ships without authentication"),
              9200: ("CRITICAL", "Elasticsearch exposes indices without authentication"),
              11211: ("CRITICAL", "Memcached leaks and amplifies"),
              1433: ("CRITICAL", "A database is reachable from the internet"),
              1521: ("CRITICAL", "A database is reachable from the internet"),
              21: ("HIGH", "FTP transmits credentials in clear text"),
              3389: ("HIGH", "Remote Desktop is exposed to credential attacks"),
              5900: ("HIGH", "VNC is frequently weakly protected"),
              10000: ("HIGH", "Admin panels are high-value targets"),
              2222: ("MEDIUM", "An alternate SSH port is exposed"),
              8080: ("MEDIUM", "A secondary web service widens the attack surface"),
              8000: ("MEDIUM", "A secondary web service widens the attack surface"),
              8888: ("MEDIUM", "A secondary web service widens the attack surface"),
              9090: ("MEDIUM", "A secondary service widens the attack surface")}
PORT_FIX = {21: "Disable FTP and move to SFTP over port 22.",
            23: "Disable Telnet; use SSH.",
            445: "Never expose SMB; require a VPN.",
            3389: "Put RDP behind a VPN gateway.",
            5900: "Put VNC behind a VPN gateway.",
            10000: "Restrict the admin panel with an allow-list or VPN.",
            3306: "Bind MySQL to 127.0.0.1 and connect over SSH/VPN.",
            5432: "Bind PostgreSQL to 127.0.0.1 and connect over SSH/VPN.",
            6379: "Bind Redis to localhost and set requirepass.",
            27017: "Bind MongoDB to localhost and enable authorisation.",
            9200: "Bind Elasticsearch to localhost and enable its security module.",
            11211: "Bind Memcached to localhost.",
            1433: "Bind MSSQL to a private network.",
            1521: "Bind Oracle to a private network."}
WEAK_CIPHER = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON", "PSK")
UA = ["Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/121.0.0.0 Mobile Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/121.0.0.0 Safari/537.36"]
CLR = {"r": "\033[0m", "b": "\033[1m", "dim": "\033[2m", "red": "\033[91m",
       "grn": "\033[92m", "yel": "\033[93m", "cyn": "\033[96m"}


def no_color():
    for k in CLR:
        CLR[k] = ""


def esc(s):
    """Escape target-controlled text before it reaches ReportLab's XML parser."""
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def cut(s, n):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n - 3] + "..."


def out_dir():
    home = os.path.expanduser("~")
    shared = os.path.join(home, "storage", "shared")
    base = os.path.join(shared, "sitest") if os.path.isdir(shared) else \
        os.path.join(home, "sitest")
    try:
        os.makedirs(base, exist_ok=True)
        return base
    except Exception:
        return "."


def score_color(score):
    return ("#15803d" if score >= 80 else "#0891b2" if score >= 70 else
            "#d97706" if score >= 55 else "#ea580c" if score >= 40 else "#b91c1c")


def grade_of(score):
    for threshold, g in ((95, "A+"), (90, "A"), (85, "A-"), (80, "B+"), (75, "B"),
                         (70, "B-"), (65, "C+"), (60, "C"), (55, "C-"), (50, "D"),
                         (40, "E")):
        if score >= threshold:
            return g
    return "F"


def count_sev(findings):
    c = dict((k, 0) for k in SEV_ORDER)
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


def cert_error_kind(msg):
    m = (msg or "").lower()
    if "expired" in m:
        return "expired"
    if "self-signed" in m or "self signed" in m:
        return "self-signed"
    if "hostname" in m or "not valid for" in m or "ip address mismatch" in m:
        return "hostname mismatch"
    if "unable to get local issuer" in m or "unknown ca" in m:
        return "untrusted issuer"
    return "invalid"


class Log:
    def __init__(self, quiet=False):
        self.quiet, self.t0 = quiet, time.time()

    def step(self, msg):
        if not self.quiet:
            print("%s[+]%s %s %s(%.1fs)%s" % (CLR["cyn"], CLR["r"], msg, CLR["dim"],
                                              time.time() - self.t0, CLR["r"]))
            sys.stdout.flush()

    def warn(self, msg):
        if not self.quiet:
            print("%s[!]%s %s" % (CLR["yel"], CLR["r"], msg))


# ==========================================================================
#  ENGINE
# ==========================================================================
class SiteAuditor:
    def __init__(self, target, timeout=8.0, threads=10, do_ports=True, do_subs=True,
                 full_ports=False, log=None, ua=None):
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        self.url = target.rstrip("/")
        p = urlparse(self.url)
        self.scheme = p.scheme
        self.host = (p.hostname or p.path).strip()
        self.port = p.port or (443 if self.scheme == "https" else 80)
        self.tmo, self.threads = timeout, max(4, int(threads))
        self.do_ports, self.do_subs, self.full_ports = do_ports, do_subs, full_ports
        self.log = log or Log(True)
        self.ua = ua or UA[0]
        self.ip = self._resolve(self.host)
        self.last_error = None
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.ua, "Accept": "*/*",
                                     "Accept-Language": "en-US,en;q=0.9"})
        # A scanner must reach hosts with an expired or self-signed certificate so it
        # can REPORT on that condition. Chain trust is judged separately in check_tls.
        self.session.verify = False

    @staticmethod
    def _resolve(host):
        try:
            return socket.gethostbyname(host)
        except Exception:
            return "Unknown"

    def _get(self, url, timeout=None, allow_redirects=True, ua=None, headers=None,
             method="GET"):
        h = {"User-Agent": ua or self.ua}
        if headers:
            h.update(headers)
        for attempt in (0, 1):
            try:
                return self.session.request(method, url, timeout=timeout or self.tmo,
                                            allow_redirects=allow_redirects, headers=h)
            except Exception as exc:
                self.last_error = "%s: %s" % (type(exc).__name__, str(exc)[:140])
                if attempt == 0:
                    time.sleep(0.4)
        return None

    def _chain(self, url, limit=8):
        out, cur = [], url
        for _ in range(limit):
            r = self._get(cur, allow_redirects=False)
            if r is None:
                out.append({"url": cur, "status": None, "location": None})
                break
            loc = r.headers.get("Location")
            out.append({"url": cur, "status": r.status_code, "location": loc})
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                cur = urljoin(cur, loc)
                continue
            break
        return out

    def fetch_homepage(self):
        self.log.step("Fetching %s" % self.url)
        t0 = time.perf_counter()
        r = self._get(self.url, timeout=max(self.tmo, 12))
        ms = round((time.perf_counter() - t0) * 1000, 1)
        if r is None:
            return {"ok": False, "reachable": False, "status": None, "elapsed_ms": ms,
                    "ttfb_ms": None, "headers": {}, "html": "", "size_kb": 0,
                    "compression": None, "cookies_raw": [], "error": self.last_error,
                    "final_url": self.url}
        return {"ok": r.status_code < 400, "reachable": True, "status": r.status_code,
                "elapsed_ms": ms, "ttfb_ms": round(r.elapsed.total_seconds() * 1000, 1),
                "headers": dict(r.headers), "html": r.text[:400000],
                "size_kb": round(len(r.content) / 1024.0, 1),
                "compression": r.headers.get("Content-Encoding"),
                "cookies_raw": self._raw_cookies(r), "error": None, "final_url": r.url}

    @staticmethod
    def _raw_cookies(r):
        try:
            return list(r.raw.headers.getlist("Set-Cookie"))
        except Exception:
            return [str(c) for c in r.cookies]

    # ----------------------------------------------------------- headers ---
    def analyze_headers(self):
        hdrs = dict((k.lower(), v) for k, v in self.results["home"]["headers"].items())
        detail, present, missing, got = {}, [], [], 0.0
        for name, spec in HEADERS.items():
            raw = hdrs.get(name.lower())
            if raw is None:
                state, note, credit = "MISSING", "Header absent", 0.0
                missing.append(name)
            else:
                state, note, credit = self._grade(name, raw)
                present.append(name)
            detail[name] = {"short": spec[0], "value": raw, "state": state, "note": note,
                            "weight": spec[1], "credit": credit, "fix": spec[2],
                            "hint": spec[3], "ref": spec[4]}
            got += spec[1] * credit
        return {"detail": detail, "present": present, "missing": missing,
                "ratio": round(got / HEADER_WEIGHT, 4),
                "disclosure": dict((k, hdrs[k.lower()]) for k in DISCLOSURE
                                   if k.lower() in hdrs),
                "csp": self._csp(hdrs.get("content-security-policy"))}

    def _grade(self, name, value):
        v, low = value.strip(), value.strip().lower()
        if name == "Strict-Transport-Security":
            if self.scheme != "https":
                return "MISSING", "Not meaningful over plain HTTP", 0.0
            m = re.search(r"max-age\s*=\s*(\d+)", low)
            age = int(m.group(1)) if m else 0
            if age < 100000:
                return "WEAK", "max-age=%d is below the 6-month minimum" % age, 0.4
            if "includesubdomains" not in low:
                return "WEAK", "Set, but subdomains are not covered", 0.7
            return "OK", "max-age=%d, subdomains covered%s" % (
                age, ", preload" if "preload" in low else ""), 1.0
        if name == "Content-Security-Policy":
            bad = []
            if "'unsafe-inline'" in low:
                bad.append("unsafe-inline")
            if "'unsafe-eval'" in low:
                bad.append("unsafe-eval")
            if re.search(r"(default|script)-src[^;]*\*", low):
                bad.append("wildcard source")
            if "http:" in low:
                bad.append("allows http:")
            if "default-src" not in low and "script-src" not in low:
                bad.append("no default-src/script-src")
            if bad:
                return "WEAK", "Policy is bypassable: " + ", ".join(bad), 0.45
            return "OK", "No unsafe directives or wildcard sources", 1.0
        if name == "X-Frame-Options":
            if "deny" in low or "sameorigin" in low:
                return "OK", v.upper(), 1.0
            if "allow-from" in low:
                return "WEAK", "ALLOW-FROM is obsolete and ignored", 0.3
            return "WEAK", "Unrecognised value: %s" % cut(v, 40), 0.3
        if name == "X-Content-Type-Options":
            return ("OK", "nosniff", 1.0) if "nosniff" in low else \
                ("WEAK", "Value is not nosniff", 0.3)
        if name == "Referrer-Policy":
            if any(s in low for s in ("no-referrer", "same-origin", "strict-origin",
                                      "no-referrer-when-downgrade")):
                return "OK", v, 1.0
            if "unsafe-url" in low:
                return "WEAK", "Leaks full URLs to third parties", 0.2
            return "WEAK", "Unknown policy: %s" % cut(v, 30), 0.4
        if name == "Permissions-Policy":
            n = len(re.findall(r"[a-z-]+\s*=", v))
            if n >= 3:
                return "OK", "%d features restricted" % n, 1.0
            if n >= 1:
                return "WEAK", "Only %d feature(s) restricted" % n, 0.6
            return "WEAK", "Declared, but nothing is disabled", 0.3
        if name == "Cross-Origin-Opener-Policy":
            return ("OK", v, 1.0) if "same-origin" in low else \
                ("WEAK", "Weak or unrecognised value", 0.4)
        if name == "Cross-Origin-Resource-Policy":
            if low in ("same-origin", "same-site"):
                return "OK", v, 1.0
            if low == "cross-origin":
                return "WEAK", "cross-origin lets any site embed responses", 0.3
            return "WEAK", "Unrecognised value", 0.4
        return "OK", v, 1.0

    @staticmethod
    def _csp(csp):
        if not csp:
            return {"present": False}
        d = {}
        for part in csp.split(";"):
            bits = part.strip().split()
            if bits:
                d[bits[0].lower()] = bits[1:]
        low = csp.lower()
        return {"present": True, "directives": d, "raw": csp,
                "has_frame_ancestors": "frame-ancestors" in d,
                "has_object": "object-src" in d,
                "unsafe_inline": "'unsafe-inline'" in low}

    # --------------------------------------------------- sensitive files ---
    def check_sensitive_files(self):
        self.log.step("Probing %d sensitive paths (byte-verified)" % len(PATHS))
        ua = UA[1]
        base = self._get("%s/%s" % (self.url, uuid.uuid4().hex), timeout=5,
                         allow_redirects=False, ua=ua)
        b_len = len(base.content) if base is not None else -1
        b_ct = base.headers.get("Content-Type", "") if base is not None else ""
        b_st = base.status_code if base is not None else -1
        soft = self._soft404(base.text[:2000].lower() if base is not None else "")

        def probe(path):
            r = self._get(self.url + path, timeout=5, allow_redirects=False, ua=ua)
            if r is None or r.status_code != 200 or len(r.content) < 8:
                return None
            ctype = r.headers.get("Content-Type", "")
            if (b_st == 200 and ctype.split(";")[0] == b_ct.split(";")[0]
                    and abs(len(r.content) - b_len) < 300):
                return None
            body = r.text[:900].lower()
            if any(s in body for s in ("not found", "cannot get", "page not found",
                                       "does not exist", "404")):
                return None
            if soft and soft in body:
                return None
            sig = self._signature(r.content, path, ctype)
            if sig is None:
                return None
            return {"path": path, "url": self.url + path, "size": len(r.content),
                    "content_type": ctype, "signature": sig,
                    "content_length": r.headers.get("Content-Length")
                    or str(len(r.content)),
                    "sample": self._sanitize(r.content[:512], path)}

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 8)) as ex:
            return sorted((x for x in ex.map(probe, PATHS) if x), key=lambda f: f["path"])

    @staticmethod
    def _soft404(text):
        for marker in ("<title>", "cannot get", "not found", "404"):
            i = text.find(marker)
            if i >= 0:
                return text[i:i + 60].strip()
        return ""

    def _signature(self, buf, path, ctype=""):
        """Byte-accurate identification. Magic bytes win; HTML and soft-404 payloads
        return None so they can never be reported as a data leak."""
        if not buf or len(buf) < 4:
            return None
        head, low = buf[:512], buf[:512].lower()
        for magic, label in ((b"\x1f\x8b\x08", "GZIP archive"),
                             (b"%PDF-", "PDF document"),
                             (b"\x7fELF", "Linux ELF binary"),
                             (b"SQL\x00", "MySQL dump"),
                             (b"PGDMP", "PostgreSQL dump")):
            if buf.startswith(magic):
                return label
        if buf[:2] == b"PK" and b"xml" not in head[:64].lower():
            return "ZIP archive (backup bundle)"
        if buf[:2] == b"MZ":
            return "Windows executable"
        if head.startswith(b"ref:"):
            return "Git HEAD (repository metadata)"
        if head.startswith(b"[core]"):
            return "Git config (repository metadata)"
        if head.lstrip()[:5].lower() == b"<?php":
            return "PHP source code"
        if b"-----BEGIN" in head and b"PRIVATE KEY" in head:
            return "Private key material"
        if "text/html" in (ctype or "").lower():
            return None
        if any(t in low for t in (b"<html", b"<!doctype", b"<head", b"<body")):
            return None
        if buf[:1] in (b"{", b"["):
            try:
                json.loads(buf.decode("utf-8", "replace")[:4000] or "{}")
                return "JSON data (structured response)"
            except Exception:
                return "JSON-like payload"
        if path.endswith((".env", ".env.local", ".env.production")) and \
                re.search(rb"(?m)^[A-Za-z0-9_]{2,}=", head):
            return "Environment / configuration file"
        if path.endswith((".sql", ".dump")) and re.search(
                rb"(?im)^(insert into|create table|drop table|-- )", head):
            return "SQL dump"
        if path.endswith((".yml", ".yaml", ".ini", ".conf", ".cnf")) and \
                re.search(rb"(?m)^\s*[A-Za-z0-9_.-]+\s*[:=]", head):
            return "Configuration file"
        if path.endswith(".log") and re.search(rb"\d{4}-\d{2}-\d{2}|error|warning", low):
            return "Application log file"
        if path.endswith(".lock"):
            return "Dependency lock file"
        if path.endswith(".json") and b'"' in head:
            return "JSON document"
        if b"repository" in low or b"reference" in low:
            return "Version-control metadata"
        return "Unexpected readable content"

    @staticmethod
    def _sanitize(buf, path):
        """Redact secrets: the report must never leak what it discovered."""
        if not buf:
            return ""
        if b"PRIVATE KEY" in buf:
            return "-----BEGIN PRIVATE KEY----- [redacted]"
        text = buf.decode("utf-8", "replace")
        if ".env" in path or (b"=" in buf[:80] and b"\n" in buf[:150]):
            lines = []
            for line in text.split("\n")[:10]:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key = line.split("=", 1)[0].strip()
                if key and len(key) < 40:
                    lines.append(key + "=***")
                if len(lines) >= 5:
                    break
            if lines:
                return " | ".join(lines)
        if path.endswith("HEAD") and text.startswith("ref:"):
            return text.strip()[:90]
        if path.endswith(".json"):
            keys = re.findall(r'"([A-Za-z_][A-Za-z0-9_]{1,30})"\s*:', text)
            if keys:
                return "keys: " + ", ".join(keys[:8])
        for line in text.split("\n"):
            line = line.strip()
            if line and not line.startswith("<!--"):
                return cut(line, 110)
        return cut(text, 90)

    def check_listing(self):
        self.log.step("Checking for directory listing")

        def probe(path):
            r = self._get(self.url + path, timeout=5, allow_redirects=False)
            if r is None or r.status_code != 200:
                return None
            low = r.text[:4000].lower()
            if "index of /" in low or "directory listing for" in low:
                t = re.search(r"<title>([^<]{0,80})", r.text[:3000], re.I)
                return {"path": path, "url": self.url + path,
                        "title": t.group(1).strip() if t else "Index",
                        "entries": len(re.findall(r"<a href=", low))}
            return None

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 8)) as ex:
            return [x for x in ex.map(probe, LISTING) if x]

    # --------------------------------------------------------------- TLS ---
    def _handshake(self, verify, version=None):
        info = {"ok": False, "protocol": None, "cipher": None, "bits": None, "alpn": None,
                "cert": None, "der": None, "error": None, "kind": None}
        try:
            if verify:
                ctx = ssl.create_default_context(cafile=CAFILE) if CAFILE else \
                    ssl.create_default_context()
            else:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            if version is not None:
                ctx.minimum_version = ctx.maximum_version = version
            else:
                try:
                    ctx.set_alpn_protocols(["h2", "http/1.1"])
                except NotImplementedError:
                    pass
            with socket.create_connection((self.host, self.port),
                                          timeout=max(self.tmo, 6)) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ss:
                    info["protocol"] = ss.version()
                    info["alpn"] = ss.selected_alpn_protocol()
                    c = ss.cipher()
                    if c:
                        info["cipher"], info["bits"] = c[0], c[2]
                    info["der"] = ss.getpeercert(binary_form=True)
                    try:
                        info["cert"] = ss.getpeercert()
                    except Exception:
                        info["cert"] = None
                    info["ok"] = True
        except ssl.SSLCertVerificationError as exc:
            info["error"] = exc.verify_message or str(exc)
            info["kind"] = cert_error_kind(info["error"])
        except ssl.SSLError as exc:
            info["error"] = str(exc)[:120]
        except Exception as exc:
            info["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:110])
        return info

    def check_tls(self):
        info = {"enabled": self.scheme == "https", "trusted": None, "protocol": None,
                "cipher": None, "bits": None, "alpn": None, "forward_secrecy": None,
                "subject": self.host, "issuer": None, "issuer_org": None, "expires": None,
                "not_before": None, "days_left": None, "san": [], "san_count": None,
                "wildcard": False, "key_type": None, "key_size": None, "sig_alg": None,
                "serial": None, "protocols": {}, "error": None, "kind": None}
        if not info["enabled"]:
            return info
        self.log.step("Auditing TLS (handshake, certificate, protocol matrix)")
        hs = self._handshake(True)
        if hs["ok"]:
            info["trusted"] = True
        else:
            info["trusted"], info["kind"] = False, hs["kind"]
            hs = self._handshake(False)
            if not hs["ok"]:
                info["error"] = hs["error"] or "handshake failed"
                return info
        for k in ("protocol", "cipher", "bits", "alpn"):
            info[k] = hs[k]
        if hs["cipher"]:
            info["forward_secrecy"] = any(k in hs["cipher"] for k in
                                          ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA"))
        self._cert_info(info, hs)
        for label, attr in (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"),
                            ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3")):
            ver = getattr(ssl.TLSVersion, attr, None)
            if ver is not None:
                info["protocols"][label] = self._handshake(False, ver)["ok"]
        return info

    def _cert_info(self, info, hs):
        cert, der = hs.get("cert"), hs.get("der")
        if cert:
            self._cert_from_dict(info, cert)
        if der and HAVE_CRYPTO:
            try:
                c = x509.load_der_x509_certificate(der)
                oid = x509.oid.NameOID
                if not info["issuer"]:
                    o = c.issuer.get_attributes_for_oid(oid.ORGANIZATION_NAME)
                    info["issuer_org"] = o[0].value if o else "?"
                    cn = c.issuer.get_attributes_for_oid(oid.COMMON_NAME)
                    info["issuer"] = cn[0].value if cn else info["issuer_org"]
                exp = getattr(c, "not_valid_after_utc", None) or \
                    c.not_valid_after.replace(tzinfo=timezone.utc)
                if not info["expires"]:
                    info["expires"] = exp.strftime("%Y-%m-%d")
                info["serial"] = hex(c.serial_number)[2:][:24]
                try:
                    info["sig_alg"] = c.signature_hash_algorithm.name.upper()
                except Exception:
                    info["sig_alg"] = None
                key = c.public_key()
                if isinstance(key, rsa.RSAPublicKey):
                    info["key_type"], info["key_size"] = "RSA", key.key_size
                elif isinstance(key, ec.EllipticCurvePublicKey):
                    info["key_type"], info["key_size"] = "ECDSA", key.curve.key_size
                elif isinstance(key, dsa.DSAPublicKey):
                    info["key_type"], info["key_size"] = "DSA", key.key_size
                elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                    info["key_type"], info["key_size"] = "EdDSA", 256
            except Exception:
                pass
        elif der:
            self._cert_from_der(info, der)
        if info["expires"]:
            try:
                exp = datetime.strptime(info["expires"], "%Y-%m-%d").replace(
                    tzinfo=timezone.utc)
                info["days_left"] = (exp - datetime.now(timezone.utc)).days
            except Exception:
                pass

    def _cert_from_dict(self, info, cert):
        """Fill certificate fields from the dictionary ssl.getpeercert() returns."""
        if not cert:
            return
        for src, dst in (("notAfter", "expires"), ("notBefore", "not_before")):
            try:
                info[dst] = datetime.strptime(cert[src], "%b %d %H:%M:%S %Y %Z"
                                              ).strftime("%Y-%m-%d")
            except Exception:
                pass
        try:
            info["subject"] = dict(x[0] for x in cert["subject"]).get("commonName",
                                                                      self.host)
            iss = dict(x[0] for x in cert["issuer"])
            info["issuer_org"] = iss.get("organizationName", "?")
            info["issuer"] = iss.get("commonName") or info["issuer_org"]
            san = cert.get("subjectAltName", ())
            info["san"] = [v for _, v in san][:12]
            info["san_count"] = len(san)
            info["wildcard"] = any("*" in v for _, v in san)
        except Exception:
            pass

    def _cert_from_der(self, info, der):
        """Best-effort certificate parse used when `cryptography` is absent.

        On Termux that matters: an untrusted or self-signed chain makes the
        verified handshake fail and getpeercert() return nothing, so without
        this fallback the report would carry no certificate facts at all.
        """
        if not der or HAVE_CRYPTO:
            return
        path = None
        try:
            import tempfile
            fd, path = tempfile.mkstemp(suffix=".pem")
            with os.fdopen(fd, "wb") as fh:
                fh.write(ssl.DER_cert_to_PEM_cert(der).encode("ascii"))
            self._cert_from_dict(info, ssl._ssl._test_decode_cert(path))
        except Exception:
            pass
        finally:
            if path:
                try:
                    os.unlink(path)
                except Exception:
                    pass

    # --------------------------------------------------------------- DNS ---
    def check_dns(self):
        out = {"available": HAVE_DNS, "a": [], "aaaa": [], "ns": [], "mx": [], "txt": [],
               "spf": None, "spf_policy": None, "spf_lookups": None, "dmarc": None,
               "dmarc_policy": None, "dmarc_pct": None, "dkim": [], "caa": [],
               "dnssec": None, "cname": None, "selectors": 0}
        if not HAVE_DNS:
            return out
        self.log.step("Auditing DNS and e-mail authentication")

        def q(name, rtype, timeout=5):
            try:
                return list(dns.resolver.resolve(name, rtype, lifetime=timeout))
            except Exception:
                return []

        out["a"] = [str(r) for r in q(self.host, "A")]
        out["aaaa"] = [str(r) for r in q(self.host, "AAAA")]
        out["ns"] = [str(r.target).rstrip(".") for r in q(self.host, "NS")]
        for r in q(self.host, "CNAME"):
            out["cname"] = str(r.target).rstrip(".")
        out["mx"] = sorted(({"host": str(r.exchange).rstrip("."),
                             "pref": getattr(r, "preference", None)}
                            for r in q(self.host, "MX")),
                           key=lambda m: m["pref"] if m["pref"] is not None else 999)
        out["txt"] = [r.to_text().strip('"').replace('" "', "")[:200]
                      for r in q(self.host, "TXT")]
        out["caa"] = ["%s %s" % (getattr(r, "flags", 0), r.to_text()[:70])
                      for r in q(self.host, "CAA")]
        for t in out["txt"]:
            if t.lower().startswith("v=spf1"):
                out["spf"] = t
                m = re.search(r"([-~+?])all\b", t)
                out["spf_policy"] = (m.group(1) + "all") if m else "absent"
                out["spf_lookups"] = len([x for x in t.split()
                                          if x.startswith("include:")
                                          or x.endswith(("a", "mx", "ptr", "exists"))])
                break
        for r in q("_dmarc." + self.host, "TXT"):
            t = r.to_text().strip('"').replace('" "', "")
            if t.lower().startswith("v=dmarc1"):
                out["dmarc"] = t
                m = re.search(r"\bp\s*=\s*(none|quarantine|reject)", t, re.I)
                out["dmarc_policy"] = m.group(1).lower() if m else "none"
                m = re.search(r"\bpct\s*=\s*(\d+)", t, re.I)
                out["dmarc_pct"] = int(m.group(1)) if m else 100
                break
        sels = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
                "dkim", "mail", "smtp", "mandrill", "sendgrid", "zoho", "amazonses"]
        out["selectors"] = len(sels)

        def dkim(sel):
            for r in q("%s._domainkey.%s" % (sel, self.host), "TXT", timeout=3):
                t = r.to_text().strip('"').replace('" "', "")
                if "v=dkim1" in t.lower() or "p=" in t:
                    return {"selector": sel, "record": t[:150]}
            return None

        with cf.ThreadPoolExecutor(max_workers=min(self.threads, 8)) as ex:
            out["dkim"] = [d for d in ex.map(dkim, sels) if d]
        try:
            res = dns.resolver.Resolver()
            res.use_edns(edns=0, payload=1232,
                         ednsflags=getattr(dns.flags, "DO", 0x8000))
            resp = res.resolve(self.host, "TXT", lifetime=5)
            out["dnssec"] = bool(resp.response.flags & dns.flags.AD)
        except Exception:
            pass
        if not out["dnssec"]:
            out["dnssec"] = bool(q(self.host, "DNSKEY", timeout=4)) or None
        return out

    # -------------------------------------------------------------- HTTP ---
    def check_http(self):
        self.log.step("Analysing redirects, methods and transport policy")
        chain = self._chain("http://" + self.host, limit=6)
        upgraded = any(h["status"] in (301, 302, 307, 308) and h["location"]
                       and h["location"].lower().startswith("https://") for h in chain)
        allow = []
        try:
            r = self.session.options(self.url, timeout=self.tmo, allow_redirects=False)
            allow = [m.strip().upper() for m in r.headers.get("Allow", "").split(",")
                     if m.strip()]
        except Exception:
            pass
        hdrs = self.results["home"]["headers"]
        return {"http_chain": chain, "https_chain": self._chain(self.url, 6),
                "https_upgrade": upgraded, "allow": allow,
                "risky": sorted(set(allow) & {"PUT", "DELETE", "TRACE", "CONNECT",
                                              "PATCH"}),
                "alt_svc": hdrs.get("Alt-Svc"),
                "cache": dict((k, hdrs[k]) for k in ("Cache-Control", "ETag", "Vary")
                              if k in hdrs),
                "compression": self.results["home"]["compression"]}

    def check_cors(self):
        self.log.step("Testing the CORS policy")
        probe = "https://audit-probe.invalid"
        out = {"origin_echo": False, "credentials": False, "wildcard": False,
               "acao": None, "acac": None, "vary": None, "dangerous": False,
               "preflight": None}
        r = self._get(self.url, headers={"Origin": probe})
        if r is None:
            return out
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower()
        out.update({"acao": acao, "acac": acac or None, "vary": r.headers.get("Vary"),
                    "origin_echo": acao == probe, "wildcard": acao == "*",
                    "credentials": acac == "true"})
        out["dangerous"] = bool(out["origin_echo"] and out["credentials"])
        try:
            p = self.session.options(self.url, timeout=self.tmo, allow_redirects=False,
                                     headers={"Origin": probe,
                                              "Access-Control-Request-Method": "GET"})
            out["preflight"] = {"status": p.status_code,
                                "acao": p.headers.get("Access-Control-Allow-Origin"),
                                "acac": p.headers.get("Access-Control-Allow-Credentials")}
            if out["preflight"]["acao"] == probe and \
                    (out["preflight"]["acac"] or "").lower() == "true":
                out["dangerous"] = True
        except Exception:
            pass
        return out

    def check_cookies(self):
        out = []
        for raw in self.results["home"].get("cookies_raw", []):
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue
            name = parts[0].split("=", 1)[0].strip()
            rest = ";".join(parts[1:]).lower()
            ss = ("none" if "samesite=none" in rest else "lax" if "samesite=lax" in rest
                  else "strict" if "samesite=strict" in rest else "missing")
            out.append({"name": name, "secure": "secure" in rest,
                        "httponly": "httponly" in rest, "samesite": ss,
                        "prefixed": name.startswith(("__Host-", "__Secure-")),
                        "host_prefix": name.startswith("__Host-"),
                        "session_like": bool(re.search(
                            r"sess|phpsessid|jsessionid|asp\.net_session|"
                            r"laravel_session|connect\.sid|csrftoken|auth|token|jwt",
                            name, re.I))})
        return out

    def check_subdomains(self):
        if not self.do_subs:
            return []
        self.log.step("Enumerating subdomains (%d candidates)" % len(SUBS))

        def probe(sub):
            host = "%s.%s" % (sub, self.host)
            try:
                return {"name": sub, "host": host, "ip": socket.gethostbyname(host)}
            except Exception:
                try:
                    infos = socket.getaddrinfo(host, None)
                    return {"name": sub, "host": host, "ip": infos[0][4][0]} \
                        if infos else None
                except Exception:
                    return None

        with cf.ThreadPoolExecutor(max_workers=min(self.threads * 2, 24)) as ex:
            found = [x for x in ex.map(probe, SUBS) if x]
        seen, uniq = set(), []
        for f in found:
            if f["ip"] in seen and f["name"] != "www":
                continue
            seen.add(f["ip"])
            uniq.append(f)
        return uniq

    def check_robots(self):
        r = self._get(self.url + "/robots.txt", timeout=6)
        if r is None or r.status_code != 200 or "<html" in r.text[:200].lower():
            return {"found": False, "sensitive": [], "sitemaps": []}
        sensitive, sitemaps = [], []
        keys = ("admin", "backup", "config", "private", "internal", "db", "sql",
                "staging", "dev", "test", "api/", "secret", "key", "token", "upload",
                "log", "console", "actuator", ".git")
        for line in r.text[:20000].split("\n"):
            low = line.strip().lower()
            if low.startswith("sitemap"):
                v = line.split(":", 1)[-1].strip()
                if v and v not in sitemaps:
                    sitemaps.append(v)
            elif low.startswith(("disallow", "allow")):
                p = line.split(":", 1)[-1].strip()
                if p and any(k in p.lower() for k in keys) and p not in sensitive:
                    sensitive.append(p)
        return {"found": True, "sensitive": sensitive[:12], "sitemaps": sitemaps[:5]}

    def check_sitemap(self):
        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            r = self._get(self.url + path, timeout=6)
            if r is not None and r.status_code == 200:
                n = len(re.findall(r"<loc>", r.text[:400000]))
                if n:
                    return {"found": True, "path": path, "urls": n}
        return {"found": False, "path": None, "urls": 0}

    def check_security_txt(self):
        for path in ("/.well-known/security.txt", "/security.txt"):
            r = self._get(self.url + path, timeout=5)
            if r is not None and r.status_code == 200 and \
                    "contact" in r.text.lower()[:3000]:
                return {"found": True, "path": path}
        return {"found": False, "path": None}

    # ----------------------------------------------------------- content ---
    def check_content(self):
        html = self.results["home"].get("html", "")
        out = {"mixed": [], "external_scripts": [], "external_iframes": [], "emails": [],
               "insecure_forms": 0, "inline_scripts": 0, "sri_missing": 0,
               "external_links": []}
        if not html:
            return out
        if self.scheme == "https":
            mixed = set(re.findall(r"""(?:src|href|action)\s*=\s*["']http://([^"'/]+)""",
                                   html, re.I))
            out["mixed"] = sorted(h for h in mixed if self.host not in h)[:8]
        for attrs, body in re.findall(r"<script([^>]*)>(.*?)</script>", html, re.I | re.S):
            src = re.search(r"""src\s*=\s*["']([^"']+)""", attrs, re.I)
            if src:
                m = re.match(r"^(?:https?:)?//([^/]+)", src.group(1))
                if m and self.host not in m.group(1) \
                        and len(out["external_scripts"]) < 12:
                    out["external_scripts"].append(m.group(1))
                if "integrity=" not in attrs.lower():
                    out["sri_missing"] += 1
            elif body.strip():
                out["inline_scripts"] += 1
        for u in re.findall(r"""<iframe[^>]+src\s*=\s*["']([^"']+)""", html, re.I):
            m = re.match(r"^(?:https?:)?//([^/]+)", u)
            if m and self.host not in m.group(1) and len(out["external_iframes"]) < 8:
                out["external_iframes"].append(m.group(1))
        out["insecure_forms"] = len(re.findall(r"""<form[^>]+action\s*=\s*["']http://""",
                                               html, re.I))
        emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", html))
        skip = ("example.com", "sentry.io", "wixpress.com", "schema.org", "w3.org",
                "google.com", "gstatic.com", "googletagmanager", "npmjs.com")
        out["emails"] = sorted(e for e in emails
                               if not any(s in e.lower() for s in skip))[:8]
        hosts = set(re.findall(r"""href\s*=\s*["']https?://([^"'/]+)""", html, re.I))
        out["external_links"] = sorted(h for h in hosts if self.host not in h)[:10]
        return out

    def check_fingerprint(self):
        home = self.results["home"]
        html = home.get("html", "")
        out = {"tech": {}, "stack": [], "error_page": {}}
        srv = home["headers"].get("Server")
        if srv:
            out["tech"]["Server"] = srv
            for kw in ("nginx", "apache", "litespeed", "openresty", "iis", "gunicorn",
                       "uvicorn", "caddy", "tomcat", "jetty", "envoy"):
                if kw in srv.lower():
                    out["stack"].append(kw)
        for h in ("X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Drupal-Cache",
                  "X-Runtime", "X-Varnish", "X-Served-By", "X-Backend-Server", "Via",
                  "X-Debug-Token"):
            if home["headers"].get(h):
                out["tech"][h] = home["headers"][h]
        for label, pat in (
                ("WordPress", r'<meta name="generator" content="WordPress ([\d.]+)"'),
                ("jQuery", r"jquery[/-]([\d.]+)(?:\.min)?\.js"),
                ("Bootstrap", r"bootstrap[/-]v?([\d.]+)"),
                ("React", r"react(?:\.production\.min)?[-.]([\d.]+)\.js"),
                ("Vue", r"vue(?:\.min|\.global(?:\.prod)?)?[-.]([\d.]+)\.js"),
                ("Next.js", r"/_next/static/"), ("PHP", r"\.php\b")):
            m = re.search(pat, html, re.I)
            if m:
                out["stack"].append(label)
                if m.groups():
                    out["tech"][label] = m.group(1)
        if "X-Drupal-Cache" in out["tech"] or "drupal" in html.lower()[:4000]:
            out["stack"].append("Drupal")
        if re.search(r"\bwp-content\b|\bwp-json\b", html, re.I):
            out["stack"].append("WordPress")
        if any("laravel" in c.lower() for c in home.get("cookies_raw", [])):
            out["stack"].append("Laravel")
        out["stack"] = sorted(set(out["stack"]))
        r = self._get("%s/%s" % (self.url, uuid.uuid4().hex), timeout=6)
        if r is not None:
            low = r.text[:20000].lower()
            sigs = [label for label, pat in (
                ("Python traceback", r"traceback \(most recent call last\)"),
                ("Java stack trace", r"at (java|org|com)\.[a-z0-9.]+\("),
                ("PHP fatal error", r"fatal error.*?on line \d+"),
                ("SQL error", r"(sql syntax|mysql_fetch|pg_query|ora-\d{5})"),
                ("ASP.NET error", r"server error in '/'|stack trace:"),
                ("Framework debug page",
                 r"(werkzeug|django debug|debug toolbar|symfony)"),
                ("Server path disclosure", r"(/var/www/|/home/\w+/|/usr/share/)"))
                if re.search(pat, low)]
            out["error_page"] = {"status": r.status_code, "signatures": sigs,
                                 "title": cut(re.sub(r"\s+", " ", re.sub(
                                     r"<[^>]+>", " ", r.text[:400])).strip(), 90)}
        return out

    # ------------------------------------------------------------- ports ---
    def is_behind_cdn(self, home):
        blob = " ".join(str(v) for v in home["headers"].values()).lower()
        for kw, name in (("cloudflare", "Cloudflare"), ("cloudfront", "AWS CloudFront"),
                         ("akamai", "Akamai"), ("arvan", "ArvanCloud"),
                         ("sucuri", "Sucuri"), ("ddos-guard", "DDoS-Guard"),
                         ("gcore", "Gcore"), ("fastly", "Fastly"),
                         ("incapsula", "Imperva"), ("varnish", "Varnish")):
            if kw in blob:
                return name
        return None

    @staticmethod
    def _probe_port(ip, port, timeout=1.6):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((ip, port))
            return port, "Open" if rc == 0 else "Closed" if rc == 111 else "Filtered"
        except Exception:
            return port, "Filtered"
        finally:
            s.close()

    def check_ports(self, skip=False):
        if skip or not self.do_ports or self.ip == "Unknown":
            self.log.step("Port scan skipped")
            return {}
        ports = sorted(set(PORTS + (PORTS_FULL if self.full_ports else [])))
        self.log.step("Scanning %d TCP ports (connect state)" % len(ports))
        with cf.ThreadPoolExecutor(max_workers=min(self.threads * 2, 24)) as ex:
            return dict(ex.map(lambda p: self._probe_port(self.ip, p,
                                                          min(self.tmo, 2.0)), ports))

    # ---------------------------------------------------------- findings ---
    def build_findings(self):
        r, out = self.results, []
        tls, dns, hdr = r["tls"], r["dns"], r["headers"]
        http, content, cors = r["http"], r["content"], r["cors"]

        def add(sev, cat, fid, title, evidence, impact, fix, snippet=None, refs=None):
            out.append({"id": fid, "severity": sev, "category": cat, "title": title,
                        "evidence": evidence, "impact": impact, "fix": fix,
                        "snippet": snippet, "refs": refs or [], "asset": self.url})

        for i, ef in enumerate(r.get("exposed", []), 1):
            add("CRITICAL", "Data Exposure", "EXP-%02d" % i,
                "Publicly readable %s" % ef["signature"],
                "%s - %s bytes, content-type: %s%s" % (
                    ef["url"], ef["size"], ef["content_type"] or "n/a",
                    (" | sample: " + ef["sample"]) if ef["sample"] else ""),
                "The file is served to anyone on the internet. Credentials, source code "
                "or configuration inside it can be used to take over the application "
                "or its database.",
                "Remove the file from the web root or block the pattern at the edge, "
                "and move secrets into environment variables or a secret manager.",
                "location ~ /\\.(env|git|svn) { deny all; }\n"
                "location ~ \\.(sql|bak|zip|log)$ { deny all; }",
                ["OWASP A05:2021 Security Misconfiguration"])
        for i, dl in enumerate(r.get("listing", []), 1):
            add("HIGH", "Data Exposure", "EXP-L%02d" % i,
                "Directory listing enabled at %s" % dl["path"],
                "%s (%d entries visible)" % (dl["url"], dl["entries"]),
                "Attackers enumerate every file in the directory, mapping backups, "
                "uploads and internal documents in seconds.",
                "Disable auto-indexing for the whole document root.",
                "nginx:  autoindex off;   (the default)\napache: Options -Indexes",
                ["OWASP A05:2021"])

        if tls.get("enabled"):
            if tls.get("error"):
                add("CRITICAL", "Transport Security", "TLS-01",
                    "TLS certificate or chain is not trusted",
                    "The verified handshake failed: %s" % tls["error"],
                    "Browsers show a full-page interstitial and users learn to click "
                    "through it, which destroys the value of HTTPS and exposes them to "
                    "active man-in-the-middle attacks.",
                    "Install the complete chain (leaf plus intermediates) from a "
                    "trusted CA and automate renewal.",
                    "openssl s_client -connect %s:443 -showcerts" % self.host,
                    ["RFC 5280", "OWASP TLS Cheat Sheet"])
            elif tls.get("days_left") is not None:
                d = tls["days_left"]
                if d < 0:
                    add("CRITICAL", "Transport Security", "TLS-02",
                        "TLS certificate expired %d days ago" % abs(d),
                        "notAfter=%s" % tls.get("expires"),
                        "Modern browsers block or warn and automated clients fail "
                        "closed, so availability and trust are both already broken.",
                        "Renew immediately and automate renewal.",
                        "certbot renew --deploy-hook 'systemctl reload nginx'",
                        ["RFC 5280"])
                elif d < 15:
                    add("HIGH", "Transport Security", "TLS-03",
                        "TLS certificate expires in %d days" % d,
                        "notAfter=%s" % tls.get("expires"),
                        "There is almost no time left for an unbudgeted renewal, so an "
                        "outage is likely.",
                        "Renew now and schedule it permanently.",
                        "certbot renew --dry-run", ["RFC 5280"])
            bad = [v for v in ("TLSv1", "TLSv1.1") if tls.get("protocols", {}).get(v)]
            if bad:
                add("HIGH", "Transport Security", "TLS-04",
                    "Deprecated TLS version(s) accepted: " + ", ".join(bad),
                    "Negotiated %s with cipher %s" % (tls.get("protocol"),
                                                      tls.get("cipher")),
                    "TLS 1.0/1.1 rest on primitives considered broken and are banned "
                    "outright by PCI DSS.",
                    "Restrict the server to TLS 1.2 and 1.3.",
                    "ssl_protocols TLSv1.2 TLSv1.3;", ["RFC 8996", "PCI DSS 4.0"])
            if tls.get("forward_secrecy") is False:
                add("HIGH", "Transport Security", "TLS-05",
                    "Cipher suite without forward secrecy",
                    "Negotiated: %s" % tls.get("cipher"),
                    "A stolen private key decrypts previously recorded traffic "
                    "(harvest now, decrypt later).",
                    "Prefer ECDHE suites and TLS 1.3.",
                    "ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:"
                    "ECDHE-RSA-AES256-GCM-SHA384;", ["RFC 7525"])
            if any(w in str(tls.get("cipher") or "").upper() for w in WEAK_CIPHER):
                add("HIGH", "Transport Security", "TLS-06",
                    "Weak cipher negotiated: %s" % tls.get("cipher"),
                    "%s (%s-bit)" % (tls.get("cipher"), tls.get("bits")),
                    "Traffic protected by a broken primitive can be decrypted with "
                    "realistic effort.",
                    "Remove RC4/3DES/NULL/EXPORT suites from the cipher list.",
                    "openssl ciphers -v 'HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES'",
                    ["RFC 7525"])
            if tls.get("key_type") == "RSA" and tls.get("key_size") \
                    and tls["key_size"] < 2048:
                add("HIGH", "Transport Security", "TLS-07",
                    "RSA key shorter than 2048 bits",
                    "%s %s-bit" % (tls.get("key_type"), tls.get("key_size")),
                    "Keys this short are within reach of a funded attacker.",
                    "Reissue with RSA-2048 or stronger, or ECDSA P-256.",
                    "openssl req -newkey rsa:4096 -nodes -keyout key.pem -out csr.pem",
                    ["NIST SP 800-57"])
            if tls.get("sig_alg") == "SHA1":
                add("HIGH", "Transport Security", "TLS-08",
                    "Certificate signed with SHA-1", "signature hash: SHA1",
                    "SHA-1 collisions are practical and browsers reject such "
                    "certificates.",
                    "Reissue with SHA-256 or stronger.", "openssl req -sha256 ...",
                    ["RFC 9155"])
            if tls.get("wildcard"):
                add("INFO", "Transport Security", "TLS-09",
                    "Wildcard certificate in use",
                    "Subject %s | SAN %s" % (tls.get("subject"),
                                             ", ".join(tls.get("san", [])[:5])),
                    "Compromise of one wildcard key affects every sibling host. This is "
                    "informational, not a defect by itself.",
                    "Consider per-host certificates and CAA to constrain issuance.",
                    None, ["CA/Browser Forum Baseline Requirements"])
            if tls.get("trusted") and not http.get("https_upgrade"):
                add("MEDIUM", "Transport Security", "TLS-10",
                    "No HTTP-to-HTTPS redirect",
                    "http://%s answers without redirecting to https" % self.host,
                    "Users who type the bare domain stay on plain HTTP and are open to "
                    "session hijacking and content injection.",
                    "Redirect every plain-HTTP request to HTTPS permanently.",
                    "server {\n  listen 80;\n  return 301 "
                    "https://$host$request_uri;\n}", ["OWASP TLS Cheat Sheet"])
        else:
            add("CRITICAL", "Transport Security", "TLS-00",
                "Target is served over plain HTTP", "Scheme http, port %d" % self.port,
                "All traffic, including credentials and session cookies, travels in "
                "clear text and can be read or modified by anyone on the path.",
                "Enable HTTPS with a trusted certificate and redirect all HTTP traffic.",
                "server {\n  listen 80;\n  return 301 https://$host$request_uri;\n}",
                ["OWASP Transport Layer Security Cheat Sheet"])

        for name, d in hdr["detail"].items():
            if d["state"] == "MISSING":
                sev = "HIGH" if name in ("Strict-Transport-Security",
                                         "Content-Security-Policy") else "MEDIUM"
                add(sev, "Security Headers", "HDR-%s" % d["short"],
                    "Missing %s header (%s)" % (d["short"], name),
                    "The response of %s carries no %s header" % (self.url, name),
                    d["hint"] + " Without it the browser applies no such protection at "
                    "all.",
                    "Send the header on every HTML response.",
                    "add_header %s always;" % d["fix"], [d["ref"]])
            elif d["state"] == "WEAK":
                sev = "MEDIUM" if name in ("Strict-Transport-Security",
                                           "Content-Security-Policy") else "LOW"
                add(sev, "Security Headers", "HDR-%s" % d["short"],
                    "%s header is present but weak" % d["short"],
                    "%s: %s (%s)" % (name, cut(d["value"], 150), d["note"]),
                    "The header exists, but its value leaves the protection partially "
                    "or entirely ineffective.",
                    d["hint"], "add_header %s always;" % d["fix"], [d["ref"]])
        csp = hdr.get("csp") or {}
        if csp.get("present"):
            if not csp.get("has_frame_ancestors") and \
                    hdr["detail"]["X-Frame-Options"]["state"] != "OK":
                add("MEDIUM", "Security Headers", "HDR-CSP2",
                    "No frame-ancestors and no usable X-Frame-Options",
                    "Directives: %s" % ", ".join(sorted(csp["directives"]))[:180],
                    "Nothing prevents the site being framed, so clickjacking is "
                    "possible.",
                    "Add frame-ancestors to the policy.",
                    "Content-Security-Policy: ...; frame-ancestors 'none';",
                    ["OWASP Clickjacking Defense Cheat Sheet"])
            if not csp.get("has_object"):
                add("LOW", "Security Headers", "HDR-CSP3",
                    "CSP does not restrict object-src",
                    "Directives: %s" % ", ".join(sorted(csp["directives"]))[:160],
                    "Legacy plugin content can be embedded as an attack vector.",
                    "Add object-src 'none'.", None, ["OWASP CSP Cheat Sheet"])

        if content.get("mixed"):
            add("MEDIUM", "Content & Privacy", "CNT-01",
                "Mixed content: HTTP resources loaded over HTTPS",
                "Insecure origins: %s" % ", ".join(content["mixed"][:5]),
                "Browsers block or degrade these resources and the HTTP requests "
                "themselves are tamperable, which downgrades page integrity.",
                "Serve every subresource over HTTPS, and add upgrade-insecure-requests.",
                "Content-Security-Policy: upgrade-insecure-requests;",
                ["OWASP Transport Layer Security Cheat Sheet"])
        if content.get("insecure_forms"):
            add("HIGH", "Content & Privacy", "CNT-02",
                "%d form(s) submit over plain HTTP" % content["insecure_forms"],
                "action http:// found in the markup",
                "Credentials or personal data leave the browser unencrypted.",
                "Point every form action at an https:// URL.", None,
                ["OWASP Transport Layer Security Cheat Sheet"])
        if content.get("emails"):
            add("LOW", "Content & Privacy", "CNT-03",
                "E-mail addresses exposed in page source",
                ", ".join(content["emails"][:4]),
                "Harvestable for targeted phishing and spam, and it confirms internal "
                "identity patterns.",
                "Obfuscate them or use a contact form, and prefer role addresses.",
                None, ["OWASP A03:2021"])
        if cors.get("dangerous"):
            add("CRITICAL", "Content & Privacy", "CNT-05",
                "CORS reflects an arbitrary origin with credentials",
                "Origin https://audit-probe.invalid reflected into "
                "Access-Control-Allow-Origin with Access-Control-Allow-Credentials: "
                "true",
                "Any website can read authenticated responses from this origin on "
                "behalf of a logged-in victim, exfiltrating their data with no user "
                "interaction.",
                "Never echo the Origin header when credentials are allowed; compare "
                "against an explicit allow-list.",
                "Access-Control-Allow-Origin: https://app.example.com\nVary: Origin",
                ["OWASP CORS", "PortSwigger CORS misconfiguration"])
        elif cors.get("origin_echo"):
            add("MEDIUM", "Content & Privacy", "CNT-06",
                "CORS reflects the request Origin",
                "Access-Control-Allow-Origin: %s" % cors.get("acao"),
                "Cross-origin reads become possible, and any credential-carrying "
                "endpoint makes that exploitable.",
                "Return a static allow-listed origin and add Vary: Origin.",
                "Vary: Origin\nAccess-Control-Allow-Origin: https://app.example.com",
                ["OWASP CORS"])
        elif cors.get("wildcard"):
            add("LOW", "Content & Privacy", "CNT-07",
                "CORS wildcard (Access-Control-Allow-Origin: *)",
                "Observed on %s" % self.url,
                "Acceptable for genuinely public data, risky if the resource later "
                "becomes private or is cached by a proxy.",
                "Keep the wildcard only on explicitly public endpoints.", None,
                ["OWASP CORS"])

        for label, names, sev, fid, why, fix in (
                ("without the Secure flag",
                 [c["name"] for c in r["cookies"]
                  if self.scheme == "https" and not c["secure"]], "HIGH", "CK-01",
                 "The cookie is also sent over plain HTTP, so one downgrade request "
                 "leaks the session.", "Add Secure to every cookie served over HTTPS."),
                ("without HttpOnly",
                 [c["name"] for c in r["cookies"] if not c["httponly"]],
                 "MEDIUM", "CK-02",
                 "Any XSS payload reads the cookie through document.cookie and "
                 "exfiltrates the session.", "Add HttpOnly to session cookies."),
                ("without SameSite",
                 [c["name"] for c in r["cookies"] if c["samesite"] == "missing"],
                 "MEDIUM", "CK-03",
                 "The browser attaches the cookie to cross-site requests, which is the "
                 "engine of CSRF.",
                 "Add SameSite=Lax (or Strict) to session cookies.")):
            if names:
                add(sev, "Content & Privacy", fid,
                    "%d cookie(s) set %s" % (len(names), label),
                    ", ".join(names[:8]), why, fix,
                    "Set-Cookie: session=<id>; Secure; HttpOnly; SameSite=Lax; "
                    "Path=/; Max-Age=3600",
                    ["OWASP Session Management Cheat Sheet"])

        if dns.get("available"):
            if not dns.get("spf"):
                add("HIGH", "Email Integrity", "DNS-01", "No SPF record published",
                    "The TXT record for %s contains no v=spf1 entry" % self.host,
                    "Anyone can send mail claiming to come from this domain, which is "
                    "ideal for phishing and invoice fraud.",
                    "Publish an SPF record listing only legitimate senders, ending in "
                    "-all.",
                    'TXT  "@"  "v=spf1 include:_spf.google.com -all"  (TTL 300)',
                    ["RFC 7208"])
            elif dns.get("spf_policy") in ("+all", "?all", "absent"):
                add("MEDIUM", "Email Integrity", "DNS-02",
                    "SPF does not restrict senders (%s)" % dns["spf_policy"],
                    cut(dns["spf"], 160),
                    "An +all or missing terminal qualifier authorises every host on the "
                    "internet to send as this domain.",
                    "Finish the record with ~all (soft fail) or -all (hard fail).",
                    'TXT  "@"  "v=spf1 include:... -all"  (TTL 300)', ["RFC 7208"])
            if dns.get("spf_lookups") and dns["spf_lookups"] > 10:
                add("MEDIUM", "Email Integrity", "DNS-03",
                    "SPF exceeds the 10 DNS lookup limit (%d)" % dns["spf_lookups"],
                    cut(dns["spf"], 160),
                    "Receivers return PERMERROR, so the record silently stops "
                    "protecting anything.",
                    "Flatten includes or use a macro-based record.", None,
                    ["RFC 7208 section 4.6.4"])
            if not dns.get("dmarc"):
                add("HIGH", "Email Integrity", "DNS-04", "No DMARC record",
                    "No TXT record at _dmarc.%s" % self.host,
                    "There is no instruction for receivers to quarantine or reject "
                    "forged mail, and no visibility into spoofing attempts.",
                    "Publish DMARC with a reporting address, then move to enforcement.",
                    'TXT  _dmarc  "v=DMARC1; p=none; rua=mailto:dmarc@%s; fo=1"'
                    % self.host, ["RFC 7489"])
            elif dns.get("dmarc_policy") == "none":
                add("MEDIUM", "Email Integrity", "DNS-05",
                    "DMARC is in monitoring mode (p=none)", cut(dns.get("dmarc"), 160),
                    "Forged mail still reaches inboxes; only reports are produced.",
                    "Once the reports look clean, raise the policy to quarantine then "
                    "reject.",
                    'TXT  _dmarc  "v=DMARC1; p=reject; rua=mailto:dmarc@%s"'
                    % self.host, ["RFC 7489"])
            elif dns.get("dmarc_pct") not in (None, 100):
                add("MEDIUM", "Email Integrity", "DNS-06",
                    "DMARC applies to only %s%% of mail" % dns["dmarc_pct"],
                    cut(dns.get("dmarc"), 160),
                    "The remaining percentage bypasses the policy entirely.",
                    "Raise pct to 100 once the reports are clean.", None, ["RFC 7489"])
            if not dns.get("dkim"):
                add("MEDIUM", "Email Integrity", "DNS-07",
                    "No DKIM key on common selectors",
                    "Checked %d well-known selectors; none published a key"
                    % dns.get("selectors", 0),
                    "Without DKIM the message body is not cryptographically bound to "
                    "the domain, which weakens DMARC alignment.",
                    "Enable DKIM signing at your mail provider and publish the public "
                    "key.",
                    'TXT  <selector>._domainkey  "v=DKIM1; k=rsa; p=MIIBIjAN..."',
                    ["RFC 6376"])
            if not dns.get("mx"):
                add("INFO", "Email Integrity", "DNS-08", "No MX records",
                    "The MX lookup returned nothing",
                    "Spoofing is easier when the domain cannot receive bounce or "
                    "complaint mail.",
                    "If the domain never sends mail, say so explicitly.",
                    'TXT "@" "v=spf1 -all"', ["RFC 7505"])
            if not dns.get("caa"):
                add("LOW", "Email Integrity", "DNS-09", "No CAA records",
                    "The CAA lookup on %s returned nothing" % self.host,
                    "Any public CA may issue a certificate for this domain, including "
                    "one tricked into an unauthorised issuance.",
                    "Restrict issuance to your CA.",
                    'CAA  0 issue "letsencrypt.org"\n'
                    'CAA  0 iodef "mailto:security@%s"' % self.host, ["RFC 8659"])
            if dns.get("dnssec") is not True:
                add("LOW", "Email Integrity", "DNS-10", "DNSSEC is not confirmed",
                    "No validated (AD) response and no DNSKEY for %s" % self.host,
                    "Without DNSSEC an on-path attacker can forge DNS answers, which "
                    "undermines SPF, DMARC and CAA.",
                    "Enable DNSSEC at the registrar and publish a DS record.", None,
                    ["RFC 4033"])

        if http.get("risky"):
            add("MEDIUM", "Transport Security", "HTTP-01",
                "Risky HTTP methods advertised: %s" % ", ".join(http["risky"]),
                "Allow: %s" % ", ".join(http.get("allow") or []),
                "PUT/DELETE can modify server state and TRACE enables cross-site "
                "tracing.",
                "Advertise and accept only the methods the application actually uses.",
                "if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) { return 405; }",
                ["OWASP Testing Guide OTG-CONFIG-006"])

        versioned = dict((k, v) for k, v in
                         (r["fingerprint"].get("tech") or {}).items()
                         if re.search(r"\d\.\d", str(v)))
        if versioned:
            add("MEDIUM", "Data Exposure", "INF-01",
                "Software versions disclosed in headers",
                ", ".join("%s: %s" % (k, cut(v, 40))
                          for k, v in list(versioned.items())[:5]),
                "Exact versions let an attacker match the target against public "
                "exploits with no reconnaissance noise.",
                "Suppress version banners.",
                "nginx:  server_tokens off;\nphp:    expose_php = Off",
                ["OWASP A05:2021"])
        sigs = (r["fingerprint"].get("error_page") or {}).get("signatures") or []
        if sigs:
            add("HIGH", "Data Exposure", "INF-02",
                "Error page discloses internals: " + ", ".join(sigs),
                "404 response: %s" % (r["fingerprint"]["error_page"].get("title") or ""),
                "Stack traces and absolute paths reveal frameworks, file layout and "
                "sometimes credentials or queries to any visitor.",
                "Turn off debug mode in production and serve a static error page.",
                "DEBUG = False            # Django\nAPP_DEBUG=false          # Laravel\n"
                "display_errors = Off     # PHP", ["OWASP A05:2021", "CWE-209"])
        if not r["security_txt"].get("found"):
            add("LOW", "Data Exposure", "INF-03",
                "No security.txt publishing a contact",
                "Neither /.well-known/security.txt nor /security.txt exists",
                "Researchers have no reporting channel, so findings reach the public or "
                "nobody instead of you.",
                "Publish RFC 9116 security.txt with a monitored contact.",
                "Contact: mailto:security@%s\nExpires: 2027-12-31T00:00:00Z"
                % self.host, ["RFC 9116"])
        if r["home"].get("reachable") and not http.get("compression"):
            add("LOW", "Data Exposure", "INF-04", "No HTTP compression",
                "Content-Encoding absent; payload %.1f kB" % r["home"].get("size_kb", 0),
                "Larger transfers mean slower first paint, especially on mobile "
                "networks.",
                "Enable gzip or brotli for text responses.",
                "gzip on;\ngzip_types text/css application/javascript "
                "application/json;", ["OWASP Secure Headers"])
        if r["robots"].get("found") and r["robots"].get("sensitive"):
            add("MEDIUM", "Data Exposure", "INF-05",
                "robots.txt advertises sensitive paths",
                ", ".join(r["robots"]["sensitive"][:6]),
                "Disallow entries are a public map of admin panels, backups and "
                "internal endpoints.",
                "Protect those paths with authentication instead of obscurity, and "
                "keep internal names out of robots.txt.", None, ["OWASP A05:2021"])

        for i, p in enumerate([int(x) for x in r.get("open_ports", [])], 1):
            if p in RISK_PORTS and p not in (80, 443):
                sev, why = RISK_PORTS[p]
                add(sev, "Network Exposure", "NET-%02d" % i,
                    "Port %d/%s reachable from the internet" % (p, PNAME.get(p, "?")),
                    "A TCP connect to %s:%d succeeded" % (self.ip, p),
                    why + ". Internet-wide scanners find such services within hours.",
                    PORT_FIX.get(p, "Firewall the port and expose it only over a "
                                    "private network or VPN."),
                    "ufw deny %d/tcp\n# or bind the service to 127.0.0.1" % p,
                    ["OWASP A05:2021", "CIS Controls v8 12.2"])
        if r.get("cdn"):
            add("INFO", "Network Exposure", "NET-CDN",
                "%s fronting detected" % r["cdn"],
                "Header fingerprint includes %s" % ", ".join(
                    k for k in ("Server", "CF-RAY", "Via", "Alt-Svc")
                    if k in r["home"]["headers"]),
                "A CDN or WAF absorbs volumetric attacks and hides the origin, but the "
                "origin must still be firewalled or it can be reached through its real "
                "IP.",
                "Restrict the origin to the CDN published egress ranges.", None,
                ["OWASP A05:2021"])
        if r.get("subdomains"):
            add("INFO", "Network Exposure", "NET-SUB",
                "%d subdomains resolve" % len(r["subdomains"]),
                ", ".join(s["host"] for s in r["subdomains"][:12]),
                "Each live host is a separate entry point, and forgotten staging or "
                "admin hosts are a classic way in.",
                "Keep an inventory, delete decommissioned records and put "
                "non-production hosts behind authentication.", None, ["OWASP A05:2021"])
        out.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["id"]))
        return out

    def calculate_score(self):
        r = self.results
        tls, dns, hdr = r["tls"], r["dns"], r["headers"]
        http, content, cors, cookies = r["http"], r["content"], r["cors"], r["cookies"]
        cats, t = {}, 0.0
        if tls.get("enabled") and not tls.get("error"):
            d = tls.get("days_left")
            t += 11 if d is None else (0 if d < 0 else (8 if d < 15 else 14))
            if not any(tls.get("protocols", {}).get(v) for v in ("TLSv1", "TLSv1.1")):
                t += 5
            if tls.get("forward_secrecy") and not any(
                    w in str(tls.get("cipher") or "").upper() for w in WEAK_CIPHER):
                t += 3
        if http.get("https_upgrade"):
            t += 3
        cats["Transport Security"] = round(min(t, 25.0), 1)
        cats["Security Headers"] = round(22.0 * hdr["ratio"], 1)
        c = 0.0 if content.get("mixed") else 4.0
        if cors.get("dangerous"):
            c += 0.0
        elif cors.get("origin_echo") or cors.get("wildcard"):
            c += 2.0
        else:
            c += 4.0
        if not cookies:
            c += 5.0
        else:
            c += 5.0 * sum(1 for x in cookies if x["secure"] and x["httponly"]
                           and x["samesite"] != "missing") / len(cookies)
        cats["Content & Privacy"] = round(min(c, 13.0), 1)
        e = 0.0
        if dns.get("available"):
            if dns.get("spf"):
                e += {"-all": 5.0, "~all": 3.5, "?all": 1.5, "absent": 0.0}.get(
                    dns.get("spf_policy"), 1.0)
            if dns.get("dmarc"):
                e += {"reject": 6.0, "quarantine": 4.5, "none": 1.5}.get(
                    dns.get("dmarc_policy"), 1.0)
            e += 2.0 if dns.get("mx") else 0.0
            e += 1.0 if dns.get("caa") else 0.0
            e += 1.0 if dns.get("dnssec") is True else 0.0
        cats["Email Integrity"] = round(min(e, 15.0), 1)
        x = 9.0 if not r.get("exposed") else max(0.0, 9.0 - 3.0 * len(r["exposed"]))
        x += 3.0 if not r.get("listing") else 0.0
        disclosing = any(re.search(r"\d\.\d", str(v))
                         for v in (r["fingerprint"].get("tech") or {}).values())
        x += 0.0 if disclosing else 3.0
        cats["Data Exposure"] = round(min(x, 15.0), 1)
        opened = [int(p) for p in r.get("open_ports", [])]
        n = 0.0 if any(p in DB_PORTS for p in opened) else 5.0
        n += 0.0 if any(p in ADMIN_PORTS for p in opened) else 3.0
        n += 0.0 if any(p in ALT_PORTS for p in opened) else 2.0
        cats["Network Exposure"] = round(min(n, 10.0), 1)
        total = max(0, min(100, int(round(sum(cats.values())))))
        return {"categories": cats, "total": total, "grade": grade_of(total),
                "counts": count_sev(r.get("findings", [])),
                "risk": round(sum(SEV_WEIGHT.get(f["severity"], 0)
                                  for f in r.get("findings", [])), 1)}

    def run_audit(self):
        t0 = time.time()
        home = self.fetch_homepage()
        self.results["home"] = home
        self.results["cdn"] = self.is_behind_cdn(home) if home.get("reachable") else None
        if not home.get("reachable"):
            self.log.warn("Target unreachable (%s)"
                          % (home.get("error") or "no response"))
            self._empty_results()
            self.results["findings"] = [{
                "id": "META-01", "severity": "INFO", "category": "Meta",
                "title": "Target could not be reached",
                "evidence": home.get("error") or "no response",
                "impact": "No assessment is possible: the host did not answer over %s. "
                          "Verify the hostname, DNS and that the service is running."
                          % self.scheme,
                "fix": "Check DNS resolution and that the web server listens on port "
                       "%d." % self.port,
                "snippet": None, "refs": [], "asset": self.url}]
            self.results["score"] = {"categories": {}, "total": 0, "grade": "n/a",
                                     "counts": count_sev(self.results["findings"]),
                                     "risk": 0}
            self.results["meta"] = self._meta(t0)
            return self.results
        jobs = {"exposed": self.check_sensitive_files, "listing": self.check_listing,
                "tls": self.check_tls, "dns": self.check_dns, "http": self.check_http,
                "cors": self.check_cors, "robots": self.check_robots,
                "sitemap": self.check_sitemap, "security_txt": self.check_security_txt,
                "fingerprint": self.check_fingerprint,
                "subdomains": self.check_subdomains}
        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = dict((k, ex.submit(fn)) for k, fn in jobs.items())
            for key, fut in futures.items():
                try:
                    self.results[key] = fut.result()
                except Exception as exc:
                    self.log.warn("%s check failed: %s" % (key, exc))
                    self.results[key] = {}
        self.results["headers"] = self.analyze_headers()
        self.results["cookies"] = self.check_cookies()
        self.results["content"] = self.check_content()
        self.results["ports"] = self.check_ports(skip=bool(self.results["cdn"]))
        self.results["open_ports"] = [str(p) for p, s in
                                      sorted(self.results["ports"].items())
                                      if s == "Open"]
        for key in ("cors", "content", "fingerprint", "robots", "sitemap",
                    "security_txt", "http", "dns", "tls"):
            if not isinstance(self.results.get(key), dict):
                self.results[key] = {}
        self.results["findings"] = self.build_findings()
        self.results["score"] = self.calculate_score()
        self.results["meta"] = self._meta(t0)
        if "html" in self.results["home"]:
            self.results["home"] = dict(self.results["home"], html="")
        return self.results

    def _empty_results(self):
        self.results.update({
            "headers": {"detail": {}, "present": [], "missing": list(HEADERS),
                        "ratio": 0.0, "disclosure": {}, "csp": {"present": False}},
            "tls": {"enabled": self.scheme == "https", "protocols": {}},
            "dns": {"available": HAVE_DNS, "dkim": [], "caa": [], "mx": [], "txt": []},
            "http": {}, "cors": {}, "content": {}, "fingerprint": {}, "cookies": [],
            "exposed": [], "listing": [], "subdomains": [],
            "robots": {"found": False, "sensitive": []},
            "sitemap": {"found": False, "urls": 0}, "security_txt": {"found": False},
            "ports": {}, "open_ports": [], "emails": []})

    def _meta(self, t0):
        return {"domain": self.host, "url": self.url, "scheme": self.scheme,
                "port": self.port, "ip": self.ip,
                "audit_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "audit_ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "duration_s": round(time.time() - t0, 1), "tool": TOOL,
                "version": VERSION,
                "reachable": bool(self.results.get("home", {}).get("reachable")),
                "dns_available": HAVE_DNS, "crypto_available": HAVE_CRYPTO,
                "cdn": self.results.get("cdn")}


# ==========================================================================
#  REPORT
# ==========================================================================
def hx(c):
    return colors.HexColor(c)


def make_styles():
    base = getSampleStyleSheet()

    def P(n, **kw):
        return ParagraphStyle(n, parent=base["Normal"], **kw)

    return {
        "h1": P("h1", fontName="Helvetica-Bold", fontSize=15, leading=18,
                textColor=hx(INK)),
        "h2": P("h2", fontName="Helvetica-Bold", fontSize=11, leading=13.5,
                textColor=hx(INK), spaceBefore=9, spaceAfter=4),
        "body": P("body", fontSize=8.3, leading=11, textColor=hx(INK)),
        "small": P("small", fontSize=7, leading=9.4, textColor=hx(MUTED)),
        "tiny": P("tiny", fontSize=6.2, leading=8, textColor=hx(FAINT)),
        "cell": P("cell", fontSize=7.3, leading=9.4, textColor=hx(INK)),
        "cellb": P("cellb", fontSize=7.3, leading=9.4, textColor=hx(WHITE),
                   fontName="Helvetica-Bold"),
        "mono": P("mono", fontName="Courier", fontSize=6.9, leading=8.8,
                  textColor=hx("#e2e8f0"))}


STY = make_styles()


def banner(width, title, lines, height=94):
    d = Drawing(width, height)
    c1, c2 = hx(NAVY), hx("#3730a3")
    steps = 80
    for i in range(steps):
        t = i / float(steps - 1)
        d.add(Rect(width * i / steps, 0, width / steps + 1, height, strokeColor=None,
                   fillColor=colors.Color(c1.red + (c2.red - c1.red) * t,
                                          c1.green + (c2.green - c1.green) * t,
                                          c1.blue + (c2.blue - c1.blue) * t)))
    d.add(Rect(0, 0, width, 3, fillColor=hx(ACCENT), strokeColor=None))
    d.add(DStr(20, height - 34, title, fontName="Helvetica-Bold", fontSize=20,
               fillColor=hx(WHITE)))
    y = height - 52
    for line in lines:
        d.add(DStr(20, y, line, fontName="Helvetica", fontSize=8.4,
                   fillColor=hx("#c7d2fe")))
        y -= 11.5
    return d


def gauge(score, grade, size=134):
    d = Drawing(size, size)
    c = size / 2.0
    r = c - 8
    col = hx(score_color(score))
    sweep = 3.6 * max(0, min(100, score))
    d.add(Circle(c, c, r, fillColor=hx(TRACK), strokeColor=None))
    if sweep > 1:
        d.add(Wedge(c, c, r, 90 - sweep, 90, fillColor=col, strokeColor=None))
    d.add(Circle(c, c, r * 0.70, fillColor=hx(WHITE), strokeColor=None))
    d.add(DStr(c, c - 5, "%d" % score, fontName="Helvetica-Bold",
               fontSize=size * 0.30, fillColor=col, textAnchor="middle"))
    d.add(DStr(c, c + r * 0.24, "of 100", fontName="Helvetica", fontSize=7.4,
               fillColor=hx(MUTED), textAnchor="middle"))
    d.add(DStr(c, c - r * 0.36, "GRADE %s" % grade, fontName="Helvetica-Bold",
               fontSize=9, fillColor=col, textAnchor="middle"))
    return d


def bar_chart(rows, width, height, label_w=112, value_w=54):
    d = Drawing(width, height)
    n = max(len(rows), 1)
    row_h = height / float(n)
    bar_w = max(10.0, width - label_w - value_w)
    for i, (label, ratio, col, text) in enumerate(rows):
        y = height - (i + 1) * row_h + row_h * 0.26
        bh = max(5.0, row_h * 0.44)
        d.add(DStr(0, y + 1.4, label, fontName="Helvetica", fontSize=7.2,
                   fillColor=hx(SLATE)))
        d.add(Rect(label_w, y, bar_w, bh, fillColor=hx(TRACK), strokeColor=None))
        d.add(Rect(label_w, y, max(1.5, bar_w * max(0.0, min(1.0, ratio))), bh,
                   fillColor=hx(col), strokeColor=None))
        d.add(DStr(label_w + bar_w + 4, y + 1.4, text, fontName="Helvetica-Bold",
                   fontSize=7.2, fillColor=hx(col)))
    return d


def sev_strip(counts, width, height=32):
    d = Drawing(width, height)
    total = sum(counts.get(k, 0) for k in SEV_ORDER) or 1
    x = 0.0
    for sev in SEV_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        w = width * n / float(total)
        d.add(Rect(x, 14, w, 14, fillColor=hx(SEV_COLOR[sev]), strokeColor=None))
        if w > 12:
            d.add(DStr(x + w / 2.0, 18.4, str(n), fontName="Helvetica-Bold",
                       fontSize=7.2, fillColor=hx(WHITE), textAnchor="middle"))
        x += w
    lx = 0.0
    for sev in SEV_ORDER:
        d.add(Rect(lx, 3, 6, 6, fillColor=hx(SEV_COLOR[sev]), strokeColor=None))
        d.add(DStr(lx + 9, 4.2, sev.title(), fontName="Helvetica", fontSize=6.4,
                   fillColor=hx(MUTED)))
        lx += 9 + len(sev) * 4.0 + 12
    return d


class Report:
    def __init__(self, data, path):
        self.d, self.path = data, path
        self.meta = data.get("meta", {})
        self.score = data.get("score", {})
        self.findings = data.get("findings", [])
        self.w = A4[0] - 68

    def grid(self, head, rows, widths, head_bg=SLATE):
        data = [[Paragraph(esc(c), STY["cellb"]) for c in head]]
        for row in rows:
            data.append([c if isinstance(c, Paragraph)
                         else Paragraph(esc(c), STY["cell"]) for c in row])
        t = Table(data, colWidths=widths, hAlign="LEFT", repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), hx(head_bg)),
              ("GRID", (0, 0), (-1, -1), 0.35, hx(LINE)),
              ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
              ("TOPPADDING", (0, 0), (-1, -1), 2.6),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 2.6),
              ("LEFTPADDING", (0, 0), (-1, -1), 4)]
        for i in range(1, len(data)):
            if i % 2 == 0:
                st.append(("BACKGROUND", (0, i), (-1, i), hx(BG)))
        t.setStyle(TableStyle(st))
        return t

    def box(self, flowables, bg=BG, border=LINE):
        t = Table([[flowables]], colWidths=[self.w])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx(bg)),
                               ("BOX", (0, 0), (-1, -1), 0.6, hx(border)),
                               ("LEFTPADDING", (0, 0), (-1, -1), 8),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                               ("TOPPADDING", (0, 0), (-1, -1), 6),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        return t

    def chips(self, items, cols=3):
        cells = [Paragraph("<font size='6' color='%s'>%s</font><br/>"
                           "<font size='8.6' color='%s'><b>%s</b></font>"
                           % (MUTED, esc(label).upper(), col, esc(value)), STY["cell"])
                 for label, value, col in items]
        while len(cells) % cols:
            cells.append(Paragraph("", STY["cell"]))
        rows = [cells[i:i + cols] for i in range(0, len(cells), cols)]
        t = Table(rows, colWidths=[self.w / float(cols)] * cols)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx("#f1f5f9")),
                               ("BOX", (0, 0), (-1, -1), 0.4, hx(LINE)),
                               ("INNERGRID", (0, 0), (-1, -1), 0.4, hx(LINE)),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 4.5),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5)]))
        return t

    def summary_text(self):
        c = self.score.get("counts", {})
        crit = [f["title"] for f in self.findings if f["severity"] == "CRITICAL"]
        high = [f["title"] for f in self.findings if f["severity"] == "HIGH"]
        weak = [k for k, v in sorted(self.score.get("categories", {}).items(),
                                     key=lambda kv: kv[1])[:2]]
        parts = ["%s was assessed as <b>%s</b> with an overall score of <b>%s/100</b> "
                 "(risk index %.0f)." % (esc(self.meta.get("domain", "the target")),
                                         self.score.get("grade", "?"),
                                         self.score.get("total", 0),
                                         self.score.get("risk", 0)),
                 "The scan recorded <b>%d CRITICAL</b>, <b>%d HIGH</b>, <b>%d "
                 "MEDIUM</b>, <b>%d LOW</b> and <b>%d informational</b> observations."
                 % (c.get("CRITICAL", 0), c.get("HIGH", 0), c.get("MEDIUM", 0),
                    c.get("LOW", 0), c.get("INFO", 0))]
        if crit:
            parts.append("Needs immediate attention: " + esc(", ".join(crit[:3])) + ".")
        if high:
            parts.append("High priority: " + esc(", ".join(high[:3])) + ".")
        if weak:
            parts.append("The weakest control areas are <b>%s</b>. Every finding "
                         "below is paired with the concrete change that removes it."
                         % ", ".join(weak))
        return " ".join(parts)

    def cover(self):
        m, sc = self.meta, self.score
        tls, dns = self.d.get("tls", {}), self.d.get("dns", {})
        hdr = self.d.get("headers", {})
        tls_state = ("not used" if not tls.get("enabled") else
                     "untrusted" if tls.get("trusted") is False else
                     "expired" if (tls.get("days_left") or 0) < 0 else
                     "%s days left" % tls.get("days_left")
                     if tls.get("days_left") is not None else "unknown")
        f = [banner(self.w, "WEB SECURITY AUDIT",
                    [esc(m.get("domain", "?")),
                     "IP %s  |  %s  |  %s" % (esc(m.get("ip")),
                                              esc(m.get("audit_date")),
                                              esc(m.get("tool")))]),
             Spacer(1, 12),
             self.chips([("Grade / score", "%s  (%d/100)"
                          % (sc.get("grade", "?"), sc.get("total", 0)),
                          score_color(sc.get("total", 0))),
                         ("Findings", "%d total" % len(self.findings),
                          SEV_COLOR["HIGH"]),
                         ("Risk index", "%.0f" % sc.get("risk", 0),
                          SEV_COLOR["MEDIUM"]),
                         ("TLS certificate", tls_state,
                          SEV_COLOR["OK"] if tls.get("trusted")
                          else SEV_COLOR["CRITICAL"]),
                         ("Security headers", "%d of %d present"
                          % (len(hdr.get("present", [])), len(HEADERS)),
                          SEV_COLOR["OK"] if not hdr.get("missing")
                          else SEV_COLOR["MEDIUM"]),
                         ("E-mail posture", "DMARC %s / SPF %s"
                          % (dns.get("dmarc_policy") or "none",
                             dns.get("spf_policy") or "none"),
                          SEV_COLOR["OK"] if dns.get("dmarc_policy") == "reject"
                          else SEV_COLOR["HIGH"]),
                         ("Exposed files", str(len(self.d.get("exposed", []))),
                          SEV_COLOR["CRITICAL"] if self.d.get("exposed")
                          else SEV_COLOR["OK"]),
                         ("Open ports", str(len(self.d.get("open_ports", []))),
                          SEV_COLOR["MEDIUM"] if self.d.get("open_ports")
                          else SEV_COLOR["OK"]),
                         ("WAF / CDN", self.d.get("cdn") or "none detected",
                          SEV_COLOR["OK"] if self.d.get("cdn") else SEV_COLOR["LOW"])]),
             Spacer(1, 14)]
        row = Table([[gauge(sc.get("total", 0), sc.get("grade", "?")),
                      sev_strip(sc.get("counts", {}), self.w - 170)],
                     [Paragraph("Overall risk score", STY["small"]),
                      Paragraph("Findings by severity", STY["small"])]],
                    colWidths=[160, self.w - 160])
        row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
                                 ("ALIGN", (0, 0), (0, 0), "CENTER"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                 ("TOPPADDING", (0, 0), (-1, 0), 0)]))
        f += [row, Spacer(1, 12), Paragraph("Executive summary", STY["h2"]),
              self.box([Paragraph(self.summary_text(), STY["body"])]), Spacer(1, 10),
              Paragraph("Scope and method", STY["h2"]),
              self.grid(["FIELD", "VALUE"], [
                  ["Target URL", m.get("url")],
                  ["Resolved address", m.get("ip")],
                  ["Scheme and port", "%s / %s" % (m.get("scheme"), m.get("port"))],
                  ["Assessment window", "%s (%s s)" % (m.get("audit_date"),
                                                       m.get("duration_s"))],
                  ["Tests executed",
                   "Header grading by value; TLS handshake, protocol matrix and "
                   "certificate inspection; DNS, SPF, DMARC, DKIM, CAA and DNSSEC; "
                   "%d sensitive paths with byte-level verification; directory "
                   "listing; CORS; cookie flags; redirect chain; HTTP methods; "
                   "technology fingerprint; TCP port state on %d ports; subdomain "
                   "resolution" % (len(PATHS), len(self.d.get("ports", {})))],
                  ["Data sources", "Publicly reachable responses, DNS records and TLS "
                   "metadata only. No credentials, no payloads, no exploitation."],
                  ["Optional modules", "dnspython %s | cryptography %s"
                   % ("yes" if m.get("dns_available") else "no",
                      "yes" if m.get("crypto_available") else "no")]],
                  [128, self.w - 128]),
              Spacer(1, 10),
              self.box([Paragraph(
                  "These findings describe observable configuration at the moment of "
                  "the scan. This is not a penetration test: no vulnerability was "
                  "exploited and no authentication was bypassed. Validate each item in "
                  "context before planning remediation.", STY["tiny"])])]
        return f

    def overview(self):
        f = [Paragraph("Score breakdown by control area", STY["h1"])]
        cats = self.score.get("categories", {})
        maxima = [("Transport Security", 25), ("Security Headers", 22),
                  ("Content & Privacy", 13), ("Email Integrity", 15),
                  ("Data Exposure", 15), ("Network Exposure", 10)]
        rows = []
        for name, mx in maxima:
            val = cats.get(name, 0)
            pct = val / float(mx) if mx else 0
            rows.append((name, pct, score_color(pct * 100), "%s / %d" % (val, mx)))
        f += [bar_chart(rows, self.w, 15.0 * len(rows) + 6),
              Spacer(1, 14), Paragraph("Security header matrix", STY["h2"])]
        hrows = []
        for name, d in self.d.get("headers", {}).get("detail", {}).items():
            col = {"OK": SEV_COLOR["OK"], "WEAK": SEV_COLOR["MEDIUM"],
                   "MISSING": SEV_COLOR["CRITICAL"]}.get(d["state"], MUTED)
            hrows.append([
                Paragraph("<font color='%s'><b>%s</b></font>"
                          % (col, esc(d["short"])), STY["cell"]),
                Paragraph(esc(name), STY["cell"]),
                Paragraph(esc(cut(d.get("value") or "-", 80)), STY["cell"]),
                Paragraph("<font color='%s'><b>%s</b></font>"
                          % (col, esc(d["state"])), STY["cell"]),
                Paragraph(esc(d.get("note") or ""), STY["cell"])])
        f.append(self.grid(["CODE", "HEADER", "OBSERVED VALUE", "STATE", "ASSESSMENT"],
                           hrows, [30, 116, 140, 42, self.w - 328], head_bg=NAVY))
        f += [Spacer(1, 14), Paragraph("Findings index", STY["h2"])]
        irows = [[Paragraph("<font color='%s'><b>%s</b></font>"
                            % (SEV_COLOR.get(x["severity"], MUTED),
                               esc(x["severity"])), STY["cell"]),
                  Paragraph("<b>%s</b>" % esc(x["id"]), STY["cell"]),
                  Paragraph(esc(x["category"]), STY["cell"]),
                  Paragraph(esc(x["title"]), STY["cell"])] for x in self.findings]
        f.append(self.grid(["SEVERITY", "ID", "CATEGORY", "TITLE"],
                           irows or [["-", "-", "-",
                                      "No issues were detected on the tested "
                                      "surfaces."]],
                           [62, 42, 88, self.w - 192]))
        return f

    def finding_block(self, x):
        col = SEV_COLOR.get(x["severity"], MUTED)
        head = Table([[Paragraph("<font color='#ffffff'><b>%s</b></font>"
                                 % esc(x["severity"]), STY["cell"]),
                       Paragraph("<font color='#ffffff'><b>%s</b> &nbsp; %s</font>"
                                 % (esc(x["id"]), esc(x["title"])), STY["cell"])]],
                     colWidths=[70, self.w - 70])
        head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx(col)),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 6),
                                  ("TOPPADDING", (0, 0), (-1, -1), 3.6),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 3.6)]))
        meta = self.grid(["FIELD", "DETAIL"], [
            ["Category", x["category"]],
            ["Affected asset", x["asset"]],
            ["Evidence", Paragraph(esc(x["evidence"]), STY["cell"])],
            ["Impact", Paragraph(esc(x["impact"]), STY["cell"])],
            ["Remediation", Paragraph(esc(x["fix"]), STY["cell"])]],
            [70, self.w - 70], head_bg="#475569")
        out = [Spacer(1, 6), KeepTogether([head, meta])]
        if x.get("snippet"):
            t = Table([[XPreformatted(esc(x["snippet"]), STY["mono"])]],
                      colWidths=[self.w])
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx("#0f172a")),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 7),
                                   ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                                   ("TOPPADDING", (0, 0), (-1, -1), 5),
                                   ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
            out += [Spacer(1, 3), t]
        if x.get("refs"):
            out += [Spacer(1, 2), Paragraph("References: "
                                            + esc("; ".join(x["refs"])), STY["tiny"])]
        return out

    def appendix(self):
        d = self.d
        tls, dns, fp = d.get("tls", {}), d.get("dns", {}), d.get("fingerprint", {})
        content, robots = d.get("content", {}), d.get("robots", {})
        f = [Paragraph("Appendix A - Transport security", STY["h1"]),
             self.grid(["FIELD", "VALUE"], [
                 ["HTTPS", "in use" if tls.get("enabled") else "not in use"],
                 ["Chain trusted", "yes" if tls.get("trusted") else
                  "no (%s)" % (tls.get("kind") or tls.get("error")
                               or "handshake failed")],
                 ["Negotiated protocol", "%s (ALPN %s)" % (tls.get("protocol"),
                                                           tls.get("alpn") or "-")],
                 ["Protocol matrix",
                  ", ".join("%s %s" % (k, "yes" if v else "no")
                            for k, v in (tls.get("protocols") or {}).items())
                  or "not tested"],
                 ["Cipher suite", "%s (%s-bit, forward secrecy %s)"
                  % (tls.get("cipher") or "-", tls.get("bits") or "?",
                     "yes" if tls.get("forward_secrecy") else "no")],
                 ["Subject", tls.get("subject")],
                 ["Issuer", "%s (%s)" % (tls.get("issuer"), tls.get("issuer_org"))],
                 ["Validity", "%s to %s (%s days left)"
                  % (tls.get("not_before"), tls.get("expires"), tls.get("days_left"))],
                 ["Key and signature", "%s %s-bit, hash %s"
                  % (tls.get("key_type") or "?", tls.get("key_size") or "?",
                     tls.get("sig_alg") or "?")],
                 ["SAN entries", "%s%s" % (tls.get("san_count"),
                                           " (wildcard)" if tls.get("wildcard")
                                           else "")],
                 ["HTTP to HTTPS redirect", "yes" if d["http"].get("https_upgrade")
                  else "no"],
                 ["Redirect chain", " -> ".join("%s [%s]" % (h["url"], h["status"])
                                                for h in
                                                (d["http"].get("https_chain") or []))
                  or "-"],
                 ["Advertised methods", ", ".join(d["http"].get("allow") or [])
                  or "none"],
                 ["Compression", d["http"].get("compression") or "none"],
                 ["Alt-Svc / HTTP2+", d["http"].get("alt_svc") or "not advertised"]],
                 [128, self.w - 128]),
             Spacer(1, 12),
             Paragraph("Appendix B - DNS and e-mail authentication", STY["h1"]),
             self.grid(["RECORD", "OBSERVED VALUE"], [
                 ["A", ", ".join(dns.get("a") or []) or "-"],
                 ["AAAA", ", ".join(dns.get("aaaa") or []) or "-"],
                 ["CNAME", dns.get("cname") or "-"],
                 ["NS", ", ".join(dns.get("ns") or []) or "-"],
                 ["MX", ", ".join("%s (pref %s)" % (m["host"], m["pref"])
                                  for m in (dns.get("mx") or [])) or "-"],
                 ["SPF", (cut(dns.get("spf"), 150) + "  [policy %s, %s lookups]"
                          % (dns.get("spf_policy"), dns.get("spf_lookups")))
                  if dns.get("spf") else "not published"],
                 ["DMARC", (cut(dns.get("dmarc"), 150) + "  [policy %s, pct %s]"
                            % (dns.get("dmarc_policy"), dns.get("dmarc_pct")))
                  if dns.get("dmarc") else "not published"],
                 ["DKIM", ", ".join(x["selector"] for x in (dns.get("dkim") or []))
                  or "no key on %s common selectors" % dns.get("selectors", 0)],
                 ["CAA", ", ".join(dns.get("caa") or []) or "not published"],
                 ["DNSSEC", "validated" if dns.get("dnssec") is True else
                  ("not confirmed" if dns.get("available")
                   else "n/a (dnspython missing)")],
                 ["TXT", " | ".join(dns.get("txt") or [])[:380] or "-"]],
                 [62, self.w - 62]),
             Spacer(1, 12),
             Paragraph("Appendix C - Exposed content, ports and cookies", STY["h1"])]
        rows = [[e["path"], e["size"], e["signature"], cut(e["sample"], 66)]
                for e in d.get("exposed", [])]
        f.append(self.grid(["PATH", "BYTES", "VERIFIED CONTENT", "REDACTED SAMPLE"],
                           rows or [["-", "-",
                                     "no publicly readable file confirmed", "-"]],
                           [88, 38, 126, self.w - 252]))
        f += [Spacer(1, 8),
              self.grid(["PORT", "SERVICE", "STATE", "SEVERITY"],
                        [[str(p), PNAME.get(p, "?"), s,
                          RISK_PORTS.get(p, ("", ""))[0] or "-"]
                         for p, s in sorted((d.get("ports") or {}).items())]
                        or [["-", "-", "skipped (CDN fronted or disabled)", "-"]],
                        [48, 104, 66, self.w - 218]),
              Spacer(1, 8),
              self.grid(["COOKIE", "SECURE", "HTTPONLY", "SAMESITE", "__HOST-",
                         "SESSION"],
                        [[c["name"], "yes" if c["secure"] else "no",
                          "yes" if c["httponly"] else "no", c["samesite"],
                          "yes" if c["host_prefix"] else "no",
                          "yes" if c["session_like"] else "no"]
                         for c in d.get("cookies", [])]
                        or [["no cookies were set on the analysed response", "-", "-",
                             "-", "-", "-"]],
                        [self.w - 296, 46, 52, 58, 52, 58]),
              Spacer(1, 12),
              Paragraph("Appendix D - Attack surface and technology", STY["h1"]),
              self.grid(["ITEM", "OBSERVED VALUE"], [
                  ["Resolving subdomains",
                   ", ".join(s["host"] for s in (d.get("subdomains") or []))
                   or "none from the tested list"],
                  ["robots.txt",
                   "present, %s flagged paths" % len(robots.get("sensitive", []))
                   if robots.get("found") else "absent"],
                  ["Sensitive entries in robots.txt",
                   ", ".join(robots.get("sensitive", [])) or "-"],
                  ["Sitemap", "%s URLs at %s" % (d["sitemap"].get("urls"),
                                                 d["sitemap"].get("path"))
                   if d["sitemap"].get("found") else "absent"],
                  ["security.txt", d["security_txt"].get("path")
                   if d["security_txt"].get("found") else "absent"],
                  ["Technology stack", ", ".join(fp.get("stack") or [])
                   or "not determined"],
                  ["Disclosed versions",
                   ", ".join("%s %s" % (k, v) for k, v in
                             (fp.get("tech") or {}).items()
                             if re.search(r"\d\.\d", str(v))) or "none"],
                  ["Error page", "%s%s" % ("HTTP %s - "
                                           % fp["error_page"].get("status")
                                           if fp.get("error_page") else "",
                                           (fp.get("error_page") or {}).get("title")
                                           or "-")],
                  ["Error page leaks",
                   ", ".join((fp.get("error_page") or {}).get("signatures") or [])
                   or "no framework or path disclosure detected"],
                  ["Mixed content hosts", ", ".join(content.get("mixed") or [])
                   or "none"],
                  ["External script origins",
                   ", ".join(content.get("external_scripts") or []) or "none"],
                  ["Inline scripts / without SRI",
                   "%s / %s" % (content.get("inline_scripts"),
                                content.get("sri_missing"))],
                  ["E-mails in source", ", ".join(content.get("emails") or [])
                   or "none"],
                  ["CORS policy",
                   ("origin reflected%s" % (", credentials allowed"
                                            if d["cors"].get("credentials") else ""))
                   if d["cors"].get("origin_echo") else
                   ("wildcard" if d["cors"].get("wildcard") else "not permissive")],
                  ["WAF / CDN", d.get("cdn") or "none detected"],
                  ["Response profile", "%s ms total, %s ms TTFB, %s kB"
                   % (d["home"].get("elapsed_ms"), d["home"].get("ttfb_ms"),
                      d["home"].get("size_kb"))]],
                  [126, self.w - 126]),
              Spacer(1, 12),
              Paragraph("Appendix E - Scoring model and limitations", STY["h1"]),
              self.grid(["CONTROL AREA", "WEIGHT", "WHAT IS MEASURED"], [
                  ["Transport Security", "25",
                   "Certificate validity and trust, protocol versions, cipher "
                   "strength, forward secrecy, HSTS quality, HTTPS redirect"],
                  ["Security Headers", "22",
                   "Weighted quality of the eight security headers, graded by value "
                   "rather than by presence"],
                  ["Content & Privacy", "13",
                   "Mixed content, CORS policy, cookie flags, form transport"],
                  ["Email Integrity", "15",
                   "SPF strength, DMARC policy, DKIM, MX, CAA, DNSSEC"],
                  ["Data Exposure", "15",
                   "Verified readable files, directory listing, version and stack "
                   "disclosure"],
                  ["Network Exposure", "10",
                   "Internet-reachable database, remote-access and administrative "
                   "ports"]],
                  [118, 44, self.w - 162]),
              Spacer(1, 8),
              self.box([Paragraph(
                  "Limitations: results reflect one moment in time and only what the "
                  "target exposes to an unauthenticated client. Content behind "
                  "authentication, business logic, client-side script flaws, race "
                  "conditions and server-side injection classes are outside this "
                  "method. A clean score is not a guarantee of security; a low score "
                  "is a reliable signal that hardening is overdue.", STY["small"])]),
              Spacer(1, 8),
              self.box([Paragraph(
                  "<b>Authorisation.</b> This assessment used non-destructive requests "
                  "only, against a target the operator owns or is authorised to test. "
                  "Port probing, path probing and DNS enumeration are active "
                  "techniques: running this tool against third-party systems without "
                  "written permission may be illegal in your jurisdiction.",
                  STY["small"])], bg="#fff7ed", border="#fed7aa")]
        return f

    def build(self):
        story = self.cover() + [PageBreak(),
                                Paragraph("Assessment overview", STY["h1"])]
        story += self.overview() + [PageBreak(),
                                    Paragraph("Detailed findings", STY["h1"])]
        if not self.findings:
            story.append(Paragraph("No issues were detected on the tested surfaces.",
                                   STY["body"]))
        for x in self.findings:
            story += self.finding_block(x)
        story += [PageBreak()] + self.appendix()
        doc = BaseDocTemplate(self.path, pagesize=A4, leftMargin=34, rightMargin=34,
                              topMargin=30, bottomMargin=40,
                              title="Security audit - %s" % self.meta.get("domain", ""),
                              author=TOOL, creator=TOOL,
                              subject="Web security and exposure assessment")
        frame = Frame(34, 40, A4[0] - 68, A4[1] - 70, id="body")
        doc.addPageTemplates([PageTemplate(id="all", frames=[frame],
                                           onPage=self.footer)])
        doc.build(story)
        return self.path

    def footer(self, canv, doc):
        canv.saveState()
        canv.setStrokeColor(hx(LINE))
        canv.setLineWidth(0.5)
        canv.line(34, 32, A4[0] - 34, 32)
        canv.setFont("Helvetica", 6.2)
        canv.setFillColor(hx(FAINT))
        canv.drawString(34, 24, "%s  |  %s  |  %s" % (TOOL,
                                                      self.meta.get("domain", ""),
                                                      self.meta.get("audit_date", "")))
        canv.drawRightString(A4[0] - 34, 24, "Page %d" % canv.getPageNumber())
        canv.restoreState()


# ==========================================================================
#  CLI
# ==========================================================================
def terminal_summary(res, pdf_path):
    m, sc = res["meta"], res["score"]
    total = sc.get("total", 0)
    col = (CLR["grn"] if total >= 80 else CLR["cyn"] if total >= 70 else
           CLR["yel"] if total >= 55 else CLR["red"])
    bar = "=" * 66
    print("\n%s%s%s" % (CLR["cyn"], bar, CLR["r"]))
    print("  %s%s%s" % (CLR["b"], m["domain"], CLR["r"]))
    print("  score    %s%s%d/100  grade %s%s   risk index %.0f"
          % (CLR["b"], col, total, sc.get("grade"), CLR["r"], sc.get("risk", 0)))
    counts = sc.get("counts", {})
    print("  findings " + ", ".join("%s%d %s%s" % (CLR["b"], counts.get(s, 0), s,
                                                   CLR["r"])
                                    for s in SEV_ORDER if counts.get(s)))
    for name, val in sc.get("categories", {}).items():
        print("    %-20s %5.1f" % (name, val))
    print("  surface  %d ports open, %d subdomains, %d exposed files, %d cookies"
          % (len(res.get("open_ports", [])), len(res.get("subdomains", [])),
             len(res.get("exposed", [])), len(res.get("cookies", []))))
    top = [f for f in res.get("findings", [])
           if f["severity"] in ("CRITICAL", "HIGH")][:6]
    if top:
        print("  top risks")
        for f in top:
            print("    %s%-8s%s %-20s %s"
                  % (CLR["red"] if f["severity"] == "CRITICAL" else CLR["yel"],
                     f["severity"], CLR["r"], f["id"], cut(f["title"], 58)))
    if pdf_path:
        print("  report   %s" % pdf_path)
    print("%s%s%s" % (CLR["cyn"], bar, CLR["r"]))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="audit",
                                 description="SiteAuditor - web security and exposure "
                                             "audit")
    ap.add_argument("target", nargs="?", help="domain or URL, e.g. example.com")
    ap.add_argument("--json", metavar="PATH", help="also write raw results as JSON")
    ap.add_argument("--pdf", metavar="PATH", help="write the PDF report to PATH")
    ap.add_argument("--render-json", metavar="PATH",
                    help="render a report from a saved JSON file, no network access")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="per-request timeout in seconds")
    ap.add_argument("--threads", type=int, default=10, help="concurrency")
    ap.add_argument("--no-ports", action="store_true", help="skip the TCP port scan")
    ap.add_argument("--no-subdomains", action="store_true",
                    help="skip subdomain enumeration")
    ap.add_argument("--full-ports", action="store_true",
                    help="scan the extended port list")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="suppress progress output")
    ap.add_argument("--version", action="version",
                    version="%s %s" % (TOOL, VERSION))
    args = ap.parse_args(argv)
    if args.no_color:
        no_color()

    if args.render_json:
        try:
            with open(args.render_json, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            sys.stderr.write("Cannot read %s: %s\n" % (args.render_json, exc))
            return 3
        path = args.pdf or os.path.join(
            out_dir(), "%s_audit.pdf" % data.get("meta", {}).get("domain", "report"))
        Report(data, path).build()
        terminal_summary(data, path)
        return 0

    target = args.target or input("Enter target domain (e.g. example.com): ").strip()
    if not target:
        sys.stderr.write("No target provided.\n")
        return 1
    log = Log(args.quiet)
    auditor = SiteAuditor(target, timeout=args.timeout, threads=args.threads,
                          do_ports=not args.no_ports, do_subs=not args.no_subdomains,
                          full_ports=args.full_ports, log=log)
    res = auditor.run_audit()
    pdf_path = args.pdf or os.path.join(
        out_dir(), "%s_audit_%s.pdf" % (res["meta"]["domain"],
                                        datetime.now().strftime("%Y%m%d_%H%M")))
    try:
        Report(res, pdf_path).build()
    except Exception as exc:
        sys.stderr.write("PDF rendering failed: %s\n" % exc)
        pdf_path = None
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(res, fh, indent=1, ensure_ascii=False)
        except Exception as exc:
            sys.stderr.write("Cannot write %s: %s\n" % (args.json, exc))
    terminal_summary(res, pdf_path)
    return 0 if res["meta"].get("reachable") else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(130)
