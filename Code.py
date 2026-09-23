cat << 'EOF' > audit2.py
#!/usr/bin/env python3
"""
SiteAuditor v3.0 -- single-page web security & exposure audit.

Built for Termux on Android (no root). Every chart is drawn with ReportLab,
so matplotlib/numpy are no longer required and startup is much faster.
"""
import concurrent.futures as cf
import os
import re
import socket
import ssl
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

# ------------------------------------------------------------- deps -------
try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests\n"
             "  Termux:  pip install requests")

try:
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.shapes import String as DStr
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)
except ImportError:
    sys.exit("Missing dependency: reportlab\n"
             "  Termux:  pip install reportlab")

try:
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
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass


def _esc(s):
    """Escape target-controlled strings before feeding ReportLab."""
    if s is None:
        return ''
    return (str(s).replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;'))


def _default_out_dir():
    """Report folder: shared storage only after `termux-setup-storage`."""
    home = os.path.expanduser('~')
    shared = os.path.join(home, 'storage', 'shared')
    if os.path.isdir(shared):
        return os.path.join(shared, 'sitest')
    return os.path.join(home, 'sitest')


# Response headers that matter, weighted by real-world impact.
SECURITY_HEADERS = {
    'Strict-Transport-Security': 12,
    'Content-Security-Policy': 14,
    'X-Frame-Options': 8,
    'X-Content-Type-Options': 6,
    'Referrer-Policy': 6,
    'Permissions-Policy': 5,
    'Cross-Origin-Opener-Policy': 4,
    'Cross-Origin-Resource-Policy': 3,
}
HEADER_MAX = float(sum(SECURITY_HEADERS.values()))
SHORT_HEADER = {
    'Strict-Transport-Security': 'HSTS',
    'Content-Security-Policy': 'CSP',
    'X-Frame-Options': 'X-Frame',
    'X-Content-Type-Options': 'X-CTO',
    'Referrer-Policy': 'Referrer',
    'Permissions-Policy': 'Perms',
    'Cross-Origin-Opener-Policy': 'COOP',
    'Cross-Origin-Resource-Policy': 'CORP',
}

SENSITIVE_PATHS = [
    '/.env', '/.git/HEAD', '/config.json', '/backup.zip',
    '/wp-config.php.bak', '/server-status', '/.aws/credentials',
    '/db.sql', '/dump.sql', '/backup.sql', '/.htaccess',
]

SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging',
    'test', 'portal', 'cpanel', 'webmail', 'vpn', 'remote',
    'git', 'blog',
]

PORTS = [21, 22, 80, 443, 3306, 8080]
PORT_NAMES = {21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS',
              3306: 'MySQL', 8080: 'HTTP-alt'}

UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

SEV_COLOR = {'CRITICAL': '#dc2626', 'HIGH': '#ea580c',
             'MEDIUM': '#d97706', 'LOW': '#0891b2', 'INFO': '#64748b'}
SEV_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


class SiteAuditor:
    def __init__(self, target):
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        self.url = target.rstrip('/')
        self.parsed = urlparse(self.url)
        self.scheme = self.parsed.scheme
        self.domain = (self.parsed.hostname or self.parsed.path).strip()
        self.port = self.parsed.port or (443 if self.scheme == 'https' else 80)
        self.ip = self._resolve_ip()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': UA_POOL[0]})
        # A scanner must still reach hosts with expired or self-signed
        # certificates so it can report on them; chain trust is assessed
        # separately in check_tls(). Verification here would turn such a
        # target into a blank "unreachable" report.
        self.session.verify = False
        self.results = {}

    def _resolve_ip(self):
        try:
            return socket.gethostbyname(self.domain)
        except Exception:
            return "Unknown"

    def _get(self, url, timeout=8, allow_redirects=True, ua=None):
        try:
            return self.session.get(
                url, timeout=timeout, allow_redirects=allow_redirects,
                headers={'User-Agent': ua or UA_POOL[0]})
        except Exception:
            return None

    # ------------------------------------------------------- homepage -----
    def fetch_homepage(self):
        print(f"[+] Fetching {self.url}")
        t0 = time.perf_counter()
        r = self._get(self.url, timeout=12)
        total = round((time.perf_counter() - t0) * 1000, 1)
        if r is None:
            return {'ok': False, 'status': 'Error', 'elapsed_ms': total,
                    'ttfb_ms': None, 'server': 'Unknown', 'sec_headers': {},
                    'html': '', 'size_kb': 0, 'encoding': None,
                    'powered_by': None, 'xss_protection': None,
                    'cf_ray': None, 'set_cookie_raw': []}
        try:
            html = r.text[:300000]
        except Exception:
            html = ''
        return {
            'ok': r.status_code < 400,
            'status': r.status_code,
            'elapsed_ms': total,
            'ttfb_ms': round(r.elapsed.total_seconds() * 1000, 1),
            'server': r.headers.get('Server', 'Hidden'),
            'sec_headers': {k: (k in r.headers) for k in SECURITY_HEADERS},
            'html': html,
            'size_kb': round(len(r.content) / 1024, 1),
            'encoding': r.headers.get('Content-Encoding'),
            'powered_by': r.headers.get('X-Powered-By'),
            'xss_protection': r.headers.get('X-XSS-Protection'),
            'cf_ray': r.headers.get('CF-RAY'),
            'set_cookie_raw': (
                r.raw.headers.getlist('Set-Cookie')
                if hasattr(r.raw.headers, 'getlist') else []
            ),
        }

    # ----------------------------------------------------- sensitive ------
    def check_sensitive_files(self):
        print("[+] Sensitive file probe (baseline + magic-byte verified)")
        ua = UA_POOL[1]
        base_url = self.url + '/' + uuid.uuid4().hex
        base = self._get(base_url, timeout=4, allow_redirects=False, ua=ua)
        base_len = len(base.content) if base else -1
        base_ct = base.headers.get('Content-Type', '') if base else ''
        base_status = base.status_code if base else -1

        def probe(path):
            r = self._get(self.url + path, timeout=4,
                          allow_redirects=False, ua=ua)
            if r is None or r.status_code != 200 or len(r.content) < 10:
                return None
            ct = r.headers.get('Content-Type', '')
            if (base_status == 200 and
                    ct.split(';')[0] == base_ct.split(';')[0] and
                    abs(len(r.content) - base_len) < 300):
                return None
            body = r.text[:800].lower()
            if any(s in body for s in
                   ('not found', '404', 'cannot get', 'page not found')):
                return None
            # Byte-level validation: an HTML / soft-404 page is not a leak.
            signature = self._detect_signature(r.content, path, ct)
            if signature is None:
                return None
            return {
                'path': path,
                'url': self.url + path,
                'size': len(r.content),
                'content_type': ct,
                'signature': signature,
                'sample': self._sanitize_sample(r.content[:512], path),
                'content_length': (r.headers.get('Content-Length')
                                   or str(len(r.content))),
            }

        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            return [x for x in ex.map(probe, SENSITIVE_PATHS) if x]

    # -------------------------------------------------------- evidence ----
    def _detect_signature(self, buf, path, ctype=''):
        """Byte-accurate content ID.

        Magic bytes are checked first; HTML/soft-404 responses return None so
        they can never be reported as a data leak.
        """
        if buf is None or len(buf) < 4:
            return None
        head = buf[:512]
        low = head.lower()

        # 1) magic bytes -- authoritative, before any heuristic.
        if buf[:2] == b'PK':
            return 'ZIP archive (backup bundle)'
        if buf[:3] == b'\x1f\x8b\x08':
            return 'GZIP compressed data'
        if buf[:5] == b'%PDF-':
            return 'PDF document'
        if buf[:4] == b'\x7fELF':
            return 'Linux ELF binary'
        if buf[:2] == b'MZ':
            return 'Windows executable'
        if head.startswith(b'ref:'):
            return 'Git HEAD -- repository exposed'
        if buf[:4] == b'SQL\x00' or buf[:9] == b'-- MySQL ':
            return 'MySQL dump'
        if buf[:5] == b'PGDMP':
            return 'PostgreSQL dump'
        if b'<?php' in head[:200]:
            return 'PHP source code'

        # 2) HTML / soft-404 pages are not leaks -- explicitly excluded.
        if 'text/html' in (ctype or '').lower():
            return None
        if (b'<html' in low or b'<!doctype' in low
                or b'<head' in low or b'<body' in low):
            return None

        # 3) text heuristics, only for payloads that survived the above.
        if buf[:1] in (b'{', b'['):
            return 'JSON data'
        if path.endswith('.env') and re.search(
                rb'(?m)^[A-Za-z0-9_]+=', head):
            return 'Environment / config file'
        if path.endswith(('.sql', '.dump')) and re.search(
                rb'(?im)^(insert into|create table|drop table|-- )', head):
            return 'SQL dump'
        if b'#' in buf[:10] and b'comment' in low[:200]:
            return 'Config file (comment header)'
        return 'Unknown content'

    def _sanitize_sample(self, buf, path):
        if buf is None:
            return ''
        text = buf.decode('utf-8', errors='replace')

        if '.env' in path or (b'=' in buf[:80] and b'\n' in buf[:150]):
            lines = []
            for line in text.split('\n')[:8]:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key = line.split('=', 1)[0].strip()
                    if key and len(key) < 40:
                        lines.append(f"{key}=***")
                if len(lines) >= 4:
                    break
            if lines:
                return ' | '.join(lines)

        if path.endswith('HEAD') and text.startswith('ref:'):
            return text.strip()[:80]

        if path.endswith('.json'):
            keys = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})"\s*:', text)
            if keys:
                return 'Keys: ' + ', '.join(keys[:6])

        for line in text.split('\n'):
            line = line.strip()
            if line and not line.startswith('<!--'):
                return line[:100]
        return text[:80]

    def extract_evidence(self):
        """Build the evidence table from the signatures the probe captured.

        No second fetch: evidence derives from the same bytes that were
        validated, so it can never contradict exposed_files.
        """
        print("[+] Building evidence from probe signatures")
        evidence = []
        for ef in self.results.get('exposed_files', []):
            signature = ef.get('signature')
            if signature is None:
                continue
            evidence.append({
                'url': ef['url'],
                'path': ef['path'],
                'size': ef.get('content_length') or ef.get('size'),
                'signature': signature,
                'sample': ef.get('sample', ''),
                'content_type': ef.get('content_type', '?'),
            })
        return evidence

    # --------------------------------------------------- attack surface ---
    def check_subdomains(self):
        print("[+] Subdomain enumeration")
        found = []

        def check(sub):
            host = f"{sub}.{self.domain}"
            try:
                return (sub, host, socket.gethostbyname(host))
            except Exception:
                return None

        with cf.ThreadPoolExecutor(max_workers=10) as ex:
            for r in ex.map(check, SUBDOMAIN_WORDLIST):
                if r:
                    found.append(r)
        return found

    def extract_robots(self):
        r = self._get(self.url + '/robots.txt', timeout=5)
        if r is None or r.status_code != 200:
            return {'found': False, 'sensitive': []}
        sensitive = []
        keywords = ['admin', 'backup', 'config', 'private', 'internal',
                    'db', 'sql', 'staging', 'dev', 'test', 'api/',
                    'secret', 'key', 'token']
        for line in r.text[:5000].split('\n'):
            line = line.strip()
            if line.lower().startswith(('disallow', 'allow')):
                p = line.split(':', 1)[-1].strip()
                if any(k in p.lower() for k in keywords) and p not in sensitive:
                    sensitive.append(p)
        return {'found': True, 'sensitive': sensitive[:8]}

    def check_sitemap(self):
        r = self._get(self.url + '/sitemap.xml', timeout=6)
        if r is None or r.status_code != 200:
            return {'found': False, 'urls': 0}
        return {'found': True, 'urls': len(re.findall(r'<loc>', r.text[:200000]))}

    def check_security_txt(self):
        for path in ('/.well-known/security.txt', '/security.txt'):
            r = self._get(self.url + path, timeout=5)
            if (r is not None and r.status_code == 200
                    and 'contact' in r.text.lower()[:2000]):
                return {'found': True, 'path': path}
        return {'found': False}

    def check_http_methods(self):
        print("[+] HTTP methods")
        try:
            r = self.session.options(self.url, timeout=6,
                                     allow_redirects=False)
            allow = r.headers.get('Allow', '')
        except Exception:
            allow = ''
        methods = [m.strip().upper() for m in allow.split(',') if m.strip()]
        return {'allow': methods, 'trace': 'TRACE' in methods}

    def check_mixed_content(self):
        if self.scheme != 'https':
            return []
        html = self.results.get('home', {}).get('html', '')
        hits = set()
        for m in re.finditer(r'''(?:src|href)\s*=\s*["']http://([^"'/]+)''',
                            html, re.I):
            host = m.group(1).lower()
            if self.domain not in host:
                hits.add(host)
        return sorted(hits)[:4]

    def extract_emails(self):
        html = self.results.get('home', {}).get('html', '')
        if not html:
            return []
        emails = set(re.findall(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html))
        skip = ['example.com', 'sentry.io', 'wixpress.com', 'schema.org',
                'w3.org', 'google.com', 'gstatic.com', 'googletagmanager']
        return [e for e in emails
                if not any(s in e.lower() for s in skip)][:6]

    def extract_versions(self):
        out = {}
        hs = self.results.get('home', {})
        srv = hs.get('server', '')
        if srv and re.search(r'\d', srv) and srv.lower() not in (
                'hidden', 'unknown'):
            out['Server'] = srv[:40]
        if hs.get('powered_by'):
            out['X-Powered-By'] = hs['powered_by'][:40]
        html = hs.get('html', '')
        for label, pat in (
                ('WordPress', r'<meta name="generator" content="WordPress '
                              r'([\d.]+)"'),
                ('jQuery', r'jquery[/-]([\d.]+)(?:\.min)?\.js'),
                ('Bootstrap', r'bootstrap[/-]v?([\d.]+)')):
            m = re.search(pat, html)
            if m:
                out[label] = m.group(1)
        return out

    # ---------------------------------------------------------- ports -----
    def is_behind_cdn(self, home):
        if home.get('cf_ray'):
            return 'Cloudflare'
        srv = (home.get('server') or '').lower()
        for kw, name in (('cloudflare', 'Cloudflare'),
                         ('cloudfront', 'CloudFront'),
                         ('akamai', 'Akamai'),
                         ('arvan', 'ArvanCloud'),
                         ('sucuri', 'Sucuri'),
                         ('fastly', 'Fastly'),
                         ('ddos-guard', 'DDoS-Guard'),
                         ('gcore', 'Gcore')):
            if kw in srv:
                return name
        return None

    def _probe_port(self, port):
        """TCP connect state: 0 => Open, ECONNREFUSED (111) => Closed,
        anything else (timeout/filtered) => Filtered."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            rc = s.connect_ex((self.ip, port))
            if rc == 0:
                return port, "Open"
            if rc == 111:
                return port, "Closed"
            return port, "Filtered"
        except Exception:
            return port, "Filtered"
        finally:
            s.close()

    def check_ports(self, skip=False):
        if skip:
            print("[+] Port scan skipped (behind CDN)")
            return {}
        print("[+] Port scan (TCP connect state)")
        if self.ip == "Unknown":
            return {}
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            return dict(ex.map(self._probe_port, PORTS))

    # ------------------------------------------------------------ TLS -----
    def _tls_context(self, verify):
        if verify:
            return (ssl.create_default_context(cafile=CAFILE) if CAFILE
                    else ssl.create_default_context())
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _cert_from_dict(self, info, cert):
        try:
            exp = datetime.strptime(cert['notAfter'],
                                    '%b %d %H:%M:%S %Y %Z'
                                    ).replace(tzinfo=timezone.utc)
            info['days_left'] = (exp - datetime.now(timezone.utc)).days
            info['expires'] = exp.strftime('%Y-%m-%d')
        except Exception:
            pass
        try:
            info['issuer'] = dict(x[0] for x in cert['issuer']
                                  ).get('organizationName', '?')
            info['subject'] = dict(x[0] for x in cert['subject']
                                   ).get('commonName', self.domain)
            info['san_count'] = len(cert.get('subjectAltName', []))
        except Exception:
            pass

    def _cert_from_der(self, info, der):
        try:
            c = x509.load_der_x509_certificate(der)
            oid = x509.oid.NameOID
            org = c.issuer.get_attributes_for_oid(oid.ORGANIZATION_NAME)
            cn = c.subject.get_attributes_for_oid(oid.COMMON_NAME)
            info['issuer'] = org[0].value if org else '?'
            info['subject'] = cn[0].value if cn else self.domain
            exp = getattr(c, 'not_valid_after_utc', None)
            if exp is None:
                exp = c.not_valid_after.replace(tzinfo=timezone.utc)
            info['days_left'] = (exp - datetime.now(timezone.utc)).days
            info['expires'] = exp.strftime('%Y-%m-%d')
            try:
                san = c.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value
                info['san_count'] = len(list(san))
            except Exception:
                pass
        except Exception:
            pass

    def check_tls(self):
        if self.scheme != 'https':
            return {'enabled': False}
        info = {'enabled': True, 'verified': False, 'issuer': '?',
                'subject': self.domain, 'days_left': None, 'expires': None,
                'protocol': None, 'cipher': None, 'alpn': None,
                'san_count': None}
        for verify in (True, False):
            try:
                ctx = self._tls_context(verify)
                try:
                    ctx.set_alpn_protocols(['h2', 'http/1.1'])
                except NotImplementedError:
                    pass
                with socket.create_connection((self.domain, self.port),
                                              timeout=8) as sock:
                    with ctx.wrap_socket(sock,
                                         server_hostname=self.domain) as ss:
                        cert = ss.getpeercert()
                        der = ss.getpeercert(binary_form=True)
                        info['protocol'] = ss.version()
                        info['alpn'] = ss.selected_alpn_protocol()
                        cipher = ss.cipher()
                        if cipher:
                            info['cipher'] = '%s (%s-bit)' % (cipher[0],
                                                              cipher[2])
                info['verified'] = bool(cert)
                if cert:
                    self._cert_from_dict(info, cert)
                elif der and HAVE_CRYPTO:
                    self._cert_from_der(info, der)
                return info
            except ssl.SSLCertVerificationError:
                continue
            except Exception as exc:
                info['error'] = str(exc)[:70]
        return info

    # ---------------------------------------------------------- email -----
    def check_email_security(self):
        out = {'spf': None, 'spf_policy': None, 'dmarc': None,
               'dmarc_policy': None, 'mx': None, 'caa': None,
               'dns_available': HAVE_DNS}
        if not HAVE_DNS:
            return out
        try:
            for rec in dns.resolver.resolve(self.domain, 'TXT', lifetime=6):
                t = rec.to_text().strip('"')
                if t.startswith('v=spf1'):
                    out['spf'] = t
                    m = re.search(r'([-~+?])all\b', t)
                    if m:
                        out['spf_policy'] = m.group(1) + 'all'
                    break
        except Exception:
            pass
        try:
            for rec in dns.resolver.resolve('_dmarc.' + self.domain,
                                            'TXT', lifetime=6):
                t = rec.to_text().strip('"')
                if t.startswith('v=DMARC1'):
                    out['dmarc'] = t
                    m = re.search(r'\bp\s*=\s*(none|quarantine|reject)',
                                  t, re.I)
                    if m:
                        out['dmarc_policy'] = m.group(1).lower()
                    break
        except Exception:
            pass
        try:
            out['mx'] = [str(r.exchange).rstrip('.')
                         for r in dns.resolver.resolve(self.domain, 'MX',
                                                       lifetime=6)]
        except Exception:
            pass
        try:
            out['caa'] = [r.to_text()[:70]
                          for r in dns.resolver.resolve(self.domain, 'CAA',
                                                        lifetime=6)]
        except Exception:
            pass
        return out

    def check_https_redirect(self):
        r = self._get('http://' + self.domain, timeout=8,
                      allow_redirects=False)
        if r is None:
            return None
        loc = r.headers.get('Location', '')
        return (r.status_code in (301, 302, 307, 308) and
                loc.lower().startswith('https://'))

    def parse_cookie_flags(self, raw_list):
        out = []
        for raw in raw_list:
            parts = [p.strip() for p in raw.split(';')]
            name = parts[0].split('=', 1)[0]
            rest = ';'.join(parts[1:]).lower()
            out.append({
                'name': name,
                'secure': 'secure' in rest,
                'httponly': 'httponly' in rest,
                'prefixed': name.startswith('__Host-')
                or name.startswith('__Secure-'),
                'samesite': ('none' if 'samesite=none' in rest
                             else 'lax' if 'samesite=lax' in rest
                             else 'strict' if 'samesite=strict' in rest
                             else 'missing'),
            })
        return out

    # -------------------------------------------------------- findings ----
    def build_findings(self):
        r = self.results
        tls = r.get('tls', {})
        em = r.get('email', {})
        home = r.get('home', {})
        out = []

        for ef in r.get('exposed_files', []):
            out.append(('CRITICAL',
                        f"Public {ef['signature']} at {ef['path']}",
                        f"{ef['size']} bytes readable without auth"))
        if '3306' in r.get('open_ports', []):
            out.append(('CRITICAL', 'MySQL port 3306 reachable',
                        'internet-facing database; brute force possible'))
        if '21' in r.get('open_ports', []):
            out.append(('HIGH', 'FTP port 21 open',
                        'plaintext credentials if used'))
        if tls.get('days_left') is not None and tls['days_left'] < 0:
            out.append(('CRITICAL', 'TLS certificate expired',
                        f"{abs(tls['days_left'])} days ago"))
        elif tls.get('days_left') is not None and tls['days_left'] < 15:
            out.append(('HIGH', 'TLS certificate expiring',
                        f"{tls['days_left']} days left"))
        if tls.get('enabled') and tls.get('protocol') in ('TLSv1', 'TLSv1.1',
                                                          'SSLv3'):
            out.append(('HIGH', 'Obsolete TLS version',
                        f"negotiates {tls['protocol']}"))
        if tls.get('error'):
            out.append(('HIGH', 'TLS handshake failed',
                        str(tls['error'])[:70]))
        if em.get('dns_available') and not em.get('dmarc'):
            out.append(('HIGH', 'No DMARC record',
                        'anyone can spoof mail from this domain'))
        elif em.get('dmarc_policy') == 'none':
            out.append(('MEDIUM', 'DMARC policy is p=none',
                        'monitoring only; spoofed mail still delivers'))
        h = home.get('sec_headers', {})
        for key in ('Content-Security-Policy', 'Strict-Transport-Security'):
            if h.get(key) is False:
                out.append(('HIGH', f"Missing {SHORT_HEADER[key]}",
                            'no defence against injection / downgrade'))
        other = [SHORT_HEADER[k] for k in SECURITY_HEADERS
                 if h.get(k) is False and k not in
                 ('Content-Security-Policy', 'Strict-Transport-Security')]
        if other:
            out.append(('MEDIUM', 'Missing security headers',
                        ', '.join(other)))
        if em.get('dns_available') and not em.get('spf'):
            out.append(('MEDIUM', 'No SPF record', 'sender forgery possible'))
        if r.get('https_redirect') is False:
            out.append(('MEDIUM', 'No HTTP-to-HTTPS redirect',
                        'plaintext traffic not upgraded'))
        if r.get('mixed_content'):
            out.append(('MEDIUM', 'Mixed content on HTTPS page',
                        ', '.join(r['mixed_content'][:3])))
        if r.get('methods', {}).get('trace'):
            out.append(('MEDIUM', 'HTTP TRACE enabled',
                        'cross-site tracing / XST risk'))
        for probe in r.get('exposed_ports_extra', []):
            out.append(('MEDIUM', f"Unexpected service on port {probe}",
                        PORT_NAMES.get(probe, 'unknown service')))
        if r.get('versions'):
            out.append(('LOW', 'Software versions disclosed',
                        ', '.join(f"{k} {v}"
                                  for k, v in list(r['versions'].items())[:3])))
        if home.get('sec_headers') and not home.get('encoding'):
            out.append(('LOW', 'No HTTP compression',
                        'reported payload sent uncompressed'))
        if r.get('security_txt', {}).get('found') is False:
            out.append(('LOW', 'No security.txt',
                        'no published vulnerability contact'))
        out.sort(key=lambda f: SEV_RANK.get(f[0], 9))
        return out

    # ----------------------------------------------------------- score ----
    def calculate_score(self):
        r = self.results
        earned = 0.0
        h = r.get('home', {}).get('sec_headers', {})
        got = sum(w for k, w in SECURITY_HEADERS.items() if h.get(k))
        earned += 45.0 * got / HEADER_MAX

        tls = r.get('tls', {})
        if tls.get('enabled') and not tls.get('error'):
            d = tls.get('days_left')
            if d is None:
                earned += 12.0
            elif d < 0:
                earned += 0.0
            elif d < 15:
                earned += 8.0
            else:
                earned += 20.0
        if r.get('https_redirect'):
            earned += 5.0
        em = r.get('email', {})
        if em.get('spf'):
            earned += 5.0
        if em.get('dmarc'):
            earned += 7.0
        if not r.get('exposed_files'):
            earned += 8.0
        if not [p for p in r.get('open_ports', []) if p in ('21', '3306')]:
            earned += 6.0
        if not r.get('mixed_content'):
            earned += 4.0
        return max(0, min(100, int(round(earned))))

    @staticmethod
    def grade(score):
        for cut, g in ((90, 'A'), (80, 'B'), (70, 'C'), (60, 'D'),
                       (50, 'E')):
            if score >= cut:
                return g
        return 'F'

    # ------------------------------------------------------ orchestrate ---
    def run_audit(self):
        self.results['home'] = self.fetch_homepage()
        home = self.results['home']
        cdn = self.is_behind_cdn(home)
        self.results['cdn'] = cdn

        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            jobs = {
                'exposed_files': ex.submit(self.check_sensitive_files),
                'tls': ex.submit(self.check_tls),
                'email': ex.submit(self.check_email_security),
                'https_redirect': ex.submit(self.check_https_redirect),
                'subdomains': ex.submit(self.check_subdomains),
                'robots': ex.submit(self.extract_robots),
                'sitemap': ex.submit(self.check_sitemap),
                'security_txt': ex.submit(self.check_security_txt),
                'methods': ex.submit(self.check_http_methods),
            }
            for key, job in jobs.items():
                self.results[key] = job.result()

        self.results['ports'] = self.check_ports(skip=bool(cdn))
        self.results['open_ports'] = [str(p) for p, s in
                                      self.results['ports'].items()
                                      if s == 'Open']
        self.results['exposed_ports_extra'] = [
            int(p) for p in self.results['open_ports']
            if int(p) not in (80, 443) and int(p) not in (21, 3306)]
        self.results['cookies'] = self.parse_cookie_flags(
            home.get('set_cookie_raw', []))

        self.results['evidence'] = self.extract_evidence()
        self.results['emails'] = self.extract_emails()
        self.results['versions'] = self.extract_versions()
        self.results['mixed_content'] = self.check_mixed_content()

        passed = sum(1 for v in home.get('sec_headers', {}).values() if v)
        total = len(SECURITY_HEADERS)
        self.results.update({
            'domain': self.domain, 'ip': self.ip,
            'passed_headers': passed, 'total_headers': total,
            'audit_date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'tool': 'SiteAuditor v3.0',
        })
        self.results['findings'] = self.build_findings()
        self.results['security_score'] = self.calculate_score()
        self.results['grade'] = self.grade(self.results['security_score'])

    # ----------------------------------------------------- charts ---------
    @staticmethod
    def _bars(rows, width, height, label_w=70, value_w=30):
        """rows: (label, ratio 0..1, colour, value_text)."""
        d = Drawing(width, height)
        n = max(len(rows), 1)
        row_h = height / n
        bar_x = label_w
        bar_w = max(10.0, width - label_w - value_w)
        for i, (label, ratio, col, text) in enumerate(rows):
            y = height - (i + 1) * row_h + row_h * 0.28
            bh = max(4.5, row_h * 0.46)
            c = colors.HexColor(col)
            d.add(DStr(0, y + 1.4, label, fontName='Helvetica', fontSize=6.3,
                       fillColor=colors.HexColor('#334155')))
            d.add(Rect(bar_x, y, bar_w, bh,
                       fillColor=colors.HexColor('#eef2f7'),
                       strokeColor=colors.HexColor('#eef2f7')))
            d.add(Rect(bar_x, y, max(1.5, bar_w * ratio), bh,
                       fillColor=c, strokeColor=c))
            d.add(DStr(bar_x + bar_w + 3, y + 1.4, text,
                       fontName='Helvetica-Bold', fontSize=6.3,
                       fillColor=c))
        return d

    def header_matrix_chart(self, width=300):
        h = self.results['home'].get('sec_headers', {})
        rows = []
        for key in SECURITY_HEADERS:
            ok = bool(h.get(key))
            rows.append((SHORT_HEADER[key], 1.0 if ok else 0.34,
                         '#16a34a' if ok else '#dc2626',
                         'OK' if ok else 'MISS'))
        return self._bars(rows, width, 9.5 * len(rows) + 4)

    def risk_chart(self, width=300):
        f = self.results.get('findings', [])
        weights = {'CRITICAL': 34, 'HIGH': 18, 'MEDIUM': 9, 'LOW': 3}
        # Ordered: first matching group wins, last group is the fallback.
        groups = [
            ('Client-side', ('mixed', 'csp', 'frame', 'security headers',
                             'cookie', 'trace', 'referrer', 'permissions')),
            ('Transport / TLS', ('tls', 'https', 'hsts', 'redirect')),
            ('Email spoofing', ('dmarc', 'spf', 'mail')),
            ('Data exposure', ('leak', 'public', 'json', 'zip', 'git',
                               'config', 'sql', 'dump')),
        ]
        buckets = {name: 0 for name, _ in groups}
        buckets['Infrastructure'] = 0
        for sev, title, _ in f:
            w = weights.get(sev, 1)
            t = title.lower()
            for name, keys in groups:
                if any(k in t for k in keys):
                    buckets[name] += w
                    break
            else:
                buckets['Infrastructure'] += w
        rows = []
        for name in [n for n, _ in groups] + ['Infrastructure']:
            pct = min(buckets.get(name, 0), 100)
            col = ('#dc2626' if pct >= 60 else
                   '#ea580c' if pct >= 35 else
                   '#16a34a' if pct <= 15 else '#d97706')
            rows.append((name, max(pct, 3) / 100.0, col, f"{pct}%"))
        return self._bars(rows, width, 9.5 * len(rows) + 4, label_w=88)

    # ---------------------------------------------------------- PDF -------
    def generate_pdf(self):
        print("[+] Generating single-page PDF report...")
        out_dir = _default_out_dir()
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            out_dir = '.'
        pdf_path = os.path.join(out_dir, f"{self.domain}_audit.pdf")

        r = self.results
        home = r['home']
        tls = r.get('tls', {})
        em = r.get('email', {})
        score = r['security_score']
        grade = r['grade']
        gcol = ('#16a34a' if score >= 80 else
                '#ca8a04' if score >= 60 else '#dc2626')

        styles = getSampleStyleSheet()
        P = lambda n, **kw: ParagraphStyle(n, parent=styles['Normal'], **kw)
        BODY = P('b', fontSize=6.6, leading=7.8,
                 textColor=colors.HexColor('#1f2937'))
        H = P('h', fontSize=8.2, leading=9.6, spaceAfter=2,
              textColor=colors.HexColor('#0f172a'),
              fontName='Helvetica-Bold')
        CELL = P('c', fontSize=6.2, leading=7.2,
                 textColor=colors.HexColor('#1f2937'))
        CELLW = P('cw', fontSize=6.2, leading=7.2, textColor=colors.white,
                  fontName='Helvetica-Bold')
        MONO = P('m', fontSize=5.9, leading=7.0, fontName='Courier',
                 textColor=colors.HexColor('#334155'))
        TITLE = P('t', fontSize=13, leading=14.5, textColor=colors.white,
                  fontName='Helvetica-Bold')
        SUBT = P('s', fontSize=6.8, leading=8.4,
                 textColor=colors.HexColor('#cbd5e1'))

        def grid(head, rows, widths, head_bg='#334155'):
            data = [[Paragraph(str(c), CELLW) for c in head]]
            for row in rows:
                data.append([c if isinstance(c, Paragraph)
                             else Paragraph(str(c), CELL) for c in row])
            t = Table(data, colWidths=widths, hAlign='LEFT')
            st = [('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(head_bg)),
                  ('GRID', (0, 0), (-1, -1), 0.35,
                   colors.HexColor('#cbd5e1')),
                  ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                  ('PADDING', (0, 0), (-1, -1), 1.7),
                  ('LEFTPADDING', (0, 0), (-1, -1), 3)]
            for i in range(1, len(data)):
                if i % 2 == 0:
                    st.append(('BACKGROUND', (0, i), (-1, i),
                               colors.HexColor('#f8fafc')))
            t.setStyle(TableStyle(st))
            return t

        total_w = A4[0] - 2 * 34

        # ---- header band ----
        band = Table([[
            Paragraph("SECURITY AUDIT &amp; VULNERABILITY ASSESSMENT", TITLE),
            Paragraph(
                f"<b>{_esc(self.domain)}</b><br/>"
                f"IP {_esc(self.ip)} &nbsp;|&nbsp; "
                f"{_esc(r['audit_date'])}<br/>"
                f"{_esc(r['tool'])}", SUBT)]],
            colWidths=[total_w * 0.62, total_w * 0.38])
        band.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ]))

        # ---- summary strip ----
        def chip(label, value, col='#0f172a'):
            return Paragraph(
                f"<font size='5.6' color='#64748b'>{label}</font><br/>"
                f"<font size='8.4' color='{col}'><b>{value}</b></font>", CELL)

        tls_txt = ('n/a' if not tls.get('enabled') else
                   'error' if tls.get('error') else
                   'unknown' if tls.get('days_left') is None else
                   f"{tls['days_left']}d")
        summary = Table([[
            chip('GRADE / SCORE', f"{grade} &nbsp;{score}/100", gcol),
            chip('TLS CERTIFICATE', tls_txt,
                 '#16a34a' if (tls.get('days_left') or 0) > 30 else '#dc2626'),
            chip('SECURITY HEADERS',
                 f"{r['passed_headers']}/{r['total_headers']}",
                 '#16a34a' if r['passed_headers'] == r['total_headers']
                 else '#d97706'),
            chip('EXPOSED FILES', str(len(r.get('exposed_files', []))),
                 '#16a34a' if not r.get('exposed_files') else '#dc2626'),
            chip('OPEN PORTS', str(len(r.get('open_ports', []))),
                 '#16a34a' if not r.get('open_ports') else '#d97706'),
            chip('TTFB / SIZE', f"{home.get('ttfb_ms') or 0:.0f}ms / "
                                f"{home.get('size_kb', 0)}kB"),
        ]], colWidths=[total_w / 6.0] * 6)
        summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.4,
             colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))

        # ---- left column ----
        findings = r.get('findings', [])
        left_w = total_w * 0.615 - 6
        f_rows = []
        for sev, title, ev in findings[:8]:
            f_rows.append([
                Paragraph(f"<b>{sev}</b>", ParagraphStyle(
                    'sv', parent=CELL, fontSize=5.8,
                    textColor=colors.HexColor(SEV_COLOR.get(sev, '#334155')),
                    fontName='Helvetica-Bold')),
                Paragraph(_esc(title[:58]), CELL),
                Paragraph(_esc(ev[:44]), CELL)])
        if not f_rows:
            f_rows = [[Paragraph('<b>INFO</b>', CELL),
                       Paragraph('No issues detected on standard surfaces',
                                 CELL), Paragraph('', CELL)]]

        sev_counts = {}
        for sev, _, _ in findings:
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_line = ' &nbsp;'.join(
            f"<font color='{SEV_COLOR[s]}'><b>{sev_counts[s]}</b></font> {s}"
            for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') if sev_counts.get(s))

        left = [
            Paragraph("1 &nbsp;Security Header Matrix", H),
            self.header_matrix_chart(total_w * 0.615 - 6),
            Spacer(1, 5),
            Paragraph(
                "2 &nbsp;Verified Findings "
                + (f"<font size='6' color='#64748b'>({sev_line})</font>"
                   if sev_line else ""), H),
            grid(['SEV', 'FINDING', 'EVIDENCE'], f_rows,
                 [42, left_w * 0.34, left_w - 42 - left_w * 0.34],
                 '#7f1d1d'),
            Spacer(1, 5),
            Paragraph("3 &nbsp;Business Risk Exposure", H),
            self.risk_chart(total_w * 0.615 - 6),
        ]

        # ---- right column ----
        assets = []
        if not tls.get('enabled'):
            assets.append(('SSL / TLS', 'NONE', 'CRITICAL', '#dc2626'))
        elif tls.get('error'):
            assets.append(('SSL / TLS', 'INVALID', 'CRITICAL', '#dc2626'))
        elif (tls.get('days_left') or 0) < 0:
            assets.append(('SSL / TLS', 'EXPIRED', 'CRITICAL', '#dc2626'))
        elif (tls.get('days_left') or 999) < 30:
            assets.append(('SSL / TLS', f"{tls['days_left']}d", 'WARNING',
                           '#d97706'))
        else:
            assets.append(('SSL / TLS', 'VALID', 'OK', '#16a34a'))
        assets.append(('HTTPS redirect',
                       'ON' if r.get('https_redirect') else 'OFF',
                       'OK' if r.get('https_redirect') else 'HIGH',
                       '#16a34a' if r.get('https_redirect') else '#dc2626'))
        if not em.get('dns_available'):
            assets.append(('DMARC', 'n/a', 'UNKNOWN', '#64748b'))
        elif em.get('dmarc'):
            assets.append(('DMARC', str(em.get('dmarc_policy') or 'set'),
                           'OK', '#16a34a'))
        else:
            assets.append(('DMARC', 'MISSING', 'HIGH', '#dc2626'))
        assets.append(('Exposed files',
                       str(len(r.get('exposed_files', []))),
                       'OK' if not r.get('exposed_files') else 'CRITICAL',
                       '#16a34a' if not r.get('exposed_files') else '#dc2626'))
        assets.append(('WAF / CDN', r.get('cdn') or 'NONE',
                       'OK' if r.get('cdn') else 'WARNING',
                       '#16a34a' if r.get('cdn') else '#d97706'))
        assets.append(('security.txt',
                       'present' if r.get('security_txt', {}).get('found')
                       else 'absent',
                       'OK' if r.get('security_txt', {}).get('found')
                       else 'LOW',
                       '#16a34a' if r.get('security_txt', {}).get('found')
                       else '#64748b'))
        a_rows = [[Paragraph(_esc(n), CELL),
                   Paragraph(f"<b>{_esc(str(v))}</b>", CELL),
                   Paragraph(f"<font color='{c}'><b>{_esc(str(sv))}"
                             f"</b></font>", CELL)]
                  for n, v, sv, c in assets]

        port_rows = [[str(p), PORT_NAMES.get(p, '?'), st]
                     for p, st in sorted(r.get('ports', {}).items())]
        if not port_rows:
            port_rows = [['-', 'skipped', 'CDN']]

        cookie_rows = [[_esc(c['name'][:18]),
                        'Y' if c['secure'] else 'N',
                        'Y' if c['httponly'] else 'N',
                        c['samesite'][:6]]
                       for c in r.get('cookies', [])[:4]]
        if not cookie_rows:
            cookie_rows = [['(none set)', '-', '-', '-']]

        robots = r.get('robots', {})
        sitemap = r.get('sitemap', {})
        subs = r.get('subdomains', [])
        surface = [
            ['Subdomains', str(len(subs)) + (
                ' (' + subs[0][1] + ')' if subs else '')],
            ['robots.txt', 'yes' if robots.get('found') else 'no'],
            ['sitemap.xml', (f"{sitemap.get('urls', 0)} urls"
                             if sitemap.get('found') else 'no')],
            ['security.txt', r.get('security_txt', {}).get('path', 'no')
             if r.get('security_txt', {}).get('found') else 'no'],
            ['HTTP methods',
             ', '.join(r.get('methods', {}).get('allow', [])[:4]) or 'n/a'],
            ['Emails in source', ', '.join(r.get('emails', [])[:2]) or 'none'],
        ]

        cert = [
            ['Issuer', str(tls.get('issuer') or '-')[:26]],
            ['Expires', str(tls.get('expires') or '-')],
            ['Protocol',
             f"{tls.get('protocol') or '-'}"
             f"{' / ' + str(tls['alpn']) if tls.get('alpn') else ''}"],
            ['Chain trusted',
             'yes' if tls.get('verified') else 'no (untrusted issuer)'],
            ['Cipher', str(tls.get('cipher') or '-')[:34]],
        ]

        col_w = total_w * 0.385 - 6
        right = [
            Paragraph("4 &nbsp;Asset Status", H),
            grid(['ASSET', 'STATE', 'RISK'], a_rows,
                 [col_w * 0.42, col_w * 0.30, col_w * 0.28], '#334155'),
            Spacer(1, 5),
            Paragraph("5 &nbsp;Certificate &amp; Transport", H),
            grid(['FIELD', 'VALUE'], cert, [col_w * 0.34, col_w * 0.66],
                 '#334155'),
            Spacer(1, 5),
            Paragraph("6 &nbsp;Ports / Cookies", H),
            grid(['PORT', 'SERVICE', 'STATE'], port_rows,
                 [col_w * 0.24, col_w * 0.42, col_w * 0.34], '#334155'),
            Spacer(1, 2),
            grid(['COOKIE', 'SEC', 'HTO', 'SAME'], cookie_rows,
                 [col_w * 0.44, col_w * 0.18, col_w * 0.18, col_w * 0.20],
                 '#334155'),
            Spacer(1, 5),
            Paragraph("7 &nbsp;Attack Surface", H),
            grid(['ITEM', 'VALUE'], [[_esc(a), _esc(b)] for a, b in surface],
                 [col_w * 0.40, col_w * 0.60], '#334155'),
        ]

        body = Table([[left, right]],
                     colWidths=[total_w * 0.615, total_w * 0.385])
        body.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (0, 0), 0),
            ('RIGHTPADDING', (0, 0), (0, 0), 10),
            ('LEFTPADDING', (1, 0), (1, 0), 8),
            ('RIGHTPADDING', (1, 0), (1, 0), 0),
            ('LINEBEFORE', (1, 0), (1, 0), 0.5,
             colors.HexColor('#e2e8f0')),
        ]))

        ev = r.get('evidence', [])
        if ev:
            ev_txt = '<br/>'.join(
                f"&bull; {_esc(i['url'])} &mdash; {_esc(i['signature'])}"
                for i in ev[:3])
        else:
            ev_txt = ('No publicly readable files were confirmed on the '
                      'standard paths tested.')
        foot = Table([[Paragraph(
            f"<b>Self-verification:</b> {ev_txt}", BODY)]],
            colWidths=[total_w])
        foot.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef2f2')
             if ev else colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#fecaca')
             if ev else colors.HexColor('#e2e8f0')),
            ('LEFTPADDING', (0, 0), (-1, -1), 7),
            ('RIGHTPADDING', (0, 0), (-1, -1), 7),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))

        disclaimer = Paragraph(
            "<font size='5.2' color='#94a3b8'>Passive assessment of publicly "
            "observable configuration only; no exploitation was attempted and "
            "no authentication was bypassed. Findings reflect the state at "
            f"scan time. Generated by {_esc(r['tool'])}.</font>", BODY)

        story = [band, Spacer(1, 5), summary, Spacer(1, 7), body,
                 Spacer(1, 6), foot, Spacer(1, 3), disclaimer]

        doc = SimpleDocTemplate(
            pdf_path, pagesize=A4, rightMargin=34, leftMargin=34,
            topMargin=30, bottomMargin=26,
            title=f"Security Audit - {self.domain}",
            author="SiteAuditor v3.0")
        doc.build(story)

        print(f"\n[\u2713] Report saved: {pdf_path}")
        return pdf_path

    def print_terminal_summary(self):
        s = self.results['security_score']
        g = self.results['grade']
        c = CLR
        col = (c['g'] if s >= 80 else c['y'] if s >= 60 else c['red'])
        print(f"\n{c['c']}{'=' * 56}{c['r']}")
        print(f"{c['b']}Audit Summary: {self.domain}{c['r']}")
        print(f"  Score: {col}{c['b']}{s}/100  (grade {g}){c['r']}")
        counts = {}
        for sev, _, _ in self.results.get('findings', []):
            counts[sev] = counts.get(sev, 0) + 1
        print("  Findings: " + (', '.join(
            f"{counts[k]} {k}" for k in
            ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') if counts.get(k)) or 'none'))
        print(f"  Files: {len(self.results['exposed_files'])} | "
              f"Ports: {len(self.results['open_ports'])} | "
              f"Subdomains: {len(self.results.get('subdomains', []))}")
        print(f"{c['c']}{'=' * 56}{c['r']}\n")


CLR = {'r': "\033[0m", 'b': "\033[1m", 'red': "\033[91m",
       'g': "\033[92m", 'y': "\033[93m", 'c': "\033[96m"}


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else \
        input("Enter Target Domain (e.g. example.com): ").strip()
    if not target:
        print("[-] No target provided.")
        sys.exit(1)
    auditor = SiteAuditor(target)
    auditor.run_audit()
    auditor.generate_pdf()
    auditor.print_terminal_summary()
EOF
chmod +x audit2.py

# --- install the `audit` command (Termux / Linux) -------------------------
BINDIR="${PREFIX:-$HOME/.local}/bin"
mkdir -p "$BINDIR" 2>/dev/null
install -m 755 audit2.py "$BINDIR/audit" 2>/dev/null \
    || { cp -f audit2.py "$BINDIR/audit" && chmod 755 "$BINDIR/audit"; }
hash -r 2>/dev/null || true

# --- fail loudly if the paste was truncated ------------------------------
PY="$(command -v python3 || command -v python || true)"
if [ -n "$PY" ] && "$PY" -c \
        "import ast; ast.parse(open('audit2.py', encoding='utf-8').read())"; then
    echo ""
    echo "✓ installed: $BINDIR/audit"
    echo "  run it with:  audit example.com"
    echo "  needs:  pip install reportlab requests dnspython"
    [ -d "$HOME/storage/shared" ] || echo \
        "  tip: run 'termux-setup-storage' once so reports land in shared storage"
else
    echo "✗ paste looks truncated — re-copy the whole block and try again"
fi
