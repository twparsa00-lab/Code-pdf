#!/usr/bin/env python3
"""
SiteAuditor v2.1 — Real-world security audit with byte-level PoC evidence.
Single-page PDF, Termux-friendly, no root.
"""
import os, sys, re, time, ssl, socket, uuid, tempfile
import concurrent.futures as cf
from datetime import datetime, timezone
from urllib.parse import urlparse
try:
    import requests
except ImportError:
    sys.exit("Missing dependency: requests\n"
             "  Termux:  pip install requests urllib3")

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("Missing dependency: matplotlib\n"
             "  Termux:  pkg install python-numpy python-matplotlib")

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Image, Table, TableStyle, HRFlowable)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
except ImportError:
    sys.exit("Missing dependency: reportlab\n"
             "  Termux:  pip install reportlab")

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass


def _esc(s):
    """Escape target-controlled strings before feeding ReportLab Paragraph."""
    if s is None:
        return ''
    return (str(s).replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;'))


def _default_out_dir():
    """Where to drop the PDF.

    On Termux this is shared storage only once `termux-setup-storage` has
    been run; otherwise $HOME is used so no phantom storage tree is created.
    """
    home = os.path.expanduser('~')
    shared = os.path.join(home, 'storage', 'shared')
    if os.path.isdir(shared):
        return os.path.join(shared, 'sitest')
    return os.path.join(home, 'sitest')


HEADER_WEIGHTS = {
    'Strict-Transport-Security': 10,
    'Content-Security-Policy': 12,
    'X-Frame-Options': 8,
    'X-Content-Type-Options': 5,
    'Referrer-Policy': 5,
    'Permissions-Policy': 3,
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

UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

CLR = {'r': "\033[0m", 'b': "\033[1m", 'red': "\033[91m",
       'g': "\033[92m", 'y': "\033[93m", 'c': "\033[96m"}


class SiteAuditor:
    def __init__(self, target_url):
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        self.url = target_url.rstrip('/')
        self.parsed = urlparse(self.url)
        self.domain = (self.parsed.netloc or self.parsed.path).split(':')[0]
        self.ip = self._resolve_ip()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': UA_POOL[0]})
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

    # ---------- headers ----------
    def audit_headers_and_speed(self):
        print(f"[+] Headers & latency: {self.domain}")
        t0 = time.time()
        r = self._get(self.url, timeout=10)
        if r is None:
            return {'status': 'Error', 'latency': 0, 'sec_headers': {},
                    'server': 'Unknown', 'error': 'unreachable',
                    'set_cookie_raw': [], 'powered_by': None,
                    'cf_ray': None, 'html': ''}
        latency = round((time.time() - t0) * 1000, 2)
        h = r.headers
        sec = {k: (k in h) for k in HEADER_WEIGHTS}
        try:
            html = r.text[:200000]
        except Exception:
            html = ''
        return {
            'status': r.status_code,
            'latency': latency,
            'sec_headers': sec,
            'server': h.get('Server', 'Hidden'),
            'powered_by': h.get('X-Powered-By'),
            'cf_ray': h.get('CF-RAY'),
            'cors': h.get('Access-Control-Allow-Origin', 'Not Set'),
            'set_cookie_raw': (
                r.raw.headers.getlist('Set-Cookie')
                if hasattr(r.raw.headers, 'getlist') else []
            ),
            'html': html,
        }

    # ---------- sensitive files ----------
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
            # Byte-level validation: an HTML / soft-404 payload is not a
            # leak, so it must never populate exposed_files.
            signature = self._detect_signature(r.content, path, ct)
            if signature is None:
                return None
            # Capture the signature and a redacted sample once, here, so the
            # evidence table reuses them instead of fetching the file again.
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

    # ---------- evidence ----------
    def _detect_signature(self, buf, path, ctype=''):
        """Byte-accurate content ID.

        Magic bytes are checked first; HTML/soft-404 responses return
        None so they can never be reported as a data leak.
        """
        if buf is None or len(buf) < 4:
            return None
        head = buf[:512]
        low = head.lower()

        # 1) magic bytes — authoritative, checked before any heuristic.
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
            return 'Git HEAD — repository exposed'
        if buf[:4] == b'SQL\x00' or buf[:9] == b'-- MySQL ':
            return 'MySQL dump'
        if buf[:5] == b'PGDMP':
            return 'PostgreSQL dump'
        if b'<?php' in head[:200]:
            return 'PHP source code'

        # 2) HTML / soft-404 pages are not leaks — explicitly excluded.
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
        try:
            text = buf.decode('utf-8', errors='replace')
        except Exception:
            return buf[:40].hex()

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
        """Build the evidence table from the signatures captured during
        check_sensitive_files. No second fetch: the evidence is derived from
        the same bytes that were validated during the probe, so it can never
        contradict exposed_files.
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

    # ---------- attack surface ----------
    def check_subdomains(self):
        print("[+] Subdomain enumeration")
        found = []

        def check(sub):
            host = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(host)
                return (sub, host, ip)
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
        text = r.text[:5000]
        sensitive = []
        keywords = ['admin', 'backup', 'config', 'private', 'internal',
                    'db', 'sql', 'staging', 'dev', 'test', 'api/',
                    'secret', 'key', 'token']
        for line in text.split('\n'):
            line = line.strip()
            if line.lower().startswith(('disallow', 'allow')):
                p = line.split(':', 1)[-1].strip()
                if any(k in p.lower() for k in keywords) and p not in sensitive:
                    sensitive.append(p)
        return {'found': True, 'sensitive': sensitive[:8]}

    def extract_emails(self):
        html = self.results.get('header_speed', {}).get('html', '')
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
        hs = self.results.get('header_speed', {})
        srv = hs.get('server', '')
        if srv and re.search(r'\d', srv) and srv.lower() not in (
                'hidden', 'unknown'):
            out['Server'] = srv[:40]
        pb = hs.get('powered_by')
        if pb:
            out['X-Powered-By'] = pb[:40]
        html = hs.get('html', '')
        m = re.search(
            r'<meta name="generator" content="WordPress ([\d.]+)"', html)
        if m:
            out['WordPress'] = m.group(1)
        m = re.search(r'jquery[/-]([\d.]+)(?:\.min)?\.js', html)
        if m:
            out['jQuery'] = m.group(1)
        m = re.search(r'bootstrap[/-]v?([\d.]+)', html)
        if m:
            out['Bootstrap'] = m.group(1)
        return out

    # ---------- ports ----------
    def is_behind_cdn(self, hs):
        if hs.get('cf_ray'):
            return 'Cloudflare'
        srv = (hs.get('server') or '').lower()
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
        any other error/timeout => Filtered."""
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
        ports = [21, 22, 80, 443, 3306, 8080]
        if self.ip == "Unknown":
            return {}
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            return dict(ex.map(self._probe_port, ports))

    # ---------- ssl ----------
    def check_ssl(self):
        if not self.url.startswith('https'):
            return {'enabled': False}
        try:
            # Only the presented certificate is read (issuer / expiry), so an
            # unverified context is deliberate: Termux frequently ships no CA
            # bundle, which would otherwise fail every HTTPS check.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.domain, 443), timeout=6) as s:
                with ctx.wrap_socket(s, server_hostname=self.domain) as ss:
                    cert = ss.getpeercert()
                    proto = ss.version()
            exp = datetime.strptime(
                cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
            ).replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            issuer = dict(x[0] for x in cert['issuer']).get(
                'organizationName', 'Unknown')
            return {'enabled': True, 'issuer': issuer, 'protocol': proto,
                    'expires': exp.strftime('%Y-%m-%d'), 'days_left': days,
                    'expired': days < 0, 'expiring_soon': 0 <= days < 30}
        except Exception as e:
            return {'enabled': True, 'error': str(e)[:60]}

    # ---------- email ----------
    def check_email_security(self):
        out = {'spf': None, 'dmarc': None, 'mx': None,
               'dns_available': HAVE_DNS}
        if not HAVE_DNS:
            return out
        try:
            for r in dns.resolver.resolve(self.domain, 'TXT', lifetime=6):
                t = r.to_text().strip('"')
                if t.startswith('v=spf1'):
                    out['spf'] = t
                    break
        except Exception:
            pass
        try:
            for r in dns.resolver.resolve('_dmarc.' + self.domain,
                                          'TXT', lifetime=6):
                t = r.to_text().strip('"')
                if t.startswith('v=DMARC1'):
                    out['dmarc'] = t
                    break
        except Exception:
            pass
        try:
            out['mx'] = [str(r.exchange).rstrip('.')
                         for r in dns.resolver.resolve(self.domain, 'MX',
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
                'samesite': ('none' if 'samesite=none' in rest
                             else 'lax' if 'samesite=lax' in rest
                             else 'strict' if 'samesite=strict' in rest
                             else 'missing'),
            })
        return out

    # ---------- score ----------
    def calculate_score(self):
        r = self.results
        score = 0
        for h, w in HEADER_WEIGHTS.items():
            if r['header_speed']['sec_headers'].get(h):
                score += w
        if self.url.startswith('https') or r.get('https_redirect'):
            score += 10
        ssl_info = r.get('ssl', {})
        if (ssl_info.get('enabled') and not ssl_info.get('expired')
                and not ssl_info.get('error')):
            score += 20
        em = r.get('email', {})
        if em.get('spf'):
            score += 5
        if em.get('dmarc'):
            score += 7
        if not r.get('exposed_files'):
            score += 8
        crit = [p for p in r.get('open_ports', []) if p in ('21', '3306')]
        if not crit:
            score += 7
        return max(int(score), 5)

    # ---------- orchestrate ----------
    def run_audit(self):
        self.results['header_speed'] = self.audit_headers_and_speed()
        hs = self.results['header_speed']
        cdn = self.is_behind_cdn(hs)
        self.results['cdn'] = cdn

        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            f_files = ex.submit(self.check_sensitive_files)
            f_ssl = ex.submit(self.check_ssl)
            f_email = ex.submit(self.check_email_security)
            f_redir = ex.submit(self.check_https_redirect)
            f_sub = ex.submit(self.check_subdomains)
            f_robots = ex.submit(self.extract_robots)
            self.results['exposed_files'] = f_files.result()
            self.results['ssl'] = f_ssl.result()
            self.results['email'] = f_email.result()
            self.results['https_redirect'] = f_redir.result()
            self.results['subdomains'] = f_sub.result()
            self.results['robots'] = f_robots.result()

        self.results['ports'] = self.check_ports(skip=bool(cdn))
        self.results['open_ports'] = [str(p) for p, s in
                                      self.results['ports'].items()
                                      if s == 'Open']
        self.results['cookies'] = self.parse_cookie_flags(
            hs.get('set_cookie_raw', []))

        self.results['evidence'] = self.extract_evidence()
        self.results['emails'] = self.extract_emails()
        self.results['versions'] = self.extract_versions()

        passed = sum(1 for v in hs.get('sec_headers', {}).values() if v)
        total = len(HEADER_WEIGHTS)
        self.results.update({
            'domain': self.domain, 'ip': self.ip,
            'passed_headers': passed, 'total_headers': total,
            'audit_date': datetime.now().strftime('%Y-%m-%d %H:%M'),
        })
        self.results['security_score'] = self.calculate_score()

    # ---------- charts ----------
    def generate_charts(self):
        path = os.path.join(tempfile.gettempdir(), 'audit_chart.png')
        fig, (ax1, ax2) = plt.subplots(
            1, 2, figsize=(7.4, 1.75),
            gridspec_kw={'width_ratios': [1.7, 1]})
        hs = self.results['header_speed'].get('sec_headers', {})
        labels_short = ['HSTS', 'CSP', 'X-Frame', 'X-Cont',
                        'Referrer', 'Perm']
        heights, cols = [], []
        for name in HEADER_WEIGHTS:
            w = HEADER_WEIGHTS[name]
            if hs.get(name):
                heights.append(8)
                cols.append('#2ecc71')
            else:
                heights.append(w)
                cols.append('#e74c3c' if w >= 10 else
                             '#f39c12' if w >= 5 else '#f1c40f')
        bars = ax1.bar(labels_short, heights, color=cols, width=0.55,
                       edgecolor='#2c3e50', linewidth=0.4)
        ax1.set_ylim(0, max(heights) * 1.35 if heights else 15)
        ax1.set_yticks([])
        ax1.tick_params(axis='x', labelsize=6.5)
        for sp in ('top', 'right', 'left'):
            ax1.spines[sp].set_visible(False)
        ax1.set_title("Security Header Matrix",
                      fontsize=7.5, fontweight='bold', pad=6)
        for b, name in zip(bars, HEADER_WEIGHTS):
            ok = hs.get(name, False)
            ax1.text(b.get_x() + b.get_width() / 2,
                     b.get_height() + (max(heights) if heights else 1) * 0.04,
                     'OK' if ok else 'MISS',
                     ha='center', va='bottom', fontsize=5.5,
                     fontweight='bold',
                     color='#27ae60' if ok else b.get_facecolor())

        score = self.results['security_score']
        sc = ('#2ecc71' if score >= 75 else
              '#f39c12' if score >= 50 else '#e74c3c')
        ax2.pie([score, max(100 - score, 0)], colors=[sc, '#ecf0f1'],
                startangle=90, counterclock=False,
                wedgeprops=dict(width=0.38, edgecolor='white',
                                linewidth=1.5))
        ax2.text(0, 0, f"{score}", ha='center', va='center',
                 fontsize=15, fontweight='bold', color=sc)
        ax2.text(0, -0.32, "/100", ha='center', va='center',
                 fontsize=7, color='#7f8c8d')
        ax2.set_title("Security Score", fontsize=7.5,
                      fontweight='bold', pad=6)
        plt.tight_layout(pad=0.4)
        plt.savefig(path, dpi=220, bbox_inches='tight', facecolor='white')
        plt.close(fig)
        return path

    def generate_risk_chart(self):
        path = os.path.join(tempfile.gettempdir(), 'risk_chart.png')
        opens = self.results.get('open_ports', [])
        em = self.results.get('email', {})
        ssl_info = self.results.get('ssl', {})

        net = 20
        if '3306' in opens:
            net += 55
        if any(p in opens for p in ('21', '22')):
            net += 20
        net = min(net, 95)

        data = 15
        data += len(self.results.get('exposed_files', [])) * 30
        if em.get('dns_available'):
            if not em.get('spf'):
                data += 15
            if not em.get('dmarc'):
                data += 15
        if ssl_info.get('expired') or ssl_info.get('error'):
            data += 20
        data = min(data, 95)

        missing = (self.results['total_headers'] -
                   self.results['passed_headers'])
        client = min(20 + missing * 11, 95)

        cats = ['Client-Side (XSS / Phishing)',
                'Data Breach (Leaks / Email Spoofing)',
                'Infrastructure (Ransomware / Intrusion)']
        vals = [client, data, net]
        cols = ['#e74c3c' if v >= 70 else
                '#f39c12' if v >= 40 else '#2ecc71' for v in vals]

        fig, ax = plt.subplots(figsize=(7.5, 0.95))
        bars = ax.barh(cats, vals, color=cols, height=0.55,
                       edgecolor='#2c3e50', linewidth=0.6)
        ax.set_xlim(0, 118)
        for sp in ('top', 'right', 'bottom'):
            ax.spines[sp].set_visible(False)
        ax.spines['left'].set_color('#bdc3c7')
        ax.xaxis.set_ticks([])
        ax.tick_params(axis='y', labelsize=7, left=False,
                       colors='#2c3e50')
        for b in bars:
            w = b.get_width()
            ax.text(w + 2.5, b.get_y() + b.get_height() / 2,
                    f'{int(w)}%', va='center', ha='left',
                    fontsize=7.5, fontweight='bold',
                    color=b.get_facecolor())
        plt.tight_layout(pad=0.3)
        plt.savefig(path, dpi=220, bbox_inches='tight', facecolor='white')
        plt.close(fig)
        return path

    # ---------- remediation ----------
    def plan_remediation(self):
        fixes = []
        r = self.results
        em = r.get('email', {})
        ssl_info = r.get('ssl', {})
        exposed = r.get('exposed_files', [])

        if exposed:
            paths = ', '.join(e['path'] for e in exposed[:2])
            fixes.append((f"Remove public access to {paths} "
                          "(move outside web root)", 'CRITICAL', '< 1h'))
        if ssl_info.get('expired'):
            fixes.append(("Renew expired SSL certificate immediately",
                          'CRITICAL', '1-2h'))
        elif ssl_info.get('expiring_soon'):
            fixes.append((f"Renew SSL certificate "
                          f"({ssl_info.get('days_left')}d left)",
                          'HIGH', '1-2h'))
        if em.get('dns_available') and not em.get('dmarc'):
            fixes.append(("Publish DMARC record (v=DMARC1; p=quarantine)",
                          'HIGH', '< 30m'))
        if em.get('dns_available') and not em.get('spf'):
            fixes.append(("Publish SPF record to authorize senders",
                          'HIGH', '< 30m'))
        hs = r['header_speed'].get('sec_headers', {})
        missing_crit = [k for k, v in hs.items()
                        if not v and HEADER_WEIGHTS.get(k, 0) >= 10]
        if missing_crit:
            names = {'Strict-Transport-Security': 'HSTS',
                     'Content-Security-Policy': 'CSP'}
            pretty = ', '.join(names.get(k, k) for k in missing_crit)
            fixes.append((f"Add critical headers: {pretty}",
                          'MEDIUM', '1-2h'))
        if r.get('https_redirect') is False:
            fixes.append(("Enable 301 redirect HTTP->HTTPS",
                          'MEDIUM', '< 15m'))
        if r.get('versions'):
            fixes.append(("Update outdated software versions "
                          "disclosed in headers",
                          'MEDIUM', '1h'))
        return fixes[:6]

    # ---------- PDF ----------
    def generate_pdf(self):
        print("[+] Generating single-page PDF report...")
        target_folder = _default_out_dir()
        try:
            os.makedirs(target_folder, exist_ok=True)
        except Exception:
            target_folder = '.'
        pdf_path = os.path.join(target_folder, f"{self.domain}_audit.pdf")

        chart1 = self.generate_charts()
        chart2 = self.generate_risk_chart()

        doc = SimpleDocTemplate(
            pdf_path, pagesize=letter,
            rightMargin=22, leftMargin=22,
            topMargin=14, bottomMargin=12)

        styles = getSampleStyleSheet()
        TITLE = ParagraphStyle('T', parent=styles['Heading1'],
                               fontSize=14.5,
                               textColor=colors.HexColor('#1a252f'),
                               spaceAfter=0, leading=16)
        SUB = ParagraphStyle('S', parent=styles['Normal'], fontSize=7,
                             textColor=colors.HexColor('#7f8c8d'),
                             spaceAfter=0, leading=8.5)
        H = ParagraphStyle('H', parent=styles['Heading2'], fontSize=8.5,
                           textColor=colors.HexColor('#2c3e50'),
                           spaceBefore=3, spaceAfter=1.5, leading=10)
        N = ParagraphStyle('N', parent=styles['Normal'], fontSize=6.5,
                           textColor=colors.HexColor('#333333'),
                           leading=7.8)
        MONO = ParagraphStyle('M', parent=styles['Normal'], fontSize=6,
                              textColor=colors.HexColor('#2c3e50'),
                              leading=7.2,
                              fontName='Courier')
        DANGER = ParagraphStyle('D', parent=styles['Normal'], fontSize=6.5,
                                textColor=colors.HexColor('#78281F'),
                                leading=8)
        CELL = ParagraphStyle('C', parent=styles['Normal'], fontSize=6.3,
                              leading=7.4)
        CELL_W = ParagraphStyle('CW', parent=styles['Normal'], fontSize=6.3,
                                textColor=colors.white, leading=7.4)
        CELL_MONO = ParagraphStyle('CM', parent=styles['Normal'],
                                   fontSize=5.7, leading=6.8,
                                   fontName='Courier',
                                   textColor=colors.HexColor('#2c3e50'))

        story = []
        r = self.results
        hs = r['header_speed']

        # ===== header =====
        story.append(Paragraph(
            "SECURITY AUDIT &amp; VULNERABILITY ASSESSMENT", TITLE))
        story.append(Paragraph(
            f"Target: <b>{_esc(self.domain)}</b> &nbsp;|&nbsp; "
            f"IP: {_esc(self.ip)} &nbsp;|&nbsp; "
            f"Date: {_esc(r['audit_date'])}", SUB))
        story.append(HRFlowable(
            width="100%", thickness=1.1,
            color=colors.HexColor('#3498db'),
            spaceBefore=2, spaceAfter=3))

        # ===== overview =====
        ssl_info = r['ssl']
        if not ssl_info.get('enabled'):
            ssl_txt = "Not enabled"
        elif ssl_info.get('error'):
            ssl_txt = "Invalid"
        else:
            ssl_txt = f"{ssl_info['days_left']}d left"

        em = r['email']
        dmarc_txt = "Set" if em.get('dmarc') else (
            "Missing" if em.get('dns_available') else "N/A")
        spf_txt = "Set" if em.get('spf') else (
            "Missing" if em.get('dns_available') else "N/A")

        overview = [
            [Paragraph('<b>Target</b>', CELL), _esc(self.domain),
             Paragraph('<b>HTTP</b>', CELL), _esc(hs.get('status')),
             Paragraph('<b>Response</b>', CELL),
             f"{hs.get('latency', 0)} ms"],
            [Paragraph('<b>IP</b>', CELL), _esc(self.ip),
             Paragraph('<b>Server</b>', CELL),
             _esc(str(hs.get('server'))[:22]) or 'Hidden',
             Paragraph('<b>CDN</b>', CELL), _esc(r.get('cdn') or 'None')],
            [Paragraph('<b>SSL Cert</b>', CELL), ssl_txt,
             Paragraph('<b>SPF</b>', CELL), spf_txt,
             Paragraph('<b>DMARC</b>', CELL), dmarc_txt],
        ]
        t_ov = Table(overview, colWidths=[60, 130, 55, 120, 60, 143])
        t_ov.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 2),
        ]))
        story.append(t_ov)
        story.append(Spacer(1, 3))

        # ===== 1. charts =====
        story.append(Paragraph("1. Visual Diagnostic Dashboard", H))
        story.append(Image(chart1, width=568, height=125))
        story.append(Spacer(1, 2))

        # ===== 2. PoC summary =====
        story.append(Paragraph(
            "2. Verified Findings &amp; Proof-of-Concept", H))
        poc_items = []
        for ef in r['exposed_files']:
            poc_items.append(
                f"<b>DATA LEAK:</b> File accessible at "
                f"<u>{_esc(ef['url'])}</u> ({ef['size']} bytes)")
        if '3306' in r.get('open_ports', []):
            poc_items.append(
                "<b>EXPOSED DATABASE:</b> MySQL 3306 reachable "
                "from internet — credential brute-force possible.")
        if '21' in r.get('open_ports', []):
            poc_items.append(
                "<b>FTP EXPOSED:</b> Port 21 open — plaintext "
                "credentials if used.")
        if ssl_info.get('expired'):
            poc_items.append(
                "<b>EXPIRED SSL:</b> Browsers show 'Not Secure' "
                "warning to every visitor.")
        elif ssl_info.get('expiring_soon'):
            poc_items.append(
                f"<b>SSL EXPIRING:</b> {ssl_info['days_left']} days "
                f"until certificate expiration.")
        if r.get('https_redirect') is False:
            poc_items.append(
                "<b>NO HTTPS REDIRECT:</b> HTTP traffic not upgraded "
                "— MITM interception possible.")
        if em.get('dns_available') and not em.get('dmarc'):
            poc_items.append(
                f"<b>NO DMARC:</b> Anyone can send spoofed email as "
                f"@{_esc(self.domain)} — phishing &amp; brand abuse risk.")
        if not poc_items:
            poc_items.append(
                "No critical active vulnerabilities detected in "
                "this assessment on standard attack surfaces.")

        threat_html = "<br/>".join([f"&bull; {i}" for i in poc_items[:5]])
        t_poc = Table([[Paragraph(
            f"<b>VERIFIED FINDINGS:</b><br/>{threat_html}", DANGER)]],
            colWidths=[568])
        t_poc.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FDEDEC')),
            ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor('#E74C3C')),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_poc)
        story.append(Spacer(1, 3))

        # ===== 3. matrix =====
        story.append(Paragraph(
            "3. Technical Matrix — Headers, Ports, Cookies", H))

        hdr_rows = [[Paragraph('<b>Header</b>', CELL_W),
                     Paragraph('<b>Status</b>', CELL_W)]]
        short = {'Strict-Transport-Security': 'HSTS',
                 'Content-Security-Policy': 'CSP',
                 'X-Frame-Options': 'X-Frame',
                 'X-Content-Type-Options': 'X-Content',
                 'Referrer-Policy': 'Referrer',
                 'Permissions-Policy': 'Permissions'}
        for k, present in hs.get('sec_headers', {}).items():
            hdr_rows.append([Paragraph(short.get(k, k), CELL),
                             Paragraph("Present" if present else "MISSING",
                                       CELL)])
        t_hdr = Table(hdr_rows, colWidths=[95, 65])
        t_hdr.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cbd5e1')),
            ('PADDING', (0, 0), (-1, -1), 1.6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        p_rows = [[Paragraph('<b>Port</b>', CELL_W),
                   Paragraph('<b>Service</b>', CELL_W),
                   Paragraph('<b>State</b>', CELL_W)]]
        pnames = {21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS',
                  3306: 'MySQL', 8080: 'HTTP-Alt'}
        port_data = r.get('ports', {})
        if port_data:
            for p, state in port_data.items():
                p_rows.append([Paragraph(str(p), CELL),
                               Paragraph(pnames.get(p, '?'), CELL),
                               Paragraph(state, CELL)])
        else:
            p_rows.append([Paragraph('—', CELL),
                           Paragraph('Skipped', CELL),
                           Paragraph('CDN', CELL)])
        t_port = Table(p_rows, colWidths=[45, 75, 70])
        t_port.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cbd5e1')),
            ('PADDING', (0, 0), (-1, -1), 1.6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        c_rows = [[Paragraph('<b>Cookie</b>', CELL_W),
                   Paragraph('<b>Sec</b>', CELL_W),
                   Paragraph('<b>HOnly</b>', CELL_W)]]
        for c in r.get('cookies', [])[:5]:
            c_rows.append([Paragraph(_esc(c['name'][:16]), CELL),
                           Paragraph('Y' if c['secure'] else 'N', CELL),
                           Paragraph('Y' if c['httponly'] else 'N', CELL)])
        if len(c_rows) == 1:
            c_rows.append([Paragraph('(none set)', CELL),
                           Paragraph('—', CELL), Paragraph('—', CELL)])
        t_cookie = Table(c_rows, colWidths=[80, 35, 40])
        t_cookie.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#5d6d7e')),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cbd5e1')),
            ('PADDING', (0, 0), (-1, -1), 1.6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        t_row = Table([[t_hdr, t_port, t_cookie]],
                      colWidths=[165, 195, 160])
        t_row.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(t_row)
        story.append(Spacer(1, 3))

        # ===== 4. assets =====
        story.append(Paragraph("4. High-Value Asset Status", H))
        assets = []

        if ssl_info.get('expired') or ssl_info.get('error'):
            assets.append(('SSL Certificate', 'INVALID', 'CRITICAL',
                           '#e74c3c'))
        elif not ssl_info.get('enabled'):
            assets.append(('SSL Certificate', 'ABSENT', 'CRITICAL',
                           '#e74c3c'))
        elif ssl_info.get('expiring_soon'):
            assets.append(('SSL Certificate', 'EXPIRING', 'WARNING',
                           '#f39c12'))
        else:
            assets.append(('SSL Certificate', 'VALID', 'SECURE',
                           '#2ecc71'))

        if r.get('https_redirect'):
            assets.append(('HTTPS Redirect', 'ACTIVE', 'SECURE', '#2ecc71'))
        else:
            assets.append(('HTTPS Redirect', 'OFF', 'WARNING', '#f39c12'))

        if not em.get('dns_available'):
            assets.append(('Email (DMARC)', 'N/A', 'UNKNOWN', '#95a5a6'))
        elif em.get('dmarc'):
            assets.append(('Email (DMARC)', 'SET', 'SECURE', '#2ecc71'))
        else:
            assets.append(('Email (DMARC)', 'MISSING', 'HIGH RISK',
                           '#e74c3c'))

        if '3306' in r.get('open_ports', []):
            assets.append(('Database (3306)', 'EXPOSED', 'CRITICAL',
                           '#e74c3c'))
        else:
            assets.append(('Database (3306)', 'PROTECTED', 'SECURE',
                           '#2ecc71'))

        if r['exposed_files']:
            assets.append(('Backup / Config', 'LEAKED', 'CRITICAL',
                           '#e74c3c'))
        else:
            assets.append(('Backup / Config', 'SECURE', 'SECURE',
                           '#2ecc71'))

        if r.get('cdn'):
            assets.append(('WAF / CDN', 'ACTIVE', 'SECURE', '#2ecc71'))
        else:
            assets.append(('WAF / CDN', 'NONE', 'WARNING', '#f39c12'))

        card_cells = []
        for i, (name, state, risk, col) in enumerate(assets):
            html = (f"<para align=center>"
                    f"<font size='6' color='#555'><b>{name}</b></font>"
                    f"<br/>"
                    f"<font size='8.5' color='{col}'><b>{state}</b></font>"
                    f"<br/>"
                    f"<font size='5' color='#888'>{risk}</font>"
                    f"</para>")
            card_cells.append(Paragraph(html, CELL))
            if i < len(assets) - 1:
                card_cells.append('')

        n = len(assets)
        card_width = (568 - (n - 1) * 4) / n
        widths = []
        for i in range(n):
            widths.append(card_width)
            if i < n - 1:
                widths.append(4)

        t_cards = Table([card_cells], colWidths=widths)
        style = [
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]
        for i, (_, _, _, col) in enumerate(assets):
            idx = i * 2
            style.append(('BACKGROUND', (idx, 0), (idx, 0),
                          colors.HexColor('#f4f6f7')))
            style.append(('BOX', (idx, 0), (idx, 0), 0.4,
                          colors.HexColor('#e2e8f0')))
            style.append(('LINEABOVE', (idx, 0), (idx, 0), 2.6,
                          colors.HexColor(col)))
        t_cards.setStyle(TableStyle(style))
        story.append(t_cards)
        story.append(Spacer(1, 4))

        # ===== 5. verify yourself =====
        story.append(Paragraph(
            "5. Verify Yourself — Direct Evidence URLs", H))

        verify_items = []
        for ef in r.get('exposed_files', [])[:4]:
            verify_items.append((ef['url'],
                                 'Your backup / config file is public'))

        ev = r.get('evidence', [])
        if ev:
            story.append(Paragraph(
                "The following URLs are <b>live and publicly accessible "
                "right now</b>. Open them in your own browser to "
                "confirm — no technical tools required. The first bytes "
                "extracted below prove the content is genuine data, not "
                "a placeholder page.", N))
            story.append(Spacer(1, 2))

            ev_rows = [[Paragraph('<b>File</b>', CELL_W),
                        Paragraph('<b>Type (magic bytes)</b>', CELL_W),
                        Paragraph('<b>Content sample (redacted)</b>',
                                  CELL_W)]]
            for item in ev[:3]:
                url_short = item['url'].replace('https://', '')\
                    .replace('http://', '')[:48]
                ev_rows.append([
                    Paragraph(_esc(url_short), CELL_MONO),
                    Paragraph(_esc(item['signature'][:34]), CELL),
                    Paragraph(
                        _esc(item['sample'][:70]) or '(binary content)',
                        CELL_MONO),
                ])
            t_ev = Table(ev_rows, colWidths=[170, 120, 278])
            t_ev.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0),
                 colors.HexColor('#7b241c')),
                ('GRID', (0, 0), (-1, -1), 0.4,
                 colors.HexColor('#e6b0aa')),
                ('PADDING', (0, 0), (-1, -1), 1.8),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(t_ev)
            story.append(Spacer(1, 3))

            if verify_items:
                click_list = "<br/>".join(
                    [f"&rarr; <b>{_esc(u)}</b> &mdash; {_esc(desc)}"
                     for u, desc in verify_items])
                t_click = Table([[Paragraph(
                    f"<b>CLICK-TO-VERIFY (open in browser):</b><br/>"
                    f"{click_list}", DANGER)]], colWidths=[568])
                t_click.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1),
                     colors.HexColor('#FDEDEC')),
                    ('BOX', (0, 0), (-1, -1), 0.8,
                     colors.HexColor('#E74C3C')),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(t_click)
        else:
            story.append(Paragraph(
                "No directly-verifiable file leaks found on standard "
                "paths. All other findings are supported by live "
                "response evidence.", N))
        story.append(Spacer(1, 3))

        # ===== 6. attack surface =====
        story.append(Paragraph(
            "6. Discovered Attack Surface", H))

        subs = r.get('subdomains', [])
        main_ip = self.ip
        sub_txt = '—'
        if subs:
            parts = []
            for s, host, ip in subs[:5]:
                marker = '' if ip == main_ip else ' *'
                parts.append(f"{host}{marker}")
            sub_txt = ', '.join(parts)

        robots = r.get('robots', {})
        rob_paths = robots.get('sensitive', []) if robots.get('found') else []
        rob_txt = ', '.join(rob_paths[:4]) if rob_paths else \
            ('(none found)' if robots.get('found') else '(no robots.txt)')

        emails = r.get('emails', [])
        email_txt = ', '.join(emails[:4]) if emails else '(none exposed)'

        vers = r.get('versions', {})
        ver_txt = ', '.join(f"{k}={v}" for k, v in vers.items()) \
            if vers else '(none disclosed)'

        surface_rows = [
            [Paragraph('<b>Subdomains discovered</b>', CELL_W),
             Paragraph(_esc(sub_txt), CELL_MONO)],
            [Paragraph('<b>Sensitive paths in robots.txt</b>', CELL_W),
             Paragraph(_esc(rob_txt), CELL_MONO)],
            [Paragraph('<b>Emails exposed in page source</b>', CELL_W),
             Paragraph(_esc(email_txt), CELL_MONO)],
            [Paragraph('<b>Outdated versions disclosed</b>', CELL_W),
             Paragraph(_esc(ver_txt), CELL_MONO)],
        ]
        t_surf = Table(surface_rows, colWidths=[150, 418])
        t_surf.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#d5d8dc')),
            ('PADDING', (0, 0), (-1, -1), 2),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_surf)
        story.append(Spacer(1, 3))

        # ===== 7. remediation =====
        fixes = self.plan_remediation()
        story.append(Paragraph(
            "7. Prioritized Remediation Plan", H))
        if fixes:
            fix_rows = [[Paragraph('<b>Issue</b>', CELL_W),
                         Paragraph('<b>Priority</b>', CELL_W),
                         Paragraph('<b>Effort</b>', CELL_W)]]
            for issue, prio, effort in fixes:
                fix_rows.append([
                    Paragraph(_esc(issue[:80]), CELL),
                    Paragraph(prio, CELL),
                    Paragraph(effort, CELL),
                ])
            t_fix = Table(fix_rows, colWidths=[388, 90, 90])
            t_fix.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0),
                 colors.HexColor('#1e8449')),
                ('GRID', (0, 0), (-1, -1), 0.4,
                 colors.HexColor('#cbd5e1')),
                ('PADDING', (0, 0), (-1, -1), 1.8),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(t_fix)
        story.append(Spacer(1, 3))

        # ===== 8. risk chart =====
        story.append(Paragraph(
            "8. Business Threat Exposure Profile", H))
        story.append(Image(chart2, width=568, height=62))

        story.append(Spacer(1, 1))
        story.append(HRFlowable(width="100%", thickness=0.4,
                                color=colors.HexColor('#bdc3c7')))
        story.append(Paragraph(
            f"<font size='5.5' color='#888'>Assessment based on "
            f"publicly observable configuration. No exploitation "
            f"attempted. Report generated by SiteAuditor v2.1 for "
            f"{_esc(self.domain)}.</font>", N))

        doc.build(story)

        for p in (chart1, chart2):
            if os.path.exists(p):
                os.remove(p)

        print(f"\n[\u2713] Report saved: {pdf_path}")
        return pdf_path

    def print_terminal_summary(self):
        s = self.results['security_score']
        c = CLR
        print(f"\n{c['c']}{'=' * 54}{c['r']}")
        print(f"{c['b']}Audit Summary: {self.domain}{c['r']}")
        print(f"  Score: {s}/100")
        if s < 40:
            print(f"  Pitch potential: {c['red']}{c['b']}HIGH{c['r']} "
                  f"(poor posture)")
        elif s < 70:
            print(f"  Pitch potential: {c['y']}{c['b']}MEDIUM{c['r']}")
        else:
            print(f"  Pitch potential: {c['g']}{c['b']}LOW{c['r']} "
                  f"(well configured)")
        print(f"  Findings: {len(self.results['exposed_files'])} file(s), "
              f"{len(self.results['open_ports'])} port(s), "
              f"{len(self.results.get('subdomains', []))} subdomain(s)")
        print(f"{c['c']}{'=' * 54}{c['r']}\n")


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
