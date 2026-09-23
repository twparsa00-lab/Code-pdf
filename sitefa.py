#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Persian (Farsi) RTL renderer for SiteAuditor v4.0.

ReportLab ships no Arabic-script font and performs neither contextual shaping
nor bidirectional reordering, so a readable Persian page needs three extra
steps, all implemented here:

  1. a TTF covering Arabic presentation forms - discovered on the system
     (Android ships Noto Naskh Arabic in /system/fonts), in the usual user
     font directories, or downloaded once to ~/.sitest/fonts;
  2. arabic_reshaper + python-bidi to convert logical Persian into the
     connected, visually ordered glyphs a PDF expects;
  3. line breaking done in LOGICAL order *before* reordering, because a fully
     reordered string handed to Paragraph would be wrapped back to front and
     the last sentence would land on the first line.

Every Persian string therefore goes through fp(): escape -> shape -> reorder,
wrapped per line, right aligned, right column last. Code snippets, header
names, DNS record names and RFC references stay Latin/LTR on purpose - they
are meant to be pasted into a server config exactly as they are.

Dependencies: arabic-reshaper, python-bidi (installed by Code.py).
"""
import os
import re

from reportlab.graphics.shapes import Circle, Drawing, Rect, Wedge
from reportlab.graphics.shapes import String as DStr
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table,
                                TableStyle, XPreformatted)

from audit2 import (ACCENT, BG, FAINT, HEADERS, INK, LINE, MUTED, NAVY, PATHS,
                    PNAME, RISK_PORTS, SEV_COLOR, SEV_ORDER, SLATE, TRACK,
                    WHITE, cut, esc, score_color, hx)

FA_REG = "SiteFA"
FA_BOLD = "SiteFAB"
_ZWNJ = "\u200c"

_RESHAPE = None
_GET_DISPLAY = None
_ZWNJ_MISSING = False
_REASON = ""
_FONT_PATHS = None

# Preference order: a purpose-built Persian face first, then whatever the
# device ships with. Every candidate is verified against the shaped probe.
_PREF = ["vazirmatn", "iransans", "iranl", "naskharabic", "naskh",
         "sansarabic", "droidnaskh", "dejavusans", "droidsansfallback",
         "notosansarabic"]
_DIRS = ["~/.sitest/fonts", "~/.fonts", "~/.local/share/fonts",
         "$PREFIX/share/fonts", "$PREFIX/share/fonts/TTF", "/system/fonts",
         "/system/font", "/usr/local/share/fonts", "/usr/share/fonts",
         "/usr/share/fonts/truetype", "/usr/share/fonts/TTF"]
_DL = {"SiteFA-Regular.ttf":
       "https://raw.githubusercontent.com/rastikerdar/vazirmatn/master/"
       "fonts/ttf/Vazirmatn-Regular.ttf",
       "SiteFA-Bold.ttf":
       "https://raw.githubusercontent.com/rastikerdar/vazirmatn/master/"
       "fonts/ttf/Vazirmatn-Bold.ttf"}


# --------------------------------------------------------------------- fonts
def _probe_chars():
    """Every codepoint a Persian report can put on a page, after shaping."""
    sample = ("امنیت وب حرفه‌ای می‌شود گزارش نفوذ پورت یافته راه‌حل تأثیر شاهد "
              "۰۱۲۳۴۵۶۷۸۹ 0123456789 ABC xyz «».,-/()‌")
    shaped = sample
    if _RESHAPE is not None:
        try:
            shaped = _GET_DISPLAY(_RESHAPE(sample))
        except Exception:
            shaped = sample
    return set(sample) | set(shaped)


def _covers(path, need):
    """True when the font maps every required codepoint.

    charToGlyph is keyed by integer codepoints while the probe is a set of
    characters, so the comparison has to go through ord().
    """
    name = "_probe_%d" % (abs(hash(path)) & 0xFFFFFF)
    try:
        f = TTFont(name, path)
        pdfmetrics.registerFont(f)
        have = set(f.face.charToGlyph)
        for c in need:
            cp = ord(c) if isinstance(c, str) else int(c)
            if cp not in have:
                return False
        return True
    except Exception:
        return False


def _rank(path):
    low = os.path.basename(path).lower()
    for i, key in enumerate(_PREF):
        if key in low.replace("-", "").replace("_", "").replace(" ", ""):
            return i
    return len(_PREF) + 1


def _family(path):
    """Font family key so the Regular and Bold of one design pair up."""
    base = os.path.basename(path).lower()
    for ext in (".ttf", ".otf"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    for token in ("regular", "bold", "-regular", "-bold", "_regular", "_bold",
                  "regular-", "bold-", "-"):
        base = base.replace(token, "")
    return base


def _candidates():
    out, seen = [], set()
    for raw in _DIRS:
        d = os.path.expandvars(os.path.expanduser(raw))
        if not os.path.isdir(d):
            continue
        for root, _dirs, files in os.walk(d):
            for fn in files:
                if not fn.lower().endswith((".ttf", ".otf")):
                    continue
                p = os.path.join(root, fn)
                if p not in seen:
                    seen.add(p)
                    out.append(p)
            if len(out) > 400:
                break
    out.sort(key=_rank)
    return out


def _download():
    try:
        import urllib.request
    except Exception:
        return
    dest = os.path.expanduser("~/.sitest/fonts")
    try:
        os.makedirs(dest, exist_ok=True)
    except Exception:
        return
    for fn, url in _DL.items():
        path = os.path.join(dest, fn)
        if os.path.exists(path):
            continue
        try:
            with urllib.request.urlopen(url, timeout=25) as resp:
                blob = resp.read()
            if len(blob) > 20000:
                with open(path, "wb") as fh:
                    fh.write(blob)
        except Exception:
            pass


def _load_shaper():
    global _RESHAPE, _GET_DISPLAY, _REASON
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
    except ImportError:
        _REASON = "missing packages: pip install arabic-reshaper python-bidi"
        return False
    _RESHAPE = arabic_reshaper.reshape
    _GET_DISPLAY = get_display
    return True


def ensure_fa():
    """Discover a Persian font and load the shaper. Returns (ok, detail)."""
    global _FONT_PATHS, _ZWNJ_MISSING, _REASON
    if _FONT_PATHS is not None:
        return bool(_FONT_PATHS[0]), _REASON
    if not _load_shaper():
        _FONT_PATHS = (None, None)
        return False, _REASON

    need = _probe_chars()
    need_no_zwnj = set(c for c in need if c != _ZWNJ)
    reg = bold = None

    forced = os.environ.get("SITEST_FA_FONT")
    if forced and os.path.exists(forced) and _covers(forced, need):
        reg = bold = forced
    if reg is None:
        paths = _candidates()
        if not paths:
            _download()
            paths = _candidates()
        for p in paths:
            if _covers(p, need):
                reg = p
                break
        if reg is None:
            for p in paths:
                if _covers(p, need_no_zwnj):
                    reg = p
                    break
        if reg is not None:
            fam = _family(reg)
            for q in paths:
                if q != reg and _family(q) == fam and \
                        "bold" in os.path.basename(q).lower():
                    bold = q
                    break
    if reg is None:
        _FONT_PATHS = (None, None)
        _REASON = ("no Persian font found (tried /system/fonts, ~/.fonts, "
                   "~/.sitest/fonts). Copy any Arabic-capable TTF such as "
                   "Vazirmatn-Regular.ttf into ~/.sitest/fonts/ or set "
                   "SITEST_FA_FONT=/path/to/font.ttf")
        return False, _REASON

    _ZWNJ_MISSING = not _covers(reg, {_ZWNJ})
    try:
        pdfmetrics.registerFont(TTFont(FA_REG, reg))
        pdfmetrics.registerFont(TTFont(FA_BOLD, bold or reg))
        pdfmetrics.registerFontFamily(FA_REG, normal=FA_REG, bold=FA_BOLD,
                                      italic=FA_REG, boldItalic=FA_BOLD)
    except Exception as exc:
        _FONT_PATHS = (None, None)
        _REASON = "cannot register font %s: %s" % (reg, exc)
        return False, _REASON
    _FONT_PATHS = (reg, bold or reg)
    _REASON = os.path.basename(reg)
    return True, _REASON


# ------------------------------------------------------------------ shaping
def fs(text):
    """Escape -> shape -> reorder one single-line run of Persian text."""
    if text is None:
        return ""
    t = esc(text)
    if _RESHAPE is not None:
        try:
            t = _GET_DISPLAY(_RESHAPE(t))
        except Exception:
            pass
    if _ZWNJ_MISSING:
        t = t.replace(_ZWNJ, "")
    return t


def fwrap(text, width, font, size):
    """Greedy wrap in LOGICAL order - the whole reason RTL wrapping works."""
    words = str(text if text is not None else "").split()
    lines, cur = [], ""
    for w in words:
        trial = w if not cur else cur + " " + w
        if cur and pdfmetrics.stringWidth(trial, font, size) > width:
            lines.append(cur)
            cur = w
        else:
            cur = trial
    if cur:
        lines.append(cur)
    return lines or [""]


def fp(text, style, width, bold=False):
    """Right-aligned Persian paragraph, pre-wrapped so lines stay in order."""
    font = FA_BOLD if bold else FA_REG
    lines = fwrap(text, max(24.0, width), font, style.fontSize)
    body = "<br/>".join(fs(line) for line in lines)
    if bold:
        body = "<b>%s</b>" % body
    return Paragraph(body, style)


def fstyles():
    base = getSampleStyleSheet()

    def P(n, **kw):
        kw.setdefault("fontName", FA_REG)
        return ParagraphStyle("fa_" + n, parent=base["Normal"], **kw)

    return {
        "h1": P("h1", fontName=FA_BOLD, fontSize=14.5, leading=22,
                textColor=hx(INK), alignment=TA_RIGHT),
        "h2": P("h2", fontName=FA_BOLD, fontSize=11, leading=18,
                textColor=hx(INK), spaceBefore=9, spaceAfter=4,
                alignment=TA_RIGHT),
        "body": P("body", fontSize=8.6, leading=15, textColor=hx(INK),
                  alignment=TA_RIGHT),
        "small": P("small", fontSize=7.4, leading=13, textColor=hx(MUTED),
                   alignment=TA_RIGHT),
        "tiny": P("tiny", fontSize=6.6, leading=11, textColor=hx(FAINT),
                  alignment=TA_RIGHT),
        "cell": P("cell", fontSize=7.5, leading=12.6, textColor=hx(INK),
                  alignment=TA_RIGHT),
        "cellb": P("cellb", fontName=FA_BOLD, fontSize=7.5, leading=12.6,
                   textColor=hx(WHITE), alignment=TA_RIGHT),
        "mono": P("mono", fontName="Courier", fontSize=6.9, leading=8.8,
                  textColor=hx("#e2e8f0"))}


# -------------------------------------------------------------- translations
SEV_FA = {"CRITICAL": "بحرانی", "HIGH": "بالا", "MEDIUM": "متوسط",
          "LOW": "پایین", "INFO": "اطلاعاتی", "OK": "مطلوب"}

CAT_FA = {"Transport Security": "امنیت انتقال",
          "Security Headers": "هدرهای امنیتی",
          "Content & Privacy": "محتوا و حریم خصوصی",
          "Email Integrity": "یکپارچگی ایمیل",
          "Data Exposure": "افشای داده",
          "Network Exposure": "مواجهه شبکه",
          "Meta": "متا"}

# Persian "why it matters" for each security header.
HDR_WHY = {
    "HSTS": "HSTS یک سال HTTPS را اجباری می‌کند و حملهٔ SSL-strip را خنثی می‌سازد.",
    "CSP": "CSP اصلی‌ترین کنترل مرورگر در برابر XSS و قاب‌گذاری مخرب است.",
    "XFO": "X-Frame-Options از کلیک‌دادن جعلی (clickjacking) جلوگیری می‌کند.",
    "XCTO": "nosniff جلوی تفسیر اشتباه فایل آپلودی به‌عنوان اسکریپت را می‌گیرد.",
    "REF": "Referrer-Policy مسیر و پارامترهای URL را از لاگ دیگران دور نگه می‌دارد.",
    "PERM": "Permissions-Policy دسترسی دوربین، میکروفن و موقعیت را برای محتوای دیگر می‌بندد.",
    "COOP": "COOP زمینهٔ مرورگر را در برابر حملات بین پنجره‌ای جدا می‌کند.",
    "CORP": "CORP از جاسازی پاسخ‌های شما توسط دامنه‌های دیگر جلوگیری می‌کند."}

HDR_NAME_FA = {"HSTS": "HSTS", "CSP": "CSP", "XFO": "X-Frame-Options",
               "XCTO": "X-Content-Type-Options", "REF": "Referrer-Policy",
               "PERM": "Permissions-Policy",
               "COOP": "Cross-Origin-Opener-Policy",
               "CORP": "Cross-Origin-Resource-Policy"}

UI = {
    "banner": "گزارش امنیت وب",
    "ch_grade": "گرید / نمره",
    "ch_find": "یافته‌ها",
    "ch_risk": "شاخص ریسک",
    "ch_tls": "گواهی TLS",
    "ch_hdr": "هدرهای امنیتی",
    "ch_mail": "وضعیت ایمیل",
    "ch_exp": "فایل‌های افشا شده",
    "ch_ports": "پورت‌های باز",
    "ch_cdn": "WAF / CDN",
    "gauge_of": "از 100",
    "gauge_grade": "گرید",
    "lab_gauge": "نمره کل ریسک",
    "lab_strip": "یافته‌ها بر اساس شدت",
    "exec": "خلاصهٔ مدیریتی",
    "scope": "دامنه و روش ارزیابی",
    "f_target": "آدرس هدف",
    "f_ip": "آدرس حل‌شده",
    "f_scheme": "پروتکل و پورت",
    "f_window": "بازهٔ ارزیابی",
    "f_tests": "آزمون‌های اجرا شده",
    "f_sources": "منابع داده",
    "f_modules": "ماژول‌های اختیاری",
    "tests": ("درجه‌بندی هدرها بر اساس مقدار؛ دست‌دادن TLS، ماتریس نسخه‌ها و "
              "بازرسی گواهی؛ DNS و SPF/DMARC/DKIM/CAA/DNSSEC؛ %d مسیر حساس با "
              "تأیید بایت‌به‌بایت؛ فهرست‌کاری دایرکتوری؛ CORS؛ پرچم‌های کوکی؛ "
              "زنجیرهٔ ریدایرکت؛ متدهای HTTP؛ اثرانگشت فناوری؛ وضعیت %d پورت "
              "TCP؛ رزولوشن ساب‌دامین"),
    "sources": ("فقط پاسخ‌های عمومی، رکوردهای DNS و فرادادهٔ TLS. بدون احراز "
                "هویت، بدون payload و بدون بهره‌برداری."),
    "cover_note": ("این یافته‌ها پیکربندی قابل مشاهده در لحظهٔ اسکن را توصیف "
                   "می‌کنند. این آزمون نفوذ نیست: هیچ آسیب‌پذیری بهره‌برداری "
                   "نشده و هیچ احراز هویتی دور زده نشده است. هر مورد را پیش از "
                   "برنامه‌ریزی رفع، در بافت خودش راستی‌آزمایی کنید."),
    "h_overview": "نمای کلی ارزیابی",
    "h_breakdown": "ترکیب نمره بر اساس حوزهٔ کنترل",
    "h_matrix": "ماتریس هدرهای امنیتی",
    "h_index": "فهرست یافته‌ها",
    "h_findings": "یافته‌های تفصیلی",
    "no_findings": "در سطوح آزمایش‌شده مشکلی شناسایی نشد.",
    "col_value": "مقدار",
    "col_field": "فیلد",
    "col_sev": "شدت",
    "col_id": "شناسه",
    "col_cat": "دسته",
    "col_title": "عنوان",
    "col_code": "کد",
    "col_header": "هدر",
    "col_observed": "مقدار مشاهده‌شده",
    "col_state": "وضعیت",
    "col_assess": "ارزیابی",
    "f_cat": "دسته",
    "f_asset": "دارایی متأثر",
    "f_evidence": "شاهد",
    "f_impact": "تأثیر",
    "f_fix": "راه‌حل",
    "refs": "مرجع‌ها:",
    "st_ok": "مطلوب", "st_weak": "ضعیف", "st_missing": "غایب",
    "note_header_absent": "هدر ارسال نمی‌شود",
    "ap_a": "پیوست A - امنیت انتقال",
    "ap_b": "پیوست B - DNS و احراز هویت ایمیل",
    "ap_c": "پیوست C - محتوای افشا شده، پورت‌ها و کوکی‌ها",
    "ap_d": "پیوست D - سطح حمله و فناوری",
    "ap_e": "پیوست E - مدل نمره‌دهی و محدودیت‌ها",
    "a_https": "HTTPS", "a_trusted": "زنجیره قابل اعتماد",
    "a_proto": "نسخهٔ مذاکره شده", "a_matrix": "ماتریس نسخه‌ها",
    "a_cipher": "مجموعه رمز", "a_subject": "موضوع", "a_issuer": "صادرکننده",
    "a_valid": "اعتبار", "a_key": "کلید و امضا", "a_san": "ورودی‌های SAN",
    "a_redirect": "ریدایرکت HTTP به HTTPS", "a_chain": "زنجیرهٔ ریدایرکت",
    "a_methods": "متدهای اعلام شده", "a_comp": "فشرده‌سازی",
    "a_altsvc": "Alt-Svc / HTTP2+",
    "b_record": "رکورد", "b_value": "مقدار مشاهده‌شده",
    "c_path": "مسیر", "c_bytes": "بایت", "c_sig": "محتوای تأیید شده",
    "c_sample": "نمونهٔ ماسک شده", "c_port": "پورت", "c_service": "سرویس",
    "c_state": "وضعیت", "c_sev": "شدت", "c_cookie": "کوکی",
    "c_secure": "Secure", "c_httponly": "HttpOnly", "c_samesite": "SameSite",
    "c_host": "__Host-", "c_sess": "نشست",
    "d_item": "مورد", "d_value": "مقدار مشاهده‌شده",
    "e_area": "حوزهٔ کنترل", "e_weight": "وزن",
    "e_what": "چه چیزی سنجیده می‌شود",
    "e_scoring": ("وزن‌ها با جمع به 100 نمره می‌رسند: امنیت انتقال 25، هدرهای "
                  "امنیتی 22، محتوا و حریم خصوصی 13، یکپارچگی ایمیل 15، افشای "
                  "داده 15 و مواجههٔ شبکه 10. نمرهٔ کل حاصل جمع همین حوزه‌هاست و "
                  "گرید از A+ تا F از روی همان نمره تعیین می‌شود."),
    "limitations": ("محدودیت‌ها: نتایج یک لحظهٔ مشخص و فقط آن چیزی را می‌سنجند "
                    "که هدف در برابر یک کلاینت بدون احراز هویت افشا می‌کند. "
                    "محتوای پشت احراز هویت، منطق کسب‌وکار، ایرادهای سمت کلاینت، "
                    "شرایط مسابقه و کلاس‌های تزریق سمت سرور خارج از این روش‌اند. "
                    "نمرهٔ پاک تضمین امنیت نیست؛ نمرهٔ پایین سیگنال مطمئنی است "
                    "که سفت‌سازی عقب افتاده است."),
    "auth_head": "مجوز قانونی",
    "auth": ("این ارزیابی فقط از درخواست‌های بدون تخریب استفاده کرد، علیه هدفی "
             "که مالک آن هستید یا مجوز کتبی تستش را دارید. اسکن پورت، اسکن مسیر "
             "و شمارش DNS تکنیک‌های فعال‌اند: اجرای این ابزار علیه سیستم‌های "
             "ثالث بدون اجازهٔ کتبی ممکن است در حوزهٔ قضایی شما غیرقانونی باشد."),
    "page": "صفحه",
    "skipped_cdn": "رد شد (پشت CDN یا غیرفعال)",
    "not_published": "انتشار نیافته", "absent": "غایب", "present": "موجود",
    "not_detected": "شناسایی نشد", "not_determined": "تعیین نشد",
    "none": "هیچ", "not_tested": "آزمایش نشد",
    "not_advertised": "اعلام نشده",
    "in_use": "در حال استفاده", "not_in_use": "بدون استفاده",
    "yes": "بله", "no": "خیر",
    "no_files": "فایل عمومی قابل خواندنی تأیید نشد",
    "no_cookies": "در پاسخ تحلیل شده کوکی‌ای تنظیم نشد",
    "open": "باز", "closed": "بسته", "filtered": "فیلتر شده",
    "tls_off": "بدون استفاده", "tls_untrusted": "غیرقابل اعتماد",
    "tls_expired": "منقضی", "tls_days": "%d روز باقی‌مانده",
    "tls_unknown": "نامشخص",
    "hdr_of": "%d از %d موجود",
    "mail_posture": "DMARC %s / SPF %s", "mail_none": "ندارد",
    "summary_a": ("%s با نمرهٔ کل %s/100 (شاخص ریسک %.0f) و گرید %s ارزیابی "
                  "شد."),
    "summary_b": ("اسکن %d مورد بحرانی، %d مورد بالا، %d مورد متوسط، %d مورد "
                  "پایین و %d مورد اطلاعاتی را ثبت کرد."),
    "summary_crit": "نیازمند توجه فوری: ",
    "summary_high": "اولویت بالا: ",
    "summary_weak": ("ضعیف‌ترین حوزه‌های کنترل %s هستند. هر یافتهٔ زیر با "
                     "تغییر مشخصی که آن را رفع می‌کند همراه شده است."),
}

AREA_FA = {"Transport Security": ("امنیت انتقال", 25),
           "Security Headers": ("هدرهای امنیتی", 22),
           "Content & Privacy": ("محتوا و حریم خصوصی", 13),
           "Email Integrity": ("یکپارچگی ایمیل", 15),
           "Data Exposure": ("افشای داده", 15),
           "Network Exposure": ("مواجهه شبکه", 10)}

AREA_DESC = {
    "Transport Security": ("اعتبار و اعتماد گواهی، نسخه‌های پروتکل، قدرت رمز، "
                           "forward secrecy، کیفیت HSTS و ریدایرکت HTTPS"),
    "Security Headers": ("کیفیت وزنی هشت هدر امنیتی، درجه‌بندی بر اساس مقدار "
                         "و نه صرف وجود"),
    "Content & Privacy": "محتوای مخلوط، سیاست CORS، پرچم‌های کوکی و انتقال فرم",
    "Email Integrity": "قدرت SPF، سیاست DMARC، DKIM، MX، CAA و DNSSEC",
    "Data Exposure": "فایل‌های تأیید شده، فهرست‌کاری، افشای نسخه و فناوری",
    "Network Exposure": ("پورت‌های دیتابیس، دسترسی از راه دور و پنل‌های "
                         "مدیریتی قابل دسترسی از اینترنت")}


# ----------------------------------------------------------------- findings
def fa_finding(f, d):
    """Persian (title, impact, fix) for a finding; None keeps the English text.

    Numbers and names are rebuilt from the scan data rather than parsed out of
    the English sentence, so a wording change upstream cannot silently produce
    a wrong Persian figure.
    """
    fid = f.get("id", "")
    tls = d.get("tls") or {}
    dns = d.get("dns") or {}
    http = d.get("http") or {}
    content = d.get("content") or {}
    cookies = d.get("cookies") or []

    if fid.startswith("EXP-L"):
        i = int(fid[5:] or 0) - 1
        items = d.get("listing") or []
        dl = items[i] if 0 <= i < len(items) else {}
        return ("نمایش فهرست دایرکتوری در %s فعال است" % dl.get("path"),
                "مهاجم می‌تواند همهٔ فایل‌های این پوشه را در چند ثانیه فهرست‌کاری "
                "کند و بکاپ‌ها، آپلودها و اسناد داخلی را بیابد.",
                "نمایه‌گذاری خودکار (autoindex) را برای کل ریشهٔ سند غیرفعال "
                "کنید.")

    if fid.startswith("EXP-"):
        i = int(fid[4:] or 0) - 1
        items = d.get("exposed") or []
        e = items[i] if 0 <= i < len(items) else {}
        return ("فایل %s عموماً قابل خواندن است" % (e.get("signature") or ""),
                "این فایل برای هر کسی در اینترنت سرویس داده می‌شود. اطلاعات داخل "
                "آن - اعم از احراز هویت، کد منبع یا پیکربندی - می‌تواند منجر به "
                "تصاحب برنامه یا پایگاه‌دادهٔ آن شود.",
                "فایل را از ریشهٔ وب حذف کنید یا الگویش را در لبه مسدود کنید و "
                "اسرار را به متغیر محیطی یا مدیر اسرار منتقل کنید.")

    if fid == "TLS-00":
        return ("هدف با HTTP ساده سرو می‌شود",
                "همهٔ ترافیک، از جمله احراز هویت و کوکی نشست، به‌صورت متن ساده "
                "رد و بدل می‌شود و هر کسی در مسیر می‌تواند آن را بخواند یا "
                "تغییر دهد.",
                "HTTPS را با گواهی معتبر فعال کنید و همهٔ ترافیک HTTP را "
                "ریدایرکت کنید.")
    if fid == "TLS-01":
        return ("گواهی یا زنجیرهٔ TLS قابل اعتماد نیست",
                "مرورگرها صفحهٔ هشدار کامل نشان می‌دهند و کاربران یاد می‌گیرند "
                "روی هشدار کلیک کنند؛ ارزش HTTPS از بین می‌رود و آن‌ها در برابر "
                "حملهٔ مرد میانی فعال آسیب‌پذیر می‌مانند.",
                "زنجیرهٔ کامل (برگه به‌علاوه گواهی‌های میانی) را از یک CA قابل "
                "اعتماد نصب کنید و تمدید خودکار بگذارید.")
    if fid == "TLS-02":
        return ("گواهی TLS %d روز پیش منقضی شده است"
                % abs(tls.get("days_left") or 0),
                "مرورگرهای مدرن آن را مسدود یا هشدار می‌دهند و کلاینت‌های "
                "خودکار شکست می‌خورند؛ هم دسترس‌پذیری و هم اعتماد عملاً از بین "
                "رفته‌اند.",
                "فوراً تمدید کنید و تمدید را خودکار کنید.")
    if fid == "TLS-03":
        return ("گواهی TLS تا %d روز دیگر منقضی می‌شود"
                % (tls.get("days_left") or 0),
                "زمان چندانی برای تمدید باقی نمانده و احتمال قطعی سرویس جدی است.",
                "همین حالا تمدید کنید و آن را دائمی زمان‌بندی کنید.")
    if fid == "TLS-04":
        bad = ", ".join(v for v in ("TLSv1", "TLSv1.1")
                        if (tls.get("protocols") or {}).get(v))
        return ("نسخه‌های منسوخ TLS پذیرفته می‌شوند: %s" % bad,
                "TLS 1.0 و 1.1 بر پایه‌هایی استوارند که شکسته شده‌اند و PCI DSS "
                "به‌صورت صریح آن‌ها را ممنوع می‌کند.",
                "سرور را به TLS 1.2 و 1.3 محدود کنید.")
    if fid == "TLS-05":
        return ("مجموعهٔ رمز بدون forward secrecy مذاکره شد",
                "با سرقت کلید خصوصی، ترافیک ضبط‌شدهٔ قبلی هم رمزگشایی می‌شود "
                "(الان برداشت کن، بعداً رمزگشایی کن).",
                "مجموعه‌های ECDHE و TLS 1.3 را در اولویت بگذارید.")
    if fid == "TLS-06":
        return ("رمز ضعیف مذاکره شد: %s" % (tls.get("cipher") or ""),
                "ترافیکی که با الگوریتم شکسته محافظت شود با تلاش واقع‌بینانه قابل "
                "رمزگشایی است.",
                "مجموعه‌های RC4/3DES/NULL/EXPORT را از فهرست رمز حذف کنید.")
    if fid == "TLS-07":
        return ("کلید RSA کوتاه‌تر از 2048 بیت است",
                "چنین کلیدهایی در دسترس مهاجمی با بودجهٔ سازمانی قرار دارند.",
                "با RSA-2048 یا قوی‌تر، یا ECDSA P-256 صدور مجدد کنید.")
    if fid == "TLS-08":
        return ("گواهی با SHA-1 امضا شده است",
                "برخورد (collision) در SHA-1 عملی است و مرورگرها چنین "
                "گواهی‌هایی را رد می‌کنند.",
                "با SHA-256 یا قوی‌تر صدور مجدد کنید.")
    if fid == "TLS-09":
        return ("گواهی ویلدکارد در حال استفاده است",
                "کلید یک ویلدکارد روی میزبان‌های خواهری هم اثر می‌گذارد؛ این "
                "مورد اطلاعاتی است و به‌خودیِ خود ایراد نیست.",
                "برای میزبان‌های جدا گواهی مستقل بگذارید و با CAA صدور را محدود "
                "کنید.")
    if fid == "TLS-10":
        return ("ریدایرکت HTTP به HTTPS وجود ندارد",
                "کاربری که دامنه را بدون https تایپ می‌کند روی HTTP ساده می‌ماند "
                "و در برابر ربودن نشست و تزریق محتوا آسیب‌پذیر است.",
                "هر درخواست HTTP را به‌صورت دائمی به HTTPS ریدایرکت کنید.")

    if fid.startswith("HDR-"):
        code = fid[4:]
        if code == "CSP2":
            return ("نه frame-ancestors داریم و نه X-Frame-Options قابل استفاده",
                    "هیچ چیزی سایت را در برابر قاب‌گذاری توسط مرورگر دیگر "
                    "مسدود نمی‌کند و حملهٔ کلیک‌دادن جعلی ممکن می‌شود.",
                    "به سیاست CSP گزینهٔ frame-ancestors را اضافه کنید.")
        if code == "CSP3":
            return ("CSP محدودیتی روی object-src ندارد",
                    "محتوای افزونه‌های قدیمی می‌تواند به‌عنوان بردار حمله "
                    "جاسازی شود.",
                    "گزینهٔ object-src 'none' را اضافه کنید.")
        state, name = None, ""
        for hn, det in ((d.get("headers") or {}).get("detail") or {}).items():
            if det.get("short") == code:
                state, name = det.get("state"), hn
                break
        label = HDR_NAME_FA.get(code, name)
        why = HDR_WHY.get(code, "")
        if state == "MISSING":
            return ("هدر %s (%s) ارسال نمی‌شود" % (label, name),
                    why + " بدون این هدر، مرورگر هیچ‌یک از این محافظت‌ها را "
                    "اعمال نمی‌کند.",
                    "این هدر را روی همهٔ پاسخ‌های HTML ارسال کنید.")
        if state == "WEAK":
            return ("هدر %s موجود اما ضعیف است" % label,
                    why + " مقدار فعلی، حفاظت را به‌طور کامل یا بخشی بی‌اثر "
                    "می‌کند.",
                    "مقدار هدر را مطابق مستندات همان هدر قوی‌تر کنید.")
        return None

    if fid == "CNT-01":
        return ("محتوای مخلوط: منابع HTTP روی HTTPS بارگذاری می‌شوند",
                "مرورگرها این منابع را مسدود یا تضعیف می‌کنند و خودِ درخواست‌های "
                "HTTP قابل دستکاری‌اند؛ یکپارچگی صفحه پایین می‌آید.",
                "همهٔ زیرمنابع را روی HTTPS سرو کنید و "
                "upgrade-insecure-requests را اضافه کنید.")
    if fid == "CNT-02":
        return ("%d فرم با HTTP ساده ارسال می‌شود"
                % (content.get("insecure_forms") or 0),
                "احراز هویت یا اطلاعات شخصی بدون رمز از مرورگر خارج می‌شود.",
                "همهٔ action فرم‌ها را به آدرس https:// اشاره دهید.")
    if fid == "CNT-03":
        return ("نشانی‌های ایمیل در سورس صفحه افشا شده‌اند",
                "برای فیشینگ هدفمند و اسپم قابل جمع‌آوری‌اند و الگوی هویت "
                "داخلی را تأیید می‌کنند.",
                "آن‌ها را مخدوش کنید یا از فرم تماس استفاده کنید و نشانی نقشی "
                "بگذارید.")
    if fid == "CNT-05":
        return ("CORS هر origin دلخواهی را همراه با اعتبارنامه بازتاب می‌دهد",
                "هر وب‌سایتی می‌تواند به‌نمایندگی از کاربر وارد شده، پاسخ‌های "
                "احرازشده را بخواند و بدون هیچ تعامل کاربر داده را خارج کند.",
                "هرگز Origin دریافتی را هنگام مجاز بودن اعتبارنامه بازتاب "
                "نکنید؛ با یک فهرست مجاز صریح مقایسه کنید.")
    if fid == "CNT-06":
        return ("CORS Origin درخواستی را بازتاب می‌دهد",
                "خواندن بین دامنه‌ای ممکن می‌شود و هر endpoint دارای "
                "اعتبارنامه‌ای آن را بهره‌پذیر می‌سازد.",
                "یک origin ثابت و در فهرست مجاز برگردانید و Vary: Origin "
                "بگذارید.")
    if fid == "CNT-07":
        return ("CORS باکارد (Access-Control-Allow-Origin: *)",
                "برای دادهٔ واقعاً عمومی قابل قبول است، اما اگر منبع بعداً "
                "خصوصی شود یا پروکسی آن را کش کند خطرناک می‌شود.",
                "بکارد را فقط روی endpointهای صریحاً عمومی نگه دارید.")

    if fid in ("CK-01", "CK-02", "CK-03"):
        if fid == "CK-01":
            names = [c.get("name") for c in cookies if not c.get("secure")]
            return ("%d کوکی بدون پرچم Secure تنظیم می‌شود" % len(names),
                    "این کوکی روی HTTP ساده هم ارسال می‌شود و یک درخواست "
                    "تنزل‌یافته کافی است تا نشست نشت کند.",
                    "به همهٔ کوکی‌های روی HTTPS پرچم Secure اضافه کنید.")
        if fid == "CK-02":
            names = [c.get("name") for c in cookies if not c.get("httponly")]
            return ("%d کوکی بدون HttpOnly تنظیم می‌شود" % len(names),
                    "هر payload مربوط به XSS می‌تواند کوکی را از "
                    "document.cookie بخواند و نشست را خارج کند.",
                    "به کوکی‌های نشست پرچم HttpOnly اضافه کنید.")
        names = [c.get("name") for c in cookies
                 if c.get("samesite") == "missing"]
        return ("%d کوکی بدون SameSite تنظیم می‌شود" % len(names),
                "مرورگر این کوکی را به درخواست‌های بین‌وب‌گاهی هم می‌چسباند؛ "
                "همان موتور CSRF است.",
                "به کوکی‌های نشست SameSite=Lax (یا Strict) اضافه کنید.")

    if fid == "DNS-01":
        return ("رکورد SPF منتشر نشده است",
                "هر کسی می‌تواند ایمیلی با ادعای این دامنه بفرستد؛ بهترین "
                "سناریو برای فیشینگ و جعل فاکتور.",
                "رکورد SPFیی منتشر کنید که فقط فرستنده‌های مجاز را فهرست کند "
                "و به ‎-all‎ ختم شود.")
    if fid == "DNS-02":
        return ("SPF فرستندگان را محدود نمی‌کند (%s)" % dns.get("spf_policy"),
                "یک ‎+all‎ یا نبودِ کوالیفایر پایانی، همهٔ میزبان‌های اینترنت "
                "را مجاز می‌کند به‌عنوان این دامنه ایمیل بفرستند.",
                "رکورد را با ‎~all‎ (نرم) یا ‎-all‎ (سخت) تمام کنید.")
    if fid == "DNS-03":
        return ("SPF از سقف 10 جست‌وجوی DNS عبور کرده (%d)"
                % (dns.get("spf_lookups") or 0),
                "گیرنده‌ها PERMERROR برمی‌گردانند و رکورد بی‌صدا از محافظت خارج "
                "می‌شود.",
                "includeها را مسطح (flatten) کنید یا از رکورد مبتنی بر ماکرو "
                "استفاده کنید.")
    if fid == "DNS-04":
        return ("رکورد DMARC وجود ندارد",
                "هیچ دستوری برای قرنطینه یا رد ایمیل جعلی به گیرنده‌ها داده "
                "نشده و هیچ دیدی از تلاش‌های جعل ندارید.",
                "DMARC را با یک آدرس گزارش‌گیری منتشر کنید و بعد به مرحلهٔ "
                "اجرا بروید.")
    if fid == "DNS-05":
        return ("DMARC در حالت پایش است (p=none)",
                "ایمیل‌های جعلی همچنان به صندوق می‌رسند و فقط گزارش تولید می‌شود.",
                "وقتی گزارش‌ها پاک بود، سیاست را به quarantine و سپس reject "
                "ارتقا دهید.")
    if fid == "DNS-06":
        return ("DMARC فقط روی %s%% از ایمیل‌ها اعمال می‌شود"
                % dns.get("dmarc_pct"),
                "باقی‌ماندهٔ درصدها کاملاً از سیاست عبور می‌کنند.",
                "پس از پاک شدن گزارش‌ها pct را به 100 ببرید.")
    if fid == "DNS-07":
        return ("روی سلکتورهای رایج کلید DKIM منتشر نشده",
                "بدون DKIM بدنهٔ پیام به‌صورت رمزنگاری‌شده به دامنه گره نمی‌خورد "
                "و هم‌راستایی DMARC ضعیف می‌شود.",
                "امضای DKIM را در سرویس‌دهندهٔ ایمیل فعال و کلید عمومی را "
                "منتشر کنید.")
    if fid == "DNS-08":
        return ("رکورد MX وجود ندارد",
                "وقتی دامنه نمی‌تواند نامهٔ برگشتی یا شکایت دریافت کند، جعل "
                "آن آسان‌تر است.",
                "اگر دامنه هرگز ایمیل نمی‌فرستد، این را صریحاً با "
                "‎v=spf1 -all‎ اعلام کنید.")
    if fid == "DNS-09":
        return ("رکورد CAA وجود ندارد",
                "هر CA عمومی می‌تواند برای این دامنه گواهی صادر کند، حتی CAیی "
                "که فریب صدور غیرمجاز بخورد.",
                "صدور را به CA خودتان محدود کنید.")
    if fid == "DNS-10":
        return ("DNSSEC تأیید نشده است",
                "بدون DNSSEC مهاجمی که در مسیر باشد می‌تواند پاسخ DNS را جعل "
                "کند و SPF و DMARC و CAA را زیر سؤال ببرد.",
                "DNSSEC را در ثبت‌کننده فعال و رکورد DS منتشر کنید.")

    if fid == "HTTP-01":
        return ("متدهای پرریسک اعلام شده‌اند: %s"
                % ", ".join(http.get("risky") or []),
                "PUT و DELETE می‌توانند وضعیت سرور را تغییر دهند و TRACE "
                "امکان ردیابی بین‌وب‌گاهی می‌دهد.",
                "فقط متدهایی را اعلام و بپذیرید که برنامه واقعاً استفاده "
                "می‌کند.")

    if fid == "INF-01":
        return ("نسخهٔ نرم‌افزار در هدرها افشا می‌شود",
                "نسخهٔ دقیق به مهاجم اجازه می‌دهد هدف را با بهره‌برداری‌های "
                "عمومی بدون هیچ سروصدای شناسایی تطبیق دهد.",
                "بنر نسخه را حذف کنید (server_tokens off و expose_php = Off).")
    if fid == "INF-02":
        sigs = ", ".join(((d.get("fingerprint") or {}).get("error_page")
                          or {}).get("signatures") or [])
        return ("صفحهٔ خطا اطلاعات داخلی را افشا می‌کند: %s" % sigs,
                "رد پشته و مسیرهای مطلق، چارچوب و ساختار پرونده و گاه احراز "
                "هویت یا کوئری‌ها را به هر بازدیدکننده‌ای نشان می‌دهد.",
                "حالت دیباگ را در محیط عملیاتی خاموش کنید و صفحهٔ خطای ایستا "
                "سرو کنید.")
    if fid == "INF-03":
        return ("security.txt با راه‌تماس منتشر نشده",
                "پژوهشگران کانال گزارش ندارند؛ یافته‌ها یا به عموم می‌رسند یا "
                "به هیچ‌کس، نه به شما.",
                "security.txt مطابق RFC 9116 با یک راه‌تماس پایش‌شده منتشر "
                "کنید.")
    if fid == "INF-04":
        return ("فشرده‌سازی HTTP فعال نیست",
                "حجم انتقال بیشتر است و اولین رندر کندتر می‌شود، به‌ویژه روی "
                "شبکهٔ موبایل.",
                "برای پاسخ‌های متنی gzip یا brotli را فعال کنید.")
    if fid == "INF-05":
        return ("robots.txt مسیرهای حساس را تبلیغ می‌کند",
                "ورودی‌های Disallow نقشهٔ عمومی پنل‌های مدیریتی، بکاپ‌ها و "
                "endpointهای داخلی است.",
                "آن مسیرها را با احراز هویت محافظت کنید و نام داخلی را از "
                "robots.txt بیرون بیاورید.")

    if fid.startswith("NET-") and fid[4:].isdigit():
        i = int(fid[4:]) - 1
        ports = d.get("open_ports") or []
        p = int(ports[i]) if 0 <= i < len(ports) else 0
        from audit2 import PORT_FIX
        return ("پورت %d/%s از اینترنت قابل دسترسی است"
                % (p, PNAME.get(p, "?")),
                "یک اتصال TCP به پورت %d برقرار شد؛ چنین سرویسی ظرف چند ساعت "
                "در اسکن‌های سراسر اینترنت پیدا می‌شود." % p,
                PORT_FIX.get(p, "پورت را با دیوار آتش ببندید و فقط از شبکهٔ "
                               "خصوصی یا VPN در دسترس بگذارید."))
    if fid == "NET-CDN":
        return ("پوشش %s شناسایی شد" % (d.get("cdn") or ""),
                "CDN یا WAF حملات حجمی را جذب و مبدأ را پنهان می‌کند، اما "
                "مبدأ باید خودش هم فایروال شده باشد تا از طریق IP واقعی قابل "
                "دسترسی نشود.",
                "دسترسی به مبدأ را فقط به محدوده‌های خروجی اعلام‌شدهٔ CDN "
                "محدود کنید.")
    if fid == "NET-SUB":
        return ("%d ساب‌دامین رزولوشن می‌شود"
                % len(d.get("subdomains") or []),
                "هر میزبان فعال یک نقطهٔ ورودی جداست و میزبان‌های فراموش‌شدهٔ "
                "استیجینگ یا مدیریت، راه کلاسیک ورود هستند.",
                "فهرست تجهیزات نگه دارید، رکوردهای بازنشده را حذف کنید و "
                "میزبان‌های غیرعملیاتی را پشت احراز هویت بگذارید.")
    if fid == "META-01":
        return ("هدف قابل دسترسی نبود",
                "ارزیابی ممکن نیست: میزبان روی %s پاسخی نداد. نام دامنه، DNS و "
                "در حال بودن سرویس را بررسی کنید."
                % (d.get("meta", {}).get("scheme") or "http"),
                "حل DNS و گوش دادن وب‌سرور روی پورت مربوطه را بررسی کنید.")
    return None


# ------------------------------------------------------------------ drawing
def banner_fa(width, title, lines, height=94):
    d = Drawing(width, height)
    c1, c2 = hx(NAVY), hx("#3730a3")
    steps = 80
    for i in range(steps):
        t = i / float(steps - 1)
        d.add(Rect(width * i / steps, 0, width / steps + 1, height,
                   strokeColor=None,
                   fillColor=colors.Color(c1.red + (c2.red - c1.red) * t,
                                          c1.green + (c2.green - c1.green) * t,
                                          c1.blue + (c2.blue - c1.blue) * t)))
    d.add(Rect(0, 0, width, 3, fillColor=hx(ACCENT), strokeColor=None))
    tw = min(pdfmetrics.stringWidth(fs(title), FA_BOLD, 20), width - 40)
    d.add(DStr(width - 20, height - 34, fs(title), fontName=FA_BOLD,
               fontSize=20, fillColor=hx(WHITE), textAnchor="end"))
    d.add(Rect(width - 20 - tw, height - 42, tw, 2, fillColor=hx(ACCENT),
               strokeColor=None))
    y = height - 58
    for line in lines:
        d.add(DStr(width - 20, y, fs(line), fontName=FA_REG, fontSize=8.6,
                   fillColor=hx("#c7d2fe"), textAnchor="end"))
        y -= 12
    return d


def gauge_fa(score, grade, size=134):
    d = Drawing(size, size)
    c = size / 2.0
    r = c - 8
    col = hx(score_color(score))
    sweep = 3.6 * max(0, min(100, score))
    d.add(Circle(c, c, r, fillColor=hx(TRACK), strokeColor=None))
    if sweep > 1:
        d.add(Wedge(c, c, r, 90 - sweep, 90, fillColor=col, strokeColor=None))
    d.add(Circle(c, c, r * 0.70, fillColor=hx(WHITE), strokeColor=None))
    d.add(DStr(c, c - 5, "%d" % score, fontName=FA_BOLD, fontSize=size * 0.30,
               fillColor=col, textAnchor="middle"))
    d.add(DStr(c, c + r * 0.24, fs(UI["gauge_of"]), fontName=FA_REG,
               fontSize=7.6, fillColor=hx(MUTED), textAnchor="middle"))
    d.add(DStr(c, c - r * 0.36,
               fs("%s %s" % (UI["gauge_grade"], grade)),
               fontName=FA_BOLD, fontSize=9, fillColor=col,
               textAnchor="middle"))
    return d


def bar_chart_fa(rows, width, height, label_w=118, value_w=54):
    """Mirrored bar chart: labels on the right, bars grow leftwards."""
    d = Drawing(width, height)
    n = max(len(rows), 1)
    row_h = height / float(n)
    track_w = max(10.0, width - label_w - value_w)
    for i, (label, ratio, col, text) in enumerate(rows):
        y = height - (i + 1) * row_h + row_h * 0.26
        bh = max(5.0, row_h * 0.44)
        d.add(DStr(width, y + 1.4, fs(label), fontName=FA_REG, fontSize=7.4,
                   fillColor=hx(SLATE), textAnchor="end"))
        d.add(Rect(value_w, y, track_w, bh, fillColor=hx(TRACK),
                   strokeColor=None))
        frac = max(0.0, min(1.0, ratio))
        d.add(Rect(value_w + track_w * (1.0 - frac), y,
                   max(1.5, track_w * frac), bh, fillColor=hx(col),
                   strokeColor=None))
        d.add(DStr(0, y + 1.4, text, fontName=FA_BOLD, fontSize=7.4,
                   fillColor=hx(col)))
    return d


def sev_strip_fa(counts, width, height=36):
    d = Drawing(width, height)
    total = sum(counts.get(k, 0) for k in SEV_ORDER) or 1
    x = width
    for sev in SEV_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        w = width * n / float(total)
        x -= w
        d.add(Rect(x, 16, w, 14, fillColor=hx(SEV_COLOR[sev]),
                   strokeColor=None))
        if w > 12:
            d.add(DStr(x + w / 2.0, 20.4, str(n), fontName=FA_BOLD,
                       fontSize=7.4, fillColor=hx(WHITE), textAnchor="middle"))
    lx = width
    for sev in SEV_ORDER:
        label = fs(SEV_FA.get(sev, sev))
        lw = pdfmetrics.stringWidth(label, FA_REG, 6.6)
        lx -= 6
        d.add(DStr(lx, 5.4, label, fontName=FA_REG, fontSize=6.6,
                   fillColor=hx(MUTED), textAnchor="end"))
        lx -= lw + 3
        d.add(DStr(lx, 5.4, str(counts.get(sev, 0)), fontName=FA_BOLD,
                   fontSize=6.6, fillColor=hx(SEV_COLOR[sev]),
                   textAnchor="end"))
        lx -= 14
    return d


# ------------------------------------------------------------------- report
class ReportFA:
    def __init__(self, data, path):
        self.d, self.path = data, path
        self.meta = data.get("meta", {})
        self.score = data.get("score", {})
        self.findings = data.get("findings", [])
        self.w = A4[0] - 68
        self.S = fstyles()

    # ------------------------------------------------------------ widgets
    def grid(self, head, rows, widths, head_bg=SLATE):
        """head and rows are in RTL column order (last column sits right)."""
        data = [[fp(c, self.S["cellb"], widths[i] - 8)
                 for i, c in enumerate(head)]]
        for row in rows:
            line = []
            for i, c in enumerate(row):
                if isinstance(c, (Paragraph, Table, Drawing)):
                    line.append(c)
                else:
                    line.append(fp(c, self.S["cell"], widths[i] - 8))
            data.append(line)
        t = Table(data, colWidths=widths, hAlign="LEFT", repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), hx(head_bg)),
              ("GRID", (0, 0), (-1, -1), 0.35, hx(LINE)),
              ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
              ("TOPPADDING", (0, 0), (-1, -1), 3.0),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 3.0),
              ("LEFTPADDING", (0, 0), (-1, -1), 4),
              ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
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
        cells = [Paragraph("<font size='6.2' color='%s'>%s</font><br/>"
                           "<font size='8.6' color='%s'><b>%s</b></font>"
                           % (MUTED, fs(label), col, fs(value)),
                           self.S["cell"])
                 for label, value, col in items]
        cells = list(reversed(cells))          # first chip lands on the right
        while len(cells) % cols:
            cells.append(Paragraph("", self.S["cell"]))
        rows = [cells[i:i + cols] for i in range(0, len(cells), cols)]
        t = Table(rows, colWidths=[self.w / float(cols)] * cols)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx("#f1f5f9")),
                               ("BOX", (0, 0), (-1, -1), 0.4, hx(LINE)),
                               ("INNERGRID", (0, 0), (-1, -1), 0.4, hx(LINE)),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 4.5),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5)]))
        return t

    def code(self, snippet):
        t = Table([[XPreformatted(snippet, self.S["mono"])]],
                  colWidths=[self.w])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx("#0f172a")),
                               ("LEFTPADDING", (0, 0), (-1, -1), 7),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                               ("TOPPADDING", (0, 0), (-1, -1), 5),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        return t

    def P(self, text, kind="cell", width=None, bold=False):
        return fp(text, self.S[kind], (width or self.w) - 10, bold=bold)

    # ----------------------------------------------------------- narrative
    def summary_text(self):
        c = self.score.get("counts", {})
        crit, high = [], []
        for f in self.findings:
            if f["severity"] not in ("CRITICAL", "HIGH"):
                continue
            tr = fa_finding(f, self.d) or (f["title"], None, None)
            (crit if f["severity"] == "CRITICAL" else high).append(tr[0])
        weak = [CAT_FA.get(k, k) for k, _v in
                sorted((self.score.get("categories") or {}).items(),
                       key=lambda kv: kv[1])[:2]]
        parts = [UI["summary_a"] % (self.meta.get("domain", "هدف"),
                                    self.score.get("total", 0),
                                    self.score.get("risk", 0),
                                    self.score.get("grade", "?")),
                 UI["summary_b"] % (c.get("CRITICAL", 0), c.get("HIGH", 0),
                                    c.get("MEDIUM", 0), c.get("LOW", 0),
                                    c.get("INFO", 0))]
        if crit:
            parts.append(UI["summary_crit"] + "، ".join(crit[:3]) + ".")
        if high:
            parts.append(UI["summary_high"] + "، ".join(high[:3]) + ".")
        if weak:
            parts.append(UI["summary_weak"] % "، ".join(weak))
        return " ".join(parts)

    def _tls_state(self):
        tls = self.d.get("tls") or {}
        if not tls.get("enabled"):
            return UI["tls_off"]
        if tls.get("trusted") is False:
            return UI["tls_untrusted"]
        if (tls.get("days_left") or 0) < 0:
            return UI["tls_expired"]
        if tls.get("days_left") is not None:
            return UI["tls_days"] % tls.get("days_left")
        return UI["tls_unknown"]

    def cover(self):
        m, sc = self.meta, self.score
        dns = self.d.get("dns") or {}
        hdr = self.d.get("headers") or {}
        ports_n = len(self.d.get("ports") or {})
        chips = [(UI["ch_grade"], "%s  (%d/100)" % (sc.get("grade", "?"),
                                                    sc.get("total", 0)),
                  score_color(sc.get("total", 0))),
                 (UI["ch_find"], "%d مورد" % len(self.findings),
                  SEV_COLOR["HIGH"]),
                 (UI["ch_risk"], "%.0f" % (sc.get("risk") or 0),
                  SEV_COLOR["MEDIUM"]),
                 (UI["ch_tls"], self._tls_state(),
                  SEV_COLOR["OK"] if (self.d.get("tls") or {}).get("trusted")
                  else SEV_COLOR["CRITICAL"]),
                 (UI["ch_hdr"], UI["hdr_of"] % (len(hdr.get("present") or []),
                                                len(HEADERS)),
                  SEV_COLOR["OK"] if not hdr.get("missing")
                  else SEV_COLOR["MEDIUM"]),
                 (UI["ch_mail"],
                  UI["mail_posture"] % (dns.get("dmarc_policy") or
                                        UI["mail_none"],
                                        dns.get("spf_policy") or
                                        UI["mail_none"]),
                  SEV_COLOR["OK"] if dns.get("dmarc_policy") == "reject"
                  else SEV_COLOR["HIGH"]),
                 (UI["ch_exp"], str(len(self.d.get("exposed") or [])),
                  SEV_COLOR["CRITICAL"] if self.d.get("exposed")
                  else SEV_COLOR["OK"]),
                 (UI["ch_ports"], str(len(self.d.get("open_ports") or [])),
                  SEV_COLOR["MEDIUM"] if self.d.get("open_ports")
                  else SEV_COLOR["OK"]),
                 (UI["ch_cdn"], self.d.get("cdn") or UI["not_detected"],
                  SEV_COLOR["OK"] if self.d.get("cdn") else SEV_COLOR["LOW"])]
        f = [banner_fa(self.w, UI["banner"],
                       [m.get("domain", "?"),
                        "IP %s  |  %s  |  %s" % (m.get("ip"),
                                                 m.get("audit_date"),
                                                 m.get("tool"))]),
             Spacer(1, 12),
             self.chips(chips),
             Spacer(1, 14)]
        row = Table([[gauge_fa(sc.get("total", 0), sc.get("grade", "?")),
                      sev_strip_fa(sc.get("counts", {}), self.w - 170)],
                     [fp(UI["lab_gauge"], self.S["small"], 150),
                      fp(UI["lab_strip"], self.S["small"], self.w - 170)]],
                    colWidths=[160, self.w - 160])
        row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
                                 ("ALIGN", (0, 0), (0, 0), "CENTER"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                 ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                 ("TOPPADDING", (0, 0), (-1, 0), 0)]))
        f += [row, Spacer(1, 12),
              Paragraph(fs(UI["exec"]), self.S["h2"]),
              self.box([fp(self.summary_text(), self.S["body"], self.w - 18)]),
              Spacer(1, 10),
              Paragraph(fs(UI["scope"]), self.S["h2"]),
              self.grid([UI["col_value"], UI["col_field"]], [
                  [m.get("url"), UI["f_target"]],
                  [m.get("ip"), UI["f_ip"]],
                  ["%s / %s" % (m.get("scheme"), m.get("port")),
                   UI["f_scheme"]],
                  ["%s (%s s)" % (m.get("audit_date"), m.get("duration_s")),
                   UI["f_window"]],
                  [UI["tests"] % (len(PATHS), ports_n), UI["f_tests"]],
                  [UI["sources"], UI["f_sources"]],
                  ["dnspython %s | cryptography %s"
                   % ("yes" if m.get("dns_available") else "no",
                      "yes" if m.get("crypto_available") else "no"),
                   UI["f_modules"]]],
                  [self.w - 128, 128]),
              Spacer(1, 10),
              self.box([fp(UI["cover_note"], self.S["tiny"], self.w - 18)])]
        return f

    def overview(self):
        f = [Paragraph(fs(UI["h_breakdown"]), self.S["h1"])]
        cats = self.score.get("categories", {})
        rows = []
        for key in AREA_FA:
            label, mx = AREA_FA[key]
            val = cats.get(key, 0)
            pct = val / float(mx) if mx else 0
            rows.append((label, pct, score_color(pct * 100),
                         "%s / %d" % (val, mx)))
        f += [bar_chart_fa(rows, self.w, 15.0 * len(rows) + 6),
              Spacer(1, 14),
              Paragraph(fs(UI["h_matrix"]), self.S["h2"])]
        hwidths = [34, 116, 138, 46, self.w - 334]
        hrows = []
        detail = (self.d.get("headers") or {}).get("detail") or {}
        for name, det in detail.items():
            col = {"OK": SEV_COLOR["OK"], "WEAK": SEV_COLOR["MEDIUM"],
                   "MISSING": SEV_COLOR["CRITICAL"]}.get(det.get("state"),
                                                         MUTED)
            state_fa = {"OK": UI["st_ok"], "WEAK": UI["st_weak"],
                        "MISSING": UI["st_missing"]}.get(det.get("state"),
                                                         det.get("state"))
            hrows.append([
                Paragraph("<font color='%s'><b>%s</b></font>"
                          % (col, esc(det.get("short"))), self.S["cell"]),
                fp(name, self.S["cell"], hwidths[1] - 8),
                fp(cut(det.get("value") or "-", 78), self.S["cell"],
                   hwidths[2] - 8),
                Paragraph("<font color='%s'><b>%s</b></font>"
                          % (col, fs(state_fa)), self.S["cell"]),
                fp(det.get("note") or UI["note_header_absent"],
                   self.S["cell"], hwidths[4] - 8)])
        f.append(self.grid([UI["col_code"], UI["col_header"],
                            UI["col_observed"], UI["col_state"],
                            UI["col_assess"]], hrows, hwidths, head_bg=NAVY))
        f += [Spacer(1, 14), Paragraph(fs(UI["h_index"]), self.S["h2"])]
        iwidths = [66, 46, 96, self.w - 208]
        irows = []
        for x in self.findings:
            tr = fa_finding(x, self.d)
            title = tr[0] if tr else x["title"]
            irows.append([
                Paragraph("<font color='%s'><b>%s</b></font>"
                          % (SEV_COLOR.get(x["severity"], MUTED),
                             fs(SEV_FA.get(x["severity"], x["severity"]))),
                          self.S["cell"]),
                Paragraph("<b>%s</b>" % esc(x["id"]), self.S["cell"]),
                fp(CAT_FA.get(x["category"], x["category"]), self.S["cell"],
                   iwidths[2] - 8),
                fp(title, self.S["cell"], iwidths[3] - 8)])
        f.append(self.grid([UI["col_sev"], UI["col_id"], UI["col_cat"],
                            UI["col_title"]],
                           irows or [["-", "-", "-", UI["no_findings"]]],
                           iwidths))
        return f

    def finding_block(self, x):
        tr = fa_finding(x, self.d)
        title, impact, fix = tr if tr else (x["title"], x["impact"], x["fix"])
        col = SEV_COLOR.get(x["severity"], MUTED)
        sev = Paragraph("<font color='#ffffff'><b>%s</b></font>"
                        % fs(SEV_FA.get(x["severity"], x["severity"])),
                        self.S["cell"])
        head = Table([[fp(title, self.S["cell"], self.w - 96, bold=True), sev]],
                     colWidths=[self.w - 76, 76])
        head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), hx(col)),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 6),
                                  ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                  ("TOPPADDING", (0, 0), (-1, -1), 4),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        meta = self.grid(
            [UI["col_value"], UI["col_field"]],
            [[CAT_FA.get(x["category"], x["category"]), UI["f_cat"]],
             [x.get("asset") or "", UI["f_asset"]],
             [fp(x.get("evidence") or "-", self.S["cell"], self.w - 94),
              UI["f_evidence"]],
             [fp(impact, self.S["cell"], self.w - 94), UI["f_impact"]],
             [fp(fix, self.S["cell"], self.w - 94), UI["f_fix"]]],
            [self.w - 76, 76], head_bg="#475569")
        out = [Spacer(1, 6), KeepTogether([head, meta])]
        if x.get("snippet"):
            out += [Spacer(1, 3), self.code(x["snippet"])]
        if x.get("refs"):
            out += [Spacer(1, 2),
                    fp(UI["refs"] + " " + "; ".join(x["refs"]),
                       self.S["tiny"], self.w - 10)]
        return out

    def appendix(self):
        d = self.d
        tls = d.get("tls") or {}
        dns = d.get("dns") or {}
        http = d.get("http") or {}
        fpn = d.get("fingerprint") or {}
        content = d.get("content") or {}
        cors = d.get("cors") or {}
        robots = d.get("robots") or {}
        w = self.w
        proto = ", ".join("%s %s" % (k, UI["yes"] if v else UI["no"])
                          for k, v in (tls.get("protocols") or {}).items()) \
            or UI["not_tested"]
        chain = " -> ".join("%s [%s]" % (h.get("url"), h.get("status"))
                            for h in (http.get("https_chain") or [])) or "-"
        aw = [w - 132, 132]
        f = [Paragraph(fs(UI["ap_a"]), self.S["h1"]),
             self.grid([UI["col_value"], UI["col_field"]], [
                 [UI["in_use"] if tls.get("enabled") else UI["not_in_use"],
                  UI["a_https"]],
                 [UI["yes"] if tls.get("trusted") else
                  "خیر (%s)" % (tls.get("kind") or tls.get("error") or
                                "شکست دست‌دادن"), UI["a_trusted"]],
                 ["%s (ALPN %s)" % (tls.get("protocol"),
                                    tls.get("alpn") or "-"), UI["a_proto"]],
                 [proto, UI["a_matrix"]],
                 ["%s (%s بیت، forward secrecy %s)"
                  % (tls.get("cipher") or "-", tls.get("bits") or "?",
                     UI["yes"] if tls.get("forward_secrecy") else UI["no"]),
                  UI["a_cipher"]],
                 [tls.get("subject") or "-", UI["a_subject"]],
                 ["%s (%s)" % (tls.get("issuer") or "-",
                               tls.get("issuer_org") or "-"), UI["a_issuer"]],
                 ["%s تا %s (%s روز باقی‌مانده)"
                  % (tls.get("not_before") or "-", tls.get("expires") or "-",
                     tls.get("days_left")), UI["a_valid"]],
                 ["%s %s بیت، هش %s" % (tls.get("key_type") or "?",
                                        tls.get("key_size") or "?",
                                        tls.get("sig_alg") or "?"),
                  UI["a_key"]],
                 ["%s%s" % (tls.get("san_count"),
                            " (ویلدکارد)" if tls.get("wildcard") else ""),
                  UI["a_san"]],
                 [UI["yes"] if http.get("https_upgrade") else UI["no"],
                  UI["a_redirect"]],
                 [chain, UI["a_chain"]],
                 [", ".join(http.get("allow") or []) or UI["none"],
                  UI["a_methods"]],
                 [http.get("compression") or UI["none"], UI["a_comp"]],
                 [http.get("alt_svc") or UI["not_advertised"],
                  UI["a_altsvc"]]],
                 aw),
             Spacer(1, 12),
             Paragraph(fs(UI["ap_b"]), self.S["h1"]),
             self.grid([UI["b_value"], UI["b_record"]], [
                 [", ".join(dns.get("a") or []) or "-", "A"],
                 [", ".join(dns.get("aaaa") or []) or "-", "AAAA"],
                 [dns.get("cname") or "-", "CNAME"],
                 [", ".join(dns.get("ns") or []) or "-", "NS"],
                 [", ".join("%s (pref %s)" % (mx.get("host"), mx.get("pref"))
                            for mx in (dns.get("mx") or [])) or "-", "MX"],
                 [(cut(dns.get("spf"), 150) + "  [سیاست %s، %s جست‌وجو]"
                   % (dns.get("spf_policy"), dns.get("spf_lookups")))
                  if dns.get("spf") else UI["not_published"], "SPF"],
                 [(cut(dns.get("dmarc"), 150) + "  [سیاست %s، pct %s]"
                   % (dns.get("dmarc_policy"), dns.get("dmarc_pct")))
                  if dns.get("dmarc") else UI["not_published"], "DMARC"],
                 [", ".join(x.get("selector") for x in (dns.get("dkim") or []))
                  or ("کلیدی روی %s سلکتور رایج نیست"
                      % dns.get("selectors", 0)), "DKIM"],
                 [", ".join(dns.get("caa") or []) or UI["not_published"],
                  "CAA"],
                 [UI["yes"] if dns.get("dnssec") is True else
                  ("تأیید نشد" if dns.get("available") else
                   "ناموجود (dnspython نصب نیست)"), "DNSSEC"],
                 [" | ".join(dns.get("txt") or [])[:380] or "-", "TXT"]],
                 [w - 62, 62]),
             Spacer(1, 12),
             Paragraph(fs(UI["ap_c"]), self.S["h1"])]
        erows = [[cut(e.get("sample"), 58), e.get("signature"), e.get("size"),
                  e.get("path")]
                 for e in (d.get("exposed") or [])]
        ewidths = [140, 130, 46, w - 316]
        f.append(self.grid([UI["c_sample"], UI["c_sig"], UI["c_bytes"],
                            UI["c_path"]],
                           erows or [["-", UI["no_files"], "-", "-"]],
                           ewidths))
        pwidths = [70, 66, 104, w - 240]
        f += [Spacer(1, 8),
              self.grid([UI["c_sev"], UI["c_state"], UI["c_service"],
                         UI["c_port"]],
                        [[port_sev_fa(p), port_state_fa(s),
                          "%d/%s" % (int(p), PNAME.get(int(p), "?")), p]
                         for p, s in sorted((d.get("ports") or {}).items())]
                        or [["-", UI["skipped_cdn"], "-", "-"]],
                        pwidths),
              Spacer(1, 8),
              self.grid([UI["c_sess"], UI["c_host"], UI["c_samesite"],
                         UI["c_httponly"], UI["c_secure"], UI["c_cookie"]],
                        [[UI["yes"] if c.get("session_like") else UI["no"],
                          UI["yes"] if c.get("host_prefix") else UI["no"],
                          c.get("samesite") or "-",
                          UI["yes"] if c.get("httponly") else UI["no"],
                          UI["yes"] if c.get("secure") else UI["no"],
                          c.get("name")]
                         for c in (d.get("cookies") or [])]
                        or [[UI["no_cookies"], "-", "-", "-", "-", "-"]],
                        [52, 50, 58, 54, 42, w - 256]),
              Spacer(1, 12),
              Paragraph(fs(UI["ap_d"]), self.S["h1"]),
              self.grid([UI["d_value"], UI["d_item"]], [
                  [", ".join(s.get("host")
                             for s in (d.get("subdomains") or []))
                   or UI["none"], "ساب‌دامین‌های رزولوشن شده"],
                  [("%s، %d مسیر علامت‌خورده"
                    % (UI["present"], len(robots.get("sensitive") or []))
                    if robots.get("found") else UI["absent"]), "robots.txt"],
                  [", ".join(robots.get("sensitive") or []) or "-",
                   "مسیرهای حساس در robots.txt"],
                  [("%s URL در %s" % ((d.get("sitemap") or {}).get("urls"),
                                      (d.get("sitemap") or {}).get("path"))
                    if (d.get("sitemap") or {}).get("found")
                    else UI["absent"]), "Sitemap"],
                  [(d.get("security_txt") or {}).get("path")
                   if (d.get("security_txt") or {}).get("found")
                   else UI["absent"], "security.txt"],
                  [", ".join(fpn.get("stack") or []) or UI["not_determined"],
                   "پشتهٔ فناوری"],
                  [", ".join("%s %s" % (k, v) for k, v in
                             (fpn.get("tech") or {}).items()
                             if re.search(r"\d\.\d", str(v))) or UI["none"],
                   "نسخه‌های افشا شده"],
                  ["%s%s" % ("HTTP %s - " % fpn["error_page"].get("status")
                             if fpn.get("error_page") else "",
                             (fpn.get("error_page") or {}).get("title") or "-"),
                   "صفحهٔ خطا"],
                  [", ".join((fpn.get("error_page") or {}).get("signatures")
                             or []) or "افشای چارچوب یا مسیری شناسایی نشد",
                   "نشت‌های صفحهٔ خطا"],
                  [", ".join(content.get("mixed") or []) or UI["none"],
                   "میزبان‌های محتوای مخلوط"],
                  [", ".join(content.get("external_scripts") or [])
                   or UI["none"], "منابع اسکریپت خارجی"],
                  ["%s / %s" % (content.get("inline_scripts"),
                                content.get("sri_missing")),
                   "اسکریپت درونی / بدون SRI"],
                  [", ".join(content.get("emails") or []) or UI["none"],
                   "ایمیل‌های سورس"],
                  [("بازتاب origin%s" % ("، مجوز اعتبارنامه داده شده"
                                         if cors.get("credentials") else ""))
                   if cors.get("origin_echo") else
                   ("بکارد" if cors.get("wildcard") else "غیرمجاز"),
                   "سیاست CORS"],
                  [d.get("cdn") or UI["not_detected"], "WAF / CDN"],
                  ["%s ms کل، %s ms TTFB، %s kB"
                   % ((d.get("home") or {}).get("elapsed_ms"),
                      (d.get("home") or {}).get("ttfb_ms"),
                      (d.get("home") or {}).get("size_kb")),
                   "پروفایل پاسخ"]],
                  aw),
              Spacer(1, 12),
              Paragraph(fs(UI["ap_e"]), self.S["h1"])]
        arows = [[AREA_DESC.get(k, ""), str(AREA_FA[k][1]), AREA_FA[k][0]]
                 for k in AREA_FA]
        f += [self.grid([UI["e_what"], UI["e_weight"], UI["e_area"]],
                        arows, [w - 170, 44, 126]),
              Spacer(1, 6),
              fp(UI["e_scoring"], self.S["small"], w - 10),
              Spacer(1, 8),
              self.box([fp(UI["limitations"], self.S["small"], w - 18)]),
              Spacer(1, 8),
              self.box([fp(UI["auth_head"], self.S["small"], w - 18, bold=True),
                        fp(UI["auth"], self.S["small"], w - 18)],
                       bg="#fff7ed", border="#fed7aa")]
        return f

    def build(self):
        story = self.cover() + [PageBreak(),
                                Paragraph(fs(UI["h_overview"]), self.S["h1"])]
        story += self.overview() + [PageBreak(),
                                    Paragraph(fs(UI["h_findings"]),
                                              self.S["h1"])]
        if not self.findings:
            story.append(fp(UI["no_findings"], self.S["body"], self.w))
        for x in self.findings:
            story += self.finding_block(x)
        story += [PageBreak()] + self.appendix()
        doc = BaseDocTemplate(self.path, pagesize=A4, leftMargin=34,
                              rightMargin=34, topMargin=30, bottomMargin=40,
                              title="گزارش امنیت وب - %s"
                              % self.meta.get("domain", ""),
                              author="SiteAuditor", creator="SiteAuditor",
                              subject="ارزیابی امنیت و مواجههٔ وب")
        frame = Frame(34, 40, A4[0] - 68, A4[1] - 70, id="body")
        doc.addPageTemplates([PageTemplate(id="all", frames=[frame],
                                           onPage=self.footer)])
        doc.build(story)
        return self.path

    def footer(self, canv, doc):
        canv.saveState()
        try:
            canv.setStrokeColor(hx(LINE))
            canv.setLineWidth(0.5)
            canv.line(34, 32, A4[0] - 34, 32)
            canv.setFont(FA_REG, 6.4)
            canv.setFillColor(hx(FAINT))
            canv.drawString(34, 24, fs("%s %d" % (UI["page"],
                                                  canv.getPageNumber())))
            canv.setFont("Helvetica", 6.2)
            canv.drawRightString(A4[0] - 34, 24,
                                 "%s  |  %s  |  %s"
                                 % (self.meta.get("tool", ""),
                                    self.meta.get("domain", ""),
                                    self.meta.get("audit_date", "")))
        finally:
            canv.restoreState()


def port_state_fa(state):
    s = str(state or "").lower()
    if s.startswith("open"):
        return UI["open"]
    if s.startswith("filter"):
        return UI["filtered"]
    return UI["closed"]


def port_sev_fa(port):
    try:
        sev = RISK_PORTS.get(int(port), ("", ""))[0]
    except Exception:
        sev = ""
    return SEV_FA.get(sev, "-") if sev else "-"
