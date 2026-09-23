#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SiteAuditor v4.0 - bilingual entry point (English + Persian).

One scan, two reports:

    <target>_audit_<ts>_en.pdf    English, LTR
    <target>_audit_<ts>_fa.pdf    Persian, RTL, shaped and right aligned

The scanning engine, the scoring model and the English renderer live in
audit2.py; sitefa.py holds the Persian renderer. This module is only the CLI
that runs the audit once and hands the same result set to both renderers, so
the two documents can never disagree.

Termux / Android, no root:
    pip install requests reportlab arabic-reshaper python-bidi
Optional extras:
    pip install dnspython certifi cryptography

  audit example.com                  # both reports (default)
  audit example.com --lang fa        # Persian only
  audit example.com --lang en        # English only
  audit example.com --json out.json  # keep machine-readable results
  audit --render-json out.json       # rebuild both reports offline
"""
import argparse
import json
import os
import sys
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE,
           os.path.join(os.path.expanduser("~"), "sitest"),
           os.path.join(os.environ.get("PREFIX") or "", "lib", "sitest"),
           os.path.dirname(os.path.abspath(sys.argv[0]))):
    if _p and os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import audit2
    import sitefa
except ImportError as exc:
    sys.exit("Missing SiteAuditor module: %s\n"
             "Keep audit2.py, sitefa.py and siteaudit.py in the same "
             "directory, or re-run Code.py." % exc)


# --------------------------------------------------------------------- paths
def pick_paths(base, lang, explicit):
    """Map a language choice onto output file names."""
    stem, ext = os.path.splitext(base)
    ext = ext or ".pdf"
    if lang == "both":
        if explicit:
            return {"en": base, "fa": stem + "_fa" + ext}
        return {"en": stem + "_en" + ext, "fa": stem + "_fa" + ext}
    return {lang: base}


def render(data, lang, base, explicit=False):
    """Render the requested reports; returns {lang: path} for what succeeded."""
    made, plan = {}, pick_paths(base, lang, explicit)
    if "en" in plan:
        try:
            audit2.Report(data, plan["en"]).build()
            made["en"] = plan["en"]
        except Exception as exc:
            sys.stderr.write("English PDF failed: %s\n" % exc)
    if "fa" in plan:
        ok, detail = sitefa.ensure_fa()
        if not ok:
            sys.stderr.write(
                "Persian PDF skipped: %s\n"
                "  fix: pip install arabic-reshaper python-bidi\n"
                "       and put an Arabic-capable TTF in ~/.sitest/fonts/\n"
                % detail)
        else:
            try:
                sitefa.ReportFA(data, plan["fa"]).build()
                made["fa"] = plan["fa"]
            except Exception as exc:
                sys.stderr.write("Persian PDF failed: %s\n" % exc)
    return made


# ------------------------------------------------------------------ summary
def summary(res, made, lang="both"):
    m, sc = res["meta"], res["score"]
    total = sc.get("total", 0)
    col = (audit2.CLR["grn"] if total >= 80 else audit2.CLR["cyn"]
           if total >= 70 else audit2.CLR["yel"] if total >= 55
           else audit2.CLR["red"])
    bar = "=" * 66
    print("\n%s%s%s" % (audit2.CLR["cyn"], bar, audit2.CLR["r"]))
    print("  %s%s%s" % (audit2.CLR["b"], m["domain"], audit2.CLR["r"]))
    print("  score    %s%s%d/100  grade %s%s   risk index %.0f"
          % (audit2.CLR["b"], col, total, sc.get("grade"),
             audit2.CLR["r"], sc.get("risk", 0)))
    counts = sc.get("counts", {})
    print("  findings " + ", ".join(
        "%s%d %s%s" % (audit2.CLR["b"], counts.get(s, 0), s, audit2.CLR["r"])
        for s in audit2.SEV_ORDER if counts.get(s)))
    for name, val in (sc.get("categories") or {}).items():
        print("    %-20s %5.1f" % (name, val))
    print("  surface  %d ports open, %d subdomains, %d exposed files, "
          "%d cookies"
          % (len(res.get("open_ports", [])), len(res.get("subdomains", [])),
             len(res.get("exposed", [])), len(res.get("cookies", []))))
    top = [f for f in res.get("findings", [])
           if f["severity"] in ("CRITICAL", "HIGH")][:6]
    if top:
        print("  top risks")
        for f in top:
            print("    %s%-8s%s %-20s %s"
                  % (audit2.CLR["red"] if f["severity"] == "CRITICAL"
                     else audit2.CLR["yel"],
                     f["severity"], audit2.CLR["r"], f["id"],
                     audit2.cut(f["title"], 58)))
    labels = {"en": "report EN", "fa": "report FA"}
    want = ["en", "fa"] if lang == "both" else [lang]
    for key in want:
        if key in made:
            print("  %-9s %s" % (labels[key], made[key]))
    missing = [k for k in want if k not in made]
    if missing:
        print("  %-9s not produced (%s)" % ("missing", ", ".join(missing)))
    print("%s%s%s" % (audit2.CLR["cyn"], bar, audit2.CLR["r"]))
    sys.stdout.flush()


# ---------------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="audit",
        description="SiteAuditor - bilingual web security and exposure audit "
                    "(English + Persian reports)")
    ap.add_argument("target", nargs="?", help="domain or URL, e.g. example.com")
    ap.add_argument("--lang", choices=("en", "fa", "both"), default="both",
                    help="which report(s) to build (default: both)")
    ap.add_argument("--json", metavar="PATH", help="also write raw results as JSON")
    ap.add_argument("--pdf", metavar="PATH",
                    help="report path; with --lang both the Persian report "
                         "gets an _fa suffix")
    ap.add_argument("--render-json", metavar="PATH",
                    help="render reports from a saved JSON file, no network")
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
                    version="%s %s (bilingual)" % (audit2.TOOL, audit2.VERSION))
    args = ap.parse_args(argv)
    explicit = bool(args.pdf)
    if args.no_color:
        audit2.no_color()

    if args.render_json:
        try:
            with open(args.render_json, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            sys.stderr.write("Cannot read %s: %s\n" % (args.render_json, exc))
            return 3
        base = args.pdf or os.path.join(
            audit2.out_dir(),
            "%s_audit_%s.pdf" % (data.get("meta", {}).get("domain", "report"),
                                 datetime.now().strftime("%Y%m%d_%H%M")))
        made = render(data, args.lang, base, explicit)
        summary(data, made, args.lang)
        return 0 if made else 3

    target = args.target or input(
        "Enter target domain (e.g. example.com): ").strip()
    if not target:
        sys.stderr.write("No target provided.\n")
        return 1

    log = audit2.Log(args.quiet)
    if args.lang in ("both", "fa"):
        log.step("Bilingual output: %s"
                 % {"both": "English + Persian", "fa": "Persian only",
                    "en": "English only"}[args.lang])
    auditor = audit2.SiteAuditor(target, timeout=args.timeout,
                                 threads=args.threads,
                                 do_ports=not args.no_ports,
                                 do_subs=not args.no_subdomains,
                                 full_ports=args.full_ports, log=log)
    res = auditor.run_audit()
    base = args.pdf or os.path.join(
        audit2.out_dir(),
        "%s_audit_%s.pdf" % (res["meta"]["domain"],
                             datetime.now().strftime("%Y%m%d_%H%M")))
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(res, fh, indent=1, ensure_ascii=False)
        except Exception as exc:
            sys.stderr.write("Cannot write %s: %s\n" % (args.json, exc))
    made = render(res, args.lang, base, explicit)
    summary(res, made, args.lang)
    return 0 if res["meta"].get("reachable") else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(130)
