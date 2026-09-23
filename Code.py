# ---------------------------------------------------------------------------
#  SiteAuditor v4.0 - one-paste installer for Termux / Android (no root)
# ---------------------------------------------------------------------------
#  Paste this whole block into Termux and press Enter. It will:
#    1. locate the three modules (audit2.py engine + English report,
#       sitefa.py Persian renderer, siteaudit.py bilingual CLI) or download
#       the ones it cannot find
#    2. install the Python packages with pip, including the two small
#       shaping libraries the Persian report needs
#    3. syntax-check every module so a truncated copy cannot pass silently
#    4. install them under $PREFIX/lib/sitest and put `audit` on your PATH
#
#  After it finishes:
#      audit example.com                    # English + Persian reports
#      audit example.com --lang fa          # Persian only
#      audit example.com --lang en          # English only
#      audit example.com --json out.json    # keep machine-readable results
#      audit example.com --full-ports       # wider port list
#      audit --render-json out.json         # rebuild both PDFs offline
#
#  Reports are written to $HOME/storage/shared/sitest when storage access has
#  been granted (termux-setup-storage), otherwise to $HOME/sitest.
#
#  Persian PDF font: taken from /system/fonts (Android ships Noto Naskh
#  Arabic). If your device has none, drop any Arabic-capable TTF such as
#  Vazirmatn-Regular.ttf into ~/.sitest/fonts/ or set SITEST_FA_FONT.
# ---------------------------------------------------------------------------

REPO_RAW="https://raw.githubusercontent.com/twparsa00-lab/Code-pdf/main"
BINDIR="${PREFIX:-$HOME/.local}/bin"
LIBDIR="${PREFIX:-$HOME/.local}/lib/sitest"

# --- 1. locate the modules --------------------------------------------------
find_or_get () {
  _name="$1"
  for _c in "./$_name" "$HOME/$_name" "$HOME/sitest/$_name" \
            "$LIBDIR/$_name"; do
    if [ -f "$_c" ]; then echo "$_c"; return 0; fi
  done
  echo "[+] $_name not found locally, downloading it..." >&2
  mkdir -p "$HOME/sitest" 2>/dev/null
  _dest="$HOME/sitest/$_name"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$REPO_RAW/$_name" -o "$_dest" 2>/dev/null || _dest=""
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$_dest" "$REPO_RAW/$_name" 2>/dev/null || _dest=""
  else
    _dest=""
  fi
  if [ -n "$_dest" ] && [ -s "$_dest" ]; then echo "$_dest"
  else echo ""; fi
}

ENG="$(find_or_get audit2.py)"
FA="$(find_or_get sitefa.py)"
CLI="$(find_or_get siteaudit.py)"

if [ -z "$ENG" ]; then
  echo "x could not obtain audit2.py"
  echo "  copy it into the current directory and run this block again, or"
  echo "  install curl first:  pkg install curl"
  exit 1
fi
echo "[+] engine:  $ENG"
[ -n "$FA" ] && echo "[+] persian: $FA"
[ -n "$CLI" ] && echo "[+] cli:     $CLI"
if [ -z "$FA" ] || [ -z "$CLI" ]; then
  echo "! bilingual modules missing - falling back to the English-only CLI."
  echo "  copy sitefa.py and siteaudit.py next to audit2.py and re-run."
fi

# --- 2. python and dependencies --------------------------------------------
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "x python3 is missing - run:  pkg install python"
  exit 1
fi
echo "[+] $($PY -V 2>&1)"

echo "[+] installing core packages (requests, reportlab, shaping)..."
if ! "$PY" -m pip install --quiet --upgrade requests reportlab \
     arabic-reshaper python-bidi; then
  echo "    retrying with --user..."
  "$PY" -m pip install --quiet --user --upgrade requests reportlab \
    arabic-reshaper python-bidi || {
      echo "x pip failed. On Termux run:  pkg install python"
      echo "  then re-run this block."
      exit 1
    }
fi

if ! "$PY" -m pip install --quiet --upgrade dnspython certifi cryptography \
     2>/dev/null; then
  echo "    note: optional extras (dnspython / certifi / cryptography) not"
  echo "    installed - DNS checks and deep certificate detail will be reduced."
fi

# --- 3. syntax check --------------------------------------------------------
if ! "$PY" - "$ENG" "$FA" "$CLI" <<'PYCHECK'
import ast, sys, os

req = {
    "audit2.py": ("def main(", "class Report"),
    "sitefa.py": ("def ensure_fa(", "class ReportFA"),
    "siteaudit.py": ("def main(", "render("),
}
for path in sys.argv[1:]:
    if not path or not os.path.exists(path):
        continue
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    ast.parse(src)                      # raises on a truncated copy
    need = req.get(os.path.basename(path))
    if need:
        for marker in need:
            if marker not in src:
                raise SystemExit("%s is missing required section %r"
                                 % (path, marker))
PYCHECK
then
  echo "x a module failed the syntax check - one of the copies looks truncated."
  echo "  Re-copy the whole file and run this block again."
  exit 1
fi
echo "[+] syntax check passed"

# --- 4. install -------------------------------------------------------------
mkdir -p "$LIBDIR" 2>/dev/null
if ! cp -f "$ENG" "$LIBDIR/audit2.py" 2>/dev/null; then
  echo "x cannot write to $LIBDIR"
  exit 1
fi
[ -n "$FA" ] && cp -f "$FA" "$LIBDIR/sitefa.py" 2>/dev/null
[ -n "$CLI" ] && cp -f "$CLI" "$LIBDIR/siteaudit.py" 2>/dev/null

mkdir -p "$BINDIR" 2>/dev/null
if [ -f "$LIBDIR/siteaudit.py" ] && [ -f "$LIBDIR/sitefa.py" ]; then
  cat > "$BINDIR/audit" <<LAUNCH
#!/bin/sh
# SiteAuditor v4.0 launcher - bilingual (English + Persian) reports
PYTHONPATH="$LIBDIR\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHONPATH
PYBIN="\$(command -v python3 || command -v python)"
exec "\$PYBIN" "$LIBDIR/siteaudit.py" "\$@"
LAUNCH
else
  cp -f "$ENG" "$BINDIR/audit"
fi
if ! chmod 755 "$BINDIR/audit" 2>/dev/null; then
  echo "x cannot write to $BINDIR"
  exit 1
fi
hash -r 2>/dev/null || true

case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) echo "! $BINDIR is not on PATH. Add it permanently with:"
     echo "      echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.bashrc" ;;
esac

echo ""
echo "v installed: $BINDIR/audit   (modules in $LIBDIR)"
echo ""
echo "  audit example.com                    # English + Persian reports"
echo "  audit example.com --lang fa          # Persian only"
echo "  audit example.com --lang en          # English only"
echo "  audit example.com --json out.json    # machine-readable results"
echo "  audit example.com --full-ports       # wider port list"
echo "  audit example.com --no-ports         # quiet config-only pass"
echo "  audit --render-json out.json         # rebuild the PDFs offline"
echo "  audit --help                         # every option"
echo ""
if [ -d "$HOME/storage/shared" ]; then
  echo "  reports -> $HOME/storage/shared/sitest"
else
  echo "  reports -> $HOME/sitest   (run 'termux-setup-storage' once to use"
  echo "             shared storage and see the PDFs in your gallery/file app)"
fi
echo "  Persian PDF font comes from /system/fonts; if none is found, copy an"
echo "  Arabic TTF (Vazirmatn-Regular.ttf) into ~/.sitest/fonts/."
echo "  use this tool only against sites you own or are authorised to test."
