#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

python3 - <<'EOF'
import re, subprocess, sys
files = subprocess.run(
    ["git", "grep", "-I", "--name-only", "-E",
     r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "--", "."],
    capture_output=True, text=True, check=True).stdout.split()
ip = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})")
def allowed(a, b, c, d):
    if (a, b, c, d) == (0, 0, 0, 0) or (a, b, c, d) == (255, 255, 255, 255):
        return True
    if a == 127 or a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if (a, b) in ((192, 0), (198, 51), (203, 0)) and (
        (c == 2 and a == 192) or (c == 100 and a == 198) or (c == 113 and a == 203)):
        return True
    return False
bad = 0
for f in files:
    try:
        text = open(f, encoding="utf-8", errors="strict").read()
    except (UnicodeError, OSError):
        continue
    for n, line in enumerate(text.splitlines(), 1):
        for m in ip.finditer(line):
            a, b, c, d = (int(m.group(i)) for i in range(1, 5))
            if not all(x <= 255 for x in (a, b, c, d)):
                continue
            if not allowed(a, b, c, d):
                print(f"::error::{f}:{n}: routable IPv4 literal {m.group(0)} — use TEST-NET (192.0.2.0/24)")
                bad += 1
sys.exit(1 if bad else 0)
EOF

if git grep -I -n -E '(vless|vmess|trojan|ss)://[^@#? ]+@[^/:?# ]+' -- . \
  | grep -v -E '@(\[::1\]|(127|10)\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]{1,3}|localhost|example\.[a-z]+|[A-Za-z0-9.-]+\.(test|invalid|localhost)|uuid|host|\{host\})([:/?#]|$)' \
  | grep -v '^Binary'; then
  echo "::error::share-link with a non-documentation host — working configs arrive as masked CI input only"
  status=1
fi

if git grep -I -n -E -e '-----BEGIN .*PRIVATE KEY-----' -- . ':!scripts/check-fixture-safety.sh'; then
  echo "::error::private key block in the tree — test material is generated at runtime"
  status=1
fi

exit "$status"
