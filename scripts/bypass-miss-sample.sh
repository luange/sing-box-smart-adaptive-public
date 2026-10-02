#!/bin/sh
# Sample recent userspace destinations from connection history.
# Usage on 115: sh bypass-miss-sample.sh [limit]
set -eu
LIMIT="${1:-40}"
API="${API:-http://127.0.0.1:9090}"
TMP="${TMPDIR:-/tmp}/sb-hist-sample.json"
echo "=== top destinations via userspace (history, limit=$LIMIT) ==="
curl -sS -m 8 "$API/history/connections?limit=$LIMIT" -o "$TMP"
python3 - "$TMP" <<'PY'
import json,sys,collections
path=sys.argv[1]
with open(path) as f:
    data=json.load(f)
rows=data.get("data") or data.get("connections") or []
ctr=collections.Counter()
directish=0
for r in rows:
    ip=r.get("destinationIP") or ""
    dom=r.get("domain") or ""
    ob=r.get("outbound") or ""
    chain=r.get("chain") or []
    leaf=(chain[0] if chain else ob)
    key=f"{ip}\t{dom}\t{leaf}"
    ctr[key]+=1
    lo=str(leaf).lower()
    if lo in ("direct","ebpf","ebpf-out") or str(ob).upper()=="DIRECT":
        directish+=1
print(f"rows={len(rows)} directish_leaf={directish}")
print("--- top ---")
for k,c in ctr.most_common(25):
    print(f"{c:4d}  {k}")
print("""
Note: under PBR+geoip bypass, DIRECT leaf rows are miss candidates.
Proxy leaves (airport/*) are expected. Check kernel logs:
  grep 'bypass miss sample\\|gap self-heal' /var/log/singbox/singbox.err | tail
""")
PY
