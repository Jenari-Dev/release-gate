"""Dynamic repro probes used by the eval runner (and by phase-03 as reference repros).

Each probe actually exercises a running fixture over loopback HTTP and reports
what it *observed*, not what the answer key says. A probe returns a finding/check
entry (finding.schema.json) or None. Evidence is written under the project's
.release-gate/evidence/. Stdlib only.

These are scoped to the eval fixtures' documented endpoints. For a real target,
phase-03 has you write the equivalent repro per SUSPECTED item; these are the
worked examples.
"""
from __future__ import annotations

import concurrent.futures
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills" / "release-gate" / "scripts"))
import rglib  # noqa: E402

TIMEOUT = 8
HASH_RE = re.compile(r"[0-9a-f]{32,}|\$?scrypt|[A-Za-z0-9+/]{40,}={0,2}")


def _req(method, url, *, headers=None, data=None, ctype=None):
    r = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if ctype:
        r.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(r, timeout=TIMEOUT) as resp:  # noqa: S310 (loopback)
            return resp.status, resp.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(16384).decode("utf-8", "replace") if e.fp else "")
    except (urllib.error.URLError, OSError) as e:
        return 0, f"<transport error: {type(e).__name__}>"


def login(base, username, password, encoding="form", path="/login", token_field="token"):
    url = base.rstrip("/") + path
    if encoding == "json":
        st, body = _req("POST", url, data=json.dumps({"username": username, "password": password}).encode(),
                        ctype="application/json")
    else:
        st, body = _req("POST", url, data=urllib.parse.urlencode({"username": username, "password": password}).encode(),
                        ctype="application/x-www-form-urlencoded")
    if st // 100 != 2:
        return None
    try:
        return json.loads(body).get(token_field)
    except (json.JSONDecodeError, AttributeError):
        return None


def _save(state: Path, name: str, text: str) -> str:
    rel = Path("evidence") / "dynamic" / name
    dest = state / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(rglib.redact_text(text), encoding="utf-8")
    return str(rel)


def _finding(fid, check_id, category, severity, title, cls, state, evname, evtext, **kw):
    entry = {
        "id": fid, "kind": "finding", "check_id": check_id, "category": category,
        "title": title, "severity": severity, "evidence_class": cls, "phase": 3,
        "created_at": rglib.now_iso(),
    }
    if cls in ("EXPLOITED", "VERIFIED-ABSENT"):
        entry["evidence"] = [{"type": "request-response", "path": _save(state, evname, evtext)}]
    else:
        entry["evidence"] = []
    if cls == "VERIFIED-ABSENT":
        entry["kind"] = "check"
        entry.pop("severity", None)
    if cls in ("EXPLOITED",) and severity in ("critical", "high"):
        entry["adversarial"] = {"required": True, "outcome": "not-run"}
    entry.update(kw)
    return entry


def _check_absent(check_id, category, title, state, evname, evtext, adversarial=False):
    entry = {"id": f"RG-{category.upper().replace('-', '')}-900", "kind": "check", "check_id": check_id,
             "category": category, "title": title, "evidence_class": "VERIFIED-ABSENT", "phase": 3,
             "evidence": [{"type": "request-response", "path": _save(state, evname, evtext)}],
             "created_at": rglib.now_iso()}
    if adversarial:
        entry["adversarial"] = {"required": True, "outcome": "not-run"}
    return entry


# --------------------------------------------------------------------------- probes

def probe_sqli(base, state, search_path="/api/search"):
    payload = "zzz' UNION SELECT id,username,password_hash FROM users-- -"
    url = base.rstrip("/") + search_path + "?" + urllib.parse.urlencode({"q": payload})
    st, body = _req("GET", url)
    leaked = st == 200 and bool(re.search(r"[0-9a-f]{40,}|scrypt|[A-Za-z0-9+/]{40,}={0,2}", body)) and "password" not in body[:0]
    looks_like_hash = st == 200 and bool(re.search(r"\b[0-9a-f]{32,}\b|scrypt:", body))
    txt = f"GET {url}\n-> HTTP {st}\n{body[:1500]}"
    if looks_like_hash:
        return _finding("RG-INJECTION-901", "SEC-INJECTION-DYNAMIC", "injection", "critical",
                        "SQL injection: UNION query returns other tables' data", "EXPLOITED", state,
                        "sqli_union.txt", txt, cwe=["CWE-89"],
                        impact="An attacker can read any table (here, user password hashes) by injecting SQL through the search query.",
                        repro=f"GET {search_path}?q=<UNION SELECT ... FROM users>; observed password-hash material in the response.",
                        fix="Use parameterised queries / prepared statements; never interpolate input into SQL.")
    return _check_absent("SEC-INJECTION-DYNAMIC", "injection",
                         "SQL injection UNION payload returned no out-of-scope data", state, "sqli_union_absent.txt", txt,
                         adversarial=True)


def probe_ssrf(base, state, token, internal_url, canary):
    url = base.rstrip("/") + "/api/fetch-preview?" + urllib.parse.urlencode({"url": internal_url})
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    st, body = _req("GET", url, headers=headers)
    txt = f"GET {url}\n-> HTTP {st}\n{body[:1500]}"
    if st == 200 and canary in body:
        return _finding("RG-SSRF-901", "SEC-SSRF-DYNAMIC", "ssrf", "high",
                        "SSRF: server fetches attacker-supplied internal URL", "EXPLOITED", state, "ssrf.txt", txt,
                        cwe=["CWE-918"],
                        impact="An attacker can make the server fetch internal-only URLs (cloud metadata, internal services) and read the response.",
                        repro=f"GET /api/fetch-preview?url={internal_url}; observed internal-only canary in the response.",
                        fix="Allowlist destination hosts, resolve and reject private IPs, disable redirects.")
    return _check_absent("SEC-SSRF-DYNAMIC", "ssrf", "SSRF to internal URL blocked", state, "ssrf_absent.txt", txt)


def probe_rate_limit(base, state, username, encoding="form", attempts=12):
    codes = []
    for i in range(attempts):
        if encoding == "json":
            st, _ = _req("POST", base.rstrip("/") + "/login",
                         data=json.dumps({"username": username, "password": f"wrong-guess-{i}"}).encode(),
                         ctype="application/json")
        else:
            st, _ = _req("POST", base.rstrip("/") + "/login",
                         data=urllib.parse.urlencode({"username": username, "password": f"wrong-guess-{i}"}).encode(),
                         ctype="application/x-www-form-urlencoded")
        codes.append(st)
    txt = f"{attempts} wrong-password POST /login for {username}\nstatus codes: {codes}"
    if 429 not in codes:
        return _finding("RG-RATELIMIT-901", "SEC-AUTHN-BRUTEFORCE", "rate-limit", "high",
                        "No brute-force protection on login", "EXPLOITED", state, "rate_limit.txt", txt,
                        cwe=["CWE-307"],
                        impact="Login accepts unlimited password guesses with no lockout or rate limit, enabling credential stuffing and brute force.",
                        repro=f"Sent {attempts} wrong-password logins for {username}; observed {codes.count(401)}x 401 and never 429.",
                        fix="Rate-limit by IP+username, add lockout/backoff, and a Retry-After header.")
    return _check_absent("SEC-AUTHN-BRUTEFORCE", "rate-limit", "Login rate-limited after repeated failures", state,
                         "rate_limit_absent.txt", txt, adversarial=True)


def probe_credential_log(state, log_path: Path, submitted_passwords):
    """Grep the app log (populated by probe_rate_limit) for any submitted password."""
    if not log_path.exists():
        return {"id": "RG-LOGGING-901", "kind": "check", "check_id": "OPS-LOG-HYGIENE", "category": "logging",
                "title": "Credential logging", "evidence_class": "NOT-TESTED",
                "not_tested_reason": f"log file not found: {log_path.name}", "evidence": [], "phase": 3}
    text = log_path.read_text(encoding="utf-8", errors="replace")
    hits = [p for p in submitted_passwords if p in text]
    if hits:
        # redact the matched secret in the evidence we save
        sample = "\n".join(ln for ln in text.splitlines() if any(p in ln for p in hits))[:1500]
        ev = _save(state, "credential_in_log.txt",
                   "app log lines containing a submitted password (redacted):\n" + re.sub("|".join(map(re.escape, hits)), "***PW***", sample))
        return {"id": "RG-LOGGING-901", "kind": "finding", "check_id": "OPS-LOG-HYGIENE", "category": "logging",
                "title": "Submitted passwords written to the application log", "severity": "high",
                "evidence_class": "EXPLOITED", "phase": 3, "cwe": ["CWE-532"],
                "impact": "Plaintext passwords appear in logs; anyone who can read logs harvests live credentials.",
                "repro": "Submitted wrong-password logins, then found the exact submitted passwords in logs/app.log.",
                "fix": "Never log credentials; log only the username and outcome.",
                "evidence": [{"type": "log", "path": ev}],
                "adversarial": {"required": True, "outcome": "not-run"}, "created_at": rglib.now_iso()}
    return _check_absent("OPS-LOG-HYGIENE", "logging", "No submitted password found in the application log", state,
                         "credential_in_log_absent.txt", "scanned app log; none of the submitted passwords were present")


def probe_deletion(base, state, encoding="form"):
    import secrets as _s
    uname = "evaluser_" + _s.token_hex(4)
    pw = "del-" + _s.token_hex(6)
    st, body = _req("POST", base.rstrip("/") + "/api/register",
                    data=json.dumps({"username": uname, "password": pw, "email": f"{uname}@fixture.test"}).encode(),
                    ctype="application/json")
    if st // 100 != 2:
        return {"id": "RG-DELETION-901", "kind": "check", "check_id": "PRIV-RIGHTS-TESTED", "category": "deletion",
                "title": "Account deletion", "evidence_class": "NOT-TESTED",
                "not_tested_reason": f"could not register a test user (HTTP {st})", "evidence": [], "phase": 7}
    token = login(base, uname, pw, encoding=encoding)
    st_del, _ = _req("DELETE", base.rstrip("/") + "/api/account",
                     headers={"Authorization": f"Bearer {token}"} if token else {})
    token2 = login(base, uname, pw, encoding=encoding)
    txt = f"registered {uname}; DELETE /api/account -> HTTP {st_del}; re-login after delete -> {'SUCCESS' if token2 else 'denied'}"
    if token2:
        return _finding("RG-DELETION-901", "PRIV-RIGHTS-TESTED", "deletion", "high",
                        "Account deletion does not erase the account", "EXPLOITED", state, "deletion.txt", txt,
                        phase=7,
                        impact="The delete endpoint returns success but the account and its data remain; a 'right to erasure' claim is false.",
                        repro="Registered a user, called DELETE /api/account (200), then logged in again successfully.",
                        fix="Actually delete the user's rows (and dependent data) in the delete handler, inside a transaction.")
    entry = _check_absent("PRIV-RIGHTS-TESTED", "deletion", "Deleted account can no longer authenticate", state,
                          "deletion_absent.txt", txt)
    entry["phase"] = 7
    return entry


def probe_analytics_beacon(base, state, username, password, sink_events_url, sink_reset_url=None, encoding="form"):
    """Confirm the app actually transmits user data to a telemetry host (upgrades a
    policy 'we never share' mismatch to EXPLOITED)."""
    if sink_reset_url:
        _req("POST", sink_reset_url)
    login(base, username, password, encoding=encoding)
    import time
    time.sleep(0.8)
    st, body = _req("GET", sink_events_url)
    received = st == 200 and (username in body or "login" in body)
    txt = f"triggered login for {username}; GET {sink_events_url} -> HTTP {st}\n{body[:1200]}"
    if received:
        return _finding("RG-POLICYMISMATCH-900", "LEGAL-POLICY-CONSISTENCY", "policy-mismatch", "high",
                        "App sends user data to a third-party analytics host (contradicts the privacy policy)",
                        "EXPLOITED", state, "analytics_beacon.txt", txt, phase=7,
                        impact="Login/signup events with user identifiers are transmitted to an analytics vendor, while the policy says data is never shared.",
                        repro=f"Triggered a login and observed the event (with user data) arrive at the analytics sink {sink_events_url}.",
                        fix="Either stop sending data to the analytics host, or change the policy to disclose it with a lawful basis.")
    entry = _check_absent("LEGAL-POLICY-CONSISTENCY", "policy-mismatch",
                          "No user data observed reaching the analytics sink", state, "analytics_beacon_absent.txt", txt)
    entry["phase"] = 7
    return entry


def probe_error_leaks(base, state):
    """Trigger server errors and check the response leaks no stack trace, SQL or path."""
    probes_urls = ["/api/messages/not-an-int", "/api/messages/999999999999999999999",
                   "/api/search?q=%ff%00", "/api/fetch-preview?url=::::"]
    leaked = []
    sample = []
    for path in probes_urls:
        st, body = _req("GET", base.rstrip("/") + path)
        sample.append(f"GET {path} -> {st}: {body[:200]}")
        if re.search(r"Traceback \(most recent call last\)|at /.+:\d+:\d+|File \"/|SQL(ite)? error|psycopg|sqlalchemy|/home/|/usr/lib/|node_modules/", body):
            leaked.append(path)
    txt = "\n".join(sample)
    if leaked:
        return _finding("RG-DATAEXPOSURE-901", "SEC-ERROR-LEAKS", "data-exposure", "medium",
                        "Error responses leak internal details", "EXPLOITED", state, "error_leaks.txt", txt,
                        impact="Error responses expose stack traces / internal paths / SQL, helping an attacker map the system.",
                        repro=f"Requests to {leaked} returned internal detail in the error body.",
                        fix="Return generic error messages; log the detail server-side only.")
    return _check_absent("SEC-ERROR-LEAKS", "data-exposure", "Error responses leak no stack trace, SQL or path",
                         state, "error_leaks_absent.txt", txt, adversarial=True)


def probe_enumeration(base, state, known_user, encoding="form"):
    """Compare responses for an unknown user vs a known user with a wrong password."""
    def _attempt(u):
        if encoding == "json":
            return _req("POST", base.rstrip("/") + "/login",
                        data=json.dumps({"username": u, "password": "definitely-wrong"}).encode(), ctype="application/json")
        return _req("POST", base.rstrip("/") + "/login",
                    data=urllib.parse.urlencode({"username": u, "password": "definitely-wrong"}).encode(),
                    ctype="application/x-www-form-urlencoded")
    st_known, b_known = _attempt(known_user)
    st_unknown, b_unknown = _attempt("nosuchuser_zzz_" + "q")
    txt = f"known-user wrong pw -> {st_known}: {b_known[:150]}\nunknown-user -> {st_unknown}: {b_unknown[:150]}"
    if st_known != st_unknown or (b_known[:120] != b_unknown[:120]):
        return _finding("RG-AUTHN-902", "SEC-AUTHN-ENUMERATION", "authn", "medium",
                        "Login responses let an attacker tell valid usernames apart", "EXPLOITED", state,
                        "enumeration.txt", txt,
                        impact="Different responses for known vs unknown usernames let an attacker enumerate valid accounts.",
                        repro="A wrong password for a real user and a login for a non-existent user returned different responses.",
                        fix="Return an identical response and timing whether or not the username exists.")
    return _check_absent("SEC-AUTHN-ENUMERATION", "authn", "Login response identical for known and unknown users",
                         state, "enumeration_absent.txt", txt, adversarial=True)


def probe_coupon_race(base, state, token, code="WELCOME10", n=10):
    def redeem(_):
        return _req("POST", base.rstrip("/") + "/api/coupons/redeem",
                    data=json.dumps({"code": code}).encode(), ctype="application/json",
                    headers={"Authorization": f"Bearer {token}"} if token else {})
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(redeem, range(n)))
    successes = sum(1 for st, _ in results if st // 100 == 2)
    txt = f"{n} concurrent POST /api/coupons/redeem {{code:{code}}} -> {successes} succeeded, codes={[st for st,_ in results]}"
    if successes > 1:
        return _finding("RG-RACE-901", "COR-RACE", "race", "high",
                        "Race condition: single-use coupon redeemed multiple times", "EXPLOITED", state,
                        "coupon_race.txt", txt, phase=4, cwe=["CWE-362"],
                        impact="Concurrent requests redeem a single-use coupon many times (check-then-write with no lock), so limits can be bypassed.",
                        repro=f"Fired {n} concurrent redeems of a max-uses-1 coupon; observed {successes} successes.",
                        fix="Use an atomic conditional update (UPDATE ... WHERE uses < max) or a transaction/row lock.")
    entry = _check_absent("COR-RACE", "race", "Single-use coupon survived concurrent redemption", state,
                          "coupon_race_absent.txt", txt)
    entry["phase"] = 4
    return entry
