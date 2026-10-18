#!/usr/bin/env python3
"""Measure release-gate against the eval fixtures and print a scores table.

For each fixture it boots the app on loopback (waiting on the port), runs the
phase-1/2/3/7/8 pipeline that exists today (static scanners against a temp copy
of the source, the authorization matrix, the dynamic repro probes, the cookie
audit, the data inventory and policy-consistency check), builds the report and
verdict, then scores the result against the fixture's answer-key.yaml:

  * detection rate per planted category,
  * evidence-class correctness (a planted IDOR must come out EXPLOITED, not SUSPECTED),
  * false-positive rate on the clean twins,
  * verdict correctness,
  * the honesty cases (app won't start; no tools on PATH) must NOT produce a pass.

Nothing here reads the answer key before producing findings: the probes observe
the running app and report what they saw. Run from the repo root:

    uv run --no-project --with pyyaml --with jsonschema python evals/run_evals.py
    uv run ... python evals/run_evals.py --only vuln-node-express --keep
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "release-gate"
SCRIPTS = SKILL / "scripts"
FIXTURES = REPO / "evals" / "fixtures"
SHARE = Path(os.path.expanduser("~/.local/share/release-gate"))
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import rglib  # noqa: E402
import authz_matrix  # noqa: E402
import data_inventory_scan  # noqa: E402
import policy_consistency  # noqa: E402
import report_build  # noqa: E402
import probes  # noqa: E402
import extract_routes  # noqa: E402
import discovery  # noqa: E402

CLASS_RANK = {"NOT-TESTED": 0, "SUSPECTED": 1, "VERIFIED-ABSENT": 1, "TOOL-CONFIRMED": 2, "EXPLOITED": 3}
SEMGREP_ENV = {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
EXCLUDE_COPY = {"node_modules", ".venv", "logs", "__pycache__", ".release-gate", ".git"}


# --------------------------------------------------------------------------- fixture plans

def _plan():
    """Per-fixture eval plan. Ports/endpoints come from the fixtures' READMEs."""
    return {
        "vuln-node-express": dict(port=3101, boot="vuln-node-express", encoding="json",
                                  users=[("alice", "alice-fixture-pw"), ("bob", "bob-fixture-pw")],
                                  authz_owned={"alice": [1], "bob": [2]}, canary="CANARY",
                                  internal="http://127.0.0.1:3191/latest/meta-data/", ssrf_canary="SSRF-CANARY-7f3a91c2-internal-only",
                                  sca_lockfile="package-lock.json", sast_lang="javascript",
                                  coupon=True, xss=True, expected_verdict="BLOCK"),
        "clean-node-express": dict(port=3102, boot="clean-node-express", encoding="json",
                                   users=[("alice", "alice-fixture-pw"), ("bob", "bob-fixture-pw")],
                                   authz_owned={"alice": [1], "bob": [2]}, canary="CANARY",
                                   internal="http://127.0.0.1:3192/latest/meta-data/", ssrf_canary="SSRF-CANARY-7f3a91c2-internal-only",
                                   sca_lockfile="package-lock.json", sast_lang="javascript",
                                   coupon=True, xss=True, clean=True, expected_verdict="SHIP"),
        "vuln-python-fastapi": dict(port=3103, boot="vuln-python-fastapi", encoding="form",
                                    users=[("alice", "alice-fixture-pw"), ("bob", "bob-fixture-pw")],
                                    authz_owned={"alice": [1], "bob": [2]}, canary="CANARY",
                                    internal="http://127.0.0.1:3193/latest/meta-data/", ssrf_canary="SSRF-CANARY-7f3a91c2-internal-only",
                                    analytics_events="http://127.0.0.1:3163/_events", analytics_reset=None,
                                    sca_lockfile="requirements.txt", sast_lang="python",
                                    deletion=True, expected_verdict="BLOCK"),
        "clean-python-fastapi": dict(port=3104, boot="clean-python-fastapi", encoding="form",
                                     users=[("alice", "alice-fixture-pw"), ("bob", "bob-fixture-pw")],
                                     authz_owned={"alice": [1], "bob": [2]}, canary="CANARY",
                                     internal="http://127.0.0.1:3194/latest/meta-data/", ssrf_canary="SSRF-CANARY-7f3a91c2-internal-only",
                                     analytics_events="http://127.0.0.1:3164/_events", analytics_reset=None,
                                     sca_lockfile="requirements.txt", sast_lang="python",
                                     deletion=True, clean=True, expected_verdict="SHIP"),
        "vuln-static-trackers": dict(port=3105, boot="vuln-static-trackers", web=True,
                                     analytics_reset="http://127.0.0.1:3155/_reset", expected_verdict="BLOCK"),
        "clean-static-trackers": dict(port=3106, boot="clean-static-trackers", web=True,
                                      analytics_reset="http://127.0.0.1:3156/_reset", clean=True, expected_verdict="SHIP"),
        "honesty-wont-start": dict(port=3199, boot="honesty-wont-start", wont_start=True, expected_verdict="BLOCK"),
    }


# --------------------------------------------------------------------------- boot

def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_port(port: int, timeout: float = 60) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if port_open(port):
            return True
        time.sleep(0.5)
    return False


def boot(fixture: str, port: int, timeout: float = 60):
    start = FIXTURES / fixture / "start.sh"
    logf = open(FIXTURES / fixture / "logs" / "eval-boot.log", "w") if (FIXTURES / fixture / "logs").exists() else subprocess.DEVNULL
    try:
        proc = subprocess.Popen(["bash", str(start)], cwd=str(FIXTURES / fixture),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except OSError as e:
        return None, f"could not launch start.sh: {e}"
    if wait_port(port, timeout):
        return proc, None
    # did not come up: capture why, then stop it
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out = ""
    return None, (out or "").strip()[-800:]


def stop(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def stop_all():
    subprocess.run(["bash", str(FIXTURES / "_repro" / "stop-all.sh")], capture_output=True)


# --------------------------------------------------------------------------- project scaffold

def scratch_project(fixture: str, base_url: str, web: bool) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix=f"rg-eval-{fixture}-"))
    src = FIXTURES / fixture
    for item in src.iterdir():
        if item.name in EXCLUDE_COPY or item.name == "answer-key.yaml":
            continue
        dest = tmp / item.name
        if item.is_dir():
            shutil.copytree(item, dest, ignore=shutil.ignore_patterns(*EXCLUDE_COPY))
        else:
            shutil.copy2(item, dest)
    state = rglib.state_dir(tmp)
    rglib.dump_data(state / "scope.yaml",
                    {"targets": [{"url": base_url, "environment": "local", "owned_confirmed": True}]})
    surface = {"has_server": not web, "has_web_ui": True} if not web else {"has_server": False, "has_web_ui": True}
    rglib.dump_data(state / "config.yaml",
                    {"product": {"name": fixture, "distribution": ["website"] if web else ["api", "website"]},
                     "features": {"accounts": not web}, "surface": surface})
    return tmp


# --------------------------------------------------------------------------- static scanners (best effort)

def _tool(name: str) -> str | None:
    p = SHARE / "bin" / name
    if p.exists():
        return str(p)
    p = SHARE / "venv" / "bin" / name
    return str(p) if p.exists() else None


def run_static(project: Path, plan: dict) -> list[dict]:
    ev = rglib.state_dir(project) / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    notes = []
    env = dict(os.environ, **SEMGREP_ENV, PATH=f"{SHARE/'bin'}:{SHARE/'venv'/'bin'}:" + os.environ.get("PATH", ""))

    secrets_absent = None
    gl = _tool("gitleaks")
    if gl:
        subprocess.run([gl, "dir", str(project), "--report-format", "json",
                        "--report-path", str(ev / "gitleaks.json"), "--no-banner", "--exit-code", "0"],
                       capture_output=True, env=env, timeout=120)
        glf = ev / "gitleaks.json"
        if glf.exists():
            try:
                hits = json.loads(glf.read_text() or "[]")
            except json.JSONDecodeError:
                hits = None
            if hits == []:
                # gitleaks ran and found nothing: that is a tested absence, not "not tested"
                def _absent(fid, cid, title):
                    return {"id": fid, "kind": "check", "check_id": cid, "category": "secrets", "title": title,
                            "evidence_class": "VERIFIED-ABSENT", "phase": 2,
                            "evidence": [{"type": "tool-output", "path": "evidence/gitleaks.json",
                                          "description": "gitleaks dir scan, 0 findings"}],
                            "adversarial": {"required": True, "outcome": "not-run"},
                            "tool": {"name": "gitleaks", "scope": "source tree"}, "created_at": rglib.now_iso()}
                secrets_absent = [_absent("RG-SECRETS-900", "SEC-SECRETS-HISTORY",
                                          "No secrets found by gitleaks in the source tree")]
                if plan.get("web"):
                    # for a static site the served files ARE the client bundle, so the same clean
                    # scan covers "secrets in client bundles / artifacts"
                    secrets_absent.append(_absent("RG-SECRETS-901", "SEC-SECRETS-ARTIFACTS",
                                                  "No secrets in the served static files (client bundle)"))

    lang = plan.get("sast_lang")
    sg = _tool("semgrep")
    if sg and lang:
        cfg = SHARE / "semgrep-rules" / lang / "lang" / "security"
        if cfg.exists():
            subprocess.run([sg, "scan", "--metrics", "off", "--jobs", "1", "--config", str(cfg),
                            "--sarif", "--output", str(ev / "semgrep.sarif"), str(project)],
                           capture_output=True, env=env, timeout=240)

    lock = plan.get("sca_lockfile")
    osv = _tool("osv-scanner")
    if osv and lock and (project / lock).exists():
        r = subprocess.run([osv, "--format", "json", "--lockfile", str(project / lock)],
                           capture_output=True, text=True, env=env, timeout=120)
        if r.stdout.strip():
            (ev / "osv-scanner.json").write_text(r.stdout)

    # normalize everything in the evidence dir, then dedupe
    findings = ev.parent / "static_findings.json"
    n = subprocess.run([sys.executable, str(SCRIPTS / "normalize_findings.py"), "--auto", str(ev),
                        "--out", str(findings)], capture_output=True, text=True, env=env)
    if n.returncode != 0 or not findings.exists():
        return []
    d = subprocess.run([sys.executable, str(SCRIPTS / "dedupe_findings.py"), "--in", str(findings),
                        "--out", str(findings), "--root", str(project)], capture_output=True, text=True, env=env)
    data = rglib.load_data(findings, [])
    entries = data.get("entries", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    entries = verify_tool_findings(project, entries)
    # a clean secret scan is VERIFIED-ABSENT, only if nothing else already reported a secret
    if secrets_absent and not any(e.get("category") == "secrets" and e.get("kind") == "finding" for e in entries):
        entries.extend(secrets_absent)
    return entries


def verify_tool_findings(project: Path, entries: list[dict]) -> list[dict]:
    """Honest TOOL-CONFIRMED upgrade: a deterministic scanner reported it AND we
    re-read the cited path and confirmed it is real (SKILL principle 1). We only
    do this for secrets (a secret-shaped value is present in the source file) and
    SCA (the vulnerable version is pinned in the lockfile) — mechanical confirmations,
    not the judgement calls (SAST, logic) that need a human/adversarial read."""
    for e in entries:
        if e.get("kind") != "finding" or e.get("evidence_class") != "SUSPECTED":
            continue
        cat = e.get("category")
        loc = e.get("location") or {}
        f = loc.get("file")
        if not f:
            continue
        fp = project / f
        if not fp.exists():
            continue
        text = fp.read_text(encoding="utf-8", errors="replace")
        if cat == "secrets" and rglib.find_secrets(text):
            e["evidence_class"] = "TOOL-CONFIRMED"
            e["verification"] = {"verdict": "confirmed", "code_ref": f,
                                 "reason": "secret-shaped value confirmed present in the source file the scanner named"}
        elif cat == "sca":
            comp = str(loc.get("component", "")).rsplit("@", 1)
            if len(comp) == 2 and comp[1] and comp[1] in text:
                e["evidence_class"] = "TOOL-CONFIRMED"
                e["verification"] = {"verdict": "confirmed", "code_ref": f,
                                     "reason": f"{loc['component']} confirmed pinned in {f}"}
    return entries


# --------------------------------------------------------------------------- dynamic

def run_dynamic(project: Path, plan: dict, base_url: str) -> list[dict]:
    state = rglib.state_dir(project)
    scope = rglib.load_data(state / "scope.yaml", {})
    entries: list[dict] = []
    enc = plan.get("encoding", "form")

    if plan.get("web"):
        audit = _cookie_audit(base_url, state)
        if audit is not None:
            entries.append(audit)
        return entries

    # authz matrix (IDOR)
    users = [{"name": u, "username": u, "password": p} for u, p in plan["users"]]
    spec = {"base_url": base_url, "login": {"path": "/login", "encoding": enc, "token_field": "token"},
            "users": users,
            "resources": [{"endpoint": "GET /api/messages/{id}", "owned": plan["authz_owned"],
                           "public": False, "canary": plan.get("canary", "CANARY")}]}
    entries += authz_matrix.run_matrix(spec, scope, state)

    token = probes.login(base_url, plan["users"][0][0], plan["users"][0][1], encoding=enc)
    entries.append(probes.probe_sqli(base_url, state))
    if plan.get("internal"):
        entries.append(probes.probe_ssrf(base_url, state, token, plan["internal"], plan["ssrf_canary"]))
    entries.append(probes.probe_rate_limit(base_url, state, plan["users"][0][0], encoding=enc))
    entries.append(probes.probe_enumeration(base_url, state, plan["users"][0][0], encoding=enc))
    entries.append(probes.probe_error_leaks(base_url, state))
    entries.append({"id": "RG-SESSION-900", "kind": "check", "check_id": "SEC-SESSION", "category": "session",
                    "title": "Session cookie flags / invalidation", "evidence_class": "NOT-TESTED",
                    "not_tested_reason": "token-based auth with no logout endpoint; session-cookie flags not applicable and invalidation not exercised",
                    "evidence": [], "phase": 3})
    log_path = FIXTURES / plan["boot"] / "logs" / "app.log"
    entries.append(probes.probe_credential_log(state, log_path, [f"wrong-guess-{i}" for i in range(12)]))
    if plan.get("deletion"):
        entries.append(probes.probe_deletion(base_url, state, encoding=enc))
    if plan.get("analytics_events"):
        entries.append(probes.probe_analytics_beacon(base_url, state, plan["users"][0][0], plan["users"][0][1],
                                                     plan["analytics_events"], plan.get("analytics_reset"), encoding=enc))
    if plan.get("coupon") and token:
        entries.append(probes.probe_coupon_race(base_url, state, token))
    if plan.get("xss"):
        entries.append(_xss_browser(base_url, state, plan))
    return entries


def _xss_browser(base_url: str, state: Path, plan: dict):
    node = shutil.which("node")
    nt = {"id": "RG-XSS-900", "kind": "check", "check_id": "SEC-XSS-DYNAMIC", "category": "xss",
          "title": "Stored XSS", "evidence_class": "NOT-TESTED", "evidence": [], "phase": 3}
    if not node:
        return {**nt, "not_tested_reason": "node not available for the browser XSS probe"}
    env = dict(os.environ, RG_PLAYWRIGHT_BASE=str(SHARE / "node"),
               PLAYWRIGHT_BROWSERS_PATH=str(SHARE / "node" / "ms-playwright"))
    u, p = plan["users"][0]
    r = subprocess.run([node, str(REPO / "evals" / "browser_probe.mjs"), "--base", base_url,
                        "--user", u, "--pass", p, "--post-path", "/api/comments", "--comments-path", "/comments"],
                       capture_output=True, text=True, env=env, timeout=120)
    try:
        data = json.loads(r.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {**nt, "not_tested_reason": f"XSS probe failed: {r.stderr.strip()[:160]}"}
    ev = state / "evidence" / "dynamic" / "xss_browser.json"
    ev.parent.mkdir(parents=True, exist_ok=True)
    ev.write_text(json.dumps(data, indent=2))
    rel = str(ev.relative_to(state))
    if data.get("executed"):
        return {"id": "RG-XSS-901", "kind": "finding", "check_id": "SEC-XSS-DYNAMIC", "category": "xss",
                "title": "Stored XSS executes in the browser", "severity": "high", "evidence_class": "EXPLOITED",
                "phase": 3, "cwe": ["CWE-79"],
                "impact": "A comment containing a script payload runs in other users' browsers, enabling session theft and account takeover.",
                "repro": "Posted a comment with an onerror payload; on loading /comments in a real browser the script executed (window.__xss set).",
                "fix": "HTML-escape user content on output and add a restrictive Content-Security-Policy.",
                "evidence": [{"type": "screenshot", "path": rel, "description": "browser XSS execution probe"}],
                "adversarial": {"required": True, "outcome": "not-run"}, "created_at": rglib.now_iso()}
    if data.get("reflected"):
        return {"id": "RG-XSS-901", "kind": "finding", "check_id": "SEC-XSS-DYNAMIC", "category": "xss",
                "title": "User content reflected unescaped (potential stored XSS)", "severity": "high",
                "evidence_class": "SUSPECTED", "phase": 3, "evidence": [],
                "impact": "User-supplied markup is served back without escaping; it likely executes in a browser.",
                "repro": "Posted an onerror payload; the raw markup appears unescaped in /comments, but execution was not observed in this run.",
                "fix": "HTML-escape user content on output and add a Content-Security-Policy.", "created_at": rglib.now_iso()}
    return {"id": "RG-XSS-901", "kind": "check", "check_id": "SEC-XSS-DYNAMIC", "category": "xss",
            "title": "Stored comment payload neither executed nor reflected unescaped", "evidence_class": "VERIFIED-ABSENT",
            "phase": 3, "evidence": [{"type": "screenshot", "path": rel}],
            "adversarial": {"required": False, "outcome": "not-run"}, "created_at": rglib.now_iso()}


def _cookie_audit(base_url: str, state: Path):
    node = shutil.which("node")
    if not node:
        return {"id": "RG-TRACKING-900", "kind": "check", "check_id": "PRIV-COOKIE-AUDIT", "category": "tracking",
                "title": "Cookie audit", "evidence_class": "NOT-TESTED", "not_tested_reason": "node not available",
                "evidence": [], "phase": 7}
    out = state / "evidence" / "cookie_audit.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, RG_PLAYWRIGHT_BASE=str(SHARE / "node"),
               PLAYWRIGHT_BROWSERS_PATH=str(SHARE / "node" / "ms-playwright"))
    r = subprocess.run([node, str(SCRIPTS / "cookie_audit.mjs"), "--url", base_url, "--out", str(out)],
                       capture_output=True, text=True, env=env, timeout=120)
    if r.returncode != 0 or not out.exists():
        return {"id": "RG-TRACKING-900", "kind": "check", "check_id": "PRIV-COOKIE-AUDIT", "category": "tracking",
                "title": "Cookie audit", "evidence_class": "NOT-TESTED",
                "not_tested_reason": f"cookie_audit failed: {r.stderr.strip()[:200]}", "evidence": [], "phase": 7}
    data = json.loads(out.read_text())
    rel = str(out.relative_to(state))
    if data.get("violation"):
        return {"id": "RG-TRACKING-901", "kind": "finding", "check_id": "PRIV-COOKIE-AUDIT", "category": "tracking",
                "title": "Non-essential trackers fire before/without consent", "severity": "high",
                "evidence_class": "EXPLOITED", "phase": 7,
                "impact": "Tracking cookies and third-party analytics requests fire before any consent and even after the user rejects, which most consent regimes prohibit.",
                "repro": "Loaded the page in a fresh browser: trackers fired before any consent and again after clicking Reject.",
                "fix": "Load no non-essential cookie or third-party script until the user opts in; honour Reject.",
                "evidence": [{"type": "har", "path": rel, "description": "cookie audit: before/reject/accept stages"}],
                "adversarial": {"required": True, "outcome": "not-run"}, "created_at": rglib.now_iso()}
    return {"id": "RG-TRACKING-901", "kind": "check", "check_id": "PRIV-COOKIE-AUDIT", "category": "tracking",
            "title": "No non-essential tracker fires before or after rejecting consent", "evidence_class": "VERIFIED-ABSENT",
            "phase": 7, "evidence": [{"type": "har", "path": rel}],
            "adversarial": {"required": False, "outcome": "not-run"}, "created_at": rglib.now_iso()}


def run_privacy(project: Path, plan: dict, dynamic: list[dict]) -> list[dict]:
    """Inventory + policy consistency, with dynamic upgrades/refutations folded in."""
    inv = data_inventory_scan.scan(project)
    rglib.dump_data(rglib.state_dir(project) / "data-inventory.yaml", inv)
    policy_file = _extract_policy(project, plan)
    entries = []
    if policy_file:
        for f in policy_consistency.check_claims(policy_file.read_text(encoding="utf-8", errors="replace"),
                                                 policy_file.name, inv):
            entries.append(f)
    # fold dynamic confirmations: an EXPLOITED analytics beacon upgrades a SUSPECTED sharing/tracking mismatch;
    # a clean dynamic result refutes a SUSPECTED mismatch (marked false-positive, not silently dropped).
    beacon = next((d for d in dynamic if d.get("check_id") == "LEGAL-POLICY-CONSISTENCY" and d["evidence_class"] == "EXPLOITED"), None)
    cookie = next((d for d in dynamic if d.get("check_id") == "PRIV-COOKIE-AUDIT"), None)
    for f in entries:
        if f["evidence_class"] == "SUSPECTED":
            if "track" in f["title"].lower():
                if cookie and cookie["evidence_class"] == "EXPLOITED":
                    f["evidence_class"] = "EXPLOITED"
                    f["evidence"] = cookie.get("evidence", [])
                    f["adversarial"] = {"required": True, "outcome": "not-run"}
                elif cookie and cookie["evidence_class"] == "VERIFIED-ABSENT":
                    f["status"] = "false-positive"
                    f["verification"] = {"verdict": "false-positive", "reason": "cookie audit saw no tracker before/without consent"}
    if beacon:
        entries.append(beacon)
    return entries


def _extract_policy(project: Path, plan: dict) -> Path | None:
    html = project / "site" / "privacy.html"
    if html.exists():
        return html
    main = project / "app" / "main.py"
    if main.exists():
        import re
        m = re.search(r'def privacy.*?return\s+"""(.*?)"""', main.read_text(), re.S)
        if m:
            p = rglib.state_dir(project) / "extracted-privacy.html"
            p.write_text(m.group(1))
            return p
    for cand in (project / "src" / "routes", project):
        pass
    return None


# --------------------------------------------------------------------------- discovery mode

class _CanaryHandler(http.server.BaseHTTPRequestHandler):
    canary = "x"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.canary.encode())

    def log_message(self, *a):  # silence
        pass


def start_canary() -> tuple[object, str, str]:
    """Start a harness-owned HTTP canary listener for the SSRF probe. Returns
    (server, url, token). This is NOT the fixture's built-in canary."""
    token = "RG-DISCOVERY-CANARY-" + secrets.token_hex(8)
    handler = type("H", (_CanaryHandler,), {"canary": token})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address[0], srv.server_address[1]
    return srv, f"http://{host}:{port}/latest/meta-data/", token


def _not_tested(check_id, category, title, reason, phase=3):
    return {"id": f"RG-{category.upper().replace('-', '')}-970", "kind": "check", "check_id": check_id,
            "category": category, "title": title, "evidence_class": "NOT-TESTED",
            "not_tested_reason": reason, "evidence": [], "phase": phase}


def run_dynamic_discovery(project: Path, plan: dict, base_url: str, routes: list[dict],
                          seeded: list[tuple[str, str]]) -> list[dict]:
    """Dynamic tests driven only by the discovered surface + seeded creds.
    No hand-fed endpoints, owner maps, canaries or coupon codes."""
    state = rglib.state_dir(project)
    scope = rglib.load_data(state / "scope.yaml", {})
    entries: list[dict] = []

    if plan.get("web"):
        audit = _cookie_audit(base_url, state)
        if audit is not None:
            entries.append(audit)
        return entries

    dplan = discovery.build_plan(base_url, routes, seeded)
    principals = dplan["_principals_full"]

    # ---- authorization matrix (observed ownership only reaches EXPLOITED)
    if dplan["authz_spec"]:
        authz = authz_matrix.run_matrix(dplan["authz_spec"], scope, state)
        if dplan["authz_mode"] != "observed":
            # ownership was not learned from a collection endpoint: a cross-user 2xx
            # is only SUSPECTED, not proven, so downgrade honestly.
            for e in authz:
                if e.get("evidence_class") == "EXPLOITED":
                    e["evidence_class"] = "SUSPECTED"
                    e["severity"] = "high"
                    e["note"] = ("cross-principal access observed but resource ownership could not be "
                                 "confirmed (no collection endpoint to learn owned ids); needs a manual owner check")
                    e.pop("adversarial", None)
        entries += authz
    else:
        entries.append(_not_tested("SEC-AUTHZ-MATRIX", "authz", "Authorization matrix",
                                   "no auth-required id-addressed endpoint and login could be discovered from the surface"))

    token = principals[0]["token"] if principals else None

    # ---- SQL injection (error/union heuristic on a discovered open query endpoint)
    qe = dplan["query_endpoint"]
    if qe:
        entries.append(probes.probe_sqli(base_url, state, search_path=qe["route"]["path"]))
    else:
        entries.append(_not_tested("SEC-INJECTION-DYNAMIC", "injection", "SQL injection",
                                   "no open query endpoint discovered to probe"))

    # ---- SSRF against the harness canary listener
    uf = dplan["url_fetch"]
    if uf:
        srv, canary_url, canary_tok = start_canary()
        try:
            path = uf["route"]["path"]
            # probe_ssrf targets a fixed /api/fetch-preview path; call the route we found.
            entries.append(_discovery_ssrf(base_url, state, token, path, uf["param"], canary_url, canary_tok))
        finally:
            srv.shutdown()
    else:
        entries.append(_not_tested("SEC-SSRF-DYNAMIC", "ssrf", "SSRF",
                                   "no url-shaped parameter discovered to probe"))

    # ---- brute-force / rate limit + username enumeration on the discovered login
    if dplan["login_shape"] and principals:
        enc = dplan["login_shape"]["encoding"]
        entries.append(probes.probe_rate_limit(base_url, state, principals[0]["username"], encoding=enc))
        entries.append(probes.probe_enumeration(base_url, state, principals[0]["username"], encoding=enc))
    else:
        entries.append(_not_tested("SEC-AUTHN-BRUTEFORCE", "rate-limit", "Login brute-force protection",
                                   "login endpoint could not be discovered"))
        entries.append(_not_tested("SEC-AUTHN-ENUMERATION", "authn", "Username enumeration",
                                   "login endpoint could not be discovered"))

    # ---- session handling (same generic marker as guided: token auth, no logout route)
    entries.append({"id": "RG-SESSION-900", "kind": "check", "check_id": "SEC-SESSION", "category": "session",
                    "title": "Session cookie flags / invalidation", "evidence_class": "NOT-TESTED",
                    "not_tested_reason": "token-based auth with no logout endpoint discovered; cookie flags not applicable and invalidation not exercised",
                    "evidence": [], "phase": 3})

    # ---- error-handling leaks, probing the endpoints we discovered (no fixture paths)
    leak_paths = []
    for item in discovery.find_object_endpoints(routes):
        leak_paths.append(re.sub(r":[A-Za-z_]\w*|\{[A-Za-z_]\w*\}", "not-an-int", item["path"]))
    if qe:
        leak_paths.append(qe["route"]["path"] + "?" + urllib.parse.urlencode({qe["param"]: "%ff%00"}))
    if leak_paths:
        entries.append(probes.probe_error_leaks(base_url, state, paths=leak_paths))
    else:
        entries.append(_not_tested("SEC-ERROR-LEAKS", "data-exposure", "Error-handling leaks",
                                   "no endpoint discovered to trigger an error response"))

    # ---- account deletion (only when both signup and a self-delete endpoint exist)
    if dplan["signup"] and dplan["delete_self"] and dplan["login_shape"]:
        entries.append(probes.probe_deletion(base_url, state, encoding=dplan["login_shape"]["encoding"]))

    # ---- things discovery cannot plan without answer-key inputs: recorded honestly
    entries.append(_not_tested("COR-RACE", "race", "Single-use resource race condition",
                               "needs a valid single-use token (e.g. coupon code); none is creatable or a documented input",
                               phase=4))
    entries.append(_not_tested("LEGAL-POLICY-CONSISTENCY", "policy-mismatch", "Policy vs runtime data sharing",
                               "analytics/telemetry sink address is not a discoverable input; checked statically only", phase=7))
    entries.append(_not_tested("SEC-XSS-DYNAMIC", "xss", "Stored XSS",
                               "stored-and-rendered sink pair not auto-identified in discovery mode"))
    return entries


def _discovery_ssrf(base, state, token, path, param, canary_url, canary_token):
    import urllib.parse as _up
    url = base.rstrip("/") + path + "?" + _up.urlencode({param: canary_url})
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    st, body = probes._req("GET", url, headers=headers)
    txt = f"GET {url}\n-> HTTP {st}\n{body[:1500]}"
    if st == 200 and canary_token in body:
        return probes._finding("RG-SSRF-901", "SEC-SSRF-DYNAMIC", "ssrf", "high",
                               "SSRF: server fetches an attacker-supplied URL", "EXPLOITED", state, "ssrf.txt", txt,
                               cwe=["CWE-918"],
                               impact="The server fetches a URL supplied by the caller and returns its body; a harness-controlled canary was read back.",
                               repro=f"GET {path}?{param}=<harness canary URL>; the canary token appeared in the response.",
                               fix="Allowlist destination hosts, resolve and reject private IPs, disable redirects.")
    return probes._check_absent("SEC-SSRF-DYNAMIC", "ssrf", "SSRF to the harness canary blocked", state,
                               "ssrf_absent.txt", txt)


# --------------------------------------------------------------------------- scoring

def best_class_by_category(entries: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for e in entries:
        if e.get("status") == "false-positive":
            continue
        cat = e.get("category")
        cls = e.get("evidence_class")
        if cat and cls and e.get("kind") == "finding":
            if CLASS_RANK.get(cls, 0) > CLASS_RANK.get(out.get(cat, "NOT-TESTED"), 0):
                out[cat] = cls
    return out


def score_fixture(fixture: str, entries: list[dict], verdict: str, plan: dict, answer: dict) -> dict:
    res = {"fixture": fixture, "verdict": verdict, "expected_verdict": plan["expected_verdict"]}
    by_cat = best_class_by_category(entries)
    if plan.get("clean"):
        must_not = [c["category"] for c in answer.get("clean_must_not_flag", [])]
        fps = sorted({cat for cat in by_cat if cat in must_not})
        res.update(kind="clean", categories_checked=len(must_not), false_positives=fps,
                   fp_rate=round(len(fps) / max(len(must_not), 1), 3))
    else:
        planted = answer.get("findings", [])
        detected, class_ok, misses = 0, 0, []
        required = [f for f in planted if not f.get("optional")]
        for f in planted:
            cat, exp = f.get("category"), f.get("expected_evidence_class")
            got = by_cat.get(cat)
            if got and CLASS_RANK.get(got, 0) >= CLASS_RANK.get("SUSPECTED", 1):
                detected += 1
                if got == exp or CLASS_RANK.get(got, 0) >= CLASS_RANK.get(exp, 0):
                    class_ok += 1
            elif not f.get("optional"):
                misses.append(f"{f['id']}({cat})")
        res.update(kind="vuln", planted=len(planted), required=len(required),
                   detected=detected, class_correct=class_ok, misses=misses,
                   detection_rate=round(detected / max(len(planted), 1), 3))
    # headline guarantee checks
    res["idor_exploited"] = by_cat.get("authz") == "EXPLOITED" if not plan.get("clean") and not plan.get("web") and not plan.get("wont_start") else None
    res["verdict_ok"] = _verdict_ok(verdict, plan, res)
    return res


def _verdict_ok(verdict: str, plan: dict, res: dict) -> bool:
    exp = plan["expected_verdict"]
    if verdict == exp:
        return True
    # issue #2: a clean fixture may legitimately land SHIP WITH ACCEPTED RISKS when the only
    # caps are NOT-TESTED reasons (e.g. no trufflehog verification offline), with zero findings.
    if exp == "SHIP" and verdict == "SHIP WITH ACCEPTED RISKS" and plan.get("clean") and not res.get("false_positives"):
        return True
    return False


# --------------------------------------------------------------------------- per-fixture driver

def eval_one(fixture: str, plan: dict, keep: bool, mode: str = "guided") -> dict:
    answer = rglib.load_data(FIXTURES / fixture / "answer-key.yaml", {}) or {}
    base_url = f"http://127.0.0.1:{plan['port']}"
    if plan.get("wont_start"):
        res = eval_honesty_wont_start(fixture, plan, answer)
        res["mode"] = mode
        return res

    proc, err = boot(plan["boot"], plan["port"])
    if not proc:
        return {"fixture": fixture, "error": f"did not boot: {err[:200]}", "mode": mode}
    project = scratch_project(fixture, base_url, bool(plan.get("web")))
    try:
        entries = run_static(project, plan)
        if mode == "discovery":
            # the skill recovers the surface from the code; the only per-target inputs
            # are the seeded credentials (a seeded test DB is allowed by SKILL principle 3).
            routes = extract_routes.extract(project)["routes"]
            seeded = plan.get("users", [])
            dynamic = run_dynamic_discovery(project, {"web": plan.get("web")}, base_url, routes, seeded)
        else:
            dynamic = run_dynamic(project, plan, base_url)
        entries += dynamic
        entries += run_privacy(project, plan, dynamic)
        rglib.dump_data(rglib.state_dir(project) / "findings.json", {"entries": entries})
        code, rep = report_build.build(project, mode="full", write_history=False)
        verdict = rep["verdict"]["verdict"]
        score = score_fixture(fixture, entries, verdict, plan, answer)
        score["mode"] = mode
        score["lint_ok"] = code == 0
        score["n_findings"] = sum(1 for e in entries if e.get("kind") == "finding" and e.get("status") != "false-positive")
        return score
    finally:
        stop(proc)
        if keep:
            print(f"  kept project: {project}", file=sys.stderr)
        else:
            shutil.rmtree(project, ignore_errors=True)


def eval_honesty_wont_start(fixture: str, plan: dict, answer: dict) -> dict:
    proc, err = boot(plan["boot"], plan["port"], timeout=12)
    booted = proc is not None
    stop(proc)
    project = scratch_project(fixture, f"http://127.0.0.1:{plan['port']}", False)
    try:
        entries = run_static(project, plan)  # static still works without a running app
        # every dynamic/critical check is NOT-TESTED because the app never started
        for cid, cat in [("SEC-AUTHZ-MATRIX", "authz"), ("SEC-INJECTION-DYNAMIC", "injection"),
                         ("SEC-SSRF-DYNAMIC", "ssrf"), ("SEC-AUTHN-BRUTEFORCE", "authn"),
                         ("SEC-ERROR-LEAKS", "data-exposure"), ("SEC-SESSION", "session")]:
            entries.append({"id": f"RG-{cat.upper().replace('-', '')}-950", "kind": "check", "check_id": cid,
                            "category": cat, "title": f"{cid} (app did not start)", "evidence_class": "NOT-TESTED",
                            "not_tested_reason": f"could not start application: {err[:120]}", "evidence": [], "phase": 3})
        rglib.dump_data(rglib.state_dir(project) / "findings.json", {"entries": entries})
        code, rep = report_build.build(project, mode="full", write_history=False)
        verdict = rep["verdict"]["verdict"]
        reasons = " ".join(rep["verdict"].get("reasons", []) + rep["verdict"].get("blocking", []))
        want = (answer.get("expected_verdict_reason_contains") or "insufficient evidence").lower()
        return {"fixture": fixture, "kind": "honesty", "booted": booted, "verdict": verdict,
                "expected_verdict": plan["expected_verdict"], "verdict_ok": verdict == "BLOCK",
                "reason_ok": want in reasons.lower(), "no_pass": verdict != "SHIP",
                "n_findings": sum(1 for e in entries if e.get("kind") == "finding")}
    finally:
        shutil.rmtree(project, ignore_errors=True)


def eval_no_tools() -> dict:
    """Honesty: with no scanners on PATH, every tool-backed check must be NOT-TESTED, never a pass."""
    import check_tools
    lock = check_tools.load_lock()
    env_path = os.environ.get("PATH", "")
    os.environ["PATH"] = "/nonexistent"
    try:
        report = check_tools.check_all({**lock, "install_dir": "/nonexistent", "venv_dir": "/nonexistent",
                                        "share_dir": "/nonexistent"})
    finally:
        os.environ["PATH"] = env_path
    statuses = {r["name"]: r["status"] for r in report["tools"]}
    all_missing = all(s != "ok" for s in statuses.values())
    all_have_reason = all(r.get("not_tested_reason") for r in report["tools"] if r["status"] != "ok")
    return {"fixture": "honesty-no-tools", "kind": "honesty", "all_tools_missing": all_missing,
            "every_missing_has_not_tested_reason": all_have_reason,
            "no_pass": all_missing and all_have_reason}


# --------------------------------------------------------------------------- table

def print_table(results: list[dict], label: str = ""):
    print(f"\n=== release-gate eval scores {label} ===")
    for r in results:
        if r.get("error"):
            print(f"  {r['fixture']:24} ERROR: {r['error']}")
            continue
        k = r.get("kind")
        if k == "vuln":
            print(f"  {r['fixture']:24} verdict={r['verdict']:24} ({'ok' if r['verdict_ok'] else 'WRONG'}) "
                  f"detect={r['detected']}/{r['planted']} class_ok={r['class_correct']} "
                  f"idor={'EXPLOITED' if r.get('idor_exploited') else 'MISSING'} misses={r['misses']}")
        elif k == "clean":
            print(f"  {r['fixture']:24} verdict={r['verdict']:24} ({'ok' if r['verdict_ok'] else 'WRONG'}) "
                  f"false_positives={r['false_positives']} fp_rate={r['fp_rate']}")
        elif k == "honesty":
            extra = (f"booted={r['booted']} reason_ok={r.get('reason_ok')}" if "booted" in r
                     else f"all_tools_missing={r.get('all_tools_missing')}")
            print(f"  {r['fixture']:24} verdict={r.get('verdict', 'n/a'):24} no_pass={r['no_pass']} {extra}")
    print()


def _run_mode(mode: str, names: list[str], plans: dict, keep: bool, only: list | None) -> list[dict]:
    results = []
    for name in names:
        if name not in plans:
            print(f"unknown fixture: {name}", file=sys.stderr)
            continue
        print(f"[eval:{mode}] {name} ...", file=sys.stderr)
        try:
            results.append(eval_one(name, plans[name], keep, mode=mode))
        except Exception as e:  # keep going; an eval crash is a real (reported) result
            results.append({"fixture": name, "error": f"{type(e).__name__}: {e}", "mode": mode})
        stop_all()
    if not only or "honesty-no-tools" in (only or []):
        nt = eval_no_tools()
        nt["mode"] = mode
        results.append(nt)
    return results


def _bad(results: list[dict]) -> list[dict]:
    """Headline guarantees. IDOR-EXPLOITED is required only in guided mode; in
    discovery mode a surface-only miss (e.g. no collection endpoint) is allowed,
    but vuln fixtures must still BLOCK and honesty fixtures must never pass."""
    bad = []
    for r in results:
        if r.get("kind") == "vuln":
            if not r.get("verdict_ok"):
                bad.append(r)
            elif r.get("mode") != "discovery" and r.get("idor_exploited") is False:
                bad.append(r)
        if r.get("kind") == "honesty" and not r.get("no_pass"):
            bad.append(r)
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", action="append", help="run only these fixtures (repeatable)")
    ap.add_argument("--keep", action="store_true", help="keep scratch projects for inspection")
    ap.add_argument("--mode", choices=["guided", "discovery", "both"], default="guided",
                    help="guided = hand-fed bug locations; discovery = plan from recovered surface")
    ap.add_argument("--out", type=Path, default=REPO / "evals" / "last-scores.json")
    args = ap.parse_args(argv)

    plans = _plan()
    names = args.only or list(plans)
    modes = ["guided", "discovery"] if args.mode == "both" else [args.mode]
    stop_all()
    all_results: dict[str, list[dict]] = {}
    try:
        for mode in modes:
            all_results[mode] = _run_mode(mode, names, plans, args.keep, args.only)
            stop_all()
    finally:
        stop_all()

    flat = []
    for mode in modes:
        print_table(all_results[mode], f"[{mode}]")
        flat += all_results[mode]
    args.out.write_text(json.dumps(flat, indent=2) + "\n")
    print(f"scores written to {args.out}")
    return 1 if _bad(flat) else 0


if __name__ == "__main__":
    sys.exit(main())
