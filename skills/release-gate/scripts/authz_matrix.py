#!/usr/bin/env python3
"""Authorization matrix: the highest-value dynamic test in release-gate.

For every resource owned by one user, every *other* principal (each other test
user, and the anonymous caller) requests it. Any 2xx response to a principal who
should not have access is broken authorization (IDOR / missing ownership check)
and is recorded as an EXPLOITED authz finding, with the exact request and the
(redacted) response saved as evidence. If every cross-principal request is
denied, the check is VERIFIED-ABSENT for SEC-AUTHZ-MATRIX and carries the saved
denials as evidence; a fresh adversarial subagent must then try to break it
before that absence can support a SHIP verdict.

Everything runs over stdlib urllib (no third-party deps). The target must be a
confirmed scope target (rglib.check_scope, fail-closed). Only loopback test
instances you started yourself should ever be in scope.

Spec (YAML/JSON), passed with --spec:

    base_url: http://127.0.0.1:3101
    login:                      # how to turn credentials into a bearer token
      path: /login
      method: POST
      encoding: form            # form | json
      token_field: token        # key in the JSON response holding the token
      header: Authorization     # header to send it in (default Authorization)
      scheme: "Bearer "         # prefix (default "Bearer ")
    users:
      - {name: alice, username: alice, password: alice-fixture-pw}
      - {name: bob,   username: bob,   password: bob-fixture-pw}
    resources:
      - endpoint: "GET /api/messages/{id}"
        owned:                  # principal name -> list of resource ids they own
          alice: [1]
          bob:   [2]
        public: false           # true = anyone may read it (no finding on access)
        canary: "CANARY"        # optional: substring proving cross-user data leaked

Output: a findings file (default <state>/authz_findings.json) of finding/check
entries valid against finding.schema.json, plus evidence under evidence/authz/.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rglib  # noqa: E402

ANON = "<anonymous>"
TIMEOUT = 10


# --------------------------------------------------------------------------- http

class Resp:
    __slots__ = ("status", "body")

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body


def http(method: str, url: str, *, headers: dict | None = None, data: bytes | None = None,
         content_type: str | None = None) -> Resp:
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310 (loopback, scope-checked)
            return Resp(r.status, r.read(8192).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return Resp(e.code, e.read(8192).decode("utf-8", "replace") if e.fp else "")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return Resp(0, f"<transport error: {type(e).__name__}: {e}>")


def login(base_url: str, spec: dict, user: dict) -> str | None:
    lg = spec.get("login") or {}
    if not lg:
        return None
    url = base_url.rstrip("/") + lg.get("path", "/login")
    payload = {"username": user["username"], "password": user["password"]}
    if lg.get("encoding", "form") == "json":
        resp = http(lg.get("method", "POST"), url, data=json.dumps(payload).encode(),
                    content_type="application/json")
    else:
        resp = http(lg.get("method", "POST"), url, data=urllib.parse.urlencode(payload).encode(),
                    content_type="application/x-www-form-urlencoded")
    if resp.status // 100 != 2:
        return None
    try:
        return json.loads(resp.body).get(lg.get("token_field", "token"))
    except (json.JSONDecodeError, AttributeError):
        return None


def auth_headers(spec: dict, token: str | None) -> dict:
    if not token:
        return {}
    lg = spec.get("login") or {}
    return {lg.get("header", "Authorization"): lg.get("scheme", "Bearer ") + token}


# --------------------------------------------------------------------------- probing

def parse_endpoint(endpoint: str) -> tuple[str, str]:
    parts = endpoint.split(None, 1)
    return (parts[0].upper(), parts[1]) if len(parts) == 2 else ("GET", endpoint)


def _save_evidence(state: Path, name: str, lines: list[str]) -> str:
    rel = Path("evidence") / "authz" / name
    dest = state / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(rglib.redact_text("\n".join(lines)) + "\n", encoding="utf-8")
    return str(rel)


def run_matrix(spec: dict, scope: dict | None, state: Path) -> list[dict]:
    base = spec["base_url"].rstrip("/")
    ok, reason = rglib.check_scope(base, "exploit", scope)
    if not ok:
        return [{
            "id": "RG-AUTHZ-001", "kind": "check", "check_id": "SEC-AUTHZ-MATRIX",
            "title": "Authorization matrix", "category": "authz", "phase": 3,
            "evidence_class": "NOT-TESTED", "not_tested_reason": f"out of scope: {reason}", "evidence": [],
        }]

    tokens: dict[str, str | None] = {ANON: None}
    for u in spec.get("users", []):
        tokens[u["name"]] = login(base, spec, u)

    exploited: list[dict] = []
    denials: list[str] = []
    n_probes = 0
    for res in spec.get("resources", []):
        method, path_tmpl = parse_endpoint(res["endpoint"])
        public = bool(res.get("public"))
        canary = res.get("canary")
        owned: dict[str, list] = res.get("owned", {})
        for owner, ids in owned.items():
            for rid in ids:
                path = path_tmpl.replace("{id}", str(rid))
                url = base + (path if path.startswith("/") else "/" + path)
                for principal, token in tokens.items():
                    if principal == owner:
                        continue  # the owner is allowed; we test everyone else
                    n_probes += 1
                    resp = http(method, url, headers=auth_headers(spec, token))
                    leaked = bool(canary) and canary in resp.body
                    allowed = resp.status // 100 == 2
                    record = (f"{method} {url}  as={principal}  owner={owner}  -> HTTP {resp.status}"
                              + (f"  [canary '{canary}' present]" if leaked else ""))
                    if allowed and not public:
                        ev = _save_evidence(
                            state, f"{method}_{re.sub(r'[^A-Za-z0-9]+', '_', path).strip('_')}_as_{principal}.txt",
                            [f"# request: {method} {url}",
                             f"# principal: {principal} (owner is {owner})",
                             f"# expected: access denied (not the owner); got HTTP {resp.status}",
                             "", "--- response body (redacted) ---", resp.body])
                        fid = f"RG-AUTHZ-{len(exploited) + 10:03d}"
                        exploited.append({
                            "id": fid, "kind": "finding", "check_id": "SEC-AUTHZ-MATRIX",
                            "title": f"Broken access control: {principal} can read {owner}'s resource via {res['endpoint']}",
                            "category": "authz", "severity": "critical", "phase": 3,
                            "evidence_class": "EXPLOITED",
                            "cwe": ["CWE-639", "CWE-284"],
                            "location": {"endpoint": res["endpoint"]},
                            "impact": (f"Any authenticated user (or {'the anonymous caller' if principal == ANON else 'another user'}) "
                                       f"can read data belonging to a different account by changing the id in the URL."),
                            "repro": f"Authenticate as {principal}, request {method} {path}. Observed HTTP {resp.status}"
                                     + (f" and the owner-only canary '{canary}' in the response." if leaked else "."),
                            "fix": "Enforce ownership in the query or handler: scope the lookup to the caller's id "
                                   "(WHERE owner_id = :caller) and return 404/403 otherwise.",
                            "evidence": [{"type": "request-response", "path": ev,
                                          "description": f"{principal} reading {owner}'s resource"}],
                            "adversarial": {"required": True, "outcome": "not-run"},
                            "created_at": rglib.now_iso(),
                        })
                    else:
                        denials.append(record)

    if exploited:
        return exploited

    ev = _save_evidence(state, "denied_cross_user_requests.txt",
                        [f"# authorization matrix: {n_probes} cross-principal probes, all denied", ""] + denials) \
        if denials else None
    if n_probes == 0:
        return [{
            "id": "RG-AUTHZ-001", "kind": "check", "check_id": "SEC-AUTHZ-MATRIX",
            "title": "Authorization matrix", "category": "authz", "phase": 3,
            "evidence_class": "NOT-TESTED",
            "not_tested_reason": "no owned resources to probe in the authz spec", "evidence": [],
        }]
    return [{
        "id": "RG-AUTHZ-001", "kind": "check", "check_id": "SEC-AUTHZ-MATRIX",
        "title": "Authorization matrix: every cross-user resource request denied",
        "category": "authz", "phase": 3, "evidence_class": "VERIFIED-ABSENT",
        "evidence": [{"type": "request-response", "path": ev,
                      "description": f"{n_probes} cross-principal probes, all denied"}],
        "adversarial": {"required": True, "outcome": "not-run"},
        "created_at": rglib.now_iso(),
    }]


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--project", required=True, type=Path)
    ap.add_argument("--spec", required=True, type=Path, help="authz spec (YAML/JSON)")
    ap.add_argument("--out", type=Path, help="findings output (default <state>/authz_findings.json)")
    args = ap.parse_args(argv)

    state = rglib.state_dir(args.project)
    spec = rglib.load_data(args.spec)
    if not isinstance(spec, dict) or not spec.get("base_url"):
        print("spec must be a mapping with a base_url", file=sys.stderr)
        return 2
    scope = rglib.load_data(state / "scope.yaml", {})
    entries = run_matrix(spec, scope, state)
    out = args.out or (state / "authz_findings.json")
    rglib.dump_data(out, {"entries": entries})
    n_exp = sum(1 for e in entries if e.get("evidence_class") == "EXPLOITED")
    print(f"authz: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}, {n_exp} EXPLOITED -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
