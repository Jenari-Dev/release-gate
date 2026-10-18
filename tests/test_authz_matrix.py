"""authz_matrix against a throwaway loopback server: one IDOR app, one clean twin."""
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "skills" / "release-gate" / "scripts" / "authz_matrix.py"
spec = importlib.util.spec_from_file_location("authz_matrix", SCRIPT)
am = importlib.util.module_from_spec(spec)
spec.loader.exec_module(am)

# message_id -> (owner_id, body). alice=id1, bob=id2.
MESSAGES = {1: (1, "alice note"), 2: (2, "Bob here: BOB-PRIVATE-CANARY-9z8y")}
TOKENS = {"tok-alice": 1, "tok-bob": 2}


def make_handler(enforce_ownership: bool):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(obj).encode())

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode()
            form = dict(p.split("=", 1) for p in raw.split("&") if "=" in p)
            tok = {"alice": "tok-alice", "bob": "tok-bob"}.get(form.get("username"))
            if tok and form.get("password", "").endswith("-pw"):
                return self._json(200, {"token": tok})
            return self._json(401, {"error": "bad creds"})

        def do_GET(self):
            if not self.path.startswith("/api/messages/"):
                return self._json(404, {"error": "nope"})
            mid = int(self.path.rsplit("/", 1)[1])
            caller = TOKENS.get(self.headers.get("Authorization", "").removeprefix("Bearer "))
            if caller is None:
                return self._json(401, {"error": "unauthenticated"})
            row = MESSAGES.get(mid)
            if not row or (enforce_ownership and row[0] != caller):
                return self._json(404, {"error": "not found"})
            return self._json(200, {"id": mid, "owner_id": row[0], "body": row[1]})

    return H


@pytest.fixture
def server():
    created = []

    def start(enforce):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(enforce))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        created.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield start
    for s in created:
        s.shutdown()


def spec_for(base):
    return {
        "base_url": base,
        "login": {"path": "/login", "encoding": "form", "token_field": "token"},
        "users": [{"name": "alice", "username": "alice", "password": "alice-pw"},
                  {"name": "bob", "username": "bob", "password": "bob-pw"}],
        "resources": [{"endpoint": "GET /api/messages/{id}",
                       "owned": {"alice": [1], "bob": [2]}, "public": False,
                       "canary": "BOB-PRIVATE-CANARY-9z8y"}],
    }


def scope_for(base):
    return {"targets": [{"url": base, "environment": "local"}]}


def test_idor_becomes_exploited_with_evidence(server, tmp_path):
    base = server(enforce=False)
    state = tmp_path / ".release-gate"
    (state / "evidence").mkdir(parents=True)
    entries = am.run_matrix(spec_for(base), scope_for(base), state)
    exploited = [e for e in entries if e["evidence_class"] == "EXPLOITED"]
    assert exploited, entries
    assert all(e["category"] == "authz" and e["severity"] == "critical" for e in exploited)
    # the owner-only canary is captured in the evidence of the cross-user read that leaked it
    all_ev = "\n".join((state / e["evidence"][0]["path"]).read_text() for e in exploited)
    assert "BOB-PRIVATE-CANARY-9z8y" in all_ev
    assert all(e["adversarial"]["required"] is True for e in exploited)


def test_clean_twin_is_verified_absent(server, tmp_path):
    base = server(enforce=True)
    state = tmp_path / ".release-gate"
    (state / "evidence").mkdir(parents=True)
    entries = am.run_matrix(spec_for(base), scope_for(base), state)
    assert len(entries) == 1
    assert entries[0]["evidence_class"] == "VERIFIED-ABSENT"
    assert entries[0]["check_id"] == "SEC-AUTHZ-MATRIX"
    assert entries[0]["adversarial"]["required"] is True


def test_out_of_scope_is_not_tested(server, tmp_path):
    base = server(enforce=False)
    state = tmp_path / ".release-gate"
    (state / "evidence").mkdir(parents=True)
    entries = am.run_matrix(spec_for(base), {"targets": []}, state)  # empty scope = fail closed
    assert len(entries) == 1 and entries[0]["evidence_class"] == "NOT-TESTED"
    assert "out of scope" in entries[0]["not_tested_reason"]


def test_entries_validate_against_schema(server, tmp_path):
    base = server(enforce=False)
    state = tmp_path / ".release-gate"
    (state / "evidence").mkdir(parents=True)
    entries = am.run_matrix(spec_for(base), scope_for(base), state)
    import sys
    sys.path.insert(0, str(SCRIPT.parent))
    import rglib
    for e in entries:
        assert rglib.validate(e, "finding") == [], e


# ---------------------------------------------------------------- positive control (issue #2)

def make_login_broken_handler():
    """Resources need auth, but /login never returns a usable token: a real app
    where the harness cannot authenticate. Every request ends up anonymous 401."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(obj).encode())

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            self.rfile.read(n)
            self._json(200, {"session_established": True})  # 2xx but NO token field

        def do_GET(self):
            caller = TOKENS.get(self.headers.get("Authorization", "").removeprefix("Bearer "))
            if caller is None:
                return self._json(401, {"error": "unauthenticated"})
            return self._json(200, {"ok": True})
    return H


@pytest.fixture
def broken_login_server():
    created = []

    def start():
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_login_broken_handler())
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        created.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield start
    for s in created:
        s.shutdown()


def test_failed_positive_control_is_not_tested_not_a_pass(broken_login_server, tmp_path):
    """If no owner can read their own resource, a wall of cross-user 401s must NOT
    be reported as VERIFIED-ABSENT. That would be a false pass from a login failure."""
    base = broken_login_server()
    state = tmp_path / ".release-gate"
    (state / "evidence").mkdir(parents=True)
    entries = am.run_matrix(spec_for(base), scope_for(base), state)
    assert len(entries) == 1
    assert entries[0]["evidence_class"] == "NOT-TESTED"
    assert "positive control" in entries[0]["not_tested_reason"].lower()
    assert entries[0]["evidence_class"] != "VERIFIED-ABSENT"


def test_nested_token_field(server, tmp_path):
    """token_field supports a dotted path into the login response."""
    base = server(enforce=True)
    sp = spec_for(base)
    # the fixture server returns {"token": ...}; a dotted path to a missing key yields no token
    sp["login"]["token_field"] = "data.token"
    state = tmp_path / ".release-gate"
    (state / "evidence").mkdir(parents=True)
    entries = am.run_matrix(sp, scope_for(base), state)
    # with no token resolvable, the positive control fails -> NOT-TESTED (honest)
    assert entries[0]["evidence_class"] == "NOT-TESTED"


def test_dig_helper():
    assert am._dig({"data": {"token": "abc"}}, "data.token") == "abc"
    assert am._dig({"token": "abc"}, "token") == "abc"
    assert am._dig({"data": {}}, "data.token") is None
    assert am._dig({"x": 1}, "y") is None
