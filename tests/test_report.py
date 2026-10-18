"""Tests for report_build.py (verdict, coverage, rendering) and report_lint.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import report_build as rb
import report_lint as rl
import rglib

CATALOG = [
    {"id": "SEC-SECRETS-HISTORY", "title": "Secrets in history", "category": "secrets", "phase": 2, "critical": True, "modes": ["quick", "full"]},
    {"id": "SEC-AUTHZ-MATRIX", "title": "Authz matrix", "category": "authz", "phase": 3, "critical": True, "modes": ["full"],
     "applies_when": {"has_server": True}},
    {"id": "SEC-SAST", "title": "SAST", "category": "sast", "phase": 2, "critical": False, "modes": ["quick", "full"]},
    {"id": "PRIV-COOKIE-AUDIT", "title": "Cookies", "category": "tracking", "phase": 7, "critical": False, "modes": ["full"],
     "applies_when": {"has_web_ui": True}},
]
WEB_CONFIG = {"schema_version": 1, "product": {"name": "demo", "distribution": ["saas"]}}


def finding(i, sev="high", cls="SUSPECTED", check="SEC-SAST", cat="sast", **kw):
    e = {"id": f"RG-T-{i:03d}", "kind": "finding", "title": f"finding {i}", "severity": sev, "category": cat,
         "evidence_class": cls, "check_id": check, "evidence": [], "status": "open"}
    if cls in rglib.ARTIFACT_REQUIRED:
        e["evidence"] = [{"type": "tool-output", "path": "evidence/x.txt"}]
    e.update(kw)
    return e


def check(i, check_id, cls="VERIFIED-ABSENT", cat="secrets", upheld=True, reason=None):
    e = {"id": f"RG-C-{i:03d}", "kind": "check", "title": f"check {i}", "category": cat, "evidence_class": cls,
         "check_id": check_id, "evidence": []}
    if cls in rglib.ARTIFACT_REQUIRED:
        e["evidence"] = [{"type": "tool-output", "path": "evidence/x.txt"}]
    if cls == "NOT-TESTED":
        e["not_tested_reason"] = reason or "tool unavailable: gitleaks"
    if cls == "VERIFIED-ABSENT":
        e["adversarial"] = {"required": True, "outcome": "upheld" if upheld else "not-run"}
    return e


def verdict(entries, config=WEB_CONFIG, mode="full", waivers=()):
    cov = rb.build_coverage(entries, CATALOG, config, mode)
    return rb.compute_verdict(entries, cov, list(waivers), mode), cov


# --------------------------------------------------------------------------- coverage

def test_missing_result_becomes_not_tested():
    _, cov = verdict([])
    row = {r["id"]: r for r in cov}["SEC-AUTHZ-MATRIX"]
    assert row["evidence_class"] == "NOT-TESTED"
    assert row["reason"] == "no result recorded"


def test_not_applicable_when_config_says_so():
    cfg = {"schema_version": 1, "product": {"name": "lib", "distribution": ["library"]}}
    _, cov = verdict([], config=cfg)
    row = {r["id"]: r for r in cov}["SEC-AUTHZ-MATRIX"]
    assert row["evidence_class"] == "N/A" and not row["applicable"]


def test_unknown_config_is_treated_as_applicable():
    _, cov = verdict([], config={})
    assert {r["id"]: r for r in cov}["SEC-AUTHZ-MATRIX"]["applicable"]


def test_partial_not_tested_wins_over_verified():
    entries = [check(1, "SEC-SECRETS-HISTORY"), check(2, "SEC-SECRETS-HISTORY", cls="NOT-TESTED")]
    _, cov = verdict(entries)
    row = {r["id"]: r for r in cov}["SEC-SECRETS-HISTORY"]
    assert row["evidence_class"] == "NOT-TESTED" and row["result"] == "partial"


def test_skipped_phase_reported_as_skipped_by_user():
    cfg = dict(WEB_CONFIG, phases_skipped=[3])
    _, cov = verdict([], config=cfg)
    row = {r["id"]: r for r in cov}["SEC-AUTHZ-MATRIX"]
    assert row["reason"] == "skipped by user" and row["skipped_by_user"]


# --------------------------------------------------------------------------- verdict

def test_unwaived_critical_blocks():
    v, _ = verdict([finding(1, sev="critical")])
    assert v["verdict"] == "BLOCK"


def test_waived_high_does_not_block():
    w = {"id": "W-001", "match": {"finding_id": "RG-T-001"}, "reason": "accepted for beta", "owner": "me",
         "created": "2026-01-01", "expires": "2999-01-01"}
    entries = [finding(1, sev="high"), check(2, "SEC-SECRETS-HISTORY"), check(3, "SEC-AUTHZ-MATRIX", cat="authz")]
    v, _ = verdict(entries, waivers=[w])
    assert v["verdict"] == "SHIP WITH ACCEPTED RISKS"
    assert any("waived by W-001" in c for c in v["caps"])


def test_exploited_high_blocks_even_when_waived():
    w = {"id": "W-001", "match": {"finding_id": "RG-T-001"}, "reason": "accepted for beta", "owner": "me",
         "created": "2026-01-01", "expires": "2999-01-01"}
    v, _ = verdict([finding(1, sev="high", cls="EXPLOITED")], waivers=[w])
    assert v["verdict"] == "BLOCK"
    assert "cannot be waived" in v["blocking"][0]


def test_expired_waiver_not_honored():
    w = {"id": "W-001", "match": {"finding_id": "RG-T-001"}, "reason": "accepted for beta", "owner": "me",
         "created": "2020-01-01", "expires": "2020-02-01"}
    active, expired = rb.split_waivers([w], on="2026-10-18")
    assert not active and expired
    v, _ = verdict([finding(1, sev="high")], waivers=active)
    assert v["verdict"] == "BLOCK"


def test_ship_requires_all_critical_verified_and_upheld():
    entries = [check(1, "SEC-SECRETS-HISTORY"), check(2, "SEC-AUTHZ-MATRIX", cat="authz")]
    v, _ = verdict(entries)
    assert v["verdict"] == "SHIP", v


def test_not_upheld_verified_absent_caps():
    entries = [check(1, "SEC-SECRETS-HISTORY", upheld=False), check(2, "SEC-AUTHZ-MATRIX", cat="authz")]
    v, _ = verdict(entries)
    assert v["verdict"] == "SHIP WITH ACCEPTED RISKS"


def test_fails_closed_when_critical_checks_not_tested():
    v, _ = verdict([])  # nothing ran at all
    assert v["verdict"] == "BLOCK"
    assert v["blocking"][0].startswith("insufficient evidence")


def test_one_of_two_not_tested_still_blocks_half_rule():
    v, _ = verdict([check(1, "SEC-SECRETS-HISTORY")])
    assert v["verdict"] == "BLOCK"


def test_user_skip_caps_but_does_not_fail_closed():
    cfg = dict(WEB_CONFIG, phases_skipped=[3])
    v, _ = verdict([check(1, "SEC-SECRETS-HISTORY")], config=cfg)
    assert v["verdict"] == "SHIP WITH ACCEPTED RISKS"


def test_quick_mode_never_ships():
    v, _ = verdict([check(1, "SEC-SECRETS-HISTORY")], mode="quick")
    assert v["verdict"] == "SHIP WITH ACCEPTED RISKS"
    assert any("quick mode" in c for c in v["caps"])


def test_open_medium_caps():
    entries = [check(1, "SEC-SECRETS-HISTORY"), check(2, "SEC-AUTHZ-MATRIX", cat="authz"), finding(3, sev="medium")]
    v, _ = verdict(entries)
    assert v["verdict"] == "SHIP WITH ACCEPTED RISKS"


def test_legal_mode_not_evaluated():
    v, _ = verdict([], mode="legal")
    assert v["verdict"] == "NOT-EVALUATED"


# --------------------------------------------------------------------------- trend

def test_trend_new_fixed_regression():
    hist = [
        {"run_at": "1", "findings": [{"key": "a", "open": True}, {"key": "b", "open": True}]},
        {"run_at": "2", "findings": [{"key": "a", "open": False}, {"key": "b", "open": True}]},
    ]
    entries = [finding(1, fingerprint="a"), finding(2, fingerprint="c")]
    t = rb.compute_trend(entries, hist)
    assert t["regressions"] == ["a"] and t["fixed"] == ["b"] and t["new"] == ["c"]


# --------------------------------------------------------------------------- end to end

def _project(tmp_path: Path, entries, config=WEB_CONFIG) -> Path:
    sd = rglib.state_dir(tmp_path)
    (sd / "evidence").mkdir(exist_ok=True)
    (sd / "evidence" / "x.txt").write_text("tool output\n")
    rglib.dump_data(sd / "findings.json", entries)
    rglib.dump_data(sd / "config.yaml", config)
    return tmp_path


def test_build_writes_all_formats_and_lints_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(rb, "load_catalog", lambda path=None: CATALOG)
    entries = [finding(1, sev="high", cls="EXPLOITED", check="SEC-AUTHZ-MATRIX", cat="authz",
                       impact="Any user can read any other user's messages by changing the id in the URL.",
                       location={"endpoint": "GET /api/messages/:id"}),
               check(2, "SEC-SECRETS-HISTORY")]
    proj = _project(tmp_path, entries)
    code, res = rb.build(proj, "full", date="2026-10-18")
    assert code == 0, res["problems"]
    assert res["verdict"]["verdict"] == "BLOCK"
    for ext in ("md", "html", "sarif", "json"):
        assert res["paths"][ext].exists()
    md = res["paths"]["md"].read_text()
    assert "Coverage matrix" in md and "RG-T-001" in md
    assert "## Disclaimer" in md and "not legal advice" in md
    assert json.loads(res["paths"]["json"].read_text())["disclaimer"] == rb.DISCLAIMER
    sarif = json.loads(res["paths"]["sarif"].read_text())
    assert sarif["runs"][0]["results"][0]["properties"]["evidence_class"] == "EXPLOITED"
    assert list((proj / ".release-gate" / "history").glob("*.json"))


def test_build_escapes_untrusted_html(tmp_path, monkeypatch):
    monkeypatch.setattr(rb, "load_catalog", lambda path=None: CATALOG)
    evil = finding(1, sev="low", title='<img src=x onerror=alert(1)> [click](javascript:alert(1))')
    proj = _project(tmp_path, [evil])
    code, res = rb.build(proj, "full", date="2026-10-18")
    page = res["paths"]["html"].read_text()
    assert "<img src=x" not in page
    assert "javascript:" not in page.split("<main>")[1].replace("[click](javascript:alert(1))", "") or 'href="javascript' not in page
    assert 'href="javascript' not in page


def test_build_redacts_secrets_in_titles(tmp_path, monkeypatch):
    monkeypatch.setattr(rb, "load_catalog", lambda path=None: CATALOG)
    leaky = finding(1, sev="low", title="key AKIAIOSFODNN7EXAMPLE committed")
    proj = _project(tmp_path, [leaky])
    code, res = rb.build(proj, "full", date="2026-10-18")
    for p in res["paths"].values():
        assert "AKIAIOSFODNN7EXAMPLE" not in p.read_text()


def test_build_fails_lint_on_pass_without_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(rb, "load_catalog", lambda path=None: CATALOG)
    bad = check(1, "SEC-SECRETS-HISTORY")
    bad["evidence"] = [{"type": "tool-output", "path": "evidence/does-not-exist.txt"}]
    proj = _project(tmp_path, [bad])
    code, res = rb.build(proj, "full", date="2026-10-18")
    assert code == 2
    assert all(".lint-failed." in p.name for p in res["paths"].values())
    assert any("missing" in p for p in res["problems"])


# --------------------------------------------------------------------------- lint unit

@pytest.mark.parametrize("line", [
    "The app is secure.", "We found no vulnerabilities.", "Fully compliant with GDPR.",
    "This is production-ready.", "Best practices followed.", "The upload handler appears safe.", "Looks good!", "Great job",
])
def test_lint_banned_phrases(tmp_path, line):
    p = tmp_path / "r.md"
    p.write_text(line + "\n")
    assert any("banned phrase" in x for x in rl.lint_markdown(p))


def test_lint_banned_phrase_allowed_with_verified_absent_link(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "t.txt").write_text("ok")
    rep = tmp_path / "reports"
    rep.mkdir()
    p = rep / "r.md"
    p.write_text("Session cookie handling is secure for this vector: VERIFIED-ABSENT [t](../evidence/t.txt)\n")
    assert rl.lint_markdown(p) == []


def test_lint_cookie_secure_flag_not_banned(tmp_path):
    p = tmp_path / "r.md"
    p.write_text("Session cookie lacks the Secure flag. Set Secure, HttpOnly and SameSite.\n")
    assert rl.lint_markdown(p) == []


def test_lint_table_row_claim_without_link(tmp_path):
    p = tmp_path / "r.md"
    p.write_text("| SEC-X | 2 | yes | VERIFIED-ABSENT | ok | — | — |\n")
    assert any("links no artifact" in x for x in rl.lint_markdown(p))


def test_lint_entries():
    entries = [
        {"id": "RG-A-001", "kind": "check", "title": "x pass", "category": "sast", "evidence_class": "VERIFIED-ABSENT", "evidence": []},
        {"id": "RG-A-002", "kind": "check", "title": "x nt", "category": "sast", "evidence_class": "NOT-TESTED", "evidence": []},
        {"id": "RG-A-003", "kind": "finding", "title": "x none", "category": "sast", "severity": "low", "evidence": []},
    ]
    probs = rl.lint_entries("r.json", entries, None)
    assert any("RG-A-001" in p and "without an artifact" in p for p in probs)
    assert any("RG-A-002" in p and "without a reason" in p for p in probs)
    assert any("RG-A-003" in p and "evidence class" in p for p in probs)


def test_lint_secret_detection(tmp_path):
    p = tmp_path / "r.sarif"
    p.write_text('{"x": "ghp_' + "a" * 36 + '"}')
    probs = rl.lint_paths([p])
    assert probs and "ghp_" + "a" * 36 not in probs[0]


def test_lint_html_external_assets(tmp_path):
    p = tmp_path / "r.html"
    p.write_text('<html><head><script src="https://cdn.example/x.js"></script></head></html>')
    probs = rl.lint_html(p)
    assert any("<script>" in x for x in probs) and any("external asset" in x for x in probs)


# --------------------------------------------------------------------------- rglib bits used by the report

def test_redact_value_keeps_four_chars():
    assert rglib.redact_value("sk_live_abcdef123456") == "sk_l" + rglib.REDACTION_MARK


@pytest.mark.parametrize("url,test,ok", [
    ("http://127.0.0.1:3000/api", "authz", True),
    ("http://127.0.0.1:3001/api", "authz", False),
    ("https://api.stripe.com", "scan", False),
    ("https://prod.example.com", "stress", False),
    ("https://prod.example.com", "scan", True),
    ("ftp://127.0.0.1:3000/x", "authz", False),
    ("file://127.0.0.1:3000/etc/passwd", "authz", False),
])
def test_check_scope(url, test, ok):
    scope = {"targets": [
        {"url": "http://127.0.0.1:3000", "environment": "local"},
        {"url": "https://prod.example.com", "environment": "production", "owned_confirmed": True,
         "production_confirmation": "yes test https://prod.example.com", "allowed_tests": ["passive", "scan", "stress"]},
    ], "excluded_hosts": ["api.stripe.com"]}
    assert rglib.check_scope(url, test, scope)[0] is ok


def test_check_scope_fails_closed_without_scope():
    assert rglib.check_scope("http://127.0.0.1:3000", "scan", None) == (False, "no confirmed scope (.release-gate/scope.yaml missing or empty)")


# ---- host identity: proofs may only read planted canaries (phase 03) -------------------------

IDENT = {"hostname": "devbox-7731", "home path": "/home/someuser"}


def test_host_identity_flags_hostname_and_home_in_reports():
    assert rl.lint_host_identity("r.md", "fetched: devbox-7731\n", IDENT)
    assert rl.lint_host_identity("r.md", "path /home/someuser/.ssh/id_rsa", IDENT)
    assert not rl.lint_host_identity("r.md", "devbox-77310 and xdevbox-7731 are different words", IDENT)


def test_host_identity_in_evidence_ignores_project_paths_but_flags_host_files(tmp_path):
    ev = tmp_path / "evidence" / "dyn"
    ev.mkdir(parents=True)
    (ev / "semgrep.sarif").write_text('{"uri": "/home/someuser/proj/app.py"}')
    assert rl.lint_evidence(tmp_path, IDENT) == []
    (ev / "ssrf.out").write_text("root:x:0:0:root:/root:/bin/bash\n")
    (ev / "ssrf2.out").write_text("HTTP/1.1 200\n\ndevbox-7731\n")
    probs = rl.lint_evidence(tmp_path, IDENT)
    assert any("passwd" in p for p in probs) and any("hostname" in p for p in probs)


def test_host_identity_skips_short_or_localhost(monkeypatch):
    monkeypatch.setattr(rl.socket, "gethostname", lambda: "localhost")
    assert "hostname" not in rl.host_identity()
