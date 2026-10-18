"""Tests for explain_finding.py."""
from __future__ import annotations

import json
from pathlib import Path

import explain_finding as ef
import rglib


def entry(**kw):
    e = {"id": "RG-AUTHZ-001", "kind": "finding", "title": "Any user can read another user's messages",
         "severity": "high", "category": "authz", "evidence_class": "EXPLOITED", "check_id": "SEC-AUTHZ-MATRIX",
         "status": "open", "location": {"endpoint": "GET /api/messages/:id", "file": "app/routes.py", "line": 41},
         "impact": "A logged-in user can read every other user's private messages by changing the id.",
         "repro": "Log in as user A, request GET /api/messages/<id of a message owned by user B>.",
         "fix": "Check message.owner_id against the session user before returning it.",
         "evidence": [{"type": "request-response", "path": "evidence/authz/idor-1.txt", "description": "B's message returned to A"}],
         "adversarial": {"required": True, "outcome": "upheld", "summary": "Fresh reviewer reproduced it."}}
    e.update(kw)
    return e


def project(tmp_path: Path, entries) -> Path:
    sd = tmp_path / ".release-gate"
    (sd / "evidence" / "authz").mkdir(parents=True)
    (sd / "findings.json").write_text(json.dumps(entries))
    return tmp_path


def test_render_has_all_sections_from_entry_fields():
    md = ef.render(entry())
    for needle in ("# RG-AUTHZ-001: Any user can read", "## What an attacker could do", "changing the id",
                   "## Why the evidence class is EXPLOITED", "## How to reproduce it", "GET /api/messages/<id",
                   "## How to fix it", "owner_id", "Outcome: upheld", "`evidence/authz/idor-1.txt`",
                   "## What would change the verdict", "`app/routes.py:41`"):
        assert needle in md, needle
    assert "waiver does not lift the block" in md       # exploited high


def test_class_explanations_differ_and_name_the_upgrade_path():
    sus = ef.render(entry(evidence_class="SUSPECTED", evidence=[], severity="medium"))
    assert "not reproduced" in sus and "To reach EXPLOITED" in sus and "can't mark it fixed" in sus
    tc = ef.render(entry(evidence_class="TOOL-CONFIRMED", verification={"code_ref": "app/routes.py:41", "verdict": "confirmed"}))
    assert "`app/routes.py:41`" in tc and "To reach EXPLOITED" in tc
    nt = ef.render(entry(evidence_class="NOT-TESTED", evidence=[], not_tested_reason="target not running"))
    assert "target not running" in nt


def test_explain_does_not_change_the_entry():
    e = entry()
    before = json.dumps(e, sort_keys=True)
    ef.render(e)
    assert json.dumps(e, sort_keys=True) == before


def test_secrets_are_redacted():
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    md = ef.render(entry(repro=f"Use the key {key} from config.py", impact=f"Leaked {key}"))
    assert key not in md
    assert "AKIA" + rglib.REDACTION_MARK in md
    assert rglib.find_secrets(md) == []


def test_cli_prints_markdown(tmp_path: Path, capsys):
    proj = project(tmp_path, [entry()])
    (proj / ".release-gate" / "evidence" / "authz" / "idor-1.txt").write_text("x")
    assert ef.main(["--project", str(proj), "RG-AUTHZ-001"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# RG-AUTHZ-001")
    assert "(file present)" in out


def test_unknown_id_exits_2_with_message(tmp_path: Path, capsys):
    proj = project(tmp_path, [entry()])
    assert ef.main(["--project", str(proj), "RG-NOPE-999"]) == 2
    err = capsys.readouterr().err
    assert "RG-NOPE-999" in err and "RG-AUTHZ-001" in err


def test_no_findings_file_exits_2(tmp_path: Path, capsys):
    assert ef.main(["--project", str(tmp_path), "RG-AUTHZ-001"]) == 2
    assert "No findings are recorded" in capsys.readouterr().err


def test_reads_extra_findings_files(tmp_path: Path, capsys):
    proj = project(tmp_path, [])
    (proj / ".release-gate" / "authz_findings.json").write_text(json.dumps({"entries": [entry()]}))
    assert ef.main(["--project", str(proj), "RG-AUTHZ-001"]) == 0


def test_check_entry_is_explained_as_a_check():
    chk = {"id": "RG-SECRETS-010", "kind": "check", "title": "gitleaks 8.30.1 found no secrets in full git history",
           "category": "secrets", "evidence_class": "VERIFIED-ABSENT", "check_id": "SEC-SECRETS-HISTORY",
           "evidence": [{"type": "tool-output", "path": "evidence/gitleaks.json"}]}
    md = ef.render(chk)
    assert "## What this check covers" in md and "only for that test" in md
