"""Tests for retest.py: what a retest re-runs and when a finding may be called fixed."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import retest
import rglib

NOW = "2026-10-18T12:00:00+00:00"


def finding(i, cls="EXPLOITED", sev="high", check="SEC-AUTHZ-MATRIX", cat="authz", status="open", loc=None, **kw):
    e = {"id": f"RG-AUTHZ-{i:03d}", "kind": "finding", "title": f"finding {i}", "severity": sev, "category": cat,
         "evidence_class": cls, "check_id": check, "status": status, "evidence": [],
         "location": loc if loc is not None else {"endpoint": "GET /api/messages/:id"}}
    if cls in rglib.ARTIFACT_REQUIRED:
        e["evidence"] = [{"type": "request-response", "path": f"evidence/original-{i}.txt"}]
    e.update(kw)
    return e


def absent(i=900, check="SEC-AUTHZ-MATRIX", evidence=None, **kw):
    e = {"id": f"RG-AUTHZ-{i:03d}", "kind": "check", "title": "authz matrix re-run found no cross-user read",
         "category": "authz", "evidence_class": "VERIFIED-ABSENT", "check_id": check,
         "evidence": evidence if evidence is not None else [{"type": "request-response", "path": "evidence/retest-1.txt"}]}
    e.update(kw)
    return e


def not_tested(i=901, check="SEC-AUTHZ-MATRIX"):
    return {"id": f"RG-AUTHZ-{i:03d}", "kind": "check", "title": "authz matrix not run", "category": "authz",
            "evidence_class": "NOT-TESTED", "check_id": check, "evidence": [],
            "not_tested_reason": "target not running"}


def run(prev, new, **kw):
    return retest.apply(prev, new, now=NOW, **kw)


def by_id(entries, i):
    return next(e for e in entries if e["id"] == i)


# --------------------------------------------------------------------------- plan

def test_plan_selects_open_reproduced_and_suspected():
    prev = [
        finding(1, "EXPLOITED"),
        finding(2, "TOOL-CONFIRMED", check="SEC-SAST", cat="sast"),
        finding(3, "SUSPECTED", check="SEC-SAST", cat="sast"),
        finding(4, "EXPLOITED", status="fix-proposed"),
    ]
    items = retest.plan(prev)
    assert [i["id"] for i in items] == ["RG-AUTHZ-001", "RG-AUTHZ-002", "RG-AUTHZ-003", "RG-AUTHZ-004"]
    by = {i["id"]: i for i in items}
    assert by["RG-AUTHZ-001"]["can_close"] is True
    assert by["RG-AUTHZ-003"]["can_close"] is False


def test_plan_skips_closed_waived_false_positive_checks_and_other_classes():
    prev = [
        finding(1, status="fixed"),
        finding(2, status="waived"),
        finding(3, status="false-positive"),
        absent(10),
        not_tested(11),
        finding(5, "NOT-TESTED", not_tested_reason="x"),
    ]
    assert retest.plan(prev) == []


# --------------------------------------------------------------------------- apply: fixed

def test_fixed_only_with_verified_absent_and_new_evidence():
    prev = [finding(1)]
    out = run(prev, [absent()])
    e = by_id(out, "RG-AUTHZ-001")
    assert e["status"] == "fixed"
    assert e["retest"] == {"status": "no-longer-reproduces", "run_at": NOW, "evidence_path": "evidence/retest-1.txt"}
    paths = [x["path"] for x in e["evidence"]]
    assert paths == ["evidence/original-1.txt", "evidence/retest-1.txt"]
    assert e["evidence_class"] == "EXPLOITED"          # the original class is history, not rewritten
    assert rglib.validate(e, "finding") == []


def test_tool_confirmed_can_be_fixed_by_rerun():
    prev = [finding(1, "TOOL-CONFIRMED", check="SEC-SAST", cat="sast", loc={"file": "app/db.py", "line": 12})]
    new = [absent(check="SEC-SAST", evidence=[{"type": "tool-output", "path": "evidence/semgrep-2/semgrep.json"}])]
    out = run(prev, new)
    assert out[0]["status"] == "fixed"
    assert out[0]["retest"]["status"] == "no-longer-reproduces"


def test_verified_absent_without_evidence_does_not_fix():
    out = run([finding(1)], [absent(evidence=[])])
    e = out[0]
    assert e["status"] == "open"
    assert e["retest"]["status"] == "not-run"


def test_code_reference_alone_does_not_fix():
    """Reading the diff is not a re-run."""
    new = [absent(evidence=[{"type": "code-ref", "path": "evidence/diff-review.txt"}])]
    e = run([finding(1)], new)[0]
    assert e["status"] == "open"
    assert e["retest"]["status"] == "not-run"


def test_same_evidence_as_original_does_not_fix():
    new = [absent(evidence=[{"type": "request-response", "path": "evidence/original-1.txt"}])]
    e = run([finding(1)], new)[0]
    assert e["status"] == "open"
    assert e["retest"]["status"] == "not-run"


def test_missing_evidence_file_does_not_fix_when_state_dir_given(tmp_path: Path):
    sd = tmp_path / ".release-gate"
    (sd / "evidence").mkdir(parents=True)
    e = run([finding(1)], [absent()], state_dir=sd)[0]
    assert e["status"] == "open"
    (sd / "evidence" / "retest-1.txt").write_text("HTTP/1.1 403\n")
    e = run([finding(1)], [absent()], state_dir=sd)[0]
    assert e["status"] == "fixed"


# --------------------------------------------------------------------------- apply: never fixed

def test_not_tested_never_marks_fixed():
    e = run([finding(1)], [not_tested()])[0]
    assert e["status"] == "open"
    assert e["retest"]["status"] == "not-run"
    assert "evidence_path" not in e["retest"]


def test_no_new_result_leaves_status_unchanged_and_not_run():
    prev = [finding(1, status="fix-proposed")]
    e = run(prev, [])[0]
    assert e["status"] == "fix-proposed"
    assert e["retest"]["status"] == "not-run"


def test_suspected_never_marked_fixed_even_with_clean_rerun():
    prev = [finding(1, "SUSPECTED", sev="medium")]
    out, outcomes = retest.apply_detailed(prev, [absent()], now=NOW)
    e = out[0]
    assert e["status"] == "open"
    assert e["retest"]["status"] == "not-run"
    assert "SUSPECTED" in outcomes[0]["reason"]


def test_still_reproduces_stays_open_and_attaches_new_evidence():
    prev = [finding(1, status="fix-proposed")]
    new = [finding(50, "EXPLOITED", evidence=[{"type": "request-response", "path": "evidence/retest-2.txt"}])]
    e = run(prev, new)[0]
    assert e["status"] == "open"
    assert e["retest"]["status"] == "still-reproduces"
    assert e["retest"]["evidence_path"] == "evidence/retest-2.txt"
    assert [x["path"] for x in e["evidence"]].count("evidence/retest-2.txt") == 1


def test_reproduction_wins_over_absence_claim_for_same_check():
    new = [absent(), finding(50, "TOOL-CONFIRMED", evidence=[{"type": "tool-output", "path": "evidence/t.json"}])]
    e = run([finding(1)], new)[0]
    assert e["status"] == "open"
    assert e["retest"]["status"] == "still-reproduces"


# --------------------------------------------------------------------------- untouched entries

def test_waived_and_false_positive_are_untouched():
    prev = [finding(1, status="waived", waiver_id="W-001"), finding(2, status="false-positive")]
    before = copy.deepcopy(prev)
    out = run(prev, [absent()])
    assert out == before


def test_inputs_are_not_mutated():
    prev, new = [finding(1)], [absent()]
    p0, n0 = copy.deepcopy(prev), copy.deepcopy(new)
    run(prev, new)
    assert prev == p0 and new == n0


def test_check_entries_in_previous_run_pass_through():
    chk = absent(10, check="SEC-SECRETS-HISTORY")
    out = run([chk, finding(1)], [absent()])
    assert out[0] == chk


# --------------------------------------------------------------------------- matching

def test_different_endpoint_is_not_a_match():
    prev = [finding(1, loc={"endpoint": "GET /api/messages/:id"})]
    new = [finding(50, "EXPLOITED", loc={"endpoint": "GET /api/orders/:id"},
                   evidence=[{"type": "request-response", "path": "evidence/x.txt"}])]
    e = run(prev, new)[0]
    assert e["retest"]["status"] == "not-run"


def test_file_match_ignores_line_drift():
    prev = [finding(1, "TOOL-CONFIRMED", check="SEC-SAST", cat="sast", loc={"file": "app/db.py", "line": 12})]
    new = [finding(50, "TOOL-CONFIRMED", check="SEC-SAST", cat="sast", loc={"file": "./app/db.py", "line": 40},
                   evidence=[{"type": "tool-output", "path": "evidence/s.json"}])]
    assert run(prev, new)[0]["retest"]["status"] == "still-reproduces"


def test_reused_id_for_a_different_check_is_not_a_match():
    prev = [finding(1)]
    new = [finding(1, "EXPLOITED", check="SEC-SAST", cat="sast", loc={"file": "a.py"},
                   evidence=[{"type": "tool-output", "path": "evidence/s.json"}])]
    out = run(prev, new)
    old = by_id(out, "RG-AUTHZ-001")
    assert old["retest"]["status"] == "not-run"
    # the unrelated new finding is kept, under an id that doesn't collide
    added = [e for e in out if e["check_id"] == "SEC-SAST"]
    assert len(added) == 1 and added[0]["id"] != "RG-AUTHZ-001"


def test_new_unmatched_findings_are_added_and_validate():
    new = [finding(60, "EXPLOITED", check="SEC-INJECTION-DYNAMIC", cat="injection", loc={"endpoint": "POST /q"},
                   evidence=[{"type": "request-response", "path": "evidence/inj.txt"}])]
    out = run([finding(1)], new)
    assert len(out) == 2
    for e in out:
        assert rglib.validate(e, "finding") == []


# --------------------------------------------------------------------------- CLI

def _project(tmp_path: Path, prev, wrapped=False) -> Path:
    sd = tmp_path / ".release-gate"
    (sd / "evidence").mkdir(parents=True)
    (sd / "findings.json").write_text(json.dumps({"entries": prev} if wrapped else prev))
    return tmp_path


def test_cli_plan_prints_json(tmp_path: Path, capsys):
    proj = _project(tmp_path, [finding(1), finding(2, status="fixed")])
    assert retest.main(["plan", "--project", str(proj)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["count"] == 1 and data["items"][0]["id"] == "RG-AUTHZ-001"


def test_cli_plan_without_findings_exits_2(tmp_path: Path, capsys):
    assert retest.main(["plan", "--project", str(tmp_path)]) == 2
    assert "nothing to retest" in capsys.readouterr().err


def test_cli_apply_writes_validated_findings_and_backup(tmp_path: Path, capsys):
    proj = _project(tmp_path, [finding(1)], wrapped=True)
    sd = proj / ".release-gate"
    (sd / "evidence" / "retest-1.txt").write_text("HTTP/1.1 403\n")
    new = tmp_path / "new.json"
    new.write_text(json.dumps([absent()]))
    assert retest.main(["apply", "--project", str(proj), "--new", str(new)]) == 0
    out = json.loads((sd / "findings.json").read_text())
    assert isinstance(out, dict)
    e = out["entries"][0]
    assert e["status"] == "fixed" and e["retest"]["status"] == "no-longer-reproduces"
    assert (sd / "findings.pre-retest.json").exists()
    assert list((sd / "evidence").glob("retest-*/outcomes.json"))
    assert not list((sd / "history").glob("*"))      # history/ is for run summaries only
    assert '"no-longer-reproduces"' in capsys.readouterr().out


def test_cli_apply_dry_run_writes_nothing(tmp_path: Path):
    proj = _project(tmp_path, [finding(1)])
    sd = proj / ".release-gate"
    (sd / "evidence" / "retest-1.txt").write_text("x")
    new = tmp_path / "new.json"
    new.write_text(json.dumps([absent()]))
    before = (sd / "findings.json").read_text()
    assert retest.main(["apply", "--project", str(proj), "--new", str(new), "--dry-run"]) == 0
    assert (sd / "findings.json").read_text() == before


def test_cli_apply_refuses_to_write_invalid_output(tmp_path: Path, capsys):
    bad = finding(1)
    del bad["severity"]                                # invalid input stays invalid; nothing is written
    proj = _project(tmp_path, [bad])
    new = tmp_path / "new.json"
    new.write_text("[]")
    before = (proj / ".release-gate" / "findings.json").read_text()
    assert retest.main(["apply", "--project", str(proj), "--new", str(new)]) == 3
    assert (proj / ".release-gate" / "findings.json").read_text() == before
    assert "do not validate" in capsys.readouterr().err
