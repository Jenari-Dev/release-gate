"""Offline tests for dedupe_findings.py, driven by normalize_findings output on the sample files."""
import copy
import hashlib
import json
import random
from pathlib import Path


import dedupe_findings as dd
import normalize_findings as nf
import rglib

DATA = Path(__file__).resolve().parent / "data" / "tool-outputs"

ALL_INPUTS = [
    ("semgrep", "semgrep.json"), ("bandit", "bandit.json"), ("sarif", "semgrep.sarif"), ("sarif", "codeql.sarif"),
    ("gitleaks", "gitleaks.json"), ("trufflehog", "trufflehog.jsonl"), ("trivy", "trivy.json"),
    ("osv-scanner", "osv-scanner.json"), ("npm-audit", "npm-audit.json"), ("pip-audit", "pip-audit.json"),
    ("checkov", "checkov.json"), ("hadolint", "hadolint.json"), ("zap", "zap.json"), ("nuclei", "nuclei.jsonl"),
]


def normalized(tmp_path: Path, inputs=ALL_INPUTS) -> list[dict]:
    out = tmp_path / "findings.json"
    for tool, name in inputs:
        assert nf.main(["--tool", tool, "--input", str(DATA / name), "--out", str(out)]) == 0
    return json.loads(out.read_text())


def merged_with(entries, **loc):
    """The merged finding whose location matches all given key/values."""
    hits = [e for e in entries if e["kind"] == "finding"
            and all((e.get("location") or {}).get(k) == v for k, v in loc.items())]
    return hits


def make(id, **over):
    base = {"id": id, "kind": "finding", "title": "Something wrong", "severity": "medium", "category": "injection",
            "evidence_class": "SUSPECTED", "evidence": [{"type": "tool-output", "path": f"evidence/{id}.json"}],
            "location": {"file": "src/a.js", "line": 10}, "cwe": ["CWE-89"], "tool": {"name": "t1", "rule_id": "r1"},
            "created_at": "2026-10-18T00:00:00+00:00", "status": "open"}
    base.update(over)
    return base


# --------------------------------------------------------------------------- cross-tool merges

def test_sql_injection_merges_across_semgrep_bandit_sarif_codeql(tmp_path):
    entries = normalized(tmp_path)
    out, log = dd.dedupe(entries)
    (m,) = merged_with(out, file="app/db.py")  # semgrep 27, bandit 28 (same line//3 bucket), sarif 27, codeql 27
    assert m["category"] == "injection" and m["cwe"] == ["CWE-89"]
    assert m["severity"] == "high"  # CodeQL security-severity 8.8 beats the two "medium"
    assert m["sources"] == ["CodeQL", "Semgrep OSS", "bandit", "semgrep"]
    assert {e["path"] for e in m["evidence"]} >= {str(DATA / "semgrep.json"), str(DATA / "bandit.json"),
                                                  str(DATA / "semgrep.sarif"), str(DATA / "codeql.sarif")}
    assert len(m["evidence"]) == 4
    assert any("merged into" in line for line in log)


def test_hardcoded_credential_merges_gitleaks_and_bandit_via_cwe_fold(tmp_path):
    out, _ = dd.dedupe(normalized(tmp_path))
    (m,) = merged_with(out, file="app/settings.py")
    assert m["category"] == "secrets" and m["sources"] == ["bandit", "gitleaks"]
    assert m["severity"] == "high"  # gitleaks high > bandit low
    assert m["cwe"] == ["CWE-259", "CWE-798"]


def test_aws_key_merges_gitleaks_trufflehog_trivy_keeps_critical(tmp_path):
    out, _ = dd.dedupe(normalized(tmp_path))
    (m,) = merged_with(out, file="config/prod.env")
    assert m["sources"] == ["gitleaks", "trivy", "trufflehog"]
    assert m["severity"] == "critical" and m["evidence_class"] == "SUSPECTED"
    assert len(m["evidence"]) == 3


def test_sca_merges_across_osv_npm_trivy_by_package_and_advisory(tmp_path):
    out, _ = dd.dedupe(normalized(tmp_path))
    lodash = [e for e in out if e["kind"] == "finding" and e["category"] == "sca"
              and (e["location"].get("component") or "").startswith("lodash")]
    assert len(lodash) == 2  # command injection (osv+npm+trivy merged) and prototype pollution (npm only)
    cmd = next(e for e in lodash if "GHSA-35jh-r3h4-6jhm" in e["tool"]["rule_id"])
    assert cmd["sources"] == ["npm-audit", "osv-scanner", "trivy"]
    assert cmd["tool"]["rule_id"] == "CVE-2021-23337, GHSA-35jh-r3h4-6jhm"
    assert cmd["severity"] == "high"
    proto = next(e for e in lodash if e is not cmd)
    assert proto["tool"]["rule_id"] == "GHSA-p6mc-m468-83gw" and proto["sources"] == ["npm-audit"]
    assert cmd["fingerprint"] == hashlib.sha256(b"sca|lodash|CVE-2021-23337").hexdigest()


def test_sca_merges_osv_and_pip_audit_despite_name_case_and_different_primary_ids(tmp_path):
    out, _ = dd.dedupe(normalized(tmp_path))
    jinja = [e for e in out if e["kind"] == "finding" and "jinja2" in (e["location"].get("component") or "").lower()]
    assert len(jinja) == 1  # osv "Jinja2" (GHSA primary) + pip-audit "jinja2" (PYSEC primary)
    (m,) = jinja
    assert m["sources"] == ["osv-scanner", "pip-audit"]
    assert m["severity"] == "high"  # osv 8.6 beats pip-audit's defaulted medium
    assert m["tool"]["rule_id"] == "CVE-2019-10906, GHSA-462w-v97r-4m45, PYSEC-2019-217"


def test_different_packages_with_distinct_advisories_do_not_merge():
    a = make("RG-SCA-001", category="sca", cwe=[], location={"component": "lodash@4.17.15"}, tool={"name": "osv-scanner", "rule_id": "CVE-2021-23337"})
    b = make("RG-SCA-002", category="sca", cwe=[], location={"component": "lodash@4.17.15"}, tool={"name": "trivy", "rule_id": "CVE-2020-8203"})
    c = make("RG-SCA-003", category="sca", cwe=[], location={"component": "express@4.17.1"}, tool={"name": "trivy", "rule_id": "CVE-2021-23337"})
    out, _ = dd.dedupe([a, b, c])
    assert len(out) == 3


def test_sca_overlap_is_transitive():
    a = make("RG-SCA-001", category="sca", cwe=[], location={"component": "x@1"}, tool={"name": "a", "rule_id": "GHSA-aaaa-bbbb-cccc"})
    b = make("RG-SCA-002", category="sca", cwe=[], location={"component": "x@1"}, tool={"name": "b", "rule_id": "GHSA-aaaa-bbbb-cccc, CVE-2020-0001"})
    c = make("RG-SCA-003", category="sca", cwe=[], location={"component": "x@2"}, tool={"name": "c", "rule_id": "CVE-2020-0001"})
    out, _ = dd.dedupe([a, b, c])
    assert len(out) == 1 and out[0]["sources"] == ["a", "b", "c"]


def test_every_output_entry_validates_and_findings_get_fingerprints(tmp_path):
    out, _ = dd.dedupe(normalized(tmp_path))
    for e in out:
        assert rglib.validate(e, "finding") == []
        if e["kind"] == "finding":
            assert len(e["fingerprint"]) == 64 and e["sources"]
        else:
            assert "fingerprint" not in e and "sources" not in e


def test_merging_reduces_count_and_fingerprints_are_unique(tmp_path):
    entries = normalized(tmp_path)
    out, _ = dd.dedupe(entries)
    assert len(out) < len(entries)
    fps = [e["fingerprint"] for e in out if e["kind"] == "finding"]
    assert len(fps) == len(set(fps))


# --------------------------------------------------------------------------- fingerprint rules

def test_nearby_lines_merge_but_distant_lines_do_not():
    a, b = make("RG-INJECTION-001", location={"file": "src/a.js", "line": 10}), make("RG-INJECTION-002", location={"file": "src/a.js", "line": 11}, tool={"name": "t2", "rule_id": "r2"})
    far = make("RG-INJECTION-003", location={"file": "src/a.js", "line": 20})
    other_file = make("RG-INJECTION-004", location={"file": "src/b.js", "line": 10})
    other_cwe = make("RG-INJECTION-005", cwe=["CWE-78"])
    other_cat = make("RG-XSS-001", category="xss")
    out, _ = dd.dedupe([a, b, far, other_file, other_cwe, other_cat])
    assert len(out) == 5
    (m,) = [e for e in out if e["sources"] == ["t1", "t2"]]
    assert m["id"] == "RG-INJECTION-001"


def test_fingerprint_formula_is_as_documented():
    e = make("RG-INJECTION-001", location={"file": "./src\\a.js", "line": 10}, cwe=["CWE-89", "CWE-564"])
    want = hashlib.sha256("injection|src/a.js|3|CWE-89".encode()).hexdigest()
    assert dd.fingerprint(e) == want
    e2 = make("RG-INJECTION-009", location={"file": "/work/proj/src/a.js", "line": 11}, cwe=["CWE-564", "CWE-89"])
    assert dd.fingerprint(e2, root="/work/proj") == want


def test_fingerprint_falls_back_to_rule_id_then_title():
    e = make("RG-SAST-001", category="sast", cwe=[], tool={"name": "t", "rule_id": "Py/Some-Rule"})
    assert dd.fingerprint(e) == hashlib.sha256("sast|src/a.js|3|py/some-rule".encode()).hexdigest()
    e = make("RG-SAST-002", category="sast", cwe=[], tool={"name": "t"}, title="  Odd   Thing ")
    assert dd.fingerprint(e) == hashlib.sha256("sast|src/a.js|3|title:odd thing".encode()).hexdigest()


def test_endpoint_findings_merge_ignoring_method_host_and_query():
    a = make("RG-HEADERS-001", category="headers", location={"endpoint": "GET /login"}, cwe=["CWE-693"])
    b = make("RG-HEADERS-002", category="headers", location={"endpoint": "http://localhost:3000/login?x=1"}, cwe=["CWE-693"], tool={"name": "t2"})
    out, _ = dd.dedupe([a, b])
    assert len(out) == 1 and out[0]["sources"] == ["t1", "t2"]


def test_findings_without_any_location_are_never_merged():
    a = make("RG-OTHER-001", category="other", location={}, cwe=[], tool={})
    b = make("RG-OTHER-002", category="other", location={}, cwe=[], tool={})
    a.pop("location"), b.pop("location")
    out, _ = dd.dedupe([a, b])
    assert len(out) == 2


# --------------------------------------------------------------------------- merge semantics

def test_strongest_evidence_class_wins_and_primary_is_that_entry():
    sus = make("RG-INJECTION-001", severity="critical", tool={"name": "t1", "rule_id": "r1"})
    conf = make("RG-INJECTION-002", severity="low", evidence_class="TOOL-CONFIRMED", tool={"name": "t2"},
                verification={"verdict": "confirmed", "code_ref": "src/a.js:10"})
    out, _ = dd.dedupe([sus, conf])
    (m,) = out
    assert m["evidence_class"] == "TOOL-CONFIRMED" and m["id"] == "RG-INJECTION-002"
    assert m["severity"] == "critical"  # highest severity still wins
    assert m["verification"]["verdict"] == "confirmed"
    assert len(m["evidence"]) == 2
    assert rglib.validate(m, "finding") == []

    expl = make("RG-INJECTION-003", evidence_class="EXPLOITED", tool={"name": "t3"})
    (m,) = dd.dedupe([sus, conf, expl])[0]
    assert m["evidence_class"] == "EXPLOITED" and m["sources"] == ["t1", "t2", "t3"]


def test_evidence_union_has_no_duplicates():
    a = make("RG-INJECTION-001", evidence=[{"type": "tool-output", "path": "evidence/x.json"}])
    b = make("RG-INJECTION-002", evidence=[{"type": "tool-output", "path": "evidence/x.json"},
                                           {"type": "repro-script", "path": "evidence/repro.sh"}])
    (m,) = dd.dedupe([a, b])[0]
    assert [(e["type"], e["path"]) for e in m["evidence"]] == [("tool-output", "evidence/x.json"), ("repro-script", "evidence/repro.sh")]


def test_missing_optional_fields_are_filled_from_other_members():
    a = make("RG-INJECTION-001")
    b = make("RG-INJECTION-002", fix="Use parameterized queries", impact="Data theft", tool={"name": "t2"})
    (m,) = dd.dedupe([a, b])[0]
    assert m["fix"] == "Use parameterized queries" and m["impact"] == "Data theft"


# --------------------------------------------------------------------------- checks

def test_checks_are_never_merged_into_findings_or_each_other():
    finding = make("RG-INJECTION-001", category="secrets", cwe=["CWE-798"], location={"file": "a.py", "line": 1})
    absent = {"id": "RG-SECRETS-001", "kind": "check", "title": "gitleaks reported no findings (scope: full git history)",
              "category": "secrets", "evidence_class": "VERIFIED-ABSENT",
              "evidence": [{"type": "tool-output", "path": "evidence/gitleaks.json"}],
              "tool": {"name": "gitleaks", "rule_id": "r1"}, "location": {"file": "a.py", "line": 1}, "cwe": ["CWE-798"]}
    absent2 = copy.deepcopy(absent) | {"id": "RG-SECRETS-002"}
    nt = {"id": "RG-SECRETS-003", "kind": "check", "title": "trufflehog produced no output file", "category": "secrets",
          "evidence_class": "NOT-TESTED", "not_tested_reason": "tool produced no output file", "evidence": []}
    entries = [finding, absent, absent2, nt]
    before = copy.deepcopy(entries)
    out, _ = dd.dedupe(entries)
    assert entries == before  # input untouched
    assert len(out) == 4
    checks_out = [e for e in out if e["kind"] == "check"]
    assert checks_out == [absent, absent2, nt]  # byte-for-byte unchanged, no fingerprint/sources added
    (f,) = [e for e in out if e["kind"] == "finding"]
    assert f["evidence_class"] == "SUSPECTED" and f["sources"] == ["t1"]


def test_checks_from_normalizer_survive_dedupe_untouched(tmp_path):
    entries = normalized(tmp_path)
    in_checks = [e for e in entries if e["kind"] == "check"]
    assert in_checks  # pip-audit coverage gap
    out, _ = dd.dedupe(entries)
    assert [e for e in out if e["kind"] == "check"] == in_checks


# --------------------------------------------------------------------------- determinism

def test_output_order_is_severity_then_id_with_checks_last(tmp_path):
    out, _ = dd.dedupe(normalized(tmp_path))
    fs = [e for e in out if e["kind"] == "finding"]
    keys = [(rglib.SEVERITY_RANK[e["severity"]], dd.natural_key(e["id"])) for e in fs]
    assert keys == sorted(keys)
    kinds = [e["kind"] for e in out]
    assert kinds == sorted(kinds, key=lambda k: k == "check")  # all findings before all checks


def test_natural_id_order():
    a, b = make("RG-INJECTION-999", severity="low", location={"file": "x", "line": 1}), make("RG-INJECTION-1000", severity="low", location={"file": "y", "line": 1})
    out, _ = dd.dedupe([b, a])
    assert [e["id"] for e in out] == ["RG-INJECTION-999", "RG-INJECTION-1000"]


def test_output_is_independent_of_input_order(tmp_path):
    entries = normalized(tmp_path)
    want, _ = dd.dedupe(entries)
    for seed in (1, 2, 3):
        shuffled = entries[:]
        random.Random(seed).shuffle(shuffled)
        got, _ = dd.dedupe(shuffled)
        assert got == want


def test_dedupe_is_idempotent(tmp_path):
    once, _ = dd.dedupe(normalized(tmp_path))
    twice, log = dd.dedupe(once)
    assert twice == once and log == []


# --------------------------------------------------------------------------- CLI

def test_cli_roundtrip(tmp_path, capsys):
    src = tmp_path / "findings.json"
    normalized(tmp_path)
    out = tmp_path / "deduped.json"
    assert dd.main(["--in", str(src), "--out", str(out)]) == 0
    got = json.loads(out.read_text())
    assert len(got) < len(json.loads(src.read_text()))
    assert "merged into" in capsys.readouterr().err
    for e in got:
        assert rglib.validate(e, "finding") == []


def test_cli_root_option_merges_absolute_and_relative_paths(tmp_path):
    a = make("RG-INJECTION-001", location={"file": "/work/p/src/a.js", "line": 10})
    b = make("RG-INJECTION-002", location={"file": "src/a.js", "line": 10}, tool={"name": "t2"})
    src, out = tmp_path / "in.json", tmp_path / "out.json"
    src.write_text(json.dumps([a, b]))
    assert dd.main(["--in", str(src), "--out", str(out)]) == 0
    assert len(json.loads(out.read_text())) == 2
    assert dd.main(["--in", str(src), "--out", str(out), "--root", "/work/p"]) == 0
    assert len(json.loads(out.read_text())) == 1


def test_cli_errors(tmp_path, monkeypatch):
    out = tmp_path / "out.json"
    assert dd.main(["--in", str(tmp_path / "missing.json"), "--out", str(out)]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a list"}')
    assert dd.main(["--in", str(bad), "--out", str(out)]) == 2
    good = tmp_path / "good.json"
    good.write_text(json.dumps([make("RG-INJECTION-001")]))
    monkeypatch.setattr(rglib, "validate", lambda obj, name: ["boom"])
    assert dd.main(["--in", str(good), "--out", str(out)]) == 1
    assert not out.exists()


def test_cli_subprocess(tmp_path):
    import subprocess
    import sys
    src, out = tmp_path / "in.json", tmp_path / "out.json"
    src.write_text(json.dumps([make("RG-INJECTION-001"), make("RG-INJECTION-002", tool={"name": "t2"})]))
    r = subprocess.run([sys.executable, str(Path(dd.__file__)), "--in", str(src), "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    (m,) = json.loads(out.read_text())
    assert m["sources"] == ["t1", "t2"]
