"""Offline tests for normalize_findings.py: sample tool outputs only, no network."""
import json
import shutil
from pathlib import Path

import pytest

import normalize_findings as nf
import rglib

DATA = Path(__file__).resolve().parent / "data" / "tool-outputs"
NOW = "2026-10-18T00:00:00+00:00"

# tool name -> sample file
SAMPLES = {
    "gitleaks": "gitleaks.json",
    "trufflehog": "trufflehog.jsonl",
    "semgrep": "semgrep.json",
    "bandit": "bandit.json",
    "osv-scanner": "osv-scanner.json",
    "npm-audit": "npm-audit.json",
    "pip-audit": "pip-audit.json",
    "trivy": "trivy.json",
    "checkov": "checkov.json",
    "hadolint": "hadolint.json",
    "zap": "zap.json",
    "nuclei": "nuclei.jsonl",
    "sarif": "semgrep.sarif",
}

# Raw secret strings present in the sample files; none may ever reach the output.
RAW_SECRETS = [
    "s3cr3t-Passw0rd-9f8e7d6c5b4a",
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "xoxb-FAKE00000000-FAKE000000000-NOTAREALSLACKTOKEN000000",
]


def run(tool: str, path: Path, **kw) -> list[dict]:
    """Normalize one file and assign ids the way the CLI does."""
    entries = nf.normalize_file(tool, path, nf.Ctx(**kw), NOW)
    ids: list[str] = []
    out = []
    for e in entries:
        e = {"id": rglib.next_id(e["category"], ids), **e}
        ids.append(e["id"])
        out.append(e)
    return out


def findings(entries):
    return [e for e in entries if e["kind"] == "finding"]


def checks(entries):
    return [e for e in entries if e["kind"] == "check"]


# --------------------------------------------------------------------------- generic contract

@pytest.mark.parametrize("tool,fname", sorted(SAMPLES.items()))
def test_every_sample_validates_and_starts_suspected(tool, fname):
    entries = run(tool, DATA / fname)
    assert findings(entries), f"{tool}: sample should produce findings"
    for e in entries:
        assert rglib.validate(e, "finding") == [], (tool, e)
    for e in findings(entries):
        assert e["evidence_class"] == "SUSPECTED"
        assert e["verification"]["verdict"] == "unverified"
        assert e["status"] == "open"
        assert e["severity"] in rglib.SEVERITIES
        assert e["evidence"][0]["type"] == "tool-output"
        assert len(e["evidence"][0]["sha256"]) == 64
        assert e["tool"]["name"]
        assert e["created_at"] == NOW


def test_sarif_codeql_validates():
    for e in run("sarif", DATA / "codeql.sarif"):
        assert rglib.validate(e, "finding") == []


# --------------------------------------------------------------------------- per-parser

def test_gitleaks():
    f = findings(run("gitleaks", DATA / "gitleaks.json"))
    assert len(f) == 2
    generic, aws = f
    assert (generic["category"], generic["severity"], generic["cwe"]) == ("secrets", "high", ["CWE-798"])
    assert generic["location"]["file"] == "app/settings.py" and generic["location"]["line"] == 12
    assert generic["tool"]["rule_id"] == "generic-api-key"
    assert aws["location"]["file"] == "config/prod.env" and aws["location"]["line"] == 3
    assert "AKIA…[REDACTED]" in aws["impact"]
    assert "unredacted secrets" in aws["evidence"][0]["description"]


def test_trufflehog_verified_is_critical_with_note_and_unverified_is_high():
    f = findings(run("trufflehog", DATA / "trufflehog.jsonl"))
    assert len(f) == 2  # the log line is not a finding
    aws, slack = f
    assert aws["severity"] == "critical" and aws["category"] == "secrets"
    assert aws["verification"]["reason"] == "verified live by trufflehog"
    assert "verified live by trufflehog" in aws["impact"]
    assert aws["evidence_class"] == "SUSPECTED"  # verified live is still only a scanner claim
    assert aws["location"] == {"file": "config/prod.env", "line": 3, "component": "commit 3f2b1c9a7d8e"}
    assert aws["tool"]["version"] == "3.88.0"
    assert slack["severity"] == "high"
    assert "reason" not in slack["verification"]
    assert slack["location"]["file"] == "scripts/notify.sh"


def test_trufflehog_filesystem_source_location(tmp_path):
    rec = {"SourceMetadata": {"Data": {"Filesystem": {"file": "a/b.env", "line": 4}}},
           "DetectorName": "Stripe", "Verified": False, "Raw": "sk_live_" + "a" * 24}
    p = tmp_path / "trufflehog.jsonl"
    p.write_text(json.dumps(rec) + "\n")
    (f,) = findings(run("trufflehog", p))
    assert f["location"] == {"file": "a/b.env", "line": 4}


def test_semgrep():
    f = findings(run("semgrep", DATA / "semgrep.json"))
    sqli, xss = f
    assert (sqli["category"], sqli["severity"], sqli["cwe"]) == ("injection", "medium", ["CWE-89"])
    assert sqli["location"] == {"file": "app/db.py", "line": 27, "end_line": 27}
    assert sqli["tool"]["version"] == "1.101.0"
    assert sqli["tool"]["scope"] == "4 files scanned"
    assert (xss["category"], xss["severity"], xss["cwe"]) == ("xss", "high", ["CWE-79"])


def test_semgrep_errors_become_not_tested_gap(tmp_path):
    d = json.loads((DATA / "semgrep.json").read_text())
    d["errors"] = [{"code": 3, "level": "warn", "type": ["PartialParsing", []], "message": "Syntax error at line app/x.py:3"}]
    d["results"] = []
    p = tmp_path / "semgrep.json"
    p.write_text(json.dumps(d))
    entries = run("semgrep", p)
    assert len(entries) == 1
    assert entries[0]["evidence_class"] == "NOT-TESTED"
    assert "incomplete coverage" in entries[0]["not_tested_reason"]


def test_bandit():
    sqli, pw = findings(run("bandit", DATA / "bandit.json"))
    assert (sqli["category"], sqli["severity"], sqli["tool"]["rule_id"]) == ("injection", "medium", "B608")
    assert sqli["location"]["file"] == "app/db.py" and sqli["location"]["line"] == 28
    assert sqli["tool"]["scope"] == "412 lines of code scanned"
    assert (pw["category"], pw["severity"], pw["cwe"]) == ("secrets", "low", ["CWE-259"])


def test_osv_scanner():
    lodash, jinja = findings(run("osv-scanner", DATA / "osv-scanner.json"))
    assert lodash["category"] == "sca" and lodash["severity"] == "high"  # max_severity 7.2
    assert lodash["location"]["component"] == "lodash@4.17.15"
    assert lodash["tool"]["rule_id"] == "GHSA-35jh-r3h4-6jhm, CVE-2021-23337"
    assert lodash["cwe"] == ["CWE-77", "CWE-94"]
    assert lodash["fix"] == "Upgrade lodash to 4.17.21"
    assert jinja["severity"] == "high"  # max_severity 8.6
    assert "PYSEC-2019-217" in jinja["tool"]["rule_id"]


def test_npm_audit_skips_transitive_only_entries():
    f = findings(run("npm-audit", DATA / "npm-audit.json"))
    assert [x["location"]["component"] for x in f] == ["lodash", "lodash", "qs"]  # express (via: ["qs"]) skipped
    cmd, proto, qs = f
    assert cmd["tool"]["rule_id"] == "GHSA-35jh-r3h4-6jhm" and cmd["severity"] == "high"
    assert cmd["cwe"] == ["CWE-77", "CWE-94"] and cmd["fix"] == "Run npm audit fix"
    assert qs["fix"] == "Upgrade express to 4.21.2"


def test_npm_audit_error_payload_is_not_tested(tmp_path):
    p = tmp_path / "npm-audit.json"
    p.write_text(json.dumps({"error": {"code": "ENOLOCK", "summary": "This command requires an existing lockfile."}}))
    (e,) = run("npm-audit", p)
    assert e["evidence_class"] == "NOT-TESTED"
    assert e["not_tested_reason"].startswith("tool output unparseable: npm-audit:")
    assert "ENOLOCK" in e["not_tested_reason"]


def test_pip_audit_defaults_severity_and_reports_skipped_deps():
    entries = run("pip-audit", DATA / "pip-audit.json")
    (f,) = findings(entries)
    assert f["severity"] == "medium" and "defaulted to medium" in f["impact"]
    assert f["tool"]["rule_id"] == "PYSEC-2019-217, CVE-2019-10906, GHSA-462w-v97r-4m45"
    assert f["fix"] == "Upgrade jinja2 to 2.10.1"
    (gap,) = checks(entries)
    assert gap["evidence_class"] == "NOT-TESTED" and "internal-lib" in gap["not_tested_reason"]


def test_trivy_vulns_misconfigs_and_secrets():
    f = findings(run("trivy", DATA / "trivy.json"))
    by_cat = {x["category"]: x for x in f}
    assert set(by_cat) == {"sca", "container", "secrets"}
    vuln = by_cat["sca"]
    assert vuln["severity"] == "high" and vuln["location"]["component"] == "lodash@4.17.15"
    assert vuln["tool"]["rule_id"] == "CVE-2021-23337, GHSA-35jh-r3h4-6jhm"
    assert vuln["tool"]["scope"] == "filesystem ."
    mis = by_cat["container"]
    assert mis["tool"]["rule_id"] == "DS002" and mis["location"] == {"file": "Dockerfile", "line": 1, "end_line": 12}
    assert by_cat["secrets"]["severity"] == "critical" and by_cat["secrets"]["location"]["line"] == 3


def test_trivy_passed_misconfigs_are_not_findings(tmp_path):
    d = json.loads((DATA / "trivy.json").read_text())
    d["Results"] = [{"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
                     "Misconfigurations": [{"ID": "DS002", "Title": "x user", "Severity": "HIGH", "Status": "PASS"}]}]
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(d))
    (e,) = run("trivy", p)
    assert e["evidence_class"] == "VERIFIED-ABSENT"


def test_checkov():
    (f,) = findings(run("checkov", DATA / "checkov.json"))
    assert f["category"] == "iac" and f["severity"] == "medium"  # OSS checkov gives no severity
    assert f["location"] == {"file": "infra/s3.tf", "line": 20, "end_line": 22, "component": "aws_s3_bucket.public"}
    assert f["tool"]["rule_id"] == "CKV_AWS_20" and f["tool"]["version"] == "3.2.382"
    assert "defaulted to medium" in f["impact"]


def test_checkov_zero_resources_is_a_gap_not_absence(tmp_path):
    p = tmp_path / "checkov.json"
    p.write_text(json.dumps({"check_type": "terraform", "results": {"passed_checks": [], "failed_checks": []},
                             "summary": {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0}}))
    (e,) = run("checkov", p)
    assert e["evidence_class"] == "NOT-TESTED" and "0 resources" in e["not_tested_reason"]


def test_hadolint():
    f = findings(run("hadolint", DATA / "hadolint.json"))
    assert [(x["tool"]["rule_id"], x["severity"]) for x in f] == [
        ("DL3006", "low"), ("DL3002", "low"), ("DL3059", "info"), ("DL4006", "medium")]
    assert all(x["category"] == "container" and x["location"]["file"] == "Dockerfile" for x in f)


def test_zap():
    csp, cookie = findings(run("zap", DATA / "zap.json"))
    assert (csp["category"], csp["severity"], csp["cwe"]) == ("headers", "medium", ["CWE-693"])
    assert csp["location"]["endpoint"] == "GET /"
    assert "2 instance(s)" in csp["impact"] and "<p>" not in csp["impact"]
    assert csp["tool"]["version"] == "2.15.0" and csp["tool"]["scope"] == "http://localhost:3000"
    assert (cookie["category"], cookie["severity"]) == ("session", "low")
    assert cookie["location"] == {"endpoint": "POST /login", "component": "param: sid"}
    assert "Set-Cookie" not in json.dumps(cookie)  # instance evidence is never copied


def test_nuclei():
    env, hdr = findings(run("nuclei", DATA / "nuclei.jsonl"))
    assert (env["category"], env["severity"], env["cwe"]) == ("data-exposure", "medium", ["CWE-200"])
    assert env["location"] == {"endpoint": "/.env", "component": "localhost:3000"}
    assert env["tool"]["rule_id"] == "dotenv-file"
    assert (hdr["category"], hdr["severity"]) == ("headers", "info")  # via tag, no CWE
    assert "redacted-by-test" not in json.dumps([env, hdr])  # response bodies are never copied


def test_sarif_semgrep_and_codeql():
    (s,) = findings(run("sarif", DATA / "semgrep.sarif"))
    assert (s["category"], s["severity"], s["cwe"]) == ("injection", "medium", ["CWE-89"])
    assert s["tool"] == {"name": "Semgrep OSS", "version": "1.101.0", "rule_id":
                         "python.lang.security.audit.formatted-sql-query.formatted-sql-query"}
    assert s["location"] == {"file": "app/db.py", "line": 27, "end_line": 27}
    assert s["title"] == "Detected possible formatted SQL query."

    sqli, path = findings(run("sarif", DATA / "codeql.sarif"))
    assert (sqli["category"], sqli["severity"], sqli["cwe"]) == ("injection", "high", ["CWE-89"])  # security-severity 8.8
    assert sqli["tool"]["name"] == "CodeQL" and sqli["title"] == "SQL query built from user-controlled sources"
    assert path["cwe"] == ["CWE-22", "CWE-23"] and path["category"] == "sast"  # CWE-22 deliberately unmapped
    assert path["severity"] == "high"  # security-severity 7.5


def test_sarif_level_mapping_and_missing_results(tmp_path):
    def sarif(level, **run_extra):
        run_ = {"tool": {"driver": {"name": "gosec", "rules": []}}, **run_extra}
        return {"version": "2.1.0", "runs": [run_]}

    p = tmp_path / "gosec.sarif"
    for level, want in [("error", "high"), ("warning", "medium"), ("note", "low"), ("none", "info")]:
        p.write_text(json.dumps(sarif(level, results=[{"ruleId": "G101", "level": level, "message": {"text": "Potential hardcoded credentials"}}])))
        (f,) = findings(run("sarif", p))
        assert f["severity"] == want
    p.write_text(json.dumps(sarif("x")))  # run without a results array: analysis may not have happened
    (e,) = run("sarif", p)
    assert e["evidence_class"] == "NOT-TESTED"
    p.write_text(json.dumps(sarif("x", results=[], invocations=[{"executionSuccessful": False}])))
    (e,) = run("sarif", p)
    assert e["evidence_class"] == "NOT-TESTED" and "executionSuccessful=false" in e["not_tested_reason"]


# --------------------------------------------------------------------------- redaction

def all_sample_output() -> str:
    parts = []
    for tool, fname in SAMPLES.items():
        parts.append(json.dumps(run(tool, DATA / fname)))
    parts.append(json.dumps(run("sarif", DATA / "codeql.sarif")))
    return "\n".join(parts)


@pytest.mark.parametrize("secret", RAW_SECRETS)
def test_raw_secret_never_appears_in_output(secret):
    out = all_sample_output()
    assert secret not in out
    # Guard the test itself: the secret really is present in at least one input file.
    assert any(secret in (DATA / f).read_text() for f in SAMPLES.values())


def test_redact_secret_keeps_at_most_a_quarter():
    assert nf.redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA…[REDACTED]"
    assert nf.redact_secret("hunter2") == "h…[REDACTED]"
    assert nf.redact_secret("abc") == "…[REDACTED]"


def test_free_text_goes_through_redact_text(tmp_path):
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    p = tmp_path / "hadolint.json"
    p.write_text(json.dumps([{"code": "DL3002", "file": "Dockerfile", "level": "warning", "line": 2,
                              "message": f"ENV AWS_KEY={key} leaks"}]))
    out = json.dumps(run("hadolint", p), ensure_ascii=False)
    assert key not in out and "AKIA…[REDACTED]" in out


def test_quoted_literals_scrubbed_in_secret_findings(tmp_path):
    p = tmp_path / "semgrep.json"
    p.write_text(json.dumps({"version": "1", "errors": [], "results": [{
        "check_id": "generic.secrets.password", "path": "a.py", "start": {"line": 1}, "end": {"line": 1},
        "extra": {"message": "Hardcoded password 'correct-horse-battery' found", "severity": "ERROR",
                  "metadata": {"cwe": ["CWE-798: Use of Hard-coded Credentials"]}}}]}))
    (f,) = findings(run("semgrep", p))
    assert f["category"] == "secrets"
    assert "correct-horse-battery" not in json.dumps(f)


# --------------------------------------------------------------------------- failure modes

def test_missing_file_is_not_tested(tmp_path):
    (e,) = run("gitleaks", tmp_path / "nope.json")
    assert e["kind"] == "check" and e["evidence_class"] == "NOT-TESTED"
    assert e["not_tested_reason"] == "tool produced no output file"
    assert e["evidence"] == [] and e["category"] == "secrets"
    assert rglib.validate(e, "finding") == []


@pytest.mark.parametrize("content,needle", [
    ("", "empty file"),
    ("   \n", "empty file"),
    ("{not json", "invalid JSON"),
    ('{"results": "oops"}', "'results' is not an array"),
])
def test_unparseable_input_is_not_tested_never_zero_findings(tmp_path, content, needle):
    p = tmp_path / "semgrep.json"
    p.write_text(content)
    entries = run("semgrep", p)
    assert len(entries) == 1
    e = entries[0]
    assert e["kind"] == "check" and e["evidence_class"] == "NOT-TESTED"
    assert e["not_tested_reason"].startswith("tool output unparseable: semgrep: ")
    assert needle in e["not_tested_reason"]
    assert e["evidence"][0]["path"] == str(p)
    assert rglib.validate(e, "finding") == []


@pytest.mark.parametrize("tool,payload", [
    ("gitleaks", {"not": "an array"}),
    ("gitleaks", [{"no": "ruleid"}]),
    ("hadolint", {"code": "DL1"}),
    ("bandit", [1, 2]),
    ("osv-scanner", {"foo": 1}),
    ("trivy", {"foo": 1}),
    ("zap", {"foo": 1}),
    ("sarif", {"runs": {"not": "list"}}),
    ("checkov", {"foo": 1}),
    ("semgrep", {"results": [None]}),   # AttributeError inside the parser must not become zero findings
])
def test_wrong_shape_is_not_tested(tmp_path, tool, payload):
    p = tmp_path / "out.json"
    p.write_text(json.dumps(payload))
    entries = run(tool, p)
    assert len(entries) == 1 and entries[0]["evidence_class"] == "NOT-TESTED"
    assert entries[0]["not_tested_reason"].startswith(f"tool output unparseable: {tool}: ")


@pytest.mark.parametrize("tool,line", [("trufflehog", "{truncated"), ("nuclei", "[1,2]"), ("nuclei", '{"a":1}')])
def test_bad_jsonl_is_not_tested(tmp_path, tool, line):
    p = tmp_path / "out.jsonl"
    p.write_text(line + "\n")
    (e,) = run(tool, p)
    assert e["evidence_class"] == "NOT-TESTED"


EMPTY_VALID = {
    "gitleaks": "[]",
    "trufflehog": '{"level":"info-0","logger":"trufflehog","msg":"finished scanning","trufflehog_version":"3.88.0"}\n',
    "semgrep": '{"version":"1.101.0","results":[],"errors":[],"paths":{"scanned":["a.py"],"skipped":[]}}',
    "bandit": '{"errors":[],"metrics":{"_totals":{"loc":10}},"results":[]}',
    "osv-scanner": '{"results":[]}',
    "npm-audit": '{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"total":0}}}',
    "pip-audit": '{"dependencies":[{"name":"flask","version":"3.0.3","vulns":[]}],"fixes":[]}',
    "trivy": '{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem"}',
    "checkov": '{"check_type":"terraform","results":{"passed_checks":[{"check_id":"X"}],"failed_checks":[]},"summary":{"passed":1,"failed":0,"skipped":0,"resource_count":1}}',
    "hadolint": "[]",
    "zap": '{"@programName":"ZAP","@version":"2.15.0","site":[{"@name":"http://localhost:3000","alerts":[]}]}',
    "sarif": '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[]}]}',
}


@pytest.mark.parametrize("tool", sorted(EMPTY_VALID))
def test_valid_empty_output_is_verified_absent_check(tmp_path, tool):
    p = tmp_path / "out.json"
    p.write_text(EMPTY_VALID[tool])
    (e,) = run(tool, p, scope_note="full git history")
    assert e["kind"] == "check" and e["evidence_class"] == "VERIFIED-ABSENT"
    assert e["title"] == f"{tool} reported no findings (scope: full git history)"
    assert e["evidence"][0]["path"] == str(p) and e["evidence"][0]["type"] == "tool-output"
    assert "severity" not in e and "not_tested_reason" not in e
    assert e["tool"]["scope"] == "full git history"
    assert rglib.validate(e, "finding") == []


def test_verified_absent_title_without_scope_note(tmp_path):
    p = tmp_path / "gitleaks.json"
    p.write_text("[]")
    (e,) = run("gitleaks", p)
    assert e["title"] == "gitleaks reported no findings (scope: unknown scope)"


def test_empty_jsonl_needs_explicit_opt_in(tmp_path):
    p = tmp_path / "nuclei.jsonl"
    p.write_text("")
    (e,) = run("nuclei", p)
    assert e["evidence_class"] == "NOT-TESTED"
    (e,) = run("nuclei", p, empty_ok=True)
    assert e["evidence_class"] == "VERIFIED-ABSENT"
    # --empty-ok never rescues an empty file for a plain-JSON tool
    q = tmp_path / "gitleaks.json"
    q.write_text("")
    (e,) = run("gitleaks", q, empty_ok=True)
    assert e["evidence_class"] == "NOT-TESTED"


# --------------------------------------------------------------------------- evidence paths, scope

def test_evidence_path_relative_to_release_gate_dir(tmp_path):
    ev = tmp_path / "proj" / ".release-gate" / "evidence"
    ev.mkdir(parents=True)
    shutil.copy(DATA / "gitleaks.json", ev / "gitleaks.json")
    entries = run("gitleaks", ev / "gitleaks.json")
    assert {e["evidence"][0]["path"] for e in entries} == {"evidence/gitleaks.json"}


def test_evidence_path_as_given_outside_release_gate():
    p = DATA / "gitleaks.json"
    assert run("gitleaks", p)[0]["evidence"][0]["path"] == str(p)


def test_scope_note_and_tool_version_flow_into_findings():
    (f, *_) = findings(run("gitleaks", DATA / "gitleaks.json", scope_note="full git history", tool_version="8.21.2"))
    assert f["tool"]["scope"] == "full git history" and f["tool"]["version"] == "8.21.2"


# --------------------------------------------------------------------------- mappings

def test_cwe_parsing():
    assert nf.parse_cwes("CWE-89: Improper Neutralization") == ["CWE-89"]
    assert nf.parse_cwes(["external/cwe/cwe-089", "security", "cwe-79"]) == ["CWE-89", "CWE-79"]
    assert nf.parse_cwes({"id": 78}, "79", 0, "-1", True, None) == ["CWE-78", "CWE-79"]


def test_categorize_only_overrides_generic_categories():
    assert nf.categorize(["CWE-89"], "sast") == "injection"
    assert nf.categorize(["CWE-79"], "other") == "xss"
    assert nf.categorize(["CWE-89"], "sca") == "sca"
    assert nf.categorize(["CWE-22"], "sast") == "sast"
    assert nf.CWE_CATEGORY["CWE-918"] == "ssrf" and nf.CWE_CATEGORY["CWE-798"] == "secrets"


def test_severity_maps_documented_values():
    assert nf.map_sev("semgrep", "ERROR") == "high" and nf.map_sev("semgrep", "INFO") == "low"
    assert nf.map_sev("advisory", "MODERATE") == "medium" and nf.map_sev("advisory", "bogus") == "medium"
    assert nf.map_sev("zap", "3") == "high" and nf.map_sev("hadolint", "style") == "info"
    assert [nf.cvss_bucket(s) for s in (9.8, 7.0, 4.0, 0.1, 0)] == ["critical", "high", "medium", "low", "info"]
    for table in nf.SEVERITY_MAPS.values():
        assert set(table.values()) <= set(rglib.SEVERITIES)


# --------------------------------------------------------------------------- CLI

def cli_out(tmp_path) -> Path:
    return tmp_path / "findings.json"


def test_cli_tool_input_out_and_append_keeps_ids_unique(tmp_path):
    out = cli_out(tmp_path)
    assert nf.main(["--tool", "semgrep", "--input", str(DATA / "semgrep.json"), "--out", str(out)]) == 0
    first = json.loads(out.read_text())
    assert len(first) == 2
    assert nf.main(["--tool", "semgrep", "--input", str(DATA / "semgrep.json"),
                    "--tool", "semgrep", "--out", str(out), "--scope-note", "src"]) == 0
    second = json.loads(out.read_text())
    assert len(second) == 4 and second[:2] == first
    ids = [e["id"] for e in second]
    assert len(set(ids)) == 4
    assert "RG-INJECTION-002" in ids and "RG-XSS-002" in ids
    for e in second:
        assert rglib.validate(e, "finding") == []


def test_cli_multiple_inputs_and_tool_alias(tmp_path):
    out = cli_out(tmp_path)
    assert nf.main(["--tool", "codeql", "--input", str(DATA / "codeql.sarif"),
                    "--input", str(DATA / "semgrep.sarif"), "--out", str(out)]) == 0
    entries = json.loads(out.read_text())
    assert [e["tool"]["name"] for e in entries] == ["CodeQL", "CodeQL", "Semgrep OSS"]


def test_cli_missing_input_file_exits_zero_with_not_tested_check(tmp_path, capsys):
    out = cli_out(tmp_path)
    assert nf.main(["--tool", "gitleaks", "--input", str(tmp_path / "missing.json"), "--out", str(out)]) == 0
    (e,) = json.loads(out.read_text())
    assert e["evidence_class"] == "NOT-TESTED"
    assert "NOT-TESTED" in capsys.readouterr().err


def test_cli_usage_errors(tmp_path):
    out = str(cli_out(tmp_path))
    assert nf.main(["--tool", "gitleaks", "--out", out]) == 2                    # no --input
    assert nf.main(["--out", out]) == 2                                          # neither --tool nor --auto
    assert nf.main(["--auto", str(tmp_path / "nope"), "--out", out]) == 2        # missing dir
    (tmp_path / "findings.json").write_text('{"not": "a list"}')
    assert nf.main(["--tool", "gitleaks", "--input", str(DATA / "gitleaks.json"), "--out", out]) == 2
    with pytest.raises(SystemExit):
        nf.main(["--tool", "notatool", "--input", "x", "--out", out])


def test_cli_schema_failure_exits_nonzero_and_writes_nothing(tmp_path, monkeypatch):
    out = cli_out(tmp_path)
    monkeypatch.setattr(rglib, "validate", lambda obj, name: ["title: broken"])
    assert nf.main(["--tool", "gitleaks", "--input", str(DATA / "gitleaks.json"), "--out", str(out)]) == 1
    assert not out.exists()


def test_cli_auto_detects_by_filename_and_content(tmp_path):
    evidence = tmp_path / ".release-gate" / "evidence"
    evidence.mkdir(parents=True)
    for name in ("gitleaks.json", "trufflehog.jsonl", "semgrep.sarif", "zap.json", "nuclei.jsonl"):
        shutil.copy(DATA / name, evidence / name)
    # content-only detection (neutral file names)
    shutil.copy(DATA / "bandit.json", evidence / "scan1.json")
    shutil.copy(DATA / "osv-scanner.json", evidence / "scan2.json")
    shutil.copy(DATA / "npm-audit.json", evidence / "scan3.json")
    shutil.copy(DATA / "pip-audit.json", evidence / "scan4.json")
    shutil.copy(DATA / "trivy.json", evidence / "scan5.json")
    shutil.copy(DATA / "checkov.json", evidence / "scan6.json")
    shutil.copy(DATA / "hadolint.json", evidence / "scan7.json")
    shutil.copy(DATA / "semgrep.json", evidence / "scan8.json")
    shutil.copy(DATA / "nuclei.jsonl", evidence / "scan9.jsonl")
    (evidence / "notes.txt").write_text("not a tool output")
    (evidence / "unrelated.json").write_text('{"hello": "world"}')
    out = tmp_path / ".release-gate" / "findings.json"
    assert nf.main(["--auto", str(evidence), "--out", str(out)]) == 0
    entries = json.loads(out.read_text())
    tools = {e["tool"]["name"] for e in entries}
    assert tools == {"gitleaks", "trufflehog", "Semgrep OSS", "zap", "nuclei", "bandit", "osv-scanner", "npm-audit",
                     "pip-audit", "trivy", "checkov", "hadolint", "semgrep"}
    assert all(e["evidence"][0]["path"].startswith("evidence/") for e in entries)
    assert len({e["id"] for e in entries}) == len(entries)
    assert not any(e["evidence"][0]["path"].endswith("unrelated.json") for e in entries)


def test_cli_auto_with_unparseable_named_file_records_not_tested(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "gitleaks-report.json").write_text("{broken")
    out = tmp_path / "f.json"
    assert nf.main(["--auto", str(ev), "--out", str(out)]) == 0
    (e,) = json.loads(out.read_text())
    assert e["evidence_class"] == "NOT-TESTED" and e["category"] == "secrets"


def test_detect_tool_by_name_and_content(tmp_path):
    assert nf.detect_tool(Path("x/semgrep-sarif.sarif")) == "sarif"
    assert nf.detect_tool(Path("npm_audit.json")) == "npm-audit"
    assert nf.detect_tool(Path("pip-audit-report.json")) == "pip-audit"
    p = tmp_path / "mystery.json"
    p.write_text("[]")
    assert nf.detect_tool(p) is None  # an empty array is ambiguous: refuse to guess


def test_cli_end_to_end_subprocess(tmp_path):
    import subprocess
    import sys
    script = Path(nf.__file__)
    out = tmp_path / "f.json"
    r = subprocess.run([sys.executable, str(script), "--tool", "gitleaks", "--input", str(DATA / "gitleaks.json"),
                        "--out", str(out), "--scope-note", "full git history"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert len(json.loads(out.read_text())) == 2


# --------------------------------------------------------------------------- real-run regressions (found against live scanners)

def test_relocate_makes_project_paths_relative(tmp_path):
    import normalize_findings as nf
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    assert nf.relocate(str(root / "src" / "a.js"), root) == ("src/a.js", False)
    assert nf.relocate("./src/a.js", root) == ("src/a.js", False)
    assert nf.relocate("/elsewhere/x.js", root) == ("/elsewhere/x.js", False)


def test_findings_inside_state_dir_are_dropped(tmp_path):
    import json as _json
    import normalize_findings as nf
    ev = tmp_path / "proj" / ".release-gate" / "evidence" / "gitleaks-1"
    ev.mkdir(parents=True)
    report = [
        {"RuleID": "stripe-access-token", "Description": "Stripe", "File": ".release-gate/evidence/old/gitleaks.json",
         "StartLine": 3, "Secret": "sk_test_" + "x" * 24, "Match": "m"},
        {"RuleID": "stripe-access-token", "Description": "Stripe", "File": str(tmp_path / "proj" / "src" / "config.js"),
         "StartLine": 9, "Secret": "sk_test_" + "y" * 24, "Match": "m"},
    ]
    (ev / "gitleaks.json").write_text(_json.dumps(report))
    out = tmp_path / "out.json"
    assert nf.main(["--auto", str(ev.parent), "--out", str(out)]) == 0
    entries = _json.loads(out.read_text())
    files = [e["location"]["file"] for e in entries if e["kind"] == "finding"]
    assert files == ["src/config.js"]


def test_auto_ignores_run_tool_result_json(tmp_path, capsys):
    import json as _json
    import normalize_findings as nf
    ev = tmp_path / "evidence" / "gitleaks-1"
    ev.mkdir(parents=True)
    (ev / "result.json").write_text(_json.dumps({"tool": "gitleaks", "status": "completed"}))
    (ev / "gitleaks.json").write_text("[]")
    assert nf.main(["--auto", str(tmp_path / "evidence"), "--out", str(tmp_path / "o.json")]) == 0
    assert "result.json" not in capsys.readouterr().err


# ---------------------------------------------------------------- check_id stamping (issue #1)

def test_check_id_stamped_by_category():
    R = nf.Raw
    assert nf._check_id_for(R(title="x", severity="high", category="sast"), "semgrep") == "SEC-SAST"
    assert nf._check_id_for(R(title="x", severity="high", category="sca"), "osv-scanner") == "SEC-SCA"
    assert nf._check_id_for(R(title="x", severity="high", category="secrets"), "gitleaks") == "SEC-SECRETS-HISTORY"
    assert nf._check_id_for(R(title="x", severity="high", category="secrets"), "trufflehog") == "SEC-SECRETS-VERIFIED"
    assert nf._check_id_for(R(title="x", severity="high", category="container"), "hadolint") == "SEC-IAC"
    assert nf._check_id_for(R(title="x", severity="low", category="other"), "zap") is None


def test_finding_entry_includes_check_id():
    raw = nf.Raw(title="SQL injection", severity="high", category="sca")
    entry = nf.finding_entry(raw, "osv-scanner", nf.Parsed(), nf.Ctx(), [{"type": "tool-output", "path": "x"}],
                             "2026-10-18T00:00:00Z")
    assert entry["check_id"] == "SEC-SCA"
