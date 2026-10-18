"""Tests for render_report.py: placeholder syntax, escaping, enum guard, CLI round-trip."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import render_report as rr
import report_build as rb
import report_lint as rl
import rglib
from test_report import CATALOG, WEB_CONFIG, _project, check, finding


def _ctx(findings=(), coverage=None, blocking=(), reasons=("r1",), counts=None):
    return {
        "product": "demo", "date": "2026-10-18", "mode": "full", "generated_at": "2026-10-18T00:00:00Z",
        "verdict": {"verdict": "SHIP WITH ACCEPTED RISKS", "blocking": list(blocking), "reasons": list(reasons)},
        "counts": counts or {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
        "coverage": coverage if coverage is not None else [],
        "findings": list(findings),
    }


def _cov(i, cls="VERIFIED-ABSENT", applicable=True, **kw):
    row = {"id": f"CHK-{i}", "title": f"check {i}", "phase": 2, "critical": True, "applicable": applicable,
           "evidence_class": cls, "result": "no issue observed", "reason": "why", "artifacts": ["evidence/a.txt", "evidence/b.txt"]}
    row.update(kw)
    return row


def _finding(i=1, **kw):
    f = {"id": f"RG-T-{i:03d}", "kind": "finding", "title": f"finding {i}", "severity": "high", "evidence_class": "EXPLOITED",
         "status": "open", "impact": "bad", "repro": "curl x", "fix": "patch",
         "location": {"file": "app.py", "line": 7}, "tool": {"name": "semgrep", "version": "1.2", "rule_id": "r.x"},
         "evidence": [{"type": "tool-output", "path": "evidence/x.txt"}]}
    f.update(kw)
    return f


def test_empty_lists_render_empty_messages():
    page = rr.render(_ctx())
    assert "Nothing is blocking." in page
    assert "No coverage rows were produced." in page
    assert "No findings were recorded." in page
    assert "Every applicable check in this mode has a recorded result." in page
    assert '<article class="finding">' not in page
    assert "<li>r1</li>" in page


def test_non_empty_lists_render_rows():
    cov = [_cov(1), _cov(2, cls="NOT-TESTED", reason="tool unavailable: gitleaks"), _cov(3, cls="N/A", applicable=False)]
    page = rr.render(_ctx(findings=[_finding(1), _finding(2, title="second")], coverage=cov, blocking=["RG-T-001 blocks"]))
    assert "Nothing is blocking." not in page and "RG-T-001 blocks" in page
    assert "No coverage rows were produced." not in page and "No findings were recorded." not in page
    assert page.count('<article class="finding">') == 2
    assert "app.py:7" in page and "semgrep 1.2, rule r.x" in page
    assert "evidence/a.txt, evidence/b.txt" in page
    assert 'class="badge ec-N-A">N/A<' in page
    # only the applicable NOT-TESTED row appears in section 4
    nt = page.split('id="not-tested"')[1].split('id="limitations"')[0]
    assert "CHK-2" in nt and "tool unavailable: gitleaks" in nt and "CHK-1" not in nt and "CHK-3" not in nt
    assert "Every applicable check in this mode has a recorded result." not in nt
    assert 'class="verdict v-SHIP-WITH-ACCEPTED-RISKS"' in page
    assert "<strong>2</strong> medium" in page


def test_missing_optional_fields_use_em_dash():
    page = rr.render(_ctx(findings=[_finding(impact=None, repro="", fix=None, tool=None, location={}, evidence=[])]))
    art = page.split('<article class="finding">')[1].split("</article>")[0]
    assert art.count("—") >= 6


def test_endpoint_preferred_for_location():
    page = rr.render(_ctx(findings=[_finding(location={"endpoint": "GET /a", "file": "x.py", "line": 1})]))
    assert "GET /a" in page and "x.py:1" not in page


def test_untrusted_values_are_escaped():
    evil = '<script>alert(1)</script> "q" & {{title}}'
    page = rr.render(_ctx(findings=[_finding(title=evil, impact="<img src=x onerror=alert(1)>")],
                          blocking=["<b>x</b>"], coverage=[_cov(1, reason="<i>r</i>")]))
    assert "<script" not in page and "<img src=x" not in page and "<b>x</b>" not in page and "<i>r</i>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&quot;q&quot; &amp; &#123;&#123;title}}" in page
    assert "{{" not in page


@pytest.mark.parametrize("bad", ['x" onload="alert(1)', "EXPLOITED extra", "", "exploited", None])
def test_enum_guard_rejects_unknown_evidence_class(bad):
    with pytest.raises(ValueError):
        rr.render(_ctx(findings=[_finding(evidence_class=bad)]))
    with pytest.raises(ValueError):
        rr.render(_ctx(coverage=[_cov(1, cls=bad)]))


def test_enum_guard_rejects_unknown_verdict_class():
    ctx = _ctx()
    ctx["verdict"]["verdict"] = 'SHIP" onload="x'
    with pytest.raises(ValueError):
        rr.render(ctx)


def test_enum_guard_in_template_slot_directly():
    with pytest.raises(ValueError):
        rr.render_template("<i class=\"{{evidence_class}}\">", {"evidence_class": "bad"})
    assert rr.render_template("{{evidence_class}}", {"evidence_class": "N/A"}) == "N-A"


def test_every_enum_value_is_accepted():
    for cls in rglib.EVIDENCE_CLASSES:
        assert f"ec-{cls}" in rr.render(_ctx(findings=[_finding(evidence_class=cls)]))
    for v in ("BLOCK", "SHIP WITH ACCEPTED RISKS", "SHIP", "NOT-EVALUATED"):
        ctx = _ctx()
        ctx["verdict"]["verdict"] = v
        assert f"v-{v.replace(' ', '-')}" in rr.render(ctx)


def test_no_placeholders_left_and_comments_stripped():
    page = rr.render(_ctx(findings=[_finding()], coverage=[_cov(1)]))
    assert "{{" not in page
    assert "<!--" not in page and "-->" not in page
    assert "Rendering rules are in README.md" not in page


def test_unfilled_or_malformed_placeholders_fail_loudly():
    with pytest.raises(ValueError):
        rr.render_template("{{nope}}", {})
    with pytest.raises(ValueError):
        rr.render_template("{{#rows xs}}{{y}}{{/rows}}", {"xs": [{"z": 1}]})
    with pytest.raises(ValueError):
        rr.render_template("{{#rows xs}}", {"xs": []})
    with pytest.raises(ValueError):
        rr.render_template("{{/rows}}", {})
    with pytest.raises(ValueError):
        rr.render_template("{{a b c}}", {"a": 1})
    with pytest.raises(ValueError):
        rr.render_template("oops {{ unterminated", {})
    with pytest.raises(ValueError):
        rr.render_template("{{#rows xs}}x{{/rows}}", {"xs": "notalist"})


def test_comment_with_placeholders_is_stripped_not_rendered():
    assert rr.render_template("a<!-- {{missing}} {{#rows q}} -->b", {}) == "ab"


def test_nested_rows():
    tmpl = "{{#rows a}}[{{n}}:{{#rows kids}}{{k}},{{/rows}}{{^rows kids}}none{{/rows}}]{{/rows}}"
    slots = {"a": [{"n": "1", "kids": [{"k": "x"}, {"k": "y"}]}, {"n": "2", "kids": []}]}
    assert rr.render_template(tmpl, slots) == "[1:x,y,][2:none]"


def test_csp_present_and_no_external_loads():
    page = rr.render(_ctx(findings=[_finding(title="see https://evil.example/x")], coverage=[_cov(1)]))
    assert '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">' in page
    assert not re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""", page, re.I)
    assert not re.search(r"<script|<link|@import|url\(", page, re.I)
    assert "http://" not in page.split("<main>")[0]


def test_disclaimer_and_limitations_verbatim():
    page = rr.render(_ctx())
    from html import escape
    assert escape(rb.DISCLAIMER, quote=True) in page
    for lim in rb.LIMITATIONS:
        assert escape(lim, quote=True) in page


def test_secrets_never_reach_the_page():
    key = "AKIAIOSFODNN7EXAMPLE"
    page = rr.render(_ctx(findings=[_finding(title=f"key {key}", location={"file": f"{key}.py", "line": 1})],
                          coverage=[_cov(1, reason=f"found {key}")]))
    assert key not in page
    assert rl.lint_secrets("x", page) == []


def test_rendered_page_passes_lint(tmp_path):
    p = tmp_path / "r.html"
    p.write_text(rr.render(_ctx(findings=[_finding()], coverage=[_cov(1)])), encoding="utf-8")
    assert rl.lint_paths([p]) == []


def test_missing_ctx_key_raises_value_error():
    ctx = _ctx()
    del ctx["product"]
    with pytest.raises(ValueError):
        rr.render(ctx)


# --------------------------------------------------------------------------- CLI

def test_cli_round_trip(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rb, "load_catalog", lambda path=None: CATALOG)
    entries = [finding(1, sev="high", cls="EXPLOITED", check="SEC-AUTHZ-MATRIX", cat="authz",
                       title="<script>alert(1)</script> IDOR",
                       impact="Any user can read any other user's messages.",
                       location={"endpoint": "GET /api/messages/:id"}),
               check(2, "SEC-SECRETS-HISTORY")]
    proj = _project(tmp_path, entries)
    assert rr.main(["--project", str(proj), "--mode", "full", "--date", "2026-10-18"]) == 0
    out = proj / ".release-gate" / "reports" / "release-gate-2026-10-18.template.html"
    assert capsys.readouterr().out.strip() == str(out)
    page = out.read_text(encoding="utf-8")
    assert "RG-T-001" in page and "GET /api/messages/:id" in page and "v-BLOCK" in page
    assert "<script>alert" not in page and "&lt;script&gt;" in page
    assert "SEC-SECRETS-HISTORY" in page and "{{" not in page
    assert rl.lint_paths([out], proj / ".release-gate") == []


def test_cli_out_option(tmp_path, monkeypatch):
    monkeypatch.setattr(rb, "load_catalog", lambda path=None: CATALOG)
    proj = _project(tmp_path, [finding(1, sev="low")])
    dest = tmp_path / "sub" / "mine.html"
    assert rr.main(["--project", str(proj), "--date", "2026-10-18", "--out", str(dest)]) == 0
    assert dest.exists()


def test_cli_lint_failure_renames_and_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rb, "load_catalog", lambda path=None: CATALOG)
    proj = _project(tmp_path, [finding(1, sev="low", title="the code looks good")])
    assert rr.main(["--project", str(proj), "--date", "2026-10-18"]) == 2
    rdir = proj / ".release-gate" / "reports"
    assert not (rdir / "release-gate-2026-10-18.template.html").exists()
    assert (rdir / "release-gate-2026-10-18.template.lint-failed.html").exists()
    assert "banned phrase" in capsys.readouterr().err
