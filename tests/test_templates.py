"""Tests for the shipped templates: CI workflow, k6 scripts, HTML report template."""
from __future__ import annotations

import html
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

import report_lint

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "skills" / "release-gate" / "templates"
CI_FILE = TEMPLATES / "ci" / "github-actions-release-gate.yml"
K6_DIR = TEMPLATES / "k6"
K6_FILES = [K6_DIR / f"{n}.js" for n in ("load", "stress", "spike", "soak")]
REPORT_TMPL = TEMPLATES / "report" / "report.html.tmpl"

SHA_RE = re.compile(r"@[0-9a-f]{40}(?:\s|$)")
EVIDENCE_CLASSES = ["EXPLOITED", "TOOL-CONFIRMED", "SUSPECTED", "VERIFIED-ABSENT", "NOT-TESTED"]


def _load_ci() -> dict:
    return yaml.safe_load(CI_FILE.read_text(encoding="utf-8"))


def _uses_lines() -> list[tuple[int, str]]:
    out = []
    for n, line in enumerate(CI_FILE.read_text(encoding="utf-8").splitlines(), 1):
        m = re.match(r"^\s*(?:-\s*)?uses:\s*(.+)$", line)
        if m:
            out.append((n, line))
    return out


# --------------------------------------------------------------------------- CI workflow

def test_ci_yaml_parses():
    data = _load_ci()
    assert isinstance(data, dict)
    assert data["name"] == "release-gate"
    assert data["jobs"]


def test_ci_triggers_on_pull_request_not_pull_request_target():
    data = _load_ci()
    triggers = data.get("on", data.get(True))  # PyYAML reads the bare key `on` as True
    assert "pull_request" in triggers
    assert "pull_request_target" not in triggers


def test_ci_every_uses_is_pinned_to_a_full_sha_or_marked_pin_me():
    structural = []
    for job in _load_ci()["jobs"].values():
        structural += [s["uses"] for s in job.get("steps", []) if "uses" in s]
    lines = _uses_lines()
    assert structural, "workflow should use at least actions/checkout"
    assert len(lines) == len(structural)
    for n, line in lines:
        pinned = bool(SHA_RE.search(line))
        marked = "PIN-ME" in line
        assert pinned or marked, f"line {n} is not pinned to a 40-hex SHA and has no PIN-ME marker: {line.strip()}"
        if pinned:
            assert re.search(r"#\s*v\d", line), f"line {n}: pinned SHA must say which tag it is in a comment"


def test_ci_checkout_is_the_expected_pinned_sha():
    text = CI_FILE.read_text(encoding="utf-8")
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2" in text


def test_ci_top_level_permissions_are_read_only():
    perms = _load_ci().get("permissions")
    assert isinstance(perms, dict), "top-level permissions must be set explicitly"
    assert perms
    assert all(v in ("read", "none") for v in perms.values()), perms


def test_ci_write_permission_is_limited_to_the_sarif_upload_job():
    data = _load_ci()
    writers = {}
    for name, job in data["jobs"].items():
        perms = job.get("permissions") or {}
        write = {k for k, v in perms.items() if v == "write"}
        if write:
            writers[name] = write
    assert writers == {"upload-sarif": {"security-events"}}, writers
    uploads = [s["uses"] for s in data["jobs"]["upload-sarif"]["steps"] if "uses" in s]
    assert any(u.startswith("github/codeql-action/upload-sarif@") for u in uploads)
    # the scanning job never gets more than contents: read
    assert data["jobs"]["gate"]["permissions"] == {"contents": "read"}


def test_ci_uses_plugin_scripts_and_pinned_flags():
    text = CI_FILE.read_text(encoding="utf-8")
    for needle in ("install_tools.py", "run_tool.py", "report_build.py", "--mode quick",
                   "gitleaks", "osv-scanner", "semgrep", "--metrics off", "--jobs 1"):
        assert needle in text, needle
    assert "RELEASE_GATE_REF" in text
    assert "persist-credentials: false" in text
    assert "fetch-depth: 0" in text


def test_ci_semgrep_never_uses_registry_rules_and_nothing_is_piped_to_a_shell():
    text = CI_FILE.read_text(encoding="utf-8")
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r"--config\s+(auto|p/|r/)", code)
    assert "config auto" not in code
    assert not re.search(r"\|\s*(ba)?sh\b", code)
    assert "curl " not in code and "wget " not in code
    assert "secrets." not in code, "the gate needs no secrets"


def test_ci_fails_the_job_on_block():
    text = CI_FILE.read_text(encoding="utf-8")
    assert '== "BLOCK"' in text
    assert "sys.exit(1)" in text


# --------------------------------------------------------------------------- k6

@pytest.mark.parametrize("path", K6_FILES, ids=lambda p: p.name)
def test_k6_guard_and_summary_present(path: Path):
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    for needle in ("BASE_URL", "PATHS", "RG_P95_MS", "RG_ERROR_RATE", "RG_SUMMARY", "k6-summary.json",
                   "export function handleSummary", "RG_ALLOW_NONLOCAL", "RG_STAGING_CONFIRM",
                   "localhost", "127", "[::1]", "maxRedirects: 0"):
        assert needle in text, f"{path.name} lacks {needle}"
    # the guard must throw at init: before options are built and before the default function
    guard = text.index("throw new Error")
    assert guard < text.index("export const options")
    assert guard < text.index("export default function")
    assert re.search(r"if \(!IS_LOOPBACK\)", text)


@pytest.mark.parametrize("path", K6_FILES, ids=lambda p: p.name)
def test_k6_has_no_network_fetched_imports_and_no_writes(path: Path):
    text = path.read_text(encoding="utf-8")
    imports = re.findall(r"^import .* from '([^']+)'", text, re.M)
    assert imports and all(i.startswith("k6") for i in imports), imports
    assert not re.search(r"http\.(post|put|patch|del|delete)\(", text)
    assert "https://jslib" not in text


def test_k6_readme_covers_the_required_points():
    text = (K6_DIR / "README.md").read_text(encoding="utf-8")
    for needle in ("production", "PERF-LOAD-PROFILES", "PERF-FAILURE-MODES", "NOT-TESTED: tool unavailable",
                   "tools.lock.yaml", "principle 3"):
        assert needle in text, needle


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("path", K6_FILES, ids=lambda p: p.name)
def test_k6_syntax_parses_with_node(path: Path, tmp_path: Path):
    # k6 imports cannot be resolved by node, but --check only parses; ES module syntax needs .mjs
    copy = tmp_path / (path.stem + ".mjs")
    copy.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    r = subprocess.run(["node", "--check", str(copy)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


GUARD_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8')
  .replace(/^import .*$/gm, '')
  .replace(/export default function/, 'function defaultFn')
  .replace(/export function/g, 'function')
  .replace(/export const/g, 'const');
const cases = JSON.parse(process.argv[3]);
const out = cases.map((env) => {
  try { new Function('__ENV', 'http', 'check', 'sleep', src)(env, {}, () => {}, () => {}); return 'ok'; }
  catch (e) { return 'throw'; }
});
console.log(JSON.stringify(out));
"""

GUARD_CASES = [
    ({}, "throw"),
    ({"BASE_URL": "http://127.0.0.1:8000"}, "ok"),
    ({"BASE_URL": "http://localhost"}, "ok"),
    ({"BASE_URL": "http://[::1]:3000/x"}, "ok"),
    ({"BASE_URL": "https://example.com"}, "throw"),
    ({"BASE_URL": "http://127.0.0.1@elsewhere.example/"}, "throw"),
    ({"BASE_URL": "http://localhost.example.com"}, "throw"),
    ({"BASE_URL": "https://stg.example.com", "RG_ALLOW_NONLOCAL": "1"}, "throw"),
    ({"BASE_URL": "https://stg.example.com", "RG_STAGING_CONFIRM": "stg.example.com"}, "throw"),
    ({"BASE_URL": "https://stg.example.com", "RG_ALLOW_NONLOCAL": "1", "RG_STAGING_CONFIRM": "other.example.com"}, "throw"),
    ({"BASE_URL": "https://stg.example.com", "RG_ALLOW_NONLOCAL": "1", "RG_STAGING_CONFIRM": "stg.example.com"}, "ok"),
    ({"BASE_URL": "http://127.0.0.1", "PATHS": "http://elsewhere.example/x"}, "throw"),
    ({"BASE_URL": "http://127.0.0.1", "PATHS": "/a,/b"}, "ok"),
]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("path", K6_FILES, ids=lambda p: p.name)
def test_k6_guard_behaviour_under_node(path: Path, tmp_path: Path):
    import json
    harness = tmp_path / "harness.js"
    harness.write_text(GUARD_HARNESS, encoding="utf-8")
    envs = [c[0] for c in GUARD_CASES]
    r = subprocess.run(["node", str(harness), str(path), json.dumps(envs)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == [c[1] for c in GUARD_CASES]


# --------------------------------------------------------------------------- report template

PLACEHOLDERS = ["title", "product", "date", "generated_at", "mode", "verdict", "verdict_class", "disclaimer",
                "count_critical", "count_high", "count_medium", "count_low", "count_info"]
ROW_LISTS = ["blocking", "reasons", "coverage", "findings", "not_tested", "limitations"]
SLOT_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")
BLOCK_RE = re.compile(r"\{\{([#^])rows ([A-Za-z0-9_]+)\}\}(.*?)\{\{/rows\}\}", re.S)


def render(tmpl: str, data: dict) -> str:
    """Minimal reference renderer for the template syntax (escapes every value)."""
    tmpl = re.sub(r"<!--.*?-->", "", tmpl, flags=re.S)

    def block(m: re.Match) -> str:
        kind, name, body = m.groups()
        rows = data.get(name, [])
        if kind == "^":
            return body if not rows else ""
        return "".join(SLOT_RE.sub(lambda s: html.escape(str(row.get(s.group(1), "")), quote=True), body) for row in rows)

    out = BLOCK_RE.sub(block, tmpl)
    return SLOT_RE.sub(lambda s: html.escape(str(data.get(s.group(1), "")), quote=True), out)


def test_report_template_has_csp_meta_and_no_script():
    text = REPORT_TMPL.read_text(encoding="utf-8")
    assert ('<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">') in text
    assert not re.search(r"<script\b", text, re.I)
    assert not re.search(r"<(link|img|iframe|object|embed|video|audio|source|base)\b", text, re.I)


def test_report_template_has_no_external_asset_references():
    text = REPORT_TMPL.read_text(encoding="utf-8")
    assert not re.search(r"""(?:src|href|action|poster|data)\s*=\s*["']?\s*(?:https?:)?//""", text, re.I)
    assert not re.search(r"url\(\s*[\"']?\s*(?:https?:)?//", text, re.I)
    assert not re.search(r"@import", text, re.I)
    assert not re.search(r"https?://", text, re.I), "no absolute URLs at all in the template"
    assert "font-face" not in text


def test_report_template_has_placeholders_and_supports_light_dark_print():
    text = REPORT_TMPL.read_text(encoding="utf-8")
    for name in PLACEHOLDERS:
        assert "{{" + name + "}}" in text, name
    for name in ROW_LISTS:
        assert "{{#rows " + name + "}}" in text, name
    assert "prefers-color-scheme:dark" in text.replace(" ", "")
    assert "@media print" in text
    # every block opens and closes
    assert len(re.findall(r"\{\{[#^]rows ", text)) == len(re.findall(r"\{\{/rows\}\}", text))


def test_report_template_evidence_classes_have_distinct_colour_symbol_and_label():
    text = REPORT_TMPL.read_text(encoding="utf-8")
    colours, symbols = set(), set()
    for cls in EVIDENCE_CLASSES:
        rule = re.search(r"\.ec-" + re.escape(cls) + r"\{color:(var\(--[a-z-]+\))", text)
        assert rule, f"no colour rule for {cls}"
        colours.add(rule.group(1))
        sym = re.search(r"\.ec-" + re.escape(cls) + r'::before\{content:"([^"]+)"', text)
        assert sym, f"no symbol rule for {cls}"
        symbols.add(sym.group(1))
        assert f'<span class="badge ec-{cls}">{cls}</span>' in text, f"legend lacks a text-labelled badge for {cls}"
    assert len(colours) == len(EVIDENCE_CLASSES)
    assert len(symbols) == len(EVIDENCE_CLASSES)
    assert "{{evidence_label}}" in text


def test_report_template_renders_and_passes_report_lint(tmp_path: Path):
    data = {
        "title": "release-gate: demo 2026-01-01", "product": "demo", "date": "2026-01-01",
        "generated_at": "2026-01-01T00:00:00Z", "mode": "quick", "verdict": "BLOCK", "verdict_class": "BLOCK",
        "disclaimer": "Generated by release-gate. Not legal advice.",
        "count_critical": 0, "count_high": 1, "count_medium": 0, "count_low": 0, "count_info": 0,
        "blocking": [{"text": "RG-SECRETS-001: unwaived high"}],
        "reasons": [{"text": "see blocking list"}],
        "coverage": [{"id": "SEC-SAST", "title": "SAST", "phase": 2, "critical": "", "evidence_class": "SUSPECTED",
                      "evidence_label": "SUSPECTED", "result": "issue found (1)", "detail": "<b>x</b>", "artifacts": "evidence/a.json"}],
        "findings": [{"id": "RG-SAST-001", "severity": "high", "evidence_class": "SUSPECTED", "evidence_label": "SUSPECTED",
                      "title": "Hard-coded value <img src=x>", "location": "app.py:10", "status": "open", "impact": "i",
                      "repro": "r", "fix": "f", "tool": "semgrep 1.0 rule x", "artifacts": "evidence/a.json"}],
        "not_tested": [{"id": "SEC-SCA", "title": "SCA", "reason": "tool unavailable: osv-scanner"}],
        "limitations": [{"text": "A scanner that reports nothing has only shown that this scanner found nothing."}],
    }
    out = render(REPORT_TMPL.read_text(encoding="utf-8"), data)
    assert "{{" not in out and "}}" not in out
    assert "&lt;img src=x&gt;" in out and "<img" not in out  # untrusted values are escaped
    for cls in EVIDENCE_CLASSES:
        assert f"ec-{cls}" in out
    page = tmp_path / "report.html"
    page.write_text(out, encoding="utf-8")
    assert report_lint.lint_html(page) == []


def test_report_template_empty_lists_render_fallback_text():
    data = {k: "" for k in PLACEHOLDERS}
    out = render(REPORT_TMPL.read_text(encoding="utf-8"), data)
    assert "Nothing is blocking." in out
    assert "No findings were recorded." in out
    assert "Every applicable check in this mode has a recorded result." in out


# --------------------------------------------------------------------------- banned phrases

TEMPLATE_FILES = [CI_FILE, *K6_FILES, K6_DIR / "README.md", REPORT_TMPL, TEMPLATES / "report" / "README.md"]


@pytest.mark.parametrize("path", TEMPLATE_FILES, ids=lambda p: p.name)
def test_no_banned_phrases_in_templates(path: Path):
    assert path.is_file(), path
    hits = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        found = report_lint._banned_hits(line)
        if found:
            hits.append((n, found))
    assert not hits, hits


@pytest.mark.parametrize("path", TEMPLATE_FILES, ids=lambda p: p.name)
def test_templates_contain_no_local_paths_or_personal_info(path: Path):
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"/home/\w+|/Users/\w+|C:\\\\Users", text)
    assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), "no email addresses"
