#!/usr/bin/env python3
"""Normalize raw scanner output into release-gate finding/check entries.

Honesty rules this script enforces:
  * a scanner result never proves anything: every normalized finding starts as
    evidence_class SUSPECTED with verification.verdict "unverified"; promoting
    it to TOOL-CONFIRMED is a later step that needs a human/agent to read the
    code path;
  * a missing, empty or unparseable tool output NEVER turns into "zero
    findings": it becomes one kind "check" entry, evidence_class NOT-TESTED;
  * a valid empty result becomes one kind "check" entry, VERIFIED-ABSENT, whose
    title states only that this scanner found nothing in that scope;
  * raw secret values are never written anywhere: gitleaks/trufflehog secret
    fields are shortened with rglib.redact_value and every free-text field goes
    through rglib.redact_text (plus quoted-literal scrubbing for secrets).

Usage:
  normalize_findings.py --tool gitleaks --input gl.json --out findings.json \\
      [--scope-note "full git history"] [--tool-version 8.21.2]
  normalize_findings.py --auto .release-gate/evidence --out findings.json

Entries are appended to --out if it already exists; ids come from
rglib.next_id so they stay unique. Exit status: 0 ok, 1 an entry failed schema
validation (nothing is written), 2 usage / I/O error.

Dependencies: Python stdlib + rglib (PyYAML, jsonschema via rglib).
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

import rglib

# --------------------------------------------------------------------------- mappings

# Severity mapping tables, one per tool dialect. Keys are lower-cased tool
# values; anything unmapped falls back to the default passed to map_sev().
SEVERITY_MAPS: dict[str, dict[str, str]] = {
    # SARIF result.level (used when no numeric security-severity is present).
    "sarif-level": {"error": "high", "warning": "medium", "note": "low", "none": "info"},
    # Semgrep extra.severity.
    "semgrep": {"critical": "critical", "error": "high", "high": "high", "warning": "medium",
                "medium": "medium", "info": "low", "low": "low"},
    # Bandit issue_severity.
    "bandit": {"high": "high", "medium": "medium", "low": "low"},
    # Vulnerability databases: osv-scanner, npm audit, trivy, checkov (when set).
    "advisory": {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium",
                 "low": "low", "info": "info", "informational": "info", "negligible": "info",
                 "unknown": "medium"},
    # Nuclei info.severity.
    "nuclei": {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
               "info": "info", "unknown": "info"},
    # Hadolint level.
    "hadolint": {"error": "medium", "warning": "low", "info": "info", "style": "info"},
    # ZAP riskcode (0 informational .. 3 high; ZAP has no "critical").
    "zap": {"3": "high", "2": "medium", "1": "low", "0": "info"},
}
# gitleaks has no severity: every hit is "high". trufflehog: Verified -> "critical",
# unverified -> "high". pip-audit has no severity: "medium". CVSS-like numbers
# (SARIF security-severity, osv max_severity) use cvss_bucket().
DEFAULT_SEVERITY = "medium"


def cvss_bucket(score: float) -> str:
    """CVSS v3 qualitative rating: >=9 critical, >=7 high, >=4 medium, >0 low, else info."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "info"


def map_sev(map_name: str, value: Any, default: str = DEFAULT_SEVERITY) -> str:
    key = "" if value is None else str(value).strip().lower()
    return SEVERITY_MAPS[map_name].get(key, default)


# CWE -> release-gate category. Used only for tools whose default category is
# generic ("sast" / "other"); SCA, secrets, IaC and container tools keep theirs.
# CWE-22 (path traversal) is deliberately NOT mapped: no category fits cleanly.
CWE_CATEGORY: dict[str, str] = {
    **{c: "injection" for c in ("CWE-77", "CWE-78", "CWE-89", "CWE-90", "CWE-94", "CWE-95",
                                "CWE-564", "CWE-643", "CWE-917", "CWE-943", "CWE-1336")},
    "CWE-79": "xss", "CWE-80": "xss",
    "CWE-918": "ssrf",
    "CWE-798": "secrets", "CWE-259": "secrets", "CWE-321": "secrets",
    "CWE-200": "data-exposure", "CWE-201": "data-exposure", "CWE-497": "data-exposure",
    "CWE-209": "error-handling",
    "CWE-117": "logging", "CWE-532": "logging",
    "CWE-352": "csrf",
    "CWE-346": "cors", "CWE-942": "cors",
    "CWE-693": "headers", "CWE-1021": "headers",
    **{c: "session" for c in ("CWE-384", "CWE-613", "CWE-614", "CWE-1004", "CWE-1275")},
    "CWE-287": "authn", "CWE-306": "authn", "CWE-521": "authn",
    "CWE-307": "rate-limit", "CWE-770": "rate-limit", "CWE-799": "rate-limit",
    **{c: "authz" for c in ("CWE-269", "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863")},
    **{c: "crypto" for c in ("CWE-295", "CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-328",
                             "CWE-330", "CWE-338", "CWE-916")},
    "CWE-434": "upload",
    "CWE-362": "race", "CWE-367": "race",
}

# Nuclei template tags -> category, first match wins (used after CWE).
NUCLEI_TAG_CATEGORY: dict[str, str] = {
    "xss": "xss", "sqli": "injection", "ssti": "injection", "rce": "injection", "ssrf": "ssrf",
    "csrf": "csrf", "cors": "cors", "headers": "headers", "default-login": "authn",
    "auth-bypass": "authn", "unauth": "authn", "token": "secrets", "exposure": "data-exposure",
}

# ZAP alert-name keywords -> category, first match wins (checked before CWE so
# header alerts do not become "data-exposure").
ZAP_KEYWORD_CATEGORY: list[tuple[str, str]] = [
    ("cookie", "session"), ("content security policy", "headers"), ("csp", "headers"),
    ("header", "headers"), ("anti-csrf", "csrf"), ("csrf", "csrf"), ("cors", "cors"),
    ("cross-domain", "cors"), ("sql injection", "injection"), ("cross site scripting", "xss"),
]


def categorize(cwes: list[str], default: str) -> str:
    """Map CWEs to a category when the tool's own category is generic."""
    if default in ("sast", "other"):
        for cwe in cwes:
            if cwe in CWE_CATEGORY:
                return CWE_CATEGORY[cwe]
    return default


# --------------------------------------------------------------------------- text helpers

_QUOTED_LITERAL = re.compile(r"""(['"])[^'"\n]{4,}\1""")
_ADVISORY_ID = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b", re.I)


def clean(text: Any, limit: int = 500, scrub_literals: bool = False) -> str:
    """Single-line, redacted, length-limited text safe to put in a report."""
    out = " ".join(str(text if text is not None else "").split())
    out = rglib.redact_text(out)
    if scrub_literals:
        out = _QUOTED_LITERAL.sub("<literal removed>", out)
    return out if len(out) <= limit else out[: limit - 1] + "…"


def strip_html(text: Any) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", str(text or "")))


def first_sentence(text: str, limit: int = 160) -> str:
    text = " ".join(str(text or "").split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    out = m.group(1) if m else text
    return out if len(out) <= limit else out[: limit - 1] + "…"


def redact_secret(value: Any) -> str:
    """Show at most a quarter of a secret (max 4 chars) via rglib.redact_value."""
    value = str(value or "")
    return rglib.redact_value(value, keep=min(4, len(value) // 4))


def parse_cwes(*values: Any) -> list[str]:
    """Extract 'CWE-n' ids from ints, 'CWE-79: ...' strings, tags, lists, {'id': n} dicts."""
    out: list[str] = []

    def add(n: int) -> None:
        if n > 0 and f"CWE-{n}" not in out:
            out.append(f"CWE-{n}")

    def walk(v: Any) -> None:
        if v is None or isinstance(v, bool):
            return
        if isinstance(v, (list, tuple, set)):
            for item in v:
                walk(item)
        elif isinstance(v, dict):
            walk(v.get("id"))
        elif isinstance(v, int):
            add(v)
        else:
            s = str(v).strip()
            found = re.findall(r"(?i)cwe[-_/ :]*0*(\d+)", s)
            if found:
                for n in found:
                    add(int(n))
            elif s.isdigit():
                add(int(s))

    for v in values:
        walk(v)
    return out


def as_int(v: Any) -> int | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def advisory_ids(*values: Any) -> list[str]:
    """Advisory ids (CVE/GHSA/PYSEC/GO/RUSTSEC) from strings or lists of strings, in order, unique."""
    out: list[str] = []

    def norm(i: str) -> str:
        return "GHSA-" + i[5:].lower() if i.upper().startswith("GHSA") else i.upper()

    def walk(v: Any) -> None:
        if v is None:
            return
        if isinstance(v, (list, tuple, set)):
            for x in v:
                walk(x)
            return
        for m in _ADVISORY_ID.finditer(str(v)):
            i = norm(m.group(0))
            if i not in out:
                out.append(i)

    for v in values:
        walk(v)
    return out


def url_path(url: str) -> tuple[str | None, str | None]:
    """Split a URL into (path, host). Non-URL strings return (None, string)."""
    if "://" not in url:
        return None, url or None
    parts = urlsplit(url)
    return parts.path or "/", parts.netloc or None


# --------------------------------------------------------------------------- data model

class ParseError(Exception):
    """The tool output is not in the expected format."""


@dataclass
class Raw:
    """One tool result before ids, evidence and timestamps are attached."""
    title: str
    severity: str
    category: str
    rule_id: str | None = None
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    endpoint: str | None = None
    component: str | None = None
    cwe: list[str] = field(default_factory=list)
    impact: str | None = None
    fix: str | None = None
    note: str | None = None          # goes to verification.reason
    tool_name: str | None = None     # overrides the --tool name (SARIF driver)
    tool_version: str | None = None


@dataclass
class Parsed:
    raws: list[Raw] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)   # parts of the scan that did not run/complete
    version: str | None = None
    scope: str | None = None


def _dict(data: Any, tool: str, *markers: str) -> dict:
    if not isinstance(data, dict):
        raise ParseError(f"expected a JSON object, got {type(data).__name__}")
    if markers and not any(m in data for m in markers):
        raise ParseError(f"not {tool} output (none of {', '.join(markers)} present)")
    return data


def _list(value: Any, what: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ParseError(f"'{what}' is not an array")
    return value


# --------------------------------------------------------------------------- parsers

def parse_gitleaks(data: Any, _: "Ctx") -> Parsed:
    if not isinstance(data, list):
        raise ParseError("gitleaks JSON report must be an array")
    out = Parsed()
    for r in data:
        if not isinstance(r, dict) or "RuleID" not in r:
            raise ParseError("gitleaks entry without RuleID")
        secret = r.get("Secret") or r.get("Match") or ""
        commit = str(r.get("Commit") or "")
        out.raws.append(Raw(
            title=clean(r.get("Description") or r["RuleID"], 200) + f" ({r['RuleID']})",
            severity="high", category="secrets", rule_id=str(r["RuleID"]),
            file=r.get("File") or None, line=as_int(r.get("StartLine")), end_line=as_int(r.get("EndLine")),
            component=f"commit {commit[:12]}" if commit else None, cwe=["CWE-798"],
            impact=f"Hard-coded secret committed to the repository (value redacted: {redact_secret(secret)}). "
                   "Treat as compromised until rotated.",
            fix="Rotate the credential, remove it from the code and git history, load it from a secret store.",
        ))
    return out


def parse_trufflehog(lines: Any, _: "Ctx") -> Parsed:
    out = Parsed()
    errors = 0
    for rec in lines:
        if not isinstance(rec, dict):
            raise ParseError("trufflehog JSONL line is not an object")
        if "DetectorName" not in rec:  # log line from --json mode
            out.version = out.version or rec.get("trufflehog_version")
            errors += rec.get("level") == "error"
            continue
        verified = rec.get("Verified") is True
        data = (rec.get("SourceMetadata") or {}).get("Data") or {}
        src = next((v for v in data.values() if isinstance(v, dict)), {})
        commit = str(src.get("commit") or "")
        raw_secret = rec.get("Raw") or rec.get("RawV2") or ""
        note = "verified live by trufflehog" if verified else None
        out.raws.append(Raw(
            title=f"{clean(rec['DetectorName'], 80)} credential detected" + (" (verified live)" if verified else ""),
            severity="critical" if verified else "high", category="secrets",
            rule_id=str(rec["DetectorName"]), file=src.get("file") or None, line=as_int(src.get("line")),
            component=f"commit {commit[:12]}" if commit else None, cwe=["CWE-798"], note=note,
            impact=("Credential verified live by trufflehog: it currently works. " if verified else
                    "Credential-shaped secret, not verified live. ")
                   + f"Value redacted: {redact_secret(raw_secret)}. Treat as compromised until rotated.",
            fix="Revoke and rotate the credential, remove it from code and git history, load it from a secret store.",
        ))
    if errors:
        out.gaps.append(f"{errors} error log line(s) in trufflehog output")
    return out


def parse_semgrep(data: Any, _: "Ctx") -> Parsed:
    d = _dict(data, "semgrep", "results")
    out = Parsed(version=d.get("version"))
    scanned = (d.get("paths") or {}).get("scanned")
    if isinstance(scanned, list):
        out.scope = f"{len(scanned)} files scanned"
    for e in _list(d.get("errors"), "errors"):
        out.gaps.append("semgrep error: " + clean((e or {}).get("message") or (e or {}).get("type") or e, 120))
    for r in _list(d["results"], "results"):
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwes = parse_cwes(meta.get("cwe"))
        cat = categorize(cwes, "sast")
        msg = extra.get("message") or r.get("check_id") or "semgrep finding"
        out.raws.append(Raw(
            title=first_sentence(msg), severity=map_sev("semgrep", extra.get("severity")), category=cat,
            rule_id=r.get("check_id"), file=r.get("path"), line=as_int((r.get("start") or {}).get("line")),
            end_line=as_int((r.get("end") or {}).get("line")), cwe=cwes, impact=str(msg),
        ))
    return out


_BANDIT_SECRET_TESTS = {"B105", "B106", "B107"}


def parse_bandit(data: Any, _: "Ctx") -> Parsed:
    d = _dict(data, "bandit", "results")
    out = Parsed()
    loc = ((d.get("metrics") or {}).get("_totals") or {}).get("loc")
    if loc is not None:
        out.scope = f"{loc} lines of code scanned"
    for e in _list(d.get("errors"), "errors"):
        out.gaps.append("bandit could not scan " + clean((e or {}).get("filename") or e, 120))
    for r in _list(d["results"], "results"):
        cwes = parse_cwes(r.get("issue_cwe"))
        test_id = r.get("test_id")
        if test_id in _BANDIT_SECRET_TESTS:
            # bandit puts the literal password in issue_text and code: never copy either.
            text = f"Possible hardcoded password ({r.get('test_name', test_id)})"
        else:
            text = r.get("issue_text") or r.get("test_name") or "bandit finding"
        conf = r.get("issue_confidence")
        out.raws.append(Raw(
            title=f"{first_sentence(text)} ({test_id})" if test_id else first_sentence(text),
            severity=map_sev("bandit", r.get("issue_severity")),
            category=categorize(cwes, "sast"), rule_id=test_id, file=r.get("filename"),
            line=as_int(r.get("line_number")), end_line=as_int(max(r.get("line_range") or [0]) or None),
            cwe=cwes, impact=f"{text} (bandit confidence: {conf})" if conf else text,
        ))
    return out


def _osv_severity(vuln: dict, groups: list[dict]) -> str:
    ids = {vuln.get("id"), *(vuln.get("aliases") or [])}
    for g in groups:
        if ids & {*(g.get("ids") or []), *(g.get("aliases") or [])}:
            try:
                return cvss_bucket(float(g["max_severity"]))
            except (KeyError, TypeError, ValueError):
                pass
    return map_sev("advisory", (vuln.get("database_specific") or {}).get("severity"))


def parse_osv(data: Any, _: "Ctx") -> Parsed:
    d = _dict(data, "osv-scanner", "results")
    out = Parsed()
    for res in _list(d["results"], "results"):
        src = (res.get("source") or {}).get("path")
        for pk in res.get("packages") or []:
            pkg = pk.get("package") or {}
            name, version = pkg.get("name") or "unknown", pkg.get("version")
            groups = pk.get("groups") or []
            for v in pk.get("vulnerabilities") or []:
                ids = [v.get("id"), *(v.get("aliases") or [])]
                ids = [i for i in ids if i]
                fixed = sorted({ev["fixed"] for a in v.get("affected") or [] for rng in a.get("ranges") or []
                                for ev in rng.get("events") or [] if "fixed" in ev})
                summary = v.get("summary") or (ids[0] if ids else "vulnerability")
                out.raws.append(Raw(
                    title=f"{name} {version}: {first_sentence(summary, 120)}" + (f" ({ids[0]})" if ids else ""),
                    severity=_osv_severity(v, groups), category="sca", rule_id=", ".join(ids) or None,
                    file=src, component=f"{name}@{version}" if version else name,
                    cwe=parse_cwes((v.get("database_specific") or {}).get("cwe_ids")),
                    impact=v.get("details") or summary,
                    fix=f"Upgrade {name} to {', '.join(fixed)}" if fixed else None,
                ))
    return out


def parse_npm_audit(data: Any, _: "Ctx") -> Parsed:
    d = _dict(data, "npm-audit", "vulnerabilities", "error")
    if "error" in d:
        err = d["error"] if isinstance(d["error"], dict) else {}
        raise ParseError(f"npm audit failed: {clean(err.get('code') or '')} {clean(err.get('summary') or d['error'], 160)}".strip())
    if "auditReportVersion" not in d:
        raise ParseError("npm audit v6 format (no auditReportVersion); npm >= 7 required")
    vulns = d["vulnerabilities"]
    if not isinstance(vulns, dict):
        raise ParseError("'vulnerabilities' is not an object")
    out = Parsed()
    for pkg_name, v in vulns.items():
        # Packages whose `via` holds only strings are vulnerable transitively; the
        # advisory itself is reported under the package that owns it.
        for adv in (x for x in v.get("via") or [] if isinstance(x, dict)):
            name = adv.get("name") or pkg_name
            cvss = (adv.get("cvss") or {}).get("score")
            sev = cvss_bucket(float(cvss)) if isinstance(cvss, (int, float)) and cvss > 0 else map_sev("advisory", adv.get("severity"))
            fa = v.get("fixAvailable")
            if isinstance(fa, dict):
                fix = f"Upgrade {fa.get('name')} to {fa.get('version')}" + (" (semver-major)" if fa.get("isSemVerMajor") else "")
            else:
                fix = "Run npm audit fix" if fa else "No fix available from npm"
            ids = advisory_ids(adv.get("url"))
            nodes = v.get("nodes") or []
            out.raws.append(Raw(
                title=f"{name}: {adv.get('title') or 'vulnerability'}" + (f" ({ids[0]})" if ids else ""),
                severity=sev, category="sca", rule_id=", ".join(ids) or str(adv.get("source") or "") or None,
                file=nodes[0] if nodes else None, component=name, cwe=parse_cwes(adv.get("cwe")),
                impact=f"Affected range: {adv.get('range')}. Advisory: {adv.get('url')}", fix=fix,
            ))
    return out


def parse_pip_audit(data: Any, _: "Ctx") -> Parsed:
    deps = data.get("dependencies") if isinstance(data, dict) else data
    if not isinstance(deps, list):
        raise ParseError("pip-audit JSON has no 'dependencies' array")
    out = Parsed()
    skipped: list[str] = []
    for d in deps:
        if not isinstance(d, dict) or "name" not in d:
            raise ParseError("pip-audit dependency entry without name")
        if "skip_reason" in d:
            skipped.append(f"{d['name']} ({clean(d['skip_reason'], 80)})")
            continue
        for v in d.get("vulns") or []:
            ids = [v.get("id"), *(v.get("aliases") or [])]
            ids = [i for i in ids if i]
            fv = v.get("fix_versions") or []
            out.raws.append(Raw(
                title=f"{d['name']} {d.get('version')}: {first_sentence(v.get('description') or ids[0], 120)}"
                      + (f" ({ids[0]})" if ids else ""),
                severity=DEFAULT_SEVERITY, category="sca", rule_id=", ".join(ids) or None,
                component=f"{d['name']}@{d['version']}" if d.get("version") else d["name"],
                impact=(v.get("description") or "") + " (pip-audit reports no severity; defaulted to medium.)",
                fix=f"Upgrade {d['name']} to {', '.join(fv)}" if fv else "No fixed version published",
            ))
    if skipped:
        out.gaps.append(f"{len(skipped)} dependenc{'y' if len(skipped) == 1 else 'ies'} not audited: " + "; ".join(skipped[:5]))
    return out


def parse_trivy(data: Any, _: "Ctx") -> Parsed:
    d = _dict(data, "trivy", "SchemaVersion", "Results", "ArtifactName")
    out = Parsed(scope=" ".join(str(x) for x in (d.get("ArtifactType"), d.get("ArtifactName")) if x) or None)
    for res in _list(d.get("Results"), "Results"):
        target = res.get("Target")
        for v in res.get("Vulnerabilities") or []:
            ids = [v.get("VulnerabilityID"), *advisory_ids(v.get("References"), v.get("PrimaryURL"))]
            ids = [i for n, i in enumerate(ids) if i and i not in ids[:n]]
            pkg, ver = v.get("PkgName") or "unknown", v.get("InstalledVersion")
            fixed = v.get("FixedVersion")
            out.raws.append(Raw(
                title=f"{pkg} {ver}: {first_sentence(v.get('Title') or v.get('VulnerabilityID') or 'vulnerability', 120)}"
                      f" ({v.get('VulnerabilityID')})",
                severity=map_sev("advisory", v.get("Severity")), category="sca", rule_id=", ".join(ids) or None,
                file=target, component=f"{pkg}@{ver}" if ver else pkg, cwe=parse_cwes(v.get("CweIDs")),
                impact=v.get("Description") or v.get("Title"),
                fix=f"Upgrade {pkg} to {fixed}" if fixed else None,
            ))
        for m in res.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            is_docker = "dockerfile" in str(res.get("Type") or m.get("Type") or "").lower()
            out.raws.append(Raw(
                title=f"{m.get('Title') or m.get('ID')} ({m.get('ID')})",
                severity=map_sev("advisory", m.get("Severity")), category="container" if is_docker else "iac",
                rule_id=m.get("ID") or m.get("AVDID"), file=target, line=as_int(cause.get("StartLine")),
                end_line=as_int(cause.get("EndLine")), impact=m.get("Message") or m.get("Description"),
                fix=m.get("Resolution"),
            ))
        for s in res.get("Secrets") or []:  # trivy masks Match; Code/Match are never copied
            out.raws.append(Raw(
                title=f"{s.get('Title') or s.get('RuleID')} ({s.get('RuleID')})",
                severity=map_sev("advisory", s.get("Severity")), category="secrets", rule_id=s.get("RuleID"),
                file=target, line=as_int(s.get("StartLine")), end_line=as_int(s.get("EndLine")), cwe=["CWE-798"],
                impact="Secret detected in the scanned files (value not copied). Treat as compromised until rotated.",
                fix="Rotate the credential and load it from a secret store.",
            ))
    return out


_CHECKOV_CATEGORY = {"secrets": "secrets", "sca_package": "sca", "sca_image": "sca", "dockerfile": "container"}


def parse_checkov(data: Any, _: "Ctx") -> Parsed:
    objs = data if isinstance(data, list) else [data]
    out = Parsed()
    if not objs:
        out.gaps.append("checkov produced no framework reports (nothing was scanned)")
    for obj in objs:
        obj = _dict(obj, "checkov", "check_type", "results")
        ctype = str(obj.get("check_type") or "unknown")
        summary = obj.get("summary") or {}
        out.version = out.version or summary.get("checkov_version")
        res = obj.get("results") or {}
        failed = _list(res.get("failed_checks"), "failed_checks")
        for pe in _list(res.get("parsing_errors"), "parsing_errors"):
            out.gaps.append(f"checkov could not parse {clean(pe, 100)}")
        if summary and not any(summary.get(k) for k in ("passed", "failed", "skipped", "resource_count")):
            out.gaps.append(f"checkov ({ctype}) evaluated 0 resources")
        for f in failed:
            fp, abs_fp = f.get("file_path") or "", f.get("file_abs_path") or ""
            rel = fp.lstrip("/") if abs_fp.endswith(fp) else fp
            lr = f.get("file_line_range") or [None, None]
            sev = f.get("severity")
            out.raws.append(Raw(
                title=f"{clean(f.get('check_name') or f.get('check_id'), 180)} ({f.get('check_id')})",
                severity=map_sev("advisory", sev) if sev else DEFAULT_SEVERITY,
                category=_CHECKOV_CATEGORY.get(ctype, "iac"), rule_id=f.get("check_id"), file=rel or None,
                line=as_int(lr[0]), end_line=as_int(lr[-1]), component=f.get("resource"),
                impact=f"{f.get('check_name')} (resource {f.get('resource')})"
                       + ("" if sev else " (checkov reported no severity; defaulted to medium.)"),
                fix=f.get("guideline"),
            ))
    return out


def parse_hadolint(data: Any, _: "Ctx") -> Parsed:
    if not isinstance(data, list):
        raise ParseError("hadolint JSON output must be an array")
    out = Parsed()
    for r in data:
        if not isinstance(r, dict) or "code" not in r:
            raise ParseError("hadolint entry without code")
        out.raws.append(Raw(
            title=f"{r['code']}: {first_sentence(r.get('message') or r['code'], 150)}",
            severity=map_sev("hadolint", r.get("level"), "low"), category="container", rule_id=r["code"],
            file=r.get("file"), line=as_int(r.get("line")), impact=r.get("message"),
        ))
    return out


def parse_zap(data: Any, _: "Ctx") -> Parsed:
    d = _dict(data, "zap", "site", "@programName")
    out = Parsed(version=d.get("@version"))
    sites = d.get("site") or []
    sites = [sites] if isinstance(sites, dict) else sites
    out.scope = ", ".join(str(s.get("@name")) for s in sites if s.get("@name")) or None
    for site in sites:
        for a in site.get("alerts") or site.get("alert") or []:
            name = a.get("name") or a.get("alert") or "ZAP alert"
            cwes = parse_cwes(a.get("cweid"))
            low = name.lower()
            cat = next((c for kw, c in ZAP_KEYWORD_CATEGORY if kw in low), None) or categorize(cwes, "other")
            insts = a.get("instances") or []
            first = insts[0] if insts else {}
            path, _host = url_path(first.get("uri") or "")
            out.raws.append(Raw(
                title=name, severity=map_sev("zap", a.get("riskcode"), "info"), category=cat,
                rule_id=str(a.get("pluginid") or a.get("alertRef") or "") or None,
                endpoint=f"{first.get('method') or 'GET'} {path}" if path else None,
                component=f"param: {first['param']}" if first.get("param") else None, cwe=cwes,
                impact=f"{strip_html(a.get('desc'))} ({a.get('count') or len(insts)} instance(s))",
                fix=strip_html(a.get("solution")) or None,
            ))
    return out


def parse_nuclei(lines: Any, _: "Ctx") -> Parsed:
    out = Parsed()
    for rec in lines:
        if not isinstance(rec, dict) or "template-id" not in rec:
            raise ParseError("nuclei JSONL line without template-id")
        info = rec.get("info") or {}
        cls = info.get("classification") or {}
        cwes = parse_cwes(cls.get("cwe-id"))
        tags = info.get("tags") or []
        tags = [t.strip().lower() for t in (tags.split(",") if isinstance(tags, str) else tags)]
        cat = categorize(cwes, "other")
        if cat == "other":
            cat = next((c for t, c in NUCLEI_TAG_CATEGORY.items() if t in tags), "other")
        path, host = url_path(str(rec.get("matched-at") or rec.get("host") or ""))
        out.raws.append(Raw(
            title=info.get("name") or rec["template-id"], severity=map_sev("nuclei", info.get("severity"), "info"),
            category=cat, rule_id=rec["template-id"], endpoint=path, component=host, cwe=cwes,
            impact=info.get("description"),
        ))
    return out


# SARIF -------------------------------------------------------------------------

# Driver-name substring -> category for SARIF produced by non-SAST scanners.
SARIF_DRIVER_CATEGORY: list[tuple[str, str]] = [
    ("gitleaks", "secrets"), ("trufflehog", "secrets"), ("checkov", "iac"), ("hadolint", "container"),
    ("osv", "sca"), ("dependency", "sca"),
]
SARIF_TAG_CATEGORY = {"secret": "secrets", "vulnerability": "sca", "misconfiguration": "iac"}


def _sarif_category(driver_name: str, tags: list[str], cwes: list[str]) -> str:
    low = driver_name.lower()
    for needle, cat in SARIF_DRIVER_CATEGORY:
        if needle in low:
            return cat
    for tag in tags:
        if tag.lower() in SARIF_TAG_CATEGORY:
            return SARIF_TAG_CATEGORY[tag.lower()]
    return categorize(cwes, "sast")


def parse_sarif(data: Any, _: "Ctx") -> Parsed:
    d = _dict(data, "sarif", "runs")
    runs = _list(d["runs"], "runs")
    out = Parsed()
    if not runs:
        out.gaps.append("SARIF log contains no runs")
    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        dname = str(driver.get("name") or "sarif")
        dver = driver.get("semanticVersion") or driver.get("version")
        rules = driver.get("rules") or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for inv in run.get("invocations") or []:
            if inv.get("executionSuccessful") is False:
                out.gaps.append(f"{dname}: invocation reported executionSuccessful=false")
        if run.get("results") is None:
            out.gaps.append(f"{dname}: run has no results array (analysis may not have completed)")
        for res in run.get("results") or []:
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id")
            idx = res.get("ruleIndex", (res.get("rule") or {}).get("index"))
            rule = rules[idx] if isinstance(idx, int) and 0 <= idx < len(rules) else by_id.get(rid, {})
            rid = rid or rule.get("id")
            rprops, props = rule.get("properties") or {}, res.get("properties") or {}
            tags = [str(t) for t in (rprops.get("tags") or []) + (props.get("tags") or [])]
            cwes = parse_cwes(tags, rprops.get("cwe"))
            secsev = props.get("security-severity", rprops.get("security-severity"))
            try:
                sev = cvss_bucket(float(secsev))
            except (TypeError, ValueError):
                level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
                sev = map_sev("sarif-level", level)
            msg = (res.get("message") or {}).get("text") or ""
            short = (rule.get("shortDescription") or {}).get("text")
            if short and short.startswith("Semgrep Finding:"):  # just the rule id again
                short = None
            cat = _sarif_category(dname, tags, cwes)
            loc = ((res.get("locations") or [{}])[0] or {}).get("physicalLocation") or {}
            uri = (loc.get("artifactLocation") or {}).get("uri")
            region = loc.get("region") or {}
            logical = ((res.get("locations") or [{}])[0] or {}).get("logicalLocations") or []
            impact = msg or None
            if res.get("suppressions"):
                impact = (impact or "") + " (tool marks this result as suppressed)"
            out.raws.append(Raw(
                title=first_sentence(short or msg or str(rid)), severity=sev, category=cat, rule_id=rid,
                file=unquote(uri[7:] if uri.startswith("file://") else uri) if uri else None,
                line=as_int(region.get("startLine")), end_line=as_int(region.get("endLine")),
                component=(logical[0].get("fullyQualifiedName") or logical[0].get("name")) if logical else None,
                cwe=cwes, impact=impact, tool_name=dname, tool_version=str(dver) if dver else None,
            ))
    return out


# --------------------------------------------------------------------------- registry

@dataclass(frozen=True)
class ToolSpec:
    fmt: str                       # "json" or "jsonl"
    parse: Callable[[Any, "Ctx"], Parsed]
    category: str                  # category for check entries (NOT-TESTED / VERIFIED-ABSENT)


TOOLS: dict[str, ToolSpec] = {
    "sarif": ToolSpec("json", parse_sarif, "sast"),
    "gitleaks": ToolSpec("json", parse_gitleaks, "secrets"),
    "trufflehog": ToolSpec("jsonl", parse_trufflehog, "secrets"),
    "semgrep": ToolSpec("json", parse_semgrep, "sast"),
    "bandit": ToolSpec("json", parse_bandit, "sast"),
    "osv-scanner": ToolSpec("json", parse_osv, "sca"),
    "npm-audit": ToolSpec("json", parse_npm_audit, "sca"),
    "pip-audit": ToolSpec("json", parse_pip_audit, "sca"),
    "trivy": ToolSpec("json", parse_trivy, "container"),
    "checkov": ToolSpec("json", parse_checkov, "iac"),
    "hadolint": ToolSpec("json", parse_hadolint, "container"),
    "zap": ToolSpec("json", parse_zap, "other"),
    "nuclei": ToolSpec("jsonl", parse_nuclei, "other"),
}
# `--tool` aliases for scanners that emit SARIF (the driver name still labels each finding).
TOOL_ALIASES = {"semgrep-sarif": "sarif", "codeql": "sarif", "trivy-sarif": "sarif", "checkov-sarif": "sarif",
                "hadolint-sarif": "sarif", "gosec": "sarif", "osv": "osv-scanner"}


@dataclass
class Ctx:
    scope_note: str | None = None
    tool_version: str | None = None
    empty_ok: bool = False


# --------------------------------------------------------------------------- entries

def evidence_path(path: Path) -> str:
    """Path relative to the enclosing .release-gate dir if there is one, else as given."""
    resolved = path.resolve()
    for parent in resolved.parents:
        if parent.name == rglib.STATE_DIRNAME:
            return resolved.relative_to(parent).as_posix()
    return str(path)


def project_root(path: Path) -> Path | None:
    """The scanned project's root: the parent of the enclosing .release-gate dir."""
    for parent in path.resolve().parents:
        if parent.name == rglib.STATE_DIRNAME:
            return parent.parent
    return None


def relocate(file: str | None, root: Path | None) -> tuple[str | None, bool]:
    """Make an absolute in-project path relative. Returns (path, is_self_artifact).

    is_self_artifact is True when the location is inside .release-gate/ itself:
    a scanner re-reading earlier evidence, never a finding about the project.
    """
    if not file:
        return file, False
    rel = file
    if root is not None and Path(file).is_absolute():
        try:
            rel = Path(file).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = file
    rel = rel[2:] if rel.startswith("./") else rel
    return rel, rel.split("/", 1)[0] == rglib.STATE_DIRNAME


def _evidence(path: Path, tool: str, secrets: bool) -> list[dict]:
    ev: dict[str, Any] = {"type": "tool-output", "path": evidence_path(path)}
    ev["description"] = f"raw {tool} output" + (" (contains unredacted secrets: do not publish)" if secrets else "")
    if path.is_file():
        ev["sha256"] = rglib.sha256_file(path)
    return [ev]


def _drop_none(d: dict) -> dict:
    """Drop empty optional values; `evidence` is required by the schema so it always stays."""
    return {k: v for k, v in d.items() if k == "evidence" or v not in (None, "", [], {})}


# Which catalog check (checks.yaml) a static finding evidences, by category. Stamping
# this lets report_build's coverage matrix count the finding against its check instead
# of leaving the check NOT-TESTED while the finding floats by severity only (issue #1).
# Secrets split by tool: gitleaks scans history, trufflehog verifies live secrets.
CATEGORY_CHECK_ID = {
    "sast": "SEC-SAST",
    "sca": "SEC-SCA",
    "iac": "SEC-IAC",
    "container": "SEC-IAC",
    "injection": "SEC-INJECTION-DYNAMIC",
    "xss": "SEC-XSS-DYNAMIC",
    "ssrf": "SEC-SSRF-DYNAMIC",
    "authz": "SEC-AUTHZ-MATRIX",
}


def _check_id_for(raw: Raw, tool: str) -> str | None:
    if raw.category == "secrets":
        return "SEC-SECRETS-VERIFIED" if (raw.tool_name or tool) == "trufflehog" else "SEC-SECRETS-HISTORY"
    return CATEGORY_CHECK_ID.get(raw.category)


def finding_entry(raw: Raw, tool: str, parsed: Parsed, ctx: Ctx, evidence: list[dict], now: str) -> dict:
    secrets = raw.category == "secrets"
    title = clean(raw.title, 200, secrets)
    if len(title) < 3:
        title = f"{tool} finding"
    reason = clean(raw.note, 200) if raw.note else None
    return _drop_none({
        "kind": "finding",
        "check_id": _check_id_for(raw, tool),
        "title": title,
        "severity": raw.severity,
        "category": raw.category,
        "evidence_class": "SUSPECTED",
        "status": "open",
        "location": _drop_none({"file": raw.file, "line": raw.line, "end_line": raw.end_line,
                                "endpoint": raw.endpoint, "component": raw.component}),
        "evidence": evidence,
        "tool": _drop_none({"name": raw.tool_name or tool, "version": ctx.tool_version or raw.tool_version or parsed.version,
                            "rule_id": clean(raw.rule_id, 200) if raw.rule_id else None,
                            "scope": ctx.scope_note or parsed.scope}),
        "verification": _drop_none({"verdict": "unverified", "reason": reason}),
        "cwe": raw.cwe,
        "impact": clean(raw.impact, 500, secrets) if raw.impact else None,
        "fix": clean(raw.fix, 300) if raw.fix else None,
        "created_at": now,
    })


def check_entry(tool: str, category: str, title: str, evidence_class: str, evidence: list[dict], now: str,
                reason: str | None = None, ctx: Ctx | None = None) -> dict:
    return _drop_none({
        "kind": "check",
        "title": clean(title, 200),
        "category": category,
        "evidence_class": evidence_class,
        "not_tested_reason": clean(reason, 300) if reason else None,
        "evidence": evidence,
        "tool": _drop_none({"name": tool, "version": ctx.tool_version if ctx else None,
                            "scope": ctx.scope_note if ctx else None}),
        "created_at": now,
    })


def _read(spec: ToolSpec, path: Path) -> Any:
    """Parse the file; returns None for an empty file. Raises ParseError on bad content."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ParseError(f"cannot read file: {type(exc).__name__}") from exc
    if not text.strip():
        return None
    try:
        if spec.fmt == "jsonl":
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc.msg} (line {exc.lineno} col {exc.colno})") from exc


def normalize_file(tool: str, path: Path, ctx: Ctx, now: str) -> list[dict]:
    """Normalize one input file into entries WITHOUT ids."""
    spec = TOOLS[tool]
    if not path.is_file():
        return [check_entry(tool, spec.category, f"{tool} produced no output file ({path.name})", "NOT-TESTED", [], now,
                            "tool produced no output file", ctx)]
    ev_secret = tool in ("gitleaks", "trufflehog")
    evidence = _evidence(path, tool, ev_secret)

    def not_tested(err: str) -> list[dict]:
        return [check_entry(tool, spec.category, f"{tool} output could not be parsed ({path.name})", "NOT-TESTED",
                            evidence, now, f"tool output unparseable: {tool}: {err}", ctx)]

    try:
        data = _read(spec, path)
        if data is None:
            if spec.fmt == "jsonl" and ctx.empty_ok:
                data = []
            else:
                return not_tested("empty file")
        parsed = spec.parse(data, ctx)
    except ParseError as exc:
        return not_tested(str(exc))
    except Exception as exc:  # malformed structure inside valid JSON: never swallow into zero findings
        return not_tested(f"{type(exc).__name__}: {exc}")

    root = project_root(path)
    kept = []
    for r in parsed.raws:
        r.file, self_artifact = relocate(r.file, root)
        if self_artifact:
            print(f"drop: {tool} finding inside {rglib.STATE_DIRNAME}/ ({r.file}) is release-gate's own evidence",
                  file=sys.stderr)
            continue
        kept.append(r)
    parsed.raws = kept
    entries = [finding_entry(r, tool, parsed, ctx, evidence, now) for r in parsed.raws]
    if parsed.gaps:
        entries.append(check_entry(tool, spec.category, f"{tool} reported incomplete coverage", "NOT-TESTED", evidence, now,
                                   f"tool reported incomplete coverage: {tool}: " + "; ".join(parsed.gaps), ctx))
    elif not parsed.raws:
        entries.append(check_entry(tool, spec.category,
                                   f"{tool} reported no findings (scope: {ctx.scope_note or 'unknown scope'})",
                                   "VERIFIED-ABSENT", evidence, now, None, ctx))
    return entries


# --------------------------------------------------------------------------- auto-detect

_FILENAME_HINTS: list[tuple[frozenset[str], str]] = [
    (frozenset({"sarif"}), "sarif"), (frozenset({"gitleaks"}), "gitleaks"), (frozenset({"trufflehog"}), "trufflehog"),
    (frozenset({"semgrep"}), "semgrep"), (frozenset({"bandit"}), "bandit"), (frozenset({"osv"}), "osv-scanner"),
    (frozenset({"npm", "audit"}), "npm-audit"), (frozenset({"pip", "audit"}), "pip-audit"),
    (frozenset({"trivy"}), "trivy"), (frozenset({"checkov"}), "checkov"), (frozenset({"hadolint"}), "hadolint"),
    (frozenset({"zap"}), "zap"), (frozenset({"nuclei"}), "nuclei"),
]
SCANNABLE_SUFFIXES = {".json", ".jsonl", ".ndjson", ".sarif"}
RUN_TOOL_METADATA = "result.json"  # run_tool.py's own record, not scanner output


def sniff(data: Any) -> str | None:
    """Detect the tool from parsed content (a dict/list, or a list of JSONL records)."""
    if isinstance(data, dict):
        if "runs" in data:
            return "sarif"
        if "@programName" in data or "site" in data:
            return "zap"
        if "auditReportVersion" in data or isinstance(data.get("vulnerabilities"), dict):
            return "npm-audit"
        if isinstance(data.get("dependencies"), list):
            return "pip-audit"
        if {"SchemaVersion", "Results", "ArtifactName"} & data.keys():
            return "trivy"
        if "check_type" in data:
            return "checkov"
        if isinstance(data.get("results"), list):
            items = [i for i in data["results"] if isinstance(i, dict)]
            if any("check_id" in i for i in items):
                return "semgrep"
            if any("test_id" in i for i in items):
                return "bandit"
            if any("packages" in i for i in items):
                return "osv-scanner"
            if "metrics" in data:
                return "bandit"
            if "paths" in data:
                return "semgrep"
            return "osv-scanner"
    elif isinstance(data, list) and data:
        recs = [r for r in data if isinstance(r, dict)]
        if any("DetectorName" in r or r.get("logger") == "trufflehog" for r in recs):
            return "trufflehog"
        if any("template-id" in r for r in recs):
            return "nuclei"
        if any("RuleID" in r for r in recs):
            return "gitleaks"
        if any({"code", "level", "line"} <= r.keys() for r in recs):
            return "hadolint"
        if any("check_type" in r for r in recs):
            return "checkov"
    return None


def detect_tool(path: Path) -> str | None:
    """Detect the scanner from the file name first, then from its content."""
    if path.suffix.lower() == ".sarif":
        return "sarif"
    tokens = set(re.split(r"[^a-z0-9]+", path.stem.lower()))
    for needed, tool in _FILENAME_HINTS:
        if needed <= tokens:
            return tool
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        return sniff(json.loads(text))
    except json.JSONDecodeError:
        pass
    try:
        return sniff([json.loads(line) for line in text.splitlines() if line.strip()])
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Normalize scanner output into release-gate findings.")
    ap.add_argument("--tool", choices=sorted([*TOOLS, *TOOL_ALIASES]), help="scanner that produced --input")
    ap.add_argument("--input", action="append", default=[], help="tool output file (repeatable)")
    ap.add_argument("--auto", metavar="EVIDENCE_DIR", help="detect tools by filename/content for files in this dir")
    ap.add_argument("--out", required=True, help="findings file (.json or .yaml); entries are appended")
    ap.add_argument("--scope-note", help="what the scan covered, e.g. 'full git history'")
    ap.add_argument("--tool-version", help="tool version to record")
    ap.add_argument("--empty-ok", action="store_true",
                    help="treat a zero-byte JSONL file (trufflehog, nuclei) as a valid empty result; "
                         "use only when the tool exited 0")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if bool(args.tool) == bool(args.auto):
        print("error: give either --tool with --input, or --auto", file=sys.stderr)
        return 2
    ctx = Ctx(scope_note=args.scope_note, tool_version=args.tool_version, empty_ok=args.empty_ok)
    out_path = Path(args.out)

    jobs: list[tuple[str, Path]] = []
    if args.tool:
        if not args.input:
            print("error: --tool needs at least one --input", file=sys.stderr)
            return 2
        tool = TOOL_ALIASES.get(args.tool, args.tool)
        jobs = [(tool, Path(p)) for p in args.input]
    else:
        root = Path(args.auto)
        if not root.is_dir():
            print(f"error: --auto directory not found: {root}", file=sys.stderr)
            return 2
        for p in sorted(root.rglob("*")):
            if (not p.is_file() or p.suffix.lower() not in SCANNABLE_SUFFIXES or p.name == RUN_TOOL_METADATA
                    or p.resolve() == out_path.resolve()):
                continue
            tool = detect_tool(p)
            if tool is None:
                print(f"skip: could not detect a supported tool for {p}", file=sys.stderr)
                continue
            jobs.append((tool, p))
        if not jobs:
            print(f"error: no recognizable tool output under {root}", file=sys.stderr)
            return 2

    try:
        existing = rglib.load_data(out_path, default=[])
    except (OSError, ValueError) as exc:
        print(f"error: cannot read {out_path}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(existing, list):
        print(f"error: {out_path} must contain a list of entries", file=sys.stderr)
        return 2

    now = rglib.now_iso()
    ids = [e["id"] for e in existing if isinstance(e, dict) and "id" in e]
    new: list[dict] = []
    for tool, path in jobs:
        for entry in normalize_file(tool, path, ctx, now):
            entry = {"id": rglib.next_id(entry["category"], ids), **entry}
            ids.append(entry["id"])
            new.append(entry)

    failures = 0
    for entry in new:
        for err in rglib.validate(entry, "finding"):
            failures += 1
            print(f"schema error in {entry['id']}: {err}", file=sys.stderr)
    if failures:
        print(f"error: {failures} schema error(s); nothing written", file=sys.stderr)
        return 1

    rglib.dump_data(out_path, existing + new)
    n_check = sum(e["kind"] == "check" for e in new)
    print(f"appended {len(new)} entries to {out_path} ({len(new) - n_check} findings, {n_check} checks)")
    for e in new:
        if e["evidence_class"] == "NOT-TESTED":
            print(f"warning: {e['id']} NOT-TESTED: {e['not_tested_reason']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
