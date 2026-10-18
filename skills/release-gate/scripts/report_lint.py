#!/usr/bin/env python3
"""Lint a release-gate report before it is allowed to be final.

Fails (exit 1) on:
  - banned reassurance phrases ("secure", "no vulnerabilities", "looks good", …)
    unless the same line carries VERIFIED-ABSENT and a link to an evidence file
  - a pass or finding (EXPLOITED / TOOL-CONFIRMED / VERIFIED-ABSENT) with no artifact
  - an artifact link that points at a file that does not exist
  - an entry without a valid evidence class, or NOT-TESTED without a reason
  - an unredacted secret anywhere in the report
  - external assets or scripts in the HTML report (it must be self-contained)

Usage: report_lint.py REPORT [REPORT ...] [--state-dir .release-gate]
File type is taken from the extension (.md, .html, .json, .sarif).
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rglib  # noqa: E402

BANNED = [
    re.compile(r"\bsecure\b(?!\s*(?:flag|attribute|cookie|context|=|;|,\s*httponly))", re.I),
    re.compile(r"\bfully[- ]compliant\b", re.I),
    re.compile(r"\bno (?:known )?vulnerabilities\b", re.I),
    re.compile(r"\bproduction[- ]ready\b", re.I),
    re.compile(r"\bbest practices (?:are )?followed\b", re.I),
    re.compile(r"\bappears (?:to be )?safe\b", re.I),
    re.compile(r"\blooks good\b", re.I),
    re.compile(r"\bgreat job\b", re.I),
]
CODE_SPAN = re.compile(r"`[^`]*`")
MD_LINK = re.compile(r"\]\(([^)\s]+)\)")
EVIDENCE_LINK = re.compile(r"\]\((?:\.\./)?evidence/[^)\s]+\)")
CLASS_RE = re.compile(r"\b(EXPLOITED|TOOL-CONFIRMED|VERIFIED-ABSENT)\b")


def _banned_hits(line: str) -> list[str]:
    text = CODE_SPAN.sub("", line)
    return [m.group(0) for pat in BANNED for m in pat.finditer(text)]


def _backed(line: str) -> bool:
    return "VERIFIED-ABSENT" in line and bool(EVIDENCE_LINK.search(line))


def lint_secrets(name: str, text: str) -> list[str]:
    return [f"{name}: unredacted {kind} secret starting {rglib.redact_value(val)}" for kind, val in rglib.find_secrets(text)]


def lint_markdown(path: Path) -> list[str]:
    problems = []
    text = path.read_text(encoding="utf-8")
    problems += lint_secrets(path.name, text)
    for n, line in enumerate(text.splitlines(), 1):
        hits = _banned_hits(line)
        if hits and not _backed(line):
            problems.append(f"{path.name}:{n}: banned phrase {hits!r} without VERIFIED-ABSENT evidence link")
        if line.startswith("|") and CLASS_RE.search(line) and not MD_LINK.search(line):
            problems.append(f"{path.name}:{n}: table row claims {CLASS_RE.search(line).group(1)} but links no artifact")
        for target in MD_LINK.findall(line):
            if re.match(r"^[a-z]+:", target) or target.startswith("#"):
                continue
            if not (path.parent / target).resolve().exists():
                problems.append(f"{path.name}:{n}: artifact link points at missing file {target}")
    return problems


def lint_html(path: Path) -> list[str]:
    problems = []
    text = path.read_text(encoding="utf-8")
    problems += lint_secrets(path.name, text)
    if re.search(r"<script\b", text, re.I):
        problems.append(f"{path.name}: contains <script>; the report must be static")
    if re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""", text, re.I):
        problems.append(f"{path.name}: references an external asset; the report must be self-contained")
    if re.search(r"""href\s*=\s*["']?\s*javascript:""", text, re.I):
        problems.append(f"{path.name}: javascript: link")
    plain = html.unescape(re.sub(r"<[^>]+>", " ", text))
    for n, line in enumerate(plain.splitlines(), 1):
        hits = _banned_hits(line)
        if hits and "VERIFIED-ABSENT" not in line:
            problems.append(f"{path.name}:{n}: banned phrase {hits!r} without VERIFIED-ABSENT evidence")
    return problems


def lint_entries(name: str, entries: list[dict], state_dir: Path | None) -> list[str]:
    problems = []
    for e in entries:
        eid = e.get("id", "<no id>")
        cls = e.get("evidence_class")
        if cls not in rglib.EVIDENCE_CLASSES:
            problems.append(f"{name}: {eid}: missing or invalid evidence class {cls!r}")
            continue
        if cls == "NOT-TESTED" and not e.get("not_tested_reason"):
            problems.append(f"{name}: {eid}: NOT-TESTED without a reason")
        evidence = e.get("evidence") or []
        if cls in rglib.ARTIFACT_REQUIRED and not evidence:
            problems.append(f"{name}: {eid}: {cls} without an artifact")
        if state_dir is not None:
            for ev in evidence:
                p = ev.get("path", "")
                if p and not (state_dir / p).exists():
                    problems.append(f"{name}: {eid}: evidence file missing: {p}")
        try:
            errs = rglib.validate(e, "finding")
        except SystemExit:
            errs = []
        problems += [f"{name}: {eid}: schema: {err}" for err in errs]
    return problems


def lint_json(path: Path, state_dir: Path | None) -> list[str]:
    text = path.read_text(encoding="utf-8")
    problems = lint_secrets(path.name, text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return problems + [f"{path.name}: not valid JSON: {exc}"]
    entries = data.get("entries", []) if isinstance(data, dict) else data
    problems += lint_entries(path.name, entries, state_dir)
    for row in (data.get("coverage", []) if isinstance(data, dict) else []):
        if row.get("evidence_class") in rglib.ARTIFACT_REQUIRED and not row.get("artifacts"):
            problems.append(f"{path.name}: coverage {row.get('id')}: {row['evidence_class']} without an artifact")
    return problems


def lint_paths(paths: list[Path], state_dir: Path | None = None) -> list[str]:
    problems: list[str] = []
    for p in paths:
        p = Path(p)
        if p.suffix == ".md":
            problems += lint_markdown(p)
        elif p.suffix == ".html":
            problems += lint_html(p)
        elif p.suffix == ".json":
            problems += lint_json(p, state_dir)
        else:  # .sarif and anything else: secrets only
            problems += lint_secrets(p.name, p.read_text(encoding="utf-8"))
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Lint release-gate reports")
    ap.add_argument("reports", nargs="+", type=Path)
    ap.add_argument("--state-dir", type=Path, help="the .release-gate directory (enables evidence-file existence checks)")
    args = ap.parse_args(argv)
    problems = lint_paths(args.reports, args.state_dir)
    for prob in problems:
        print(prob)
    print(f"{len(problems)} problem(s)" if problems else "report lint: clean")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
