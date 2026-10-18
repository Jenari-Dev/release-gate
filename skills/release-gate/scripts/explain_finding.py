#!/usr/bin/env python3
"""Explain one release-gate finding in plain language.

    explain_finding.py --project P [--findings FILE ...] <finding-id>

Reads the recorded entry and prints markdown. It only restates what the entry
says: it never changes an evidence class, a severity or a status, and it never
runs a test. Secrets are redacted on the way out (rglib.redact_text).

Exit codes: 0 ok, 2 unknown id / no findings file.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import rglib

CLASS_MEANING = {
    "EXPLOITED": (
        "Someone (this run) reproduced the problem against a running instance and saved the request and "
        "response. It is the strongest class: it happened, it was not just predicted.",
        "Nothing stronger exists. What changes it is a fix plus a retest that re-runs the same repro and no "
        "longer reproduces it.",
    ),
    "TOOL-CONFIRMED": (
        "A deterministic tool reported it, and the code path was read and judged real. It was not reproduced "
        "against a running instance.",
        "To reach EXPLOITED: reproduce it against an in-scope instance and save the repro script and the "
        "captured request/response. To drop it: show the tool hit is a false positive, with the reason.",
    ),
    "SUSPECTED": (
        "It comes from reading code or from judgment. It was not reproduced and no tool confirmed it, so "
        "treat it as a lead, not a fact.",
        "To reach TOOL-CONFIRMED: back it with tool output and verify the code path. To reach EXPLOITED: "
        "reproduce it. To drop it: show it is a false positive, with the reason. A retest alone can't mark it "
        "fixed, because there is no repro to re-run.",
    ),
    "VERIFIED-ABSENT": (
        "A specific test ran and the issue did not occur. It speaks only for that test, with its rules and "
        "scope, not for the whole category.",
        "A broader or different test that finds the issue, or an adversarial review that refutes the pass, "
        "would replace it.",
    ),
    "NOT-TESTED": (
        "The check was not performed, so there is no result either way.",
        "Running the check (or removing the blocker named in the reason) would turn this into a real result.",
    ),
}

VERDICT_RULES = {
    "critical": "An open critical finding blocks release unless a waiver is active.",
    "high": "An open high finding blocks release unless a waiver is active.",
    "medium": "An open medium finding caps the verdict at SHIP WITH ACCEPTED RISKS.",
    "low": "Low findings are reported but do not move the verdict.",
    "info": "Info findings are reported but do not move the verdict.",
}

EXTRA_FILES = ("authz_findings.json", "policy_findings.json")


# --------------------------------------------------------------------------- loading

def _entries_from(data: Any) -> list[dict]:
    if data is None:
        return []
    if isinstance(data, dict):
        return list(data.get("entries", []))
    return list(data)


def load_entries(project: Path, extra: list[Path] | None = None) -> list[dict]:
    sd = rglib.state_dir(project, create=False)
    entries = _entries_from(rglib.load_data(sd / "findings.json"))
    for name in EXTRA_FILES:
        entries += _entries_from(rglib.load_data(sd / name))
    for p in extra or []:
        entries += _entries_from(rglib.load_data(p))
    return entries


def find_entry(entries: list[dict], finding_id: str) -> dict | None:
    for e in entries:
        if e.get("id") == finding_id:
            return e
    return None


# --------------------------------------------------------------------------- rendering

def _location(loc: dict | None) -> str:
    if not loc:
        return "not recorded"
    parts = []
    if loc.get("endpoint"):
        parts.append(f"`{loc['endpoint']}`")
    if loc.get("file"):
        line = f":{loc['line']}" if loc.get("line") is not None else ""
        parts.append(f"`{loc['file']}{line}`")
    if loc.get("component"):
        parts.append(f"component `{loc['component']}`")
    return ", ".join(parts) or "not recorded"


def _attacker_section(e: dict) -> list[str]:
    if e.get("kind") == "check":
        return ["## What this check covers", e.get("title", ""), ""]
    impact = (e.get("impact") or "").strip()
    out = ["## What an attacker could do"]
    out.append(impact if impact else "The entry has no impact text recorded. Read the location and the evidence "
                                     "below, and treat the impact as not yet assessed.")
    out.append("")
    return out


def _class_section(e: dict) -> list[str]:
    cls = e.get("evidence_class", "?")
    meaning, change = CLASS_MEANING.get(cls, ("Unknown evidence class.", "Fix the entry so it carries exactly one class."))
    out = [f"## Why the evidence class is {cls}", meaning]
    if cls == "NOT-TESTED":
        out.append(f"Reason recorded: {e.get('not_tested_reason') or 'none recorded (this entry is invalid without one)'}")
    if cls == "TOOL-CONFIRMED":
        v = e.get("verification") or {}
        if v.get("code_ref"):
            out.append(f"Code path read to confirm it: `{v['code_ref']}`.")
    if cls == "SUSPECTED":
        v = e.get("verification") or {}
        if v.get("reason"):
            out.append(f"Recorded reason it was not reproduced: {v['reason']}")
    tool = e.get("tool") or {}
    if tool.get("name"):
        bits = [tool["name"] + (f" {tool['version']}" if tool.get("version") else "")]
        if tool.get("rule_id"):
            bits.append(f"rule `{tool['rule_id']}`")
        if tool.get("scope"):
            bits.append(f"scope: {tool['scope']}")
        out.append("Reported by " + ", ".join(bits) + ".")
    out.append("")
    out.append(f"What would change it: {change}")
    out.append("")
    return out


def _repro_section(e: dict) -> list[str]:
    cls = e.get("evidence_class")
    out = ["## How to reproduce it"]
    repro = (e.get("repro") or "").strip()
    if repro:
        out.append(repro)
    else:
        out.append("No reproduction steps are recorded on this entry.")
    if cls == "SUSPECTED":
        out.append("")
        out.append("This was not reproduced during the run; the steps above (if any) are what to try, against a "
                   "local instance you started yourself.")
    elif cls == "EXPLOITED":
        out.append("")
        out.append("Run these only against a target listed in `.release-gate/scope.yaml`; the saved request and "
                   "response under Evidence show what happened the first time.")
    out.append("")
    return out


def _fix_section(e: dict) -> list[str]:
    fix = (e.get("fix") or "").strip()
    out = ["## How to fix it", fix if fix else "No fix is recorded on this entry.", ""]
    if e.get("kind") == "finding":
        out.append("After changing the code, run `/release-gate retest`. A finding is only marked fixed when its "
                   "original repro was re-run and no longer reproduces; the diff alone doesn't count.")
        out.append("")
    return out


def _adversarial_section(e: dict) -> list[str]:
    adv = e.get("adversarial")
    if not adv:
        return []
    out = ["## Independent check (adversarial verification)"]
    out.append(f"Required: {'yes' if adv.get('required') else 'no'}. Outcome: {adv.get('outcome', 'not-run')}.")
    if adv.get("summary"):
        out.append(adv["summary"])
    if adv.get("action_taken"):
        out.append(f"Action taken: {adv['action_taken']}")
    if adv.get("required") and adv.get("outcome") in (None, "not-run", "inconclusive"):
        out.append("It is not upheld yet, so it can't support a SHIP verdict.")
    out.append("")
    return out


def _retest_section(e: dict, state_dir: Path | None) -> list[str]:
    rt = e.get("retest")
    if not rt:
        return []
    out = ["## Last retest", f"Result: {rt.get('status', 'not-run')}" + (f" at {rt['run_at']}" if rt.get("run_at") else "") + "."]
    if rt.get("evidence_path"):
        out.append(f"Evidence: `{rt['evidence_path']}`" + _presence(rt["evidence_path"], state_dir))
    out.append("")
    return out


def _presence(path: str, state_dir: Path | None) -> str:
    if state_dir is None:
        return ""
    return " (file present)" if (state_dir / path).exists() else " (file NOT found under .release-gate/)"


def _evidence_section(e: dict, state_dir: Path | None) -> list[str]:
    ev = e.get("evidence") or []
    out = ["## Evidence"]
    if not ev:
        out.append("No evidence artifacts are attached.")
    for item in ev:
        desc = f": {item['description']}" if item.get("description") else ""
        out.append(f"- {item.get('type', 'other')}: `{item.get('path', '?')}`{desc}{_presence(item.get('path', ''), state_dir)}")
    out.append("")
    return out


def _verdict_section(e: dict) -> list[str]:
    out = ["## What would change the verdict"]
    status = e.get("status", "open")
    sev, cls = e.get("severity"), e.get("evidence_class")
    if e.get("kind") == "check":
        if cls == "VERIFIED-ABSENT":
            out.append("This is a pass. It counts toward SHIP only if the check is non-critical or its adversarial "
                       "verification is upheld; a critical pass that is not upheld caps the verdict.")
        elif cls == "NOT-TESTED":
            out.append("An applicable critical check that is NOT-TESTED caps the verdict. Enough of them "
                       "NOT-TESTED in a full run blocks it, because the gate fails closed when it could not look.")
        else:
            out.append("Resolve the finding(s) this check produced; a critical check needs a VERIFIED-ABSENT "
                       "result that survives adversarial verification.")
        out.append("")
        return out
    if status in ("fixed", "false-positive"):
        out.append(f"Status is {status}, so it does not count as open. Re-opening happens if a later run "
                   "finds it again.")
    elif status == "waived":
        out.append("It is waived. A waiver changes how the verdict treats the finding until it expires; it doesn't "
                   "make the issue go away.")
        if cls == "EXPLOITED" and sev in ("critical", "high"):
            out.append("An EXPLOITED critical or high finding blocks even when waived.")
    else:
        out.append(VERDICT_RULES.get(sev, "Severity is not recorded, which makes the entry invalid."))
        if cls == "EXPLOITED" and sev in ("critical", "high"):
            out.append("It was reproduced, so a waiver does not lift the block. Fixing it and passing a retest does.")
        out.append("To close it: fix it, then run a retest that re-executes the original repro and records new "
                   "evidence that it no longer reproduces.")
        if cls == "SUSPECTED":
            out.append("Or show it is a false positive, with the reason recorded; the class is not changed here.")
    out.append("")
    return out


def render(entry: dict, state_dir: Path | None = None) -> str:
    lines = [f"# {entry.get('id', '?')}: {entry.get('title', '(untitled)')}", ""]
    meta = [
        ("Kind", entry.get("kind")),
        ("Severity", entry.get("severity")),
        ("Status", entry.get("status", "open") if entry.get("kind") == "finding" else None),
        ("Evidence class", entry.get("evidence_class")),
        ("Check", entry.get("check_id")),
        ("Category", entry.get("category")),
        ("Location", _location(entry.get("location"))),
        ("CWE", ", ".join(entry.get("cwe") or []) or None),
    ]
    lines += [f"- {k}: {v}" for k, v in meta if v]
    lines.append("")
    lines += _attacker_section(entry)
    lines += _class_section(entry)
    lines += _repro_section(entry)
    lines += _fix_section(entry)
    lines += _adversarial_section(entry)
    lines += _retest_section(entry, state_dir)
    lines += _evidence_section(entry, state_dir)
    lines += _verdict_section(entry)
    lines.append("This is an automated aid, not a penetration test or legal advice. You decide what ships.")
    return rglib.redact_text("\n".join(lines).rstrip() + "\n")


# --------------------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Explain one release-gate finding in plain language")
    ap.add_argument("--project", type=Path, required=True)
    ap.add_argument("--findings", type=Path, action="append", default=[], help="extra findings files")
    ap.add_argument("finding_id")
    args = ap.parse_args(argv)

    entries = load_entries(args.project, args.findings)
    entry = find_entry(entries, args.finding_id)
    if entry is None:
        known = ", ".join(sorted(e["id"] for e in entries if e.get("kind") == "finding" and "id" in e)[:15])
        hint = f" Known finding ids: {known}" if known else " No findings are recorded for this project."
        print(f"explain: no entry with id {args.finding_id!r} in the recorded findings.{hint}", file=sys.stderr)
        return 2
    print(render(entry, rglib.state_dir(args.project, create=False)), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
