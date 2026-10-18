#!/usr/bin/env python3
"""Retest bookkeeping for release-gate: decide what to re-run and what may be called fixed.

    retest.py plan  --project P [--prev FILE]
    retest.py apply --project P --new NEW.json [--prev FILE] [--out FILE] [--dry-run]

`plan` prints the findings that a retest has to re-run (JSON).
`apply` merges the results of that re-run into findings.json.

The one rule this module exists to enforce: a finding becomes `fixed` only when
the original reproduction was re-executed and no longer reproduces, with new
evidence on disk. Reading a diff is never enough, a missing or NOT-TESTED result
never closes anything, and a SUSPECTED finding (never reproduced) can't be
closed by a retest at all.

Stdlib + rglib only. Never touches the network and never runs project code.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

import rglib

# Findings in these statuses are not part of a retest and are never modified.
SKIP_STATUSES = frozenset({"fixed", "false-positive", "waived"})
# Evidence classes a retest re-runs.
RETEST_CLASSES = frozenset({"EXPLOITED", "TOOL-CONFIRMED", "SUSPECTED"})
# New results in these classes mean the issue was seen again.
REPRODUCED_CLASSES = frozenset({"EXPLOITED", "TOOL-CONFIRMED"})
# Evidence types that show something was executed. A code reference is
# reading, so on its own it can't prove a fix.
EXECUTED_EVIDENCE_TYPES = frozenset({
    "tool-output", "repro-script", "request-response", "har", "screenshot", "log", "test-output", "other",
})
# New entries with these statuses are ignored when looking for a reproduction.
NEW_IGNORED_STATUSES = frozenset({"fixed", "false-positive"})


# --------------------------------------------------------------------------- loading

def entries_from(data: Any) -> list[dict]:
    """findings.json is either a list or {"entries": [...]}."""
    if data is None:
        return []
    if isinstance(data, dict):
        return list(data.get("entries", []))
    return list(data)


def _status(entry: dict) -> str:
    return entry.get("status", "open")


# --------------------------------------------------------------------------- plan

def _evidence_paths(entry: dict) -> list[str]:
    return [e.get("path", "") for e in entry.get("evidence") or [] if e.get("path")]


def plan(prev_entries: list[dict]) -> list[dict]:
    """Findings a retest must re-run, in the order they appear."""
    items = []
    for e in prev_entries:
        if e.get("kind") != "finding":
            continue
        if _status(e) in SKIP_STATUSES:
            continue
        cls = e.get("evidence_class")
        if cls not in RETEST_CLASSES:
            continue
        can_close = cls in REPRODUCED_CLASSES
        if cls == "EXPLOITED":
            action = "re-run the original repro against the in-scope instance"
        elif cls == "TOOL-CONFIRMED":
            action = "re-run the same tool with the same scope, then re-read the code path"
        else:
            action = ("re-check the code path; a retest can't close a SUSPECTED finding "
                      "(it was never reproduced), so write a repro first if you want it closed")
        items.append({
            "id": e["id"],
            "check_id": e.get("check_id"),
            "title": e.get("title"),
            "severity": e.get("severity"),
            "evidence_class": cls,
            "status": _status(e),
            "location": copy.deepcopy(e.get("location")),
            "repro": e.get("repro"),
            "previous_evidence": _evidence_paths(e),
            "can_close": can_close,
            "action": action,
        })
    return items


# --------------------------------------------------------------------------- matching

def _norm_loc_value(key: str, value: Any) -> str:
    text = " ".join(str(value).split())
    if key == "endpoint":
        return text.upper()
    if key == "file":
        text = text.replace("\\", "/")
        return text[2:] if text.startswith("./") else text
    return text


def _loc_compatible(prev: dict | None, new: dict | None) -> bool:
    """Two locations conflict only when they both name the same kind of place and differ.

    Line numbers are ignored on purpose: they drift between runs. A missing
    location on either side means "whole check", which is compatible.
    """
    if not prev or not new:
        return True
    for key in ("endpoint", "file", "component"):
        if prev.get(key) and new.get(key):
            if _norm_loc_value(key, prev[key]) != _norm_loc_value(key, new[key]):
                return False
    return True


def _matches(prev: dict, new: dict) -> bool:
    p_chk, n_chk = prev.get("check_id"), new.get("check_id")
    if p_chk and n_chk and p_chk != n_chk:
        return False                      # a reused id for a different check is not the same finding
    if not _loc_compatible(prev.get("location"), new.get("location")):
        return False
    if prev.get("id") == new.get("id"):
        return True
    if prev.get("fingerprint") and prev.get("fingerprint") == new.get("fingerprint"):
        return True
    return bool(p_chk and n_chk and p_chk == n_chk)


# --------------------------------------------------------------------------- evidence rules

def _evidence_problem(prev: dict, new: dict, state_dir: Path | None) -> str | None:
    """Why a VERIFIED-ABSENT result can't support closing `prev`, or None if it can."""
    ev = new.get("evidence") or []
    if not ev:
        return "the VERIFIED-ABSENT result carries no evidence"
    if not any(e.get("type") in EXECUTED_EVIDENCE_TYPES for e in ev):
        return "the only evidence is a code reference; reading code does not show the repro was re-run"
    prev_paths = set(_evidence_paths(prev))
    new_paths = [p for p in _evidence_paths(new) if p]
    if not new_paths:
        return "the VERIFIED-ABSENT result has evidence entries without paths"
    if all(p in prev_paths for p in new_paths):
        return "the evidence is the same artifact(s) as the original finding, not a new run"
    if state_dir is not None:
        missing = [p for p in new_paths if not (state_dir / p).exists()]
        if missing:
            return f"evidence file(s) not found under .release-gate/: {', '.join(missing[:3])}"
    return None


def _merge_evidence(target: dict, new: dict) -> None:
    have = {e.get("path") for e in target.get("evidence") or []}
    for item in new.get("evidence") or []:
        if item.get("path") and item["path"] not in have:
            target.setdefault("evidence", []).append(copy.deepcopy(item))
            have.add(item["path"])


# --------------------------------------------------------------------------- apply

def _outcome(prev: dict, updated: dict, retest_status: str, reason: str, matched: list[dict]) -> dict:
    return {
        "id": prev["id"],
        "check_id": prev.get("check_id"),
        "previous_evidence_class": prev.get("evidence_class"),
        "previous_status": _status(prev),
        "status": _status(updated),
        "retest": retest_status,
        "reason": reason,
        "matched_new_ids": [m.get("id") for m in matched],
    }


def apply_detailed(prev_entries: list[dict], new_entries: list[dict], *, state_dir: Path | None = None,
                   now: str | None = None) -> tuple[list[dict], list[dict]]:
    """Return (updated entries, per-finding outcomes). Inputs are not modified."""
    run_at = now or rglib.now_iso()
    planned_ids = {p["id"] for p in plan(prev_entries)}
    consumed: set[int] = set()
    outcomes: list[dict] = []
    result: list[dict] = []

    for prev in prev_entries:
        entry = copy.deepcopy(prev)
        if prev.get("id") not in planned_ids or prev.get("kind") != "finding":
            result.append(entry)
            continue

        matched = []
        for idx, new in enumerate(new_entries):
            if new.get("status") in NEW_IGNORED_STATUSES and new.get("kind") == "finding":
                continue
            if _matches(prev, new):
                matched.append(new)
                consumed.add(idx)

        reproduced = [m for m in matched if m.get("evidence_class") in REPRODUCED_CLASSES]
        absent = [m for m in matched if m.get("evidence_class") == "VERIFIED-ABSENT"]
        retest: dict[str, Any] = {"status": "not-run", "run_at": run_at}

        if reproduced:
            # Fail closed: any reproduction wins over any absence claim for the same check.
            entry["status"] = "open"
            retest["status"] = "still-reproduces"
            ev = _evidence_paths(reproduced[0])
            if ev:
                retest["evidence_path"] = ev[0]
            for m in reproduced:
                _merge_evidence(entry, m)
            reason = "re-run reproduced the issue"
        elif absent:
            problems = [_evidence_problem(prev, m, state_dir) for m in absent]
            usable = [m for m, prob in zip(absent, problems) if prob is None]
            if not usable:
                reason = "VERIFIED-ABSENT result not accepted: " + problems[0]
            elif prev.get("evidence_class") == "SUSPECTED":
                ev = _evidence_paths(usable[0])
                if ev:
                    retest["evidence_path"] = ev[0]
                _merge_evidence(entry, usable[0])
                reason = ("the finding was never reproduced (SUSPECTED), so a clean re-run can't close it; "
                          "left open. Write a repro, or have a human decide to mark it false-positive")
            else:
                entry["status"] = "fixed"
                retest["status"] = "no-longer-reproduces"
                retest["evidence_path"] = _evidence_paths(usable[0])[0]
                _merge_evidence(entry, usable[0])
                reason = "original check re-run; VERIFIED-ABSENT with new evidence"
        elif matched:
            kinds = sorted({m.get("evidence_class", "?") for m in matched})
            reason = f"re-run produced no usable result ({', '.join(kinds)}); status unchanged"
        else:
            reason = "no matching result in the re-run; status unchanged"

        entry["retest"] = retest
        outcomes.append(_outcome(prev, entry, retest["status"], reason, matched))
        result.append(entry)

    # New findings that matched nothing: surface them, with ids that can't collide.
    used_ids = {e["id"] for e in result}
    for idx, new in enumerate(new_entries):
        if idx in consumed or new.get("kind") != "finding":
            continue
        added = copy.deepcopy(new)
        if added["id"] in used_ids:
            added["id"] = rglib.next_id(added.get("category", "other"), used_ids)
        used_ids.add(added["id"])
        result.append(added)
        outcomes.append({"id": added["id"], "check_id": added.get("check_id"), "previous_evidence_class": None,
                         "previous_status": None, "status": _status(added), "retest": "new-finding",
                         "reason": "found during the re-run; not in the previous findings", "matched_new_ids": []})
    return result, outcomes


def apply(prev_entries: list[dict], new_entries: list[dict], *, state_dir: Path | None = None,
          now: str | None = None) -> list[dict]:
    """Merge re-run results into the previous entries. See module docstring for the rules."""
    return apply_detailed(prev_entries, new_entries, state_dir=state_dir, now=now)[0]


# --------------------------------------------------------------------------- CLI

def _load_entries(path: Path) -> tuple[list[dict], bool]:
    data = rglib.load_data(path)
    return entries_from(data), isinstance(data, dict)


def _prev_path(args: argparse.Namespace) -> Path:
    return args.prev or (rglib.state_dir(args.project, create=False) / "findings.json")


def cmd_plan(args: argparse.Namespace) -> int:
    path = _prev_path(args)
    if not path.exists():
        print(f"retest: no previous findings at {path}; nothing to retest "
              "(history/ holds run summaries only, not enough to re-run a check)", file=sys.stderr)
        return 2
    prev, _ = _load_entries(path)
    items = plan(prev)
    print(rglib.redact_text(json.dumps({"count": len(items), "items": items}, indent=2)))
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    path = _prev_path(args)
    if not path.exists():
        print(f"retest: no previous findings at {path}", file=sys.stderr)
        return 2
    if not args.new.exists():
        print(f"retest: new results file not found: {args.new}", file=sys.stderr)
        return 2
    prev, wrapped = _load_entries(path)
    new, _ = _load_entries(args.new)
    sd = rglib.state_dir(args.project, create=False)
    updated, outcomes = apply_detailed(prev, new, state_dir=sd)

    errors = []
    for e in updated:
        for msg in rglib.validate(e, "finding"):
            errors.append(f"{e.get('id', '?')}: {msg}")
    if errors:
        print("retest: updated findings do not validate; nothing written:", file=sys.stderr)
        for line in errors[:20]:
            print(f"  {line}", file=sys.stderr)
        return 3

    summary = {"fixed": 0, "still-reproduces": 0, "not-run": 0, "new-finding": 0, "no-longer-reproduces": 0}
    for o in outcomes:
        summary[o["retest"]] = summary.get(o["retest"], 0) + 1
    if not args.dry_run:
        out = args.out or path
        if out == path:
            rglib.dump_data(path.with_name("findings.pre-retest.json"), {"entries": prev} if wrapped else prev)
        rglib.dump_data(out, {"entries": updated} if wrapped else updated)
        stamp_dir = sd / "evidence" / f"retest-{rglib.stamp()}"
        rglib.dump_data(stamp_dir / "outcomes.json", {"run_at": rglib.now_iso(), "outcomes": outcomes})
    print(rglib.redact_text(json.dumps({"summary": summary, "outcomes": outcomes}, indent=2)))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan", help="print the findings a retest must re-run")
    p.add_argument("--project", type=Path, required=True)
    p.add_argument("--prev", type=Path, help="previous findings file (default: .release-gate/findings.json)")
    p.set_defaults(func=cmd_plan)
    a = sub.add_parser("apply", help="merge re-run results into findings.json")
    a.add_argument("--project", type=Path, required=True)
    a.add_argument("--new", type=Path, required=True, help="entries produced by the re-run")
    a.add_argument("--prev", type=Path, help="previous findings file (default: .release-gate/findings.json)")
    a.add_argument("--out", type=Path, help="write here instead of replacing findings.json")
    a.add_argument("--dry-run", action="store_true", help="validate and print outcomes, write nothing")
    a.set_defaults(func=cmd_apply)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
