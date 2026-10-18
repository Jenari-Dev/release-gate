#!/usr/bin/env python3
"""Merge duplicate findings reported by several scanners.

Usage:
  dedupe_findings.py --in findings.json --out deduped.json [--root /abs/project/dir]

Two kinds of duplicates are merged (only kind "finding" entries; kind "check"
entries pass through untouched and are never merged into a finding):

1. SCA duplicates: same package + same advisory. A finding is an SCA candidate
   when category == "sca", location.component is "name" or "name@version", and
   tool.rule_id carries at least one advisory id (CVE-, GHSA-, PYSEC-, GO-,
   RUSTSEC-; the normalizers write every alias there, comma separated). Two
   candidates merge when the package names match (lower-cased, runs of
   "-_." collapsed, so Jinja2 == jinja2) and their advisory id sets intersect;
   overlap is transitive, so osv-scanner (GHSA + CVE alias), npm audit (GHSA),
   pip-audit (PYSEC + aliases) and trivy (CVE + GHSA from references) land in
   one group. Versions are ignored.
   fingerprint = sha256("sca|<package>|<canonical advisory id>"), where the
   canonical id is the first of the group's ids ordered CVE, GHSA, others, each
   sorted.

2. Everything else: same location and issue. fingerprint =
   sha256("<category>|<normalized path>|<line // 3>|<cwe or rule>") where
     * normalized path: location.file with "\\" -> "/", a leading "./" or
       "file://" removed, and --root stripped when given; for findings with no
       file the URL path of location.endpoint (method dropped) is used;
     * line bucket: line // 3 (lines 9-11 share a bucket, 12-14 the next; two
       findings straddling a bucket edge do not merge), "-" if no line;
     * issue: the smallest CWE number, with CWE-259 and CWE-321 folded into
       CWE-798 (hard-coded credentials); if there is no CWE, the lower-cased
       tool.rule_id; if neither, the normalized title.
   A finding with neither a file nor an endpoint nor a component is never
   merged (its fingerprint includes its id), so location-less human findings
   are not collapsed together.

A merged entry is the "primary" member (strongest evidence class, then highest
severity, then lowest id) with: the highest severity of the group; the
strongest evidence class (EXPLOITED > TOOL-CONFIRMED > SUSPECTED); the union
of evidence (by type+path), CWEs and sources; `sources` = sorted tool names;
`fingerprint` set; the earliest created_at; and optional fields (location,
impact, fix, ...) filled from other members when the primary lacks them. The
ids of absorbed members are dropped from the output and listed on stderr.

Output order is deterministic: findings by (severity, id), then checks by id.
Exit status: 0 ok, 1 an output entry failed schema validation (nothing is
written), 2 usage / I/O error.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import rglib

CLASS_RANK = {"EXPLOITED": 0, "TOOL-CONFIRMED": 1, "SUSPECTED": 2}   # anything else ranks 3
CWE_FOLD = {"CWE-259": "CWE-798", "CWE-321": "CWE-798"}              # children of "hard-coded credentials"
ADVISORY_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b", re.I)


# --------------------------------------------------------------------------- keys

def natural_key(text: str) -> list[Any]:
    """Sort 'RG-SCA-2' before 'RG-SCA-10'."""
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", text)]


def sev_rank(entry: dict) -> int:
    return rglib.SEVERITY_RANK.get(entry.get("severity"), len(rglib.SEVERITIES))


def norm_path(path: str, root: str | None = None) -> str:
    p = path.replace("\\", "/")
    if p.startswith("file://"):
        p = p[7:]
    if root:
        r = root.replace("\\", "/").rstrip("/") + "/"
        if p.startswith(r):
            p = p[len(r):]
    while p.startswith("./"):
        p = p[2:]
    return str(PurePosixPath(p)) if p else ""


def endpoint_path(endpoint: str) -> str:
    """'GET http://h:3000/a/b?x=1' or 'GET /a/b' -> '/a/b'."""
    target = endpoint.split(None, 1)[-1] if " " in endpoint.strip() else endpoint
    return urlsplit(target).path or target


def norm_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def norm_advisory(adv: str) -> str:
    return "GHSA-" + adv[5:].lower() if adv.upper().startswith("GHSA") else adv.upper()


def advisory_ids(entry: dict) -> list[str]:
    rule_id = (entry.get("tool") or {}).get("rule_id") or ""
    out: list[str] = []
    for m in ADVISORY_RE.finditer(rule_id):
        adv = norm_advisory(m.group(0))
        if adv not in out:
            out.append(adv)
    return out


def canonical_advisory(ids: list[str]) -> str:
    """CVE first, then GHSA, then the rest; sorted within each class."""
    order = lambda a: (0 if a.startswith("CVE-") else 1 if a.startswith("GHSA-") else 2, a)  # noqa: E731
    return sorted(ids, key=order)[0]


def package_of(entry: dict) -> str | None:
    comp = (entry.get("location") or {}).get("component")
    if not comp:
        return None
    name = comp.rsplit("@", 1)[0] if "@" in comp[1:] else comp
    return norm_package(name) or None


def primary_issue(entry: dict) -> str:
    cwes = sorted((int(c[4:]) for c in entry.get("cwe") or [] if re.fullmatch(r"CWE-\d+", c)))
    if cwes:
        cwe = f"CWE-{cwes[0]}"
        return CWE_FOLD.get(cwe, cwe)
    rule = ((entry.get("tool") or {}).get("rule_id") or "").strip().lower()
    return rule or "title:" + " ".join(str(entry.get("title", "")).lower().split())


def fingerprint(entry: dict, root: str | None = None) -> str:
    loc = entry.get("location") or {}
    where = norm_path(loc["file"], root) if loc.get("file") else (endpoint_path(loc["endpoint"]) if loc.get("endpoint") else "")
    line = loc.get("line")
    bucket = str(line // 3) if isinstance(line, int) else "-"
    parts = [entry.get("category", ""), where, bucket, primary_issue(entry)]
    if not where and not loc.get("component"):
        parts.append("id:" + str(entry.get("id")))   # nothing to anchor a merge on
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def sca_fingerprint(pkg: str, ids: list[str]) -> str:
    return hashlib.sha256(f"sca|{pkg}|{canonical_advisory(ids)}".encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- grouping

def group_findings(findings: list[dict], root: str | None) -> list[tuple[str, list[dict], list[str] | None]]:
    """Return (fingerprint, members, sca_ids) groups; sca_ids is None for non-SCA groups."""
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[tuple[str, str], int] = {}
    sca_info: dict[int, tuple[str, list[str]]] = {}
    for i, f in enumerate(findings):
        pkg, ids = package_of(f), advisory_ids(f)
        if f.get("category") == "sca" and pkg and ids:
            sca_info[i] = (pkg, ids)
            for adv in ids:
                j = seen.setdefault((pkg, adv), i)
                parent[find(i)] = find(j)

    clusters: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        if i in sca_info:
            key = f"sca-cluster:{find(i)}"
        else:
            key = fingerprint(f, root)
        clusters.setdefault(key, []).append(i)

    groups = []
    for key, idxs in clusters.items():
        members = [findings[i] for i in idxs]
        if idxs[0] in sca_info:
            pkg = sca_info[idxs[0]][0]
            ids = sorted({a for i in idxs for a in sca_info[i][1]})
            groups.append((sca_fingerprint(pkg, ids), members, ids))
        else:
            groups.append((key, members, None))
    return groups


def primary_sort_key(entry: dict) -> tuple:
    return (CLASS_RANK.get(entry.get("evidence_class"), 3), sev_rank(entry), natural_key(str(entry.get("id", ""))))


def merge_group(fp: str, members: list[dict], sca_ids: list[str] | None) -> dict:
    ordered = sorted(members, key=primary_sort_key)
    merged = copy.deepcopy(ordered[0])
    best_sev = min((m for m in members if m.get("severity")), key=sev_rank, default=None)
    if best_sev:
        merged["severity"] = best_sev["severity"]
    merged["evidence_class"] = ordered[0]["evidence_class"]   # strongest, by construction

    evidence: list[dict] = []
    seen_ev: set[tuple[str, str]] = set()
    for m in ordered:
        for ev in m.get("evidence") or []:
            k = (ev.get("type", ""), ev.get("path", ""))
            if k not in seen_ev:
                seen_ev.add(k)
                evidence.append(copy.deepcopy(ev))
    merged["evidence"] = evidence

    cwes = sorted({c for m in members for c in m.get("cwe") or []}, key=natural_key)
    if cwes:
        merged["cwe"] = cwes
    sources = sorted({s for m in members for s in [(m.get("tool") or {}).get("name"), *(m.get("sources") or [])] if s})
    if sources:
        merged["sources"] = sources
    stamps = [m["created_at"] for m in members if m.get("created_at")]
    if stamps:
        merged["created_at"] = min(stamps)
    for m in ordered[1:]:   # fill gaps from the other members
        for key, value in m.items():
            if key not in merged and key not in ("sources", "fingerprint"):
                merged[key] = copy.deepcopy(value)
    if sca_ids:
        merged.setdefault("tool", {})["rule_id"] = ", ".join(sorted(sca_ids, key=lambda a: (0 if a.startswith("CVE-") else 1 if a.startswith("GHSA-") else 2, a)))
    merged["fingerprint"] = fp
    return merged


def dedupe(entries: list[dict], root: str | None = None) -> tuple[list[dict], list[str]]:
    """Return (deduped entries, merge log lines)."""
    findings = [e for e in entries if e.get("kind") == "finding"]
    checks = [e for e in entries if e.get("kind") != "finding"]
    merged_findings: list[dict] = []
    log: list[str] = []
    for fp, members, sca_ids in group_findings(findings, root):
        merged = merge_group(fp, members, sca_ids)
        merged_findings.append(merged)
        if len(members) > 1:
            gone = sorted((str(m.get("id")) for m in members if m.get("id") != merged.get("id")), key=natural_key)
            log.append(f"{', '.join(gone)} merged into {merged.get('id')} (sources: {', '.join(merged.get('sources', []))})")
    merged_findings.sort(key=lambda e: (sev_rank(e), natural_key(str(e.get("id", "")))))
    checks.sort(key=lambda e: natural_key(str(e.get("id", ""))))
    return merged_findings + checks, sorted(log)


# --------------------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Deduplicate release-gate findings across tools.")
    ap.add_argument("--in", dest="inp", required=True, help="findings file (list of entries)")
    ap.add_argument("--out", required=True, help="deduplicated output file")
    ap.add_argument("--root", help="project root to strip from absolute file paths before fingerprinting")
    args = ap.parse_args(argv)

    try:
        entries = rglib.load_data(args.inp)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read {args.inp}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        print(f"error: {args.inp} must contain a list of finding/check objects", file=sys.stderr)
        return 2

    out, log = dedupe(entries, args.root)
    failures = 0
    for e in out:
        for err in rglib.validate(e, "finding"):
            failures += 1
            print(f"schema error in {e.get('id')}: {err}", file=sys.stderr)
    if failures:
        print(f"error: {failures} schema error(s); nothing written", file=sys.stderr)
        return 1
    for line in log:
        print(line, file=sys.stderr)
    rglib.dump_data(Path(args.out), out)
    print(f"{len(entries)} entries in, {len(out)} out ({len(entries) - len(out)} merged) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
