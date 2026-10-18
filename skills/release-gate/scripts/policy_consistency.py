#!/usr/bin/env python3
"""Check a privacy policy's factual claims against the data inventory (phase 8).

A privacy statement that the code contradicts is not a wording nit: in many
jurisdictions a false privacy claim is a deceptive-practice risk. This tool
reads one or more policy documents (plain text or HTML) and the inventory, then
flags each *denial* claim the inventory contradicts. It keys on the claim text,
not just the inventory, so a truthful policy that discloses analytics does not
get flagged while a policy that swears it shares nothing does.

Findings are `TOOL-CONFIRMED` policy-mismatch (High): the claim's file:line and
the contradicting inventory refs are the evidence. A running confirmation (an
analytics beacon actually observed, a deleted account that still logs in) is a
separate phase-3/7 step that upgrades the matching mismatch to EXPLOITED.

Stdlib only; HTML tags are stripped naively (no network, no parser dep).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rglib  # noqa: E402

TAG_RE = re.compile(r"<[^>]+>")
LOCAL_RE = re.compile(r"^(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|::1)")

# Each rule: a denial-claim pattern, and a predicate over the inventory that,
# when true, makes that claim false. (claim_id, pattern, predicate, why)
NO_SHARE = re.compile(r"\b(never|do not|don't|will not|won't|no)\b[^.]{0,40}\b(share|sell|disclose|transfer|send)\b"
                      r"[^.]{0,60}\b(third part|partner|advertis|analytic|vendor|external)", re.I)
NO_SHARE2 = re.compile(r"\bno\b[^.]{0,20}\b(third part(y|ies))\b", re.I)
NO_TRACK = re.compile(r"\b(do not|don't|no|never)\b[^.]{0,40}\b(track|tracker|analytics|advertis|cookies?)\b", re.I)
NO_COLLECT = re.compile(r"\b(do not|don't|no|never)\b[^.]{0,30}\b(collect|gather|store)\b[^.]{0,40}\b(information|data|personal)", re.I)
DELETE_CLAIM = re.compile(r"\b(permanently (erase|delete)|delete[sd]?|erase[sd]?|remov(e|ed|al))\b[^.]{0,60}"
                          r"\b(all|your|account|personal|data)\b", re.I)
ENCRYPT_CLAIM = re.compile(r"\b(encrypt(ed|ion)?)\b[^.]{0,40}\b(at rest|stored|data|database)\b", re.I)


# A denial that is conditioned on consent ("only after you accept", "with your
# consent", "unless you opt in") is not a blanket denial and must not be flagged.
CONDITIONAL_RE = re.compile(r"\b(after|unless|if|once|when|with your|upon|only)\b[^.]{0,40}"
                            r"\b(accept|consent|opt[\s-]?in|agree|allow|choose|reject|decline)\b", re.I)


def strip_html(text: str) -> str:
    return TAG_RE.sub(" ", text)


def _sentence_around(text: str, start: int) -> str:
    left = text.rfind(".", 0, start)
    right = text.find(".", start)
    return text[(left + 1 if left >= 0 else 0):(right if right >= 0 else len(text))]


TELEMETRY_PURPOSE_RE = re.compile(r"(analytic|telemetr|track|beacon|advertis|metrics)", re.I)


def external_third_parties(inv: dict) -> list[dict]:
    """Third parties the app PROACTIVELY sends data to (telemetry/analytics).

    A user-supplied URL the app merely fetches (a preview/SSRF feature, recorded
    as <dynamic-egress> with no telemetry purpose) is NOT data sharing, so it
    must not flag a truthful "we don't share" policy. We count a destination
    only when it is marked as telemetry egress or is a known analytics vendor —
    which is what distinguishes the vulnerable fixture from its clean twin."""
    out = []
    for t in inv.get("third_parties", []):
        if t.get("role") == "first-party" or t.get("set_by") == "first-party":
            continue
        purpose = str(t.get("purpose", ""))
        if t.get("role") == "subprocessor" or TELEMETRY_PURPOSE_RE.search(purpose):
            out.append(t)
    return out


def analytics_storage(inv: dict) -> list[dict]:
    return [c for c in inv.get("client_storage", [])
            if c.get("necessity") in ("analytics", "advertising") or c.get("set_by") == "third-party"
            or str(c.get("name", "")).lower().startswith(("_trk", "_ga", "_fbp", "amplitude", "mp_"))]


def check_claims(policy_text: str, policy_ref: str, inv: dict) -> list[dict]:
    text = strip_html(policy_text)
    lines = text.splitlines()
    findings: list[dict] = []
    tps = external_third_parties(inv)
    tp_refs = sorted({r for t in tps for r in t.get("provenance", {}).get("refs", [])})[:4]
    has_deletion = bool((inv.get("rights") or {}).get("deletion"))
    unencrypted = [s for s in inv.get("stores", []) if s.get("encrypted_at_rest") in ("no", "unknown")] \
        + [f for f in inv.get("fields", []) if f.get("encrypted_at_rest") == "no"]

    def line_no(m_text: str) -> int:
        for i, ln in enumerate(lines, 1):
            if m_text[:30].strip() and m_text[:30].strip().lower() in ln.lower():
                return i
        return 1

    def conditional(claim_m) -> bool:
        return bool(CONDITIONAL_RE.search(_sentence_around(text, claim_m.start())))

    def emit(cid, severity, title, impact, claim_m, why, extra_refs, evidence_class="TOOL-CONFIRMED"):
        ln = line_no(claim_m.group(0))
        entry = {
            "id": f"RG-POLICYMISMATCH-{len(findings) + 1:03d}",
            "kind": "finding", "check_id": "LEGAL-POLICY-CONSISTENCY",
            "title": title, "category": "policy-mismatch", "severity": severity, "phase": 8,
            "evidence_class": evidence_class,
            "location": {"file": policy_ref, "line": ln},
            "impact": impact,
            "repro": f"Policy ({policy_ref}:{ln}) states: \"{claim_m.group(0).strip()[:160]}\". {why}",
            "fix": "Either change the code so the claim is true, or change the policy to describe what the code does.",
            "tool": {"name": "policy_consistency", "scope": policy_ref},
            "created_at": rglib.now_iso(),
        }
        if evidence_class == "TOOL-CONFIRMED":
            entry["evidence"] = [{"type": "code-ref", "path": policy_ref,
                                  "description": f"policy claim at line {ln}: {claim_m.group(0).strip()[:120]}"}]
            entry["verification"] = {"verdict": "confirmed",
                                     "reason": f"contradicted by inventory: {', '.join(extra_refs) if extra_refs else why}"}
        else:  # SUSPECTED: needs a runtime check (cookie audit / deletion test) to confirm or refute
            entry["evidence"] = []
        findings.append(entry)

    for m in list(NO_SHARE.finditer(text)) + list(NO_SHARE2.finditer(text)):
        if tps and not conditional(m):
            emit("no-share", "high",
                 "Privacy policy claims no data sharing, but the code sends data to a third party",
                 "A user reading the policy would believe their data stays on your servers; it does not.",
                 m, f"the inventory records {len(tps)} outbound third-party destination(s) "
                    f"({', '.join(sorted(str(t['host']) for t in tps))}).", tp_refs)
            break
    for m in NO_TRACK.finditer(text):
        trackers = analytics_storage(inv) or tps  # tps already restricted to telemetry destinations
        if trackers and not conditional(m):
            # trackers exist in code, but whether they fire before consent is a runtime question
            emit("no-track", "high",
                 "Privacy policy claims no tracking/analytics, but trackers or analytics calls exist",
                 "Non-essential tracking may happen despite the policy promising none; the cookie audit confirms it.",
                 m, f"the inventory records {len(trackers)} tracker/analytics signal(s); "
                    f"a cookie audit must confirm they fire before/without consent.",
                 tp_refs, evidence_class="SUSPECTED")
            break
    for m in NO_COLLECT.finditer(text):
        if inv.get("fields") and not conditional(m):
            emit("no-collect", "high",
                 "Privacy policy claims no data collection, but the code collects personal data",
                 "The policy says nothing is collected while the app stores personal fields.",
                 m, f"the inventory records {len(inv['fields'])} personal-data field(s).",
                 sorted({r for f in inv["fields"] for r in f["provenance"]["refs"]})[:4])
            break
    for m in DELETE_CLAIM.finditer(text):
        if not has_deletion and not conditional(m):
            emit("deletion", "high",
                 "Privacy policy promises deletion, but no deletion implementation was found",
                 "Users are told their data is erased; no erase path was found in code, so it may be retained.",
                 m, "the inventory records no deletion right implemented in code "
                    "(rights.deletion is absent). A live deletion test confirms or refutes this.", [],
                 evidence_class="SUSPECTED")
            break
    for m in ENCRYPT_CLAIM.finditer(text):
        if unencrypted and not any(s.get("encrypted_at_rest") == "yes" for s in inv.get("stores", [])):
            emit("encryption", "medium",
                 "Privacy policy claims encryption at rest not evidenced in the inventory",
                 "The policy promises encryption at rest that the inventory cannot confirm.",
                 m, "no store is recorded as encrypted_at_rest: yes.", [])
            break
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--project", required=True, type=Path)
    ap.add_argument("--policy", action="append", type=Path, required=True,
                    help="policy document (txt/html/md); repeatable")
    ap.add_argument("--inventory", type=Path, help="default <state>/data-inventory.yaml")
    ap.add_argument("--out", type=Path, help="default <state>/policy_findings.json")
    args = ap.parse_args(argv)

    state = rglib.state_dir(args.project)
    inv = rglib.load_data(args.inventory or (state / "data-inventory.yaml"), {}) or {}
    all_findings: list[dict] = []
    for pol in args.policy:
        text = Path(pol).read_text(encoding="utf-8", errors="replace")
        try:
            rel = str(Path(pol).resolve().relative_to(args.project.resolve()))
        except ValueError:
            rel = Path(pol).name
        all_findings += check_claims(text, rel, inv)
    # renumber ids across files
    for i, f in enumerate(all_findings, 1):
        f["id"] = f"RG-POLICYMISMATCH-{i:03d}"
    out = args.out or (state / "policy_findings.json")
    rglib.dump_data(out, {"entries": all_findings})
    print(f"policy-consistency: {len(all_findings)} mismatch(es) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
