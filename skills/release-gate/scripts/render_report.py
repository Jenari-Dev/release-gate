#!/usr/bin/env python3
"""Render the self-contained HTML report template from a report_build context.

Reads templates/report/report.html.tmpl and fills it from the same `ctx` dict that
report_build.build_context() produces (slot-to-ctx mapping: templates/report/README.md).

Syntax: {{name}} (escaped scalar), {{#rows list}}...{{/rows}} (repeat, may nest),
{{^rows list}}...{{/rows}} (only when the list is empty), <!-- author comments --> stripped.

Safety: every value is HTML-escaped (values are untrusted project data) and passed through
rglib.redact_text; evidence_class / verdict_class only accept their documented enum values;
any leftover {{...}} in the output is an error (ValueError).

Usage: render_report.py --project P [--mode full] [--date D] [--out FILE]
Default output: <P>/.release-gate/reports/release-gate-<date>.template.html. The result is
linted with report_lint; on failure it is renamed to *.lint-failed.html and the exit code is 2.
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report_build  # noqa: E402
import rglib  # noqa: E402

TEMPLATE_FILE = rglib.SKILL_DIR / "templates" / "report" / "report.html.tmpl"
EM_DASH = "—"

EVIDENCE_CLASS_VALUES = frozenset(rglib.EVIDENCE_CLASSES) | {"N-A"}
VERDICT_CLASS_VALUES = frozenset({"BLOCK", "SHIP-WITH-ACCEPTED-RISKS", "SHIP", "NOT-EVALUATED"})
ENUM_SLOTS = {"evidence_class": EVIDENCE_CLASS_VALUES, "verdict_class": VERDICT_CLASS_VALUES}

COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
TAG_RE = re.compile(r"\{\{(.*?)\}\}")
NAME = r"[A-Za-z_][A-Za-z0-9_]*"


# --------------------------------------------------------------------------- parsing

def _parse(template: str) -> list:
    """Template text -> tree of ("text", s) / ("var", name) / ("rows", name, inverted, children)."""
    template = COMMENT_RE.sub("", template)
    if "<!--" in template:
        raise ValueError("unterminated <!-- comment in template")
    root: list = []
    stack: list[tuple[str, list]] = []  # (list name, parent's children list)
    cur = root
    pos = 0

    def literal(text: str) -> None:
        if "{{" in text:
            raise ValueError(f"malformed placeholder near {text[text.index('{{'):][:40]!r}")
        if text:
            cur.append(("text", text))

    for m in TAG_RE.finditer(template):
        literal(template[pos:m.start()])
        pos = m.end()
        body = m.group(1).strip()
        if mo := re.fullmatch(rf"([#^])rows\s+({NAME})", body):
            node = ("rows", mo.group(2), mo.group(1) == "^", [])
            cur.append(node)
            stack.append((mo.group(2), cur))
            cur = node[3]
        elif body == "/rows":
            if not stack:
                raise ValueError("{{/rows}} without an opening {{#rows ...}}")
            _, cur = stack.pop()
        elif re.fullmatch(NAME, body):
            cur.append(("var", body))
        else:
            raise ValueError(f"unknown placeholder {{{{{body}}}}}")
    literal(template[pos:])
    if stack:
        raise ValueError(f"unclosed {{{{#rows {stack[-1][0]}}}}} block")
    return root


# --------------------------------------------------------------------------- rendering

def _escape(value: str) -> str:
    # Redact again (idempotent) so a raw secret can never reach the page, escape, and
    # neutralise "{" so untrusted data can never look like a placeholder.
    return html.escape(rglib.redact_text(value), quote=True).replace("{", "&#123;")


def _scalar(name: str, value: Any) -> str:
    if isinstance(value, (list, dict)) or value is None and name in ENUM_SLOTS:
        raise ValueError(f"slot {name!r} needs a scalar, got {type(value).__name__}")
    text = "" if value is None else str(value)
    if name in ENUM_SLOTS:
        text = text.replace("/", "-")
        if text not in ENUM_SLOTS[name]:
            raise ValueError(f"{name} must be one of {sorted(ENUM_SLOTS[name])}, got {text!r}")
        return text
    return _escape(text)


def _render_nodes(nodes: list, scope: dict) -> str:
    out: list[str] = []
    for node in nodes:
        kind = node[0]
        if kind == "text":
            out.append(node[1])
        elif kind == "var":
            if node[1] not in scope:
                raise ValueError(f"no value for slot {{{{{node[1]}}}}}")
            out.append(_scalar(node[1], scope[node[1]]))
        else:
            _, name, inverted, children = node
            if name not in scope:
                raise ValueError(f"no list named {name!r}")
            rows = scope[name]
            if not isinstance(rows, list):
                raise ValueError(f"{name!r} is not a list")
            if inverted:
                if not rows:
                    out.append(_render_nodes(children, scope))
                continue
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError(f"rows of {name!r} must be dicts")
                out.append(_render_nodes(children, row))
    return "".join(out)


def render_template(template: str, slots: dict) -> str:
    """Fill a template from a slots dict (scalars and lists of dicts)."""
    out = _render_nodes(_parse(template), slots)
    if "{{" in out:
        raise ValueError("unfilled {{...}} left in output")
    return out


# --------------------------------------------------------------------------- ctx -> slots

def _dash(value: Any) -> str:
    text = "" if value is None else str(value)
    return text if text.strip() else EM_DASH


def _ec(cls: Any) -> str:
    return str(cls).replace("/", "-")


def _location(f: dict) -> str:
    loc = f.get("location") or {}
    if loc.get("endpoint"):
        return str(loc["endpoint"])
    if loc.get("file") and loc.get("line"):
        return f"{loc['file']}:{loc['line']}"
    return _dash(loc.get("file"))


def _tool(f: dict) -> str:
    t = f.get("tool")
    if not t:
        return EM_DASH
    name = " ".join(str(x) for x in (t.get("name") or "?", t.get("version")) if x)
    return f"{name}, rule {t['rule_id']}" if t.get("rule_id") else name


def build_slots(ctx: dict) -> dict:
    """Map a report_build ctx onto the template slots (see templates/report/README.md)."""
    try:
        verdict = ctx["verdict"]
        counts = ctx.get("counts") or {}
        slots: dict[str, Any] = {
            "title": f"release-gate: {ctx['product']} {ctx['date']}",
            "product": ctx["product"], "date": ctx["date"], "mode": ctx["mode"],
            "generated_at": ctx["generated_at"],
            "verdict": verdict["verdict"],
            "verdict_class": str(verdict["verdict"]).replace(" ", "-"),
        }
    except KeyError as exc:
        raise ValueError(f"ctx is missing {exc}") from None
    for sev in rglib.SEVERITIES:
        slots[f"count_{sev}"] = counts.get(sev, 0)
    slots["disclaimer"] = report_build.DISCLAIMER
    slots["blocking"] = [{"text": t} for t in verdict.get("blocking", [])]
    slots["reasons"] = [{"text": t} for t in verdict.get("reasons", [])]
    coverage = ctx.get("coverage") or []
    slots["coverage"] = [{
        "id": r["id"], "title": r["title"], "phase": r.get("phase", ""),
        "critical": "yes" if r.get("critical") else "",
        "evidence_class": _ec(r["evidence_class"]), "evidence_label": r["evidence_class"],
        "result": _dash(r.get("result")), "detail": _dash(r.get("reason")),
        "artifacts": _dash(", ".join(r.get("artifacts") or [])),
    } for r in coverage]
    slots["findings"] = [{
        "id": f["id"], "severity": f.get("severity", ""),
        "evidence_class": _ec(f["evidence_class"]), "evidence_label": f["evidence_class"],
        "title": f["title"], "location": _location(f),
        "status": f.get("status", "open") + (f" · waiver {f['waiver_id']}" if f.get("waiver_id") else ""),
        "impact": _dash(f.get("impact")), "repro": _dash(f.get("repro")), "fix": _dash(f.get("fix")),
        "tool": _tool(f),
        "artifacts": _dash(", ".join(ev["path"] for ev in f.get("evidence") or [] if ev.get("path"))),
    } for f in ctx.get("findings") or []]
    slots["not_tested"] = [
        {"id": r["id"], "title": r["title"], "reason": _dash(r.get("reason"))}
        for r in coverage if r.get("applicable") and r["evidence_class"] == "NOT-TESTED"]
    slots["limitations"] = [{"text": t} for t in report_build.LIMITATIONS]
    return slots


def render(ctx: dict, template: str | None = None) -> str:
    """Render the HTML report for `ctx`. Raises ValueError on any template or enum violation."""
    if template is None:
        template = TEMPLATE_FILE.read_text(encoding="utf-8")
    return render_template(template, build_slots(ctx))


# --------------------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    import report_lint  # local import keeps module import cheap

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--project", required=True, type=Path)
    ap.add_argument("--mode", choices=report_build.MODES, default="full")
    ap.add_argument("--date", help="report date (default: today, UTC)")
    ap.add_argument("--out", type=Path, help="output file (default: <project>/.release-gate/reports/release-gate-<date>.template.html)")
    args = ap.parse_args(argv)

    state = report_build.load_state(args.project, [])
    date = args.date or rglib.today().isoformat()
    ctx = report_build.build_context(state, report_build.load_catalog(), args.mode, date)
    try:
        page = render(ctx)
    except ValueError as exc:
        print(f"render error: {exc}", file=sys.stderr)
        return 1
    out = args.out or state["state_dir"] / "reports" / f"release-gate-{date}.template.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")
    problems = report_lint.lint_paths([out], state["state_dir"])
    if problems:
        failed = out.with_name(out.stem + ".lint-failed.html")
        out.replace(failed)
        for prob in problems:
            print(f"LINT: {prob}", file=sys.stderr)
        print(failed)
        return 2
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
