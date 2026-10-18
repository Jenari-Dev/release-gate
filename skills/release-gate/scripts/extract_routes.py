#!/usr/bin/env python3
"""Extract the HTTP attack surface from source code, from framework semantics.

This is release-gate's recon helper (phase 1): it reads route definitions and
reports, per endpoint, the method, path, whether authentication is required,
the path parameters, and the query/body parameter names the handler reads. It
knows nothing about any particular application: auth is inferred from the names
of the middleware / dependencies a framework uses to gate a handler, not from a
hand-written list of endpoints.

Supported inputs:
  * Express / Express-Router     (`router.get('/x', requireAuth, handler)`)
  * FastAPI / Starlette          (`@app.get('/x')` + `Depends(...)` in the sig)
  * Flask                        (`@app.route('/x', methods=[...])`)
  * OpenAPI 3 document           (openapi.json / openapi.yaml, `security:` per op)

What it deliberately does NOT do: decide that an endpoint is vulnerable, or know
which user owns which record. Those are the job of the dynamic phase, which
builds its plan from this surface. An endpoint whose auth or parameters cannot
be determined is reported with `auth_required: null` (unknown) so the caller
treats it as SUSPECTED, never as a confirmed pass.

stdlib + PyYAML only. Run:  extract_routes.py --project P [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import rglib  # noqa: E402
except Exception:  # pragma: no cover - rglib optional for --json stdout use
    rglib = None  # type: ignore

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")

# A middleware / dependency / decorator whose name matches this is treated as an
# authentication or authorization gate. This is a naming heuristic over common
# security-middleware vocabulary, not a per-app allowlist.
AUTH_NAME_RE = re.compile(
    r"auth|login_?req|logged_?in|require|ensure|protect|session|token|jwt|bearer|"
    r"current[_]?user|verify|principal|identity|permission|passport|guard|"
    r"is_?admin|role|scope|authenticate|authorize|authori[sz]ed",
    re.IGNORECASE,
)
# Parameters whose name matches this carry a URL the server may fetch (SSRF surface).
URL_PARAM_RE = re.compile(
    r"^(url|uri|link|href|src|target|dest|destination|endpoint|callback|webhook|"
    r"redirect|next|return_?url|image_?url|avatar|fetch|proxy|feed|remote)$",
    re.IGNORECASE,
)
IGNORE_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git", "dist",
               "build", ".release-gate", "logs", "site-packages"}

EXPRESS_PATH_PARAM = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
BRACE_PATH_PARAM = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)")


# --------------------------------------------------------------------------- util

def _iter_files(project: Path, suffixes: tuple[str, ...]):
    for p in sorted(project.rglob("*")):
        if p.is_dir():
            continue
        if any(part in IGNORE_DIRS for part in p.parts):
            continue
        if p.suffix in suffixes:
            yield p


def _rel(project: Path, p: Path) -> str:
    try:
        return str(p.relative_to(project))
    except ValueError:
        return str(p)


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _match_paren(text: str, open_idx: int) -> int:
    """Index just past the ')' matching the '(' at open_idx. -1 if unbalanced.

    Skips over string literals and template literals so brackets inside them do
    not throw off the depth count.
    """
    depth = 0
    i = open_idx
    n = len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


_SCALAR_ANNOT = {
    "int", "str", "float", "bool", "bytes", "UUID", "uuid", "datetime", "date",
    "time", "Decimal", "list", "dict", "set", "tuple", "List", "Dict", "Optional",
    "Any", "bytearray", "EmailStr",
}


def _is_model_annotation(param: str, pname: str) -> bool:
    """A FastAPI param `name: SomeCapWordType [= ...]` with a custom (non-scalar)
    annotation is a request-body model (Pydantic), not a query param."""
    m = re.match(r"[A-Za-z_]\w*\s*:\s*([A-Za-z_][\w.]*)", param)
    if not m:
        return False
    annot = m.group(1).split(".")[-1]
    return annot not in _SCALAR_ANNOT and annot[:1].isupper()


def _path_params(path: str) -> list[str]:
    params = EXPRESS_PATH_PARAM.findall(path) + BRACE_PATH_PARAM.findall(path)
    seen: list[str] = []
    for p in params:
        if p not in seen:
            seen.append(p)
    return seen


def _route(method, path, *, auth, source, line, path_params, query=None, body=None,
           framework, note=None) -> dict:
    r = {
        "method": method.upper(),
        "path": path,
        "auth_required": auth,  # True / False / None(unknown)
        "path_params": path_params,
        "query_params": sorted(set(query or [])),
        "body_params": sorted(set(body or [])),
        "framework": framework,
        "source": f"{source}:{line}",
    }
    if note:
        r["note"] = note
    return r


# --------------------------------------------------------------------------- Express

_EXPRESS_CALL = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*(" + "|".join(HTTP_METHODS) + r")\s*\(", re.IGNORECASE
)


def parse_express(text: str, source: str) -> list[dict]:
    routes: list[dict] = []
    for m in _EXPRESS_CALL.finditer(text):
        open_idx = m.end() - 1
        close_idx = _match_paren(text, open_idx)
        if close_idx < 0:
            continue
        inner = text[open_idx + 1:close_idx - 1]
        # first argument must be a string-literal path
        pm = re.match(r"\s*(['\"`])([^'\"`]*)\1", inner)
        if not pm:
            continue
        path = pm.group(2)
        if not path.startswith("/"):
            continue
        method = m.group(2)
        # middleware chain: bare identifiers between the path and the handler
        rest = inner[pm.end():]
        # strip the final handler function body from auth detection by looking only
        # at top-level identifier tokens that appear before a `function`/`=>`/`async`.
        head = re.split(r"=>|\bfunction\b|\basync\b", rest, maxsplit=1)[0]
        mids = re.findall(r"[A-Za-z_$][\w$.]*", head)
        auth = True if any(AUTH_NAME_RE.search(x) for x in mids) else False
        # read param references from the handler body
        body_region = text[open_idx:close_idx]
        query = re.findall(r"req(?:uest)?\.query\.([A-Za-z_$][\w$]*)", body_region)
        query += re.findall(r"req(?:uest)?\.query\[['\"]([^'\"]+)['\"]\]", body_region)
        bodyp = re.findall(r"req(?:uest)?\.body\.([A-Za-z_$][\w$]*)", body_region)
        for dm in re.finditer(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:\([^)]*\)\s*=\s*)?req(?:uest)?\.body", body_region):
            bodyp += [t.strip().split(":")[0].strip() for t in dm.group(1).split(",") if t.strip()]
        routes.append(_route(method, path, auth=auth, source=source,
                             line=_line_of(text, m.start()), path_params=_path_params(path),
                             query=query, body=bodyp, framework="express"))
    return routes


# --------------------------------------------------------------------------- FastAPI / Starlette

_PY_DECORATOR = re.compile(
    r"@\s*([A-Za-z_][\w]*)\s*\.\s*(" + "|".join(HTTP_METHODS) + r")\s*\(", re.IGNORECASE
)


def _py_signature(text: str, def_idx: int) -> str:
    open_idx = text.find("(", def_idx)
    if open_idx < 0:
        return ""
    close_idx = _match_paren(text, open_idx)
    return text[open_idx + 1:close_idx - 1] if close_idx > 0 else ""


def _split_top_level(sig: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for c in sig:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def parse_fastapi(text: str, source: str) -> list[dict]:
    routes: list[dict] = []
    for m in _PY_DECORATOR.finditer(text):
        open_idx = m.end() - 1
        close_idx = _match_paren(text, open_idx)
        if close_idx < 0:
            continue
        inner = text[open_idx + 1:close_idx - 1]
        pm = re.match(r"\s*(['\"])([^'\"]*)\1", inner)
        if not pm:
            continue
        path = pm.group(2)
        if not path.startswith("/"):
            continue
        method = m.group(2)
        # find the function definition that follows the (possibly stacked) decorators
        def_m = re.compile(r"\n\s*(?:async\s+)?def\s+[A-Za-z_]\w*").search(text, close_idx)
        auth: Any = False
        query: list[str] = []
        body: list[str] = []
        ppar = _path_params(path)
        if def_m:
            sig = _py_signature(text, def_m.start())
            for param in _split_top_level(sig):
                name = re.match(r"([A-Za-z_]\w*)", param)
                if not name:
                    continue
                pname = name.group(1)
                if pname in ("self", "cls", "request"):
                    continue
                if "Depends(" in param:
                    dep = re.search(r"Depends\(\s*([A-Za-z_][\w.]*)", param)
                    if dep and AUTH_NAME_RE.search(dep.group(1)):
                        auth = True
                    continue
                if re.search(r"\b(Header|Cookie|Security)\s*\(", param):
                    if re.search(r"Security\s*\(", param):
                        auth = True
                    continue
                if pname in ppar:
                    continue
                if "BaseModel" in param or re.search(r"Body\s*\(", param):
                    body.append(pname)
                elif re.search(r"\b(Form|File|UploadFile)\b", param):
                    body.append(pname)
                elif _is_model_annotation(param, pname):
                    # a param annotated with a custom (CapWord) type is a request body model
                    body.append(pname)
                else:
                    query.append(pname)
        routes.append(_route(method, path, auth=auth, source=source,
                             line=_line_of(text, m.start()), path_params=ppar,
                             query=query, body=body, framework="fastapi"))
    return routes


# --------------------------------------------------------------------------- Flask

_FLASK_ROUTE = re.compile(r"@\s*([A-Za-z_][\w]*)\s*\.\s*route\s*\(")


def parse_flask(text: str, source: str) -> list[dict]:
    routes: list[dict] = []
    for m in _FLASK_ROUTE.finditer(text):
        open_idx = m.end() - 1
        close_idx = _match_paren(text, open_idx)
        if close_idx < 0:
            continue
        inner = text[open_idx + 1:close_idx - 1]
        pm = re.match(r"\s*(['\"])([^'\"]*)\1", inner)
        if not pm:
            continue
        path = pm.group(2)
        if not path.startswith("/"):
            continue
        methods_m = re.search(r"methods\s*=\s*\[([^\]]*)\]", inner)
        methods = re.findall(r"['\"]([A-Za-z]+)['\"]", methods_m.group(1)) if methods_m else ["GET"]
        # Flask auth is usually a decorator above the route (e.g. @login_required)
        head = text[max(0, m.start() - 200):m.start()]
        deco = re.findall(r"@\s*([A-Za-z_][\w.]*)", head)
        auth = True if any(AUTH_NAME_RE.search(d) for d in deco) else None
        ppar = _path_params(re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", path))
        norm_path = re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", path)
        for method in methods:
            routes.append(_route(method, norm_path, auth=auth, source=source,
                                 line=_line_of(text, m.start()), path_params=ppar,
                                 framework="flask",
                                 note="auth inferred from decorators only" if auth is None else None))
    return routes


# --------------------------------------------------------------------------- OpenAPI

def parse_openapi(doc: dict, source: str) -> list[dict]:
    routes: list[dict] = []
    global_sec = bool(doc.get("security"))
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            sec = op.get("security", None)
            auth = bool(sec) if sec is not None else global_sec
            params = op.get("parameters", []) or []
            ppar = [p["name"] for p in params if isinstance(p, dict) and p.get("in") == "path"]
            query = [p["name"] for p in params if isinstance(p, dict) and p.get("in") == "query"]
            routes.append(_route(method, path, auth=auth, source=source, line=1,
                                 path_params=ppar or _path_params(path), query=query,
                                 framework="openapi"))
    return routes


# --------------------------------------------------------------------------- driver

def extract(project: Path) -> dict:
    project = Path(project)
    routes: list[dict] = []
    frameworks: set[str] = set()
    sources: list[str] = []

    for p in _iter_files(project, (".js", ".mjs", ".cjs", ".ts")):
        text = p.read_text(encoding="utf-8", errors="replace")
        if ".get(" in text or ".post(" in text or "express" in text.lower() or "Router(" in text:
            found = parse_express(text, _rel(project, p))
            if found:
                routes += found
                frameworks.add("express")
                sources.append(_rel(project, p))

    for p in _iter_files(project, (".py",)):
        text = p.read_text(encoding="utf-8", errors="replace")
        if "FastAPI" in text or "APIRouter" in text or re.search(r"@\w+\.(get|post|put|patch|delete)\(", text):
            found = parse_fastapi(text, _rel(project, p))
            if found:
                routes += found
                frameworks.add("fastapi")
                sources.append(_rel(project, p))
        if ".route(" in text and ("Flask" in text or "Blueprint" in text):
            found = parse_flask(text, _rel(project, p))
            if found:
                routes += found
                frameworks.add("flask")
                sources.append(_rel(project, p))

    for p in list(_iter_files(project, (".json",))) + list(_iter_files(project, (".yaml", ".yml"))):
        if not re.search(r"openapi|swagger", p.name, re.IGNORECASE):
            continue
        try:
            doc = rglib.load_data(p) if rglib else json.loads(p.read_text())
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("paths"):
            found = parse_openapi(doc, _rel(project, p))
            if found:
                routes += found
                frameworks.add("openapi")
                sources.append(_rel(project, p))

    # de-duplicate (method, path); prefer an entry that resolved auth over an unknown one
    best: dict[tuple, dict] = {}
    for r in routes:
        key = (r["method"], r["path"])
        cur = best.get(key)
        if cur is None or (cur["auth_required"] is None and r["auth_required"] is not None):
            best[key] = r
    merged = sorted(best.values(), key=lambda r: (r["path"], r["method"]))
    return {
        "frameworks": sorted(frameworks),
        "n_routes": len(merged),
        "routes": merged,
        "sources": sorted(set(sources)),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--project", required=True, type=Path)
    ap.add_argument("--json", action="store_true", help="print JSON (default: short table)")
    args = ap.parse_args(argv)
    result = extract(args.project)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"frameworks: {', '.join(result['frameworks']) or 'none detected'}  "
              f"({result['n_routes']} routes)")
        for r in result["routes"]:
            a = {True: "auth", False: "open", None: "auth?"}[r["auth_required"]]
            extra = []
            if r["path_params"]:
                extra.append("path:" + ",".join(r["path_params"]))
            if r["query_params"]:
                extra.append("q:" + ",".join(r["query_params"]))
            if r["body_params"]:
                extra.append("body:" + ",".join(r["body_params"]))
            print(f"  [{a:5}] {r['method']:6} {r['path']:32} {' '.join(extra)}  ({r['source']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
