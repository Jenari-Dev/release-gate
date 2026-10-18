#!/usr/bin/env python3
"""Detect the technology stack of a project so the audit can pick relevant tools.

    detect_stack.py <project> [--json]

Everything in the project is treated as data: files are only read and parsed
(JSON / TOML / YAML via safe loaders or regexes). Nothing from the project is
ever imported or executed, and symlinks are never followed.

Output dict keys: project, scanned_files, truncated, languages, primary_language,
package_managers, lockfiles_missing, frameworks, entry_points, deployment, ci,
tests, openapi_specs, warnings.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

SKIP_DIRS = frozenset({
    "node_modules", ".venv", "venv", "vendor", ".git", "dist", "build", ".release-gate",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", ".gradle", "Pods",
})
MAX_FILES = 100_000
MAX_READ = 1_000_000          # bytes read from any single file
MAX_SOURCE_SCAN = 2_000       # python files scanned for entry points
MAX_SOURCE_BYTES = 256_000

LANG_BY_EXT = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".py": "python", ".go": "go", ".rs": "rust",
    ".rb": "ruby", ".php": "php", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".swift": "swift", ".dart": "dart", ".sh": "shell", ".lua": "lua", ".scala": "scala",
    ".vue": "vue", ".svelte": "svelte",
}

NPM_LOCKS = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn",
             "pnpm-lock.yaml": "pnpm", "bun.lock": "bun", "bun.lockb": "bun"}
PY_LOCKS = {"poetry.lock": "poetry", "uv.lock": "uv", "Pipfile.lock": "pipenv", "pdm.lock": "pdm"}
OTHER_LOCKS = {"go.sum": "go", "Cargo.lock": "cargo", "Gemfile.lock": "bundler",
               "composer.lock": "composer", "gradle.lockfile": "gradle"}

NODE_FRAMEWORKS = {
    "express": "express", "fastify": "fastify", "next": "next", "react": "react", "vue": "vue",
    "svelte": "svelte", "@sveltejs/kit": "svelte", "electron": "electron",
    "@tauri-apps/api": "tauri", "@tauri-apps/cli": "tauri", "koa": "koa",
    "@nestjs/core": "nestjs", "nuxt": "nuxt",
}
PY_FRAMEWORKS = {"fastapi": "fastapi", "flask": "flask", "django": "django"}
RUST_FRAMEWORKS = {"actix-web": "actix", "actix": "actix", "axum": "axum", "tauri": "tauri"}

DEPLOY_NAMES = {"serverless.yml": "serverless", "serverless.yaml": "serverless",
                "fly.toml": "fly", "vercel.json": "vercel", "netlify.toml": "netlify",
                "Chart.yaml": "helm"}
TEST_DIR_NAMES = frozenset({"tests", "test", "__tests__", "spec", "e2e", "cypress"})
TEST_FILE_RE = re.compile(r"(^test_.*\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$)")

PY_MAIN_RE = re.compile(r"""^if\s+__name__\s*==\s*['"]__main__['"]\s*:""", re.M)
PY_APP_RE = re.compile(r"^\s*(\w+)\s*=\s*(FastAPI|Flask|Starlette|Quart)\s*\(", re.M)
PY_UVICORN_RE = re.compile(r"\buvicorn\.run\s*\(")
K8S_API_RE = re.compile(r"^apiVersion:\s*\S+", re.M)
K8S_KIND_RE = re.compile(r"^kind:\s*(\S+)", re.M)
SPEC_KEY_RE = re.compile(r"""(?:^|[{,])\s*["']?(openapi|swagger)["']?\s*:""", re.M)
REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")
REQ_FILE_RE = re.compile(r"^requirements.*\.txt$", re.I)


# --------------------------------------------------------------------------- helpers

def read_text(path: Path, limit: int = MAX_READ) -> str:
    """Read at most `limit` bytes as text; unreadable files yield ''."""
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class Project:
    """Walk result plus cached, defensive parsers."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files: list[str] = []          # posix paths relative to root
        self.dirs: list[str] = []
        self.truncated = False
        self.warnings: list[str] = []
        self._json: dict[str, Any] = {}
        self._toml: dict[str, Any] = {}
        self._walk()
        self.fileset = set(self.files)

    def _walk(self) -> None:
        for cur, dirnames, filenames in os.walk(self.root, followlinks=False):
            here = Path(cur)
            rel_dir = here.relative_to(self.root).as_posix()
            prune = set(SKIP_DIRS)
            if (here / "Cargo.toml").exists() or (here / "pom.xml").exists():
                prune.add("target")
            dirnames[:] = sorted(d for d in dirnames if d not in prune and not (here / d).is_symlink())
            for d in dirnames:
                self.dirs.append(f"{rel_dir}/{d}" if rel_dir != "." else d)
            for f in sorted(filenames):
                if (here / f).is_symlink():
                    continue
                if len(self.files) >= MAX_FILES:
                    self.truncated = True
                    return
                self.files.append(f"{rel_dir}/{f}" if rel_dir != "." else f)

    def text(self, rel: str, limit: int = MAX_READ) -> str:
        return read_text(self.root / rel, limit)

    def json(self, rel: str) -> Any:
        if rel not in self._json:
            try:
                self._json[rel] = json.loads(self.text(rel))
            except ValueError:
                self.warnings.append(f"could not parse JSON: {rel}")
                self._json[rel] = None
        return self._json[rel]

    def toml(self, rel: str) -> dict:
        if rel not in self._toml:
            try:
                self._toml[rel] = tomllib.loads(self.text(rel))
            except tomllib.TOMLDecodeError:
                self.warnings.append(f"could not parse TOML: {rel}")
                self._toml[rel] = {}
        return self._toml[rel]

    def has_in_ancestors(self, rel_file: str, names: set[str] | dict[str, str]) -> list[str]:
        """Lockfiles named in `names` present in the manifest's directory or any ancestor."""
        found = []
        d = PurePosixPath(rel_file).parent
        while True:
            for n in names:
                cand = (d / n).as_posix() if str(d) != "." else n
                if cand in self.fileset:
                    found.append(cand)
            if str(d) == ".":
                break
            d = d.parent
        return found


def _base(rel: str) -> str:
    return PurePosixPath(rel).name


# --------------------------------------------------------------------------- detectors

def detect_languages(p: Project) -> tuple[dict[str, int], str | None]:
    counts: Counter[str] = Counter()
    for rel in p.files:
        lang = LANG_BY_EXT.get(PurePosixPath(rel).suffix.lower())
        if lang:
            counts[lang] += 1
    ordered = dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
    return ordered, (next(iter(ordered)) if ordered else None)


def _node_deps(pkg: Any) -> dict:
    if not isinstance(pkg, dict):
        return {}
    deps: dict = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        if isinstance(pkg.get(key), dict):
            deps.update(pkg[key])
    return deps


def _py_dep_names(p: Project, rel: str) -> set[str]:
    """Normalised dependency names declared in a Python manifest."""
    base = _base(rel)
    names: set[str] = set()
    if base == "pyproject.toml":
        data = p.toml(rel)
        for spec in data.get("project", {}).get("dependencies", []) or []:
            m = REQ_NAME_RE.match(str(spec))
            if m:
                names.add(_norm(m.group(1)))
        for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
            for spec in group or []:
                m = REQ_NAME_RE.match(str(spec))
                if m:
                    names.add(_norm(m.group(1)))
        poetry = data.get("tool", {}).get("poetry", {})
        for key in ("dependencies", "dev-dependencies"):
            names.update(_norm(k) for k in (poetry.get(key) or {}))
        for grp in (poetry.get("group") or {}).values():
            names.update(_norm(k) for k in (grp.get("dependencies") or {}))
        for spec in (data.get("dependency-groups") or {}).values():
            for item in spec or []:
                m = REQ_NAME_RE.match(str(item)) if isinstance(item, str) else None
                if m:
                    names.add(_norm(m.group(1)))
    elif base == "Pipfile":
        data = p.toml(rel)
        for key in ("packages", "dev-packages"):
            names.update(_norm(k) for k in (data.get(key) or {}))
    elif base in ("setup.py", "setup.cfg"):
        text = p.text(rel).lower()
        names.update(n for n in PY_FRAMEWORKS if re.search(rf"['\"\s]{n}\b", text))
    else:  # requirements*.txt
        for line in p.text(rel).splitlines():
            s = line.strip()
            if not s or s.startswith(("#", "-")):
                continue
            m = REQ_NAME_RE.match(s)
            if m:
                names.add(_norm(m.group(1)))
    return names


def _is_requirements(rel: str) -> bool:
    pp = PurePosixPath(rel)
    return pp.suffix == ".txt" and (REQ_FILE_RE.match(pp.name) is not None or pp.parent.name == "requirements")


def _cargo_dep_names(p: Project, rel: str) -> set[str]:
    data = p.toml(rel)
    names: set[str] = set()
    tables = [data.get(k) for k in ("dependencies", "dev-dependencies", "build-dependencies")]
    tables.append((data.get("workspace") or {}).get("dependencies"))
    for t in tables:
        if isinstance(t, dict):
            names.update(t)
    return names


def detect_package_managers_and_frameworks(p: Project) -> tuple[list[dict], list[dict], list[dict]]:
    """Return (package_managers, lockfiles_missing, frameworks)."""
    managers: dict[str, dict[str, set[str]]] = {}
    missing: list[dict] = []
    fw: dict[str, list[str]] = {}

    def add(name: str, manifest: str | None = None, lockfile: str | None = None) -> None:
        rec = managers.setdefault(name, {"manifests": set(), "lockfiles": set()})
        if manifest:
            rec["manifests"].add(manifest)
        if lockfile:
            rec["lockfiles"].add(lockfile)

    def add_fw(name: str, evidence: str) -> None:
        ev = fw.setdefault(name, [])
        if evidence not in ev:
            ev.append(evidence)

    def flag_missing(manager: str, manifest: str, hint: str) -> None:
        missing.append({"manager": manager, "manifest": manifest, "expected_lockfile": hint})

    for rel in p.files:
        base = _base(rel)
        # ---- lockfiles
        for table in (NPM_LOCKS, PY_LOCKS, OTHER_LOCKS):
            if base in table:
                add(table[base], lockfile=rel)

        # ---- node
        if base == "package.json":
            pkg = p.json(rel)
            locks = p.has_in_ancestors(rel, NPM_LOCKS)
            mgr = NPM_LOCKS[_base(locks[0])] if locks else "npm"
            add(mgr, manifest=rel)
            deps = _node_deps(pkg)
            if deps and not locks:
                flag_missing("npm", rel, "package-lock.json | yarn.lock | pnpm-lock.yaml")
            for name, label in NODE_FRAMEWORKS.items():
                if name in deps:
                    add_fw(label, rel)
            continue

        # ---- python
        if base == "pyproject.toml":
            data = p.toml(rel)
            tool = data.get("tool", {}) if isinstance(data.get("tool"), dict) else {}
            same_dir = str(PurePosixPath(rel).parent)
            uv_lock = (PurePosixPath(rel).parent / "uv.lock").as_posix() if same_dir != "." else "uv.lock"
            mgr = "poetry" if "poetry" in tool else "uv" if ("uv" in tool or uv_lock in p.fileset) else "pip"
            add(mgr, manifest=rel)
            names = _py_dep_names(p, rel)
            if names and not p.has_in_ancestors(rel, set(PY_LOCKS)):
                sibling_req = any(
                    _is_requirements(f) and PurePosixPath(f).parent == PurePosixPath(rel).parent for f in p.files
                )
                if not sibling_req:
                    flag_missing(mgr, rel, "poetry.lock | uv.lock | Pipfile.lock | pdm.lock")
            for n, label in PY_FRAMEWORKS.items():
                if n in names:
                    add_fw(label, rel)
            continue
        if base == "Pipfile":
            add("pipenv", manifest=rel)
            if _py_dep_names(p, rel) and not p.has_in_ancestors(rel, {"Pipfile.lock"}):
                flag_missing("pipenv", rel, "Pipfile.lock")
            for n, label in PY_FRAMEWORKS.items():
                if n in _py_dep_names(p, rel):
                    add_fw(label, rel)
            continue
        if _is_requirements(rel) or base in ("setup.py", "setup.cfg"):
            add("pip", manifest=rel)
            names = _py_dep_names(p, rel)
            for n, label in PY_FRAMEWORKS.items():
                if n in names:
                    add_fw(label, rel)
            continue

        # ---- go
        if base == "go.mod":
            add("go", manifest=rel)
            text = p.text(rel)
            has_req = bool(re.search(r"^\s*require\b", text, re.M))
            if has_req and not p.has_in_ancestors(rel, {"go.sum"}):
                flag_missing("go", rel, "go.sum")
            if "github.com/gin-gonic/gin" in text:
                add_fw("gin", rel)
            continue

        # ---- rust
        if base == "Cargo.toml":
            add("cargo", manifest=rel)
            names = _cargo_dep_names(p, rel)
            data = p.toml(rel)
            if (names or "package" in data) and not p.has_in_ancestors(rel, {"Cargo.lock"}):
                flag_missing("cargo", rel, "Cargo.lock")
            for n, label in RUST_FRAMEWORKS.items():
                if n in names:
                    add_fw(label, rel)
            continue

        # ---- ruby / php
        if base == "Gemfile":
            add("bundler", manifest=rel)
            text = p.text(rel)
            if re.search(r"^\s*gem\s+['\"]\w", text, re.M) and not p.has_in_ancestors(rel, {"Gemfile.lock"}):
                flag_missing("bundler", rel, "Gemfile.lock")
            if re.search(r"""^\s*gem\s+['"]rails['"]""", text, re.M):
                add_fw("rails", rel)
            continue
        if base == "composer.json":
            add("composer", manifest=rel)
            data = p.json(rel)
            req = data.get("require") if isinstance(data, dict) else None
            deps = {k: v for k, v in (req or {}).items() if k != "php" and not k.startswith("ext-")}
            if deps and not p.has_in_ancestors(rel, {"composer.lock"}):
                flag_missing("composer", rel, "composer.lock")
            for k in list(deps) + list((data or {}).get("require-dev", {}) if isinstance(data, dict) else []):
                if k == "laravel/framework":
                    add_fw("laravel", rel)
            continue

        # ---- jvm / dotnet (no standard lockfile: never flagged)
        if base == "pom.xml":
            add("maven", manifest=rel)
            if re.search(r"spring-boot|org\.springframework", p.text(rel)):
                add_fw("spring", rel)
        elif base in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
            add("gradle", manifest=rel)
            if base.startswith("build.") and re.search(r"spring-boot|org\.springframework", p.text(rel)):
                add_fw("spring", rel)
        elif base.endswith(".csproj"):
            add("nuget", manifest=rel)

    # ---- project-type markers
    for d in p.dirs:
        if _base(d) == "ProjectSettings":
            add_fw("unity", d + "/")
        if d.endswith(".xcodeproj") or d.endswith(".xcworkspace"):
            add_fw("ios", d + "/")
    for rel in p.files:
        base = _base(rel)
        if base.endswith(".uproject"):
            add_fw("unreal", rel)
        elif base == "AndroidManifest.xml":
            add_fw("android", rel)
        elif base == "tauri.conf.json":
            add_fw("tauri", rel)
        elif base == "manifest.json":
            data = p.json(rel)
            if (isinstance(data, dict) and data.get("manifest_version") in (2, 3)
                    and ("background" in data or "content_scripts" in data)):
                add_fw("browser-extension", rel)

    pm = [
        {"name": n, "manifests": sorted(r["manifests"]), "lockfiles": sorted(r["lockfiles"])}
        for n, r in sorted(managers.items())
    ]
    frameworks = [{"name": n, "evidence": sorted(ev)} for n, ev in sorted(fw.items())]
    return pm, sorted(missing, key=lambda m: (m["manager"], m["manifest"])), frameworks


def detect_entry_points(p: Project) -> list[dict]:
    out: list[dict] = []
    py_scanned = 0
    for rel in p.files:
        base = _base(rel)
        if base == "package.json":
            pkg = p.json(rel)
            if not isinstance(pkg, dict):
                continue
            if isinstance(pkg.get("main"), str):
                out.append({"type": "node-main", "path": rel, "detail": pkg["main"]})
            scripts = pkg.get("scripts")
            if isinstance(scripts, dict) and isinstance(scripts.get("start"), str):
                out.append({"type": "node-script", "path": rel, "detail": f"start: {scripts['start']}"})
        elif base == "main.go":
            out.append({"type": "go-main", "path": rel, "detail": ""})
        elif rel == "src/main.rs" or rel.endswith("/src/main.rs"):
            out.append({"type": "rust-main", "path": rel, "detail": ""})
        elif base == "manage.py":
            out.append({"type": "django-manage", "path": rel, "detail": ""})
        elif base.endswith(".py"):
            parts = set(PurePosixPath(rel).parts[:-1])
            if parts & TEST_DIR_NAMES or py_scanned >= MAX_SOURCE_SCAN:
                continue
            py_scanned += 1
            try:
                text = p.text(rel, MAX_SOURCE_BYTES)
            except OSError:
                continue
            if PY_MAIN_RE.search(text):
                out.append({"type": "python-main", "path": rel, "detail": '__name__ == "__main__"'})
            m = PY_APP_RE.search(text)
            if m:
                out.append({"type": "python-app", "path": rel, "detail": f"{m.group(1)} = {m.group(2)}(...)"})
            if PY_UVICORN_RE.search(text):
                out.append({"type": "python-uvicorn", "path": rel, "detail": "uvicorn.run"})
    return out


def detect_deployment(p: Project) -> dict[str, list[str]]:
    dep: dict[str, list[str]] = {}

    def add(kind: str, rel: str) -> None:
        dep.setdefault(kind, []).append(rel)

    for rel in p.files:
        base = _base(rel)
        low = base.lower()
        suffix = PurePosixPath(rel).suffix.lower()
        if low.startswith("dockerfile") or low.endswith(".dockerfile"):
            add("docker", rel)
        elif re.match(r"^(docker-)?compose.*\.ya?ml$", low):
            add("compose", rel)
        elif base in DEPLOY_NAMES:
            add(DEPLOY_NAMES[base], rel)
        elif suffix == ".service":
            add("systemd", rel)
        elif suffix == ".tf":
            add("terraform", rel)
        elif suffix in (".yaml", ".yml") and not rel.startswith(".github/"):
            head = p.text(rel, 65_536)
            if K8S_API_RE.search(head) and K8S_KIND_RE.search(head):
                add("kubernetes", rel)
    return {k: sorted(v) for k, v in sorted(dep.items())}


def detect_ci(p: Project) -> dict[str, list[str]]:
    ci: dict[str, list[str]] = {}
    for rel in p.files:
        pp = PurePosixPath(rel)
        if rel.startswith(".github/workflows/") and pp.suffix in (".yml", ".yaml"):
            ci.setdefault("github-actions", []).append(rel)
        elif rel == ".gitlab-ci.yml":
            ci.setdefault("gitlab-ci", []).append(rel)
        elif rel == ".circleci/config.yml":
            ci.setdefault("circleci", []).append(rel)
        elif rel == "Jenkinsfile":
            ci.setdefault("jenkins", []).append(rel)
    return ci


def detect_tests(p: Project) -> dict[str, Any]:
    dirs = [d for d in p.dirs if _base(d) in TEST_DIR_NAMES]
    n_files = sum(1 for rel in p.files if TEST_FILE_RE.search(_base(rel)))
    return {"dirs": sorted(dirs), "test_files": n_files}


def detect_openapi(p: Project) -> list[str]:
    out = []
    for rel in p.files:
        base = _base(rel).lower()
        if base.endswith((".json", ".yaml", ".yml")) and base.startswith(("openapi", "swagger")):
            if SPEC_KEY_RE.search(p.text(rel, 8192)):
                out.append(rel)
    return sorted(out)


# --------------------------------------------------------------------------- entry points

def detect(project: str | Path) -> dict[str, Any]:
    root = Path(project).resolve()
    p = Project(root)
    languages, primary = detect_languages(p)
    managers, missing, frameworks = detect_package_managers_and_frameworks(p)
    return {
        "project": str(root),
        "scanned_files": len(p.files),
        "truncated": p.truncated,
        "languages": languages,
        "primary_language": primary,
        "package_managers": managers,
        "lockfiles_missing": missing,
        "frameworks": frameworks,
        "entry_points": detect_entry_points(p),
        "deployment": detect_deployment(p),
        "ci": detect_ci(p),
        "tests": detect_tests(p),
        "openapi_specs": detect_openapi(p),
        "warnings": sorted(set(p.warnings)),
    }


def format_summary(d: dict[str, Any]) -> str:
    lines = [f"project: {d['project']}  ({d['scanned_files']} files{', TRUNCATED' if d['truncated'] else ''})"]
    lines.append("languages: " + (", ".join(f"{k}={v}" for k, v in d["languages"].items()) or "none"))
    lines.append("frameworks: " + (", ".join(f["name"] for f in d["frameworks"]) or "none"))
    lines.append("package managers: " + (", ".join(m["name"] for m in d["package_managers"]) or "none"))
    for m in d["lockfiles_missing"]:
        lines.append(f"  LOCKFILE MISSING: {m['manifest']} (expected {m['expected_lockfile']})")
    for e in d["entry_points"]:
        lines.append(f"entry: {e['type']} {e['path']} {e['detail']}".rstrip())
    for kind, paths in d["deployment"].items():
        lines.append(f"deploy/{kind}: {', '.join(paths)}")
    for kind, paths in d["ci"].items():
        lines.append(f"ci/{kind}: {', '.join(paths)}")
    lines.append(f"tests: {len(d['tests']['dirs'])} dirs, {d['tests']['test_files']} files")
    if d["openapi_specs"]:
        lines.append("openapi: " + ", ".join(d["openapi_specs"]))
    for w in d["warnings"]:
        lines.append(f"warning: {w}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Detect a project's stack (read-only).")
    ap.add_argument("project")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a text summary")
    args = ap.parse_args(argv)
    if not Path(args.project).is_dir():
        print(f"not a directory: {args.project}", file=sys.stderr)
        return 2
    result = detect(args.project)
    print(json.dumps(result, indent=2) if args.json else format_summary(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
