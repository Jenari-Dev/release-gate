#!/usr/bin/env python3
"""Report which pinned release-gate tools are usable on this machine.

    check_tools.py [--lock PATH] [--json] [--tool NAME] [--require NAME...]

For every tool in tools.lock.yaml the executable is looked up on PATH, then in
install_dir, then in venv_dir/bin. Its version_cmd runs (20s timeout) and the
version is parsed with version_regex. Status values:

    ok                version matches the pin
    version-mismatch  found and runnable, but a different version than pinned
    missing           not found anywhere
    broken            found, but the version command failed or printed no version

Anything that is not "ok" carries a ready-made `not_tested_reason`; a tool that
is missing or broken must be reported NOT-TESTED, never as a pass. Docker
availability is reported separately. Exit status is 0 (this is a report),
except 3 when --require names a tool that is not ok.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from rglib import LOCK_FILE, load_data

VERSION_TIMEOUT = 20
DOCKER_TIMEOUT = 20


def expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(str(path))))


def load_lock(path: str | Path | None = None) -> dict:
    lock = load_data(path or LOCK_FILE, None)
    if not isinstance(lock, dict) or not isinstance(lock.get("tools"), dict):
        raise SystemExit(f"unreadable or invalid lock file: {path or LOCK_FILE}")
    return lock


def _executable_names(name: str, entry: dict) -> list[str]:
    names = [name]
    cmd = entry.get("version_cmd")
    if isinstance(cmd, list) and cmd and str(cmd[0]) not in names:
        names.append(str(cmd[0]))
    return names


def _is_exe(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


PRESENCE_KINDS = frozenset({"archive-dir", "git", "npm"})


def share_dir(lock: dict) -> Path:
    base = lock.get("share_dir")
    if not base:
        inst = str(lock.get("install_dir", ""))
        base = inst.rsplit("/", 1)[0] if "/" in inst else inst
    return expand(str(base))


def resolve_tool(name: str, lock: dict) -> Path | None:
    """Find the executable for `name`: PATH, then install_dir, then venv_dir/bin."""
    entry = (lock.get("tools") or {}).get(name)
    if not isinstance(entry, dict):
        return None
    names = _executable_names(name, entry)
    for n in names:
        found = shutil.which(n)
        if found:
            return Path(found)
    dirs = []
    if lock.get("install_dir"):
        dirs.append(expand(lock["install_dir"]))
    if lock.get("venv_dir"):
        dirs.append(expand(lock["venv_dir"]) / "bin")
    for d in dirs:
        for n in names:
            cand = d / n
            if _is_exe(cand):
                return cand
    # payload tools (archive-dir, e.g. ZAP) live under share_dir at exe_rel
    if entry.get("exe_rel") and lock.get("share_dir"):
        cand = expand(lock["share_dir"]) / entry["exe_rel"]
        if _is_exe(cand):
            return cand
    return None


def tool_env_path(lock: dict) -> str:
    """PATH value with the lock's install/venv dirs prepended (for running tools)."""
    extra = []
    if lock.get("install_dir"):
        extra.append(str(expand(lock["install_dir"])))
    if lock.get("venv_dir"):
        extra.append(str(expand(lock["venv_dir"]) / "bin"))
    return os.pathsep.join(extra + [os.environ.get("PATH", "")])


def docker_status() -> dict[str, Any]:
    """Whether `docker info` succeeds. Never raises."""
    exe = shutil.which("docker")
    if not exe:
        return {"available": False, "reason": "docker not found on PATH"}
    try:
        r = subprocess.run([exe, "info"], capture_output=True, timeout=DOCKER_TIMEOUT, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "reason": f"docker info failed: {type(exc).__name__}"}
    if r.returncode != 0:
        return {"available": False, "reason": "docker info exited non-zero (daemon not running or no permission)"}
    return {"available": True, "path": exe}


def docker_available() -> bool:
    return bool(docker_status()["available"])


def check_tool(name: str, lock: dict) -> dict[str, Any]:
    """Check one tool and return its report row."""
    entry = lock["tools"][name]
    row: dict[str, Any] = {
        "name": name,
        "category": entry.get("category"),
        "expected": str(entry.get("version")) if entry.get("version") is not None else None,
        "found_version": None,
        "path": None,
        "status": "missing",
    }
    if entry.get("kind") in PRESENCE_KINDS:
        # Payload tools (ZAP tree, template/rule snapshots, node+playwright) are
        # confirmed by their verify_path existing, not by a version command.
        vp = entry.get("verify_path")
        target = share_dir(lock) / vp if vp else None
        if target and target.exists():
            exe_rel = entry.get("exe_rel")
            row.update(status="ok", found_version=row["expected"],
                       path=str(share_dir(lock) / exe_rel) if exe_rel else str(target))
        else:
            row["not_tested_reason"] = f"tool unavailable: {name} (missing)"
        return row

    path = resolve_tool(name, lock)
    if path is None:
        row["not_tested_reason"] = f"tool unavailable: {name} (missing)"
        return row
    row["path"] = str(path)
    cmd = entry.get("version_cmd") or [name, "--version"]
    argv = [str(path)] + [str(a) for a in cmd[1:]]
    env = dict(os.environ, PATH=tool_env_path(lock))
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=VERSION_TIMEOUT, env=env,
                           stdin=subprocess.DEVNULL)
        out, ok = (r.stdout or "") + "\n" + (r.stderr or ""), r.returncode == 0
    except subprocess.TimeoutExpired:
        out, ok = "", False
    except (OSError, subprocess.SubprocessError):
        out, ok = "", False
    m = re.search(entry.get("version_regex") or r"(\d+\.\d+\.\d+)", out) if ok else None
    if not ok or not m:
        row["status"] = "broken"
        row["not_tested_reason"] = f"tool unavailable: {name} (broken)"
        return row
    found = m.group(1) if m.groups() else m.group(0)
    row["found_version"] = found
    if row["expected"] is not None and found != row["expected"]:
        row["status"] = "version-mismatch"
        row["not_tested_reason"] = f"tool unavailable: {name} (version-mismatch: found {found}, expected {row['expected']})"
    else:
        row["status"] = "ok"
    return row


def check_all(lock: dict, only: str | None = None) -> dict[str, Any]:
    names = [only] if only else list(lock["tools"])
    return {"docker": docker_status(), "tools": [check_tool(n, lock) for n in names]}


def format_table(report: dict[str, Any]) -> str:
    lines = [f"{'tool':<14}{'category':<10}{'expected':<10}{'found':<10}{'status':<17}path"]
    for r in report["tools"]:
        lines.append(f"{r['name']:<14}{str(r['category']):<10}{str(r['expected']):<10}"
                     f"{str(r['found_version'] or '-'):<10}{r['status']:<17}{r['path'] or '-'}")
    d = report["docker"]
    lines.append("docker: " + ("available" if d["available"] else f"unavailable ({d['reason']})"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check pinned release-gate tools.")
    ap.add_argument("--lock", default=str(LOCK_FILE))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--tool", help="check only this tool")
    ap.add_argument("--require", nargs="+", action="extend", default=[], metavar="NAME",
                    help="exit 3 if any of these tools is not ok")
    args = ap.parse_args(argv)
    lock = load_lock(args.lock)
    for n in ([args.tool] if args.tool else []) + args.require:
        if n not in lock["tools"]:
            print(f"tool not in lock file: {n}", file=sys.stderr)
            return 2
    report = check_all(lock, args.tool)
    print(json.dumps(report, indent=2) if args.json else format_table(report))
    if args.require:
        rows = {r["name"]: r for r in report["tools"]}
        bad = [n for n in args.require if (rows.get(n) or check_tool(n, lock))["status"] != "ok"]
        if bad:
            print("required tools not ok: " + ", ".join(bad), file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
