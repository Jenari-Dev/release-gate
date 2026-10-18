#!/usr/bin/env python3
"""Run one pinned scanner and capture auditable evidence.

    run_tool.py --project DIR --tool NAME [--target URL]
                [--test-type scan|authz|exploit|fuzz|load|stress|spike|soak|passive]
                [--timeout 900] [--docker auto|never|always] [--lock PATH]
                -- <tool args...>

Evidence goes to <project>/.release-gate/evidence/<tool>-<stamp>/ :
stdout.txt, stderr.txt (raw, for parsing) and result.json. Raw output may
contain secrets (gitleaks et al. print what they find); evidence/ is local-only
and gitignored, and result.json says `raw_output_may_contain_secrets: true`.
Only the recorded argv is redacted.

Placeholders in tool args: `{project}` and `{evidence}` (container paths /src
and /out in docker mode, host paths otherwise).

Honesty rules:
  * tool missing           -> result status "not-run", exit 4. Never a pass.
  * target out of scope    -> result status "refused-out-of-scope", exit 5, and
    no process is started. Network-facing tools (category dast/load) require
    --target and a confirmed scope; fuzz/stress/etc. follow rglib.check_scope.
  * Many scanners exit non-zero when they FIND issues, so exit_code alone is
    not failure. status "completed" only means the process ran to completion;
    judging the findings is the caller's job.

Exit codes: 0 completed, 4 not-run, 5 refused, 6 timeout, 7 error, 2 usage.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import check_tools
import rglib

TEST_TYPES = ("scan", "authz", "exploit", "fuzz", "load", "stress", "spike", "soak", "passive")
NETWORK_CATEGORIES = frozenset({"dast", "load"})
EXIT_OK, EXIT_USAGE, EXIT_NOT_RUN, EXIT_REFUSED, EXIT_TIMEOUT, EXIT_ERROR = 0, 2, 4, 5, 6, 7


# Flags that keep a tool from contacting third parties on its own (principle 5). They are
# added when missing, never left to the caller: nuclei otherwise registers with a public
# Interactsh server (oast.*) for out-of-band checks, and checks for template/engine updates.
FORCED_FLAGS: dict[str, list[tuple[str, ...]]] = {
    "nuclei": [("-ni", "-no-interactsh"), ("-duc", "-disable-update-check")],
}


def force_offline_flags(tool: str, args: list[str]) -> tuple[list[str], list[str]]:
    """Return (args with any missing forced flags appended, the flags that were added)."""
    added = []
    for aliases in FORCED_FLAGS.get(tool, []):
        if not any(a in args for a in aliases):
            added.append(aliases[0])
    return [*args, *added], added


def substitute(args: list[str], project: str, evidence: str) -> list[str]:
    """Replace {project} and {evidence} placeholders (plain replace: other braces stay)."""
    return [a.replace("{project}", project).replace("{evidence}", evidence) for a in args]


def build_docker_argv(image: str, args: list[str], project: Path, evidence: Path,
                      name: str, with_target: bool, docker: str = "docker") -> list[str]:
    """argv for a sandboxed run: read-only project at /src, evidence at /out."""
    return [
        docker, "run", "--rm", "--name", name,
        "--network", "host" if with_target else "none",
        "-v", f"{project}:/src:ro", "-v", f"{evidence}:/out", "-w", "/src",
        image, *substitute(args, "/src", "/out"),
    ]


def make_evidence_dir(project: Path, tool: str) -> Path:
    """Create a fresh evidence/<tool>-<stamp>[-N] directory."""
    base = rglib.state_dir(project) / "evidence"
    stamp = rglib.stamp()
    n = 0
    while True:
        d = base / (f"{tool}-{stamp}" + (f"-{n}" if n else ""))
        try:
            d.mkdir()
            return d
        except FileExistsError:
            n += 1


def write_result(evidence: Path, result: dict[str, Any]) -> Path:
    return rglib.dump_data(evidence / "result.json", result)


def _terminate(proc: subprocess.Popen, docker_name: str | None, docker: str | None) -> None:
    """Kill the whole process group (and the container, in docker mode)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()
    if docker_name and docker:
        subprocess.run([docker, "kill", docker_name], capture_output=True, timeout=30)
    proc.wait()


def execute(argv: list[str], cwd: Path, evidence: Path, timeout: float, env: dict[str, str],
            docker_name: str | None = None, docker: str | None = None) -> dict[str, Any]:
    """Run argv (list, never a shell), stream output to evidence files, return run facts."""
    started = rglib.now_iso()
    t0 = time.monotonic()
    out: dict[str, Any] = {"started_at": started, "exit_code": None, "status": "error", "timed_out": False}
    with open(evidence / "stdout.txt", "wb") as so, open(evidence / "stderr.txt", "wb") as se:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, stdout=so, stderr=se, stdin=subprocess.DEVNULL,
                                    env=env, start_new_session=True)
        except OSError as exc:
            out["error"] = f"could not start process: {type(exc).__name__}: {exc}"
        else:
            try:
                out["exit_code"] = proc.wait(timeout=timeout)
                out["status"] = "completed"
            except subprocess.TimeoutExpired:
                _terminate(proc, docker_name, docker)
                out["status"], out["timed_out"] = "timeout", True
    out["finished_at"] = rglib.now_iso()
    out["duration_s"] = round(time.monotonic() - t0, 3)
    return out


def _refuse_or_skip(evidence: Path, base: dict[str, Any], status: str, reason: str, code: int) -> int:
    result = {**base, "status": status, "reason": reason, "finished_at": rglib.now_iso()}
    write_result(evidence, result)
    print(json.dumps(result, indent=2))
    return code


def run(args: argparse.Namespace, tool_args: list[str]) -> int:
    project = Path(args.project).resolve()
    if not project.is_dir():
        print(f"not a directory: {args.project}", file=sys.stderr)
        return EXIT_USAGE
    lock = check_tools.load_lock(args.lock)
    entry = (lock["tools"].get(args.tool) or {})
    category = entry.get("category")
    test_type = args.test_type or ("scan" if args.target else "passive")
    evidence = make_evidence_dir(project, args.tool)
    base: dict[str, Any] = {
        "tool": args.tool, "category": category, "target": args.target, "test_type": test_type,
        "cwd": str(project), "started_at": rglib.now_iso(), "evidence_dir": str(evidence),
    }

    # ---- scope gate first: nothing launches against an unconfirmed target
    if args.target or category in NETWORK_CATEGORIES:
        if not args.target:
            return _refuse_or_skip(evidence, base, "refused-out-of-scope",
                                   f"{args.tool} is network-facing ({category}) and requires --target", EXIT_REFUSED)
        try:
            scope = rglib.load_data(project / rglib.STATE_DIRNAME / "scope.yaml", None)
        except Exception as exc:  # unreadable scope fails closed
            return _refuse_or_skip(evidence, base, "refused-out-of-scope",
                                   f"scope.yaml unreadable: {type(exc).__name__}", EXIT_REFUSED)
        ok, why = rglib.check_scope(args.target, test_type, scope)
        if not ok:
            return _refuse_or_skip(evidence, base, "refused-out-of-scope", why, EXIT_REFUSED)
        base["scope_decision"] = why

    # ---- pick a mode
    local = check_tools.resolve_tool(args.tool, lock)
    image = entry.get("docker_image")
    use_docker = False
    if args.docker != "never" and image and check_tools.docker_available():
        use_docker = True
    if args.docker == "always" and not use_docker:
        return _refuse_or_skip(evidence, base, "not-run",
                               f"tool unavailable: {args.tool} (docker required but docker or docker_image unavailable)",
                               EXIT_NOT_RUN)
    if not use_docker and local is None:
        reason = f"tool unavailable: {args.tool}"
        if args.tool not in lock["tools"]:
            reason += " (not in lock file)"
        return _refuse_or_skip(evidence, base, "not-run", reason, EXIT_NOT_RUN)

    version = None
    if local is not None:
        version = check_tools.check_tool(args.tool, lock).get("found_version")
    tool_args, forced = force_offline_flags(args.tool, tool_args)
    if forced:
        base["forced_flags"] = forced
    docker_name = None
    docker_exe = None
    if use_docker:
        docker_exe = "docker"
        docker_name = f"rg-{args.tool}-{rglib.stamp()}-{os.getpid()}"
        argv = build_docker_argv(image, tool_args, project, evidence, docker_name, bool(args.target))
        mode, cwd, version = "docker", project, version or f"image:{image}"
    else:
        argv = [str(local), *substitute(tool_args, str(project), str(evidence))]
        mode, cwd = "local", project
    env = dict(os.environ, PATH=check_tools.tool_env_path(lock))

    run_facts = execute(argv, cwd, evidence, args.timeout, env, docker_name, docker_exe)
    result: dict[str, Any] = {
        **base, **run_facts,
        "version": version,
        "argv": [rglib.redact_text(a) for a in argv],
        "mode": mode,
        "sha256": {n: rglib.sha256_file(evidence / n) for n in ("stdout.txt", "stderr.txt")},
        "raw_output_may_contain_secrets": True,
    }
    path = write_result(evidence, result)
    print(path)
    return {"completed": EXIT_OK, "timeout": EXIT_TIMEOUT}.get(result["status"], EXIT_ERROR)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    tool_args: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, tool_args = argv[:i], argv[i + 1:]
    ap = argparse.ArgumentParser(description="Run a pinned tool and capture evidence.",
                                 usage="run_tool.py --project DIR --tool NAME [options] -- <tool args...>")
    ap.add_argument("--project", required=True)
    ap.add_argument("--tool", required=True)
    ap.add_argument("--target")
    ap.add_argument("--test-type", choices=TEST_TYPES)
    ap.add_argument("--timeout", type=float, default=900)
    ap.add_argument("--docker", choices=("auto", "never", "always"), default="auto")
    ap.add_argument("--lock", default=str(rglib.LOCK_FILE))
    return run(ap.parse_args(argv), tool_args)


if __name__ == "__main__":
    sys.exit(main())
