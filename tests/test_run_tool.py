"""run_tool with fake tool scripts. No network, no docker, scanners never real."""
import json
import time
from pathlib import Path

import pytest
import yaml

import check_tools
import run_tool as rt

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"


def make_exe(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)
    return path


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(check_tools, "docker_available", lambda: False)
    project = tmp_path / "proj"
    project.mkdir()
    bin_dir = tmp_path / "bin"
    marker = tmp_path / "marker"
    make_exe(bin_dir / "rgfake", f'''
if [ "$1" = "--version" ]; then echo "rgfake 1.2.3"; exit 0; fi
echo started >> "{marker}"
echo "args: $*"
echo "cwd: $(pwd)"
echo "token {AWS_KEY}"
echo "some warning" >&2
exit ${{RG_EXIT:-0}}
''')
    make_exe(bin_dir / "rgsleep", 'if [ "$1" = "--version" ]; then echo "rgsleep 1.0.0"; exit 0; fi\nsleep 30')
    make_exe(bin_dir / "rgdast", f'if [ "$1" = "--version" ]; then echo "rgdast 2.0.0"; exit 0; fi\necho started >> "{marker}"')
    lock = {
        "schema_version": 1, "install_dir": str(bin_dir), "venv_dir": str(tmp_path / "venv"),
        "tools": {
            "rgfake": {"category": "secrets", "version": "1.2.3", "version_cmd": ["rgfake", "--version"],
                       "version_regex": r"(\d+\.\d+\.\d+)"},
            "rgsleep": {"category": "sast", "version": "1.0.0", "version_cmd": ["rgsleep", "--version"],
                        "version_regex": r"(\d+\.\d+\.\d+)"},
            "rgdast": {"category": "dast", "version": "2.0.0", "version_cmd": ["rgdast", "--version"],
                       "version_regex": r"(\d+\.\d+\.\d+)"},
            "rgghost": {"category": "sast", "version": "1.0.0", "version_cmd": ["rgghost", "--version"]},
        },
    }
    lock_path = tmp_path / "tools.lock.yaml"
    lock_path.write_text(yaml.safe_dump(lock))
    return {"project": project, "lock": lock_path, "marker": marker, "tmp": tmp_path, "lock_data": lock}


def write_scope(project: Path, **target):
    t = {"url": "http://127.0.0.1:3000", "environment": "local"}
    t.update(target)
    d = project / ".release-gate"
    d.mkdir(exist_ok=True)
    (d / "scope.yaml").write_text(yaml.safe_dump({
        "schema_version": 1, "confirmed_at": "2026-10-18T00:00:00+00:00", "confirmed_by": "user", "targets": [t]}))


def call(env, *extra, tool="rgfake", tool_args=("a", "b")):
    argv = ["--project", str(env["project"]), "--tool", tool, "--lock", str(env["lock"]), *extra]
    if tool_args is not None:
        argv += ["--", *tool_args]
    return rt.main(argv)


def only_result(env, tool="rgfake"):
    dirs = sorted((env["project"] / ".release-gate" / "evidence").glob(f"{tool}-*"))
    assert len(dirs) == 1, dirs
    return dirs[0], json.loads((dirs[0] / "result.json").read_text())


def test_successful_run_writes_evidence(env, capsys):
    assert call(env, tool_args=("--flag", "x")) == 0
    d, res = only_result(env)
    assert capsys.readouterr().out.strip() == str(d / "result.json")
    assert res["tool"] == "rgfake" and res["version"] == "1.2.3"
    assert res["status"] == "completed" and res["exit_code"] == 0 and res["timed_out"] is False
    assert res["mode"] == "local" and res["cwd"] == str(env["project"].resolve())
    assert res["argv"][1:] == ["--flag", "x"]
    assert res["raw_output_may_contain_secrets"] is True
    assert res["duration_s"] >= 0 and res["started_at"] and res["finished_at"]
    out = (d / "stdout.txt").read_text()
    assert "args: --flag x" in out and f"cwd: {env['project'].resolve()}" in out
    assert (d / "stderr.txt").read_text().strip() == "some warning"
    import hashlib
    assert res["sha256"]["stdout.txt"] == hashlib.sha256((d / "stdout.txt").read_bytes()).hexdigest()
    assert res["sha256"]["stderr.txt"] == hashlib.sha256((d / "stderr.txt").read_bytes()).hexdigest()


def test_raw_output_kept_but_argv_redacted(env):
    assert call(env, tool_args=("--token", AWS_KEY)) == 0
    d, res = only_result(env)
    assert AWS_KEY in (d / "stdout.txt").read_text()  # raw evidence is for parsing
    assert AWS_KEY not in json.dumps(res)
    assert "REDACTED" in " ".join(res["argv"])


def test_nonzero_exit_is_still_completed(env, monkeypatch):
    monkeypatch.setenv("RG_EXIT", "1")
    assert call(env) == 0
    _, res = only_result(env)
    assert res["status"] == "completed" and res["exit_code"] == 1


def test_missing_tool_not_run(env, capsys):
    assert call(env, tool="rgghost") == 4
    _, res = only_result(env, "rgghost")
    assert res["status"] == "not-run" and res["reason"] == "tool unavailable: rgghost"
    assert "stdout.txt" not in {p.name for p in _.iterdir()}
    assert json.loads(capsys.readouterr().out)["status"] == "not-run"


def test_tool_not_in_lock_not_run(env):
    assert call(env, tool="rgunknown") == 4
    _, res = only_result(env, "rgunknown")
    assert res["status"] == "not-run" and res["reason"].startswith("tool unavailable: rgunknown")


def test_out_of_scope_target_launches_nothing(env):
    write_scope(env["project"])
    assert call(env, "--target", "http://evil.example.com", "--test-type", "scan") == 5
    _, res = only_result(env)
    assert res["status"] == "refused-out-of-scope" and "not a confirmed target" in res["reason"]
    assert not env["marker"].exists()


def test_no_scope_file_refused(env):
    assert call(env, "--target", "http://127.0.0.1:3000") == 5
    _, res = only_result(env)
    assert res["status"] == "refused-out-of-scope" and "no confirmed scope" in res["reason"]
    assert not env["marker"].exists()


def test_disallowed_test_type_refused(env):
    write_scope(env["project"], allowed_tests=["passive"])
    assert call(env, "--target", "http://127.0.0.1:3000", "--test-type", "exploit") == 5
    assert not env["marker"].exists()


def test_malformed_scope_fails_closed(env):
    (env["project"] / ".release-gate").mkdir()
    (env["project"] / ".release-gate" / "scope.yaml").write_text("targets: [unclosed")
    assert call(env, "--target", "http://127.0.0.1:3000") == 5
    assert not env["marker"].exists()


def test_in_scope_target_runs(env):
    write_scope(env["project"])
    assert call(env, "--target", "http://127.0.0.1:3000", "--test-type", "scan") == 0
    _, res = only_result(env)
    assert res["target"] == "http://127.0.0.1:3000" and res["test_type"] == "scan"
    assert res["scope_decision"].startswith("in scope")
    assert env["marker"].exists()


def test_network_tool_requires_target(env):
    write_scope(env["project"])
    assert call(env, tool="rgdast", tool_args=("x",)) == 5
    _, res = only_result(env, "rgdast")
    assert res["status"] == "refused-out-of-scope" and "requires --target" in res["reason"]
    assert not env["marker"].exists()
    assert call(env, "--target", "http://127.0.0.1:3000", tool="rgdast", tool_args=("x",)) == 0
    assert env["marker"].exists()


def test_timeout(env):
    t0 = time.monotonic()
    assert call(env, "--timeout", "1", tool="rgsleep", tool_args=()) == 6
    assert time.monotonic() - t0 < 15
    _, res = only_result(env, "rgsleep")
    assert res["status"] == "timeout" and res["timed_out"] is True
    assert res["exit_code"] is None


def test_placeholders_substituted(env):
    assert call(env, tool_args=("--src={project}", "{evidence}/out.json", "{braces}")) == 0
    d, res = only_result(env)
    proj = str(env["project"].resolve())
    out = (d / "stdout.txt").read_text()
    assert f"args: --src={proj} {d}/out.json {{braces}}" in out
    assert res["argv"][1:] == [f"--src={proj}", f"{d}/out.json", "{braces}"]


def test_repeated_runs_get_distinct_evidence_dirs(env):
    for _ in range(3):
        assert call(env) == 0
    dirs = list((env["project"] / ".release-gate" / "evidence").glob("rgfake-*"))
    assert len(dirs) == 3


def test_substitute_pure():
    assert rt.substitute(["{project}/x", "{evidence}", "{keep}"], "/p", "/e") == ["/p/x", "/e", "{keep}"]


def test_docker_argv_shape(tmp_path):
    img = "ghcr.io/x/y@sha256:" + "a" * 64
    none = rt.build_docker_argv(img, ["scan", "{project}", "-o", "{evidence}/r.json"], tmp_path / "p", tmp_path / "e", "n", False)
    assert none[:5] == ["docker", "run", "--rm", "--name", "n"]
    assert none[none.index("--network") + 1] == "none"
    assert f"{tmp_path / 'p'}:/src:ro" in none and f"{tmp_path / 'e'}:/out" in none
    assert none[none.index("-w") + 1] == "/src"
    assert none[none.index(img):] == [img, "scan", "/src", "-o", "/out/r.json"]
    host = rt.build_docker_argv(img, [], tmp_path / "p", tmp_path / "e", "n", True)
    assert host[host.index("--network") + 1] == "host"


def test_docker_mode_selected_when_available(env, monkeypatch):
    env["lock_data"]["tools"]["rgfake"]["docker_image"] = "example.invalid/rgfake@sha256:" + "b" * 64
    env["lock"].write_text(yaml.safe_dump(env["lock_data"]))
    monkeypatch.setattr(check_tools, "docker_available", lambda: True)
    seen = {}

    def fake_execute(argv, cwd, evidence, timeout, envv, docker_name=None, docker=None):
        seen["argv"] = argv
        (evidence / "stdout.txt").write_bytes(b"")
        (evidence / "stderr.txt").write_bytes(b"")
        return {"started_at": "t", "finished_at": "t", "duration_s": 0.0, "exit_code": 0,
                "status": "completed", "timed_out": False}

    monkeypatch.setattr(rt, "execute", fake_execute)
    assert call(env) == 0
    _, res = only_result(env)
    assert res["mode"] == "docker" and seen["argv"][:3] == ["docker", "run", "--rm"]
    assert seen["argv"][seen["argv"].index("--network") + 1] == "none"
    # --docker never forces local
    assert call(env, "--docker", "never") == 0
    assert seen["argv"][0].endswith("rgfake")


def test_docker_always_without_docker_is_not_run(env):
    assert call(env, "--docker", "always") == 4
    _, res = only_result(env)
    assert res["status"] == "not-run"


def test_project_must_exist(env, tmp_path, capsys):
    rc = rt.main(["--project", str(tmp_path / "nope"), "--tool", "rgfake", "--lock", str(env["lock"])])
    assert rc == 2


def test_nuclei_offline_flags_are_forced():
    import run_tool
    args, added = run_tool.force_offline_flags("nuclei", ["-u", "http://127.0.0.1:1"])
    assert "-ni" in args and "-duc" in args and added == ["-ni", "-duc"]
    args, added = run_tool.force_offline_flags("nuclei", ["-no-interactsh", "-duc"])
    assert added == []
    assert run_tool.force_offline_flags("gitleaks", ["dir", "."]) == (["dir", "."], [])
