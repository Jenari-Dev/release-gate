"""check_tools with a fake lock pointing at tiny shell scripts. No network, no docker."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import check_tools as ct

SCRIPT = Path(ct.__file__)


def make_exe(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)
    return path


@pytest.fixture
def lock_env(tmp_path, monkeypatch):
    monkeypatch.setattr(ct, "docker_status", lambda: {"available": False, "reason": "test"})
    bin_dir, venv = tmp_path / "bin", tmp_path / "venv"
    make_exe(bin_dir / "rgfake-ok", 'echo "rgfake-ok version 1.2.3"')
    make_exe(bin_dir / "rgfake-old", 'echo "rgfake-old 1.0.0"')
    make_exe(bin_dir / "rgfake-broken", 'echo "boom" >&2; exit 1')
    make_exe(bin_dir / "rgfake-noversion", 'echo "no digits here"')
    make_exe(venv / "bin" / "rgfake-pip", 'echo "rgfake-pip 4.5.6"')
    tools = {
        "rgfake-ok": {"category": "secrets", "version": "1.2.3", "version_cmd": ["rgfake-ok", "--version"]},
        "rgfake-old": {"category": "sast", "version": "1.2.3", "version_cmd": ["rgfake-old", "--version"]},
        "rgfake-missing": {"category": "sca", "version": "9.9.9", "version_cmd": ["rgfake-missing", "--version"]},
        "rgfake-broken": {"category": "iac", "version": "1.0.0", "version_cmd": ["rgfake-broken", "--version"]},
        "rgfake-noversion": {"category": "iac", "version": "1.0.0", "version_cmd": ["rgfake-noversion"]},
        "rgfake-pip": {"category": "sast", "version": "4.5.6", "kind": "pip", "version_cmd": ["rgfake-pip", "-V"]},
    }
    for t in tools.values():
        t["version_regex"] = r"(\d+\.\d+\.\d+)"
    lock = {"schema_version": 1, "install_dir": str(bin_dir), "venv_dir": str(venv), "tools": tools}
    path = tmp_path / "tools.lock.yaml"
    path.write_text(yaml.safe_dump(lock))
    return lock, path


def rows(lock):
    return {r["name"]: r for r in ct.check_all(lock)["tools"]}


def test_statuses(lock_env):
    lock, _ = lock_env
    r = rows(lock)
    assert r["rgfake-ok"]["status"] == "ok"
    assert r["rgfake-ok"]["found_version"] == "1.2.3" and r["rgfake-ok"]["category"] == "secrets"
    assert "not_tested_reason" not in r["rgfake-ok"]
    assert r["rgfake-old"]["status"] == "version-mismatch"
    assert r["rgfake-old"]["found_version"] == "1.0.0"
    assert r["rgfake-old"]["not_tested_reason"].startswith("tool unavailable: rgfake-old (version-mismatch")
    assert r["rgfake-missing"]["status"] == "missing"
    assert r["rgfake-missing"]["path"] is None
    assert r["rgfake-missing"]["not_tested_reason"] == "tool unavailable: rgfake-missing (missing)"
    assert r["rgfake-broken"]["status"] == "broken"
    assert r["rgfake-broken"]["not_tested_reason"] == "tool unavailable: rgfake-broken (broken)"
    assert r["rgfake-noversion"]["status"] == "broken"  # runs but gives no parseable version


def test_venv_bin_lookup_and_expected_fields(lock_env):
    lock, _ = lock_env
    r = rows(lock)["rgfake-pip"]
    assert r["status"] == "ok" and r["path"].endswith("venv/bin/rgfake-pip")
    assert r["expected"] == "4.5.6"


def test_path_wins_over_install_dir(lock_env, tmp_path, monkeypatch):
    lock, _ = lock_env
    pdir = tmp_path / "onpath"
    make_exe(pdir / "rgfake-ok", 'echo "rgfake-ok 1.2.3"')
    monkeypatch.setenv("PATH", f"{pdir}{os.pathsep}{os.environ['PATH']}")
    assert ct.resolve_tool("rgfake-ok", lock) == pdir / "rgfake-ok"


def test_resolve_tool(lock_env):
    lock, _ = lock_env
    assert ct.resolve_tool("rgfake-ok", lock).name == "rgfake-ok"
    assert ct.resolve_tool("rgfake-missing", lock) is None
    assert ct.resolve_tool("not-in-lock", lock) is None


def test_non_executable_file_is_not_found(lock_env):
    lock, _ = lock_env
    p = Path(lock["install_dir"]) / "rgfake-missing"
    p.write_text("#!/bin/sh\necho 9.9.9\n")  # not chmod +x
    assert ct.resolve_tool("rgfake-missing", lock) is None


def test_timeout_is_broken(lock_env, monkeypatch):
    lock, _ = lock_env
    monkeypatch.setattr(ct, "VERSION_TIMEOUT", 1)
    make_exe(Path(lock["install_dir"]) / "rgfake-slow", "sleep 20")
    lock["tools"]["rgfake-slow"] = {"category": "sca", "version": "1.0.0", "version_cmd": ["rgfake-slow"]}
    assert ct.check_tool("rgfake-slow", lock)["status"] == "broken"


def run_cli(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_cli_json_and_exit_zero(lock_env):
    _, path = lock_env
    r = run_cli("--lock", str(path), "--json")
    assert r.returncode == 0  # a report: exit 0 even with missing/broken tools
    data = json.loads(r.stdout)
    assert set(data) == {"docker", "tools"} and isinstance(data["docker"]["available"], bool)
    assert {t["name"] for t in data["tools"]} >= {"rgfake-ok", "rgfake-missing"}


def test_cli_single_tool(lock_env):
    _, path = lock_env
    data = json.loads(run_cli("--lock", str(path), "--json", "--tool", "rgfake-ok").stdout)
    assert [t["name"] for t in data["tools"]] == ["rgfake-ok"]
    assert run_cli("--lock", str(path), "--tool", "nope").returncode == 2


def test_cli_require(lock_env):
    _, path = lock_env
    assert run_cli("--lock", str(path), "--require", "rgfake-ok", "rgfake-pip").returncode == 0
    r = run_cli("--lock", str(path), "--require", "rgfake-ok", "rgfake-old")
    assert r.returncode == 3 and "rgfake-old" in r.stderr
    assert run_cli("--lock", str(path), "--require", "rgfake-missing").returncode == 3


def test_docker_status_without_docker(monkeypatch):
    monkeypatch.setattr(ct.shutil, "which", lambda n: None)
    s = ct.docker_status()
    assert s["available"] is False and "reason" in s


def test_table_output(lock_env):
    lock, _ = lock_env
    out = ct.format_table(ct.check_all(lock))
    assert "rgfake-ok" in out and "docker: unavailable" in out
