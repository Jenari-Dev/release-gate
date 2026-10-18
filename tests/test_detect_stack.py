"""detect_stack on small synthetic project trees. No network, nothing executed."""
import json
import subprocess
import sys
from pathlib import Path

import detect_stack as ds

SCRIPT = Path(ds.__file__)


def write(root: Path, rel: str, content: str = "") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def fw_names(d: dict) -> set[str]:
    return {f["name"] for f in d["frameworks"]}


def missing_manifests(d: dict) -> set[str]:
    return {m["manifest"] for m in d["lockfiles_missing"]}


def test_node_express(tmp_path):
    write(tmp_path, "package.json", json.dumps({
        "name": "app", "main": "src/server.js", "scripts": {"start": "node src/server.js"},
        "dependencies": {"express": "^4.19.0"}}))
    write(tmp_path, "package-lock.json", "{}")
    write(tmp_path, "src/server.js", "const express = require('express')")
    write(tmp_path, "src/util.ts", "export {}")
    write(tmp_path, "node_modules/express/index.js", "x")
    write(tmp_path, "tests/app.test.js", "")
    write(tmp_path, ".github/workflows/ci.yml", "on: push")
    write(tmp_path, "Dockerfile", "FROM node:20")
    write(tmp_path, "docker-compose.yml", "services: {}")
    d = ds.detect(tmp_path)
    assert d["languages"] == {"javascript": 2, "typescript": 1}  # node_modules skipped
    assert d["primary_language"] == "javascript"
    assert "express" in fw_names(d)
    npm = next(m for m in d["package_managers"] if m["name"] == "npm")
    assert npm["manifests"] == ["package.json"] and npm["lockfiles"] == ["package-lock.json"]
    assert d["lockfiles_missing"] == []
    types = {(e["type"], e["detail"]) for e in d["entry_points"]}
    assert ("node-main", "src/server.js") in types
    assert ("node-script", "start: node src/server.js") in types
    assert d["deployment"]["docker"] == ["Dockerfile"]
    assert d["deployment"]["compose"] == ["docker-compose.yml"]
    assert d["ci"]["github-actions"] == [".github/workflows/ci.yml"]
    assert d["tests"]["dirs"] == ["tests"] and d["tests"]["test_files"] == 1


def test_fastapi(tmp_path):
    write(tmp_path, "requirements.txt", "# deps\nfastapi==0.110.0\nuvicorn[standard]>=0.29\n-r other.txt\n")
    write(tmp_path, "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    write(tmp_path, "run.py", "import uvicorn\nif __name__ == \"__main__\":\n    uvicorn.run('main:app')\n")
    write(tmp_path, "openapi.json", json.dumps({"openapi": "3.0.0", "paths": {}}))
    write(tmp_path, "swagger-ui-bundle.js", "// not a spec")
    d = ds.detect(tmp_path)
    assert "fastapi" in fw_names(d)
    assert d["primary_language"] == "python"
    assert any(m["name"] == "pip" for m in d["package_managers"])
    types = {(e["type"], e["path"]) for e in d["entry_points"]}
    assert ("python-app", "main.py") in types
    assert ("python-main", "run.py") in types
    assert ("python-uvicorn", "run.py") in types
    assert d["openapi_specs"] == ["openapi.json"]
    # requirements.txt alone is not a missing lockfile
    assert d["lockfiles_missing"] == []


def test_electron(tmp_path):
    write(tmp_path, "package.json", json.dumps({
        "main": "main.js", "devDependencies": {"electron": "^30.0.0"}, "dependencies": {"react": "18"}}))
    write(tmp_path, "yarn.lock", "")
    write(tmp_path, "main.js", "")
    d = ds.detect(tmp_path)
    assert {"electron", "react"} <= fw_names(d)
    assert [m["name"] for m in d["package_managers"] if m["manifests"]] == ["yarn"]
    assert d["lockfiles_missing"] == []


def test_browser_extension(tmp_path):
    write(tmp_path, "manifest.json", json.dumps({
        "manifest_version": 3, "name": "x", "background": {"service_worker": "bg.js"}}))
    write(tmp_path, "bg.js", "")
    write(tmp_path, "pwa/manifest.json", json.dumps({"name": "plain web app manifest", "start_url": "/"}))
    d = ds.detect(tmp_path)
    ext = next(f for f in d["frameworks"] if f["name"] == "browser-extension")
    assert ext["evidence"] == ["manifest.json"]


def test_missing_lockfile(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"left-pad": "1.0.0"}}))
    write(tmp_path, "go.mod", "module x\n\nrequire github.com/gin-gonic/gin v1.9.0\n")
    write(tmp_path, "Cargo.toml", "[package]\nname='a'\n[dependencies]\naxum='0.7'\n")
    write(tmp_path, "Gemfile", "source 'x'\ngem 'rails'\n")
    write(tmp_path, "composer.json", json.dumps({"require": {"php": ">=8", "laravel/framework": "^11"}}))
    write(tmp_path, "pyproject.toml", "[project]\nname='p'\ndependencies=['django>=5']\n")
    write(tmp_path, "empty/package.json", json.dumps({"name": "no-deps"}))
    d = ds.detect(tmp_path)
    assert missing_manifests(d) == {
        "package.json", "go.mod", "Cargo.toml", "Gemfile", "composer.json", "pyproject.toml"}
    assert {"gin", "axum", "rails", "laravel", "django"} <= fw_names(d)


def test_lockfile_present_in_workspace_root_is_ok(tmp_path):
    write(tmp_path, "package.json", json.dumps({"workspaces": ["pkgs/*"], "dependencies": {"a": "1"}}))
    write(tmp_path, "pnpm-lock.yaml", "")
    write(tmp_path, "pkgs/a/package.json", json.dumps({"dependencies": {"b": "1"}}))
    d = ds.detect(tmp_path)
    assert d["lockfiles_missing"] == []


def test_poetry_with_lock_ok_and_without_flagged(tmp_path):
    write(tmp_path, "a/pyproject.toml", "[tool.poetry]\nname='a'\n[tool.poetry.dependencies]\nflask='*'\n")
    write(tmp_path, "a/poetry.lock", "")
    write(tmp_path, "b/pyproject.toml", "[tool.poetry]\nname='b'\n[tool.poetry.dependencies]\nflask='*'\n")
    d = ds.detect(tmp_path)
    assert missing_manifests(d) == {"b/pyproject.toml"}
    assert "flask" in fw_names(d)


def test_k8s_manifest_and_other_deploy(tmp_path):
    write(tmp_path, "deploy/app.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n")
    write(tmp_path, "deploy/notk8s.yaml", "name: foo\nkind_of: thing\n")
    write(tmp_path, "main.tf", "")
    write(tmp_path, "fly.toml", "app='x'")
    write(tmp_path, "vercel.json", "{}")
    write(tmp_path, "netlify.toml", "")
    write(tmp_path, "serverless.yml", "service: x")
    write(tmp_path, "svc/app.service", "[Service]")
    write(tmp_path, ".gitlab-ci.yml", "stages: []")
    d = ds.detect(tmp_path)
    assert d["deployment"]["kubernetes"] == ["deploy/app.yaml"]
    for kind in ("terraform", "fly", "vercel", "netlify", "serverless", "systemd"):
        assert kind in d["deployment"], kind
    assert d["ci"]["gitlab-ci"] == [".gitlab-ci.yml"]


def test_game_and_mobile_markers(tmp_path):
    write(tmp_path, "ProjectSettings/ProjectVersion.txt", "")
    write(tmp_path, "Game.uproject", "{}")
    write(tmp_path, "app/src/main/AndroidManifest.xml", "<manifest/>")
    (tmp_path / "App.xcodeproj").mkdir()
    write(tmp_path, "src-tauri/tauri.conf.json", "{}")
    write(tmp_path, "src-tauri/src/main.rs", "fn main(){}")
    d = ds.detect(tmp_path)
    assert {"unity", "unreal", "android", "ios", "tauri"} <= fw_names(d)
    assert ("rust-main", "src-tauri/src/main.rs") in {(e["type"], e["path"]) for e in d["entry_points"]}


def test_skip_dirs_and_symlinks(tmp_path):
    outside = tmp_path / "outside"
    write(outside, "secret.py", "x")
    proj = tmp_path / "proj"
    write(proj, "a.py", "")
    write(proj, "vendor/v.go", "")
    write(proj, ".venv/lib/x.py", "")
    write(proj, "dist/d.js", "")
    write(proj, "build/b.js", "")
    write(proj, ".release-gate/evidence/x.py", "")
    (proj / "link").symlink_to(outside, target_is_directory=True)
    (proj / "flink.py").symlink_to(outside / "secret.py")
    d = ds.detect(proj)
    assert d["languages"] == {"python": 1}
    assert d["scanned_files"] == 1


def test_empty_and_malformed(tmp_path):
    write(tmp_path, "package.json", "{not json")
    write(tmp_path, "Cargo.toml", "[[[broken")
    d = ds.detect(tmp_path)
    assert d["warnings"]
    assert d["languages"] == {}


def test_cli_json(tmp_path):
    write(tmp_path, "app.py", "")
    r = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path), "--json"], capture_output=True, text=True)
    assert r.returncode == 0
    assert json.loads(r.stdout)["primary_language"] == "python"
    r = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path / "nope")], capture_output=True, text=True)
    assert r.returncode == 2
    r = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 0 and "languages: python=1" in r.stdout
