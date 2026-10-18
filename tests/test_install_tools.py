"""Offline tests for install_tools.py: no network, local fake archives only."""
import hashlib
import importlib.util
import io
import os
import tarfile
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(__file__).resolve().parent.parent / "skills" / "release-gate" / "scripts" / "install_tools.py"
spec = importlib.util.spec_from_file_location("install_tools", SCRIPT)
it = importlib.util.module_from_spec(spec)
spec.loader.exec_module(it)

PAYLOAD = b"#!/bin/sh\necho faketool 1.2.3\n"


def make_tar(path: Path, members: dict[str, bytes], extra=None) -> str:
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if extra:
            extra(tf)
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def fake_net(tmp_path, monkeypatch):
    """Route download() to local files keyed by URL; fail on anything unknown."""
    served: dict[str, Path] = {}

    def fake_download(url, dest):
        if url not in served:
            raise AssertionError(f"unexpected network fetch: {url}")
        dest.write_bytes(served[url].read_bytes())

    monkeypatch.setattr(it, "download", fake_download)
    return served


def binary_spec(url, sha, member="faketool"):
    s = {"kind": "binary", "version": "1.2.3", "source": url, "sha256": sha}
    if member:
        s["archive_member"] = member
    return s


def test_install_binary_extracts_only_named_member(tmp_path, fake_net):
    arc = tmp_path / "fake.tar.gz"
    sha = make_tar(arc, {"faketool": PAYLOAD, "README": b"x", "other": b"y"})
    fake_net["https://example.invalid/fake.tar.gz"] = arc
    bindir = tmp_path / "bin"
    out = it.install_binary("faketool", binary_spec("https://example.invalid/fake.tar.gz", sha), bindir)
    assert out == bindir / "faketool"
    assert out.read_bytes() == PAYLOAD
    assert os.access(out, os.X_OK)
    assert sorted(p.name for p in bindir.iterdir()) == ["faketool"]  # nothing else extracted


def test_bare_executable_install(tmp_path, fake_net):
    raw = tmp_path / "faketool-linux"
    raw.write_bytes(PAYLOAD)
    fake_net["https://example.invalid/faketool-linux"] = raw
    sha = hashlib.sha256(PAYLOAD).hexdigest()
    out = it.install_binary("faketool", binary_spec("https://example.invalid/faketool-linux", sha, member=None), tmp_path / "bin")
    assert out.read_bytes() == PAYLOAD and os.access(out, os.X_OK)


def test_hash_mismatch_refuses_and_leaves_nothing(tmp_path, fake_net):
    arc = tmp_path / "fake.tar.gz"
    make_tar(arc, {"faketool": PAYLOAD})
    fake_net["https://example.invalid/fake.tar.gz"] = arc
    bindir = tmp_path / "bin"
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(it.InstallError, match="sha256 mismatch"):
        it.install_binary("faketool", binary_spec("https://example.invalid/fake.tar.gz", "0" * 64), bindir, workdir=work)
    assert not (bindir / "faketool").exists()
    assert list(work.iterdir()) == []  # downloaded file deleted


def test_checksums_file_disagreement_refused(tmp_path, fake_net):
    arc = tmp_path / "fake.tar.gz"
    sha = make_tar(arc, {"faketool": PAYLOAD})
    listing = tmp_path / "sums.txt"
    listing.write_text(f"{'1' * 64}  fake.tar.gz\n")
    fake_net["https://example.invalid/fake.tar.gz"] = arc
    fake_net["https://example.invalid/sums.txt"] = listing
    s = binary_spec("https://example.invalid/fake.tar.gz", sha)
    s["checksums_url"] = "https://example.invalid/sums.txt"
    with pytest.raises(it.InstallError, match="disagrees"):
        it.install_binary("faketool", s, tmp_path / "bin")
    assert not (tmp_path / "bin" / "faketool").exists()


def test_checksum_listing_parser():
    text = f"{'a' * 64}  foo.tar.gz\n{'b' * 64} *bar\n"
    assert it.checksum_from_listing(text, "foo.tar.gz") == "a" * 64
    assert it.checksum_from_listing(text, "bar") == "b" * 64
    assert it.checksum_from_listing(text, "baz") is None


@pytest.mark.parametrize("bad", ["../evil", "/etc/passwd", "a/../../evil", "", "a\\b"])
def test_member_name_guard(bad):
    with pytest.raises(it.InstallError):
        it.normalize_member(bad)


def test_path_traversal_member_never_extracted(tmp_path):
    arc = tmp_path / "evil.tar.gz"
    make_tar(arc, {"../evil": b"pwned", "faketool": PAYLOAD})
    dest = tmp_path / "bin" / "faketool"
    # asking for the traversal member by name is refused outright
    with pytest.raises(it.InstallError):
        it.extract_member(arc, "../evil", dest)
    assert not (tmp_path / "evil").exists()
    # asking for a safe member still works, and the evil entry is ignored
    it.extract_member(arc, "faketool", dest)
    assert dest.read_bytes() == PAYLOAD
    assert not (tmp_path / "evil").exists()


def test_symlink_member_refused(tmp_path):
    arc = tmp_path / "link.tar.gz"

    def add_link(tf):
        info = tarfile.TarInfo("faketool")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)

    make_tar(arc, {}, extra=add_link)
    with pytest.raises(it.InstallError, match="not a regular file"):
        it.extract_member(arc, "faketool", tmp_path / "bin" / "faketool")
    assert not (tmp_path / "bin" / "faketool").exists()


def test_missing_member(tmp_path):
    arc = tmp_path / "a.tar.gz"
    make_tar(arc, {"something": b"x"})
    with pytest.raises(it.InstallError, match="not found"):
        it.extract_member(arc, "faketool", tmp_path / "faketool")


def test_non_https_refused(tmp_path):
    with pytest.raises(it.InstallError, match="non-https"):
        it.download("http://example.invalid/x", tmp_path / "x")


def write_lock(tmp_path) -> Path:
    lock = {
        "schema_version": 1,
        "install_dir": str(tmp_path / "bin"),
        "venv_dir": str(tmp_path / "venv"),
        "venv_python": "3.12",
        "tools": {
            "faketool": {
                "kind": "binary", "version": "1.2.3", "category": "secrets",
                "version_cmd": ["faketool"], "version_regex": r"(\d+\.\d+\.\d+)",
                "source": "https://example.invalid/fake.tar.gz", "sha256": "0" * 64,
                "archive_member": "faketool",
            },
            "faketool2": {
                "kind": "pip", "version": "9.9.9", "category": "sast", "package": "faketool2",
                "version_cmd": ["faketool2", "--version"], "version_regex": r"(\d+\.\d+\.\d+)",
            },
        },
    }
    p = tmp_path / "tools.lock.yaml"
    p.write_text(yaml.safe_dump(lock))
    return p


def test_dry_run_touches_nothing(tmp_path, monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("dry-run must not do network or subprocess work")

    monkeypatch.setattr(it, "download", boom)
    monkeypatch.setattr(it, "run", boom)
    monkeypatch.setattr(it.subprocess, "run", boom)
    lock = write_lock(tmp_path)
    rc = it.main(["--lock", str(lock), "--all", "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "[dry-run] faketool 1.2.3: download https://example.invalid/fake.tar.gz" in out
    assert "uv pip install faketool2==9.9.9" in out
    assert not (tmp_path / "bin").exists() and not (tmp_path / "venv").exists()


def test_main_exits_nonzero_on_failure(tmp_path, fake_net, capsys):
    arc = tmp_path / "fake.tar.gz"
    make_tar(arc, {"faketool": PAYLOAD})
    fake_net["https://example.invalid/fake.tar.gz"] = arc  # lock hash is 000..., so this must fail
    lock = write_lock(tmp_path)
    rc = it.main(["--lock", str(lock), "--tool", "faketool"])
    assert rc == 1
    assert "sha256 mismatch" in capsys.readouterr().err
    assert not (tmp_path / "bin" / "faketool").exists()


def test_main_success_and_idempotent(tmp_path, fake_net, capsys):
    script = b"#!/bin/sh\necho faketool 1.2.3\n"
    arc = tmp_path / "fake.tar.gz"
    sha = make_tar(arc, {"faketool": script})
    fake_net["https://example.invalid/fake.tar.gz"] = arc
    lock_path = write_lock(tmp_path)
    lock = yaml.safe_load(lock_path.read_text())
    lock["tools"]["faketool"]["sha256"] = sha
    lock_path.write_text(yaml.safe_dump(lock))
    assert it.main(["--lock", str(lock_path), "--tool", "faketool"]) == 0
    assert "installed" in capsys.readouterr().out
    # second run: already at pinned version, no download
    fake_net.clear()
    assert it.main(["--lock", str(lock_path), "--tool", "faketool"]) == 0
    assert "already installed" in capsys.readouterr().out


def test_unknown_tool_and_usage(tmp_path, capsys):
    lock = write_lock(tmp_path)
    assert it.main(["--lock", str(lock), "--tool", "nope"]) == 2
    assert it.main(["--lock", str(lock)]) == 2


def test_real_lock_file_is_well_formed():
    lock = it.load_lock(it.DEFAULT_LOCK)
    assert set(lock["tools"]) == {
        "gitleaks", "trufflehog", "osv-scanner", "trivy", "syft", "hadolint",
        "semgrep", "bandit", "pip-audit", "checkov",
    }
    for name, t in lock["tools"].items():
        assert t["version"] and t["version_cmd"] and t["version_regex"], name
        if t["kind"] == "binary":
            assert t["source"].startswith("https://") and len(t["sha256"]) == 64, name
            assert t["checksums_url"].startswith("https://"), name
        else:
            assert t["kind"] == "pip" and t["package"], name
