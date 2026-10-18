#!/usr/bin/env python3
"""Install the pinned release-gate tool set from tools.lock.yaml.

Rules this script enforces:
  * every version is an exact pin from the lock file, no "latest";
  * binaries are downloaded over https to a temp dir and their sha256 is
    verified BEFORE anything is extracted; a mismatch deletes the download
    and fails the tool;
  * only the single named archive member is extracted, never extractall(),
    and member names are rejected if absolute or containing "..";
  * pip tools go through `uv venv` + `uv pip install name==version`;
  * nothing is ever piped to a shell and no install scripts are fetched.

Dependencies: Python stdlib + PyYAML. Exit status is non-zero if any
requested tool fails.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

import yaml

DEFAULT_LOCK = Path(__file__).resolve().parent.parent / "tools.lock.yaml"
USER_AGENT = "release-gate-installer"
CHUNK = 1 << 20


class InstallError(Exception):
    """A tool could not be installed safely."""


# --------------------------------------------------------------------------
# lock file
# --------------------------------------------------------------------------
def expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path)))


def load_lock(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        lock = yaml.safe_load(fh)
    if not isinstance(lock, dict) or lock.get("schema_version") != 1:
        raise InstallError(f"{path}: unsupported or missing schema_version")
    for key in ("install_dir", "venv_dir", "tools"):
        if key not in lock:
            raise InstallError(f"{path}: missing '{key}'")
    return lock


# --------------------------------------------------------------------------
# hashing / download
# --------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    if not url.lower().startswith("https://"):
        raise InstallError(f"refusing non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as out:  # noqa: S310
        shutil.copyfileobj(resp, out, CHUNK)


def checksum_from_listing(text: str, asset_name: str) -> str | None:
    """Return the sha256 listed for asset_name in a `sha256sum`-style file."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == asset_name:
            return parts[0].lower()
    return None


def verify_sha256(path: Path, expected: str) -> None:
    actual = sha256_file(path)
    if actual != expected.lower():
        raise InstallError(f"sha256 mismatch for {path.name}: expected {expected}, got {actual}")


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------
def normalize_member(name: str) -> str:
    """Normalise an archive member name; raise if it could escape a directory."""
    if not name or "\\" in name or "\x00" in name:
        raise InstallError(f"unsafe archive member name: {name!r}")
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts:
        raise InstallError(f"unsafe archive member name: {name!r}")
    return str(p)  # PurePosixPath drops a leading "./" and duplicate slashes


def _write_executable(src, dest: Path) -> None:
    """Copy file object src to dest atomically and chmod it +x."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
    try:
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(src, out, CHUNK)
        mode = os.stat(tmp).st_mode
        os.chmod(tmp, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_IRUSR)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def extract_member(archive: Path, member: str, dest: Path) -> None:
    """Extract exactly one regular-file member of a tar/zip archive to dest.

    The output path is chosen by the caller, never taken from the archive, and
    the member name is validated, so a hostile archive cannot write elsewhere.
    """
    wanted = normalize_member(member)
    if tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            for info in tf.getmembers():
                try:
                    name = normalize_member(info.name)
                except InstallError:
                    continue  # never match an unsafe entry
                if name != wanted:
                    continue
                if not info.isreg():
                    raise InstallError(f"archive member {member!r} is not a regular file")
                fh = tf.extractfile(info)
                if fh is None:
                    raise InstallError(f"cannot read archive member {member!r}")
                with fh:
                    _write_executable(fh, dest)
                return
    elif zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                try:
                    name = normalize_member(info.filename)
                except InstallError:
                    continue
                if name != wanted or info.is_dir():
                    continue
                with zf.open(info) as fh:
                    _write_executable(fh, dest)
                return
    else:
        raise InstallError(f"{archive.name} is not a tar or zip archive")
    raise InstallError(f"member {member!r} not found in {archive.name}")


# --------------------------------------------------------------------------
# per-kind installers
# --------------------------------------------------------------------------
def install_binary(name: str, spec: dict, install_dir: Path, workdir: Path | None = None) -> Path:
    source = spec["source"]
    expected = spec.get("sha256")
    if not expected:
        raise InstallError(f"{name}: lock entry has no sha256")
    dest = install_dir / name
    with tempfile.TemporaryDirectory(prefix=f"rg-{name}-", dir=workdir) as tmp:
        tmpdir = Path(tmp)
        asset = tmpdir / source.rsplit("/", 1)[-1]
        download(source, asset)
        verify_sha256(asset, expected)  # before any extraction
        # Cross-check the pinned hash against the project's own checksums file.
        if spec.get("checksums_url") and spec.get("checksum_source") != "computed-local":
            listing = tmpdir / "checksums.txt"
            download(spec["checksums_url"], listing)
            listed = checksum_from_listing(listing.read_text(encoding="utf-8", errors="replace"), asset.name)
            if listed is None:
                raise InstallError(f"{name}: {asset.name} not listed in {spec['checksums_url']}")
            if listed != expected.lower():
                raise InstallError(f"{name}: lock sha256 disagrees with published checksums file")
        member = spec.get("archive_member")
        if member:
            extract_member(asset, member, dest)
        else:
            with open(asset, "rb") as fh:
                _write_executable(fh, dest)
    return dest


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)  # noqa: S603


def ensure_venv(lock: dict) -> Path:
    venv = expand(lock["venv_dir"])
    py = venv / "bin" / "python"
    want = str(lock.get("venv_python", ""))
    if py.exists():
        have = run([str(py), "-c", "import sys;print('%d.%d'%sys.version_info[:2])"]).stdout.strip()
        if not want or have == want:
            return venv
    cmd = ["uv", "venv", "--clear", str(venv)]
    if want:
        cmd += ["--python", want]
    venv.parent.mkdir(parents=True, exist_ok=True)
    run(cmd)
    return venv


def install_pip(name: str, spec: dict, lock: dict, install_dir: Path) -> Path:
    version = str(spec["version"])
    package = spec.get("package", name)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", package) or not re.fullmatch(r"\d[\w.+!-]*", version):
        raise InstallError(f"{name}: invalid package/version in lock")
    venv = ensure_venv(lock)
    run(["uv", "pip", "install", "--python", str(venv / "bin" / "python"), f"{package}=={version}"])
    exe = venv / "bin" / name
    if not exe.exists():
        raise InstallError(f"{name}: {exe} missing after pip install")
    link = install_dir / name
    install_dir.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(exe)
    return link


# --------------------------------------------------------------------------
# verification / status
# --------------------------------------------------------------------------
def probe_version(name: str, spec: dict, install_dir: Path) -> str | None:
    """Run the tool's version_cmd from install_dir; return the parsed version or None."""
    cmd = list(spec["version_cmd"])
    exe = install_dir / cmd[0]
    if not exe.exists():
        return None
    cmd[0] = str(exe)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(spec["version_regex"], (res.stdout or "") + "\n" + (res.stderr or ""))
    return m.group(1) if m else None


def install_one(name: str, lock: dict, install_dir: Path) -> str:
    spec = lock["tools"][name]
    kind = spec.get("kind")
    if kind == "binary":
        install_binary(name, spec, install_dir)
    elif kind == "pip":
        install_pip(name, spec, lock, install_dir)
    else:
        raise InstallError(f"{name}: kind {kind!r} is not installable by this script")
    got = probe_version(name, spec, install_dir)
    if got is None:
        raise InstallError(f"{name}: installed but `{' '.join(spec['version_cmd'])}` did not report a version")
    if got != str(spec["version"]):
        raise InstallError(f"{name}: expected {spec['version']}, reports {got}")
    return got


def dry_run_line(name: str, spec: dict, lock: dict, install_dir: Path) -> str:
    kind = spec.get("kind")
    if kind == "binary":
        member = spec.get("archive_member")
        how = f"extract '{member}'" if member else "install bare executable"
        return (f"{name} {spec['version']}: download {spec['source']}; verify sha256 {spec.get('sha256')}; "
                f"{how} -> {install_dir / name}")
    if kind == "pip":
        py = lock.get("venv_python", "default")
        return (f"{name} {spec['version']}: uv venv {lock['venv_dir']} (python {py}); "
                f"uv pip install {spec.get('package', name)}=={spec['version']}; link -> {install_dir / name}")
    return f"{name} {spec.get('version')}: kind {kind!r} not installable by this script"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lock", type=Path, default=DEFAULT_LOCK, help="path to tools.lock.yaml")
    ap.add_argument("--list", action="store_true", help="list locked tools and install status")
    ap.add_argument("--tool", action="append", metavar="NAME", help="install this tool (repeatable)")
    ap.add_argument("--all", action="store_true", help="install every locked tool")
    ap.add_argument("--dry-run", action="store_true", help="show what would happen; no network, no writes")
    ap.add_argument("--force", action="store_true", help="reinstall even if the pinned version is present")
    args = ap.parse_args(argv)

    try:
        lock = load_lock(args.lock)
    except (OSError, yaml.YAMLError, InstallError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    install_dir = expand(lock["install_dir"])
    tools = lock["tools"]

    if args.list:
        for name, spec in tools.items():
            have = probe_version(name, spec, install_dir) if spec.get("version_cmd") else None
            status = f"installed {have}" if have else "not installed"
            print(f"{name:14} {spec.get('kind'):7} {spec.get('category', '-'):8} pinned {spec['version']:10} {status}")
        if not (args.tool or args.all):
            return 0

    if not (args.tool or args.all):
        if not args.list:
            ap.print_usage(sys.stderr)
            print("error: give --list, --all or --tool NAME", file=sys.stderr)
            return 2
        return 0

    names = list(tools) if args.all else args.tool
    unknown = [n for n in names if n not in tools]
    if unknown:
        print(f"error: unknown tool(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    failed: list[str] = []
    for name in names:
        spec = tools[name]
        if args.dry_run:
            print("[dry-run] " + dry_run_line(name, spec, lock, install_dir))
            continue
        if not args.force and probe_version(name, spec, install_dir) == str(spec["version"]):
            print(f"[ok] {name} {spec['version']} already installed")
            continue
        try:
            got = install_one(name, lock, install_dir)
            print(f"[ok] {name} {got} installed")
        except (InstallError, OSError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as exc:
            detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else exc
            print(f"[FAIL] {name}: {detail}", file=sys.stderr)
            failed.append(name)
        except Exception as exc:  # urllib errors etc.; never leave a tool half-reported
            print(f"[FAIL] {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            failed.append(name)

    if failed:
        print(f"{len(failed)} tool(s) failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
