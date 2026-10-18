"""Shared helpers for release-gate scripts.

Everything here is deliberately small and stdlib-first. PyYAML is required for
the .yaml state files; jsonschema is optional and only needed for validate().
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

SKILL_DIR = Path(__file__).resolve().parent.parent
SCHEMA_DIR = SKILL_DIR / "schemas"
LOCK_FILE = SKILL_DIR / "tools.lock.yaml"

STATE_DIRNAME = ".release-gate"
STATE_SUBDIRS = ("evidence", "history", "reports")

EVIDENCE_CLASSES = ("EXPLOITED", "TOOL-CONFIRMED", "SUSPECTED", "VERIFIED-ABSENT", "NOT-TESTED")
# Classes that claim something was actually observed, so they need an artifact.
ARTIFACT_REQUIRED = frozenset({"EXPLOITED", "TOOL-CONFIRMED", "VERIFIED-ABSENT"})
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CRITICAL_CATEGORIES = frozenset({"authn", "authz", "injection", "secrets", "data-exposure"})


# --------------------------------------------------------------------------- time

def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def stamp() -> str:
    """Filesystem-safe UTC timestamp, e.g. 20261018T120301Z."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_date(value: Any) -> _dt.date:
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    return _dt.date.fromisoformat(str(value)[:10])


# --------------------------------------------------------------------------- files

def state_dir(project: str | Path, create: bool = True) -> Path:
    root = Path(project).resolve() / STATE_DIRNAME
    if create:
        root.mkdir(exist_ok=True)
        for sub in STATE_SUBDIRS:
            (root / sub).mkdir(exist_ok=True)
    return root


def _yaml():
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment problem, not logic
        raise SystemExit("release-gate needs PyYAML: uv pip install pyyaml") from exc
    return yaml


def load_data(path: str | Path, default: Any = None) -> Any:
    """Load .yaml/.yml/.json. Returns `default` if the file does not exist."""
    p = Path(path)
    if not p.exists():
        return default
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".json":
        return json.loads(text) if text.strip() else default
    data = _yaml().safe_load(text)
    return default if data is None else data


def dump_data(path: str | Path, data: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.suffix == ".json":
        p.write_text(json.dumps(data, indent=2, sort_keys=False, default=str) + "\n", encoding="utf-8")
    else:
        p.write_text(_yaml().safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return p


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- schemas

def load_schema(name: str) -> dict:
    fname = name if name.endswith(".json") else f"{name}.schema.json"
    return json.loads((SCHEMA_DIR / fname).read_text(encoding="utf-8"))


def validate(obj: Any, schema_name: str) -> list[str]:
    """Return a list of human-readable schema errors (empty list = valid)."""
    try:
        import jsonschema  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("schema validation needs jsonschema: uv pip install jsonschema") from exc
    schema = load_schema(schema_name)
    validator = jsonschema.Draft202012Validator(schema)
    errors = []
    for err in sorted(validator.iter_errors(obj), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"{where}: {err.message}")
    return errors


# --------------------------------------------------------------------------- secrets

# Patterns for credentials that must never appear unredacted in a report.
# Kept specific on purpose: false positives here block reports.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

REDACTION_MARK = "…[REDACTED]"


def redact_value(value: str, keep: int = 4) -> str:
    """Show only the first `keep` characters of a secret."""
    value = str(value)
    return value[:keep] + REDACTION_MARK


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return (kind, match) for unredacted secrets in text."""
    hits = []
    for kind, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            hits.append((kind, m.group(0)))
    return hits


def redact_text(text: str) -> str:
    """Replace every recognised secret with its first 4 chars + redaction mark."""
    for kind, pat in SECRET_PATTERNS:
        if kind == "private-key":
            text = pat.sub("-----BEGIN PRIVATE KEY" + REDACTION_MARK, text)
        else:
            text = pat.sub(lambda m: redact_value(m.group(0)), text)
    return text


# --------------------------------------------------------------------------- ids

def next_id(category: str, existing: Iterable[str]) -> str:
    prefix = "RG-" + re.sub(r"[^A-Z0-9]", "", category.upper())[:12] + "-"
    nums = [int(i[len(prefix):]) for i in existing if i.startswith(prefix) and i[len(prefix):].isdigit()]
    return f"{prefix}{(max(nums) + 1) if nums else 1:03d}"


# --------------------------------------------------------------------------- scope

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})
DESTRUCTIVE_TESTS = frozenset({"fuzz", "stress", "spike", "soak"})


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url if "://" in url else f"http://{url}")
    host = (parts.hostname or "").lower()
    port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
    return parts.scheme, host, port


def check_scope(url: str, test_type: str, scope: dict | None) -> tuple[bool, str]:
    """Decide whether `test_type` may be run against `url`.

    Fails closed: no scope file, unknown target, or a disallowed test type all
    return (False, reason).
    """
    if not scope or not scope.get("targets"):
        return False, "no confirmed scope (.release-gate/scope.yaml missing or empty)"
    scheme, host, port = _origin(url)
    if scheme not in ("http", "https", "ws", "wss"):
        return False, f"unsupported URL scheme {scheme!r} (only http/https/ws/wss targets are testable)"
    excluded = {h.lower() for h in scope.get("excluded_hosts", [])}
    if host in excluded:
        return False, f"{host} is an excluded third-party host"
    for target in scope["targets"]:
        t_scheme, t_host, t_port = _origin(target["url"])
        if (t_host, t_port) != (host, port):
            continue
        env = target.get("environment")
        allowed = target.get("allowed_tests")
        if env == "production":
            if not target.get("production_confirmation") or target["url"].rstrip("/") not in target["production_confirmation"]:
                return False, "production target without a typed confirmation naming its URL"
            if test_type in DESTRUCTIVE_TESTS:
                return False, f"{test_type} is never run against production"
        if env != "local" and not target.get("owned_confirmed"):
            return False, f"{target['url']} not confirmed as owned by the user"
        if allowed is not None and test_type not in allowed:
            return False, f"{test_type} not in allowed_tests for {target['url']}"
        return True, f"in scope: {target['url']} ({env})"
    return False, f"{host}:{port} is not a confirmed target"
