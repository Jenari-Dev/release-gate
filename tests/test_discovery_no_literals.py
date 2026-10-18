"""The discovery code path must plan from framework semantics, never from the
fixtures' answer keys. This test fails if a fixture-specific endpoint path,
canary string, coupon code or owner map literal appears in the discovery code.

If this test fails, someone taught the extractor the answers. That makes the
discovery score meaningless. Fix the code, not the test.
"""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DISCOVERY_CODE = [
    REPO / "skills" / "release-gate" / "scripts" / "extract_routes.py",
    REPO / "evals" / "discovery.py",
]

# Literals lifted straight from the fixtures / their answer keys. None of these
# may appear in code that is supposed to discover the surface on its own.
BANNED_SUBSTRINGS = [
    # fixture endpoint paths
    "/api/messages", "/api/fetch-preview", "fetch-preview", "/api/coupons",
    "coupons/redeem", "/api/comments", "/api/account", "/api/register", "/api/me",
    "/api/search",
    # fixture canaries / secrets / coupon codes
    "CANARY", "SSRF-CANARY", "PRIVATE-CANARY", "ALICE-PRIVATE", "BOB-PRIVATE",
    "WELCOME10",
    # hand-fed credentials / owner maps
    "alice-fixture-pw", "bob-fixture-pw",
]
# These names are conventions (login/signup/auth vocabulary), not fixture
# literals, and are allowed. Listed here so a reviewer sees the line was drawn
# deliberately.
ALLOWED_CONVENTION_WORDS = ["login", "signup", "register", "auth", "session", "token"]


@pytest.mark.parametrize("path", DISCOVERY_CODE, ids=lambda p: p.name)
def test_no_fixture_literals(path):
    text = path.read_text(encoding="utf-8")
    hits = [s for s in BANNED_SUBSTRINGS if s in text]
    assert not hits, f"{path.name} contains fixture-specific literal(s): {hits}"


def _code_lines(text):
    """Source with triple-quoted strings (docstrings) and # comments removed, so
    a mention of the guided plan in prose doesn't count as using it in code."""
    text = re.sub(r'"""[\s\S]*?"""', "", text)
    text = re.sub(r"'''[\s\S]*?'''", "", text)
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#"))


def test_discovery_imports_no_fixture_module():
    """discovery.py must not import or call the hand-fed guided plan."""
    code = _code_lines((REPO / "evals" / "discovery.py").read_text(encoding="utf-8"))
    assert "FIXTURE_PLANS" not in code
    # the guided plan builder is `_plan()`; our own `build_plan`/`build_authz_spec` are fine
    assert not re.search(r"(?<![\w])_plan\(", code)
    assert "import run_evals" not in code and "from run_evals" not in code
    assert "answer-key" not in code and "answer_key" not in code


def test_alice_bob_only_as_passed_in_seed():
    """The only place seeded names may appear in run_evals is the guided _plan();
    the discovery driver must take them as a parameter, not hardcode them."""
    runner = (REPO / "evals" / "run_evals.py").read_text(encoding="utf-8")
    # the discovery dynamic runner receives `seeded` as an argument
    assert "def run_dynamic_discovery(" in runner
    assert re.search(r"run_dynamic_discovery\([^)]*seeded", runner)
