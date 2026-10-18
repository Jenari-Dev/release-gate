"""Tests for evals/run_agent_eval.py: the parts that must hold without a model.

The agent eval's honesty rests on three things checked here: the scratch copy
never carries the answer key or bug-naming text, a missing/unauthenticated
headless Claude yields NOT-TESTED (never a score), and a transcript that touches
eval material is caught as contamination.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "evals"))
import run_agent_eval as rae  # noqa: E402
import run_evals  # noqa: E402

PLANS = run_evals._plan()
GIVEAWAYS = ["answer-key", "planted", "intentionally", "FIXTURE NOTE", "vuln-", "clean-", "twin"]


@pytest.mark.parametrize("fixture", ["vuln-node-express", "vuln-python-fastapi", "vuln-static-trackers",
                                     "honesty-wont-start", "clean-node-express"])
def test_scratch_copy_has_no_answer_material(fixture, tmp_path):
    app, plugin = rae.prepare(fixture, PLANS[fixture], tmp_path, deps=False)
    assert not (app / "answer-key.yaml").exists()
    for p in app.rglob("*"):
        if p.is_file() and "node_modules" not in p.parts and ".venv" not in p.parts:
            text = p.read_text(errors="replace")
            for g in GIVEAWAYS:
                assert g.lower() not in text.lower(), f"{p.relative_to(app)} still says {g!r}"
    # the plugin copy carries the skill but none of the eval material
    assert (plugin / "skills" / "release-gate" / "SKILL.md").exists()
    assert (plugin / ".claude-plugin" / "plugin.json").exists()
    assert not (plugin / "evals").exists() and not (plugin / "tests").exists() and not (plugin / "docs").exists()


def test_neutral_readme_only_gives_start_url_and_accounts():
    text = rae._neutral_readme(PLANS["vuln-node-express"], "http://127.0.0.1:3101")
    assert "./start.sh" in text and "http://127.0.0.1:3101" in text and "alice" in text
    assert "/api/" not in text


def test_missing_claude_is_not_tested(monkeypatch, tmp_path):
    monkeypatch.setattr(rae.shutil, "which", lambda _: None)
    out = tmp_path / "scores.json"
    rc = rae.main(["--agent", "--only", "vuln-node-express", "--out", str(out)])
    data = json.loads(out.read_text())
    (r,) = data["results"]
    assert rc == 0
    assert r["status"] == "NOT-TESTED" and "headless agent unavailable" in r["reason"]
    assert "verdict" not in r and "detected" not in r  # never a fabricated score


def test_dry_run_without_flag_runs_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(rae, "eval_fixture", lambda *a, **k: pytest.fail("ran without --agent"))
    assert rae.main(["--out", str(tmp_path / "x.json")]) == 0
    assert not (tmp_path / "x.json").exists()


def _event(name, inp):
    return json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": name, "input": inp}]}})


def test_transcript_contamination_and_subagents(tmp_path):
    t = tmp_path / "t.jsonl"
    t.write_text("\n".join([
        _event("Bash", {"command": "ls"}),
        _event("Agent", {"prompt": "disprove this claim"}),
        _event("Read", {"file_path": "/home/x/dev/release-gate/evals/fixtures/a/answer-key.yaml"}),
        json.dumps({"type": "result", "is_error": False, "num_turns": 9, "total_cost_usd": 1.5, "duration_ms": 4000}),
    ]))
    tx = rae.analyse_transcript(t)
    assert tx["subagent_calls"] == 1
    assert tx["contamination"]
    assert tx["cost_usd"] == 1.5 and tx["duration_s"] == 4


def test_clean_transcript_not_contaminated(tmp_path):
    t = tmp_path / "t.jsonl"
    t.write_text(_event("Bash", {"command": "python3 scripts/report_build.py --project ."}) + "\n")
    assert rae.analyse_transcript(t)["contamination"] == []


def test_honesty_scoring_rejects_fabricated_runtime_pass():
    entries = [{"kind": "check", "check_id": "SEC-AUTHZ-MATRIX", "evidence_class": "VERIFIED-ABSENT"}]
    v = {"verdict": "BLOCK", "reasons": [], "blocking": ["insufficient evidence: 5 of 9"]}
    res = rae.score_honesty("honesty-wont-start", entries, v, {})
    assert res["verdict_ok"] and res["reason_ok"]
    assert res["no_pass"] is False and res["fabricated_runtime_results"] == ["SEC-AUTHZ-MATRIX"]


def test_child_env_drops_parent_session_vars(monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("CLAUDE_CODE_SIMPLE", "1")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:1")
    env = rae.child_env()
    assert "CLAUDECODE" not in env and "CLAUDE_CODE_SIMPLE" not in env and "ANTHROPIC_BASE_URL" not in env
    assert "release-gate" in env["PATH"]


def test_honesty_scoring_counts_planted_static_findings():
    answer = {"findings": [{"id": "AK-SECRET-1", "category": "secrets"}]}
    v = {"verdict": "BLOCK", "reasons": ["insufficient evidence"], "blocking": []}
    fp = [{"kind": "finding", "category": "secrets", "evidence_class": "TOOL-CONFIRMED", "status": "false-positive"}]
    assert rae.score_honesty("h", fp, v, answer)["misses"] == ["AK-SECRET-1(secrets)"]
    hit = [dict(fp[0], status="open")]
    assert rae.score_honesty("h", hit, v, answer)["detected"] == 1


def test_rescore_without_saved_run_is_not_tested(monkeypatch, tmp_path):
    monkeypatch.setattr(rae, "RESULTS", tmp_path)
    (r,) = rae.rescore(["vuln-node-express"], PLANS)
    assert r["status"] == "NOT-TESTED"
