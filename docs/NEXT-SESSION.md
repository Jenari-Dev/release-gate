# Next session: build session 3 of 4 — remaining phases + run modes

Paste the prompt below into a fresh Claude Code session started in `~/dev/release-gate`.

---

We're building `release-gate`, a Claude Code plugin at `~/dev/release-gate`. It runs an evidence-backed pre-release gate (security, privacy, legal drafts, ops) and gives a BLOCK / SHIP WITH ACCEPTED RISKS / SHIP verdict. Every result carries an evidence class, and the honesty rules are non-negotiable. This is **build session 3 of 4**. Sessions 1 and 2 built the foundation and the minimum viable skill (phases 0, 1, 2, 3, 7, 8, 13, the eval runner, and first measured scores). Read these first, in order:

1. `docs/BUILD-LOG.md` — what exists, what was verified, the measured eval scores, and the open issues (there are 5 carried forward).
2. `skills/release-gate/SKILL.md` — the 6 principles and the phase router. They bind everything you write.
3. `skills/release-gate/references/checks.yaml`, `schemas/*.json`, `scripts/rglib.py`, `scripts/report_build.py` — the contracts.
4. The phase references already written: `references/00,01,02,03,07,08,13-*.md` — match their style and depth.
5. `evals/run_evals.py`, `evals/probes.py` — the harness you will extend. The original spec Parts 4 (phases 4,5,6,9,10,11,12) and 3 (modes) if needed.

Rules carried over:
- Public repo identity is JenAriDev / Jenari-Dev only. No personal info, hostnames or local paths in committed files.
- No sudo. Tools only via `tools.lock.yaml` + `scripts/install_tools.py` (exact versions, official SHA-256 or pinned commit). Dev runs use `uv run --no-project --with pytest --with pyyaml --with jsonschema ...`. Installed tools live under `~/.local/share/release-gate` (bin/ + share root); check with `check_tools.py`.
- Dynamic tests only against the 127.0.0.1 fixtures. Never contact real third parties. semgrep runs offline with the vendored rules and `--jobs 1`.
- Subagents: implementation on Sonnet, lookups and test runs on Haiku, design/security review on Opus. Max 3–4 concurrent, batched, each scoped to its own files (sessions share this repo — other agents may be editing; touch only your paths, commit nothing until the end).
- Commit to our own repo at the end of the session. Never push without the user's OK.

## Goals for session 3
1. **Phase references + wiring for the remaining phases:** `04-correctness-testing`, `05-performance-stress`, `06-ops-resilience`, `09-platform-requirements`, `10-accessibility`, `11-supply-chain-licensing`, `12-ai-features`. Each a concrete playbook like the existing seven: which script/tool, how results map to the `check_id`s already in `checks.yaml`, evidence classes, adversarial triggers, and the exact NOT-TESTED reason when something can't run.
2. **`references/stacks/*`** — per-stack notes (python, node, go, rust, java, dotnet, php, unreal/unity, electron, tauri, android, ios, browser-extension): what to detect, which tools apply, stack-specific gotchas. Keep each short.
3. **Run modes** (spec Part 3): implement `quick`, `retest`, `ci`, `explain` as documented flows (SKILL router + a short reference each). `quick` = secrets + deps + fast SAST + existing tests + policy diff on changed files, no dynamic. `retest` = re-run only previously-failing checks and mark `FIXED` only when the original repro now fails. `ci` = generate `templates/ci/github-actions-release-gate.yml` + branch-protection advice. `explain <finding-id>` = plain-language explanation.
4. **Templates:** `templates/ci/github-actions-release-gate.yml`, `templates/k6/*` (load/stress/spike/soak), `templates/report/*` (self-contained HTML report template, no external assets).
5. **Close the session-2 open issues where cheap:** stamp `check_id` per tool in the static flow (issue #1); add a positive-control + more auth shapes to `authz_matrix.py` (issue #2); wire a ZAP baseline + nuclei safe-template smoke run into phase 03 / the eval (issue #5).
6. **Re-run `evals/run_evals.py` after each phase** and keep the scores table in `docs/BUILD-LOG.md` current. Add correctness/perf/ops coverage to the vuln fixtures' expectations only if you also add the detection for it — never loosen the honesty or verdict rules to make a number look better.

7. **Discovery-mode eval (priority, do this before adding new phases' eval expectations).** The session-2 scores are *guided*: `FIXTURE_PLANS` in `run_evals.py` hand-feeds each fixture's bug locations (IDOR endpoint + owned ids, SSRF target + canary, coupon code). See the "What these scores measure" note in BUILD-LOG. Add `run_evals.py --mode discovery` where the plan is built by the skill's own recon from the code:
   - A route/attack-surface extractor (e.g. `scripts/extract_routes.py`: Express `app/router.<method>()`, FastAPI decorators, Flask, plus OpenAPI when present) producing the endpoint list with auth requirements and path params.
   - The authz matrix generated from that list. Test users are created through the app's own signup flow where one exists, with the seeded fixture credentials only as a documented fallback ("seeded test DB" is allowed by spec phase 3).
   - SSRF tested against a canary listener the harness starts itself, not the fixture's built-in canary.
   - Anything the extractor can't plan stays SUSPECTED or NOT-TESTED, and is scored that way. A miss is a miss.
   - Allowed per-fixture inputs: port, start command, seeded credentials. Add a unit test that fails if the discovery code path contains fixture-specific endpoint, canary or coupon literals.
   - Report both tables in BUILD-LOG, clearly labeled **guided** vs **discovery**. Expect discovery to score lower. That is the honest number, so don't tune the extractor against the answer keys. Write the extractor from framework semantics, then measure.

Done when: `pytest` is green, a discovery-mode scores table exists next to the guided one, `run_evals.py` still produces the scores table with the vuln fixtures BLOCK (IDOR EXPLOITED) and the honesty fixtures never passing, the new phase references and stack notes exist, the four run modes are implemented and documented, BUILD-LOG is updated, everything is committed, and `docs/NEXT-SESSION.md` is rewritten for session 4.

## Session 4 (for orientation)
Polish and publish. Add an **end-to-end agent eval**: run the real skill headless (`claude -p` with the plugin loaded) on a copy of each fixture with the answer key removed, then score it with the same scorer. The README publishes guided, discovery and end-to-end numbers, each with a one-line description of what it measures. The rest: a final short SKILL.md, the README (demo cast, sample HTML report, limitations), a self-audit with release-gate and the Trail of Bits skills against this repo, and a visual check of the HTML report. Publish to GitHub only after the user confirms.
