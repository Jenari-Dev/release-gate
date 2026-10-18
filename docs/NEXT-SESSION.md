# Next session: build session 4 of 4 — end-to-end agent eval, polish, publish

Paste the prompt below into a fresh Claude Code session started in `~/dev/release-gate`.

---

We're building `release-gate`, a Claude Code plugin at `~/dev/release-gate`: an evidence-backed pre-release gate (security, privacy, legal drafts, ops) that returns a BLOCK / SHIP WITH ACCEPTED RISKS / SHIP verdict, with non-negotiable honesty rules. This is **build session 4 of 4 (the last)**. Sessions 1–3 are committed. Read these first, in order:

1. `docs/BUILD-LOG.md` — everything built and verified, the **guided** and **discovery** eval tables and what each measures, and the 4 open issues carried forward.
2. `skills/release-gate/SKILL.md` — the 6 principles and the phase/mode router. They bind everything.
3. `skills/release-gate/references/checks.yaml`, `schemas/*.json`, `scripts/*.py`, `references/13-report-and-verdict.md`, `evals/run_evals.py`, `evals/discovery.py`, `evals/probes.py` — the contracts and the harness you will extend.

Rules carried over (unchanged):
- Public repo identity is **JenAriDev / Jenari-Dev only**. No personal info, hostnames or local absolute paths in committed files.
- No sudo. Tools only via `tools.lock.yaml` + `scripts/install_tools.py` (exact versions, official SHA-256 or pinned commit). Dev runs: `uv run --no-project --with pytest --with pyyaml --with jsonschema ...` (never bare `uv run` — it creates `.venv`/`uv.lock`). Installed tools live under `~/.local/share/release-gate`.
- Dynamic tests only against the 127.0.0.1 fixtures. Never contact real third parties. semgrep runs offline with the vendored rules and `--jobs 1`.
- Subagents: implementation on Sonnet, lookups/test-runs on Haiku, design/security review on Opus. Max 3–4 concurrent, batched, each scoped to its own files (sessions share this repo — touch only your paths, commit nothing until the end).
- **Commit to our own repo at the end. Publish to GitHub only after the user confirms.** Never push without the user's OK.

## Goals for session 4 (final)
1. **End-to-end agent eval (priority).** Run the *real skill* headless on each fixture with the answer key removed, then score it with the same scorer, so the README can publish guided / discovery / end-to-end numbers side by side.
   - Add `evals/run_agent_eval.py`: for each fixture, copy it to a scratch dir **without `answer-key.yaml`**, boot it on loopback, then invoke the skill headless — `claude -p` with this plugin loaded (marketplace at `.claude-plugin/`) and a fixed prompt like "run /release-gate full on this project; scope is the local instance at <url>". Capture the produced `.release-gate/findings.json` + report and score it with the existing `score_fixture` path.
   - Headless Claude may be unavailable/non-deterministic in CI: if `claude` is not on PATH or the run errors, record the fixture as `NOT-TESTED: headless agent unavailable` — never fabricate a score. Keep the run opt-in (`--agent`), off by default, documented.
   - Expect end-to-end to differ from discovery (the agent also does manual code review, adversarial verification, and judgement). Report the honest number with a one-line description of what it measures. Do not tune the skill against the keys.
2. **Run the real adversarial-verification subagent in a measured path** (closes open issue #1): a mode where a critical VERIFIED-ABSENT is only accepted when a fresh subagent tried to break it and `upheld` it, so a clean fixture can reach bare SHIP. Show that path at least once (can be inside the agent eval).
3. **README** (`README.md`): what it is, install, the 6 principles in brief, a demo (asciinema/`demo.cast` or a short transcript), a **sample HTML report** rendered from `templates/report/report.html.tmpl` on a real fixture run, the three eval numbers each with its one-line "what it measures", and an explicit **Limitations** section (not a pentest, discovery coverage gaps from BUILD-LOG issues 2–4, scanner network disclosure, legal drafts are not legal advice).
4. **Self-audit**: run release-gate (and the Trail of Bits skills if available) against this repo itself; fix what's cheap, record the rest as waivers/known-issues. Visually check the generated HTML report (open it; confirm CSP, light/dark, evidence-class badges, no external requests).
5. **Final SKILL.md pass**: flip the BUILD STATUS banner to "complete / v1", confirm every phase+mode reference and script in the router exists, and that the "report NOT-TESTED, never improvise" rule is prominent.
6. **Cheap leftovers from session 3 (BUILD-LOG open issues):** if cheap, wire a ZAP baseline / nuclei safe-template smoke into the phase-03 eval path (issue 3); consider an OpenAPI-ownership or create-endpoint hint so discovery's FastAPI IDOR can reach EXPLOITED (issue 2) — only if it stays honest (no answer-key literals; `test_discovery_no_literals.py` must still pass). Do not loosen honesty or verdict rules to improve a number.

Done when: `pytest` is green; `run_evals.py --mode both` still produces the two tables (vuln BLOCK, honesty never pass, clean twins no false positives); an end-to-end agent table exists (or is honestly NOT-TESTED where headless Claude isn't available); the README publishes all three eval numbers with labels and a Limitations section; a sample HTML report is in the repo and has been visually checked; the self-audit is recorded; SKILL.md is finalized; everything is committed. Then ask the user before publishing to GitHub.
