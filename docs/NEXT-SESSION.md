# Next session: build session 2 of 4 — minimum viable skill

Paste the prompt below into a fresh Claude Code session started in `~/dev/release-gate`.

---

We're building `release-gate`, a Claude Code plugin at `~/dev/release-gate`. It runs an evidence-backed pre-release gate (security, privacy, legal drafts, ops) and gives a BLOCK / SHIP WITH ACCEPTED RISKS / SHIP verdict. Every result carries an evidence class, and the honesty rules are non-negotiable. This is **build session 2 of 4**. Session 1 built the foundation. Read these first, in order:

1. `docs/BUILD-LOG.md`: what exists, what was verified, open issues.
2. `skills/release-gate/SKILL.md`: the principles. They bind everything you write.
3. `skills/release-gate/references/checks.yaml`, `schemas/*.json`, `scripts/rglib.py`, `scripts/report_build.py`: the contracts you build on.
4. The original spec, if needed: Parts 4 (phases 0, 1, 2, 3, 7, 8, 13) and 6 (evals).

Rules carried over:
- Public repo identity is JenAriDev / Jenari-Dev only. No personal info, hostnames or local paths in committed files.
- No sudo. Tools only via `tools.lock.yaml` + `scripts/install_tools.py` (exact versions, official SHA-256). Dev venv: `.venv/bin/python` (`uv pip install --python .venv/bin/python pyyaml jsonschema pytest`).
- Dynamic tests only against the 127.0.0.1 fixtures. Never contact real third parties.
- Subagents: implementation on Sonnet, lookups and test runs on Haiku, design and security review on Opus. Max 3–4 concurrent, batched.
- Commit to our own repo at the end of the session. Never push without the user's OK.

## Goals for session 2
1. **Fix open issue #1 first.** Vendor pinned semgrep rules (no registry fetch at runtime). Disclose and offer offline modes for osv-scanner and trivy network use in SKILL.md and README.
2. **Install session-2 tools** through the lock: OWASP ZAP (Java 21 is at `/usr/lib/jvm/java-21-openjdk`), nuclei (pin the templates too), and Playwright + Chromium via npm in a skill-local dir.
3. **Phase references:** `00-intake`, `01-recon-and-data-map`, `02-static-security`, `03-dynamic-security`, `07-privacy-compliance`, `08-legal-documents`, `13-report-and-verdict`. Each one is a concrete playbook: which script or tool to run, how to map results to `check_id`s and evidence classes, when to spawn the adversarial subagent, and what NOT-TESTED reason to record when something can't run.
4. **Scripts with tests:**
   - `data_inventory_scan.py`
   - `authz_matrix.py`: roles × endpoints × other users' resources. Must turn the fixture IDORs into EXPLOITED with saved request/response, and the clean twins into VERIFIED-ABSENT.
   - `cookie_audit.mjs`: Playwright, three stages: before consent, after reject, after accept.
   - `policy_consistency.py`
5. **Law reference data** `references/law/*.yaml` for the 10 regimes in the spec. Use only facts from official sources fetched this session, each with `source_url` + `last_verified`. Leave out anything unverified rather than guess.
6. **Legal templates** `templates/legal/*`. Each must start with the mandatory DRAFT / not-legal-advice header (SKILL.md principle 4). Every privacy-policy statement must trace to an inventory entry.
7. **Eval runner** `evals/run_evals.py`:
   - Boot each fixture by waiting on its port (up to 60s).
   - Run the pipeline and score it against `answer-key.yaml`: detection per category, false-positive rate on the clean twins, evidence-class correctness, verdict correctness, and the honesty cases (`honesty-wont-start`, plus a PATH-stripped no-tools run).
   - Resolve open issue #2 (clean-fixture verdict) and document the decision.
   - Record the first measured scores in `docs/BUILD-LOG.md`.
8. Update the SKILL.md router to point at the new references. Keep it short.

Done when: pytest is green, `run_evals.py` produces a scores table, the vuln fixtures come out BLOCK with the planted IDOR as EXPLOITED, the honesty fixture is BLOCK "insufficient evidence", BUILD-LOG is updated, everything is committed, and `docs/NEXT-SESSION.md` is rewritten for session 3.

## Later sessions (for orientation)
- **Session 3:** phases 4, 5, 6, 9, 10, 11 and 12, `references/stacks/*`, and the modes quick / retest / ci / explain / legal. Re-run the evals after each phase.
- **Session 4:** polish and publish. That covers a final short SKILL.md, the README (demo cast, sample HTML report, eval table, limitations), a self-audit with release-gate and the Trail of Bits skills, and a visual check of the HTML report. Publish to GitHub only after the user confirms.
