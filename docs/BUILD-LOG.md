# Build log

## Session 1 — 2026-10-18 — foundation + fixtures

### Built
- Plugin skeleton: `.claude-plugin/plugin.json`, `marketplace.json`, MIT `LICENSE`, `SECURITY.md`, `DISCLAIMER.md`, `.gitignore`, `pyproject.toml`, repo `.gitleaks.toml`.
- Schemas (`skills/release-gate/schemas/`): finding (with `kind` finding|check, `check_id`, evidence class rules enforced by `allOf`), data-inventory (every entry carries provenance `code` + file:line or `user`), config (incl. `surface`), scope (production restrictions), waivers.
- Check catalog `references/checks.yaml`: 46 checks across phases 1–12, each with `critical`, `modes`, `applies_when`. Drives the coverage matrix, so checks with no recorded result appear as NOT-TESTED instead of vanishing.
- Scripts: `rglib.py` (shared: state dir, YAML/JSON, schema validation, secret patterns + redaction, ids, fail-closed scope check), `detect_stack.py`, `check_tools.py`, `run_tool.py`, `install_tools.py`, `normalize_findings.py` (13 formats + SARIF aliases), `dedupe_findings.py`, `report_build.py`, `report_lint.py`.
- `tools.lock.yaml`: gitleaks 8.30.1, trufflehog 3.97.9, osv-scanner 2.6.0, trivy 0.75.0, syft 1.54.0, hadolint 2.15.1 (binaries, SHA-256 from official checksum files); semgrep 1.179.0, bandit 1.9.4, pip-audit 2.10.1, checkov 3.3.22 (uv venv, Python 3.12). All 10 installed in `~/.local/share/release-gate/` and `check_tools.py` reports them `ok`.
- Eval fixtures (`evals/fixtures/`): vuln + clean twins for Node/Express (3101/3102), Python/FastAPI (3103/3104), static site + trackers (3105/3106), and `honesty-wont-start` (exits 1, missing DATABASE_URL). Answer keys list each planted bug with category, expected evidence class, location and observed repro.

### Verdict rules implemented (report_build.py)
Spec 13.1 plus two deliberate tightenings, both documented in the module docstring:
1. EXPLOITED critical/high blocks even if waived (a proven hole is not an accepted risk).
2. Full mode fails closed: if half or more of the expected critical checks are NOT-TESTED (other than user-skipped), verdict is BLOCK "insufficient evidence". Otherwise a run where nothing worked would read SHIP WITH ACCEPTED RISKS.
A critical-category VERIFIED-ABSENT only counts toward SHIP when adversarial verification `upheld` it. Legal mode returns NOT-EVALUATED.

### Verified (by the main session, not just reported)
- `pytest`: 221 passed.
- Real-tool round trip on scratch copies of both vuln apps: gitleaks, semgrep, osv-scanner, trivy, bandit, pip-audit via `run_tool.py` → `normalize_findings.py --auto` → `dedupe_findings.py` → `report_build.py --mode quick` → lint clean, verdict BLOCK, planted secret absent from every report file.
  - Found and fixed 3 bugs this way: scanners re-reading `.release-gate/evidence` (now dropped as self-artifacts), absolute paths from osv-scanner (now relative), `--auto` noise on run_tool's `result.json`. Regression tests added.
- Fixture repro, run by the main session with the fixtures' `_repro` scripts:
  - vuln-node-express: IDOR, SQLi (hash dump), stored XSS, SSRF (canary read), no rate limit (12×401), password in log, coupon race (10/10 redeemed) all reproduce. clean twin: 404, `[]`, escaped HTML, 403, 429 after 4, no password in log, 1/10 redeemed.
  - vuln-python-fastapi: IDOR, SQLi, SSRF, no rate limit, password in log, fake deletion (login after delete = 200), policy says "never share" while emails reach the analytics host. clean twin blocks each one (deleted user login = 401, analytics host receives nothing).
  - Static tracker pair: verified by the fixtures session in a real browser; NOT re-verified by the main session (needs Playwright, comes with `cookie_audit.mjs` in session 2).
- Detection seen from static tools alone (useful baseline for session 2 evals): secrets and vulnerable deps found on both vuln apps; semgrep `p/default` found the Python SQLi but not the Node SQLi; nothing static finds IDOR, race, rate limit, fake deletion or policy mismatch. Those need phases 3/7/8.

### Open issues found this session (carry forward)
1. **Network use by scanners vs principle 1.5.** `semgrep --config p/default` downloads rules from the registry at runtime: that is "fetching rules from the network". Fix in session 2: vendor a pinned semgrep-rules snapshot (commit SHA + sha256 in `tools.lock.yaml`, installed by `install_tools.py`) and run with `--config <local path> --metrics off`. osv-scanner queries api.osv.dev with package names/versions, trivy downloads its vuln DB. These send dependency metadata, not code, but must be disclosed in SKILL.md/README and offer offline modes (`osv-scanner --offline-vulnerabilities --download-offline-databases`, `trivy --skip-db-update` with a pre-fetched DB).
2. **Clean-fixture expected verdict.** Answer keys say SHIP. That needs every critical check VERIFIED-ABSENT and adversarial-upheld. Decide in the eval scorer whether SHIP WITH ACCEPTED RISKS on a clean fixture counts as correct when the only caps are legitimate NOT-TESTED reasons (e.g. no trufflehog verification possible offline).
3. `normalize_findings.py` test samples were written from memory of each tool's format; the 6 formats exercised above are now proven against real output. ZAP, nuclei, npm audit, checkov, hadolint, trufflehog JSON still need a real-output check when those tools run in session 2.
4. Fixture cold boot can exceed 10 s; eval runner must wait on the port (up to ~60 s), not a fixed sleep.
5. Coupon race repro needs requests within ~150 ms of each other to win reliably.
6. Answer keys use a few extra fields (`optional`, `also_matches`, `must_not`, `runtime_checks_expected_evidence_class`, `expected_verdict_reason_contains`). The AWS example key pair is `optional` because gitleaks skips EXAMPLE keys by default.
