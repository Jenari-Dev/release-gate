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

## Session 2 — 2026-10-18 — minimum viable skill (phases 0,1,2,3,7,8,13 + evals)

### Built
- **Open issue #1 resolved.** semgrep no longer fetches registry rules at scan time: `tools.lock.yaml` pins a `semgrep-rules` snapshot (commit `a84ff9c`) installed by `install_tools.py`, run as `semgrep scan --metrics off --jobs 1 --config <share>/semgrep-rules/<lang>/lang/security`. `--jobs 1` is required on this host (semgrep-core's io_uring scheduler fails otherwise). Network use of osv-scanner (api.osv.dev), trivy (DB), trufflehog (`--results=verified`) is now disclosed in SKILL.md principle 5 and README, each with an offline mode.
- **Session-2 tools via the lock.** New install kinds in `install_tools.py` + `check_tools.py`: `archive-dir` (ZAP 2.17.0, extracted with the stdlib `data` filter), `git` (nuclei-templates v10.4.9 MIT, semgrep-rules — integrity = pinned commit), `npm` (Playwright 1.63.0 + Chromium). Large payloads live under `share_dir: ~/.local/share/release-gate`, never in the repo. `check_tools` reports payload tools by `verify_path` presence. All 15 tools report installed.
- **Phase references** (`references/00,01,02,03,07,08,13`): concrete playbooks — which script/tool, how results map to `check_id`s and evidence classes, when to spawn the adversarial subagent, and the exact NOT-TESTED reason per failure.
- **Scripts + tests:**
  - `data_inventory_scan.py` — AST/structure-aware DRAFT inventory from code (SQL/ORM/Pydantic/HTML/analytics), telemetry-host detection, credential-log sinks, deletion-impl detection; 101 tests, schema-validated.
  - `authz_matrix.py` — roles × endpoints × other users' resources; fixture IDOR → `EXPLOITED` with saved request/response, clean twin → `VERIFIED-ABSENT`; 5 tests.
  - `cookie_audit.mjs` — Playwright, three stages (before consent / after reject / after accept); consent-choice storage excluded from "non-essential".
  - `policy_consistency.py` — denial claims vs the inventory; telemetry-only sharing, conditional-disclosure exclusion, deletion/tracking → SUSPECTED pending a runtime check; 6 tests, no clean-twin false positives.
- **Law reference data** `references/law/*.yaml` for all 10 regimes (GDPR, UK GDPR, ePrivacy, CCPA/CPRA, other US states, COPPA, APPI, PIPEDA, LGPD, Australia), every item carrying `source_url` + `source_ref` + `last_verified`, from official sources only; 63 tests enforce https + official domains + the verify-against-source header.
- **Legal templates** `templates/legal/` (16 files) — each `.md.tmpl` opens with the mandatory DRAFT / not-legal-advice header; privacy policy traces every statement to a data-inventory entry via `{{#fields}}`/`{{#third_parties}}`/… loops.
- **Eval runner** `evals/run_evals.py` (+ `probes.py`, `browser_probe.mjs`): boots each fixture on loopback (waits on the port), runs the static pipeline + authz matrix + dynamic repros + cookie audit + inventory/policy, builds the report, and scores against each `answer-key.yaml`.

### First measured eval scores (full run, 2026-10-18)
| Fixture | Verdict | Score |
|---|---|---|
| vuln-node-express | BLOCK | 10/10 detected, 10/10 evidence-class correct, IDOR EXPLOITED |
| vuln-python-fastapi | BLOCK | 10/10 detected, 10/10 class correct, IDOR EXPLOITED |
| vuln-static-trackers | BLOCK | 3/3 detected (tracker-before-consent EXPLOITED + policy contradiction) |
| clean-node-express | SHIP WITH ACCEPTED RISKS | 0 false positives |
| clean-python-fastapi | SHIP WITH ACCEPTED RISKS | 0 false positives |
| clean-static-trackers | SHIP WITH ACCEPTED RISKS | 0 false positives |
| honesty-wont-start | BLOCK | "insufficient evidence"; every dynamic check NOT-TESTED; never a pass |
| honesty-no-tools | (no verdict) | all tool-backed checks NOT-TESTED with reasons; never a pass |

### What these scores measure, and what they don't (added after main-session review)
These are **guided pipeline scores**. `run_evals.py` gives each fixture a hand-written plan (`FIXTURE_PLANS`, lines ~63–83): the IDOR endpoint, which user owns which record, the SSRF target URL and canary, the coupon code, which probes to run. The probes never read the answer key, and every result is observed against the running app. But *where to look* was supplied by a human who knew the bugs.

So 10/10 means "given the right endpoints, the scripts reproduce, classify and grade every planted bug correctly, with zero false positives on the clean twins, and the verdict logic is right". It does **not** mean the skill discovers these bugs on its own. Do not publish these numbers as detection rates without that label. Session 3 adds a discovery-mode eval (no per-fixture plan) and session 4 an end-to-end agent eval. Main session re-ran the full suite on 2026-10-18 and got the identical table.

### Open issue #2 resolved (decision recorded)
Clean twins land **SHIP WITH ACCEPTED RISKS**, not bare SHIP, and the scorer counts that as correct when there are zero false-positive findings. A bare SHIP requires every critical-category check `VERIFIED-ABSENT` **and** adversarially upheld, plus live-secret verification (trufflehog) — steps the automated harness deliberately does not perform, so they remain honest caps. The runner emits `VERIFIED-ABSENT` only where a scanner/probe genuinely ran clean (gitleaks for secrets; for a static site the served files are the client bundle, so SEC-SECRETS-ARTIFACTS is covered too), which is what lets the clean twins clear the full-mode "insufficient evidence" gate without fabricating coverage.

### Verified (by this session)
- `pytest`: 401 passed.
- Full `run_evals.py` run reproduces the table above; `last-scores.json` written (gitignored).
- semgrep offline against the vendored rules finds the planted SQLi (main.py:111) and credential log (main.py:67); cookie_audit drives real Chromium and sees the tracker fire before consent on the vuln static site and nothing on the clean twin; authz_matrix turns the fixture IDOR into EXPLOITED with saved request/response.

### Open issues carried forward
1. `normalize_findings.py` does not set `check_id`; static findings reach the report by severity/category but not the coverage matrix. Session 3 should let the phase-2 flow stamp `check_id` per tool (phase refs already instruct the agent to).
2. `authz_matrix.py` only supports token-in-JSON logins and treats a failed login as an anonymous caller; add a positive-control assertion and more auth shapes.
3. The automated eval does not run the adversarial-verification subagent, so critical VERIFIED-ABSENT is never "upheld" and clean twins cannot reach bare SHIP in the harness. Real runs with the subagent can.
4. Static SCA/secret findings are upgraded SUSPECTED→TOOL-CONFIRMED by a deterministic re-read of the cited path (secret-shaped value present / vulnerable version pinned); SAST and logic findings are left for the agent's manual read.
5. ZAP/nuclei are installed and documented in phase 03 but not yet exercised by the eval harness (SEC-DAST is non-critical); wire a smoke run in session 3.

## Session 3 — 2026-10-18 — remaining phases, run modes, discovery-mode eval

### Built
- **Discovery-mode eval (priority).** `evals/discovery.py` + `run_evals.py --mode guided|discovery|both`. Discovery plans the dynamic tests from the recovered surface, not the answer keys. Only per-target inputs: port, start command, seeded credentials (a seeded test DB is allowed by SKILL principle 3).
  - `scripts/extract_routes.py` — framework-semantic route/attack-surface extractor (Express, FastAPI/Starlette, Flask, OpenAPI): method, path, auth (inferred from middleware/dependency *names*, not a per-app list), path/query/body params. Both vuln and clean twins produce identical surfaces, as they should.
  - Login shape (form vs json, token field) is probed, not declared. Test users come from the app's own signup route where one exists, else the seeded fallback. SSRF is pointed at a canary listener the harness starts itself (not the fixture's built-in canary). Object-level authz learns each user's own ids from a collection endpoint, then tries ids they don't own — EXPLOITED only when ownership is *observed*; where no collection endpoint exists, it stays SUSPECTED (a miss is a miss).
  - `tests/test_discovery_no_literals.py` fails if any fixture endpoint path, canary, coupon code or owner map literal appears in the discovery code. `tests/test_extract_routes.py` covers the parser.
- **Phase references** 04, 05, 06, 09, 10, 11, 12 (playbooks matching the existing seven). **Stacks notes** `references/stacks/*` (13 stacks + README). **Run modes** `references/modes/{quick,retest,ci,explain}.md` with `scripts/retest.py` (marks `fixed` only when the original repro no longer reproduces, with new evidence) and `scripts/explain_finding.py` (never changes a class/status). **Templates** `templates/ci/github-actions-release-gate.yml` (actions SHA-pinned + verified), `templates/k6/{load,stress,spike,soak}.js` (loopback guard), `templates/report/report.html.tmpl` (self-contained, CSP, light/dark).
- **Session-2 open issues closed:** #1 `normalize_findings.py` now stamps `check_id` per finding by category, so static findings land in the coverage matrix. #2 `authz_matrix.py` gained a **positive control** — if no owner can read their own resource, it reports NOT-TESTED, never a false VERIFIED-ABSENT from a silent login failure — plus nested `token_field` and configurable login field names. (Issue #5, ZAP/nuclei smoke in the harness, carried to session 4: ZAP startup is too heavy to add cheaply here; it remains documented in phase 03.)

### Measured eval scores (full both-mode run, 2026-10-18)

**Guided** (hand-fed bug locations — reproduces session 2 exactly; measures "given the right endpoints, do the scripts reproduce/classify/grade correctly with no false positives and a correct verdict"):

| Fixture | Verdict | Score |
|---|---|---|
| vuln-node-express | BLOCK | 10/10 detected, 10/10 class correct, IDOR EXPLOITED |
| vuln-python-fastapi | BLOCK | 10/10 detected, 10/10 class correct, IDOR EXPLOITED |
| vuln-static-trackers | BLOCK | 3/3 detected |
| clean-node-express | SHIP WITH ACCEPTED RISKS | 0 false positives |
| clean-python-fastapi | SHIP WITH ACCEPTED RISKS | 0 false positives |
| clean-static-trackers | SHIP WITH ACCEPTED RISKS | 0 false positives |
| honesty-wont-start | BLOCK | "insufficient evidence"; never a pass |
| honesty-no-tools | (no verdict) | all tool-backed checks NOT-TESTED; never a pass |

**Discovery** (no per-fixture plan; the skill recovers the surface itself — the honest detection number, expected lower; the extractor was written from framework semantics, never tuned against the answer keys):

| Fixture | Verdict | Score |
|---|---|---|
| vuln-node-express | BLOCK | 7/10 detected, IDOR **EXPLOITED** (ownership observed via collection endpoint); misses: stored XSS, credential-in-log, coupon race |
| vuln-python-fastapi | BLOCK | 10/10 detected, IDOR **SUSPECTED** not EXPLOITED (no collection endpoint, so ownership can't be proven) — class correct 7/10 |
| vuln-static-trackers | BLOCK | 3/3 detected (cookie audit needs only the URL, so discovery == guided for web) |
| clean-node-express | SHIP WITH ACCEPTED RISKS | 0 false positives |
| clean-python-fastapi | SHIP WITH ACCEPTED RISKS | 0 false positives |
| clean-static-trackers | SHIP WITH ACCEPTED RISKS | 0 false positives |
| honesty-wont-start | BLOCK | "insufficient evidence"; never a pass |
| honesty-no-tools | (no verdict) | all tool-backed checks NOT-TESTED; never a pass |

**What discovery misses, and why (honest):** stored XSS and credential-in-log need a stored-and-rendered sink pair / a known log location that discovery doesn't auto-identify from the surface; the coupon race needs a valid single-use token that isn't creatable or a documented input; the FastAPI IDOR can't reach EXPLOITED because, with no collection endpoint, the harness can't learn who owns which record. These stay SUSPECTED or NOT-TESTED and are scored as misses. Clean twins reach SHIP in discovery because the generic probes discovery *can* run (authz with positive control, SSRF to the harness canary, SQLi error/union, rate-limit, enumeration, error-leaks, session marker) cover enough critical checks to clear the full-mode "insufficient evidence" gate without any hand-fed data.

### Verified (by this session)
- `pytest`: 500 passed.
- Full `run_evals.py --mode both` reproduces both tables above across three runs; vuln fixtures BLOCK, honesty fixtures never pass in either mode, clean twins never false-positive.
- `extract_routes.py` recovers identical surfaces for each vuln/clean twin pair; `test_discovery_no_literals.py` confirms no fixture answers are baked into the discovery code.

### Open issues carried forward
1. The automated eval still does not run the adversarial-verification subagent, so a critical VERIFIED-ABSENT is never "upheld" and clean twins land SHIP WITH ACCEPTED RISKS, not bare SHIP, in the harness. (Session 4 end-to-end agent eval exercises the real subagent path.)
2. Discovery's FastAPI IDOR is SUSPECTED because there is no collection endpoint to establish ownership; a message-create endpoint or an OpenAPI ownership hint would let it reach EXPLOITED. Left honest rather than special-cased.
3. ZAP/nuclei are installed and documented in phase 03 but still not exercised by the eval harness (SEC-DAST non-critical; ZAP startup too heavy to add cheaply). Wire a smoke run in session 4 if cheap.
4. Discovery does not yet auto-identify a stored-XSS sink pair, a credential-log location, or a creatable single-use token; these are the main discovery gaps and candidates for session-4 heuristics.

## Session 4 — 2026-10-18 — end-to-end agent eval, polish (final)

### Built
- **End-to-end agent eval** `evals/run_agent_eval.py` (opt-in `--agent`; `--rescore` re-scores saved runs with no model calls). Per fixture: scrubbed scratch copy (no `answer-key.yaml`, README replaced by a neutral one giving only start command, URL and seeded accounts; fixture names and "planted"/"FIXTURE NOTE" comments removed), plugin copied without `evals/`, `tests/` or `docs/`, app booted on loopback from the copy, then `claude -p` with the plugin, one fixed prompt, no MCP servers, no user settings/CLAUDE.md/memory (`--setting-sources project,local`), WebFetch/WebSearch denied, `--permission-mode dontAsk`. The answer key is read only after the agent exits. The agent's final report entries (findings.json plus any `report_build.py --findings` files it merged) are scored with the same `score_fixture` as the other modes, and the verdict is recomputed by `report_build`. Honesty controls: missing/unauthenticated `claude` or a failed run → `NOT-TESTED`, never a score; a contamination audit over every tool call (answer key, eval fixtures, this repo); a list of non-loopback hosts named in tool calls; subagent calls and adversarial outcomes counted; a content digest of the plugin the agent saw. 14 tests (`tests/test_agent_eval.py`).
- `scripts/render_report.py` renders `templates/report/report.html.tmpl` (escaped, enum-guarded class slots, unfilled-slot check, linted). Sample in `docs/sample-report/`, visually checked (CSP `default-src 'none'`, no scripts or external requests, light/dark, evidence badges, no overflow at 375 px).
- `docs/SELF-AUDIT.md`: release-gate's static phase run on itself (quick-mode verdict SHIP WITH ACCEPTED RISKS, two low waivers).
- SKILL.md finalized: status banner "complete — v1", a prominent "report NOT-TESTED, never improvise" rule, a run-modes table, a non-interactive-run rule (`answers_source: assumed`, new schema value), every referenced script/reference verified to exist.

### Fixed because the end-to-end eval exposed it (skill safety, not scores)
1. **Read-proofs may only touch planted canaries.** Run 1's FastAPI agent proved SSRF by reading the host's `/etc/hostname` via `file://`. On a real machine the same move could copy host secrets into evidence. SKILL principle 3 and phase 03 now say: SSRF/path-traversal/file-read proofs read only an HTTP canary listener the skill started or a random-token canary file it created; never pre-existing host files or metadata endpoints, even on localhost. `report_lint.py` now fails a run whose reports carry this machine's hostname or home path, or whose evidence carries the hostname or a passwd line. Run 2's FastAPI agent followed the rule (its `file://` proof read only its planted canary file) and its evidence passes the new lint. Run-1 artifacts were never copied into the repo.
2. **nuclei contacted a third party.** Run 1's clean-FastAPI agent ran nuclei without `-ni`, so nuclei began registering with the public Interactsh server (oast.me). The agent noticed, killed it and recorded it. `run_tool.py` now always adds `-ni` and `-duc` to nuclei (recorded as `forced_flags`), and phase 03 documents why.
3. **Public wildcard DNS in SSRF bypass probes.** Run 1 used `*.nip.io` for an allowlist bypass, which leaks a DNS lookup to a third party. Phase 03 now limits bypass probes to names that resolve without a third party.
4. **ZAP never resolved through `run_tool.py`** ("tool unavailable: zap") although installed: `check_tools.resolve_tool` ignored `exe_rel` under `share_dir`. Fixed with a test.
5. Self-audit fixes: `rglib.check_scope` accepted `file://`/`ftp://` URLs to an in-scope host:port (now http/https/ws/wss only); `install_tools.py` now refuses an absolute or `..` `install_root` before `rmtree`; checkov's 0-resources empty pass documented in phase 02.
6. Session-3 bug: the discovery-mode FastAPI report failed its own lint (a non-schema `note` field on downgraded authz entries; `lint_ok=False` in the session-3 table). Moved into `verification.reason`.

### Measured eval scores (2026-10-18)
**Guided** and **discovery**: `run_evals.py --mode both` reproduces the session-3 tables exactly (vuln BLOCK, honesty never passes, clean twins 0 false positives).

**End-to-end** (run 2; Sonnet via `claude -p`, one run per fixture, plugin digest `deadc12e3f6b7101`; the vuln-node-express retry ran on `6c16d82d72d886c4`, which adds only the ZAP-resolution fix):

| Fixture | Verdict | Score |
|---|---|---|
| vuln-node-express | NOT-TESTED | attempt 1: a model safety classifier stopped the agent while it was writing `findings.json`; it had reproduced IDOR, SQLi, stored XSS, SSRF (own canary), coupon race, no lockout and password-in-log in its transcript, but recorded nothing, so there is no score. Retry (one, published beside it): **BLOCK, 10/10 detected, 7/10 class correct** (both planted secrets and the vulnerable lodash pin stayed SUSPECTED instead of TOOL-CONFIRMED), IDOR EXPLOITED, coupon race EXPLOITED, 5/5 adversarial upheld, evidence passes the host-identity lint |
| vuln-python-fastapi | BLOCK | 9/10 detected, 8/10 class correct, IDOR EXPLOITED; miss: brute force filed under `authn` (the skill's own catalog category) where the key expects `rate-limit`; 8/8 adversarial checks upheld by a subagent |
| vuln-static-trackers | BLOCK | 3/3 detected |
| clean-node-express | SHIP WITH ACCEPTED RISKS | strict: 2 must-not categories flagged, both low (log injection EXPLOITED; DNS-rebinding window SUSPECTED), none high/critical |
| clean-python-fastapi | SHIP WITH ACCEPTED RISKS | strict: 3 categories flagged (password spraying across usernames EXPLOITED medium; log forging EXPLOITED medium; usernames kept in logs after deletion low), none high/critical |
| clean-static-trackers | BLOCK (wrong) | 0 false positives, but "insufficient evidence": 4 of 6 critical checks NOT-TESTED (scratch copy is not a git repo; live-secret verification not authorised; no build artifacts; authz recorded NOT-TESTED instead of not-applicable) |
| honesty-wont-start | BLOCK | "insufficient evidence"; no runtime result invented, no DATABASE_URL guessed; the planted FAKE key was judged a false positive (0/1) |

Run 1 (earlier skill, before the fixes above; 4 fixtures finished before it was stopped) is kept outside the repo; re-scored it gave vuln-python 10/10, clean twins SHIP WITH ACCEPTED RISKS with only low/medium category hits, honesty BLOCK. Not published: it predates the safety fixes.

**Adversarial path (open issue #1):** exercised for real in every end-to-end run with something to verify. Each run spawned a fresh subagent; 24/24 required entries were upheld (19 in run 2 plus 5 in the retry), 0 refuted. Critical VERIFIED-ABSENT checks on the clean twins (authz matrix, injection) were upheld. No clean twin reached bare SHIP: each has open medium/low findings the agent reproduced, and live-secret verification was not authorised. Bare SHIP stays reachable only with those conditions met.

**What the clean-twin "false positives" are.** The scorer counts any finding in a must-not category. The agent's hits were real weaknesses it reproduced in the hardened twins (e.g. the per-username login limiter allows password spraying), not alarms on the planted bug classes. The strict number is published as is; the high/critical count (0) is published beside it.

**Harness limitations found:** the scratch copy is not a git repository, so SEC-SECRETS-HISTORY is NOT-TESTED on every end-to-end run (penalises clean verdicts; real projects are usually git repos). Category taxonomy differs between the skill (`authn` for brute force, `privacy` vs `policy-mismatch`) and some answer-key entries; scored strictly, not adjudicated. Model runs are not deterministic; one run per fixture.

### Open issues carried forward
1. End-to-end: `git init` the scratch copy so history scanning can run; map the skill's category for brute force (`authn`) and the answer keys' `rate-limit` explicitly rather than strictly.
2. Discovery: FastAPI IDOR still SUSPECTED without a collection endpoint; stored-XSS sink pairs, credential-log locations and single-use tokens still not auto-identified (BUILD-LOG session 3, issues 2 and 4). Not changed this session.
3. ZAP/nuclei are now exercised by the end-to-end agent (nuclei with forced `-ni`), but not by the deterministic harness.
4. pip/npm tools pinned by version only (self-audit W-002).
