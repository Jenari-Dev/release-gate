# release-gate self-audit (static phase)

Date: 2026-10-18. Subject: this repository at commit `419e0e6` plus the uncommitted working tree present at scan time (other-session edits to README, SKILL.md, references and new files `render_report.py`, `run_agent_eval.py`, `test_agent_eval.py`, `test_render_report.py` were in the tree; see "Scope notes"). Owner: JenAriDev.

This is the plugin's own phase 2 playbook (`skills/release-gate/references/02-static-security.md`) run against itself. It is an automated aid, not a penetration test and not a guarantee. Dynamic phases were not run (see the table).

## Quick-mode verdict (computed by `report_build.py --mode quick`)

**SHIP WITH ACCEPTED RISKS.** Blocking reasons: none. This is the ceiling quick mode can give; it is not a release decision. Caps recorded by the tool: eight checks not part of quick mode (SEC-SECRETS-VERIFIED, SEC-SECRETS-ARTIFACTS, SEC-AUTHZ-MATRIX, SEC-INJECTION-DYNAMIC, SEC-AUTHN-BRUTEFORCE, SEC-AUTHN-ENUMERATION, SEC-SESSION, SEC-ERROR-LEAKS) and two active waivers (W-001, W-002). The report lint passed (an earlier run failed on evidence paths and was rebuilt). State and evidence are in the gitignored `.release-gate/` directory.

## What ran

All scanners are the pinned versions from `skills/release-gate/tools.lock.yaml`, run through `scripts/run_tool.py` (evidence in `.release-gate/evidence/`). `check_tools.py` reported all 15 pinned entries present at their pinned version.

| Tool | Version | Scope | Flags |
|---|---|---|---|
| gitleaks | 8.30.1 | `git` mode, all 4 commits; also `dir` mode over a copy of the 233 tracked files | `--config .gitleaks.toml` (default ruleset + allowlist) for the verdict run; `--config` with only `useDefault = true` (no allowlist) to enumerate planted material; `--config evals/fixtures/.gitleaks-allowlist.toml` for a third comparison; `--no-banner` |
| semgrep | 1.179.0 | `skills/`, `evals/discovery.py`, `evals/probes.py`, `evals/run_evals.py`, `evals/browser_probe.mjs` (96 files, 364 rules) | `--metrics off --jobs 1 --json`, env `SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0`; local rules only, snapshot commit `a84ff9c`: `python/lang/security`, `python/requests`, `python/cryptography`, `javascript/lang/security`, `generic/secrets`. No registry config. |
| bandit | 1.9.4 | `skills/release-gate/scripts`, `evals/discovery.py`, `evals/probes.py`, `evals/run_evals.py` (7,850 lines) | `-r -f json` |
| osv-scanner | 2.6.0 | `uv.lock` (13 packages) | `scan source --lockfile uv.lock --format json`. No local OSV database existed, so this ran in default online mode: package names and versions went to api.osv.dev, no source code. |
| checkov | 3.3.22 | `skills/release-gate/templates/ci/github-actions-release-gate.yml`, copied to `.github/workflows/` in a scratch directory because checkov's `github_actions` framework only recognizes that path (a first run with `-f` on the template path scanned 0 resources and was discarded) | `--framework github_actions --skip-download`, `CKV_DISABLE_TELEMETRY=1` |
| pytest | via `uv run --no-project --with pytest --with pyyaml --with jsonschema` | `tests/` | `-q` |
| manual review | n/a | `install_tools.py`, `run_tool.py`, `check_tools.py`, `authz_matrix.py`, `rglib.check_scope`, `extract_routes.py`, the CI template, plus grep for `shell=True`, `os.system`, `yaml.load`, `pickle`, `eval(`, `exec(`, `extractall`, `mktemp` | read by me, not by a tool |

An independent read-only subagent (no access to my reasoning) was briefed to disprove the secrets claim; outcome `upheld` (details under Secrets).

## Results

Evidence for each row is in the gitignored `.release-gate/evidence/<tool>-<stamp>/` directories and the generated report under `.release-gate/reports/` (lint-clean). This hand-written page links no evidence files, so `report_lint.py` run directly on it flags the rows; run the lint on the generated report instead.

| # | Check | Evidence class | Result |
|---|---|---|---|
| 1 | SEC-SECRETS-HISTORY: gitleaks, full history, repo config | VERIFIED-ABSENT | gitleaks 8.30.1 found no secrets in the 4 commits (default ruleset plus the repo allowlist). Scoped to that scanner and ruleset. Adversarial verification: upheld. |
| 1a | Planted fixture material under `evals/fixtures/` | VERIFIED-ABSENT (as real credentials) | 3 gitleaks hits, all FAKE-shaped (see below). Not findings. |
| 1b | Credential-shaped test inputs under `tests/` (outside `evals/fixtures/`) | VERIFIED-ABSENT (as real credentials) | 6 gitleaks hits, all synthetic. Allowlisted in `.gitleaks.toml`. Reported here because they sit outside `evals/fixtures/`. |
| 1c | gitleaks false positive in docs | false-positive | `skills/release-gate/references/02-static-security.md:102` (commit `0af27001`): `generic-api-key` matched the prose `semgrep/bandit`. Fixed by a rule-scoped allowlist. |
| 2 | SEC-SAST: semgrep + bandit | TOOL-CONFIRMED (1 low, waived) plus 37 false positives | 19 semgrep hits and 34 bandit hits; after dedupe 38 entries. 37 classified false-positive with reasons (below), 1 real low (`extract_routes.py:385`). No `shell=True`, no `yaml.load`, no tarfile extraction without a filter. |
| 3 | SEC-SCA: osv-scanner on `uv.lock` | VERIFIED-ABSENT | osv-scanner 2.6.0 reported zero advisories for the 13 packages on 2026-10-18 (online). Reachability not assessed because nothing was reported. `pip-audit` was not run. |
| 4 | SEC-IAC: checkov on the CI template | VERIFIED-ABSENT | github_actions framework: 68 passed, 0 failed (`CKV_GHA_1` to `7`, `CKV2_GHA_1`). Other IaC checks: the repo has no Dockerfile, compose, k8s or terraform files, so hadolint and trivy config were not run. |
| 4a | CI template actions pinned to commit SHAs | VERIFIED-ABSENT (unpinned actions) | All 4 `uses:` lines are 40-hex SHAs with a tag comment. Whether each SHA is the commit its comment tag names was NOT-TESTED here (needs network); `git ls-remote` recheck is documented in the template header. |
| 5 | Privacy / public identity | VERIFIED-ABSENT | grep over the 233 tracked files found no real local path, no local username, no non-test email, no private host or IP. Details below. |
| 6 | Supply chain: `tools.lock.yaml` | VERIFIED-ABSENT for binaries and git payloads; SUSPECTED gap for pip/npm | See below. |
| 7 | COR-TEST-SUITE: repo's own pytest | VERIFIED-ABSENT (failures) | 548 passed, 0 failed, after the fixes below. Says nothing about untested lines. |
| 8 | SEC-SBOM (syft) | NOT-TESTED | Not run: not in the requested scope. |
| 9 | META-REPO-INJECTION-CONTENT | NOT-TESTED | Not performed. This repo's SKILL.md and references are agent-facing by design, so a naive sweep would be all noise; needs a purpose-built pass. |
| 10 | LEGAL-POLICY-CONSISTENCY | NOT-TESTED | No privacy policy file exists in this repo to compare against (the legal files are templates). |
| 11 | All dynamic phases (authz, injection, authn, session, error leaks, DAST, load) | NOT-TESTED | The plugin has no server. The eval fixtures use ports 3101-3199, which a running eval occupied; no fixture was started or stopped. |
| 12 | SEC-SECRETS-VERIFIED (trufflehog live verification) | NOT-TESTED | Not run: sends candidate secrets to providers, needs explicit consent, and there were no candidates. |
| 13 | SEC-SECRETS-ARTIFACTS | NOT-TESTED | No build artifacts present. |
| 14 | Trail of Bits skills | NOT-TESTED | Not installed: nothing matching Trail of Bits under `~/.claude/plugins` or `~/.claude/skills`. |
| 15 | Manual review beyond the files listed above (SEC-MANUAL-REVIEW) | NOT-TESTED | The remaining scripts (`data_inventory_scan.py`, `report_build.py`, `normalize_findings.py`, `policy_consistency.py`, `retest.py`, etc.) were covered by the scanners only, not read line by line. |

## Secrets detail

gitleaks without any allowlist reported 10 hits in history. Each was opened:

Planted FAKE material inside `evals/fixtures/` (3):
- `evals/fixtures/vuln-node-express/src/config.js:9`, `evals/fixtures/vuln-python-fastapi/app/config.py:12`, `evals/fixtures/honesty-wont-start/server.js:12`: Stripe-shaped `sk_t...` value with the literal word FAKE in it, documented as FAKE in each fixture's `answer-key.yaml`.
- Not flagged by gitleaks (its default ruleset skips them) but present in the same fixtures: the public AWS-documentation example key pair ending in `EXAMPLE` (`config.js:10-11` and the python fixture's config, documented as FAKE in the answer keys).

Synthetic test inputs under `tests/`, outside `evals/fixtures/` (6, allowlisted by the `tests/test_[a-z_]+\.py` and `tests/data/tool-outputs/` patterns):
- `tests/data/tool-outputs/bandit.json:35` and `tests/data/tool-outputs/gitleaks.json:10`: `s3cr...` placeholder password.
- `tests/data/tool-outputs/trufflehog.jsonl:2` and `tests/test_normalize_findings.py:36`: `xoxb...` sequential Slack-shaped token (digits and alphabet run).
- `tests/test_run_tool.py:12`: `AKIA...` sequential AWS-shaped id (alphabet run).
- `tests/test_report.py:302`: `sk_l...`, input to a redaction test, sequential characters.

The one hit outside both groups is the docs false positive (1c). Nothing outside `evals/fixtures/` and `tests/` matched. The allowlist is path-exact for the six fixture files and two `tests/` patterns. Note that `evals/fixtures/.gitleaks-allowlist.toml` does not cover `tests/`; running gitleaks with only that config reports 7 hits (6 test inputs and the doc line). Use the root `.gitleaks.toml` for the self-gate.

Subagent sweep (read-only, git and grep only, all commits and the tree): key-format greps (private key headers, AWS, GitHub, Slack, Stripe, npm, PyPI, JWT, Google, Anthropic, SendGrid, Twilio, GitLab), `.env`/key-file names, deleted-file history, allowlist scope, personal identifiers. It could not disprove the claim and classified every credential-shaped string as synthetic. Its coverage was grep-based, so it is an independent second look, not a proof.

Not covered: untracked files are outside git history. A grep of the four untracked files found only the public AWS-documentation example id (test data) and a fake absolute path in `tests/test_agent_eval.py:73`.

## SAST detail

Every hit's code was read. Classification:

| Rule(s) | Locations | Class | Why |
|---|---|---|---|
| bandit B603/B607/B404, semgrep `dangerous-subprocess-use-audit` (semgrep rates these ERROR) | `run_tool.py:90,102`, `check_tools.py:111,156`, `install_tools.py:199,359`, `evals/run_evals.py:32,123,149,194,225,232,239,243,341,384` | false-positive | argv lists, no shell; executables are fixed names or tool paths from the shipped lock file. |
| B310 / `dynamic-urllib-use-detected` | `install_tools.py:77` | false-positive | `download()` rejects any URL not starting with `https://` (lines 74-75) and every payload is SHA-256 checked before use. |
| same | `authz_matrix.py:78` | false-positive after fix | Host and port must match a confirmed `scope.yaml` target (`check_scope`, fail-closed). The scheme was not checked: reproduced on the HEAD code, `ftp://127.0.0.1:3000/x` and `file://127.0.0.1:3000/x` returned in-scope for an `http://127.0.0.1:3000` target. Fixed (see below). Impact was low because the URL comes from the operator's own spec file. |
| same | `evals/discovery.py:63`, `evals/probes.py:37` | false-positive | Loopback fixture base URLs built by the eval harness. |
| `insecure-file-permissions` | `install_tools.py:117` | false-positive | `chmod` adds execute to a 0600 temp file; no group/other write bit. |
| `html-in-template-string` | `evals/browser_probe.mjs:28` | false-positive | The string is the XSS probe payload sent to a local fixture. |
| B608 | `evals/probes.py:112` | false-positive | Text of a repro message that contains "UNION SELECT"; no SQL is built. |
| B105/B107 | `probes.py:45,266,268`, `run_evals.py:301`, `data_inventory_scan.py:1233`, `normalize_findings.py:117,645` | false-positive | Field names, category labels, and a deliberately wrong test password. |
| B112 | `extract_routes.py:385` | **TOOL-CONFIRMED, low** (RG-SAST-004, waiver W-001) | An OpenAPI/Swagger file that fails to parse is skipped with `except Exception: continue` and no note. Recon can under-report the attack surface without saying so. Not exploitable. |

Also read and not flagged by any tool: `extract_member()` extracts one named regular file and validates the member name (rejects absolute, `..`, backslash, NUL); the archive-dir path uses `tarfile.extractall(filter="data")`; zip handling reads a single member; git installs require https and verify the checked-out commit; `yaml` is only used via `safe_load`; temp files use `mkstemp`/`TemporaryDirectory`; `run_tool.py` runs scanners with an argv list and `start_new_session`.

Untracked `evals/run_agent_eval.py` (bandit B404/B603/B607 only, semgrep 2 subprocess audit hits, all list-argv) and `skills/release-gate/scripts/render_report.py` (no semgrep or bandit hits) were scanned but are in flux in the other session; treat as informational, not part of the verdict's committed scope.

## Dependencies and `uv.lock`

`uv.lock` was added in the first commit (`1f57c78`) alongside `pyproject.toml`, not by accident of a later bare `uv run`. It holds 13 third-party packages (attrs, colorama, iniconfig, jsonschema, jsonschema-specifications, packaging, pluggy, pygments, pytest, pyyaml, referencing, rpds-py, typing-extensions) plus the project itself as `virtual = "."`, with SHA-256 for every sdist and wheel, and no local paths. `uv lock --check --offline` passes, so it matches `pyproject.toml`. Recommendation: keep it committed. It gives a hash-pinned test environment and gives osv-scanner something to scan. It does not affect plugin users: the scripts need only PyYAML and jsonschema, which the README tells users to supply. Regenerate it whenever `pyproject.toml` dependencies change.

## Privacy and public identity (tracked files, grep)

- Local absolute paths (Linux home, temp, macOS and Windows user-directory prefixes): 4 matches, none real. `evals/probes.py:248` and `tests/test_templates.py:332` are regexes that detect path leaks; `tests/data/tool-outputs/nuclei.jsonl:1-2` contain a fake absolute path under a `test` user in captured sample output.
- The local account name, outside the public `JenAriDev` / `Jenari-Dev` identity: none. The identity strings found are the `Jenari-Dev` GitHub URLs (`README.md:12`, `.claude-plugin/plugin.json:5-7`, `.claude-plugin/marketplace.json:3`, five `schemas/*.json:3` ids, `report_build.py:713`), `LICENSE:3` and `docs/NEXT-SESSION.md:14`.
- Email addresses: domains found are `fixture.test`, `example.invalid`, `elsewhere.example`, plus two non-addresses (`tests/test_data_inventory_scan.py:278` is a fake DB URL `...@db.managed-pg.io`, line 370 is a decorator `n@app.patch`). No personal email.
- Private hosts or IPs: only `127.0.0.1` (150 occurrences) and `0.0.0.0` (3). No RFC1918 addresses and no private hostnames.
- Git history: all 4 commits use author and committer `Jenari Dev` with the GitHub noreply address of the `Jenari-Dev` account.

## Supply chain (`tools.lock.yaml`)

- Binary tools (gitleaks, trufflehog, osv-scanner, trivy, syft, hadolint, nuclei) and the ZAP archive: exact version, 64-hex SHA-256, https source. `install_tools.py` verifies the hash before extraction and cross-checks it against the project's published checksums file (ZAP's hash is computed locally, flagged `checksum_source: computed-local`).
- Git payloads (nuclei-templates, semgrep-rules): exact version plus a full 40-hex commit, verified by `git rev-parse HEAD` after checkout.
- Known gap: semgrep 1.179.0, bandit 1.9.4, pip-audit 2.10.1, checkov 3.3.22 (pip) and playwright 1.63.0 (npm) are pinned by exact version only. There is no `--require-hashes`, and transitive dependencies are resolved at install time. Recorded as RG-SUPPLY-001 (SUSPECTED, low, waiver W-002).

## What I fixed

- `.gitleaks.toml`: added a rule-scoped (`generic-api-key`, regex `semgrep/bandit`) allowlist for the docs false positive; history scan now reports 0 hits.
- `skills/release-gate/scripts/rglib.py`: `check_scope` now refuses any scheme other than http/https/ws/wss (closes the `ftp://` and `file://` pass-through, reproduced on HEAD); two cases added to `tests/test_report.py`.
- `skills/release-gate/scripts/install_tools.py`: new `_install_root()` rejects an absolute or `..` `install_root` before the `rmtree` in the archive-dir, git and npm installers (hardening, no known exploit because the lock ships inside the plugin); tests added to `tests/test_install_tools.py`.

`pytest -q`: 548 passed after the changes (537 before; the extra tests are the ones above plus the other session's additions).

Nothing was committed or pushed. Files owned by the other session were not edited.

## Known issues and waivers

Both waivers: owner JenAriDev, created 2026-10-18, expiry 2027-04-18 (in `.release-gate/waivers.yaml`, gitignored).

| ID | Finding | Class | Severity | Reason |
|---|---|---|---|---|
| W-001 | RG-SAST-004: `extract_routes.py:383-386` swallows OpenAPI parse errors silently | TOOL-CONFIRMED | low | Under-reported recon surface, not exploitable; the fix changes the script's output and needs a schema decision. |
| W-002 | RG-SUPPLY-001: pip and npm scanners pinned by version only, no hashes | SUSPECTED | low | Hashed lock generation deferred; binary tools are checksum-verified. |

Other items, not waived:
- `evals/fixtures/.gitleaks-allowlist.toml` does not cover `tests/`; CI and docs should point at the root `.gitleaks.toml` (see above).
- Tag-to-SHA mapping of the four CI-template actions (including `github/codeql-action/upload-sarif` v3.38.2) was not rechecked against the remote.
- `checkov` needs the `.github/workflows/` path to analyze the template; `references/02-static-security.md` step 6 uses `-d {project}` and would scan the template as 0 resources and report an empty pass. Worth a note in that playbook (not edited here because the file is outside my ownership for this task).
- The superseded and misfired scanner runs are kept under `.release-gate/superseded/` and a stale `*.lint-failed.*` report set remains in `.release-gate/reports/`; both are gitignored.

## Scope notes

- Scans read the working tree, so uncommitted edits from the other session were included where they touch scanned paths. Scanned code files are unchanged by that session apart from the files named above.
- gitleaks `git` mode covers committed history only; untracked files were checked by grep, not by gitleaks.
- This audit does not show the plugin is free of defects; it shows what the named tools, rules and reads found in the named scope on 2026-10-18.
