# Phase 2: Static security

## Goal
Run every applicable static scanner against the source tree, history and build artifacts, normalize the output into one findings file, and confirm each hit by reading the code path. Scanners only produce `SUSPECTED`; you promote or reject.

## Setup
```
S=<skill>/scripts          # scripts dir
SHARE=~/.local/share/release-gate
export SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
python $S/check_tools.py --json     # confirm which tools are ok (phase 0)
```
Run each scanner through `run_tool.py` so evidence is captured and scope/tool checks are enforced:
```
python $S/run_tool.py --project <project> --tool <name> --test-type scan -- <tool args>
```
Output lands in `<project>/.release-gate/evidence/<tool>-<stamp>/` (`stdout.txt`, `stderr.txt`, `result.json`, plus any `{evidence}` files). `{project}` and `{evidence}` in args are substituted. Exit 4 = tool not run, 5 = refused, 6 = timeout, 7 = error. Exit codes other than 0 from a scanner can just mean "found issues": read `result.json` `status` (`completed`, `not-run`, ...).

## Network disclosure (tell the user before running)
- `osv-scanner` queries package names and versions to an external vulnerability API by default. `trivy` downloads its vulnerability DB. `pip-audit` and `npm audit` query their registries. No source code is sent.
- Offline modes: pre-fetch once, then run without network.
  - `osv-scanner scan source --offline-vulnerabilities --download-offline-databases ...` (first run downloads the DBs; later runs add `--offline-vulnerabilities` only).
  - `trivy fs --skip-db-update ...` with a DB fetched earlier.
- If the user refuses network use and no cached DB exists: SCA is `NOT-TESTED: network use declined and no offline vulnerability database`.
- `trufflehog --results=verified` sends each candidate secret to its provider to test it: a third-party contact. Get explicit user consent per run (see SEC-SECRETS-VERIFIED).

## Steps and mapping
In the NOT-TESTED strings below, the text after `NOT-TESTED:` is the exact `not_tested_reason` value.

### 1. Secrets in git history: SEC-SECRETS-HISTORY (critical, category secrets)
```
run_tool.py --project P --tool gitleaks --test-type scan -- \
  git {project} --report-format json --report-path {evidence}/gitleaks.json --no-banner
```
- Not a git repo: run `gitleaks dir {project}` instead and record the check `NOT-TESTED: not a git repository; history not scanned` (the working tree alone cannot prove history clean).
- Hit, and you opened `file:line` / the historical blob and it is a real credential: finding, `TOOL-CONFIRMED`, severity high or critical, `verification.code_ref`. Placeholder/example/test key: `status: false-positive` with `verification.reason`.
- Zero hits: check entry `VERIFIED-ABSENT`, title "gitleaks 8.30.1 found no secrets in full git history (default ruleset)". Evidence: the report file. Critical category: adversarial verification required.
- Rotation advice goes in `fix`: removing the commit does not un-leak a key.

### 2. Live-secret verification: SEC-SECRETS-VERIFIED (critical)
```
run_tool.py --project P --tool trufflehog --test-type scan -- \
  git file://{project} --results=verified --json --no-update
```
- Only with the user's explicit consent (third-party contact). Declined: `NOT-TESTED: live verification declined by user (third-party contact)`.
- A verified result is a live credential: severity critical, `TOOL-CONFIRMED` (the provider accepted it), do not re-use the key, tell the user to rotate now.
- Zero verified results is `VERIFIED-ABSENT` only for "no secret that trufflehog's detectors could verify"; unverified candidates stay with gitleaks findings.

### 3. Secrets in artifacts: SEC-SECRETS-ARTIFACTS (critical)
- Scan existing build output / client bundles / images, not the source: `gitleaks dir <dist-dir> --report-format json --report-path {evidence}/gitleaks-artifacts.json --no-banner`; images via `trivy image --scanners secret --skip-db-update <image>` when a local image exists.
- Do not run the project's build to get artifacts unless the user approves (build scripts execute untrusted code); if approved, build in a throwaway copy.
- Also grep bundles for server-only env names shipped to the client (e.g. public-prefixed env vars holding keys).
- No artifacts present: `NOT-TESTED: no build artifacts present`. Same class rules as step 1.

### 4. SAST: SEC-SAST (non-critical)
Semgrep MUST run offline against the vendored, commit-pinned rules, never the registry. `--jobs 1` is REQUIRED on this host (the parallel scheduler fails).
```
run_tool.py --project P --tool semgrep --test-type scan -- \
  scan --metrics off --jobs 1 --json --output {evidence}/semgrep.json \
  --config $SHARE/semgrep-rules/python/lang/security \
  --config $SHARE/semgrep-rules/javascript/lang/security {project}
```
- Pick `--config` dirs from `detect_stack.py`: `<lang>/lang/security` for each language (`python`, `javascript`, `go`, `java`, ...), plus framework dirs that exist (`python/django/security`, `python/flask/security`, `python/fastapi/security`, `javascript/express`, `javascript/react`, `dockerfile/security`, `generic/secrets`). `ls $SHARE/semgrep-rules/<lang>` first; skip dirs that do not exist.
- Never use `--config auto`, `p/...` or any registry id. If the vendored rules are missing: `NOT-TESTED: tool unavailable: semgrep-rules`.
- Python: also `bandit -r {project} -f json -o {evidence}/bandit.json` (skip tests/venv via `-x`). JS/TS/Go/etc.: semgrep only; say so.
- Hit you verified by reading the sink and confirming attacker-controlled input reaches it: `TOOL-CONFIRMED` with `verification.code_ref`. Pattern match with no reachable input: `false-positive` + reason. Unsure: leave `SUSPECTED`.
- Zero hits: `VERIFIED-ABSENT` worded as "semgrep (rule set: <dirs>, commit a84ff9c) found nothing in <paths>"; never "no vulnerabilities".

### 5. SCA: SEC-SCA (non-critical)
```
run_tool.py --project P --tool osv-scanner --test-type scan -- \
  scan source -r --format json --output-file {evidence}/osv-scanner.json {project}
run_tool.py --project P --tool pip-audit --test-type scan -- \
  -r {project}/requirements.txt -f json -o {evidence}/pip-audit.json
```
- Run the ecosystem auditor that matches the lockfile (`pip-audit` for Python; `npm audit --package-lock-only --json` for npm, saved to `evidence/npm-audit.json`). Cross-tool duplicates collapse in dedupe.
- Missing lockfile: results are approximate; note it and file `lockfiles_missing` under SUP-PINNING.
- A vulnerable package is `TOOL-CONFIRMED` only if the vulnerable function/feature is reachable (read the call site). Otherwise keep `SUSPECTED` with "not reachable / not checked".

### 6. IaC and containers: SEC-IAC (non-critical)
```
run_tool.py --project P --tool hadolint --test-type scan -- -f json <Dockerfile>
run_tool.py --project P --tool checkov  --test-type scan -- -d {project} -o json --output-file-path {evidence}
run_tool.py --project P --tool trivy    --test-type scan -- config --skip-db-update --format json -o {evidence}/trivy-config.json {project}
```

checkov's `github_actions` framework only recognises workflows under `.github/workflows/`; a workflow anywhere else is scanned as 0 resources and reads as an empty pass. Check the resource count in its output: 0 resources for a file you expected it to scan = `NOT-TESTED: checkov scanned 0 resources`, never `VERIFIED-ABSENT`.

Run only those whose inputs exist (Dockerfile, k8s/terraform/compose). No IaC files present: check is not applicable; record `NOT-TESTED: no IaC or container files present`.

### 7. SBOM: SEC-SBOM
```
run_tool.py --project P --tool syft --test-type scan -- scan dir:{project} -o cyclonedx-json={evidence}/sbom.cdx.json
```
Evidence is the SBOM file. Generated: `VERIFIED-ABSENT` as completed marker, title "CycloneDX SBOM generated (syft 1.54.0)". Failed: `NOT-TESTED: tool unavailable: syft`.

### 8. Manual review: SEC-MANUAL-REVIEW (full)
Scanners miss logic flaws. Read, in this order, the rows of `attack-surface.md` that are unauthenticated or state-changing, then: authn flows, password reset, ownership checks on every object fetch, file handling, deserialization, outbound fetches (SSRF), crypto use, mass assignment. Every issue: `SUSPECTED` with `file:line` and a sentence on why it was not reproduced; phase 3 tries to upgrade it to `EXPLOITED`. Record the files read as evidence. Not done: `NOT-TESTED: manual review not performed`.

## Normalize, set check_id, merge
```
python $S/normalize_findings.py --auto <project>/.release-gate/evidence --out <project>/.release-gate/findings-raw.json
python $S/dedupe_findings.py --in <project>/.release-gate/findings-raw.json --out <project>/.release-gate/findings.json --root <project>
```
- `normalize_findings.py` does NOT set `check_id`. Entries without `check_id` never reach the coverage matrix, so set it on every entry: gitleaks -> SEC-SECRETS-HISTORY (SEC-SECRETS-ARTIFACTS for artifact scans), trufflehog -> SEC-SECRETS-VERIFIED, semgrep/bandit -> SEC-SAST, osv-scanner/pip-audit/npm-audit -> SEC-SCA, checkov/hadolint/trivy config -> SEC-IAC, syft -> SEC-SBOM.
- Empty or unparseable tool output becomes `NOT-TESTED` automatically, never "zero findings". Empty valid output becomes `VERIFIED-ABSENT` scoped to that scanner.
- Raw secrets are never written; values show first 4 chars only. Keep it that way in anything you write by hand (`rglib.redact_value`).
- Merge `authz_findings.json`, `policy_findings.json` etc. later with `report_build.py --findings`.

## Adversarial verification (SKILL principle 2)
Spawn a fresh subagent, giving it only the claim and the evidence file, instructed to disprove it:
- every Critical/High finding (e.g. "the key at `config.py:12` is a live credential");
- every critical-category `VERIFIED-ABSENT` here: SEC-SECRETS-HISTORY, SEC-SECRETS-VERIFIED, SEC-SECRETS-ARTIFACTS. Brief: "this scanner reported nothing for <scope>; find a secret in that scope it missed" (grep for key formats, `.env*`, config files, deleted-file history via `git log --all --diff-filter=D`).
Record `adversarial.outcome` = `upheld` | `refuted` | `inconclusive`. Refuted finding: downgrade and say why. Refuted pass: re-run, do not report it as absent.

## NOT-TESTED strings (exact)
- `tool unavailable: <tool>` (from `check_tools.py not_tested_reason`)
- `not a git repository; history not scanned`
- `live verification declined by user (third-party contact)`
- `network use declined and no offline vulnerability database`
- `no build artifacts present`
- `no IaC or container files present`
- `manual review not performed`
- `skipped by user`
