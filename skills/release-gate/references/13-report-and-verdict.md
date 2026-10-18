# Phase 13: Report and verdict

## Goal
Merge all results, close every open adversarial check, build the report and verdict with `report_build.py`, and present it honestly. The verdict is computed by the script from the recorded entries. You do not choose it, soften it, or edit the report afterwards.

## Step 1: Pre-flight (before building)
1. **Collect entries.** Everything lands in `<project>/.release-gate/findings.json` (list or `{"entries": [...]}`), or in extra files passed with `--findings`: `authz_findings.json` (phase 3), `policy_findings.json` (phase 8). Make sure scanner entries from phases 2-3 were normalized and carry a `check_id` (`normalize_findings.py` does not set it; an entry without one never reaches the coverage matrix).
2. **Merge duplicates:**
   ```
   python <skill>/scripts/dedupe_findings.py --in <project>/.release-gate/findings-raw.json \
     --out <project>/.release-gate/findings.json --root <project>
   ```
   Strongest evidence class wins in a merge (EXPLOITED > TOOL-CONFIRMED > SUSPECTED); `kind: check` entries pass through untouched.
3. **Class audit.** For each entry: exactly one evidence class; `EXPLOITED` / `TOOL-CONFIRMED` / `VERIFIED-ABSENT` have artifacts that exist under `.release-gate/`; `NOT-TESTED` has `not_tested_reason`; `TOOL-CONFIRMED` has `verification.code_ref`; no scanner finding is still `unverified` if you can verify it. Fix the entry, not the wording.
4. **Adversarial sweep (SKILL principle 2).** List every entry with `adversarial.required: true` (all Critical/High findings, all critical-category `VERIFIED-ABSENT`: SEC-SECRETS-HISTORY, SEC-SECRETS-VERIFIED, SEC-SECRETS-ARTIFACTS, SEC-AUTHZ-MATRIX, SEC-INJECTION-DYNAMIC, SEC-AUTHN-BRUTEFORCE, SEC-AUTHN-ENUMERATION, SEC-SESSION, SEC-ERROR-LEAKS). Any with outcome `not-run`: spawn a fresh subagent per claim (or one batch if the claims are independent; max 3-4 concurrent), giving it only the claim and the evidence and telling it to disprove it. Record `outcome` = `upheld` / `refuted` / `inconclusive`, plus `summary` and `action_taken`.
   - Refuted finding: downgrade (usually to `SUSPECTED`) or mark `false-positive` with `verification.reason`.
   - Refuted pass: re-run the check; keep the old entry only as history.
   - `inconclusive` / `not-run`: the pass is not upheld and caps the verdict.
5. **Waivers.** `waivers.yaml` entries (`W-nnn`, `match.finding_id` or `fingerprint`, `reason`, `owner`, `created`, `expires`) are applied only if unexpired. A waiver changes how the verdict treats a finding; it never turns it into a pass. Never write one yourself without the user's explicit request in chat.
6. **State files.** Optional inputs: `privacy.json` (07), `documents.json` (08), `perf.json` (phase 5), `config.yaml` (`phases_skipped`, `features`, `surface` drive "not applicable" vs NOT-TESTED).

## Step 2: Build
```
python <skill>/scripts/report_build.py --project <project> --mode full \
  [--findings <project>/.release-gate/authz_findings.json] \
  [--findings <project>/.release-gate/policy_findings.json] [--date YYYY-MM-DD] [--no-history]
```
- `--mode`: `quick`, `full`, `legal`, `retest`.
- Writes `.release-gate/reports/release-gate-<date>.{md,html,sarif,json}` (HTML is self-contained, no scripts) and a run summary in `history/`, then runs the lint automatically.
- Exit 0 = final report. Exit 2 = lint failed: files are renamed `release-gate-<date>.lint-failed.*`, problems are printed as `LINT: ...`, and no history is written. A lint-failed report is never delivered as final.
- Lint fails on: banned reassurance phrases ("secure", "fully compliant", "no vulnerabilities", "production-ready", "best practices followed", "appears safe", "looks good", "great job") unless the same line has `VERIFIED-ABSENT` and an evidence link; a pass or finding (EXPLOITED / TOOL-CONFIRMED / VERIFIED-ABSENT) with no artifact; an artifact path that does not exist; a missing/invalid evidence class; `NOT-TESTED` without a reason; an unredacted secret; external assets or scripts in the HTML.
- On a lint failure: read the `LINT:` lines, fix the underlying entries (add the evidence, correct the class, redact the value, reword the title), rebuild. Do not edit the generated files, and do not weaken the lint.

## Step 3: Verdict rules (as computed by `report_build.py`)
**BLOCK** if any of:
- an open critical or high finding with no active waiver;
- an `EXPLOITED` critical or high finding, even if waived (a proven hole is not an accepted risk);
- full mode only: "insufficient evidence", i.e. at least half of the applicable critical checks expected in full mode are `NOT-TESTED` for a reason other than "skipped by user". The gate fails closed when it could not look.

**SHIP WITH ACCEPTED RISKS** if no BLOCK and any of:
- an applicable critical check is not `VERIFIED-ABSENT` (`NOT-TESTED` or `SUSPECTED`), or is `VERIFIED-ABSENT` but not `upheld` by adversarial verification;
- an active waiver covers a finding;
- an open medium finding exists;
- the mode is not `full` ("this is not a release decision").

**SHIP** only when every applicable critical check is `VERIFIED-ABSENT`, each adversarially upheld, with no open critical, high or medium finding, no active waiver, and `full` mode.

Special cases: `legal` mode returns `NOT-EVALUATED` (documents and consistency check, no release verdict). Checks that do not apply per `config.yaml` show "not applicable" and are excluded; the same check with an unanswered config key shows NOT-TESTED, so finish intake first. Low and info findings do not move the verdict.

## Step 4: Report contents (what each section must show)
1. **Verdict** with the exact blocking/capping reasons and open-finding counts.
2. **Coverage matrix:** every check in `checks.yaml` with phase, critical flag, evidence class, result, reason, linked artifact. NOT-TESTED rows are visible, never omitted; "no result recorded" means a phase did not write an entry.
3. **Findings:** by severity then evidence strength; each with location, impact (attacker view first), repro, fix, retest status, evidence links, reporting tool/rule/scope.
4. **Adversarial verification:** each entry that required it, with outcome and action.
5. **Privacy summary:** inventory table (and whether the user confirmed it), third parties, applicable regimes (flagged stale after 12 months), rights tests, cookie audit stages, policy-mismatch count.
6. **Generated documents:** DRAFT list and "Questions for a lawyer".
7. **Performance:** from `perf.json`, else "Not run".
8. **Trend vs previous run:** new, fixed, regressions.
9. **Waivers:** active and expired.
10. **Limitations**, then the mandatory **Disclaimer** section. Never remove or soften it.
Appendix A lists findings judged false positives with reasons.

## Step 5: Present to the user
- Lead with the verdict and the 1-3 things an attacker could do today; then counts; then NOT-TESTED areas that matter; then the report paths.
- State what the verdict does not cover: only what the coverage matrix shows was checked; scanners report only their own rules and scope; not a penetration test, not legal advice.
- Offer fixes as patches, never as edits to the project; commit nothing. For each EXPLOITED finding give the repro command so the user can watch it fail after the fix.
- Offer waivers (with reason, owner, expiry) for accepted non-exploited risks. If asked to mark something passing without evidence: refuse, explain the evidence class it would need.
- After fixes: run `retest` mode. Each previously reported finding gets re-run; `retest.status` becomes `no-longer-reproduces` or `still-reproduces` with an evidence path. A fix without a passing retest stays open.

## Modes at a glance
| Mode | Phases | Verdict |
|---|---|---|
| quick | secrets, SAST, SCA, tests, policy check | capped at SHIP WITH ACCEPTED RISKS at best |
| full | all | BLOCK / SHIP WITH ACCEPTED RISKS / SHIP |
| legal | 1, 7, 8 | NOT-EVALUATED |
| retest | prior findings with a recorded repro | capped; trend shows fixed vs regressed (playbook: `references/modes/retest.md`) |

## NOT-TESTED strings (exact)
- `no result recorded` (shown automatically for a check no phase wrote; fix by running or explicitly recording the phase)
- `skipped by user` (exact phrase; excluded from the "insufficient evidence" count)
- `not part of <mode> mode`
- Phase files not yet available: `phase not implemented in this release-gate version`
