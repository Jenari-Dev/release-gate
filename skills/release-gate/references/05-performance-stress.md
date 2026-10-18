# Phase 5: Performance and failure modes

## Goal
Measure how the service behaves under defined load and when its dependencies fail, against thresholds the user agreed to, and record the numbers. This phase reports measurements on one machine at one time; it does not certify capacity.

## Preconditions (hard stops)
- Both checks apply only when `config.surface.has_server` is true. Otherwise they are not applicable.
- Targets come only from `.release-gate/scope.yaml`. Default: the loopback instance from phase 3 (`DYN-APP-START`), or a staging environment the user owns and listed in scope.
- Production: never run stress, spike or soak (SKILL principle 3). The `baseline`/`load` profile against production needs a typed confirmation naming the exact URL, and the user must own it. When unsure, treat the target as production and refuse.
- Never aim load at a third party the app calls (payments, OAuth, CDN, APIs). Point the app at mocks or vendor sandboxes first.
- Warn the user before starting: load can exhaust the local machine, fill disks with logs and trip hosted-provider quotas. Remind them they must own or be authorised to test every target.
- Synthetic data and test accounts only. Seed through the project's own API or seed script.

## Tooling
k6 is NOT in `tools.lock.yaml`, so release-gate does not install it and cannot vouch for its version. Check with `check_tools.py --json` and `command -v k6`. If k6 is missing: `NOT-TESTED: tool unavailable (k6 not pinned in this release-gate version)` on PERF-LOAD-PROFILES, and tell the user they may install k6 themselves and rerun. If the user supplies k6, record its version in the evidence. Do not download or build k6 for them.

Templates (shipped with this plugin, read-only): `templates/k6/load.js`, `templates/k6/stress.js`, `templates/k6/spike.js`, `templates/k6/soak.js`. Copy to `.release-gate/perf/`, set `BASE_URL` and the endpoint list from `attack-surface.md` by environment variable, and run through `run_tool.py` (test type `load`) so the scope check applies.

## Step 1: Agree thresholds (before any run)
Ask the user to confirm in chat, per endpoint group where they differ:
- p95 latency ceiling (ms) and p99 if they care
- max error rate (percent of non-2xx/3xx excluding expected 4xx)
- peak concurrent users or requests per second the product claims to handle
- for soak: acceptable memory growth and duration
Write them to `.release-gate/perf/thresholds.yaml`. If the user will not choose, use no pass/fail: record the numbers as `info` and do not mark the profile passed. Never invent a threshold and then pass against it silently.

## Step 2: Load profiles (PERF-LOAD-PROFILES, category `performance`)
| Profile | Template | Shape | Allowed targets |
|---|---|---|---|
| baseline/load | `load.js` | steady expected traffic, a few minutes | loopback, staging, production only with typed confirmation |
| stress | `stress.js` | ramp beyond expected load until thresholds break | loopback or user-owned staging |
| spike | `spike.js` | sudden jump and drop | loopback or user-owned staging |
| soak | `soak.js` | moderate load for an extended time | loopback or user-owned staging |

1. Run profiles in that order, one at a time, with `--summary-export <evidence>/k6-<profile>-summary.json` and the console output saved. Record machine facts that change results (CPU count, whether the DB is local SQLite or a real server, debug mode on or off).
2. Compare the summary to `thresholds.yaml`: p95/p99 latency, error rate, request count, dropped iterations, and the load level at which a threshold first broke (for stress).
3. Classification:
   - Threshold breached: finding `PERF-LOAD-PROFILES`, category `performance`, severity medium (high if the service stops answering or corrupts data under load), class `EXPLOITED` when the k6 summary and run script are saved and the breach reproduced in this run; state the load level.
   - Within thresholds: `VERIFIED-ABSENT` titled "profile P: p95 X ms, error rate Y percent at Z virtual users for D minutes on <target description>; thresholds confirmed by user". It covers that profile on that machine only.
   - Profile not run: one `NOT-TESTED` entry per profile, with the reason. Do not roll a skipped soak into a pass for "performance".
4. Soak also needs a resource trace (process memory sampled at intervals via the OS tooling available) to claim anything about leaks. No trace: say "memory growth not measured".

## Step 3: Failure modes (PERF-FAILURE-MODES, category `performance`)
Run against the local instance only, by controlling the environment you started (never by breaking shared infrastructure):
1. Database unavailable: stop or point the app at a closed port; send requests; record status codes, bodies, whether the process crashes, and whether it recovers when the DB returns without a restart.
2. Third-party timeout: point the app's outbound URL at a loopback listener you start that accepts and never responds (or returns 500s); record request duration, timeouts configured in code, and whether threads/workers are exhausted.
3. Disk full or unwritable data directory: use a small tmpfs or read-only mount you create for the test; record behaviour on writes and uploads. If you cannot create one without privileges: `NOT-TESTED: could not simulate disk full without elevated privileges`.
4. Read health-check behaviour in each state (does `/health` still say OK?).
5. Findings: unhandled crash, hung requests with no timeout, stack trace leaking in the error body (also feed SEC-ERROR-LEAKS), or health check reporting healthy while broken. `EXPLOITED` when reproduced with saved logs and responses; reading a missing timeout in code without running it is `SUSPECTED`.
6. All three modes ran and degraded cleanly: `VERIFIED-ABSENT` scoped to the modes tried, with logs. Modes skipped are listed as `NOT-TESTED` with reasons.

## Adversarial verification
No check here is critical-category. Any High finding still gets a fresh subagent (SKILL principle 2): give it the k6 script, the summary and the thresholds, and ask it to find an environmental cause (local CPU contention, debug server, cold start) before the claim stands.

## NOT-TESTED strings (exact)
- `tool unavailable (k6 not pinned in this release-gate version)`
- `out of scope: <reason>`; `no confirmed scope`
- `application did not start: <error>`
- `thresholds not confirmed by user` (numbers recorded as info only)
- `not run against production: stress/spike/soak refused (principle 3)`
- `could not simulate disk full without elevated privileges`
- `skipped by user`
