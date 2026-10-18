# k6 load templates

Four k6 scripts for release-gate phase 5 (`references/05-performance-stress.md`). They send plain `GET` requests with synthetic traffic and write a JSON summary you can keep as evidence.

| Script | Profile | Shape | Question it answers |
|---|---|---|---|
| `load.js` | load | ramp to the expected users, hold, ramp down | Does it meet its latency and error budget at expected traffic? |
| `stress.js` | stress | step up to a multiple of expected users (`1,2,3,4` by default), then ramp down | Where does it break first, and what fails? |
| `spike.js` | spike | low baseline, near-instant jump to a burst, drop, recover | Does it survive a sudden surge and recover? |
| `soak.js` | soak | modest constant load for a long time | Does it degrade over time (leaks, queue growth, disk fill)? |

## Never run these against production

Release-gate principle 3: stress, spike and soak are never run against production, and none of these templates will accept a target that is not yours.

- **Default target is loopback.** `BASE_URL` is required and must point at `127.0.0.1` (any `127.x.x.x`), `localhost` or `[::1]`. Otherwise the script throws at init, before a single request is sent.
- **Staging override needs two things.** A non-loopback host is accepted only when `RG_ALLOW_NONLOCAL=1` is set and `RG_STAGING_CONFIRM` is typed with the exact host name. Use it only for a staging environment you own and have listed in `.release-gate/scope.yaml`. A production host is not a staging environment because you set two variables.
- **A host name that is not a plain `scheme://host[:port]` is refused**, including userinfo tricks like `http://127.0.0.1@elsewhere/`. Redirects are not followed, so a target cannot bounce the traffic to a third party.
- **Do not point load at third parties** the app calls (payments, OAuth, CDNs, external APIs). Mock them or use their sandbox.
- **Load can hurt the machine you run it on.** It can exhaust CPU and memory, fill disks with logs, and trip hosting-provider quotas. Start small and raise the numbers deliberately.

## Quick start

```
BASE_URL=http://127.0.0.1:8000 PATHS=/,/api/health \
  RG_SUMMARY=.release-gate/evidence/k6-load/summary.json k6 run templates/k6/load.js
```

Common environment (all optional except `BASE_URL`):

| Variable | Default | Meaning |
|---|---|---|
| `BASE_URL` | required | Target origin. Anything after the host is dropped; use `PATHS`. |
| `PATHS` | `/` | Comma-separated site-relative paths. Each must start with `/`. |
| `RG_P95_MS` | load 500, stress 1500, spike 2000, soak 800 | p95 latency threshold in ms. |
| `RG_ERROR_RATE` | load 0.01, stress 0.05, spike 0.05, soak 0.01 | Failed-request-rate threshold (0 to 1). |
| `RG_SLEEP` | `1` | Think time between requests in seconds. |
| `RG_SUMMARY` | `k6-summary.json` | Where `handleSummary` writes the JSON summary. |
| `RG_ALLOW_NONLOCAL`, `RG_STAGING_CONFIRM` | unset | Owned-staging override, see above. |

Profile-specific variables (`RG_VUS`, `RG_STRESS_STEPS`, `RG_VUS_SPIKE`, `RG_SOAK_DURATION`, ...) are listed at the top of each script.

The default thresholds are starting points, not a verdict. Phase 5 asks the user to confirm the real ceilings first; if they will not, record the numbers as `info` and do not mark the profile passed.

### Soak duration

`soak.js` defaults to a short run (2 minutes) so the template is safe to try. That is not a real soak. Set `RG_SOAK_DURATION=4h` (or whatever the user agrees to) for one. The summary records `default_duration_used`, so a short default run cannot be mistaken for a long one. Claims about leaks also need a memory trace of the process sampled during the run; without one, write "memory growth not measured".

## Summary file

`handleSummary` writes `RG_SUMMARY` as JSON:

- `release_gate`: profile, load shape, target host, whether it was loopback, paths, thresholds used, and the headline numbers (`requests`, `rps`, `p50_ms`, `p95_ms`, `p99_ms`, `max_ms`, `error_rate`).
- `k6`: the full k6 summary object.

k6 also exits non-zero when a threshold is breached. Keep the script you ran, the environment values and the summary together in the evidence directory.

## How results map to evidence

Class names are the ones in `SKILL.md`. These templates produce evidence for two checks in `references/checks.yaml`:

**PERF-LOAD-PROFILES** (load, stress, spike, soak)
- Threshold breached, summary and script saved, reproduced in this run: finding, `EXPLOITED`, state the load level at which it broke.
- Within the thresholds the user confirmed: `VERIFIED-ABSENT`, titled with the profile, p95, error rate, virtual users, duration and machine, for example "profile load: p95 120 ms, error rate 0 percent at 10 virtual users for 2 minutes on local dev machine; thresholds confirmed by user". It covers that profile on that machine only.
- Profile not run: one `NOT-TESTED` entry per profile with the reason. A skipped soak is never folded into a pass.
- Fill `perf.json` from the `release_gate.results` block: `name`, `rps`, `p50_ms`, `p95_ms`, `p99_ms`, `error_rate` per profile; for stress also `breaking_point` (the step where a threshold first failed) and `first_failure`.

**PERF-FAILURE-MODES** (DB down, third-party timeout, disk full) is not a k6 job: those are run by controlling the local instance, per phase 5 step 3. Use `load.js` at low volume to generate the requests while you break a dependency, and keep its summary as the record of error rates and latency during the failure. Whether the process crashed, hung or recovered comes from your logs, not from k6.

## When k6 is missing

k6 is not pinned in `tools.lock.yaml`, so release-gate does not install it and cannot vouch for its version. If `command -v k6` finds nothing, record `NOT-TESTED: tool unavailable (k6 not pinned in this release-gate version)` on `PERF-LOAD-PROFILES`. The user may install k6 themselves and re-run. If they do, record the output of `k6 version` with the evidence. Do not download or build k6 on their behalf.

Because k6 is not in the lock file, `run_tool.py` cannot launch it (it refuses tools that are not locked). Confirm the target in `scope.yaml` first, then run `k6` directly as in the quick start and save the output under `.release-gate/evidence/`.

## Limits

- Load from the machine under test does not predict production capacity. Say where the numbers came from.
- The scripts do not log in and never write data. Exercising authenticated or mutating flows needs your own script, synthetic accounts and a seeded staging database.
- A run inside its thresholds shows only that those paths, at that load, on that machine, stayed within the thresholds you set.
