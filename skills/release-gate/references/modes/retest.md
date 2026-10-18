# Mode: retest

## Goal
After the user changes code, find out which previously reported problems are actually gone. A retest closes findings only on new evidence from re-running the original check. It never closes one because the diff looks right.

## Inputs
- `<project>/.release-gate/findings.json`: the previous run's entries. This is the source of truth for retest.
- `history/*.json` holds run summaries (ids, severity, class, open flag) for the trend table. It is not enough to re-run a check, so a project with history but no `findings.json` has nothing to retest: say that, and offer a full run.
- `scripts/retest.py` does the bookkeeping. The re-running is done by you with the normal tools, in scope.

Show the one-line disclaimer from SKILL principle 6 first (retest is one of the modes that requires it).

## Flow
1. **Plan.** `python <skill>/scripts/retest.py plan --project <project>` prints the findings to re-run: `kind: finding`, status not `fixed` / `false-positive` / `waived`, class `EXPLOITED`, `TOOL-CONFIRMED` or `SUSPECTED`. Show the user the list. Waived and false-positive entries are left alone on purpose.
2. **Scope.** Dynamic re-runs need the target in `scope.yaml`. If it is missing or stale, re-confirm it with the user in chat first (principle 3). Local instance by default; no fuzz/stress against production, ever.
3. **Re-run per finding**, using exactly the original method:
   - `EXPLOITED`: start the app (phase 3 steps), then re-execute the saved repro script / request. Capture the new request/response under `evidence/retest-<stamp>/`. Same input, same account setup.
   - `TOOL-CONFIRMED`: re-run the same tool, same rules, same scope. Re-read the code path at the (possibly moved) location.
   - `SUSPECTED`: re-read the code path and note the state. It was never reproduced, so a retest can't prove it gone. Write a repro now if you can; that creates a new `EXPLOITED` result the next run can close.
4. **Record results as entries**, to a separate file (`findings-retest.json`), with the same `check_id` and `location` as the original so they match:
   - issue reproduced again: a finding, class `EXPLOITED` / `TOOL-CONFIRMED`, with the new evidence;
   - the repro ran and did not reproduce: a `check` entry, `VERIFIED-ABSENT`, title scoped like "original repro for RG-AUTHZ-001 re-run: request returned 403 for another user's message", evidence = the new run's output;
   - could not run (app won't start, tool missing, repro script gone): `NOT-TESTED` with the exact reason.
5. **Apply.** `python <skill>/scripts/retest.py apply --project <project> --new <project>/.release-gate/findings-retest.json`. It validates every entry against `finding.schema.json`, keeps a copy as `findings.pre-retest.json`, and prints one outcome per finding. `--dry-run` shows the outcomes without writing.
6. **Adversarial verification** on every finding you are about to call fixed if it was Critical/High: a fresh subagent gets the original claim and the new evidence and tries to show the issue still exists (a different account, a variant payload, another route to the same sink). Record the outcome in `adversarial`. Refuted: revert `status` to `open` and say why.
7. **Build.** `report_build.py --project <project> --mode retest`. The trend section lists what was fixed, new and regressed. Lint failures are fixed in the entries, never in the report.

## Outcome rules (what `retest.py apply` enforces)
| Re-run result | `status` | `retest.status` |
|---|---|---|
| Original `EXPLOITED` / `TOOL-CONFIRMED`, matching `VERIFIED-ABSENT` with non-code-ref evidence that is new and exists on disk | `fixed` | `no-longer-reproduces` (+ `evidence_path`) |
| Matching `EXPLOITED` / `TOOL-CONFIRMED` result, even next to a clean one | `open` | `still-reproduces` |
| `NOT-TESTED`, no matching result, evidence missing / identical to the original / a code reference only | unchanged | `not-run` |
| Original `SUSPECTED`, any result | unchanged (open) | `not-run`; the outcome note says why |

Matching is by `check_id` plus endpoint/file/component (line numbers drift and are ignored), or by id or fingerprint. A reused id for a different check never matches. A result with no location matches every finding of that check, which fails closed. New findings that match nothing are appended with collision-free ids and show up as new.

## What a retest never does
- Mark `fixed` from reading the diff, from a commit message, or because the code "now checks ownership".
- Close a finding whose repro could not be run. It stays open and the report says NOT-TESTED.
- Touch waivers. An expired waiver is a finding again; the user renews or fixes it.
- Reword the verdict. `report_build.py` computes it from the updated entries.

A fixed finding keeps its original evidence class as history; the new evidence is appended next to it.
