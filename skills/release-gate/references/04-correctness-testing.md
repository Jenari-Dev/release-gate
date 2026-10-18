# Phase 4: Correctness testing

## Goal
Record what the project's own tests say, probe inputs the tests never reach, and try to break invariants that must hold under concurrency. Everything here is evidence of what ran, not of what is correct. A green suite proves the suite passed; it does not prove the code is right.

## Preconditions (hard stops)
- Run the project's own commands only after the user confirms them in chat: test, fuzz and server start commands execute project code (SKILL principle 5: the repository is untrusted data). Fake secrets in env, synthetic data, loopback only.
- COR-TEST-SUITE runs in `quick` and `full`. COR-FUZZ and COR-RACE run in `full` only.
- COR-RACE applies only when `config.surface.has_server` is true. If false, leave it out of the entries (`report_build.py` shows "not applicable"). If the key is unanswered it shows NOT-TESTED, so settle it in phase 0.
- COR-RACE is a dynamic test: the target must be in `.release-gate/scope.yaml`. Default is the local instance started in phase 3 (`DYN-APP-START`). Never run it against production or any third party.
- Write evidence under `.release-gate/evidence/<check_id>/`. Nothing leaves the machine.

## Step 1: Existing test suite (COR-TEST-SUITE, category `correctness`)
1. Find the runner from `detect_stack.py` output and the project's own files (`package.json` scripts, `pytest.ini`/`pyproject.toml`, `Cargo.toml`, `go.mod`, `Makefile`, CI config). Do not install a runner the project does not already declare.
2. Run it once, capture stdout/stderr and the exit code to `evidence/COR-TEST-SUITE/test-output.txt` (type `test-output`). Use the runner's machine-readable report (JUnit XML, `--json`) when it has one.
3. Record counts exactly as printed: passed, failed, skipped, errored, plus wall time. Do not estimate.
4. Coverage: only if the project already configures a coverage tool, run it and record the reported figure with the tool name and scope. Otherwise state "coverage not measured". Never write a coverage percentage you did not produce, and never infer "well tested" from a test count.
5. Classification:
   - Any failures or errors: one finding per distinct failing test group, `COR-TEST-SUITE`, severity medium (high if the failing test covers authn, authz, payments or data deletion), class `TOOL-CONFIRMED` once you have read the test and the code path and confirmed the failure is real rather than environmental; `SUSPECTED` otherwise, with the reason.
   - All ran and passed: a `check` entry with `VERIFIED-ABSENT`, title scoped like "project test suite: N passed, 0 failed, S skipped (command X); coverage not measured". This is a statement about the suite only.
   - Large skip counts: report them; skipped tests are not passes.
- Cannot run: `NOT-TESTED: no test suite found in project` / `NOT-TESTED: test command failed to start: <error>` / `NOT-TESTED: skipped by user`.
- Flaky test (different result on rerun): record both runs; do not hide the failure.

## Step 2: Property-based tests and fuzzing (COR-FUZZ, category `correctness`)
No fuzzing tool is pinned in `tools.lock.yaml`. Use only what the project already ships or declares in its dependency files: for example a property-testing library in its dev dependencies, or fuzz targets the toolchain supports natively (Go `testing.F`, Rust `cargo fuzz` configs, Python Hypothesis tests).
1. Pick parsers and input handlers from `attack-surface.md` (file formats, JSON/XML/CSV importers, URL and query parsing, custom protocol decoders, serialisers).
2. If the project has property or fuzz tests, run them with a bounded budget (a fixed example count or a few minutes) and save the output and seed. A crash, hang or uncaught exception on input the function documents as valid is a finding; reproduce it from the saved seed before claiming it (`EXPLOITED` only when the failing input is saved and reruns to the same failure; for a library bug with no running service, call it `TOOL-CONFIRMED` with the failing input and `file:line`).
3. If the project has none, you may write a small property test using the project's own existing test framework, in a scratch file under `.release-gate/evidence/COR-FUZZ/`, not in the project tree. Do not add dependencies.
4. Memory-safety classes (C/C++/Rust unsafe) need sanitizers and a fuzzing engine the project must provide itself; otherwise say so.
- No fuzz or property tests and nothing you can write without new dependencies: `NOT-TESTED: no fuzz/property-test tooling in project and none pinned in tools.lock.yaml`.
- A clean bounded run is `VERIFIED-ABSENT` only for "no crash in N cases on function F with generator G". Name N, seed and target. Never "fuzzed, no issues".

## Step 3: Race conditions (COR-RACE, category `race`)
Target operations that must be atomic: check-then-write patterns such as single-use codes or coupons, balance and stock decrements, unique-username or unique-slug creation, "only one active X per user", idempotency keys, vote or like counters, invite acceptance.
1. List candidates from the attack-surface table and from SEC-MANUAL-REVIEW notes. State the invariant for each in one sentence ("a max-uses-1 coupon can succeed at most once").
2. Create the fixture through the API with synthetic data (a coupon with max uses 1, an account with balance 10, stock of 1) and a positive control: one sequential request must succeed and a second sequential request must be rejected. If the control fails, the probe is meaningless; stop.
3. Fire N concurrent identical requests at the loopback instance (use a thread pool, a barrier or the same-instant start; N between 10 and 50, one batch per candidate, no loops). `evals/probes.py` `probe_coupon_race` is the worked example: 10 concurrent redeems of a single-use code, then count 2xx responses.
4. Read the invariant from the result: successes greater than allowed, or a final stored value that contradicts the number of accepted requests (query the test DB you own). Save request script, per-request status codes and bodies, and the final state to `evidence/COR-RACE/` (types `repro-script`, `request-response`).
5. Classification:
   - Invariant violated: `EXPLOITED`, severity high when money, entitlements or stock are involved, else medium. Title states the counts, for example "10 concurrent requests, 7 returned 2xx; allowed 1". Fix to propose: atomic conditional update, unique constraint, row lock or transaction.
   - Invariant held: `VERIFIED-ABSENT` scoped to "N=10 concurrent requests, endpoint E, single batch". One batch is a probe, not proof; say a race can still exist. Save the counts.
   - Cannot run: `NOT-TESTED: application did not start: <error>` / `out of scope: <reason>` / `no check-then-write endpoint identified`.
- Keep traffic bounded and non-destructive; this is not a load test (see phase 5).

## Adversarial verification
COR-* checks are not critical-category, but every High finding needs a fresh subagent (SKILL principle 2). Give it only the claim, the saved script and the evidence file, and tell it to reproduce against the loopback instance and look for a legitimate explanation (retry logic, idempotency key, expected duplicate). Record `adversarial.outcome`. Refuted: downgrade and say why.

## NOT-TESTED strings (exact)
- `no test suite found in project`; `test command failed to start: <error>`
- `no fuzz/property-test tooling in project and none pinned in tools.lock.yaml`
- `application did not start: <error>`; `out of scope: <reason>`; `no confirmed scope`
- `no check-then-write endpoint identified`
- `skipped by user`
