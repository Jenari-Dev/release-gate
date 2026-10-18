# Phase 3: Dynamic security

## Goal
Start the app locally with synthetic data and try to break it. Each issue gets a repro script plus the captured request/response; a probe that ran and failed to break it is `VERIFIED-ABSENT` with that output as evidence. The authorization matrix is the highest-value test.

## Preconditions (hard stops)
- `scope.yaml` is confirmed by the user and lists the target. Default target: a local instance you start yourself on `127.0.0.1`. Remind the user once: "You must own or be authorized to test every target in scope.yaml."
- Applies only when `config.surface.has_server` (and `has_web_ui` for XSS/CSRF). Otherwise record each check as not applicable, not as passing.
- Never touch hosts in `excluded_hosts` (payment, OAuth, CDN, APIs the app calls). Point the app at mocks or vendor sandboxes via env.
- Only synthetic data and test accounts you create. Never real credentials, never production data.
- Production targets: passive/scan/authz/exploit/load only, typed confirmation, no fuzz/stress/spike/soak, no data-deleting requests.
- Exploit probes must be non-destructive: markers and canaries, no `DROP`, no deletes, no mass requests. Brute-force and enumeration probes stay below ~50 requests.
- **Read-proofs touch only canaries you planted.** SSRF, path traversal, file inclusion, XXE and any other "the server will read X for me" proof may only read:
  - an HTTP canary listener you start yourself on a free loopback port, serving a random token; or
  - a canary file you create, with a random token, in a scratch directory you own (`.release-gate/evidence/<check>/canary-<token>.txt`).

  Never read pre-existing host files (`/etc/*`, `~`, `/proc`, `.env`/env files, SSH keys, cloud credential files) or any metadata endpoint (`169.254.169.254`, `metadata.google.internal`, and their loopback stand-ins), even on localhost and even when a fixture invites it. If a scheme reaches the filesystem (`file://`, `../`), demonstrate it with your planted canary file and stop: one token read is the whole proof. Anything else would copy real host secrets into evidence and reports. `report_lint.py` fails a run whose evidence contains this machine's hostname or a passwd line.

## Step 1: Start the app (DYN-APP-START)
1. Take `surface.start_command` (confirm with the user: it executes project code). Bind to loopback, fake secrets in env, seeded test DB. Use the project's own seed script or create data through its API.
2. Create at least two ordinary users (`alice`, `bob`) and, if roles exist, one privileged user, each owning a resource with a unique canary string in its content.
3. Wait for the port (up to 60 s). Save start command, env names (not values), and the first health response to `.release-gate/evidence/app-start/`.
- Started and answering: `DYN-APP-START` check, class `VERIFIED-ABSENT` as completed marker ("application started locally, seeded"), evidence = start log + health response.
- Will not start: `NOT-TESTED: application did not start: <error>` on DYN-APP-START and the same reason on every other has_server check in this phase. Do not substitute static reasoning for a dynamic pass. (A gate that could not run its dynamic tests is likely `BLOCK: insufficient evidence` in full mode; that is correct.)

## Step 2: Authorization matrix (SEC-AUTHZ-MATRIX, critical)
Build `authz-spec.yaml` from `attack-surface.md` (every object-by-id route):
```yaml
base_url: http://127.0.0.1:3101
login:                      # token-in-JSON logins only
  path: /login
  method: POST
  encoding: form            # form | json
  token_field: token        # key in the JSON response
  header: Authorization     # default
  scheme: "Bearer "         # default
users:
  - {name: alice, username: alice, password: <fixture-pw>}
  - {name: bob,   username: bob,   password: <fixture-pw>}
resources:
  - endpoint: "GET /api/messages/{id}"
    owned: {alice: [1], bob: [2]}     # principal -> ids they own
    public: false                      # true = anyone may read
    canary: "CANARY"                   # substring proving cross-user data leaked
```
Run:
```
python <skill>/scripts/authz_matrix.py --project <project> --spec authz-spec.yaml
# writes .release-gate/authz_findings.json + evidence/authz/*.txt
```
- It logs in each user, then every other principal plus the anonymous caller requests each owned resource. Any 2xx on a non-public resource: finding `RG-AUTHZ-0xx`, critical, `EXPLOITED`, saved request/response. All denied: one check `VERIFIED-ABSENT`, evidence `evidence/authz/denied_cross_user_requests.txt`, `adversarial.required: true`.
- Scope is checked with test type `exploit`; out of scope gives `NOT-TESTED: out of scope: <reason>`. No owned resources in the spec gives `NOT-TESTED: no owned resources to probe in the authz spec`.
- Positive control first: with curl, confirm each user can read their own resource. A failed login silently makes that principal anonymous and its "denials" meaningless. Keep the control output as evidence.
- Vertical escalation: model admin-only endpoints as resources owned by the admin user so every normal user and anonymous probe them.
- Methods other than GET execute: use throwaway ids, and cookie-session logins are not supported (manual curl probes instead, saved as `request-response` evidence, class set by the same rule: 2xx cross-user = `EXPLOITED`).
- A VERIFIED-ABSENT here covers only the listed endpoints and ids. Title it so, and list uncovered routes in the check's description.

## Step 3: Other dynamic probes
For each, save the exact curl/script (`repro-script`) and the response (`request-response`) under `.release-gate/evidence/<check>/`. Reproduced = `EXPLOITED`. Probe ran, no effect = `VERIFIED-ABSENT` (scoped to the inputs tried). Not run = `NOT-TESTED: <reason>`.

| check_id | Critical | Probe |
|---|---|---|
| SEC-INJECTION-DYNAMIC | yes | Per input from the attack-surface table: SQLi (single quote error diff, boolean pair, short `sleep`), command injection (`;echo RGMARK`), template (`{{7*7}}`), path traversal (only the canary file you planted; never system files, see preconditions). Success = marker/canary in the response. |
| SEC-XSS-DYNAMIC | no | Unique payload (`<img src=x onerror=...rgmark>`) stored/reflected; EXPLOITED if returned unescaped in an executable HTML context (confirm in the Playwright Chromium if available), else `VERIFIED-ABSENT` for that sink. |
| SEC-SSRF-DYNAMIC | no | For URL-taking features, point at a canary listener you start on a free loopback port (in scope), serving a random token. A callback hit or the token in the response = `EXPLOITED`. If `file://` is accepted, read only your planted canary file and stop. Never aim at cloud metadata, internal services the app ships with, host files, or third-party hosts. Allowlist/DNS-rebinding bypass probes use only names that resolve without a third party (`localhost`, `*.localhost`, an `/etc/hosts`-free numeric form like `http://2130706433/`); never public wildcard-DNS services (`nip.io`, `sslip.io`, `xip.io`) or Interactsh/OAST hosts, since resolving them contacts a third party. |
| SEC-AUTHN-BRUTEFORCE | yes | ~30 wrong passwords for a test account at normal speed; record lockout / 429 / delay. No limiting observed after N attempts = `EXPLOITED` (state N). |
| SEC-AUTHN-ENUMERATION | yes | Compare login, reset and register for an existing vs nonexistent account: status, body, headers, timing. Any distinguishable difference = `EXPLOITED`. |
| SEC-SESSION | yes | Cookie flags (`HttpOnly`, `Secure` when served over TLS, `SameSite`); old token/cookie reused after logout and after password change must be rejected. |
| SEC-CSRF | no | Cookie-auth state-changing request with `Origin: http://evil.invalid` and no token; accepted = `EXPLOITED`. Token-header APIs: record why not applicable. |
| SEC-HEADERS-CORS | no | `curl -sI` for CSP, X-Content-Type-Options, frame protections, HSTS (TLS only); send hostile `Origin`, flag reflected origin with credentials allowed. |
| SEC-UPLOADS | no | Oversize file, wrong extension/content-type, HTML/SVG with script, traversal in filename; check stored name and served `Content-Type`. No upload feature: not applicable. |
| SEC-ERROR-LEAKS | yes | Malformed JSON, wrong types, huge values, bad ids, unknown routes; stack traces, SQL, file paths, secrets in the body = finding (`EXPLOITED`). |

Rules:
- The class is `EXPLOITED` only if you reproduced it in this run. Code reading alone stays `SUSPECTED` with the reason it was not reproduced (for example "app would not start").
- `VERIFIED-ABSENT` on SEC-INJECTION-DYNAMIC, SEC-AUTHN-BRUTEFORCE, SEC-AUTHN-ENUMERATION, SEC-SESSION, SEC-ERROR-LEAKS needs saved probes and adversarial verification. State the inputs covered ("12 string parameters on 7 routes").
- Inapplicable (no accounts, no web UI): leave the check out of the entries; `report_build.py` shows "not applicable" from `config.yaml`. Unanswered config: it shows NOT-TESTED, so answer config in phase 0.

## Step 4: Scanner sweep (SEC-DAST-SCAN, non-critical)
Both run only against in-scope targets via `run_tool.py` (it refuses out-of-scope targets, exit 5, and starts no process).

**nuclei: safe templates only**, from the pinned vendored set:
```
SHARE=~/.local/share/release-gate
run_tool.py --project P --tool nuclei --target http://127.0.0.1:3101 --test-type scan -- \
  -u http://127.0.0.1:3101 -t $SHARE/nuclei-templates/http/misconfiguration \
  -t $SHARE/nuclei-templates/http/exposures -severity info,low,medium -rl 20 -duc -ni \
  -jsonl -o {evidence}/nuclei.jsonl
```
`-ni` (no Interactsh) is mandatory: without it nuclei registers with a public out-of-band server (`oast.*`), a third party. `-duc` stops its update check. `run_tool.py` adds both if they are missing and records them in `result.json` as `forced_flags`. Never call nuclei directly, outside `run_tool.py`. No fuzzing, DoS, brute-force, default-login or `cves` dirs, no destructive templates, no template downloads or `-update-templates`.

**ZAP baseline (spider + passive only, no active scan).** Write `.release-gate/zap-plan.yaml`:
```yaml
env:
  contexts:
    - {name: rg, urls: ["http://127.0.0.1:3101"], includePaths: ["http://127.0.0.1:3101.*"]}
  parameters: {failOnError: false, progressToStdout: true}
jobs:
  - {type: spider, parameters: {context: rg, maxDuration: 2}}
  - {type: passiveScan-wait, parameters: {maxDuration: 5}}
  - {type: report, parameters: {template: traditional-json, reportDir: <abs>/.release-gate/evidence/zap, reportFile: zap.json}}
```
For an API with an OpenAPI file add an `openapi` job before the spider. Run (zap needs a JRE; set `JAVA_HOME` if `zap.sh` cannot find Java):
```
JAVA_HOME=/usr/lib/jvm/java-21-openjdk python <skill>/scripts/run_tool.py --project P --tool zap \
  --target http://127.0.0.1:3101 --test-type scan -- -cmd -silent -autorun <abs>/.release-gate/zap-plan.yaml
```
Executable: `$SHARE/zap/ZAP_2.17.0/zap.sh`. Add no `activeScan` job and no ZAP quick-attack mode. Never point it at an excluded host (its spider follows links: keep `includePaths` tight).

Normalize and set `check_id: SEC-DAST-SCAN` on these entries:
```
python <skill>/scripts/normalize_findings.py --auto <project>/.release-gate/evidence --out <project>/.release-gate/findings-raw.json
```
Scanner alerts start `SUSPECTED`. Reproduce the request that triggered it (curl it, save it): reproduced = `EXPLOITED`, confirmed in code only = `TOOL-CONFIRMED`. Header or banner informational alerts stay low/info.
- Missing tool: `NOT-TESTED: tool unavailable: nuclei` / `tool unavailable: zap` / `tool unavailable: java runtime`.

## Merge
```
python <skill>/scripts/dedupe_findings.py --in findings-raw.json --out findings.json --root <project>
```
Include `authz_findings.json` through `report_build.py --findings` (phase 13) or by concatenating before dedupe. Findings never lose their evidence class in a merge: the strongest wins.

## Adversarial verification (SKILL principle 2)
Spawn a fresh subagent with only the claim, the repro and the evidence file:
- every Critical/High finding: "reproduce this against `http://127.0.0.1:<port>` and say whether the response proves the claim; try to find a legitimate reason access was allowed (public resource, same owner, test-data collision)";
- every critical-category `VERIFIED-ABSENT`: SEC-AUTHZ-MATRIX, SEC-INJECTION-DYNAMIC, SEC-AUTHN-BRUTEFORCE, SEC-AUTHN-ENUMERATION, SEC-SESSION, SEC-ERROR-LEAKS. Brief: "this check says X cannot happen; find an endpoint, role, id or input the tests missed and try it." Give it the spec/probe list so it knows what was covered.
Write the result to `adversarial.outcome` (`upheld` / `refuted` / `inconclusive`). Refuted finding: downgrade and record why. Refuted pass: add the missing probe and re-run. `inconclusive` or `not-run` on a critical pass keeps the verdict at SHIP WITH ACCEPTED RISKS at best.

## NOT-TESTED strings (exact)
- `application did not start: <error>`
- `out of scope: <reason from check_scope>`; `no confirmed scope`
- `no owned resources to probe in the authz spec`
- `tool unavailable: <nuclei|zap|java runtime>`
- `no feature to test: <upload|URL fetching>` (when the surface table shows none; otherwise treat as not applicable)
- `skipped by user`
