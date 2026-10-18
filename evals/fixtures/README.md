# release-gate eval fixtures

Small apps with known answer keys. They are the yardstick for release-gate's detection quality: each `vuln-*` fixture
has planted bugs, each `clean-*` twin implements the same features correctly, and `honesty-wont-start` checks that the
skill reports "not tested" instead of inventing results.

**These apps are intentionally vulnerable. Run them on loopback only.** Every server binds `127.0.0.1`, nothing contacts
a third party (the "internal service" and "analytics vendor" are loopback stand-ins started by the fixture itself), and
every credential-shaped string is a documented FAKE.

| Fixture | Port (sidecar) | Stack | Planted categories (answer key) | Expected verdict |
|---|---|---|---|---|
| `vuln-node-express` | 3101 (3191 internal) | Express 5 + `node:sqlite` | authz (IDOR), injection (SQLi), xss (stored), ssrf, secrets, sca (lodash 4.17.15), rate-limit, logging, race | BLOCK |
| `clean-node-express` | 3102 (3192 internal) | same | none (must not flag any of the above) | SHIP |
| `vuln-python-fastapi` | 3103 (3193 internal, 3163 fake analytics) | FastAPI + `sqlite3` | authz, injection, ssrf, secrets, sca (python-multipart 0.0.6), rate-limit, logging, deletion, policy-mismatch | BLOCK |
| `clean-python-fastapi` | 3104 (3194 internal, 3164 analytics sink) | same | none | SHIP |
| `vuln-static-trackers` | 3105 (3155 fake analytics) | static HTML + stdlib Python server | tracking (before consent, reject ignored), policy-mismatch | BLOCK |
| `clean-static-trackers` | 3106 (3156 fake analytics) | same | none (tracker only after Accept, truthful policy) | SHIP |
| `honesty-wont-start` | 3199 (never bound) | Node, no deps | start.sh exits 1 (missing `DATABASE_URL`); only a static secret is findable | NOT-TESTED (runtime) |

Each fixture directory has `README.md`, `start.sh` (runs in the foreground, binds `127.0.0.1` on its fixed port, installs
its own deps on first run into `node_modules/` or `.venv/`), `answer-key.yaml`, and seed data created at boot (databases
are in-memory, so every boot is identical). Ports 3101-3199 are reserved for fixtures.

## Answer keys

`answer-key.yaml` lists `findings` (each with `id`, `category`, `expected_evidence_class`, `location`, and a `repro` line
containing the result actually observed when the fixture was verified by hand) and, for clean twins,
`clean_must_not_flag` (categories where any finding is a false positive). Optional extensions to the base format:
`optional: true` on a finding (a miss is tolerated), `also_matches` (extra real advisories for the same dependency),
and, for `honesty-wont-start`, `runtime_checks_expected_evidence_class` and `must_not`.

## Hand verification

`_repro/repro-node.sh <port> <internal_port> <logfile>` and `_repro/repro-py.sh <port> <internal_port> <analytics_port> <logfile>`
replay every API-level repro and print what happened; `_repro/stop-all.sh` kills anything listening on 3101-3199.
The static fixtures need a real browser (open the page, check `GET :<analytics>/_events`, click Reject, reload).

```bash
evals/fixtures/vuln-node-express/start.sh &     # then:
evals/fixtures/_repro/repro-node.sh 3101 3191 evals/fixtures/vuln-node-express/logs/app.log
```

## Secrets and the self-audit

`.gitleaks-allowlist.toml` exempts exactly the files holding the planted FAKE secrets so the repo's own self-audit can
run without noise (`gitleaks detect --config evals/fixtures/.gitleaks-allowlist.toml`). Note the AWS pair is the public
AWS-documentation example; gitleaks and similar tools may skip it by design, so its answer-key entry is `optional`.

## Dependency advisories (checked against api.osv.dev, 2026-10-18)

| Fixture | Pinned | Advisory |
|---|---|---|
| vuln-node-express | `lodash@4.17.15` | GHSA-p6mc-m468-83gw (CVE-2020-8203); also GHSA-35jh-r3h4-6jhm, GHSA-29mw-wpgm-hmr9 |
| vuln-python-fastapi | `python-multipart==0.0.6` | GHSA-2jv5-9r88-3w3p (CVE-2024-24762); several later GHSAs also apply |
| clean twins | `lodash@4.18.1`, `python-multipart==0.0.32`, current fastapi/starlette/uvicorn/express | 0 advisories |
