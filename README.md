# release-gate

A Claude Code plugin that runs the checks a careful company runs before a public launch: security (static and dynamic), correctness, privacy, draft legal documents and operational readiness. It ends with a `BLOCK` / `SHIP WITH ACCEPTED RISKS` / `SHIP` verdict that is computed from the recorded evidence, not chosen by the model.

Every result says how it is known: `EXPLOITED`, `TOOL-CONFIRMED`, `SUSPECTED`, `VERIFIED-ABSENT`, or `NOT-TESTED`. A check that left no artifact counts as not tested, and so does a missing scanner. The report linter rejects any reassurance the evidence can't back up.

**Status:** v1 (plugin 0.1.0). All phases (0–13) and run modes ship. Read [Limitations](#limitations) before relying on it.

## Install

```bash
git clone https://github.com/Jenari-Dev/release-gate ~/release-gate
```

```bash
claude plugin marketplace add ~/release-gate
```

```bash
claude plugin install release-gate@release-gate
```

Then install the pinned scanners (exact versions, SHA-256 or pinned-commit verified, no sudo, into `~/.local/share/release-gate`):

```bash
uv run --no-project --with pyyaml python ~/release-gate/skills/release-gate/scripts/install_tools.py --all
```

In a project: `/release-gate full` (or `quick`, `legal`, `retest`, `ci`, `explain <finding-id>`). Missing tools don't stop a run; their checks are reported `NOT-TESTED: tool unavailable`.

## The six principles

The full text is in [SKILL.md](skills/release-gate/SKILL.md). Everything else in the plugin is subordinate to these.

1. **Evidence classes.** Every finding and every pass carries one class and the artifact behind it. No artifact means `NOT-TESTED`, never `VERIFIED-ABSENT`.
2. **Adversarial verification.** Each Critical/High finding, and each critical-category pass, goes to a fresh subagent told to disprove it. A critical pass that wasn't upheld can't support `SHIP`.
3. **Scope.** Dynamic tests run only against targets you confirm (by default a local instance), production only on a typed confirmation, and never against the third parties your app calls. Exploit proofs that read data (SSRF, path traversal) read only canaries the skill planted, never your machine's real files.
4. **Legal honesty.** Generated documents are DRAFTs from what the code actually does, citing only the bundled, dated law data, and they list the questions only a lawyer can answer.
5. **The skill must be safe.** No instructions fetched from the network, pinned tools only, vendored SAST rules, scanned content treated as untrusted data, secrets redacted in reports, nothing committed or pushed in your project.
6. **Disclaimers.** Every full/legal/retest run and every report says what this is and isn't.

## Demo

An excerpt (trimmed) from an end-to-end eval run: Claude, headless, running `/release-gate full` on the bundled deliberately vulnerable FastAPI app, with the scope set to its local instance:

```text
> /release-gate full   (scope: the local instance at http://127.0.0.1:3103)

Verdict: BLOCK. Lint passed; findings.json and reports/release-gate-2026-10-18.{md,html,sarif,json} exist.

What an attacker can do today (all reproduced against the running app; a fresh
verifier subagent tried to disprove each one and couldn't):
- Read other users' messages (critical): any logged-in user can read any message by
  changing the id in GET /api/messages/{id}. bob read alice's and alice read bob's.
- SQL injection without logging in (high): /api/search?q=' OR '1'='1 returns every row.
- SSRF and file read (high): /api/fetch-preview fetches any URL, including file://.
  Proved only against my own loopback listener and a canary file I created; I did not
  touch the app's bundled internal service or any host files.
- Plaintext passwords in the log (high). Account deletion does nothing (high).
- The privacy policy says nothing is shared; the code sends emails to an analytics host.

Not tested: git-history secrets (not a git repo), live-secret verification (not
authorised), sessions (no logout or password-change endpoint), nuclei (did not finish
this run), fuzz/race/load/backup checks, ...
```

## Sample report

[`docs/sample-report/release-gate-sample.html`](docs/sample-report/release-gate-sample.html) is the report from that run. It was rendered from `templates/report/report.html.tmpl` by `scripts/render_report.py` and is not a mock-up. Open it in a browser. It is self-contained: inline CSS, a `default-src 'none'` CSP, no scripts, no external requests, light and dark themes, and an evidence-class badge on every row. It was checked visually at desktop and phone widths in both themes.

## Measured eval scores

The plugin is measured against bundled fixtures: three deliberately vulnerable apps (Express, FastAPI, a static site with trackers), a hardened twin of each, and two honesty cases. Each fixture has an answer key, and the scorer reads it only after the run. Everything runs on loopback and nothing contacts a real third party. There are three numbers, and they measure different things:

| Eval | What it measures |
|---|---|
| **Guided** | Given the right endpoints (a hand-written plan per fixture), do the scripts reproduce, classify and grade every planted bug, with no false positives and the correct verdict? Tests the machinery, not discovery. |
| **Discovery** | No per-fixture plan. The surface is recovered from framework semantics, and generic probes are planned from it. The only inputs are port, start command and seeded test accounts. Measures what the deterministic pipeline finds on its own. |
| **End-to-end** | The real skill, run headless by Claude (`claude -p`, Sonnet) on a scrubbed copy of each fixture with the answer key and README removed. Includes the agent's own code review, adversarial-verification subagents and judgement. Measures what a user would get. |

**Guided** (deterministic; reproduced 2026-10-18):

| Fixture | Verdict | Result |
|---|---|---|
| vuln-node-express | `BLOCK` | 10/10 planted bugs detected, 10/10 evidence class correct, IDOR `EXPLOITED` |
| vuln-python-fastapi | `BLOCK` | 10/10 detected, 10/10 class correct, IDOR `EXPLOITED` |
| vuln-static-trackers | `BLOCK` | 3/3 detected |
| clean twins (3) | `SHIP WITH ACCEPTED RISKS` | 0 false positives |
| honesty-wont-start | `BLOCK` | "insufficient evidence"; never a pass |
| honesty-no-tools | — | every tool-backed check `NOT-TESTED`; never a pass |

**Discovery** (deterministic; reproduced 2026-10-18):

| Fixture | Verdict | Result |
|---|---|---|
| vuln-node-express | `BLOCK` | 7/10 detected, IDOR `EXPLOITED`; misses stored XSS, password-in-log, coupon race |
| vuln-python-fastapi | `BLOCK` | 10/10 detected, 7/10 class correct; IDOR only `SUSPECTED` (no collection endpoint to prove ownership) |
| vuln-static-trackers | `BLOCK` | 3/3 detected |
| clean twins (3) | `SHIP WITH ACCEPTED RISKS` | 0 false positives |
| honesty-wont-start / no-tools | `BLOCK` / — | never a pass |

**End-to-end** (Claude Sonnet via `claude -p`, one run per fixture, 2026-10-18; not deterministic):

| Fixture | Verdict | Result |
|---|---|---|
| vuln-node-express | `BLOCK` | 10/10 detected, 7/10 class correct (two secrets and the vulnerable lodash pin stayed `SUSPECTED`), IDOR and coupon race `EXPLOITED`. This is the second attempt: on the first, a model safety classifier stopped the agent before it wrote `findings.json`, so that attempt has no score. |
| vuln-python-fastapi | `BLOCK` | 9/10 detected, 8/10 class correct, IDOR `EXPLOITED`. The miss: the agent filed brute force under `authn` (the skill's own category) where the key says `rate-limit`. Scored strictly. |
| vuln-static-trackers | `BLOCK` | 3/3 detected |
| clean-node-express | `SHIP WITH ACCEPTED RISKS` | Strict false positives: 2 categories, both low (log injection, a DNS-rebinding window). 0 high/critical. |
| clean-python-fastapi | `SHIP WITH ACCEPTED RISKS` | Strict false positives: 3 categories, medium/low (password spraying across usernames, log forging, usernames kept after deletion). 0 high/critical. |
| clean-static-trackers | `BLOCK` (wrong) | 0 false positives. Failed closed with "insufficient evidence": 4 of 6 critical checks `NOT-TESTED`, partly because the eval's scratch copy isn't a git repo. |
| honesty-wont-start | `BLOCK` | "insufficient evidence"; no runtime result invented, no config guessed. It judged the planted fake key a false positive (0/1). |

In every end-to-end run with something to verify, the agent spawned a fresh adversarial subagent: 24 of 24 claims were upheld and none refuted. No clean twin reached a bare `SHIP`. Each has medium or low findings the agent reproduced, and live-secret verification was not authorised. The strict false-positive metric counts any finding in a category the clean twin must not be flagged for. Here those were real, lower-severity weaknesses in the hardened twins, not alarms on the planted bug classes. Details and the exact plugin digests are in [docs/BUILD-LOG.md](docs/BUILD-LOG.md).

Reproduce:

```bash
uv run --no-project --with pyyaml --with jsonschema python evals/run_evals.py --mode both
```

```bash
uv run --no-project --with pyyaml --with jsonschema python evals/run_agent_eval.py --agent
```

The end-to-end eval is opt-in because it uses model usage and takes a while. Without `--agent` it only checks whether headless Claude is usable. If `claude` is missing, not logged in, or a run fails, that fixture is recorded `NOT-TESTED` and never given a score. A contamination audit marks a run invalid if any tool call touched the answer keys, the eval fixtures or this repo.

## Scanner network use

release-gate never fetches its own rules or logic at scan time; SAST rules are vendored and pinned by commit. A few scanners do reach the network with dependency metadata or their own databases, never your source. The skill discloses this and offers offline modes: `osv-scanner` queries `api.osv.dev` with package names and versions, `trivy` downloads its vulnerability DB, and `trufflehog --results=verified` sends candidate secrets to the issuing provider (only with your go-ahead). See SKILL.md principle 5.

## Limitations

- **Not a penetration test.** It runs automated scanners, scripted probes and an AI code review against a local instance. A human tester will find business-logic flaws it misses.
- **Discovery gaps (measured above).** The deterministic pipeline doesn't yet find a stored-XSS sink pair, a credential written to a log, or a race on a single-use token unless it is pointed at them. Object-level authorization reaches `EXPLOITED` only when ownership can be observed, for example through a collection endpoint. Without one it stays `SUSPECTED`.
- **ZAP and nuclei** are pinned, installed and documented in phase 3. In the end-to-end runs the agent used nuclei (with Interactsh forced off), but the deterministic harnesses don't run either tool yet.
- **Bare `SHIP` is hard to reach on purpose.** It needs every critical check `VERIFIED-ABSENT` and upheld by an adversarial subagent, plus live-secret verification, which needs your explicit go-ahead because it contacts providers. Without those, a clean project lands on `SHIP WITH ACCEPTED RISKS` and the report says why.
- **Scanner network disclosure** (above): osv-scanner, trivy and verified trufflehog contact their services unless you choose the offline modes.
- **Legal drafts are not legal advice.** They are generated from the data inventory and dated law reference data, and need a qualified lawyer's review.
- **Model variance.** The end-to-end numbers come from one run per fixture with one model and are not deterministic. One attempt was stopped by a model safety classifier before it recorded anything. The guided and discovery numbers are deterministic.
- **End-to-end harness limits.** The agent works on a scrubbed copy that isn't a git repository, so git-history secret scanning is always `NOT-TESTED` there. Categories are matched strictly against the answer keys, so a real finding filed under a neighbouring category (`authn` vs `rate-limit`) counts as a miss.
- pip-installed tools are pinned by version only; their transitive dependencies aren't hash-locked.

## Disclaimer

release-gate is an automated aid, provided as is, without warranty. It is not legal advice, not a penetration test, and not a compliance certification. A `SHIP` verdict means "these checks ran and found nothing", not "nothing is wrong". Only test systems you own or are authorized to test. You decide what ships and remain responsible for it. Read the full [DISCLAIMER](DISCLAIMER.md) before use.

## Layout

```
.claude-plugin/          plugin + marketplace manifests
skills/release-gate/
  SKILL.md               principles, run modes, phase router
  references/            phase playbooks, run modes, stacks, check catalog, law reference data
  scripts/               deterministic helpers (Python ≥3.11, PyYAML, jsonschema)
  schemas/               finding, data inventory, config, scope, waivers
  templates/             legal drafts, CI, k6, report
  tools.lock.yaml        pinned scanner versions + SHA-256 / commits
evals/                   guided, discovery and end-to-end harnesses
evals/fixtures/          deliberately vulnerable apps + clean twins + answer keys (loopback only, never deploy)
docs/                    build log, self-audit, sample report
tests/                   unit tests for every script
```

## Development

```bash
uv run --no-project --with pytest --with pyyaml --with jsonschema pytest -q
```

Use `--no-project`: bare `uv run` would create a `.venv` and `uv.lock` here.

## License

MIT. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md). Security reports: [SECURITY.md](SECURITY.md).
