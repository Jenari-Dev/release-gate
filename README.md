# release-gate

A Claude Code plugin that runs the pre-release process a careful company runs before a public launch — security (static and dynamic), correctness, privacy, draft legal documents, operational readiness — and ends with an honest `BLOCK` / `SHIP WITH ACCEPTED RISKS` / `SHIP` verdict.

Every result says how it is known: `EXPLOITED`, `TOOL-CONFIRMED`, `SUSPECTED`, `VERIFIED-ABSENT`, or `NOT-TESTED`. A check that left no artifact counts as not tested. A missing scanner counts as not tested. The report linter refuses reassurance it cannot back up.

> **Status: under construction (build session 2 of 4).** The minimum viable skill runs end to end — intake, data map, static and dynamic security (including the authorization matrix), privacy and cookie audit, draft legal documents, and the report with its verdict (phases 0, 1, 2, 3, 7, 8, 13). Correctness/perf/ops/platform phases and the quick/retest/ci modes come in session 3; polish and publish in session 4. First measured eval scores are below. Don't rely on it for a real launch yet.

## Measured eval scores

Run against the bundled fixtures with `uv run --no-project --with pyyaml --with jsonschema python evals/run_evals.py` (each app is booted on loopback; nothing contacts a real third party). Latest run:

| Fixture | Verdict | Result |
|---|---|---|
| vuln-node-express | `BLOCK` | 10/10 planted bugs detected, evidence classes correct, planted IDOR comes out `EXPLOITED` |
| vuln-python-fastapi | `BLOCK` | 10/10 detected, classes correct, IDOR `EXPLOITED` |
| vuln-static-trackers | `BLOCK` | 3/3 detected (tracker-before-consent and policy contradiction) |
| clean-node-express | `SHIP WITH ACCEPTED RISKS` | 0 false positives |
| clean-python-fastapi | `SHIP WITH ACCEPTED RISKS` | 0 false positives |
| clean-static-trackers | `SHIP WITH ACCEPTED RISKS` | 0 false positives |
| honesty-wont-start | `BLOCK` | app can't start → critical checks `NOT-TESTED` → "insufficient evidence", never a pass |
| honesty-no-tools | — | with no scanners on `PATH`, every tool-backed check is `NOT-TESTED`, never a pass |

The clean twins land `SHIP WITH ACCEPTED RISKS` rather than a bare `SHIP` on purpose: a plain `SHIP` needs every critical-category check `VERIFIED-ABSENT` **and** upheld by an adversarial subagent, plus live-secret verification — steps the automated eval harness does not perform. This is the gate being honest about what it did and did not do, not a failure. The deliberately vulnerable apps are for testing only; run them on loopback.

## Scanner network use

release-gate never fetches its own rules or logic at scan time (SAST rules are vendored and pinned by commit). A few scanners do reach the network with *dependency metadata or their own databases* — never your source — and the skill discloses this and offers offline modes: `osv-scanner` queries `api.osv.dev`; `trivy` downloads its vulnerability DB; `trufflehog --results=verified` checks candidate secrets with the issuing provider (run only with your go-ahead). See SKILL.md principle 5.

## Disclaimer

release-gate is an automated aid, provided as is, without warranty. It is not legal advice, not a penetration test, and not a compliance certification. A `SHIP` verdict means "these checks ran and found nothing", not "nothing is wrong". Only test systems you own or are authorized to test. You decide what ships and remain responsible for it. Read the full [DISCLAIMER](DISCLAIMER.md) before use.

## Layout

```
.claude-plugin/          plugin + marketplace manifests
skills/release-gate/
  SKILL.md               principles + router
  references/            phase playbooks, check catalog, law reference data
  scripts/               deterministic helpers (Python ≥3.11, PyYAML, jsonschema)
  schemas/               finding, data inventory, config, scope, waivers
  templates/             legal drafts, CI, k6, report
  tools.lock.yaml        pinned scanner versions + SHA-256
evals/fixtures/          deliberately vulnerable apps + clean twins + answer keys
tests/                   unit tests for every script
```

## Development

```bash
uv run --with pytest --with pyyaml --with jsonschema pytest -q
```

```bash
uv run --with pyyaml python skills/release-gate/scripts/install_tools.py --all
```

## License

MIT. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md). Security reports: [SECURITY.md](SECURITY.md).
