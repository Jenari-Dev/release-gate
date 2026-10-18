# release-gate

A Claude Code plugin that runs the pre-release process a careful company runs before a public launch — security (static and dynamic), correctness, privacy, draft legal documents, operational readiness — and ends with an honest `BLOCK` / `SHIP WITH ACCEPTED RISKS` / `SHIP` verdict.

Every result says how it is known: `EXPLOITED`, `TOOL-CONFIRMED`, `SUSPECTED`, `VERIFIED-ABSENT`, or `NOT-TESTED`. A check that left no artifact counts as not tested. A missing scanner counts as not tested. The report linter refuses reassurance it cannot back up.

> **Status: under construction (build session 1 of 4).** The core scripts, schemas and eval fixtures exist. Phase playbooks, eval scores and a sample report come in later sessions. Don't rely on it yet.

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
