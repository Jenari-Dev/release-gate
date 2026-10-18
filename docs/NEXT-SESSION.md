# Next session: after the build

The four build sessions are complete (see `docs/BUILD-LOG.md`, session 4). release-gate is v1 (plugin 0.1.0).

## Publishing
Publishing to GitHub (`Jenari-Dev/release-gate`) happens only after the owner says so in chat. Public identity is JenAriDev / Jenari-Dev only. Before pushing:
- `git ls-files` must not include `.claude/`, `CLAUDE.md`, `graphify-out/`, `evals/results/`, `.release-gate/` or any file with a local absolute path, hostname or personal email.
- Re-run `pytest` and `evals/run_evals.py --mode both`.

## Follow-ups (open issues from BUILD-LOG session 4)
1. End-to-end eval: `git init` the scratch copy so SEC-SECRETS-HISTORY can run; decide how the scorer maps the skill's `authn` brute-force category to answer keys that say `rate-limit` (state the rule before re-running; don't tune the skill against the keys).
2. Discovery gaps: FastAPI IDOR without a collection endpoint, stored-XSS sink pairs, credential-log locations, single-use tokens.
3. Exercise ZAP/nuclei in the deterministic harness (the end-to-end agent already runs nuclei with forced `-ni`).
4. Hash-lock the pip/npm tools (self-audit waiver W-002).

Dev runs: `uv run --no-project --with pytest --with pyyaml --with jsonschema ...` (never bare `uv run`). The end-to-end eval is opt-in and uses model usage: `evals/run_agent_eval.py --agent`.
