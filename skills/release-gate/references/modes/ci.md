# Mode: ci

## Goal
Give the user a pull-request tripwire that runs the quick-mode checks in their CI. This mode only produces a workflow file and advice. It does not run anything itself.

## Rules
- The repository is the user's. Write the file only when they ask for it in chat, and show the path before writing. Never commit, push, or open a pull request for them.
- Source: `templates/ci/github-actions-release-gate.yml`. Copy it to `<project>/.github/workflows/release-gate.yml`. If that file exists, show a diff and ask; don't overwrite.
- Two placeholders must be filled by the user: `RELEASE_GATE_REPO` (https clone URL of where they keep release-gate) and `RELEASE_GATE_REF` (a full 40-character commit SHA they have reviewed). The workflow refuses to run with a branch or tag name, because a moving ref means the code gating their merges can change unreviewed. Help them find the SHA (`git rev-parse HEAD` in their checkout); don't invent one.
- Every `uses:` in the template is pinned to a commit SHA. Keep it that way when editing, and re-verify a pin before bumping it (`git ls-remote --tags <repo> <tag>`).

## What the CI run does
Quick-equivalent: gitleaks over full history (the runner fetches `fetch-depth: 0`), osv-scanner, semgrep with the vendored commit-pinned rules (`--metrics off --jobs 1`, never the registry), then `report_build.py --mode quick`. The job fails on `BLOCK`, on a lint failure, or when no report was produced.

It never runs dynamic tests: it starts no application, probes no URL, and never targets production or any third party. Tools that fail or are missing become `NOT-TESTED`, not passes. The only scanner network use is osv-scanner's dependency lookup (package names and versions); the template shows the offline variant.

Say what the green check means: "no new BLOCK from three static scanners". It does not mean ready to ship. Quick mode can't reach SHIP.

## Branch protection advice (GitHub; adapt for other hosts)
- Require status checks to pass before merging, and add `release-gate / gate`. Don't require `upload-sarif`: it needs code scanning, which not every plan has.
- Require branches to be up to date before merging.
- No bypass: no admin override, no "allow specified actors to bypass". A gate an admin can skip is a suggestion.
- CODEOWNERS review for `.github/workflows/`, so a pull request can't weaken the gate that checks it.
- Use `pull_request`, not `pull_request_target`: the latter gives fork code write access and secrets.
- Keep default workflow permissions at `contents: read`; the template grants `security-events: write` only to the SARIF job.
- Pin every action to a full commit SHA.

## Limits to tell the user
- Fork pull requests get a read-only token, so SARIF upload is skipped for them.
- Raw scanner output in `.release-gate/evidence/` can hold secrets. The template uploads only the redacted reports; don't change that.
- A full release decision still needs `/release-gate full` on a machine where the dynamic phases can run.
