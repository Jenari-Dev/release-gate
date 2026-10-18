# Phase 6: Operations and resilience

## Goal
Check that the deployment can be restored, does not write secrets or unneeded personal data to logs, ships with safe production settings, and (if it sends email) has sender authentication records. Reading config proves what the config says, not what runs.

## Preconditions
- Runtime steps (the restore test, log search, any local default-credential check) need the app or its data on a target in `.release-gate/scope.yaml`. Default: the loopback instance from phase 3.
- Never restore into or write to a production database. The restore target is a scratch database you create.
- Synthetic data only. If the only backup is of real data, do not copy it; say so and use `NOT-TESTED: only production backups exist; restore needs user-supplied scratch copy`.
- OPS-EMAIL-DNS makes network lookups; get the user's go-ahead first (see Step 4).
- Tools pinned in `tools.lock.yaml` and usable here: `trivy` (config scan), `checkov`, `hadolint`. Run them via `run_tool.py` (test type `scan`).

## Step 1: Backup and restore (OPS-BACKUP-RESTORE, category `backup`, applies when `has_server`)
1. Find how backups are made: scripts, cron/systemd units, compose volumes, managed-DB settings, `pg_dump`/`mysqldump`/SQLite copy commands. Read them and note: schedule, destination, retention, encryption, who can read the destination.
2. Actual restore test (the only way to claim anything):
   - Seed the local instance, take a backup with the project's own backup command, record row counts per table (`SELECT count(*)` or the equivalent) as `evidence/OPS-BACKUP-RESTORE/counts-before.txt`.
   - Create a scratch database or fresh data directory, restore the backup into it with the project's documented restore command, record counts again, and diff. Also start the app against the restored data and run one authenticated read.
   - Matching counts and a working read: `VERIFIED-ABSENT` titled "backup of seeded local DB restored into scratch DB; row counts match for N tables; app read succeeded". It does not cover production backup jobs, retention or off-site copies; list them as not verified.
   - Counts differ, restore errors, or app cannot read: `EXPLOITED` (reproduced failure), severity high, with logs and both count files.
3. Cannot do the restore: if config shows no backup at all, finding `TOOL-CONFIRMED` (grep output, no backup script/schedule found), severity medium, or `SUSPECTED` if the project may rely on provider snapshots you cannot see. Config exists but restore not run: `SUSPECTED` gaps only (for example no retention, unencrypted destination, no restore doc) with `file:line`, plus `NOT-TESTED: restore not executed: <reason>` for the pass itself.
- Reasons: `no database or persistent state` (not applicable if confirmed), `application did not start: <error>`, `no backup command found`, `skipped by user`.

## Step 2: Log hygiene (OPS-LOG-HYGIENE, category `logging`)
Run this after the phase-3 probes, when the app log contains real request traffic from test accounts.
1. Collect application logs: the stdout/stderr you captured at app start (`evidence/app-start/`), plus any log files the app writes. List the log sinks from `data-inventory.yaml` (`contains_credential: true` entries from phase 7 Step 4 come here).
2. Search for: every password and token you submitted in the phase-3 and phase-7 probes (the exact synthetic values), session cookie values, `Authorization` header contents, the canary strings placed in profile content, and email addresses of the test users. `evals/probes.py` `probe_credential_log` is the worked example: it greps the log for each submitted password and redacts matches in the saved evidence.
3. Also scan for unnecessary personal data patterns (full request bodies, IP plus user agent plus user id on every line) and verbose debug dumps. These are `SUSPECTED` unless a canary proves it.
4. Classification:
   - Submitted credential or token found in log: `EXPLOITED`, severity high, evidence = redacted matching lines (first 4 characters only via `rglib.redact_value`), never the full value.
   - Canary or personal data in log with no need: `EXPLOITED` medium.
   - Searched and found none: `VERIFIED-ABSENT` titled "none of N submitted credentials or tokens present in logs F1..Fn after phase-3 probes". Covers those values and files only; not production logging config.
   - No logs captured: `NOT-TESTED: log file not found` / `application not running`.

## Step 3: Deploy configuration (OPS-DEPLOY-CONFIG, category `ops`)
Read, do not run against anything but the local instance:
- Debug and dev flags (`DEBUG=true`, `NODE_ENV` unset, framework debug toolbars, stack traces enabled, verbose ORM logging), default or sample credentials in compose/env/example files, seed accounts that survive to production, admin panels with default paths.
- Secrets sourced from environment or a secret store rather than committed files (cross-reference SEC-SECRETS-HISTORY), `.env` files in images, separate settings for dev, staging and production.
- Health and readiness endpoints exist and do not need production secrets; containers do not run as root; ports not bound to all interfaces without need; migrations are reversible or have a documented rollback; a documented rollback path for the deploy.
- Run `trivy config`, `checkov` and `hadolint` on Dockerfiles, compose and IaC if present (phase 2 SEC-IAC output may be reused; cite it, do not re-run). A tool hit you confirm in the file is `TOOL-CONFIRMED` (tool output + `file:line`); a hit you cannot confirm stays `SUSPECTED`.
- Items found only by reading are `SUSPECTED`: a flag in a config file does not prove what the deployed environment sets. Default-credential claims become `EXPLOITED` only if you start the stack locally and log in with them.
- Nothing found: `VERIFIED-ABSENT` only for the specific greps and tools run, listed by name and scope. A clean read of files you were given is not a statement about the live environment.
- No deploy files in the repo: `NOT-TESTED: no deployment configuration in project`.

## Step 4: Email DNS (OPS-EMAIL-DNS, category `ops`, applies when `features.sends_email`)
1. Identify the sending domain(s) and the DKIM selector(s) from code, config or the email provider settings the user supplies. Do not guess selectors.
2. Ask the user: "I can look up the public DNS TXT records for <domain> (SPF, DMARC, and DKIM for selector <s>) with read-only queries. Go ahead?" Only after a yes, run the lookups with the system resolver (`dig +short TXT`) and save the output. Records are public data, but the lookup contacts a resolver; say so.
3. Evaluate: SPF record present and ends in a restrictive qualifier; DMARC present with a policy; DKIM key present for the selector. Report what is there, not whether mail will be delivered. A missing or weak record: finding `OPS-EMAIL-DNS`, `TOOL-CONFIRMED` (lookup output saved), severity medium. Records that look right in the lookup are `VERIFIED-ABSENT` only for "SPF, DMARC and DKIM (selector S) records present and parse"; delivery and alignment are not tested.
4. Not authorised: `NOT-TESTED: DNS lookups not authorised by user`. No domain known: `NOT-TESTED: sending domain not provided`.

## Adversarial verification
No check here is critical-category. Every High finding (failed restore, credentials in logs) still gets a fresh subagent: give it the claim and evidence, ask it to disprove it (is the value the same one, is it a test fixture, is the log rotated and unreachable). Record the outcome.

## NOT-TESTED strings (exact)
- `restore not executed: <reason>`; `no backup command found`; `only production backups exist; restore needs user-supplied scratch copy`
- `log file not found`; `application not running`
- `no deployment configuration in project`
- `DNS lookups not authorised by user`; `sending domain not provided`
- `tool unavailable: <trivy|checkov|hadolint>`
- `out of scope: <reason>`; `skipped by user`
