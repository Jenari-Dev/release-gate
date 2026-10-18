# Security policy

release-gate runs scanners and test harnesses with your privileges, so bugs in it matter.

## Reporting a vulnerability in release-gate itself

Please use GitHub's private vulnerability reporting on this repository
(Security tab → "Report a vulnerability"). Do not open a public issue for
security problems.

Include what you ran, what happened, and what you expected. We aim to
acknowledge within 7 days.

## In scope

- The skill's scripts, templates and instructions (anything under `skills/`).
- The tool installer and `tools.lock.yaml` (wrong hashes, unpinned installs,
  path traversal on extract).
- Anything that makes the skill follow instructions found inside a scanned
  project, send data off the machine, or report a pass without evidence.

## Out of scope

- Vulnerabilities in the third-party scanners themselves (report upstream).
- The deliberately vulnerable apps under `evals/fixtures/vuln-*`. They are
  vulnerable on purpose and bind to 127.0.0.1 only. Secrets in them are fake.
