# Sample report

`release-gate-sample.html` is a real report, not a mock-up. It comes from the end-to-end agent eval: Claude (Sonnet, headless `claude -p`) ran `/release-gate full` on a scrubbed copy of the bundled `vuln-python-fastapi` fixture, a deliberately vulnerable app on loopback, with the answer key removed. The agent's own recorded entries were rendered with `skills/release-gate/scripts/render_report.py` from `templates/report/report.html.tmpl`.

Open it in a browser. It is self-contained: inline CSS only, a `default-src 'none'` Content-Security-Policy, no scripts, no external requests, and light and dark themes that follow your system setting. Every coverage row and finding carries an evidence-class badge.

The evidence files the report refers to (request/response captures, tool output) are not included here. They contain exploit payloads against the fixture, and the report is meant to be read on its own. The product name reads `app` because the eval scrubs fixture names before the agent sees the code.

Checked on 2026-10-18 in a Chromium-based browser at desktop width and at 375 px, in both colour schemes. `report_lint.py` passes it.
