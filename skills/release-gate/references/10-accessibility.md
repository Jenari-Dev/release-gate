# Phase 10: Accessibility

## Goal
Run the automated accessibility checks that are available, report what they found, and say plainly how little automated checking covers. Automated tools detect only a fraction of WCAG 2.2 failures (keyboard flow, focus order, meaningful alt text, reading order, screen-reader behaviour and cognitive issues need a human). This phase never concludes that a product is "accessible" or "WCAG compliant".

## Applies when
`config.surface.has_web_ui` is true (check `A11Y-AUTOMATED`, category `accessibility`, phase 10, `full` mode). Desktop apps, games, native mobile apps, CLIs and APIs: not applicable to this phase; for native UIs record `NOT-TESTED: no web UI to audit` and tell the user that platform accessibility testing (screen reader, keyboard, scaling) is a manual task not covered by this skill.

## Preconditions
- Pages to test are served from a target in `.release-gate/scope.yaml`; default is the loopback instance from phase 3. No third-party sites.
- Pick key pages from `attack-surface.md`: landing, login/register, one form-heavy page, the main logged-in view, the consent banner and the legal pages. Record the list; the result covers only these pages.
- Tool facts from `tools.lock.yaml`: `playwright` 1.63.0 with its pinned Chromium is installed by `install_tools.py`. `axe-core` and `pa11y` are NOT pinned there. Do not download either.

## Step 1: Choose the check mode
1. Run `check_tools.py --json`. If `playwright` is not ok: `NOT-TESTED: tool unavailable: playwright`, stop.
2. axe-core: use it only if it is already present in the project itself (for example the project's own dev dependency such as `axe-core` or `@axe-core/playwright` in its lockfile and `node_modules`). Run it via the project's installed copy, record the version from the project's lockfile, and treat the project's copy as unreviewed tool code (it runs inside the page you load). Otherwise state: "axe-core not pinned in tools.lock.yaml, not available in project: Playwright-only subset used".
3. Never fetch a script from a CDN into the page, and never `npm install` an unpinned package for this check.

## Step 2: axe-core run (only when available)
1. For each key page, load with Playwright (Chromium, desktop viewport, then a 390px-wide viewport), wait for network idle, run axe with the WCAG 2.2 A and AA tag set the installed version supports, and save the full JSON result to `evidence/A11Y-AUTOMATED/axe-<page>.json` (type `tool-output`).
2. Each violation: rule id, impact, target selectors, help URL. Confirm 2-3 representative instances by reading the markup (`TOOL-CONFIRMED`); the rest stay in the tool output. Axe "incomplete" results (needs review) are `SUSPECTED` and not counted as passes.
3. Severity mapping: axe critical/serious on a form, navigation or login path = medium; others low. These are not security issues; do not inflate.

## Step 3: Playwright-only subset (default)
Documented checks, run per key page with a Playwright script saved to `evidence/A11Y-AUTOMATED/a11y-subset.mjs` (type `repro-script`), output JSON saved alongside:
- `<html lang>` present and non-empty.
- Page `<title>` present and not identical across all pages.
- Every `<img>` has an `alt` attribute (empty alt is allowed for decorative; record the count of missing attribute, and list for human review the images whose alt is a filename or generic word).
- Form controls (`input`, `select`, `textarea`) have an accessible name: associated `<label>`, `aria-label`, or `aria-labelledby`; placeholder alone does not count.
- Buttons and links have non-empty accessible names (icon-only buttons are the common failure).
- Exactly one `<h1>` and no skipped heading levels (record, do not over-weight).
- Viewport meta does not disable zoom (`user-scalable=no`, restrictive `maximum-scale`).
- Focusability smoke test: tabbing through the page reaches the main interactive controls and a visible focus change occurs (compare computed outline/box-shadow before and after focus on a sample of controls). This is a smoke test, not a keyboard-accessibility audit.
- Colour contrast is NOT measured by this subset. Say so in the check title and in the report: "contrast not measured".
Each failing element is a finding with selector and page. They are `TOOL-CONFIRMED` only when the script output is saved and you read the element's markup; otherwise `SUSPECTED`.

## Step 4: Recording
- Findings: `check_id: A11Y-AUTOMATED`, `category: accessibility`, severity low or medium, `fix` giving the specific attribute or element change.
- No violations: a `check` entry with `VERIFIED-ABSENT` titled exactly in this shape: "automated checks (<axe-core vX | Playwright subset: lang, title, img alt, form labels, link/button names, zoom, focus smoke test>) found no violations on N pages at 2 viewports; this covers a fraction of WCAG 2.2 AA and is not a conformance claim". Evidence = the JSON outputs. Never "accessible".
- Add to the report's open questions for the owner: keyboard-only walkthrough, screen reader pass, zoom to 200 percent, captions/transcripts for media, accessible authentication, and colour contrast measurement. All are manual and not run.
- If the user wants an accessibility statement draft, use `templates/legal/accessibility-statement.md.tmpl`; it must say conformance has not been evaluated unless the owner commissioned a full audit.

## Adversarial verification
Not critical-category. High is not used here. If a finding blocks a core task (login form with no labels), spawn a fresh subagent with the selector, the markup and the page URL and ask it to find an accessible name source the script missed (`aria-labelledby` chain, `title`, visually hidden text).

## NOT-TESTED strings (exact)
- `tool unavailable: playwright`
- `no web UI to audit`
- `application not running`; `out of scope: <reason>`
- `colour contrast not measured: no contrast tool pinned in tools.lock.yaml`
- `axe-core not pinned in tools.lock.yaml and not available in project`
- `skipped by user`
