# Report template

`report.html.tmpl` is a self-contained HTML report skeleton for release-gate: inline CSS only, no scripts, no web fonts, no images, no network requests. It follows `prefers-color-scheme` for light and dark and has print rules (Ctrl+P gives a clean PDF).

The template matches the data `scripts/report_build.py` already builds in `build_context()`. `report_build.py` itself still renders its own HTML from the Markdown report; `scripts/render_report.py` is the renderer for this template. It implements exactly the syntax and mapping below, escapes every value, redacts secrets, refuses unknown `evidence_class` / `verdict_class` values, strips author comments and raises `ValueError` if any `{{...}}` is left unfilled:

```
python scripts/render_report.py --project . [--mode full] [--date 2026-10-18] [--out report.html]
```

By default it writes `<project>/.release-gate/reports/release-gate-<date>.template.html`, runs `report_lint` on it and prints the path. If lint fails it renames the file to `*.lint-failed.html` and exits 2. From Python, `render_report.render(ctx)` takes the dict from `report_build.build_context()` and returns the HTML. To restyle the report, edit the template; the renderer reads it on every run.

## Placeholder syntax

| Syntax | Meaning |
|---|---|
| `{{name}}` | Scalar slot. The renderer must HTML-escape the value. |
| `{{#rows name}} ... {{/rows}}` | Repeat the block once for each item of the list `name`. Inside it, `{{field}}` reads that item. |
| `{{^rows name}} ... {{/rows}}` | Emit the block only when the list `name` is empty (for "none recorded" messages). |

Everything between `<!--` and `-->` is a comment for template authors; a renderer should strip it. Report values come from the scanned project (finding titles, file paths, tool output) and are untrusted: escape them, never insert them as raw HTML.

`evidence_class` and `verdict_class` end up inside `class="..."` attributes. A renderer must only substitute the enum values listed below (replace `/` with `-`, so `N/A` becomes `N-A`) and refuse anything else.

## Slots and where the data comes from

Names in parentheses are keys of the `ctx` dict in `report_build.py`.

Scalars:

| Slot | Source |
|---|---|
| `title` | `release-gate: <product> <date>` |
| `product`, `date`, `mode`, `generated_at` | `ctx["product"]`, `["date"]`, `["mode"]`, `["generated_at"]` |
| `verdict` | `ctx["verdict"]["verdict"]`: `BLOCK`, `SHIP WITH ACCEPTED RISKS`, `SHIP` or `NOT-EVALUATED` |
| `verdict_class` | the verdict with spaces turned into hyphens: `BLOCK`, `SHIP-WITH-ACCEPTED-RISKS`, `SHIP`, `NOT-EVALUATED` |
| `count_critical`, `count_high`, `count_medium`, `count_low`, `count_info` | `ctx["counts"]` (open findings) |
| `disclaimer` | `report_build.DISCLAIMER` (do not shorten or remove it) |

Lists:

| List | Item fields | Source |
|---|---|---|
| `blocking` | `text` | `ctx["verdict"]["blocking"]` |
| `reasons` | `text` | `ctx["verdict"]["reasons"]` |
| `coverage` | `id`, `title`, `phase`, `critical` (`yes` or empty), `evidence_class`, `evidence_label`, `result`, `detail`, `artifacts` | `ctx["coverage"]`; `detail` is the row's `reason`; `artifacts` is the comma-joined paths |
| `findings` | `id`, `severity`, `evidence_class`, `evidence_label`, `title`, `location`, `status`, `impact`, `repro`, `fix`, `tool`, `artifacts` | `ctx["findings"]`; `location` is `endpoint`, else `file:line`; `tool` is name, version and rule id; use an em dash for missing optional fields |
| `not_tested` | `id`, `title`, `reason` | coverage rows where `applicable` is true and `evidence_class` is `NOT-TESTED` |
| `limitations` | `text` | `report_build.LIMITATIONS` |

`evidence_label` is the text printed inside the badge. It equals `evidence_class` except for not-applicable rows, where the class is `N-A` and the label is `N/A`.

## Evidence class badges

Each class has its own colour, its own symbol and, for two of them, its own border style, and the class name is always printed as text. The badge never relies on colour alone.

| Class | Symbol | Colour (light) | Border |
|---|---|---|---|
| `EXPLOITED` | filled square | red | solid |
| `TOOL-CONFIRMED` | filled diamond | orange | solid |
| `SUSPECTED` | filled triangle | purple | double |
| `VERIFIED-ABSENT` | filled circle | green | solid |
| `NOT-TESTED` | open circle | grey | dashed |

Dark-mode colours are lighter variants defined in the `:root` blocks of the template.

## Self-contained by construction

- `Content-Security-Policy` meta tag: `default-src 'none'; style-src 'unsafe-inline'; img-src data:`. Scripts, fonts, frames and network requests are all blocked.
- No `<script>`, no `<link>`, no `@import`, no `url(...)`, no external `src` or `href`.
- Artifact paths are printed as text, not links. If your renderer adds links, keep them relative (`../evidence/...`) as `report_build.py` does.

`scripts/report_lint.py` already rejects `<script>`, external `src`/`href` and the banned reassurance phrases in HTML reports. Run it on anything you render from this template:

```
python scripts/report_lint.py path/to/report.html
```

`tests/test_templates.py` checks the template itself: placeholders present, CSP meta present, no external asset references, no banned phrases.
