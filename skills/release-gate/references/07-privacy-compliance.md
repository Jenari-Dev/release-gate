# Phase 7: Privacy and compliance

## Goal
Map the confirmed data inventory onto the privacy regimes that apply, run the runtime checks (data-subject rights, cookie/tracker behaviour), and flag collected data nobody uses. Output feeds phase 8 and section 5 of the report (`privacy.json`).

This phase screens against a short curated checklist. It does not decide legal applicability or compliance (SKILL principle 4).

## Prerequisites
- `data-inventory.yaml` exists (phase 1). Check `confirmed_by_user`. If false, say "inventory not confirmed by user" in every output of this phase.
- `config.yaml` has `audience`, `features`, `product.distribution`.
- Dynamic parts (rights tests, cookie audit) need the phase-3 app running on a target listed in `scope.yaml`. `legal` mode with no running app does the static parts only.

## Step 1: Regime mapping (PRIV-REGIME-MAPPING)
1. Load every `references/law/*.yaml` (`gdpr`, `uk-gdpr`, `eprivacy`, `ccpa-cpra`, `us-state-privacy`, `coppa`, `pipeda`, `lgpd`, `appi`, `au-privacy-act`). Format: `references/law/README.md`.
2. Translate config to the law files' `config_predicate` vocabulary:
   - `audience.regions`: `eu-eea`, `uk`, `us-ca`, `canada`, `brazil`, `japan`, `australia` map 1:1. `us-other-states` -> `us-other`. `us` -> treat as both `us-ca` and `us-other`. `worldwide` -> every jurisdiction "may apply". `other` -> no data covers it.
   - `features_any`: `user_generated_content` -> `ugc`; `analytics` is true when the inventory has third parties with an analytics/telemetry purpose or analytics-event fields.
   - `children_under_13` = `audience.under_13_possible`; `directed_at_children` = `audience.directed_at_children`.
3. A regime "may apply" when any `applicability.triggers[].config_predicate` matches. Record `applies` (boolean; true for "may apply") plus `why` (trigger id) and the `last_verified` date. Entries older than 12 months are flagged stale by `report_build.py`; say "possibly stale" when you cite them.
4. For each applicable regime, walk `obligations[]`: use its `check` text and `inventory_keys` against `data-inventory.yaml` and code. Classify each: met-in-inventory / gap / cannot be determined by this skill. Examples: no `lawful_basis` on a personal-data field; no `rights.deletion`; no retention (`none defined`); third party with `transfer_region` empty.
5. Anything outside the data (regime not in `references/law`, a jurisdiction `other`, sector law such as health or payments): record "not covered by this skill's reference data; verify with a lawyer or official source" and add it to the lawyer questions. Copy each regime's `lawyer_questions` and `not_covered` into `documents.json` later (phase 8).
6. Gaps become findings: `check_id: PRIV-REGIME-MAPPING`, `category: privacy`, class `SUSPECTED` with the inventory ref or `file:line` and "why not reproduced" (it is a checklist gap, not a runtime fact). A gap you confirmed by grepping the code (no deletion route anywhere) is `TOOL-CONFIRMED` with the grep output as evidence.
- Mapping done, no gaps: one check entry with `VERIFIED-ABSENT` as completed marker, title "no gap between inventory and screening checklist for <regime list>; legal applicability not determined". Evidence: the mapping table you wrote to `.release-gate/evidence/privacy/regime-mapping.md` (a `VERIFIED-ABSENT` with no artifact fails the report lint).
- Config/inventory missing: `NOT-TESTED: no data inventory` or `NOT-TESTED: audience regions not provided`.

## Step 2: Rights tests (PRIV-RIGHTS-TESTED, needs features.accounts)
Run against the local instance, with a synthetic test user (never real data):
1. Create user `rg-privacy-test`, store a unique canary in its profile/content.
2. Export (access): call the export endpoint or download; the canary must appear. Save request + response.
3. Correction: update a field; read it back from the API.
4. Deletion: call delete-account/erase. Then verify: login rejected, profile/content endpoints 404, canary absent in the DB (query the test DB you own) and in app logs. Also check whether the same email can re-register (leftover record).
5. Record each in `privacy.json` `rights_tests` (below). Result vs class:
   - Right missing in code: `TOOL-CONFIRMED` gap (grep output), severity medium.
   - Right exists, worked: `VERIFIED-ABSENT` for "right not honoured", evidence = the request/response + DB query output.
   - Right exists, data remains or login still works: `EXPLOITED`, severity high.
   - Could not run: `NOT-TESTED: <reason>`.
- Reasons: `application not running`, `no export endpoint in code`, `out of scope: <reason>`, `tool unavailable: <tool>`.
- If phase 8 raised a SUSPECTED deletion/data-sharing claim mismatch, this result upgrades it to `EXPLOITED` (data remains) or marks it `false-positive` with `verification.reason` (deletion verified).

## Step 3: Cookie and tracker audit (PRIV-COOKIE-AUDIT, needs has_web_ui)
Loads the page in three fresh browser contexts (before consent, after clicking reject, after clicking accept) and records cookies, localStorage keys and third-party requests.
```
SHARE=~/.local/share/release-gate
mkdir -p <project>/.release-gate/evidence/cookie-audit
RG_PLAYWRIGHT_BASE=$SHARE/node PLAYWRIGHT_BROWSERS_PATH=$SHARE/node/ms-playwright \
  node <skill>/scripts/cookie_audit.mjs --url http://127.0.0.1:3105/ \
  --out <project>/.release-gate/evidence/cookie-audit/cookie-audit.json \
  [--reject-text Reject] [--accept-text Accept] [--timeout 15000]
```
- Refuses non-loopback URLs unless `RG_ALLOW_NONLOCAL=1`; set it only for a staging target the user confirmed in `scope.yaml`. Exit 2 = refused/usage, 3 = Playwright missing (`NOT-TESTED: tool unavailable: playwright`).
- Pass the app's real button labels with `--reject-text` / `--accept-text`. If neither control is found the script still records the three loads; note "no consent control found" in the finding.
- Output keys: `before_consent`, `after_reject`, `after_accept` (lists like `cookie:_ga`, `request:https://...`, `localStorage:k`), `detail`, `violation`.
- The "essential" filter is name-based (session/csrf style names). Read `detail` and re-classify by hand.
- A page that embeds third-party hosts makes Chromium attempt real requests to them, as any visit would. If the user does not want that contact, run it with outbound network blocked; requests are still logged when issued.
- Mapping:
  - Non-essential cookie/tracker/third-party request in `before_consent` or `after_reject`: finding `PRIV-COOKIE-AUDIT`, category `tracking`, `EXPLOITED`, evidence = the JSON. Severity high if gdpr/uk-gdpr/eprivacy applies (consent required), else medium.
  - Both lists empty: check `VERIFIED-ABSENT`, title "no non-essential cookie/third-party request before consent or after reject (3 loads, Chromium, page <url>)". Covers that page only.
  - Trackers present only `after_accept`: expected; record in `privacy.json`, no finding.
  - Cannot run: `NOT-TESTED: application not running` / `tool unavailable: playwright` / `out of scope: <reason>`.
- Desktop apps, games, extensions: no page to load. Static evidence only (inventory `third_parties`, `client_storage`); record `NOT-TESTED: no web UI to audit`.

## Step 4: Data minimization (PRIV-MINIMIZATION)
For each inventory field with `used_in_code: false`: grep the code for reads of it. No read path: finding `PRIV-MINIMIZATION`, `category: privacy`, low (medium if `classification` is `sensitive`, `financial`, `children` or `credential`); `TOOL-CONFIRMED` when your grep (saved as evidence) shows no reader, else `SUSPECTED`. Also flag fields with `retention: none defined` and `contains_credential: true` log sinks (hand the latter to phase 6 `OPS-LOG-HYGIENE`). No unused fields: `VERIFIED-ABSENT` scoped to the inventory fields checked. Inventory unconfirmed: `SUSPECTED` at best.

## privacy.json (read by `report_build.py`)
```json
{
  "regimes": [{"name": "GDPR", "applies": true, "why": "may apply: audience includes eu-eea (established-in-eu)", "last_verified": "2026-10-18"}],
  "rights_tests": [{"right": "deletion", "result": "profile deleted; login rejected; canary absent in DB",
                    "evidence_class": "VERIFIED-ABSENT", "evidence": "evidence/privacy/deletion-test.txt"}],
  "cookie_audit": {"before_consent": [], "after_reject": [], "after_accept": ["request:https://stats.example/c"],
                   "evidence": "evidence/cookie-audit/cookie-audit.json"}
}
```
`applies` must be a JSON boolean: the report renders any non-empty string, including "no", as `yes`. Put "may apply" / "does not apply" nuance in `why`. Evidence paths are relative to `.release-gate/`.

## Adversarial verification
No check here is critical-category, but every High finding needs it (SKILL principle 2): for an `EXPLOITED` tracker-before-consent or a failed deletion, spawn a fresh subagent with the evidence JSON and request script to disprove it ("is that host first-party, or a strictly necessary service? re-run the audit and tell me if it reproduces"). Outcome into `adversarial`. Refuted: downgrade, say why. Medium and below: not required, but state that the pass covers only the pages and inputs tried.

## NOT-TESTED strings (exact)
- `no data inventory`; `inventory not confirmed by user` (add as a note on results, not as a pass)
- `application not running`
- `tool unavailable: playwright`
- `out of scope: <reason>`
- `no web UI to audit`
- `no export endpoint in code` / `no deletion endpoint in code`
- `skipped by user`
