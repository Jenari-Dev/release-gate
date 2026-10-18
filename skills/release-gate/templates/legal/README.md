# Legal document templates

Blank drafts that release-gate fills in during the `legal` phase. They are not legal advice and contain no real company data. Every template (except `security.txt.tmpl`) starts with the DRAFT banner required by SKILL.md principle 4, and ends with "Questions for a lawyer" and a reminder to verify regimes against `references/law/`.

## Which template applies

| Template | Generate when (intake answer) |
|---|---|
| `privacy-policy.md.tmpl` | Always, if any personal data appears in `data-inventory.yaml` fields |
| `terms-of-service.md.tmpl` | `distribution` includes website, saas, api, mobile-app; or `features.accounts` |
| `eula.md.tmpl` | `distribution` includes desktop-app, game, game-mod, mobile-app, self-hosted, cli |
| `cookie-policy.md.tmpl` | Any `client_storage` entry whose `necessity` is not `strictly-necessary` |
| `consent-ui.md.tmpl` | Non-essential `client_storage`; or `features.accounts`; or marketing email (`features.sends_email`); or `audience.under_13_possible` / `under_16_possible` (age gate) |
| `acceptable-use-policy.md.tmpl` | `features.user_generated_content` or `features.messaging` |
| `dmca-takedown.md.tmpl` | `features.user_generated_content`, hosted user uploads |
| `refund-and-cancellation.md.tmpl` | `features.payments` or `features.subscriptions` |
| `subprocessors.md.tmpl` | `third_parties` with role processor/subprocessor/unknown; essential if you sell to businesses |
| `ai-disclosure.md.tmpl` | `features.ai_features` (providers from `features.ai_providers` and `third_parties`) |
| `third-party-notices.md.tmpl` | Any distributed dependency (always for desktop-app, game, mobile-app, browser-extension, self-hosted, cli) |
| `vulnerability-disclosure-policy.md.tmpl` | Any internet-facing service or distributed software, if someone will read the inbox |
| `security.txt.tmpl` | Same as above, for web properties (`surface.has_web_ui` or `has_server`) |
| `accessibility-statement.md.tmpl` | Any user-facing UI, especially website, saas, mobile-app; required in some markets |
| `mod-disclaimer.md.tmpl` | `distribution` includes game-mod, or `product.modded_product` is set |

Regional extras are chosen from `audience.regions` and the triggers in `references/law/*.yaml` (for example GDPR/UK GDPR sections in the privacy policy, `coppa.yaml` when `under_13_possible` or `directed_at_children`).

## How placeholders are filled

- `{{UPPER_CASE}}` values come from `.release-gate/config.yaml` (examples: `PRODUCT_NAME` = `product.name`, `ENTITY_NAME` = `operator.legal_entity`, `JURISDICTION` = `operator.entity_jurisdiction`, `CONTACT_EMAIL` = `operator.contact_email`, `MODDED_PRODUCT` = `product.modded_product`) or from answers the user gives in chat. Dates such as `EFFECTIVE_DATE` are set by the user at publish time.
- `{{#list}} ... {{/list}}` loops repeat once per entry in `.release-gate/data-inventory.yaml`: `fields`, `third_parties`, `client_storage`, `stores`, `log_sinks`. Inside a loop, lowercase names (`{{name}}`, `{{classification}}`, `{{purposes}}`, `{{retention}}`, `{{host}}`, `{{vendor}}`, `{{data_sent}}`, `{{mechanism}}`, `{{expiry}}`) are that entry's schema keys.
- `{{#flag}} ... {{/flag}}` renders only when the flag is true (config `features.*` or something derived from the inventory); `{{^flag}} ... {{/flag}}` renders when it is false or missing.
- `{{TODO ...}}` and `{{LAWYER_QUESTIONS}}` are never auto-filled with guesses. Leftover `{{...}}` markers mean a gap; do not publish until each is resolved.
- Inventory `rights.*` entries decide which rights the privacy policy may promise.

## Rules for filling

1. Traceability: every fact in the privacy policy, cookie policy, subprocessor list and AI disclosure must trace to an inventory entry. Remove unbacked statements. An inventory entry with no statement is a gap to report.
2. Do not invent retention periods, security measures or training promises. Use the inventory value, the owner's answer, or leave the TODO.
3. Delete the `<!-- AUTHOR NOTES -->` comments before publishing. Keep the DRAFT banner until a lawyer has reviewed the document.
4. Law references come only from `references/law/*.yaml`. Anything outside it (copyright, consumer payments, AI law, accessibility, IP and anti-circumvention) is "not covered by this skill's reference data; verify with a lawyer or official source".
