# Curated legal reference data

These files give release-gate a short, traceable checklist for each privacy regime it can check a project against. They are screening aids. They are not legal advice and they are not a complete statement of any law.

## Rules for this folder

1. **Official sources only.** A fact goes in only if it was read on an official government, legislature or regulator page. No law-firm blogs, no Wikipedia, no trade-body summaries, no memory.
2. **Omit anything unverified.** If a fact could not be confirmed from an official page, it is left out and listed under `not_covered:` with a note such as "not verified from an official source this session". Omitting is always better than guessing.
3. **Rules change. Verify before relying.** Thresholds (revenue, number of consumers, ages) and deadlines (72 hours, 45 days) are amended often, and many are inflation-adjusted. Every file carries a header comment saying so. The user must check the official source and, for any real decision, a qualified lawyer.
4. **Staleness.** Each file has `last_verified` (ISO date). The report flags any entry whose `last_verified` is older than 12 months as stale.
5. **Short quotes only.** Items are plain-English paraphrases. Nothing longer than about 15 words is quoted verbatim.
6. **Traceable.** Every trigger, obligation, right, rule and breach item has its own `source_url` (the page that was read). A `source_ref` field gives the article or section number.

## File format

One YAML file per regime, named `<id>.yaml`. The file starts with two comment lines: the official name, then the "Thresholds and rules change. Verify against the official source before relying on this." statement.

```yaml
id: gdpr                      # unique, matches the file name
name: "..."
short_name: GDPR
jurisdiction: EU/EEA
source_url: https://...       # https, official domain
last_verified: 2026-10-18     # ISO date
applicability:
  triggers:                   # machine-checkable triggers used by phase 7
    - id: ...
      description: "..."
      config_predicate: {jurisdictions_any: [eu-eea]}   # optional
      source_url: https://...
  notes: "..."
obligations:                  # checkable items
  - id: ...
    summary: "..."
    check: "how release-gate can check it against data-inventory.yaml or code"
    inventory_keys: [fields.lawful_basis]               # optional
    source_url: https://...
    source_ref: "Art. 6(1)"
breach_notification: [ {id, summary, deadline, source_url} ]
user_rights:  [ {id, summary, response_deadline?, source_url} ]
consent:      [ {id, summary, source_url} ]
children:     [ {id, summary, age?, source_url} ]
penalties_note:               # optional: {summary, source_url}
not_covered: ["..."]
lawyer_questions: ["..."]
```

`config_predicate` keys: `jurisdictions_any` (worldwide, eu-eea, uk, us-ca, us-other, japan, canada, brazil, australia), `children_under_13`, `directed_at_children`, `features_any` (accounts, payments, ugc, messaging, ai_features, analytics, sends_email).

## Checks

`tests/test_law_data.py` loads every file and enforces: required keys, unique ids, `https` source URLs on an allowed official domain list, an ISO `last_verified`, a `source_url` on every item, and the header statement.

When you add or refresh a file, fetch the official page again, update `last_verified`, and add any new official domain to the allow list in the test.
