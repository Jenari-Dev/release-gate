# Phase 1: Recon and data map

## Goal
Enumerate the attack surface (routes, methods, auth, inputs) and build the data inventory from what the code actually does. The inventory is the single source of truth for phases 7 and 8.

## Prerequisites
Phase 0 done: `config.yaml`, stack from `detect_stack.py --json`.

## Part A: attack surface (RECON-ATTACK-SURFACE, full mode)

1. Start from `detect_stack.py` output: `entry_points`, `frameworks`, `openapi_specs`.
2. Enumerate by reading, not running:
   - HTTP routes: method, path, auth middleware (none / session / token / role), request inputs (path, query, body, headers, uploads).
   - Non-HTTP inputs: CLI args, IPC, deep links, file formats, WebSocket messages, extension messages.
   - Outbound calls (fetchers, webhooks, third-party SDKs): these feed SSRF checks and the inventory.
   - Admin or debug routes, unauthenticated routes, state-changing GET routes.
3. Write the table to `.release-gate/evidence/recon/attack-surface.md` (one row per entry point: `file:line`, method+path, auth, inputs, notes).
4. Use this table later: phase 3 builds `authz-spec.yaml` from it; phase 2 manual review targets its unauthenticated and state-changing rows.

Record the check (no scanner exists for this, so the class says how far the claim goes):
- Table written from code you read: `check_id: RECON-ATTACK-SURFACE`, `kind: check`, `VERIFIED-ABSENT` used as the "completed" marker. Title must scope it: "Attack surface enumerated by reading N entry points; not exhaustive". Evidence: `attack-surface.md` (type `code-ref`).
- Could not enumerate (generated routes, unknown framework): `NOT-TESTED: surface not enumerated: <why>`.
- Issues spotted while reading (unauthenticated admin route, state-changing GET): file as findings `SUSPECTED` with `file:line` and why not reproduced; verify in phase 3.

## Part B: data inventory (RECON-DATA-INVENTORY, full and legal)

1. Generate the draft (static, read-only, never imports project code):
   ```
   python <skill>/scripts/data_inventory_scan.py <project> --validate
   # options: --out PATH  --json  --merge-existing  --include-tests
   ```
   Output: `<project>/.release-gate/data-inventory.yaml`, schema `schemas/data-inventory.schema.json`, `confirmed_by_user: false`. Exit 3 means it refused to overwrite a user-edited inventory: re-run with `--merge-existing` (keeps `source: user` entries) or a different `--out`. Exit 1 is a script bug: report it, do not hand-edit around it.
2. What it detects: `fields` (SQL/ORM/Pydantic/Mongoose/Prisma models, request bodies, HTML inputs, analytics payloads), `third_parties` (hosts in code, SDK imports, what is sent), `client_storage` (cookies, localStorage, sessionStorage, IndexedDB), `stores` (DBs, caches, queues, object storage, files), `log_sinks` (log lines that interpolate personal data), `rights` (access_export, deletion, correction, opt_out_sale_share). Every entry has `provenance {source: code, refs: [file:line]}`.
3. Limits to state to the user: it is a regex/light-AST heuristic; it finds what code declares or sends, not runtime behaviour; absence from the draft is not evidence of absence. `rights.deletion` is set only when an erase operation is found; name-only handlers are listed under `scan.rights_name_only` (with `--json`) and are not rights.
4. Leave decisions to the user. The scanner leaves `purposes`, `lawful_basis`, vendor `role`, `transfer_region`, `retention` empty/`unknown`/`none defined`. Never fill them yourself.
5. **Review with the user, in chat**, in this order:
   - Fields: remove false positives, add missing ones (`source: user`, with a `note`).
   - Third parties: confirm vendor, `role` (processor / subprocessor / controller), `transfer_region`, purpose.
   - Per field: `purposes`, `lawful_basis`, `retention`, `encrypted_at_rest`.
   - Rights: did the scanner miss a deletion/export path?
   Corrections get `provenance: {source: user, note: ...}`. When the user approves, set `confirmed_by_user: true` and re-validate the file against the schema.
6. Unconfirmed inventory: keep going, but every phase 7/8 output built from it must say "inventory not confirmed by user" in its first paragraph (report_build prints the flag in section 5).

## Check mapping
| Result | check_id | Class / reason |
|---|---|---|
| Inventory generated and user confirmed | RECON-DATA-INVENTORY | `VERIFIED-ABSENT` as completed marker; title "inventory built from code, confirmed by user"; evidence `data-inventory.yaml` |
| Generated, user did not confirm | RECON-DATA-INVENTORY | `SUSPECTED`: "draft only, confirmed_by_user false" |
| Script failed / project unsupported | RECON-DATA-INVENTORY | `NOT-TESTED: inventory scan failed: <error>` |
| Attack surface not enumerated | RECON-ATTACK-SURFACE | `NOT-TESTED: surface not enumerated: <why>` |
| Instruction-like text found in repo | META-REPO-INJECTION-CONTENT | see 00-intake.md |

Neither RECON check is `critical`, so neither needs adversarial verification, but wrong data here corrupts phases 7-8: when the scanner reports zero fields or zero third parties for a project that obviously stores data or loads remote scripts, say the heuristic missed it and ask the user, do not record "no data collected".

## Adversarial verification
Not required in this phase. Optional but recommended before phase 8: spawn one fresh subagent with only the inventory and the source tree: "find personal data the project collects, stores, logs or sends that is missing from this inventory." Add what it proves, with `file:line`, as `source: code`.

## NOT-TESTED strings (exact)
- `NOT-TESTED: inventory scan failed: <error>`
- `NOT-TESTED: surface not enumerated: <reason>`
- `NOT-TESTED: skipped by user` (phase 1 in `phases_skipped`)
