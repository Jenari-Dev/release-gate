# Phase 9: Platform requirements

## Goal
Compare what the distribution platform will ask you to declare (privacy label, data-safety form, permissions, store listing disclosures) with what the data inventory and code say the product does. Find mismatches before a reviewer or user does.

This skill has no reference data for any store's rules. It cannot tell you whether a submission will be accepted. Every requirement below is a pointer to the official page you must read at the time of submission, not rule text.

## Applies when
`product.distribution` includes any of `mobile-app`, `browser-extension`, `game`, `desktop-app` (check `PLAT-DISCLOSURES`, category `platform`, phase 9, `full` mode). Websites, APIs, libraries, CLIs and self-hosted services: not applicable. A `game-mod` is covered by the mod disclaimer in phase 8, and by the host game's own terms (see Step 3).

## Preconditions
- `data-inventory.yaml` exists and `confirmed_by_user` is true. Unconfirmed inventory makes every comparison here `SUSPECTED` at best and the output must say "inventory not confirmed by user".
- Phase 8 policy (the user's real policy file or the draft) is available for the label-vs-policy comparison.
- Nothing is submitted, logged into or entered in any store console by this skill. You read the user's own manifests and drafts only.

## Step 1: Declared data vs actual data
1. Ask the user which store(s) they publish to and for any already-filled privacy label, data-safety form or listing text (pasted or as files). If they have none, build a table from the inventory and tell them it is a starting point for the form, not the form.
2. Build a table: each inventory field and each third party (SDK, analytics, ads, crash reporting) against the store's data-category questions. Each row: what is collected, purpose, whether linked to identity, whether shared with a third party, whether optional, retention.
3. Compare against what the user declared. Flag: collected-but-undeclared (highest value), declared-but-not-collected, third-party SDK present in dependencies with no matching declaration, tracking declared as "none" while an analytics or ad host appears in the code or in cookie/tracker audit output, and a privacy-policy URL requirement with no policy yet (phase 8).
4. Classification:
   - Undeclared collection confirmed by a grep or SDK in the lockfile that you read: `TOOL-CONFIRMED` (grep or SBOM output + `file:line`), severity medium (high if the data is sensitive or children's data).
   - Mismatch from your reading only: `SUSPECTED` with the reason it was not reproduced.
   - No mismatch found: `VERIFIED-ABSENT` is only allowed for the specific rows compared, with the comparison table saved to `evidence/PLAT-DISCLOSURES/label-vs-inventory.md`. Title it "declared categories match the N inventory fields and M third parties compared; store acceptance not determined".

## Step 2: Permissions and capabilities
1. Collect requested permissions from the project's manifests: `AndroidManifest.xml`, `Info.plist` usage strings and entitlements, browser extension `manifest.json` `permissions`/`host_permissions`, desktop installer or sandbox manifests, Steam depot/launch options if present.
2. For each permission, find the code that needs it and the user-facing reason string. Unused permission, or a broad host permission where a narrow one would do, is a `PRIV-MINIMIZATION`-style finding recorded under `PLAT-DISCLOSURES`, `SUSPECTED` unless your grep proves no code path uses it (`TOOL-CONFIRMED`).
3. Each permission needs a written justification the user can paste into the store form. Write it from the code you found. If you cannot find a use, say so; do not invent a purpose.

## Step 3: Store-specific pointers (check the current policy; do not rely on this file)
Only cite what the user must verify. Do not quote store text.
- Apple App Store: privacy "nutrition label" and privacy policy URL requirement. Check the current policy at https://developer.apple.com/app-store/review/guidelines/ and https://developer.apple.com/app-store/app-privacy-details/.
- Google Play: Data safety form and Permissions declarations. Check the current policy at https://support.google.com/googleplay/android-developer/answer/10787469 and https://play.google.com/about/developer-content-policy/.
- Chrome Web Store: privacy practices tab, single-purpose and limited-use statements. Check the current policy at https://developer.chrome.com/docs/webstore/program-policies/.
- Firefox Add-ons: data collection permission disclosures. Check the current policy at https://extensionworkshop.com/documentation/publish/add-on-policies/.
- Steam: store page disclosures and any questionnaires the partner portal presents. Check the current policy at https://partner.steamgames.com/doc/gettingstarted.
- Microsoft Store, itch.io, GOG, console platforms, mod hubs (Nexus, Steam Workshop) and other stores: not covered by this skill's reference data; verify with the store's official developer documentation.
URLs are pointers recorded on the date of this release-gate version and may have moved; treat a dead link as "unverified" and find the store's current developer policy page.

## Step 4: Output
Findings go in `findings.json` with `check_id: PLAT-DISCLOSURES`, `category: platform`. Add to the lawyer/owner questions: "Are these store declarations accurate to what third-party SDKs actually collect? (SDK documentation is the authority; this skill reads only your code)", and "Which store policy version applied on the submission date?".

## Adversarial verification
Not critical-category. High findings (for example undeclared collection of sensitive data) still get a fresh subagent: give it the declaration, the inventory row and the code reference and ask it to find a reason the declaration is correct (data never leaves device, optional and off by default).

## NOT-TESTED strings (exact)
- `no data inventory`; `inventory not confirmed by user`
- `store declarations not provided by user`
- `store policy not covered by this skill's reference data; verify with the store's official documentation`
- `no manifest found for permissions review`
- `skipped by user`
