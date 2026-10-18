# Phase 11: Supply chain and licensing

## Goal
Report which licenses the shipped dependencies and bundled assets carry, whether they fit the project's own license and distribution, and whether the build can be reproduced from pinned inputs. Not legal advice: a license reading that matters goes to a lawyer.

## Relationship to phase 2
- SEC-SBOM (phase 2, `supply-chain`, syft) and SEC-SCA (phase 2, `sca`, osv-scanner and ecosystem auditors) already produced an SBOM and vulnerability findings. Reuse that output (`evidence/syft-*/`) and cite it; do not re-run unless the tree changed. SUP-LICENSES and SUP-PINNING add the license and pinning dimensions. A vulnerability in a dependency is a SEC-SCA finding, not a SUP finding.
- If SEC-SBOM is NOT-TESTED, SUP-LICENSES can still be done from lockfiles and package metadata you read, but at `SUSPECTED` only.

## Preconditions
- `config.yaml` has `product.license` and `product.distribution`. Without them: `NOT-TESTED: project license not provided`.
- Tools pinned and used: `syft` (SBOM with license fields), optionally `trivy` license scan if you choose. Others are not pinned: a dedicated license-scanner is not in `tools.lock.yaml`; do not name one as installed.
- Network: syft reads the local tree and does not need to send source. Package-registry lookups (for example to resolve a missing license) are not done; unresolved licenses stay unresolved.

## Step 1: Licenses (SUP-LICENSES, category `licensing`)
1. Read the SBOM from phase 2 or run `run_tool.py --project P --tool syft --test-type scan -- scan dir:{project} -o cyclonedx-json={evidence}/sbom.cdx.json`. Extract component, version, and declared license (SPDX id or expression).
2. Build `evidence/SUP-LICENSES/license-table.md`: license, count, example packages, runtime vs dev dependency (dev-only deps matter less when not distributed).
3. Compare with the project's license and how it ships:
   - Strong or network copyleft (GPL, AGPL, SSPL-style, and similar) in a component linked into a proprietary or differently-licensed distributable: finding, `SUSPECTED`, severity medium to high depending on distribution (static link in a distributed binary versus a server-side dev tool). State the facts; leave the conclusion to a lawyer.
   - Licenses with attribution or notice requirements (MIT, BSD, Apache-2.0): check the project ships a NOTICE/third-party-licenses file for what it distributes; a missing one is low severity `SUSPECTED`.
   - Non-OSS or custom licenses, "no license" repositories, or license fields like `UNLICENSED`, `SEE LICENSE IN ...`: `SUSPECTED`, flag for human review.
   - Unknown or missing license metadata: `SUSPECTED` for human review, list the package, never assume permissive. Count them in the title.
   - Bundled assets (fonts, images, audio, models, game assets, vendored code): search for files in the tree with their own license headers or no clear origin; ask the owner for the source and license of each distributed asset. Anything the owner cannot source is flagged, not assumed free to use.
   - Extension, mod or plugin projects: add the host product's terms (see phase 8 and the EULA reading) to the lawyer questions.
4. Results:
   - Table built, no flagged items: `VERIFIED-ABSENT` titled "N components with declared licenses all permissive (list); K with no declared license, listed for review" only when K is zero. If K is greater than zero, the entry is a finding for K and nothing is a pass.
   - License metadata reflects what package authors declared; it is not verified against the package contents. Say so.
5. Copy to the lawyer questions: compatibility of each copyleft/custom component with the intended distribution; whether attribution notices are sufficient.

## Step 2: Pinning and build integrity (SUP-PINNING, category `supply-chain`)
Read the repo; no network.
1. Lockfiles: for each ecosystem in `detect_stack.py` output, check a lockfile is committed (`package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`, `Cargo.lock` for binaries, `poetry.lock`/`uv.lock`/hashed `requirements.txt`, `go.sum`, `Gemfile.lock`, `composer.lock`). No lockfile for an application: `TOOL-CONFIRMED` (file listing) medium.
2. Unpinned ranges: dependencies with `*`, `latest`, wide `>=` ranges, git URL dependencies without a commit, and floating Docker tags (`:latest`, no digest). Count and list; severity low to medium.
3. CI: for each workflow file, list `uses:` entries. Third-party actions not pinned to a full commit SHA are findings (low to medium; higher when the workflow has write permissions or secrets). `run:` steps that pipe a downloaded script to a shell are findings (`curl | sh` patterns).
4. Install scripts: dependencies with install/postinstall hooks (npm `scripts.install`/`postinstall` in lockfile metadata, Python `setup.py` with custom commands). List packages that run code at install; recommend `--ignore-scripts` where the project does not need them. This is a risk list, not an incident.
5. Typosquat-style risk: compare dependency names against what the code imports and what the registry-popular spelling is, by eye and by the names in the lockfile. Without a registry lookup you can only flag suspicious near-duplicates as `SUSPECTED`; do not claim "no typosquats".
6. Results: findings carry `file:line` and class `TOOL-CONFIRMED` (grep output saved) for verifiable facts like a missing lockfile or an unpinned `uses:` line; `VERIFIED-ABSENT` only for the exact rule checked ("all N `uses:` entries in M workflows pinned to SHAs", output saved). Everything about whether a pinned dependency is itself trustworthy is out of scope.
- No CI, no lockfiles because there are no dependencies: record "not applicable" with the reason, do not mark pass.

## Adversarial verification
Not critical-category; none of these are High by default. If you rate a license finding High (copyleft in a shipped proprietary binary), a fresh subagent gets the SBOM row and the linking facts and tries to argue it does not apply (dev-only, dynamic linking exception, dual-licensed). Record the outcome; the lawyer still decides.

## NOT-TESTED strings (exact)
- `project license not provided`
- `tool unavailable: syft` (license data then from lockfiles, SUSPECTED only)
- `no dependency manifest in project`
- `no CI configuration in project`
- `skipped by user`
