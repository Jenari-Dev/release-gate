# Stack: Tauri

## Detect
`tauri.conf.json` (reported as framework `tauri`), `src-tauri/Cargo.toml` (`tauri` crate), `@tauri-apps/api` / `@tauri-apps/cli` in `package.json`, `src-tauri/capabilities/*.json` (Tauri 2). Read `rust.md` and `node.md` too (Rust backend plus a web front end).

## Pinned tools that apply
- semgrep: `javascript/lang/security`, `typescript/lang/security` for the front end; Rust rules are thin (`rust/lang`), so say so.
- osv-scanner on `Cargo.lock` and the JS lockfile; gitleaks; syft.
- Not pinned: cargo-audit, `tauri info`. `NOT-TESTED: tool unavailable: cargo-audit` unless the project ships it.

## Gotchas to read for
- Tauri 1 `tauri.allowlist`: `"all": true`, `fs.scope` of `**` or the home directory, `shell.execute`/`shell.open` enabled, `http.scope` wildcards, `protocol.assetScope` too wide, `dangerousRemoteDomainIpcAccess`.
- Tauri 2 capabilities and permissions (`src-tauri/capabilities/*.json`): `core:default` plus broad `fs:*`, `shell:*`, `http:*`, `opener:*` grants; capabilities attached to remote URLs (`remote.urls` with wildcards); windows listed in more capabilities than they need.
- `#[tauri::command]` handlers that take paths, URLs or shell arguments from the front end without validation (path traversal, argument injection). Each command is an API that any script in the webview can call.
- Content Security Policy: `app.security.csp` set to `null`, or containing `unsafe-eval` / `unsafe-inline` / broad `connect-src` / `*`; `dangerousDisableAssetCspModification`; `devUrl`/`devPath` pointing at a dev server in a release config.
- Loading remote content into a window that has command access; `withGlobalTauri: true` exposing the invoke bridge to every script on the page.
- Updater plugin: `pubkey` missing or placeholder, endpoints over HTTP, private signing key in the repo or CI logs. Bundler config: unsigned installers, `identifier` collisions.
- Sidecars/external binaries (`externalBin`) shipped without a version pin or hash.

## Check ids
SEC-SAST, SEC-SCA, SEC-SECRETS-HISTORY (updater keys), PLAT-DISCLOSURES (signing), SEC-XSS-DYNAMIC if the front end renders user content.
