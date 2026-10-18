# Stack: Rust

## Detect
`Cargo.toml` (+ `Cargo.lock`; a binary crate without one is a `lockfiles_missing` entry), `*.rs`. Frameworks reported: actix, axum, tauri. `target/` is skipped when scanning.

## Pinned tools that apply
- semgrep: `rust/lang` rules if the snapshot has them for security; coverage is thin, so say so in the SAST entry instead of implying breadth.
- osv-scanner on `Cargo.lock`; gitleaks; syft; hadolint/trivy config.
- Not pinned: cargo-audit, cargo-deny, cargo-geiger, clippy. `NOT-TESTED: tool unavailable: cargo-audit` unless the project ships or declares it.

## Gotchas to read for
- `unsafe` blocks: each one is a manual-review item (raw pointer lifetimes, `from_raw_parts`, `transmute`, FFI boundaries). Count them with a grep and read the ones on parsing or input paths.
- `.unwrap()` / `.expect()` / indexing / integer arithmetic on attacker-controlled input: a panic is a denial of service in a server; overflow wraps silently in release builds unless `overflow-checks` is on.
- `std::process::Command::new("sh").arg("-c")` with interpolated input; SQL built with `format!` (sqlx `query` instead of `query!`/binds).
- `danger_accept_invalid_certs(true)` (reqwest), disabled TLS verification, hard-coded keys, `rand::thread_rng` is fine but a seeded `StdRng` for tokens is not.
- Deserialisation of untrusted data into large structures with no size limits (serde, bincode).
- axum/actix: handlers missing an auth extractor, permissive CORS layers, no request body limit.
- `Cargo.toml` `[patch]` / git dependencies without a locked rev; build scripts (`build.rs`) and proc-macros run code at build time.
- For Tauri apps also read `tauri.md`.

## Check ids
SEC-SAST (thin coverage, state it), SEC-SCA, SUP-PINNING, COR-RACE if has_server.
