# Stack notes

Short per-stack add-ons for phases 2 and 3. Load only the files for stacks that `detect_stack.py` reports (and any marker listed in the file), alongside the phase file. They add detection hints, which pinned tools apply, and gotchas worth reading code for. They don't replace the phase playbooks, and they don't change evidence rules (SKILL principle 1).

Conventions in every file:
- Only tools in `tools.lock.yaml` are pinned: gitleaks, trufflehog, osv-scanner, trivy, syft, hadolint, semgrep (+ vendored `semgrep-rules`), bandit, pip-audit, checkov, nuclei, zap, playwright.
- Any other auditor (cargo-audit, govulncheck, composer audit, `dotnet list package --vulnerable`, OWASP dependency-check, Android lint, MobSF, ...) is not pinned. Use it only if the project already ships or declares it, record its version, and otherwise record `NOT-TESTED: tool unavailable: <name>`. Never download one on the fly. osv-scanner still covers the lockfile.
- Gotchas are things to read code and config for. A hit stays `SUSPECTED` until you reproduce it or a tool confirms it and you read the code path.
- Semgrep rule directories are picked from what exists under the vendored snapshot (`ls $SHARE/semgrep-rules/<lang>` first); skip missing ones and say so.

| File | Triggered by (`detect_stack.py` unless noted) |
|---|---|
| `python.md` | language `python`; pip/poetry/uv/pipenv/pdm |
| `node.md` | npm/yarn/pnpm/bun; frameworks express, next, react, ... |
| `go.md` | `go.mod` |
| `rust.md` | `Cargo.toml` |
| `java.md` | maven/gradle; framework `spring`; Kotlin on JVM |
| `dotnet.md` | `*.csproj` (nuget); language `csharp` |
| `php.md` | composer; framework `laravel` |
| `unreal-unity.md` | frameworks `unreal`, `unity` |
| `electron.md` | framework `electron` |
| `tauri.md` | framework `tauri` |
| `android.md` | framework `android` (`AndroidManifest.xml`) |
| `ios.md` | framework `ios` (`*.xcodeproj` / `*.xcworkspace`) |
| `browser-extension.md` | framework `browser-extension` (MV2/MV3 `manifest.json`) |

Several can apply at once (an Electron app is also Node; a Tauri app is also Rust plus a web front end). Read each, de-duplicate overlapping items.
