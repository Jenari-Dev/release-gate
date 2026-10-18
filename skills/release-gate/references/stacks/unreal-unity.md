# Stack: Unreal Engine / Unity (games and mods)

## Detect
Unreal: `*.uproject`, `Source/`, `Config/Default*.ini`. Unity: `ProjectSettings/` directory (+ `Assets/`, `Packages/manifest.json`). `detect_stack.py` reports frameworks `unreal` / `unity`. Compiled builds (`.pak`, `GameAssembly.dll`, `*_Data/Managed`) are artifacts, not source: scan them only if they already exist.

## Pinned tools that apply
- gitleaks on the repo, and on existing build output (`gitleaks dir <build-dir>`) for SEC-SECRETS-ARTIFACTS: API keys and server URLs get baked into `DefaultGame.ini`, ScriptableObjects, `.asset` files and `Resources/`.
- semgrep: `csharp/lang/security` for Unity scripts; `c/lang` rules are thin for Unreal C++, so say SAST coverage is partial.
- osv-scanner on `Packages/manifest.json` / any `package-lock`-style file the project has; syft; trivy for dedicated-server Dockerfiles; hadolint.
- Not pinned: Unity Package Manager audit, Unreal's own static analysis. `NOT-TESTED: tool unavailable: <name>`.

## Gotchas to read for
- Plaintext save games and settings (`SaveGame` slots, `PlayerPrefs`, JSON next to the exe) holding tokens, purchase state or currency. Editable saves are a product decision; stored credentials or entitlements in them are a finding.
- Anti-tamper and anti-cheat claims: if the store page, EULA or README says "protected", "tamper-proof" or "anti-cheat", look for what is really there. Client-side checks (memory flags, obfuscated numbers, `Application.genuine`) only raise effort. Anything authoritative (currency, progression, matchmaking, purchases) must be decided on a server. Report an authority-on-client design as a finding in terms of what a player could do, and don't call the game "secured".
- Dedicated-server and multiplayer: RPCs / Commands without server-side validation, client-supplied damage/position trusted, debug console or cheat commands (`ExecuteConsoleCommand`, `Cheat*`) compiled into shipping builds, listen server exposed with no auth.
- Telemetry and analytics SDKs (Unity Analytics, Firebase, Sentry) feeding the privacy inventory; ad IDs; children's data if the audience includes under-13s.
- Mods and scripting: runtime loading of user DLLs/Lua/Blueprints, asset-bundle loading from user paths or URLs (code execution via `AssetBundle` scripts), auto-update downloading without signature checks; mod-site uploads.
- Shipping config: development build flags, `-log`/`-console` enabled, debug symbols and unstripped `.pdb`s, hard-coded dev endpoints, test accounts, left-in editor scripts.
- Licensing: engine and middleware EULA terms, third-party asset licences (SUP-LICENSES), platform requirements (PLAT-DISCLOSURES).

## Check ids
SEC-SECRETS-ARTIFACTS, SEC-SAST (partial), SEC-SCA, PRIV-MINIMIZATION, PLAT-DISCLOSURES, SUP-LICENSES. Dynamic multiplayer tests only against a local dedicated server you start in scope.
