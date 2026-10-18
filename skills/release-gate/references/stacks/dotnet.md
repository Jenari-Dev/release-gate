# Stack: .NET (C#)

## Detect
`*.csproj` (package manager `nuget`), `*.sln`, `*.cs`, `appsettings*.json`, `packages.lock.json` (opt-in; absent lockfile is not flagged by `detect_stack.py`, so note unpinned `*` / floating versions under SUP-PINNING yourself).

## Pinned tools that apply
- semgrep: `csharp/lang/security`, `csharp/dotnet`, `csharp/razor` where the snapshot has them.
- osv-scanner on `packages.lock.json` / `*.csproj`; gitleaks (also covers `appsettings*.json`); syft; hadolint/trivy config.
- Not pinned: `dotnet list package --vulnerable`, Security Code Scan, Roslyn analyzers. Use only if the project's SDK is already installed and the user confirms (it contacts NuGet); otherwise `NOT-TESTED: tool unavailable: dotnet`.

## Gotchas to read for
- `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `LosFormatter`, Json.NET `TypeNameHandling` other than `None` on untrusted data.
- SQL built with string interpolation (`FromSqlRaw`, `ExecuteSqlRaw`, `SqlCommand` text); `Process.Start` with user input; `XmlDocument` / `XmlReader` with DTD processing enabled (XXE).
- ASP.NET Core: missing `[Authorize]` / fallback policy, `[AllowAnonymous]` on broad controllers, `[IgnoreAntiforgeryToken]`, CORS `AllowAnyOrigin` with credentials, `UseDeveloperExceptionPage` outside Development, Swagger exposed publicly, `ValidateIssuer = false` / `ValidateAudience = false` / `RequireSignedTokens = false` in JWT bearer setup.
- Model binding over-posting: binding request bodies straight to EF entities (mass assignment).
- `ServerCertificateCustomValidationCallback` returning true, `ServicePointManager` validation off, `Random` for tokens, MD5/SHA1/DES, hard-coded `MachineKey`, connection strings and keys in committed `appsettings.json`.
- Desktop (WPF/WinForms) and Unity-on-.NET: plaintext tokens in config files, auto-update over HTTP, no signature check on downloaded updates.

## Check ids
SEC-SAST, SEC-SCA (osv-scanner), SUP-PINNING, SEC-HEADERS-CORS, SEC-SESSION, SEC-SECRETS-HISTORY (appsettings).
