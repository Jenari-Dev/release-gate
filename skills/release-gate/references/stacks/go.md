# Stack: Go

## Detect
`go.mod` (+ `go.sum`), `*.go`. Package manager `go`. Frameworks: none reported specifically; read imports for gin, echo, fiber, chi, gorilla, net/http.

## Pinned tools that apply
- semgrep: `go/lang/security`, plus `go/gorilla`, `go/gorm`, `go/jwt-go`, `go/template`, `go/grpc` when imported.
- osv-scanner on `go.mod` / `go.sum`; gitleaks; syft; hadolint/trivy config for Dockerfiles.
- Not pinned: govulncheck (reachability-aware, the better SCA signal for Go), gosec, staticcheck. `NOT-TESTED: tool unavailable: govulncheck` unless the project ships or declares it. Without it, treat osv-scanner hits as `SUSPECTED` until you check the call path.

## Gotchas to read for
- `text/template` used for HTML (no escaping) instead of `html/template`; `template.HTML(userInput)`.
- `exec.Command("sh", "-c", ...)` with interpolated input; `fmt.Sprintf` into SQL instead of placeholders.
- `http.ListenAndServe` with no timeouts (`ReadHeaderTimeout` missing: slowloris); `http.Server` without `MaxHeaderBytes`; `io.ReadAll(r.Body)` with no `http.MaxBytesReader`.
- `InsecureSkipVerify: true`, `tls.Config` without a minimum version, `math/rand` for tokens, `filepath.Join` with user input and no containment check (zip-slip in `archive/zip`).
- Goroutine/data-race patterns on shared maps and counters (COR-RACE: run the project's tests with `-race` only if the suite already runs and the user confirmed the command).
- `net/http/pprof` or `expvar` imported in a binary that listens publicly.
- `replace` directives pointing at local paths or forks in `go.mod`; vendored dependencies that differ from `go.sum`.

## Check ids
SEC-SAST, SEC-SCA, COR-RACE (if has_server), SEC-SSRF-DYNAMIC for handlers that fetch URLs, OPS-DEPLOY-CONFIG for pprof/debug exposure.
