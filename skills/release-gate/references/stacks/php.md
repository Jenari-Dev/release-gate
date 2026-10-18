# Stack: PHP

## Detect
`composer.json` (+ `composer.lock`; missing lock with dependencies is a `lockfiles_missing` entry), `*.php`, `php.ini`, `.htaccess`. Framework reported: `laravel` (laravel/framework). WordPress/Drupal are not detected by name; look for `wp-content/`, `wp-config.php`.

## Pinned tools that apply
- semgrep: `php/lang/security`, plus `php/laravel`, `php/symfony`, `php/doctrine`, `php/wordpress-plugins` when present.
- osv-scanner on `composer.lock`; gitleaks (check `.env` files committed by mistake); syft; hadolint/trivy config.
- Not pinned: `composer audit`, PHPStan, Psalm, Progpilot. `NOT-TESTED: tool unavailable: composer` unless the project ships it.

## Gotchas to read for
- Production config: `display_errors=On` / `display_startup_errors`, `error_reporting(E_ALL)` echoed to users, `expose_php`, `allow_url_include=On`, `allow_url_fopen` with user URLs, `register_globals`-style `extract($_REQUEST)`, `phpinfo()` files left in the web root.
- `include`/`require` with user-influenced paths (LFI/RFI), `unserialize` on user data (POP chains; prefer JSON), `eval`, `assert` with strings, `preg_replace` with `/e`, `system`/`exec`/`passthru`/backticks with interpolated input.
- SQL via string concatenation or `mysqli_query` with request values; `PDO` with emulated prepares off is the safe pattern to compare against.
- Uploads: extension/MIME checks only, files saved inside the web root with their original name (executable `.php`/`.phtml`), no `.htaccess` deny for the upload directory.
- Sessions and auth: `md5`/`sha1` password hashes (use `password_hash`), `==` comparisons on tokens or hashes (type juggling, `0e...` collisions), missing `session_regenerate_id` after login, cookies missing the HttpOnly, SameSite and transport-only flags.
- Laravel: `APP_DEBUG=true` and `APP_KEY` in the repo, `$guarded = []` / `$fillable` missing (mass assignment), `DB::raw` with input, `{!! !!}` in Blade on user data, `.env` served from a mis-pointed web root (`public/` must be the document root).
- WordPress plugins: missing nonce or capability checks on AJAX/REST handlers, direct `$wpdb->query` without `prepare`.

## Check ids
SEC-SAST, SEC-SCA, SEC-ERROR-LEAKS, SEC-UPLOADS, OPS-DEPLOY-CONFIG, SEC-INJECTION-DYNAMIC.
