# Stack: Android

## Detect
`AndroidManifest.xml` (reported as framework `android`), `build.gradle(.kts)` with `com.android.application`, `res/xml/network_security_config.xml`, `proguard-rules.pro`. Kotlin/Java sources: also read `java.md`. React Native / Flutter / Capacitor apps carry their own front end: read `node.md` where relevant.

## Pinned tools that apply
- semgrep: `java/android`, `java/lang/security`, `kotlin/lang` where the snapshot has them.
- gitleaks (keystores, `google-services.json`, `local.properties`, API keys in `strings.xml` and `BuildConfig`); osv-scanner on Gradle lockfiles if present; syft; trivy for backend Dockerfiles.
- Existing APK/AAB: `gitleaks dir` on the unpacked output of a build the user already has (SEC-SECRETS-ARTIFACTS). Don't run `./gradlew` without approval; it runs project code.
- Not pinned: Android Lint, MobSF, apkleaks. Use only if the project already ships or runs them; else `NOT-TESTED: tool unavailable: <name>`. Dynamic app testing needs a device/emulator the user owns and an explicit scope entry.

## Gotchas to read for (manifest first)
- Exported components: `<activity>`, `<service>`, `<receiver>`, `<provider>` with `android:exported="true"` or an `<intent-filter>` and no permission. Anything exported takes input from any installed app. Check what each handler does with Intent extras, deep-link URIs and `Uri` path segments.
- Content providers: `grantUriPermissions`, `exported`, unvalidated `_data`/path from the URI (path traversal), SQL built from `selection` strings.
- Cleartext traffic: `android:usesCleartextTraffic="true"`, a `network_security_config` with `cleartextTrafficPermitted="true"` or a `<certificates src="user">` trust anchor in release, pinned-certificate bypasses guarded by `BuildConfig.DEBUG` that ship.
- `android:allowBackup="true"` (default) with tokens/databases in app data; `android:debuggable="true"` in release; `WebView` with `setJavaScriptEnabled(true)` plus `addJavascriptInterface`, `setAllowFileAccess(true)`, `setAllowUniversalAccessFromFileURLs`, `loadUrl` on untrusted URLs.
- Storage: tokens/PII in `SharedPreferences` or external storage in plaintext, world-readable files, secrets in logs (`Log.d` of tokens), clipboard use of secrets. Prefer Keystore-backed storage.
- Pending intents that are mutable/implicit, `sendBroadcast` of sensitive data without a permission, custom permissions with `normal` protection level guarding sensitive APIs.
- Weak crypto: hard-coded keys/IVs, ECB, `MODE_WORLD_READABLE`, `SecureRandom` seeded with constants, `TrustManager` that accepts all certificates, `HostnameVerifier` returning true.
- Play Console data-safety form vs. what the SDKs actually collect (feeds PLAT-DISCLOSURES and the data inventory); `targetSdkVersion` below the store minimum.

## Check ids
SEC-SAST, SEC-SECRETS-ARTIFACTS, SEC-SCA, PRIV-MINIMIZATION, PLAT-DISCLOSURES, SEC-IAC for backend containers.
