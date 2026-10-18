# Stack: Java / Kotlin (JVM)

## Detect
`pom.xml`, `build.gradle(.kts)`, `settings.gradle(.kts)`; `*.java`, `*.kt`. Framework reported: `spring` (spring-boot / org.springframework). No standard lockfile is expected for Maven/Gradle, so none is flagged; note unpinned version ranges (`+`, `[1.0,)`, `LATEST`) under SUP-PINNING.

## Pinned tools that apply
- semgrep: `java/lang/security`, `java/spring`, `java/servlets`, `java/jax-rs`, `java/jjwt`, `java/java-jwt`, `kotlin/lang` where the snapshot has them.
- osv-scanner on `pom.xml` / `gradle.lockfile` if present (Gradle lockfiles are opt-in; without one, results are approximate: say so).
- gitleaks, syft, trivy config, hadolint.
- Not pinned: OWASP dependency-check, SpotBugs/find-sec-bugs, `mvn versions`. `NOT-TESTED: tool unavailable: <name>` unless the project ships it.

## Gotchas to read for
- Deserialisation: `ObjectInputStream.readObject` on network/file/cache data, Jackson `enableDefaultTyping` / `@JsonTypeInfo(use = Id.CLASS)`, XStream and SnakeYAML without safe constructors, Java RMI/JMX exposed.
- XXE: `DocumentBuilderFactory`, `SAXParser`, `XMLInputFactory` without disallowing DOCTYPE/external entities.
- SQL/JPQL/HQL built by string concatenation; `@Query` with `nativeQuery` and concatenation; SpEL / OGNL / JNDI lookups with user input (Log4Shell-style); template engines (Freemarker, Thymeleaf, Velocity) rendering user-supplied templates.
- Spring: Actuator endpoints (`/env`, `/heapdump`, `/jolokia`) exposed without auth (`management.endpoints.web.exposure.include=*`), `permitAll()` on broad matchers, CSRF disabled on session-cookie apps, mass assignment through `@ModelAttribute` without `@InitBinder` allow-lists, `spring.h2.console.enabled=true`.
- Path handling: `new File(base, userInput)` without canonical-path containment; zip-slip in archive extraction.
- Trust managers that accept everything, `HostnameVerifier` that returns true, `java.util.Random` for tokens, MD5/SHA-1 for passwords.
- Credentials in `application.properties` / `application-*.yml`; Gradle/Maven repositories over plain HTTP.

## Check ids
SEC-SAST, SEC-SCA, SEC-IAC (container), SUP-PINNING, OPS-DEPLOY-CONFIG (actuator/debug), SEC-INJECTION-DYNAMIC on reachable sinks.
