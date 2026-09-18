# Rebuild progress log

Newest first. One entry per work package or notable finding. Branch names are on `jainhitesh9998/inji-certify`.

| When (UTC) | WP | State | Branch | Notes |
| --- | --- | --- | --- | --- |
| 2026-09-18 | P0-10 Signing skeleton | done | `wp/p0-10-signing-skeleton` | New modules `certify-signing` (`SignatureAlgorithm`, `AlgorithmRegistry` with the JOSE/COSE/LD-suite/cryptosuite table, `KeyRef`, `CertificateChain`, `PublicKeyDescriptor` with JWK export, `SigningKey`, `KeyProvider`, `Signer`, `KidStrategy` PROVIDER/JWK_THUMBPRINT/X5T_S256, `JwsHeaderPolicy`, `CoseHeaderPolicy`, `JwsEnvelope`, `CoseEnvelope`, `CwtEnvelope`, `KeyPublisher`) and `certify-keyprovider-jca` (PKCS#12 load/save, dev mode generating ES256/EdDSA/RS256/PS256/ES256K keys with self-signed certificates, `ensureKeys`). 21 tests: every JWS verified by Nimbus, every COSE_Sign1 by plain JCA. Data Integrity and legacy LD envelope builders arrive with P1-03 (they need the danubetech stack). Not yet wired into `certify-service`. Also fixed the P0-09 interceptor constructor ambiguity that broke context boot. |
| 2026-09-18 | P0-09 Deprecation infrastructure | done | `wp/p0-09-deprecation-infra` | `@DeprecatedEndpoint` + `DeprecationInterceptor`: RFC 9745 `Deprecation`, RFC 8594 `Sunset`, `Link rel=deprecation/successor-version`, Micrometer `certify.deprecated.calls{endpoint,enabled}`, hourly log throttle, kill switch `mosip.certify.deprecated.<name>.enabled=false` answering 410 JSON; OpenAPI `deprecated` flag when springdoc is present. No endpoint annotated yet. |
| 2026-09-18 | P0-06 ArchUnit rules | done | `wp/p0-06-archunit-rules` | Six frozen rules; store holds 246 `io.mosip.kernel` references outside a provider module, 5 Spring Web uses in `certify-core`, 4 repository reads in the template engine; controllers and VCFormats rules currently clean (VCFormats constants are inlined by javac, so that rule bites only after P1) |
| 2026-09-18 | Baseline | done | `design/extensibility` | Existing suite on JDK 21: 858 tests, 0 failures, 1 skipped, BUILD SUCCESS. Build needs `JAVA_HOME` on JDK 21, `-Dgpg.skip=true`, and locally `.mvn/settings-local.xml` because JitPack hangs on missing coordinates; see CLAUDE.md |

## Findings about the existing test suite ("trust but verify")

- `CertifyApplicationTests.test()` boots the application a second time by calling `CertifyServiceApplication.main()` inside a `@SpringBootTest`; it asserts only that the class is not null.
- Controller tests are `@WebMvcTest` with mocked services; no test exercises an end-to-end issuance through the real signing path.
- Repository tests run on H2 with `schema.sql`, not on the PostgreSQL DDL under `db_scripts` (JSONB, `TEXT[]`, enum and partial indexes are never exercised).
