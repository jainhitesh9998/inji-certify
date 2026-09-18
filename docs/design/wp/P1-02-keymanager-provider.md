# P1-02 certify-keyprovider-keymanager: kernel-keymanager as the default KeyProvider

Branch: `wp/p1-02-keymanager-provider` off `design/extensibility`. Phase 1 (extraction). Size: M. Depends on: P0-10, P1-01.

## Goal

Make MOSIP kernel-keymanager one `KeyProvider` among possible others while keeping it the embedded default: the module owns every `io.mosip.kernel` reference that is not a signing call site (those move in P1-03), the JPA wiring of `key_alias`/`key_store`/`key_policy_def`, and the startup key provisioning.

## Scope

- New module `certify-keyprovider-keymanager` (package `io.mosip.certify.keyprovider.keymanager`):
  - `KeymanagerKeyProvider` (`id = keymanager`): `resolve` reads `KeymanagerService.getAllCertificates(appId, refId)` and picks the latest-expiring certificate valid now (or the one pinned by `KeyRef.version`, which is keymanager's key id = certificate thumbprint); `publicKeys` lists the aliases named in `mosip.certify.signature-algo.key-alias-mapper` plus `CERTIFY_SERVICE`; `signRaw` calls `SignatureServicev2.signv2` with `base64url` output, which is exactly the JOSE-shaped raw signature (ECDSA transcoded to concatenation by keymanager, Ed25519 raw, RSA PKCS#1 v1.5 or PSS); `ensureKeys` reproduces the historical `initKeys` calls (`generateMasterKey("certificate")` for RSA; master key then `generateECSignKey` for EC and Ed25519). Certificates are cached for `certify.keyprovider.keymanager.certificate-cache-ttl` (typed `KeymanagerProviderProperties`, default 60 s).
  - `KeymanagerAlias`: `KeyRef` alias grammar `APPID` or `APPID/REFID`, e.g. `keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN`.
  - `KeymanagerKeyInitializer` (`ApplicationRunner`): the master keys (ROOT, CERTIFY_SERVICE, its cache secret, CERTIFY_PARTNER) always; in `DataProvider` plugin mode the four historical signing keys plus any further alias the key-alias-mapper names for an algorithm keymanager can generate.
  - `KeymanagerKeyProviderConfiguration`: a Spring Boot auto-configuration (`META-INF/spring/...AutoConfiguration.imports`) carrying the kernel component scan (the exact list `CertifyServiceApplication` carried), `@EnableJpaRepositories`/`@EntityScan` for the kernel packages, and the two beans above. Auto-configuration rather than `@Import` because `@WebMvcTest`/`@DataJpaTest` slices apply their filters to component scans and auto-configurations but not to `@Import`s on the application class; the first attempt with `@Import` broke 66 slice tests with "No bean named 'entityManagerFactory'".
- `certify-service`: `CertifyServiceApplication` no longer scans kernel packages; `AppConfig` keeps only the Certify/verify JPA wiring and its three beans; `initKeys` is gone.
- `certify-signing`: `SigningKey.withAlgorithm` (PS256 over an RSA key); `KeyProviderRegistry.signingContext` applies `SigningConfig.algorithm`.
- Not in scope: the signing call sites in `credential/`, `proofgenerators/`, `utils/`, `services/JwksServiceImpl`, `controller/SystemInfoController` (P1-03, P1-04); a switch to run without keymanager (only meaningful once those call sites are gone, P1-13).

## Acceptance criteria

- [x] Module tests: 16 (JWS through a keymanager stand-in that reproduces keymanager's encoding, verified with Nimbus for EdDSA, ES256, ES256K, RS256, PS256; certificate selection, pinning, caching, `ensureKeys` call sequence, initializer ordering and mapper handling).
- [x] `KeymanagerKeyProviderWiringTest` boots the real service on H2 + PKCS#12: the four provisioned keys sign JWS that verify with Nimbus, and the provider publishes exactly the key ids `/.well-known/jwks.json` publishes.
- [x] Zero wire-byte change: `IssuanceGoldenTest` unchanged and green.
- [x] ArchUnit frozen store for `io.mosip.kernel` shrinks (39 references left `certify-service` wiring classes); no rule regressed.
- [x] Full `certify-service` suite green: 893 tests, 0 failures, 1 skipped.

## Rules that apply

- Keymanager stays an embedded library; nothing here makes a remote call.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/06-signing-extensibility.md`.
