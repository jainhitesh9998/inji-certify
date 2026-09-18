# P1-01 certify-spi and the protocol-agnostic issuance core

Branch: `wp/p1-01-spi-and-issuance-core` off `design/extensibility`. Phase 1 (extraction). Size: L. Depends on: P0-10, P0-08.

## Goal

Give every protocol adapter, the CLI and the Phase 1 formatters one entry point (`IssuanceService.issue(IssuanceCommand)`) and one set of extension points, with no reference to Spring Web, JPA, Velocity or keymanager.

## Scope

- New module `certify-spi` (package `io.mosip.certify.spi`): `CredentialConfiguration` (tenant, id, scope, format, `FormatConfig`, `TemplateRef`, `SigningConfig`, `IssuanceStrategy` TEMPLATE/EXTERNAL/SUPPLIED, `StatusConfig`, `DisplayConfig`, protocol overrides), `IssuanceContext`, `Authorization`, `HolderBinding`, `ClaimSet`, `UnsignedCredential`, `IssuedCredential`, `SigningContext`, `TenantContext`/`TenantResolver`, `ProtocolVersion`, and the interfaces `CredentialFormatter`, `CredentialDataSource`, `ExternalIssuer`, `ProofValidator`, `StatusProvider`, `TemplateEngine`, `IssuanceListener` with their checked exceptions.
- New module `certify-issuance` (package `io.mosip.certify.issuance`): `IssuanceCommand` (id or draft-13 `ConfigurationSelector`, proofs, `ProofPolicy`, `NonceCheck`, supplied document, protocol params), sealed `IssuanceResult` (`Issued`/`Deferred`), `IssuanceException` with protocol-agnostic error codes, `ConfigurationRegistry` (+ `InMemoryConfigurationRegistry`), `FormatterRegistry`, `KeyProviderRegistry`, `AuthorizationPolicy` (`SCOPE` default), `DefaultIssuanceService`.
- The flow of `05-target-architecture.md`: resolve → authorize → validate proofs into holder bindings (one credential per valid proof; a nonce failure wins over other proof failures) → fetch/render or supplied or external → formatter `build` → `StatusProvider.attach` → `IssuanceListener.beforeSign` → `formatter.sign` through the `KeyProviderRegistry` → `onIssued`; every failure after configuration resolution reaches `onFailed`.
- Not wired into `certify-service` yet; today's `*IssuanceServiceImpl` keep serving until P1-13.

## Acceptance criteria

- [x] `mvn -pl certify-spi,certify-issuance test` green: 23 component tests with fakes for every SPI and the real `JcaKeyProvider`; the produced JWS verifies with Nimbus.
- [x] ArchUnit: `io.mosip.certify.spi`, `..issuance`, `..signing` depend on none of Spring, servlet, JPA, Velocity, `io.mosip.kernel`, `certify-core`.
- [x] Zero wire-byte change: `certify-service` untouched; goldens unchanged.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
