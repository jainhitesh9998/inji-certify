# P1-04 KeyPublisher behind jwks.json and did.json

Branch: `wp/p1-04-key-publisher` off `design/extensibility`. Phase 1 (extraction). Size: M. Depends on: P1-02, P1-03.

## Goal

The two documents that publish issuer keys stop reading kernel-keymanager DTOs and describe whatever `KeyProvider`s are registered, so a key added through another provider is published the same way.

## Scope

- `certify-signing`: `KeyProvider.publicKeys(KeyRef)` (every key an alias has had, current one included, so rotated-out keys stay resolvable; default = the current key), implemented in `KeymanagerKeyProvider` from all certificates of the alias.
- `SigningBeans`: a `KeyPublisher` bean over every `KeyProvider`.
- `JwksServiceImpl`: JWKS from `KeyPublisher.descriptors(KeyFilter.validNow())`; the field set per key is exactly what the keymanager-backed code produced (`kid`, `kty`, `use`, `exp`, `x5c`, `x5t#S256`, `e`/`n` or `x`/`y`/`crv`, no `alg`); `use` from the certificate's KeyUsage as before, `sig` for Ed25519 and certificate-less keys.
- `DIDDocumentUtil`: verification methods from `KeyProvider.publicKeys(ref)` per `credential_config` key column pair; `getCertificateDataResponseDto` (the `kid` for LD proofs) from `resolve(ref)`; the Ed25519 method takes the raw key from the SubjectPublicKeyInfo instead of casting to a BouncyCastle class, so keys from any JCA provider work.
- Goldens recorded first: `v1/well-known/jwks.json` and `v1/well-known/did.json` (key material masked, since the test keystore regenerates VC keys per run); every credential golden verifies against these documents.

## Acceptance criteria

- [x] `jwks.json` and `did.json` goldens unchanged after the switch; all credential goldens still verify against them.
- [x] `KeymanagerKeyProviderWiringTest`: provider kids == JWKS kids on the real service.
- [x] Unit tests for `JwksServiceImpl` (field sets, expiry filtering, certificate-less keys, aggregation across providers) and `DIDDocumentUtil` against a fake provider.
- [x] ArchUnit kernel store shrinks; `JwksServiceImpl` and `DIDDocumentUtil` import no `io.mosip.kernel` type.
- [x] Full `certify-service` suite green: 877 tests.

## Notes

- JWKS key order changes from "mapper aliases then CERTIFY_SERVICE" to the provider's alias order (CERTIFY_SERVICE first); RFC 7517 gives the array no order semantics and the goldens sort object arrays.
- Only `SystemInfoController` (certificate upload, CSR: keymanager administration) and `Credential.signQRData` / `Credential.addProof` still reference `io.mosip.kernel` outside the provider module.
