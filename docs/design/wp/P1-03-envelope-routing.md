# P1-03 Route the signing paths through certify-signing (first slice: the golden-guarded paths)

Branch: `wp/p1-03-envelope-routing` off `design/extensibility`. Phase 1 (extraction). Size: L, delivered in slices. Depends on: P0-03, P1-02.

## Goal

Signing code in `certify-service` stops calling kernel-keymanager DTOs and instead asks the `KeyProviderRegistry` for the provider a `KeyRef` names and hands the bytes to the `certify-signing` envelope builders, so a configuration can point at any `KeyProvider` and the output stays verifiable by third parties.

## Slice 1 (this branch): paths locked by goldens with independent verification

| Path | Before | After | Guard |
| --- | --- | --- | --- |
| `Ed25519Signature2020ProofGenerator` | `signv2` base58btc | `LdLegacyEnvelope.proofValueBase58` over `signRaw` | golden + danubetech `Ed25519Signature2020LdVerifier` |
| `EcdsaSecp256r1Signature2019ProofGenerator` | `signv2` base58btc | same, ES256 | unit test verified with JCA (no golden yet; identical code path) |
| `RSASignature2018ProofGenerator` | `jwsSign` detached, `b64=false`, `x5t#S256` | `LdLegacyEnvelope.detachedJws` (`JwsEnvelope`, RFC 7797, `kid`, `x5t#S256`) | golden + danubetech `RsaSignature2018LdVerifier` |
| `W3CJsonLD` Data Integrity branch (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`) | `KeymanagerByteSigner` over `signv2` | `SignerByteSigner` over `signRaw` | golden + danubetech `DataIntegrityProofLdVerifier` |
| `SDJWT.addProof` | `jwsSignV2` (`typ`, `kid`, `x5c`, `x5t#S256`) | `JwsEnvelope.sign` with `JwsHeaderPolicy.sdJwtVc()` | golden + Nimbus against `jwks.json` |

Also: `JwsEnvelope` now assembles the RFC 7797 signing input as bytes (a binary hash as unencoded payload was going through a UTF-8 String); `LegacyKeyRefs.keymanager(appId, refId)` maps today's `credential_config` key columns to `keymanager:APPID/REFID`; `SigningBeans` exposes the `KeyProviderRegistry`; `certify-signing` gained `ld-signatures-java`, `data-integrity-java` and `java-multibase`; `KeymanagerByteSigner` and its factory are deleted.

Tests replaced, not adapted: the previous generator and SD-JWT tests asserted that a mocked keymanager response was passed through; the new ones sign with a generated key and verify the proof with plain JCA or Nimbus (`TestKeyProviders`).

## Slice 2 (branch `wp/p1-03-envelope-routing-2`): the JWS paths, after their goldens landed in P0-03 slice 2

| Path | Before | After | Guard |
| --- | --- | --- | --- |
| `Ed25519Signature2018ProofGenerator` | `jwsSign` detached EdDSA | `LdLegacyEnvelope.detachedJws` | golden + danubetech `Ed25519Signature2018LdVerifier` |
| `EcdsaSecp256k1Signature2019ProofGenerator` | `jwsSign` detached ES256K | same | golden + danubetech verifier over JCA |
| `EcdsaKoblitzSignature2016ProofGenerator` | `jwsSign` detached ES256K | same | unit test verified with JCA (same code path; no golden, the suite has no registered context in the static loader) |
| `AccessTokenJwtUtil` | `jwsSign` RS256 with `CERTIFY_SERVICE` | `JwsEnvelope.sign` compact (`alg`, `kid`) | pre-authorized-code golden: token verified with Nimbus against `jwks.json`; header golden `alg`+`kid` |

## Slice 3 (branch `wp/p1-03-envelope-routing-3`): mDoc IssuerAuth

| Path | Before | After | Guard |
| --- | --- | --- | --- |
| `MDocProcessor.signMSO` | keymanager `coseSign1` (alg protected, x5chain unprotected via `includeCertificate`, untagged, hex out) | `CoseEnvelope.sign1` with `CoseHeaderPolicy.mdocIssuerAuth()` | mDoc golden (IssuerAuth verified with JCA against the x5chain leaf; MSO summary golden records the header layout) plus JCA-verified unit tests |

## Slice 4 (branch `wp/p1-03-envelope-routing-4`): claim-169 CWT

| Path | Before | After | Guard |
| --- | --- | --- | --- |
| `Credential.signQRData` | keymanager `cwtSign` (kid protected, no chain, tag 18 in tag 61, `exp`/`nbf`/`iat` from keymanager defaults, claim 169 = `bstr .cbor` of the PixelPass CBOR, hex out) | `CwtEnvelope.sign` with `CoseHeaderPolicy.cwt()` (kid in the protected header, no chain) and `CwtSigningProperties` (`certify.signing.cwt.exp-days` 180, `nbf-days` 0) | claim-169 golden (CWT verified with JCA against the JWKS key named by kid; summary golden records the header and claim labels) plus a JCA-verified unit test |

`CoseHeaderPolicy` gained `kidInProtected`; including the certificate chain in the CWT stays a change for the new surface (decision log).

## Open

`Credential.addProof` (`vc` format, abstract default with no live caller) and the `Credential` constructor still take keymanager's `SignatureService`; they go with the formatter extraction (P1-05/P1-13). `SystemInfoController` keeps `KeymanagerService` (certificate upload and CSR are keymanager administration). `JwksServiceImpl` and `DIDDocumentUtil` move to `KeyPublisher` in P1-04; `SystemInfoController` keeps `KeymanagerService` (certificate upload and CSR are keymanager administration).

## Acceptance criteria (slice 1)

- [x] `IssuanceGoldenTest` unchanged and green (all four signing paths verified independently).
- [x] Unit tests for the three generators, `SDJWT`, `W3CJsonLD` verify real signatures.
- [x] ArchUnit: `io.mosip.kernel` store shrinks again; no rule regressed.
- [x] Full `certify-service` suite green: 881 tests, 0 failures, 1 skipped.
