# P1-05 certify-format-ldp-vc

Branch: `wp/p1-05-ldp-vc-formatter` off `design/extensibility`. Phase 1. Size: M. Depends on: P1-01, P1-03.

## Goal

The first `CredentialFormatter` module: `ldp_vc` documents get their proof from `certify-signing` through the `SigningContext` the core resolves, with the same suites the legacy path issues, verified by libraries Certify does not write.

## Scope

- Module `certify-format-ldp-vc`: `LdpVcFormatter` (`formatId = ldp_vc`): `build` takes the rendered document as the credential; `sign` adds a Data Integrity proof for a registered cryptosuite (`eddsa-rdfc-2022`, `ecdsa-rdfc-2019`, ...; danubetech `LdSigner` over `SignerByteSigner`) or a legacy Linked Data proof for a suite name (`Ed25519Signature2020`, `EcdsaSecp256r1Signature2019` as `proofValue`; `RsaSignature2018`, `Ed25519Signature2018`, `EcdsaSecp256k1Signature2019`, `EcdsaKoblitzSignature2016` as detached JWS; URDNA2015 canonicalization through `LdLegacyEnvelope`). `verificationMethod` = issuer DID `#` kid; `created` = the credential's `issuanceDate`/`validFrom` read as UTC (the legacy path parses it in the JVM's zone, see findings), else the issuance instant; `metadataFragment` = `format` + `credential_definition`.
- `LdpVcAutoConfiguration` over the application's JSON-LD `DocumentLoader` bean (`StaticContextLoader` in certify-service); `certify-service` depends on the module so the bean exists for the coming `/oid4vci` adapter.

## Acceptance criteria

- [x] `LdpVcFormatterTest`: Ed25519Signature2020, RsaSignature2018, EcdsaSecp256k1Signature2019 verified by danubetech's LD verifiers, eddsa-rdfc-2022 by `DataIntegrityProofLdVerifier`, all against `JcaKeyProvider` dev keys; metadata fragment; unknown/missing suite refused.
- [x] The formatter bean exists in the real service context (`IssuanceGoldenTest`).
- [x] Goldens unchanged; full `certify-service` suite green: 889 tests.
