# 18. Compatibility validation: holder key forms and issuer DID methods

What 1.0.0-beta.1 (`develop`) accepted from wallets and published as issuer identity, and the test on this branch
that proves each item still works on the new surface (`POST /oid4vci/credential`) and on the compatibility surface
(`POST /issuance/credential`). Both surfaces run the unchanged `JwtProofValidator`, `DIDjwkProofManager` and
`DIDkeysProofManager` of `develop` behind `JwtProofValidatorAdapter`; the credential's `credentialSubject.id`
(`_holderId` in templates) is the identifier the proof binds.

## Holder keys in the `jwt` proof

`HolderDidMethodsTest` issues one credential per row on each surface and checks the bound identifier.

| Wallet presents | Key, alg | Bound identifier | develop | This branch |
| --- | --- | --- | --- | --- |
| `jwk` header | P-256, ES256 | `did:jwk:<base64url(jwk)>` | yes | yes, both surfaces |
| `jwk` header | Ed25519, EdDSA | `did:jwk:...` | yes | yes |
| `jwk` header | RSA 2048, RS256 | `did:jwk:...` | yes | yes |
| `jwk` header | RSA 2048, PS256 | `did:jwk:...` | yes | yes |
| `kid: did:jwk:...#0` | P-256, ES256 | the `kid` as sent | yes | yes |
| `kid: did:key:z6Mk...` (multicodec `0xed01`) | Ed25519, EdDSA | the `kid` as sent | yes | yes |
| `kid: did:key:zDna...` (`0x1200`, sent as `0x80 0x24`) | P-256, ES256 | the `kid` as sent | yes | yes |
| `kid: did:key:zQ3s...` (`0xe701`) | secp256k1, ES256K | the `kid` as sent | yes, when `ES256K` is in `proof_signing_alg_values_supported` (the shipped defaults list RS256, PS256, ES256, EdDSA) | same |
| `kid: did:key:z4MX...` (`0x1205`, sent as `0x85 0x24`) | RSA 2048, RS256 | the `kid` as sent | decoded but never verified: the resolver built the JWK without its `kid`, so the JWS key selector answered "no matching key(s) found" and the request failed with `invalid_proof` | fixed: the RSA branch now sets `kid` like the P-256 branch; both surfaces issue |

Proof claim checks (`typ openid4vci-proof+jwt`, allowed `alg`, exactly one of `kid` or `jwk`, `aud`, `iat`,
`nonce`, optional `exp`, `iss` equal to the client id when present) are the `develop` code and stay covered by
`JwtProofValidatorTest`; the new surface adds names for the failures (`invalid_proof`, `invalid_nonce`) that the
compatibility surface reports as a plain `invalid_proof`.

Not supported on `develop` and not supported here: holders identified by `did:web`, by an `x5c` chain or by a
bare JWK thumbprint `kid`. Note that the shipped local profile advertises
`cryptographic_binding_methods_supported: [did:jwk, did:web]` for `ldp_vc` and `dc+sd-jwt` although no resolver
honours `did:web` holders; a proof with `kid: did:web:...` is rejected. Either the default should drop `did:web`
or a `did:web` `HolderKeyResolver` should be added (capability gap 6 in `04-capability-gaps.md`). Owner's call,
recorded in `12-risks-and-decisions.md`.

## Issuer identity

| Item | develop | This branch | Proof |
| --- | --- | --- | --- |
| `did:web` document at `GET /.well-known/did.json` built from the configured keys | yes | yes, plus one document per tenant host | `WellKnownControllerTest`, `IssuanceGoldenTest`, `TenancyIssuanceTest` |
| Verification method types: `Ed25519VerificationKey2020`, `Ed25519VerificationKey2018`, `RsaVerificationKey2018`, `EcdsaSecp256r1VerificationKey2019`, `EcdsaSecp256k1VerificationKey2019` with their `@context` entries | yes | yes | `DIDDocumentUtilTest` |
| `did_url` per configuration (`did:web:...`) and the `mosip.certify.data-provider-plugin.did-url` default, `verificationMethod = <did>#<kid>` | yes | yes | `IssuanceGoldenTest` (resolves the proof's `verificationMethod` in did.json and verifies with danubetech), `D13GoldenReplayTest`, `VcIssuancePluginGoldenTest` |
| Issuer signing suites: `RsaSignature2018`, `Ed25519Signature2018/2020`, `EcdsaKoblitzSignature2016`, `EcdsaSecp256k1Signature2019`, `EcdsaSecp256r1Signature2019`, `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`, `eddsa-rdfc-2022`, `eddsa-jcs-2022`; key aliases `CERTIFY_VC_SIGN_RSA`, `_ED25519`, `_EC_K1`, `_EC_R1` | yes | yes, same aliases and `kid` values | golden sets `legacy-develop`, `legacy-0.14.0` and the signature vectors (`goldens/README.md`) |
| A configuration signed by a non-keymanager provider (`x509-file:...`) next to keymanager keys | n/a | did.json lists the keymanager keys and skips the others instead of failing | `PkiSdJwtIssuanceTest` with `IssuanceGoldenTest` in CI order (fixed in P3-09) |

## How to re-run

```bash
mvn -B -pl certify-service test -Dtest=HolderDidMethodsTest,DIDkeysProofManagerTest,DIDjwkProofManagerTest,JwtProofValidatorTest,DIDDocumentUtilTest,WellKnownControllerTest
```
