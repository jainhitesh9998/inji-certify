# P0-03 Signature vectors for the seven signing paths

Branch: `wp/p0-03-signature-vectors` off `develop`. Phase 0 (guardrails). Size: M. Depends on: none.

## Goal

Lock the bytes keymanager produces on each signing path so Phase 1 can route them through envelope builders without changing output.

## Scope

- Fixed inputs (documents, claims, MSO, claim-169 payload, access-token claims) and the local keystore (`sample-keystore/test.p12`, SoftHSM config from `application-local.properties`).
- One vector per path: legacy LD JWS suites (4), legacy LD multibase suites (2), Data Integrity (4 cryptosuites), SD-JWT `jwsSignV2`, mDoc `coseSign1`, claim-169 `cwtSign`, access-token `jwsSign`.
- Comparison rule per algorithm: EdDSA and RSA PKCS#1 by bytes; ECDSA by verification with the public key plus header/structure equality; store both the raw output and the parsed header.
- A `SignatureVectorTest` that runs against the same keystore in CI.

## Acceptance criteria

- [x] Vectors are the goldens of `IssuanceGoldenTest`, each verified by an independent library: Ed25519Signature2020, Ed25519Signature2018, RsaSignature2018, EcdsaSecp256k1Signature2019 (danubetech), eddsa-rdfc-2022 (danubetech Data Integrity), SD-JWT ES256 and the pre-authorized-code access token (Nimbus against `jwks.json`), EcdsaSecp256r1Signature2019 (danubetech canonicalization + JCA; no third-party verifier exists, see PROGRESS findings).
- [x] mDoc `coseSign1`: IssuerAuth verified with JCA against the `x5chain` leaf, MSO structure and device key checked (`mdocIssuanceGoldenAndIndependentVerification`).
- [x] Claim-169 `cwtSign`: CWT decoded from the PixelPass string, verified with JCA against the JWKS key named by `kid` (`claim169QrGoldenAndIndependentVerification`).
- [ ] Remaining: `Credential.addProof` (`vc`, no caller found besides the abstract default), the other Data Integrity cryptosuites (`ecdsa-rdfc-2019`, `ecdsa-jcs-2019`, `eddsa-jcs-2022`).
- [x] Each golden names the test method that produced it (file name = test).

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
