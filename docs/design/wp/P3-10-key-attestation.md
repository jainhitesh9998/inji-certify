# P3-10 Key attestations: `key_attestation` on `jwt` proofs and the `attestation` proof type

Branch: `wp/p3-10-key-attestation` off `design/extensibility`. Phase 3. Size: M. Depends on: P3-03 (nonces, batch size), P3-06 (attester configuration pattern).

## Goal

Item 6 of docs/design/17-conformance-gaps.md: OpenID4VCI 1.0 Appendix D (key attestations in JWT format) and Appendix F (`key_attestation` in the `jwt` proof header, the `attestation` proof type) on the new surface, so a HAIP configuration can require attested wallet keys and the conformance suite's optional key attestation tests pass.

## Spec rules implemented

- Appendix D.1: `typ key-attestation+jwt`; `alg` asymmetric and, when the configuration has metadata, one of `proof_signing_alg_values_supported` of the proof type it arrives with; `iat` required and not in the future; `exp` optional, required with the `jwt` proof type, not in the past; `attested_keys` a non-empty array of public JWKs; `key_storage` and `user_authentication` optional non-empty arrays of attack potential resistance values (D.2); `nonce` optional; signed by an attester the deployment trusts.
- Appendix F.1: a `jwt` proof may carry `key_attestation`; the proof key (`jwk` or `kid`, resolved as today) must be in `attested_keys`; when a `c_nonce` was provided the attestation's `nonce` must be it; one credential is issued per attested key (the SHOULD), the proof's key first.
- Appendix F.3: `proofs.attestation` is a list of key attestations; when the issuer has a nonce endpoint the `nonce` must be the `c_nonce` (missing: `invalid_nonce`); one credential per attested key.
- Metadata: `proof_types_supported.<type>.key_attestations_required` with optional `key_storage` and `user_authentication` lists of accepted values; present (even empty) means an attestation is required for that proof type; the attestation must assert at least one accepted value per listed member.
- Errors: `invalid_proof` for every attestation failure, `invalid_nonce` for a missing or wrong nonce, `invalid_credential_request` when the attested keys exceed `batch_size`.

## Scope

- `KeyAttestationValidator` (`io.mosip.certify.proof`): parses and verifies one key attestation against `certify.protocol.oid4vci-v1.key-attestation.attesters.<id>` (`jwks`: a JWK Set the signing key is in, matched by `kid` when both carry one; `trust-anchor`: PEM certificates an `x5c` chain validates to with PKIX, revocation off, the anchor itself excluded from the path), with `clock-skew` (default 60 s) on `iat` and `exp`.
- `JwtProofValidatorAdapter`: after the legacy checks, reads `key_attestation` from the header; refuses its absence when the configuration requires one; validates it (exp required), checks the nonce and that the proof key is attested; returns the proof's holder plus one `did:jwk` holder per other attested key through the new `ProofValidator.validateAll`.
- `KeyAttestationProofValidator`: the `attestation` proof type; enabled per configuration by an `attestation` entry in `proof_types_supported`.
- `certify-spi`: `ProofValidator.validateAll` (default: the single binding). `certify-issuance`: `IssuanceCommand.maxCredentials` (0 = no cap) enforced in `DefaultIssuanceService.holders` after expansion; `holders` collects `validateAll`.
- `Oid4vciCredentialController`: the policy's `extra` carries the configuration's raw `proof_types_supported` (both validators read their own entry); `maxCredentials(batch_size)`.
- `ProofType.ATTESTATION` in `certify-core` so the request DTO accepts `proofs.attestation`; the compatibility surfaces answer `unsupported_proof_type` for it, as for any type they do not know.
- `Oid4vciProperties.KeyAttestation(attesters, clockSkew)` and `Attester(jwks, trustAnchor)`; on the owner's remark `Oid4vciV1Properties` is renamed `Oid4vciProperties` (the prefix `certify.protocol.oid4vci-v1` is unchanged).
- Tests: `KeyAttestationTest` (end to end on `/oid4vci/credential`: required attestation missing, valid attestation with two keys yields two credentials, unattested proof key, unknown attester, key storage below the accepted values, nonce mismatch, `attestation` proof with two keys and the consumed nonce, missing nonce, eleven keys against `batch_size` 10, metadata); `KeyAttestationValidatorTest` (typ, alg, signer, expiry, exp optional for the attestation type, accepted values, empty or private `attested_keys`, `x5c` to a PEM anchor and a self-signed chain refused).

## Outside scope

OpenID Federation `trust_chain`; `status` of a key attestation (Token Status List of the attestation); the same-key deduplication across several proofs of one request; key attestations on the compatibility and draft-13 surfaces; the wallet side (`certify-cli` does not mint attestations).

## Acceptance criteria

- [x] `KeyAttestationTest`, `KeyAttestationValidatorTest`, `JwtProofValidatorAdapterTest`, `IssuanceGoldenTest`, `Oid4vciNonceBatchTest` green; no golden changed (proofs without attestations behave as before).
- [x] Full `certify-service` suite green (1030, reverse order); CI: the integration-branch run after merge.
- [x] Decision row (attester trust, one credential per attested key, new surface only) in `12-risks-and-decisions.md`; release note; `17-conformance-gaps.md` item 6 marked done.
