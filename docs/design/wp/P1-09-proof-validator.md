# P1-09 ProofValidator (first slice): jwt proofs through the SPI

Branch: `wp/p1-09-proof-validator` off `design/extensibility`. Phase 1. Size: S. Depends on: P1-01.

## Goal

The new core validates holder proofs through `io.mosip.certify.spi.ProofValidator` and gets a `HolderBinding` back; the checks stay the ones today's `JwtProofValidator` applies, so both surfaces accept exactly the same proofs.

## Scope (this slice)

- `JwtProofValidatorAdapter` (`proofType = jwt`, Spring bean) over the legacy `JwtProofValidator`: the adapter's `NonceCheck` is consulted with the proof's `nonce` first (the legacy validator then compares the same value), `ProofPolicy.allowedAlgorithms` becomes the legacy `proof_signing_alg_values_supported`, `ProofPolicy.clientId` the legacy `iss` expectation; the holder is the `did:jwk`/`did:key` the legacy key managers derive.
- Error detail the legacy boolean hides is reported by name on the new surface: `proof_header_invalid_typ`, `proof_header_invalid_alg` (checked in the adapter before delegating), `invalid_nonce`, `invalid_proof`, `proof_header_invalid_key`.
- Not changed: the legacy `ProofValidatorFactory` path used by `CertifyIssuanceServiceImpl`; the audience the legacy validator expects is still `mosip.certify.identifier` (`ProofPolicy.audience` is recorded but not yet enforced separately, see finding on the dual identity keys).

## Not in this slice

`cwt`/`ldp_vc` proof types, `HolderKeyResolver` implementations per DID method, DPoP-bound proofs, and wiring `DefaultIssuanceService` into the HTTP surface (P1-11).

## Acceptance criteria

- [x] `JwtProofValidatorAdapterTest`: real ES256 proofs as a wallet builds them; holder returned as `did:jwk` carrying the proof key; nonce store consulted and its rejection wins; missing nonce, wrong typ, disallowed alg, wrong audience and non-JWT input each yield the named error.
- [x] Goldens and ArchUnit unchanged.
- [x] Full `certify-service` suite green: 884 tests.
