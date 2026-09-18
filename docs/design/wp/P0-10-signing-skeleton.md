# P0-10 certify-signing skeleton with the jca provider and AlgorithmRegistry

Branch: `wp/p0-10-signing-skeleton` off `develop`. Phase 0 (guardrails). Size: M. Depends on: P0-03, P0-06.

## Goal

Create the seam the Phase 1 signing extraction will fill, and a provider that runs without keymanager for tests and the CLI.

## Scope

- New Maven module `certify-signing` (no Spring Web, no JPA): `KeyProvider`, `Signer`, `SigningKey`, `KeyRef`, `PublicKeyDescriptor`, `SignatureAlgorithm`, `AlgorithmRegistry` (JOSE alg, COSE int, LD suite, DI cryptosuite, JCA name, curve in one table, populated from today's three mappings), `KidStrategy`.
- `certify-keyprovider-jca`: PKCS#12/PEM backed `KeyProvider` + `Signer.signRaw` for RS256, PS256, ES256, ES256K, EdDSA; `publicKeys()` from the keystore certificates.
- Envelope builders `JwsEnvelope`, `CoseEnvelope`, `CwtEnvelope`, `DataIntegrityEnvelope`, `LdLegacyEnvelope` with unit tests against the P0-03 vectors using the jca provider (structure equality; byte equality where deterministic).
- Not wired into the service in this WP.

## Acceptance criteria

- [ ] Module builds and tests pass standalone (`mvn -pl certify-signing,certify-keyprovider-jca test`).
- [ ] ArchUnit rules for `..signing..` pass.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
