# P1-14 certify-cli (first cut): keys and envelopes from the command line

Branch: `wp/p1-14-cli` off `design/extensibility`. Phase 1. Size: S. Depends on: P0-10.

## Goal

Signing without the service: the same `certify-signing` envelopes and the `jca` provider over a PKCS#12 file, for issuers who script signing, for test fixtures, and for verifying that a key set works before deploying it.

## Scope (this cut)

- Module `certify-cli` (picocli, shaded `target/certify-cli.jar`, main class `io.mosip.certify.cli.CertifyCli`).
- `keys generate --keystore f.p12 --password pw --alias a --alg ES256|ES256K|EdDSA|RS256|PS256 [--subject DN]` (self-signed certificate, kid = alias), `keys list`, `keys jwks` (RFC 7517 JWK Set with `x5c`).
- `sign jws --key a [--alg PS256] [--typ JWT] [--x5c] [--x5t] [--kid PROVIDER|JWK_THUMBPRINT|X5T_S256|NONE] [--detached] --in payload [--out file]`: compact JWS through `JwsEnvelope`, including the RFC 7797 detached form the Linked Data JWS suites use.
- `sign cose --key a [--tagged] [--kid] --in payload --out file`: COSE_Sign1 through `CoseEnvelope` (alg protected, `x5chain` unprotected; tag 18 optional), the ISO 18013-5 IssuerAuth layout.
- Password prompted when `-p` is given without a value.

## Not in this cut

`issue`, `batch`, `verify`, Data Integrity / legacy LD proofs (they need the JSON-LD stack and a document loader; arrive with the `ldp_vc` formatter module), the keymanager provider (needs the database), PEM key files (P3 `x509-file`).

## Acceptance criteria

- [x] In-process tests drive every command; each signature is verified with Nimbus or plain JCA, the JWKS is parsed by Nimbus, the COSE_Sign1 checked structurally and verified against the embedded certificate.
- [x] Shaded jar runs (`java -jar certify-cli/target/certify-cli.jar keys generate ...`).
- [ ] Jar size: 53 MB because `certify-signing` carries the JSON-LD stack for the LD envelopes; split `certify-signing-ld` out when the `ldp_vc` formatter lands.
