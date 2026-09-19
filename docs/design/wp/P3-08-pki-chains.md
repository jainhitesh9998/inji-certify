# P3-08 X.509 chains for SD-JWT VC and mDoc

Branch: `wp/p3-08-pki-chains` off `design/extensibility`. Phase 3 (PKI, docs/design/06a). Size: M. Depends on: P3-01 (x509-file provider), P2-06 (v2 configuration API).

## Goal

Item 4 of docs/design/17-conformance-gaps.md: the conformance suite verifies SD-JWT VC and mDoc against a trust anchor the tester uploads; HAIP forbids a self-signed signing certificate and the anchor inside `x5c`. Today the x509-file provider generates self-signed keys and the formatters always send the whole chain.

## Scope

- `x509-file` dev mode generates a CA (`certify.keyprovider.x509-file.ca-alias`, default `dev-ca`, subject `ca-subject`) once and signs every generated key with it, so a key's chain is `[leaf, ca]` (`JcaKeyProvider.generateCa`, `generateSignedBy`, `DevKeys`). Existing keystores are untouched; the CA certificate is what the tester uploads: `keytool -exportcert -rfc -keystore <path> -alias dev-ca`.
- `JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR` and `CertificateChain.withoutAnchor()`: every certificate but a self-signed root; `JwsEnvelope` and `CoseEnvelope` honour it.
- `signing_config.x5c` (`full`, `leaf`, `without-anchor`, `none`) on a configuration, written through the v2 API (`signing.x5c`), read by the registry into the `SigningConfig` header policies; the SD-JWT and mDoc formatters apply the configured inclusion and keep their defaults otherwise, so today's keymanager output is unchanged.
- `CertificateChainPolicy` (`certify-signing`): every certificate valid at signing time and signed by the next; run by the SD-JWT and mDoc formatters before signing, refusing with `certificate_chain_invalid`.
- Tests: `DevChainTest` (jca), `X509FileKeyProvidersTest` (constructor), `PkiSdJwtIssuanceTest` (an SD-JWT VC under the dev CA with a one-certificate `x5c` that chains to the CA in the keystore and verifies with the leaf key).

- Finding fixed on the way: `certify-service` never depended on `certify-keyprovider-x509-file`, so the provider's auto-configuration could not load in the service and P3-01's "joins the registry" held only in the module's own tests. The service now ships the module (compile scope).

## Outside scope

Keymanager CSR-based chains, operator-supplied PKCS#12 chains (they already work through `x509-file` without dev mode), trust-anchor publication over HTTP, the `mso_mdoc` end-to-end test under the dev CA (same code path; covered by the COSE unit tests), IACA/DSC profile checks of ISO 18013-5 Annex B.

## Acceptance criteria

- [x] `DevChainTest`, `X509FileKeyProvidersTest`, `PkiSdJwtIssuanceTest`, `IssuanceGoldenTest`, `D13GoldenReplayTest` green; no golden changed.
- [x] Full `certify-service` suite green (993 tests, 0 failures); CI pending.
