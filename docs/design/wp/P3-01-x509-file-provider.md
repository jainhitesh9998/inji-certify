# P3-01 certify-keyprovider-x509-file

Branch: `wp/p3-01-x509-file-provider` off `design/extensibility`. Phase 3 (pulled forward). Size: S. Depends on: P0-10, P1-02, P1-11a.

## Goal

The first key provider next to keymanager: a PKCS#12 file with X.509 certificates, for issuers with their own PKI (mDoc DSCs, SD-JWT `x5c`) or without keymanager tables, and a dev mode that generates the keys at startup (decision of 2026-09-18).

## Scope

- Module `certify-keyprovider-x509-file`: `X509FileProperties` (`certify.keyprovider.x509-file.enabled|id|path|password|dev-mode|keys[alias,algorithm,subject]|purpose`), `X509FileKeyProviders.open` (loads the file; in dev mode generates the listed keys with self-signed certificates and writes the file; in production refuses a missing file or missing keys), `X509FileAutoConfiguration` behind `enabled=true` (off by default, so nothing changes for existing deployments).
- `JcaKeyProvider.fromPkcs12(id, path, password)`: the same keystore under another provider id.
- `JpaConfigurationRegistry`: a `key_manager_app_id` written as `provider:alias[@version]` (e.g. `x509-file:issuer-es256`) selects that provider on the new surface; plain values stay keymanager's. The legacy path ignores the prefix (it always calls keymanager), which is why the new surface is where other providers become usable.
- The provider joins the `KeyProviderRegistry` and `KeyPublisher`, so its certificates appear in `jwks.json` and the DID document only when enabled.

## Not in this slice

PEM key files, `CertificateChainPolicy` and trust-anchor publication (P3), `x509-pkcs11`/`x509-kms`.

## Acceptance criteria

- [x] `X509FileKeyProvidersTest`: dev mode creates the file and keys, a second start reuses them, signatures produced; production refuses missing files/keys/unknown algorithms.
- [x] `JpaConfigurationRegistryTest`: provider-prefixed key column parsed as a `KeyRef`.
- [x] Goldens and ArchUnit unchanged (provider off by default).
- [x] Full `certify-service` suite green (898 tests, 0 failures).
