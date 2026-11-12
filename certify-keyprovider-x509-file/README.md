# certify-keyprovider-x509-file

A `KeyProvider` whose keys are in a PKCS#12 keystore: for issuers with their own PKI, for mDL Document Signers and for
SD-JWT `x5c`, with keymanager or without it. Off by default (`certify.keyprovider.x509-file.enabled=false`), so an
existing deployment is unaffected. History: [P3-01](../docs/design/wp/P3-01-x509-file-provider.md) (the provider),
[P3-08](../docs/design/wp/P3-08-pki-chains.md) (the dev CA and chains), [M-05](../docs/design/20-mdl-issuer.md)
(ISO/IEC 18013-5 Annex B, PEM import, rotation).

## Configuration

All properties are `certify.keyprovider.x509-file.*`. Nothing below is required for a deployment that only used the
provider before M-05: the first nine keys keep their meaning and defaults.

| Key | Meaning |
| --- | --- |
| `enabled` | registers the provider; default `false` |
| `id` | provider id used in key references; default `x509-file` |
| `path`, `password` | the PKCS#12 file and its password |
| `dev-mode` | generate the keys in `keys` that are missing and create the file; never in production |
| `keys[].alias` | keystore alias; `alias@version` (e.g. `mdl-dsc@2026-11`) is one version of a rotated key |
| `keys[].algorithm` | JOSE name (`ES256`, `ES384`, `ES512`, `EdDSA`, `RS256`, `PS256`) |
| `keys[].subject` | subject DN of a generated certificate; for a Document Signer its CN is the DSC common name |
| `keys[].profile` | `plain` (default) or `mdoc-dsc` (ISO/IEC 18013-5 Annex B) |
| `keys[].validity-days` | certificate lifetime of a generated key; the Annex B maximum is 457 days for a DSC |
| `purpose` | purpose recorded for plain keys; default `vc-signing` |
| `ca-alias`, `ca-subject` | the dev CA that signs plain generated keys; default `dev-ca`, `CN=Inji Certify Dev CA` |
| `iaca.alias` | keystore alias of the Annex B IACA; default `iaca` |
| `iaca.country`, `.state`, `.common-name` | IACA subject; country is ISO 3166-1 alpha-2, state optional |
| `iaca.issuer-alt-name` | issuerAltName: a URI (`https://…`, `mailto:…`) or an email address |
| `iaca.crl-uri` | CRL distribution point of the IACA, an absolute http(s) URI; a DSC copies it |
| `iaca.validity-years` | IACA lifetime; omitted is the 20-year Annex B maximum |
| `iaca.algorithm` | IACA key/signature algorithm; Annex B allows `ES256`, `ES384`, `ES512`; default `ES256` |
| `pem-keys[].alias` | key alias, optionally `alias@version` |
| `pem-keys[].key` | PEM private key file (PKCS#8 or SEC1/RSA), plaintext or encrypted |
| `pem-keys[].key-password` | password of an encrypted key; omitted for a plaintext one |
| `pem-keys[].chain` | PEM certificate chain file, **leaf first**: `[DSC, IACA]` |

## Dev mode: the P3-08 dev CA, unchanged

Without `iaca` and without `profile: mdoc-dsc`, dev mode behaves exactly as P3-08: the missing keys are generated with
self-signed leaves signed by a dev CA stored under `ca-alias`, the keystore is written once and reused, and a plain key's
chain is `[leaf, dev-ca]`. The dev CA is not an IACA and is never published as one.

## Dev mode: an Annex B IACA and Document Signers

Set the `iaca` block and give the mDL key `profile: mdoc-dsc`:

```yaml
certify:
  keyprovider:
    x509-file:
      enabled: true
      path: /keys/issuer.p12
      password: ${X509_FILE_PASSWORD}
      dev-mode: true
      iaca:
        country: IN
        state: Karnataka
        common-name: Lorem Ipsum Demo IACA
        issuer-alt-name: https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca
        crl-uri: https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/lorem-ipsum-demo-iaca.crl
      keys:
        - alias: mdl-dsc@2026-11
          algorithm: ES256
          subject: CN=Lorem Ipsum Demo DSC
          profile: mdoc-dsc
          validity-days: 400
        - alias: issuer-es256
          algorithm: ES256
          subject: CN=Inji Certify VC issuer
```

The IACA and every `mdoc-dsc` key are generated with `certify-pki` (`IsoMdocProfiles`), validated with
`AnnexBValidator` at startup, and the generated material is written to the keystore, so a restart reuses the same IACA
and DSCs. **Startup fails** when the IACA or a DSC does not meet Annex B, when a DSC's chain does not end at an IACA, or
when a key with `profile: mdoc-dsc` is configured without an `iaca` block. Country, state, issuerAltName and CRL
distribution point of a DSC come from the IACA; a DSC's chain is `[DSC, IACA]`, and `signing.x5c=without-anchor` (or the
mDoc formatter's `WITHOUT_ANCHOR` policy) drops the IACA from the header, as HAIP requires.

## Production: a Document Signer an operator holds

```yaml
      pem-keys:
        - alias: mdl-dsc@2027-02
          key: /keys/mdl-dsc-2027-02.key.pem     # optionally encrypted
          key-password: ${MDL_DSC_KEY_PASSWORD}
          chain: /keys/mdl-dsc-2027-02.chain.pem # [DSC, IACA]
```

The private key is read through `certify-pki` `Pem` (PKCS#8 PBES2, PBES1 and the traditional OpenSSL scheme, with a
warning for weak ones), and the chain is returned to the formatter as `[DSC, IACA]`. When the leaf carries the mDL
extended key usage `1.0.18013.5.1.2` the DSC is validated against its IACA (the chain's last certificate) with
`AnnexBValidator.validateDs`, the IACA itself with `validateIaca`, and startup fails on any violation; a chain with the
mDL EKU but no IACA (`DS_IACA_MISSING`) is refused too. PEM keys are not copied into the keystore, so no private key is duplicated; when all keys are PEM keys,
`path` may be omitted.

## Rotation

Every version of a key is its own entry, `mdl-dsc@2026-11`, `mdl-dsc@2027-02`, and so on (a version label is an opaque
string; the examples use the month a DSC was issued).

- `x509-file:mdl-dsc` (no version) resolves to the **newest** entry of that alias whose certificate is valid now —
  `notBefore <= now < notAfter`, the newest by `notBefore`, ties broken by the version label. An expired version is
  never chosen, so a rotation window with an old and a new DSC signs with the new one and keeps the old one verifiable.
  When an alias has a single entry and no versions, it resolves to that entry whatever its dates, exactly as before
  M-05.
- `x509-file:mdl-dsc@2027-02` (a version) resolves to that entry, valid or not, so an old DSC can still be used to
  re-sign a list it owns.
- `KeyProvider.publicKeys(KeyRef)` lists **every** version of an alias, oldest first, which is what a JWKS or a DID
  document publishes so credentials signed before a rotation keep verifying; the provider's own `kid` for each entry is
  the full alias including `@version`.

If no version of an alias is valid now, resolution fails with `No key with alias 'mdl-dsc' in provider 'x509-file'; no
version has a certificate valid now (versions: …)` rather than falling back to an expired certificate.

## Expiry visibility

`certify-service` registers `certify.signing.key.expires_in_days{keyRef="<provider>:<kid>"}` for every published
certificate (days left, recomputed per scrape, negative once expired) and logs one `WARN` at startup for each
certificate expiring within 30 days. It covers every provider, keymanager included, because the metric belongs to the
service, not to a key-provider module.

## Publishing the IACA (M-06)

`X509FileKeyProviders.iacaCertificates(provider)` returns the IACA certificates this provider can publish: the dev-mode
IACA entry and the anchor each Document Signer chain ends at (production), deduplicated by encoding. A self-signed
certificate counts only when it passes `AnnexBValidator.validateIaca`, so the P3-08 dev CA and a plain self-signed dev
key are excluded. The method serves nothing over HTTP; M-06's trust-anchor registry reads it.

## Tests

`mvn -pl certify-keyprovider-x509-file test`. The suite proves a generated IACA and DSC pass `AnnexBValidator` and
`openssl verify -x509_strict` (skipped without `openssl` locally, failing in CI), PEM import of a plaintext and an
encrypted key with a chain built by `certify-pki` in the test, refusal of a chain that violates Annex B, rotation over
an expired and a valid version, and that the P3-08 output is unchanged and not published as an IACA.
