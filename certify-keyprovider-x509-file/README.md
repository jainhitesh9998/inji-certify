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
| `keys[].alias` | keystore alias, **lower case**; `alias@version` (e.g. `mdl-dsc@2026-11`) is one version of a rotated key |
| `keys[].algorithm` | JOSE name (`ES256`, `ES384`, `ES512`, `EdDSA`, `RS256`, `PS256`) |
| `keys[].subject` | subject DN of a generated certificate; for a Document Signer its CN is the DSC common name |
| `keys[].profile` | `plain` (default) or `mdoc-dsc` (ISO/IEC 18013-5 Annex B); any other value is refused |
| `keys[].validity-days` | certificate lifetime of a generated key; the Annex B maximum is 457 days for a DSC |
| `purpose` | purpose recorded for plain keys; default `vc-signing` |
| `ca-alias`, `ca-subject` | the dev CA that signs plain generated keys; default `dev-ca`, `CN=Inji Certify Dev CA` |
| `iaca.alias` | keystore alias of the Annex B IACA; default `iaca` |
| `iaca.country`, `.state`, `.common-name` | IACA subject; country is ISO 3166-1 alpha-2, state optional |
| `iaca.issuer-alt-name` | issuerAltName: a URI (`https://…`, `mailto:…`) or an email address |
| `iaca.crl-uri` | CRL distribution point of the IACA, an absolute http(s) URI; a DSC copies it |
| `iaca.validity-years` | IACA lifetime; omitted is the 20-year Annex B maximum |
| `iaca.algorithm` | IACA key/signature algorithm; Annex B allows `ES256`, `ES384`, `ES512`; a generated IACA uses `ES256` when it is not set |
| `pem-keys[].alias` | key alias, optionally `alias@version` |
| `pem-keys[].key` | PEM private key file (PKCS#8 or SEC1/RSA), plaintext or encrypted |
| `pem-keys[].key-password` | password of an encrypted key; omitted for a plaintext one |
| `pem-keys[].chain` | PEM certificate chain file, **leaf first**: `[DSC, IACA]` |

Every alias (`keys[].alias`, `pem-keys[].alias`, `iaca.alias`, `ca-alias`) must be lower case, with at most one `@`:
the JDK PKCS#12 keystore lower-cases aliases when it reads them back, so `Mdl-DSC` written on the first start would be
`mdl-dsc` on the next and every key reference naming it would break. Binding refuses such an alias with the lower-case
spelling to use instead.

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
when a key with `profile: mdoc-dsc` is configured without an `iaca` block.

**Settings are compared with what the keystore holds.** A certificate cannot change in place, so every start compares
the `iaca.*` settings that are given (country, state, common-name, issuer-alt-name, crl-uri, algorithm,
validity-years) with the IACA in the keystore, and the `subject` CN, `algorithm` and `validity-days` of each `mdoc-dsc`
key with its Document Signer. A DSC whose validity was clamped to its IACA's end matches only a `validity-days` that
reaches that end: the expected end is `min(notBefore + validity-days - 1 s, IACA notAfter)`. A difference
refuses startup and names each setting: restore the settings, or rotate. The IACA is never regenerated
automatically, because verifiers already hold it as a trust anchor: to change it, set `iaca.alias` to a new alias
(`iaca-2`), and dev mode generates a new IACA under it while the old entry stays in the keystore; Document Signers
already issued keep validating against the IACA their own chain ends at, new `mdoc-dsc` keys are issued under the new
one, and `iacaCertificates` lists both. To change a Document Signer, add a new version of its alias
(`mdl-dsc@2027-02`). A setting left out is not compared, so a production IACA can be named by `iaca.alias` alone.

**Purposes after a restart.** PKCS#12 stores no purpose, so each entry's purpose is derived from its certificate on
every load: the configured `iaca.alias`, or a self-signed CA that passes `AnnexBValidator.validateIaca`, is
`mdoc-iaca`; the configured `ca-alias` (the P3-08 dev CA) is `dev-ca`; a certificate with the mDL EKU
`1.0.18013.5.1.2` is `mdoc-dsc`; anything else, including any other CA key an operator keeps in the keystore, is a
plain key with the configured `purpose` (`vc-signing`), as before M-05. An `mdoc-iaca` entry is a trust anchor and is never listed as a signing key in the
JWKS or a DID document; nothing changes for a deployment without the M-05 properties, whose dev CA is published as
before. Country, state, issuerAltName and CRL
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
warning for weak ones), and the chain is returned to the formatter as `[DSC, IACA]`. Startup fails when:

- the private key is not the key of the leaf certificate: a random challenge is signed with the key and verified with
  the leaf's public key, plaintext and encrypted keys alike;
- the chain is not leaf first with each certificate signed by the next;
- the leaf carries the mDL extended key usage `1.0.18013.5.1.2` and the chain is not exactly `[DSC, IACA]` (no IACA is
  `DS_IACA_MISSING`; Annex B has no intermediate CAs, so a longer chain is refused), or the DSC fails
  `AnnexBValidator.validateDs` against that IACA, or the IACA fails `validateIaca`;
- a PEM alias is already an alias in the keystore.

PEM keys are read after the keystore has been written, so an operator's private key is never copied into the PKCS#12
file; when all keys are PEM keys, `path` may be omitted. A `path` that is set must exist unless dev mode is on, PEM
keys or not, and dev mode refuses to generate anything (the IACA, a Document Signer, a plain key) without a `path`
to write it to, since it would generate new keys on every start.

## Rotation

Every version of a key is its own entry, `mdl-dsc@2026-11`, `mdl-dsc@2027-02`, and so on (a version label is an opaque
string; the examples use the month a DSC was issued).

- `x509-file:mdl-dsc` (no version) resolves to the **newest** entry of that alias whose certificate is valid now —
  `notBefore <= now < notAfter`, the newest by `notBefore`; on an equal `notBefore` the version labels decide, compared
  numerically: runs of digits compare as numbers, so `2026-11.10` is newer than `2026-11.2` and `2026-11` older than
  `2026-11.1`. This matches the `<prefix>@yyyy-MM[.N]` labels `certify-cli pki dsc rotate` writes (M-07), and orders any
  other label deterministically. An expired version is never chosen, so a rotation window with an old and a new DSC
  signs with the new one and keeps the old one verifiable.
- When an alias has a single entry and no versions, it resolves to that entry whatever its dates, exactly as before
  M-05 — **except a Document Signer** (purpose `mdoc-dsc` or the mDL EKU): an mDL signed outside its DSC's validity is
  one every verifier rejects, so an expired or not-yet-valid single DSC does not resolve.
- `x509-file:mdl-dsc@2027-02` (a version) resolves to that entry exactly, valid or not, so an old DSC can still be used
  to re-sign a list it owns.
- `KeyProvider.publicKeys(KeyRef)` lists **every** version of an alias, oldest first in the same order (`notBefore`,
  then the numeric version comparison), which is what a JWKS or a DID document publishes so credentials signed before
  a rotation keep verifying; the provider's own `kid` for each entry is the full alias including `@version`.

If no version of an alias is valid now, resolution fails with `No key with alias 'mdl-dsc' in provider 'x509-file'; no
version has a certificate valid now (versions: …)` rather than falling back to an expired certificate.

## Expiry visibility

`certify-service` (`SigningKeyExpiry`) reports the **current key of every alias** of every provider, keymanager
included, because the metric belongs to the service, not to a key-provider module:

- the gauge `certify.signing.key.expires_in_days{keyRef}`: days left, recomputed on every scrape, negative once
  expired. `keyRef` is the reference that pins the key and parses as a `KeyRef`: `x509-file:mdl-dsc@2027-02`,
  `x509-file:iaca`, `keymanager:CERTIFY_SERVICE@<kid>`, `keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN@<kid>`;
- one `WARN` when a current key enters the window of `certify.signing.key-expiry.warn-days` (30) days, and one when an
  alias is left with no valid key; an alias whose versions are all still in the future logs
  `alias X has no key valid now; next version valid from <notBefore>` at every reconciliation.

The current key is the one an unversioned reference resolves to; when no version is valid, the one that expired last
among the versions that have started (`notBefore <= now`), so the alias shows a negative number instead of
disappearing, even while its successor waits for its `notBefore`; when every version is still in the future (a single
DSC not valid yet), the earliest of them at `0`. Rotated-out versions (an older DSC in its rotation
window, keymanager's expired certificates) are not reported. Nothing is read while beans are created: the first
report runs once the application is ready, after keymanager has provisioned its keys, and the gauges are reconciled
with the providers every `certify.signing.key-expiry.reconcile-interval` (`PT1H`; zero turns the periodic run off), so
a key that appears later gets a gauge, a key that is gone loses it, and a provider unavailable at startup is picked up
when it answers. A provider that fails to answer is logged and keeps its previous gauges.

## Publishing the IACA (M-06)

`X509FileKeyProviders.iacaCertificates(provider)` returns the IACA certificates this provider can publish: the dev-mode
IACA entry and the anchor each Document Signer chain ends at (production), deduplicated by encoding. A self-signed
certificate counts only when it passes `AnnexBValidator.validateIaca`, so the P3-08 dev CA and a plain self-signed dev
key are excluded. The method serves nothing over HTTP; M-06's trust-anchor registry reads it.

## Tests

`mvn -pl certify-keyprovider-x509-file test`. The suite proves a generated IACA and DSC pass `AnnexBValidator` and
`openssl verify -x509_strict` (skipped without `openssl` locally, failing in CI), PEM import of a plaintext and an
encrypted key with a chain built by `certify-pki` in the test, refusal of a chain that violates Annex B, of a key that
does not match its certificate (plaintext, encrypted, other key type), of an mDL chain that is not `[DSC, IACA]` and of
a chain out of order, that PEM keys never enter the keystore, that purposes survive a restart, that changed IACA and
DSC settings refuse startup until restored or rotated, rotation over an expired and a valid version, and that the P3-08
output is unchanged and not published as an IACA. `certify-keyprovider-jca` tests the numeric version order and the
Document Signer exception to the single-entry rule; `certify-service` `SigningKeyExpiryTest` and
`SigningKeyExpiryStartupTest` the expiry report.
