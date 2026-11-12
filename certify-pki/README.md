# certify-pki

ISO/IEC 18013-5:2021 Annex B certificate profiles, a CRL builder, PKCS#10 parsing and a profile validator.
BouncyCastle only: no Spring, web, JPA, Velocity or JSON-LD, so the offline CLI (`certify-cli`) and the issuance
runtime share one implementation. See [M-04](../docs/design/20-mdl-issuer.md) and
[06a](../docs/design/06a-x509-pki-and-mdoc.md).

## Profiles

The figures are the ones in the **2021 edition** of ISO/IEC 18013-5 (decision D11): IACA validity at most 20 years,
Document Signer validity at most 457 days, Document Signer extended key usage `1.0.18013.5.1.2`, and no
basicConstraints on a Document Signer. Annex B in later editions may differ; do not change these constants without a
new decision and a re-read of the edition the profiles target.

| Object | Figure / clause | Rules implemented |
| --- | --- | --- |
| IACA certificate | Annex B, IACA profile | self-signed; subject `C` (ISO 3166-1 alpha-2) and `CN` mandatory, `ST`/`O` optional; issuerAltName (URI and/or rfc822) non-critical; CRL distribution point URI; SubjectKeyIdentifier; `keyUsage = keyCertSign + cRLSign`, critical; `basicConstraints CA:true, pathLen:0`, critical; validity at most 20 years; `ecdsa-with-SHA256/384/512` matching a P-256/384/521 key |
| Document Signer certificate | Annex B, DS profile | issuer = IACA subject; subject `C` (and `ST` when the IACA has one) equal to the IACA's, `CN` configured; AuthorityKeyIdentifier = IACA SubjectKeyIdentifier; SubjectKeyIdentifier; `keyUsage = digitalSignature`, critical; `extendedKeyUsage = 1.0.18013.5.1.2`, critical; issuerAltName copied from the IACA; CRL distribution point; validity at most 457 days; no basicConstraints |
| CRL | Annex B, CRL distribution point | X.509 v2, signed by the IACA, AuthorityKeyIdentifier, cRLNumber, thisUpdate, nextUpdate, a reason per revoked serial |

```java
KeyPair iacaKeyPair = /* generated offline or in an HSM-backed provider */;
X509Certificate iaca = IsoMdocProfiles.iaca(iacaKeyPair)
        .country("IN").organization("Lorem Ipsum Demo")
        .commonName("Lorem Ipsum Demo IACA")
        .issuerAltUri("https://credentials.example.test/mdoc/iaca")
        .crlDistributionPoint("https://credentials.example.test/mdoc/iaca/lorem-ipsum-demo-iaca.crl")
        .build();

// either a generated Document Signer key ...
X509Certificate dsc = IsoMdocProfiles.ds(dscKeyPair, iaca, iacaKeyPair).commonName("Lorem Ipsum Demo DSC").build();
// ... or the public key of a PKCS#10 request, which Csr verifies on parse
Csr csr = Csr.parsePem(requestPem);
X509Certificate fromCsr = IsoMdocProfiles.ds(csr.publicKey(), iaca, iacaKeyPair).commonName("Lorem Ipsum Demo DSC").build();

List<AnnexBValidator.Violation> violations = AnnexBValidator.validateDs(fromCsr, iaca);
X509CRL crl = CrlBuilder.forIaca(iaca, iacaKeyPair).revoke(serial, Instant.now()).build();
```

## Validation

`AnnexBValidator` returns named violations instead of throwing, so a caller can refuse an issuance with a stable rule
identifier (`DS_EKU_MISSING`, `DS_VALIDITY_TOO_LONG`, `IACA_PATHLEN`, `DS_COUNTRY_MISMATCH`, `SERIAL_TOO_LONG`, ...).
A generated IACA, Document Signer and CRL pass with an empty list.

## Tests

`mvn -pl certify-pki test`. The suite builds broken certificates and CRLs with plain BouncyCastle (the builders refuse
invalid input), one per rule, so every rule has a negative test; it validates the DS-to-IACA path and a revoked serial
with the JDK `CertPathValidator`; and it runs `openssl verify -x509_strict` and `openssl crl -CAfile` when `openssl` is
on the PATH. `PkiArchitectureTest` keeps Spring, web, JPA, Velocity, JSON-LD, keymanager and global JCA-provider
registration out of the module.
