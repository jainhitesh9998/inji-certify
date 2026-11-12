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
| IACA certificate | Annex B, IACA profile | self-signed; subject `C` (ISO 3166-1 alpha-2, PrintableString) and `CN` mandatory, `ST`/`O` optional; issuerAltName (URI and/or rfc822) non-critical; CRL distribution point URI; SubjectKeyIdentifier by RFC 5280 method 1; `keyUsage = keyCertSign + cRLSign` and nothing else, critical; `basicConstraints CA:true, pathLen:0`, critical; validity at most 20 years; `ecdsa-with-SHA256/384/512` matching a P-256/384/521 key |
| Document Signer certificate | Annex B, DS profile | issuer = the IACA subject **DER, unchanged**; subject `C` (and `ST` when the IACA has one) copied from the IACA as the ASN.1 values it carries, `CN` configured; AuthorityKeyIdentifier = IACA SubjectKeyIdentifier; SubjectKeyIdentifier; `keyUsage = digitalSignature` only, critical; `extendedKeyUsage = 1.0.18013.5.1.2`, critical; issuerAltName copied from the IACA; CRL distribution point; validity at most 457 days, inside the IACA's; no basicConstraints |
| CRL | Annex B, CRL distribution point | X.509 v2, signed by the IACA, AuthorityKeyIdentifier, cRLNumber, thisUpdate, nextUpdate; revoked entries with **no entry extensions** (Table B.9 prohibits them) |

Copying the IACA's `C` and `ST` as `ASN1Encodable` values rather than through a string is deliberate: RFC 4514 escaping
turns `Foo, Bar` into `Foo\, Bar`, so a DS subject built from a string would differ from the IACA's in the type, the
bytes and the decoded value. The DS issuer is the IACA subject DER byte for byte, so a name comparison cannot fail on a
re-encoding difference either.

### Keys

Annex B (2021) signs with ECDSA over **P-256, P-384 or P-521** and nothing else, and the signature algorithm follows
the key: `ecdsa-with-SHA256`, `-SHA384`, `-SHA512` respectively. Both builders, `Csr` and the validator enforce one
allowlist:

- the curve must be named, by one of the three OIDs — **brainpool is not allowed** in this profile, and enabling it
  needs a new decision and a re-read of the edition the profiles target;
- explicit curve parameters are refused (only a named curve OID is accepted);
- the public key must be an uncompressed point (`0x04`) of the curve's field size;
- RSA and every other key type are refused.

A compressed point or explicit parameters cannot survive a JCA `PublicKey` (every encoder writes a named curve and an
uncompressed point), so for generated keys the check is defensive; where such an encoding can really arrive — a CSR's
`subjectPublicKeyInfo` and a certificate under validation — it is refused with `CSR_KEY_INVALID` /
`IACA_KEY_INVALID` / `DS_KEY_INVALID`.

### Validity

`notAfter` is inclusive (RFC 5280 section 4.1.2.5), so a validity `Duration` is the span the certificate is valid for
and the builder writes `notAfter = notBefore + validity - 1s`. A builder refuses a validity that is not positive
(`*_VALIDITY_INVALID`) or that exceeds the profile cap (`*_VALIDITY_TOO_LONG`) instead of silently capping it. A
Document Signer never outlives its IACA: a `notBefore` earlier than the IACA's is moved forward to it and a `notAfter`
later than the IACA's is clamped to it.

### Serials

`Serials.random()` produces a positive serial of exactly 9 DER content octets with bit 70 set, so the magnitude is
always 71 bits (70 of them random) and never falls under the Annex B 63-bit floor; Annex B itself is satisfied by the
64-bit minimum the validator enforces. `Serials.octets` counts the DER content octets **including the sign octet**, so
`2^159` — 20 magnitude octets with the top bit set — is 21 octets and does not fit RFC 5280's 20.

### CRLs

The CRL number is mandatory and the caller's: RFC 5280 section 5.2.3 makes it a monotonically increasing counter per
issuer, and only the operator knows the previous one, so `CrlBuilder` will not invent one from the clock (two CRLs
published in the same second would then share a number). Pass `crlNumber(n)` with `n` greater than the last published
CRL, and let the CLI/publisher keep the counter.

Revoked entries carry no extensions at all: Annex B Table B.9 prohibits CRL entry extensions, so there is no reason
code and no invalidity date, and the builder has no parameter for either.

## Usage

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
X509CRL crl = CrlBuilder.forIaca(iaca, iacaKeyPair).crlNumber(BigInteger.valueOf(3)).revoke(serial, Instant.now()).build();
```

`DsBuilder` validates the IACA it is given with `AnnexBValidator.validateIaca` and refuses to sign under one that does
not conform (`DS_IACA_INVALID`), so a Document Signer can never be issued by an IACA the runtime would refuse.

Private keys can be written and read encrypted, which the offline IACA flow (D3) needs:

```java
String pem = Pem.writeEncryptedPrivateKey(iacaKeyPair.getPrivate(), password); // PKCS#8, AES-256-CBC, PBKDF2/HMAC-SHA256
PrivateKey key = Pem.readPrivateKey(pem, password);
boolean encrypted = Pem.isEncryptedPrivateKey(pem);
```

Reading an encrypted key without a password fails with `PEM_KEY_ENCRYPTED` rather than returning nothing; a legacy
OpenSSL `EC PRIVATE KEY` block with `Proc-Type: 4,ENCRYPTED` headers is read the same way.

## Validation

`AnnexBValidator` returns named violations instead of throwing, so a caller can refuse an issuance with a stable rule
identifier. The prefixes are the profile — `IACA_`, `DS_`, `CRL_` — and `ruleIds` returns the distinct identifiers in a
sorted order (`IACA_KEY_USAGE_EXTRA`, `IACA_PATHLEN`, `DS_EKU_MISSING`, `DS_VALIDITY_TOO_LONG`, `DS_COUNTRY_MISMATCH`,
`DS_SERIAL_TOO_SHORT`, `DS_SERIAL_TOO_LONG`, `DS_KEY_INVALID`, `CRL_NUMBER_MISSING`, `CRL_ENTRY_EXTENSION_PRESENT`, ...).
A generated IACA, Document Signer and CRL pass with an empty list.

What it checks, beyond the table above: certificate version 3; serial positivity, 64-bit floor and 20-octet cap; the
signature algorithm against the signer's curve (SHA-1 is not in the allowlist) and the inner/outer `AlgorithmIdentifier`
consistency; the subject key identifier against RFC 5280 method 1 and the authority key identifier against the issuer's
SKI; extension criticality (SKI, AKI, issuerAltName and CRL DP non-critical; keyUsage, basicConstraints and EKU
critical); any unknown critical extension; the CRL distribution point structure (`fullName` with URI GeneralNames only,
no `reasons`, no `cRLIssuer`); names attribute by attribute anywhere in the RDN sequence, with duplicates flagged and
values compared decoded (`ASN1String.getString()`) or as DER, never through RFC 4514 escaping; and for a CRL its
signature algorithm, AKI, CRL number (0..2^159), the absence of other CRL extensions, the absence of entry extensions
and the date order.

## Tests

`mvn -pl certify-pki test`. The suite builds broken certificates and CRLs with plain BouncyCastle (the builders refuse
invalid input), one per rule, so every rule has a negative test that breaks only that rule —
`everyRuleHasANegativeTest` compares the exercised rule ids with the list the validator can emit, so a new rule cannot
be added without its test. The baseline fixtures are fully conforming, random serials included. It validates the
DS-to-IACA path and a revoked serial with the JDK `CertPathValidator`; and it runs `openssl verify -x509_strict
-crl_check -CRLfile` and `openssl crl -CAfile` — skipping without `openssl` on the PATH, **failing** when `CI` is set.
`PkiArchitectureTest` keeps Spring, web, JPA, Velocity, JSON-LD, keymanager and global JCA-provider registration
(`Security.addProvider` and `Security.insertProviderAt`) out of the module.

## Outside scope

- **The Multipaz chain check** (an independent JVM mDoc verifier as a merge gate) is deferred to **M-01/M-06**, where
  the shared verifier module and the DSC trust-anchor policy live; this module keeps the JDK `CertPathValidator` and
  OpenSSL as its independent implementations.
- A VICAL, IACA publication and CRL refresh belong to M-08; `certify-pki` only writes the objects.
- Brainpool curves are refused by decision (see "Keys" above); supporting them is a new decision, not a code change.
