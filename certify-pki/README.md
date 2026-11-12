# certify-pki

ISO/IEC 18013-5:2021 Annex B certificate profiles, a CRL builder, PKCS#10 parsing and a profile validator.
BouncyCastle only: no Spring, web, JPA, Velocity or JSON-LD, so the offline CLI (`certify-cli`) and the issuance
runtime share one implementation. See [M-04](../docs/design/20-mdl-issuer.md) and
[06a](../docs/design/06a-x509-pki-and-mdoc.md).

## The standard and our choices

The profiles target the **2021 edition** of ISO/IEC 18013-5 (decision D11). This README and the code separate three
kinds of rule, and say which one applies:

- **Annex B**: a property the IACA, Document Signer or CRL profile of Annex B requires, as the team reads it. Where the
  reading has not yet been checked against the purchased ISO text it is marked *to be confirmed*.
- **RFC 5280 / RFC 5758 / X.520**: a property of every X.509 certificate or CRL, which Annex B builds on.
- **Module choice**: something this module decides where the standard is silent, permissive or not yet confirmed. Each
  one is a row of the decision log (`docs/design/12-risks-and-decisions.md`, 2026-11-13, pending owner review) and can
  be changed by a new decision without re-reading the standard.

Do not change the profile constants (20 years, 457 days, EKU `1.0.18013.5.1.2`) without a new decision and a re-read of
the edition the profiles target.

## Profiles

| Object | Rules and their source |
| --- | --- |
| IACA certificate | Annex B: version 3; self-signed; subject `C` (ISO 3166-1 alpha-2) and `CN` mandatory, `ST`/`O` optional; issuerAltName non-critical; CRL distribution point; SubjectKeyIdentifier (RFC 5280 method 1); `keyUsage = keyCertSign + cRLSign` only, critical; `basicConstraints CA:true, pathLen:0`, critical; validity at most 20 years; `ecdsa-with-SHA256/384/512`. Module choice: P-256/384/521 only; the 20 years are calendar years in UTC, endpoints compared directly; extensions other than SKI, AKI, keyUsage, basicConstraints, issuerAltName and CRL DP must not be critical (an `extendedKeyUsage` marked critical is reported). |
| Document Signer certificate | Annex B: issuer = the IACA subject; subject `C` (and `ST` when the IACA has one) equal to the IACA's, `CN` configured; AuthorityKeyIdentifier = IACA SubjectKeyIdentifier; SubjectKeyIdentifier; `keyUsage = digitalSignature` only, critical; `extendedKeyUsage = 1.0.18013.5.1.2`, critical; issuerAltName; CRL distribution point; validity at most 457 days. RFC 5280: inside the IACA's validity. Module choice: the builder writes no basicConstraints, and the validator accepts `CA:false` (critical or not) while refusing `CA:true`. |
| CRL | RFC 5280: X.509 v2, signed by the IACA, AuthorityKeyIdentifier, cRLNumber of at most 20 octets, thisUpdate, nextUpdate. Annex B (*to be confirmed*): revoked entries carry **no entry extensions**; the builder writes none and the validator reports them. Module choice: the cRLNumber is supplied by the caller and must increase; no extension other than AKI and cRLNumber; thisUpdate not more than 5 minutes after the validation instant; nextUpdate not after the IACA's notAfter. |

The DS builder copies the IACA's `C` and `ST` as `ASN1Encodable` values rather than through a string: RFC 4514 escaping
turns `Foo, Bar` into `Foo\, Bar`, so a DS subject built from a string would differ from the IACA's in the type, the
bytes and the decoded value. The DS issuer is the IACA subject DER byte for byte, so a name comparison cannot fail on a
re-encoding difference either.

### Subject names

RFC 5280 section 4.1.2.4 requires a directory string (`CN`, `O`, `OU`, `ST`, `L`) to be a PrintableString or a
UTF8String; X.520 makes `C` and `serialNumber` PrintableStrings. The builders write `C` as a PrintableString and the
rest as UTF8Strings, and the validator reports any other type (`*_SUBJECT_ENCODING_INVALID`,
`*_SUBJECT_COUNTRY_NOT_PRINTABLE`). The builders refuse an empty `ST` or `O` and the RFC 5280 upper bounds (`CN` and
`O` 64 characters, `ST` 128); the validator does not check lengths.

### Contact and CRL locations

- issuerAltName: a URI of **any scheme**, as long as it is absolute (`https://...` and `mailto:...` both pass), or an
  rfc822Name that is a syntactically valid mailbox (RFC 5321: dot-atom local part, letter-digit-hyphen domain labels;
  quoted local parts and address literals are refused). Builder and validator call the same two checks.
- CRL distribution point: `fullName` URIs that are absolute `http` or `https` URIs with a host; `ldap://`, `file:` and
  strings that are not URIs are refused by both. No `reasons`, no `cRLIssuer`.

### Keys

ISO/IEC 18013-5 lists both the NIST curves and the brainpool curves for issuer signing. **This module allows only
P-256, P-384 and P-521** (module choice; enabling brainpool is a new decision, not a code change), and the signature
algorithm follows the key: `ecdsa-with-SHA256`, `-SHA384`, `-SHA512` respectively, with the AlgorithmIdentifier
parameters field absent (RFC 5758 section 3.2) on certificates, CRLs and CSRs. Both builders, `Csr` and the validator
enforce one allowlist:

- the curve must be named by one of the three OIDs; explicit curve parameters are refused;
- the public key must be an uncompressed point (`0x04`) of the curve's field size that BouncyCastle's
  `ECCurve.decodePoint` accepts and `isValid()` confirms: the point at infinity, points off the curve and coordinates
  outside the field are refused (`CSR_KEY_INVALID` / `IACA_KEY_INVALID` / `DS_KEY_INVALID`);
- RSA and every other key type are refused.

### Validity

The validator compares the endpoints: a Document Signer passes when `notAfter - notBefore <= 457 days` (exactly 457
days passes) and an IACA when `notAfter <= notBefore + 20 calendar years` (UTC); `notAfter <= notBefore` is
`*_VALIDITY_REVERSED`. The builders treat a validity `Duration` as the inclusive span RFC 5280 section 4.1.2.5
describes and write `notAfter = notBefore + validity - 1s`, so their output is always inside the validator's caps.

A builder refuses a validity shorter than **one hour** (`IsoMdocProfiles.MIN_VALIDITY`, module choice; Annex B sets no
minimum) or longer than the cap. A Document Signer never outlives its IACA: a `notBefore` earlier than the IACA's is
moved forward to it and a `notAfter` later than the IACA's is clamped to it; when the clamped certificate would be valid
for less than one hour, the builder refuses with `DS_VALIDITY_OUTSIDE_IACA` instead of issuing a seconds-long
certificate.

### Serials

Annex B asks for a serial with at least 63 bits of CSPRNG output; RFC 5280 limits it to 20 DER content octets.
`Serials.random()` produces a positive serial of exactly 9 DER content octets with bit 70 set, so the magnitude is
always 71 bits (70 of them random), and the builders refuse a caller-supplied serial shorter than 64 bits.

Entropy cannot be measured from one serial, so the validator applies a heuristic (module choice): it reports only
serials shorter than **56 bits** (`AnnexBValidator.MIN_SERIAL_BITS`). A serial drawn from 63 random bits is shorter
than 56 bits with probability 2^-7, so a stricter floor would flag conforming certificates from other issuers.
`Serials.octets` counts the DER content octets **including the sign octet**, so `2^159` (20 magnitude octets with the
top bit set) is 21 octets and does not fit.

### CRLs

The CRL number is mandatory and the caller's (module choice): RFC 5280 section 5.2.3 makes it a monotonically
increasing counter per issuer and only the operator knows the previous one, so `CrlBuilder` will not invent one from
the clock (two CRLs published in the same second would then share a number). Pass `crlNumber(n)` with `n` greater
than the last published CRL and at most `2^159 - 1`, and let the CLI/publisher keep the counter.

`CrlBuilder` refuses what the validator would report: an IACA that fails `validateIaca` (one without `cRLSign` cannot
sign a CRL) with `CRL_IACA_INVALID`, a revocation dated after thisUpdate (`CRL_ENTRY_DATE_INVALID`), a serial revoked
twice (`CRL_ENTRY_DUPLICATE`), and a nextUpdate after the IACA expires (`CRL_NEXT_UPDATE_AFTER_IACA`). thisUpdate
defaults to the instant `build()` runs; nextUpdate defaults to 30 days later or the IACA's notAfter, whichever is
sooner. Entries carry no extensions, so there is no reason code and no invalidity date.

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
OpenSSL `EC PRIVATE KEY` block with `Proc-Type: 4,ENCRYPTED` headers is read the same way. Encrypted PKCS#8 is read
when it uses PBES2 with PBKDF2 (what `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256` and this library
write) or a PKCS#12 PBE scheme older OpenSSL releases wrote; scrypt and every other scheme are refused with
`PEM_KEY_UNSUPPORTED: unsupported PBE scheme ...` before a password is tried.

## Validation

`AnnexBValidator` returns named violations instead of throwing, so a caller can refuse an issuance with a stable rule
identifier. The prefixes are the profile (`IACA_`, `DS_`, `CRL_`); `AnnexBValidator.RULES` lists every identifier the
validator can emit, and `ruleIds` returns the distinct identifiers of a result in sorted order. A generated IACA,
Document Signer and CRL pass with an empty list.

What it checks, beyond the sections above: certificate version 3; serial positivity, the 56-bit heuristic and the
20-octet cap; the signature algorithm against the signer's curve (SHA-1 is not in the allowlist), parameters absent,
and the inner/outer `AlgorithmIdentifier` consistency; the subject key identifier against RFC 5280 method 1 and the
authority key identifier against the issuer's SKI; extension criticality (SKI, AKI, issuerAltName and CRL DP
non-critical; keyUsage, basicConstraints and EKU critical) and, per profile, any critical extension the profile does not
define; the CRL distribution point structure; names attribute by attribute anywhere in the RDN sequence, with
duplicates flagged and values compared decoded (`ASN1String.getString()`) or as DER, never through RFC 4514 escaping;
and for a CRL its signature algorithm, AKI, CRL number, the absence of other CRL extensions and of entry extensions, and
the date rules. `validateCrl(crl, iaca, at)` judges thisUpdate against `at`; the two-argument form uses now.

**Malformed extensions never throw.** Every extension is read from its DER on its own: exactly one DER object inside
the extension's OCTET STRING, then the extension's structure. One that cannot be read is reported as
`*_SKI_MALFORMED`, `*_AKI_MALFORMED`, `*_ISSUER_ALT_NAME_MALFORMED`, `*_CRL_DP_MALFORMED`, `*_KEY_USAGE_MALFORMED`,
`*_BASIC_CONSTRAINTS_MALFORMED`, `DS_EKU_MALFORMED`, `CRL_AKI_MALFORMED` or `CRL_NUMBER_MALFORMED`, and none of its other
properties are assessed. A malformed extension on the IACA a Document Signer or CRL is checked against makes the
dependent comparison fail (`DS_AKI_MISMATCH`, `DS_ISSUER_ALT_NAME_MISMATCH`, `CRL_AKI_MISMATCH`) rather than throw.

## Tests

`mvn -pl certify-pki test`. The suite builds broken certificates and CRLs with plain BouncyCastle (the builders refuse
invalid input), one per rule, so every rule has a negative test that breaks only that rule; malformed `keyUsage` and
`basicConstraints` are parsed by the JDK, which keeps a malformed non-critical extension as raw octets where
BouncyCastle refuses the certificate. Coverage is recorded, not declared: each negative assertion records its rule
when it passes, and `everyRuleHasANegativeTest` (run last) compares the recorded rules with `AnnexBValidator.RULES`, so
a rule cannot be published without a passing test. The baseline fixtures are fully conforming, random serials
included. It validates the DS-to-IACA path and a revoked serial with the JDK `CertPathValidator`; it runs `openssl
verify -x509_strict -crl_check -CRLfile` and `openssl crl -CAfile`, and exchanges encrypted PKCS#8 keys with OpenSSL in
both directions (`openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256` read here, ours decrypted by
`openssl pkey`, an OpenSSL scrypt key refused by name) — skipping without `openssl` on the PATH, **failing** when `CI`
is set. `PkiArchitectureTest` keeps Spring, web, JPA, Velocity, JSON-LD, keymanager and global JCA-provider
registration (`Security.addProvider` and `Security.insertProviderAt`) out of the module.

## Outside scope

- **The Multipaz chain check** (an independent JVM mDoc verifier as a merge gate) is deferred to **M-01/M-06**, where
  the shared verifier module and the DSC trust-anchor policy live; this module keeps the JDK `CertPathValidator` and
  OpenSSL as its independent implementations.
- A VICAL, IACA publication and CRL refresh belong to M-08; `certify-pki` only writes the objects.
- Brainpool curves are excluded by decision (see "Keys" above); supporting them is a new decision, not a code change.
- Confirming the *to be confirmed* readings of Annex B (the CRL entry-extension rule above) against the purchased ISO
  text.
