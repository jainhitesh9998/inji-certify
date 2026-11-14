# Wallet presentation fixtures (P5-03)

The bytes here are what Inji Certify itself issues, not a shape the harness made up. `certify-mdl.issuersigned` is the
IssuerSigned `MdocFormatter` signed; `certify-mdl.holder.jwk` is the holder key it was issued to (a test key, never a
secret). `docs/design/tools/check-offer-wallet.mjs` reads both: it decodes the credential, checks every element's digest
against the MSO, keeps it through the offer page with that key, and signs with the kept key.

## How they were produced

`WalletFixtureRecorder` (`certify-format-mdoc/src/test/java/io/mosip/certify/format/mdoc/`, P5-03a; plan section 4.12)
builds an ISO/IEC 18013-5 Table 5 mDL with the test fixtures' DSC (a dev-mode DSC issued by a dev IACA), a fresh P-256
holder key, and signs it through the formatter. The committed copy is written only when asked, like the golden recorders:

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true \
    -Dmaven.gitcommitid.skip=true -pl certify-format-mdoc -am test \
    -Dtest=WalletFixtureRecorder -Dsurefire.failIfNoSpecifiedTests=false -Dwallet.fixture.record=true
```

Every run, recording or not, also writes `certify-format-mdoc/target/wallet-fixture/` with the real clock, for a CI
interop job that needs a fresh MSO.

## What the bytes say (the layout a reader must accept)

- `issuerAuth` is an untagged COSE_Sign1 `[protected, unprotected, payload, signature]` (RFC 9052 §4.2).
- `issuerAuth[2]` is a **byte string**; its content is `#6.24(bstr .cbor MobileSecurityObject)`, so the payload begins
  `d8 18 59 …` (ISO/IEC 18013-5 §9.1.2.4). A reader that expects the tag at `issuerAuth[2]` itself refuses every real
  Certify mDL.
- The `x5chain` header (label 33) is a **single bstr**, because Certify carries the DSC alone and HAIP forbids shipping
  the IACA: `COSE_X509 = bstr / [2*certs: bstr]` (RFC 9360 §2).
- Every `IssuerSignedItemBytes` is a tag-24 item, and its SHA-256 is the MSO's `valueDigests` entry for its
  `digestID` (§9.1.2.5).

A tag is recognised by its numeric value whatever head encodes it: `d9 00 18` is tag 24 as much as `d8 18` (RFC 8949
§3.1). The harness checks that with its own byte-assembled fixtures, and this recorded one is the untagged,
preferred-head case the issuer actually writes.
