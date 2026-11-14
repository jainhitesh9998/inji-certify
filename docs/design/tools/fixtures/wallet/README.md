# Wallet presentation fixtures (P5-03)

The bytes here are what Inji Certify itself issues, not a shape the harness made up. `mdl-a.issuersigned` is the
IssuerSigned `MdocFormatter` signed for the demo subject `mdl-demo-1`: an `org.iso.18013.5.1.mDL` with the 15 elements
the demo issues to it (`docker-compose/docker-compose-injistack/config/mdl/holders.json` and its portrait file, in the
order `config/mdl/mdl.vm` writes them). `mdl-a.holder.jwk` is the holder key it was issued to (a test key, never a
secret). `docs/design/tools/check-offer-wallet.mjs` reads both: it decodes the credential, checks every element's digest
against the MSO, keeps it through the offer page with that key, and signs with the kept key.

The names are plan section 4.12's. `mdl-b`, `pid`, `iaca.*`, `clock.txt`, `verifier/` and `hosted/` come with the work
packages that use them (P5-03b and later).

## How they were produced

`WalletFixtureRecorderTest` (`certify-format-mdoc/src/test/java/io/mosip/certify/format/mdoc/`; plan section 4.12)
builds the mDL with the test fixtures' DSC (a dev-mode DSC issued by a dev IACA), a fresh P-256 holder key, and signs it
through the formatter. It is an ordinary surefire test, so its assertions on the layout below gate every build of the
module. The committed copy is written only when asked, like the golden recorders:

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true \
    -Dmaven.gitcommitid.skip=true -pl certify-format-mdoc -am test \
    -Dtest=WalletFixtureRecorderTest -Dsurefire.failIfNoSpecifiedTests=false -Dwallet.fixture.record=true
```

Every run, recording or not, also writes `certify-format-mdoc/target/wallet-fixture/` with the real clock, for a CI
interop job that needs a fresh MSO.

## What the bytes say (the layout a reader must accept)

- `issuerAuth` is an untagged COSE_Sign1 `[protected, unprotected, payload, signature]` (RFC 9052 §4.2), and it comes
  first in the IssuerSigned map.
- `issuerAuth[2]` is a **byte string**; its content is `#6.24(bstr .cbor MobileSecurityObject)`, so the payload begins
  `d8 18 59 …` (ISO/IEC 18013-5 §9.1.2.4). A reader that expects the tag at `issuerAuth[2]` itself refuses every real
  Certify mDL.
- The `x5chain` header (label 33) is a **single bstr**, because Certify carries the DSC alone and HAIP forbids shipping
  the IACA: `COSE_X509 = bstr / [2*certs: bstr]` (RFC 9360 §2). The array form always carries two or more, so a
  one-entry array is refused, not read.
- Every `IssuerSignedItemBytes` is a tag-24 item, and its SHA-256 is the MSO's `valueDigests` entry for its
  `digestID` (§9.1.2.5).

A tag is recognised by its numeric value whatever head encodes it: `d9 00 18` is tag 24 as much as `d8 18` (RFC 8949
§3.1). The harness checks that with its own byte-assembled fixtures, and this recorded one is the untagged,
preferred-head case the issuer actually writes. What the reader refuses is checked on the bytes, not only on decoded
values: a tag other than 18 around `issuerAuth`, a tag on any of its four elements, a map key that is not a text string
(the decoy `{"issuerAuth": …}` key), a key IssuerSigned does not define, and an item that is not tag 24.
