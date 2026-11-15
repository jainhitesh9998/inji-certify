# Wallet presentation fixtures (P5-03)

## What Certify issues: `mdl-a`

The bytes here are what Inji Certify itself issues, not a shape the harness made up. `mdl-a.issuersigned` is the
IssuerSigned `MdocFormatter` signed for the demo subject `mdl-demo-1`: an `org.iso.18013.5.1.mDL` with the 15 elements
the demo issues to it (`docker-compose/docker-compose-injistack/config/mdl/holders.json` and its portrait file, in the
order `config/mdl/mdl.vm` writes them). `mdl-a.holder.jwk` is the holder key it was issued to (a test key, never a
secret). `docs/design/tools/check-offer-wallet.mjs` reads both: it decodes the credential, checks every element's digest
against the MSO, keeps it through the offer page with that key, and signs with the kept key.

The names are plan section 4.12's. `mdl-b`, `pid`, `iaca.*` and `clock.txt` come with the packages that read them
(P5-03d, P5-03h).

## How `mdl-a` was produced

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

## The test verifier: `verifier/` (P5-03c)

`docs/design/tools/fixtures/wallet/make-verifier.sh` builds these with OpenSSL 3.6 and nothing else, and the output is
committed; a re-run is a deliberate re-record, never part of a test:

```bash
docs/design/tools/fixtures/wallet/make-verifier.sh
```

Nothing here is used against a real verifier. These stand in for the certificates EUDI and Multipaz send, so the page's
own chain and client-identifier checks (plan 4.5, R6/R7/R10) run offline against known-good and known-bad material. The
**private keys are test keys, committed on purpose**; they sign nothing but the harness's request objects.

| File | What it is |
|---|---|
| `ca.pem` (`.key.pem`) | the test CA: EC P-256, `CN=Wallet Fixture Verifier CA`, `cA` with `pathlen:2`, valid 2026-01-01..2046-01-01 |
| `intermediate.pem` (`.key.pem`) | an intermediate the CA signed, `pathlen:0`, for the three-certificate chain |
| `verifier.pem` (`.key.pem`) | the verifier's leaf: `CN=Wallet Fixture Verifier`, `DNS:verifier.example` **and** `URI:https://verifier.example/v1/certify/offer/wallet` (EUDI's leaf carries a URI SAN too), valid 2026-01-01..2036-01-01 |
| `other.pem` (`.key.pem`) | a second name under the same CA (`DNS:other.example`): a well-formed chain with the wrong name |
| `expired.pem` (`.key.pem`) | `DNS:verifier.example`, valid 2019-01-01..2020-01-01 |
| `future.pem` (`.key.pem`) | `DNS:verifier.example`, valid 2040-01-01..2045-01-01 |
| `leaf-under-intermediate.pem` (`.key.pem`) | a leaf the intermediate signed, for the three-certificate chain |
| `rsa-ca.pem`, `rsa-leaf.pem` (`.key.pem`) | an RSA 2048 chain, for RS256 and PS256 |
| `p384-ca.pem`, `p384-leaf.pem` (`.key.pem`) | a P-384 chain, for ES384 |
| `p521-ca.pem`, `p521-leaf.pem` (`.key.pem`) | a P-521 chain, for ES512 |
| `impostor-ca.pem` (`.key.pem`) | a second CA that signed none of the leaves: the chain link that does not verify |
| `self-signed.pem` (`.key.pem`) | one self-signed certificate with `DNS:verifier.example`: HAIP §5's finding, not a refusal |
| `jwe.key.pem`, `jwe.pub.pem`, `kid.txt` | the verifier's response-encryption key pair and the `kid` it names (P5-03e reads these) |

Every validity range is written with an explicit `-not_before`/`-not_after`, because three checks are about the clock.
The harness pins "now" at **2026-11-15T09:00:00Z**, which is inside every leaf's validity except `expired` and `future`.

## The verifiers' request objects: `hosted/` (P5-03c)

`docs/design/tools/fixtures/wallet/make-hosted.mjs` writes them, and the output is committed:

```bash
node docs/design/tools/fixtures/wallet/make-hosted.mjs
```

**These are the verifiers' shapes, not their captured bytes.** Plan 4.12 names `hosted/` as the request objects captured
from `verifier-backend.eudiw.dev` and `verifier.multipaz.org`; those captures are not in this repository, and no test may
contact a real verifier. So the shapes plan 2.1 records are reproduced here and signed with the fixture leaf:

| File | Shape |
|---|---|
| `eudi.request.jwt` | `x509_hash:<SHA-256 of the leaf>`, `aud: https://self-issued.me/v2`, `state`, `nonce`, `direct_post.jwt`, `client_metadata` with a `jwks` (ECDH-ES P-256, `kid`) and both `issuerauth_alg_values`/`deviceauth_alg_values`, a 10-claim mDL DCQL query, and a `verifier_info` registration certificate - 23 KB, as EUDI's is |
| `multipaz.request.jwt` | `x509_san_dns:verifier.example`, `expected_origins`, `direct_post.jwt`, a `jwks`, a 6-claim mDL DCQL query, and **no `aud` and no `state`**, which is what Multipaz sends and what the card reports as findings |

Their timestamps sit around the harness's pinned instant. What the checks prove with them is that the page reads these
shapes - R1-R11, the card's subject/issuer/fingerprints, and Multipaz's two findings - not that these are the verifiers'
bytes.
