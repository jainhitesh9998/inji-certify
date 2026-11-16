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
| `ca.pem` (`.key.pem`) | the test CA: EC P-256, `CN=Wallet Fixture Verifier CA`, `cA` with `pathlen:2` and `keyCertSign`, valid 2026-01-01..2046-01-01 |
| `intermediate.pem` (`.key.pem`) | an intermediate the CA signed, `pathlen:0`, for the three-certificate chain |
| `verifier.pem` (`.key.pem`) | the verifier's leaf: `CN=Wallet Fixture Verifier`, `DNS:verifier.example` **and** `URI:https://verifier.example/v1/certify/offer/wallet` (EUDI's leaf carries a URI SAN too), valid 2026-01-01..2036-01-01 |
| `other.pem` (`.key.pem`) | a second name under the same CA (`DNS:other.example`): a well-formed chain with the wrong name. Its serial has the top bit set |
| `expired.pem` (`.key.pem`) | `DNS:verifier.example`, valid 2019-01-01..2020-01-01 |
| `future.pem` (`.key.pem`) | `DNS:verifier.example`, valid 2040-01-01..2045-01-01 |
| `leaf-under-intermediate.pem` (`.key.pem`) | a leaf the intermediate signed, for the three-certificate chain |
| `rsa-ca.pem`, `rsa-leaf.pem` (`.key.pem`) | an RSA 2048 chain, for RS256 and PS256 |
| `rsa-pss-leaf.pem` (`.key.pem`) | the same RSA CA signing the leaf with RSA-PSS and SHA-256: signatureAlgorithm `1.2.840.113549.1.1.10` with its parameters (RFC 4055 §3.1) |
| `rsa-small-ca.pem`, `rsa-small-leaf.pem` (`.key.pem`) | a 1024-bit RSA chain: RS256 and PS256 must refuse it (RFC 7518 §3.3) |
| `p384-ca.pem`, `p384-leaf.pem` (`.key.pem`) | a P-384 chain, for ES384 |
| `p521-ca.pem`, `p521-leaf.pem` (`.key.pem`) | a P-521 chain, for ES512 |
| `impostor-ca.pem` (`.key.pem`) | a second CA that signed none of the leaves: the chain link that does not verify |
| `self-signed.pem` (`.key.pem`) | one self-signed certificate with `DNS:verifier.example`: HAIP §5's finding, not a refusal |
| `ca-variant.key.pem` + `nonca.pem`, `nokeycertsign.pem`, `unknown-critical.pem`, `tight-pathlen.pem` | four certificates carrying the CA's own subject name and not its key, one for each RFC 5280 §6.1.4 path rule the page enforces: `cA` not set, a `keyUsage` without `keyCertSign`, an unrecognised critical extension, and a `pathLenConstraint` of 0. The page reads a certificate's own extensions before it tries the signature link, so each one reaches the CA check it is there for; one key serves all four, and none of them signs anything |
| `nc-intermediate.pem` (`.key.pem`), `leaf-under-nc.pem` | an intermediate the CA signed with a **critical `nameConstraints`** permitting only `DNS:allowed.example`, and a leaf it signed for `DNS:verifier.example` (with `verifier`'s key). Every signature and validity is good; `openssl verify` refuses the chain (permitted subtree violation), and the page refuses it because it runs no name-constraint processing (RFC 5280 §4.2) |
| `iap-intermediate.pem` (`.key.pem`), `leaf-under-iap.pem` | the same shape with a **critical `inhibitAnyPolicy`**: a policy extension the page does not process, so a critical one ends the path |
| `keyagreement-leaf.pem` | a leaf under the CA whose `keyUsage` is `keyAgreement` only (with `verifier`'s key): it may not sign the request object (RFC 5280 §4.2.1.3) |
| `rsa-pss-sha1-leaf.pem` | the RSA CA signing with RSA-PSS over SHA-1, MGF1-SHA-1 and a 20-octet salt, every parameter at its DEFAULT (with `rsa-pss-leaf`'s key): SHA-1 is refused whether it is spelled `sha1WithRSAEncryption` or RSA-PSS |
| `rsa-leaf-under-small-ca.pem` | a 2048-bit leaf (with `rsa-leaf`'s key) signed by the 1024-bit `rsa-small-ca`: the 2048-bit floor holds for a certificate's signer too |
| `generalized-time.pem` | a self-signed leaf (with `names`' key) whose `notAfter` is in 2051, which RFC 5280 §4.1.2.5 writes as GeneralizedTime; the harness rewrites its fields in place to reach that half of the time reader |
| `names.pem` (`.key.pem`) | a self-signed leaf whose `CN` is four characters, so the harness can rewrite that one string's tag in place and reach the two name string types no certificate here writes: NumericString (tag 18) and UniversalString (tag 28) |
| `jwe.key.pem`, `jwe.pub.pem`, `kid.txt` | the verifier's response-encryption key pair and the `kid` it names (P5-03e reads these) |

Serials are OpenSSL's own 20 random octets - the size RFC 5280 §4.1.2.2 allows up to, and what the hosted captures
carry - except `other`, whose first octet has its top bit set, so DER writes a leading `0x00` pad. Both shapes are why
the page keeps a serial as bytes and hex rather than as a number. A negative serial, which no fixture carries, is
reached by rewriting the `verifier` serial's first octet in the harness.

The harness reaches the strict-DER refusals the same way, by rewriting octets of a committed certificate in place so
that every length stays the same: an extension that appears twice, `cA` written as `0x01` or as FALSE, a `critical`
FALSE, a version of v1, 3 or v2-with-extensions, a month 13 or an hour 40 in either time type, and RSA-PSS parameters
that write a DEFAULT or name SHA-224.

Every validity range is written with an explicit `-not_before`/`-not_after`, because three checks are about the clock.
The harness pins "now" at **2026-11-15T09:00:00Z**, which is inside every leaf's validity except `expired` and `future`.

## The verifiers' request objects: `hosted/` (P5-03c)

**These are the real bytes.** The coordinator captured them once, by hand, from the two hosted verifiers on
2026-11-16, and `PROVENANCE.md` beside them records how, when, and what each leaf carries. No test contacts a verifier;
the checks only read these files. Nothing regenerates them: a capture is a deliberate act, not a build step (the
synthetic `make-hosted.mjs` that stood here first is deleted, and the decision log's 2026-11-16 row says why).

| File | What it is |
|---|---|
| `eudi-request-get.jwt` | `verifier-backend.eudiw.dev`'s request object, fetched with `request_uri_method=get` (~23 KB) |
| `eudi-request-post.jwt` | the same verifier's object for `request_uri_method=post`; its `wallet_nonce` is `capture-wallet-nonce-20261116` |
| `eudi-init-get.json`, `eudi-init-post.json` | the verifier's transaction-init answers: `client_id`, `request_uri`, and the `haip-vp://` `authorization_request_uri` the page reads |
| `mp-request.jwt` | `verifier.multipaz.org`'s request object: `x509_san_dns:verifier.multipaz.org`, no `aud`, no `state` |
| `mp-begin-response.json` | that verifier's begin answer, whose `uri` is the doubled-separator form `haip-vp://://?…` |
| `PROVENANCE.md` | how each file was captured, when, and the leaf certificates' serials, names and validity |

What they carry that a shape signed with our own leaf could not:

- **EUDI**: `client_id` `x509_hash:<SHA-256 of the leaf>`, a **20-octet serial** (`606F16D48D021AC3A3E68F2E44F636AE3B786699`),
  an **URI-only** subject alternative name (`https://verifier.eudiw.dev`, no dNSName), and a `verifier_info` holding a
  registration certificate.
- **Multipaz**: `x509_san_dns:verifier.multipaz.org`, no `aud` and no `state` (both findings on the card), a 13-octet
  serial, and a **critical** `extendedKeyUsage` the page has to know to read the leaf at all.

Each is evaluated under a faked clock at the instant it was captured, its own `iat` (2026-11-16T05:30:33Z for EUDI's
get form, 05:30:35Z for its post form, 05:31:09Z for Multipaz), because that is when the request `iat` and the leaves'
validity mean anything.
