# certify-testkit-mdoc

The independent ISO/IEC 18013-5 verifier the mDoc tests lean on (work package **M-01** in
[`docs/design/20-mdl-issuer.md`](../../docs/design/20-mdl-issuer.md), decision **D9**). Certify's formatter tests
can only prove the writer agrees with itself; this module proves the bytes are readable by software Certify does
not maintain.

**Test-only.** Nothing in production depends on it and it is never published (`maven.deploy.skip`,
`central-publishing-maven-plugin` `skipPublishing`). `certify-format-mdoc` and `certify-conformance-mdoc` consume it
with `<scope>test</scope>`, so its Kotlin dependencies cannot reach a deployed artifact — and
`docs/design/tools/check-runtime-classpath.sh` fails the build if `certify-service`'s runtime classpath ever moves.

## What verifies what

| Stack | Used for |
| --- | --- |
| [OpenWallet Foundation Multipaz](https://github.com/openwallet-foundation/multipaz) `org.multipaz:multipaz-jvm` **0.102.0** (pinned) | CBOR, COSE_Sign1, MSO, `IssuerNamespaces` (+ its own validators), `x5chain`, the COSE_Sign1 signature, per-item digests, `X509CertChain.validate`, and `DrivingLicense` element types |
| [Authlete](https://github.com/authlete/cbor) `com.authlete:cbor` **1.19** | second, independent COSE_Sign1 parse and `COSEVerifier` oracle |
| `org.multipaz:multipaz-doctypes-jvm` **0.102.0** | `DrivingLicense` element types and mandatory elements |
| JDK PKIX | the chain-to-IACA trust decision (check `x5chain.iaca`) |
| `WireIssuerSignedItems` (this module) | the exact bytes each `Tagged(24, bstr)` item arrived as, which is what ISO/IEC 18013-5 9.1.2.5 hashes |

`IndependentMdocVerifier.verify(byte[] issuerSignedCbor, JWK expectedHolderKey, Optional<X509Certificate> iaca,
Instant at, Options options)` returns a `VerificationReport` of named checks, each `PASS`, `FAIL` or `SKIPPED`.

| Check | Rule |
| --- | --- |
| `issuerSigned.parse` | the IssuerSigned parses at all; a missing `issuerAuth` or `x5chain` is a failed check, not an exception |
| `issuerAuth.signature.multipaz`, `issuerAuth.signature.authlete` | COSE_Sign1 verifies with the `x5chain` (label 33) leaf, by both oracles; a tag-18 COSE_Sign1 (the draft-13 Document) is unwrapped, not re-encoded |
| `mso.payloadTag24` | the COSE payload is `#6.24(bstr .cbor MobileSecurityObject)` (9.1.2.4) |
| `mso.parse` | Multipaz's `MobileSecurityObject.fromDataItem` accepts the MSO as sent: a Multipaz-based wallet reads the credential through exactly this parser. Every other MSO check reads its fields from the wire with Multipaz's CBOR, so a refusal here does not cascade |
| `mso.nameSpaces` | Multipaz `IssuerNamespaces.validate` on the namespaces as received plus `validateAgainstMso` (when Multipaz has an MSO model): duplicate `elementIdentifier`, duplicate `digestID`, missing fields, salt length. Its errors fail, its warnings are reported |
| `mso.valueDigests` | every `IssuerSignedItem` hashes, **over the bytes as received**, to its `valueDigests` entry under the MSO's declared algorithm; every namespace in `nameSpaces` has a digest table; the verified count equals the item count |
| `mso.valueDigests.calculateDigest` | Multipaz's `IssuerSignedItem.calculateDigest` agrees — a second opinion only, because it re-encodes: a non-preferred encoding such as `18 00` for `0` passes here and fails `mso.valueDigests`, which is the point |
| `mso.valueDigests.digestIdsUnique` | `digestID`s unique within each namespace (9.1.2.5) |
| `mso.deviceKey` | `deviceKeyInfo.deviceKey` is the holder key by Multipaz's `CoseKey` and by the COSE labels: EC2 P-256/384/521 by x and y, OKP Ed25519 by x (kty 1, crv 6, no `y`; Nimbus cannot turn an OKP JWK into a JCA key, so x is the comparison); a COSE_Key carrying `d` (label -4) fails |
| `mso.docType` | equals the expected doctype |
| `mso.validityInfo` | ordered from the dates **as sent**, tagged or not: `signed <= validFrom < validUntil`, `validFrom <= expectedUpdate < validUntil`, `at` inside `validFrom..validUntil`; Multipaz must read the same instants, and its `MobileSecurityObject.validate` runs when it can read the MSO as sent. A repaired parse cannot decide the window |
| `mso.validityInfo.tdateTags` | `signed`, `validFrom`, `validUntil` and `expectedUpdate` are `#6.0(tstr)`, RFC 3339 with whole seconds and `Z`, a real calendar instant (9.1.2.4, gap G1) |
| `x5chain.iaca` | PKIX to the supplied IACA plus `X509CertChain.validate`; **strict mode without an IACA fails** rather than skipping |
| `x5chain.noSelfSigned` | no self-signed certificate in `x5chain` (HAIP) |
| `x5chain.serialNumber` | every `x5chain` serial is positive and at most 20 octets (RFC 5280 4.1.2.2; keymanager's are negative half the time, gap G27) |
| `mdl.elementTypes` | every problem with `org.iso.18013.5.1`, not the first: Table 5 mandatory elements, elements outside the doctype, types from Multipaz's `DrivingLicense` (`tstr`, `uint`, simple true/false, `bstr`), and Table 5 where Multipaz 0.102.0 disagrees: `issue_date`/`expiry_date` are full-date **or** tdate, `portrait_capture_date` is tdate, `driving_privileges` follows 7.2.4 (`vehicle_category_code`, full-date sub-dates, `codes[].code`). `full-date` is `#6.1004(tstr)` strictly parsed (`2026-99-99` fails), `tdate` as above; an unknown attribute type fails |

### Skipped is not passed

`VerificationReport.passed()` and `assertAllPassed()` only accept `PASS`. A check that did not run is `SKIPPED` and
still fails the assertion unless the caller names it: `assertAllPassed(Set.of(CHECK_TDATE_TAGS, ...))`.
`skippedNames()` exists so a test can assert *exactly* which checks were not performed — the interesting failure is a
check that quietly stopped running.

`Options.strict(doctype)` runs every check; the conformance run and the formatter's own baseline test use it and hold
the report to the sample's declared gaps (below). `Options.baseline(doctype)` skips the checks an open gap blocks (G1
untagged or fractional tdate, G2 element typing, G9 the trust anchor in `x5chain`, chain-to-IACA) and is what the
mutation tests use when the point is one specific check.

A check that throws reports the throw as its failure, `Error`s included (a Kotlin `NotImplementedError`, a
`StackOverflowError`); only a VM failure such as `OutOfMemoryError` propagates.

### Declared gaps: `AcceptedGaps` and the `.gaps` sidecar

Each sample carries the checks it is known not to pass yet, one per line with the reason and the work package that
fixes it:

```
mso.validityInfo.tdateTags # G1: signed/validFrom/validUntil carry milliseconds (UTC_DATETIME_PATTERN); fixed by M-02
x5chain.serialNumber? # G27: keymanager draws certificate serials from SecureRandom.nextLong(), negative in about half the runs; M-06/keymanager provider
```

`AcceptedGaps.assertMatches(report, sample)` fails on a check that does not pass and is not listed, and on a listed
check that passes ("gap no longer present, remove it from <sample>.gaps"), so the change that fixes a gap deletes
its line. A trailing `?` marks an intermittent gap: the product draws the failing value at random, the check still
runs, and it may pass or fail. Unknown check names and lines without a reason are refused.

## Samples, and the two other stacks

`MdocSamples.write(directory, producer, surface, credential, holder, docType, gaps)` records a credential as
`<TestClass>-<surface>` plus everything another verifier needs, raw CBOR and sidecars only (`certify-service` writes
the same files with its own `golden/MdocSampleWriter`, because it must not depend on this module):

| File | Content |
| --- | --- |
| `<name>.mdoc` | the credential exactly as issued: an `IssuerSigned`, or the draft-13 `Document {docType, issuerSigned}`, whose `issuerSigned` the readers slice out of the received bytes |
| `<name>.holder.jwk` | the holder public JWK, expected to equal the MSO deviceKey |
| `<name>.doctype` | the docType the credential configuration asked for |
| `<name>.gaps` | the checks the sample is known not to pass yet (`AcceptedGaps`) |
| `<name>.iaca.pem` | the IACA, written only when the chain carries a self-signed anchor behind the leaf |

The first write of a producer in a JVM deletes that producer's earlier samples. The producers are
`certify-format-mdoc`'s `MdocIndependentVerificationTest` (`formatter`, and `ed25519-fixture`: today's output re-signed
with an Ed25519 deviceKey, until M-02 lets the formatter bind one, gap G6) and `certify-service`'s
`IssuanceGoldenTest`/`IssuanceGoldenCoreTest` (`legacy`, `oid4vci`) and `D13GoldenReplayTest` (`d13`). Two consumers
read them:

- `certify-conformance-mdoc` re-verifies every sample with this module (see its README note: it must run after the
  producing tests, which the parent `<modules>` order guarantees in a reactor build);
- `.github/workflows/rebuild-ci.yml` installs `docs/design/tools/requirements-verify.txt` in a venv and runs
  `docs/design/tools/verify_mdoc.py` over every sample, passing the doctype, the IACA, the holder key and the gaps from
  the sidecars. It hashes the items over the bytes as received (SHA-256/384/512, pymdoccbor's SHA-256-only check as a
  second opinion) and fails on duplicate identifiers or digestIDs, a non-preferred `#6.24` head, an empty
  `nameSpaces`, a namespace the MSO has no digests for, a count mismatch, the validity order or tag 0, and a deviceKey
  that is not the holder JWK (EC2 or OKP); a failure of a check the `.gaps` sidecar lists is reported as accepted.

## Kotlin, on purpose

Multipaz is a Kotlin multiplatform library built against **Kotlin 2.2.21** and needs `kotlin.time.Instant`, which does
not exist in the 1.9.22 that Spring Boot 3.2's BOM pins. The parent POM keeps the pins in `multipaz.kotlin.version`
and `multipaz.kotlinx.coroutines.version`; this module's `dependencyManagement` applies them, and each *test-scope*
consumer declares `kotlin-stdlib` at that version for its own test classpath. That is the whole reason the verifier is
a separate module: an earlier attempt pinned the stdlib in `certify-service` itself, which changed what the product
ships. `docs/design/tools/check-runtime-classpath.sh` now diffs the service's resolved runtime classpath against
`certify-service/runtime-classpath.txt` and fails on any change.

`com.android.keyattestation:keyattestation` is declared by `multipaz-jvm` itself as a runtime dependency (the Android
flavour needs it, and it is not on Maven Central), so it is excluded here: the JVM verifier never calls it.

## Building the Kotlin-2.2.21 test classpath

A module that consumes this one resolves it from the reactor, so build them together:

```bash
mvn -B -ntp -pl certify-testkit-mdoc,certify-format-mdoc -am test -Dtest='*Mdoc*,WireIssuerSignedItems*' \
    -Dsurefire.failIfNoSpecifiedTests=false
mvn -B -ntp -pl certify-testkit-mdoc,certify-format-mdoc,certify-service,certify-conformance-mdoc -am test \
    -Dtest='IssuanceGolden*,*Mdoc*,*Conformance*,D13Golden*,WireIssuerSignedItems*' -Dsurefire.failIfNoSpecifiedTests=false
```

The module's own tests (`WireIssuerSignedItemsTest`: the CBOR framing matrix; `MdocVerifierRulesTest`: the date,
element, serial, runner and gap rules) need no other module.
