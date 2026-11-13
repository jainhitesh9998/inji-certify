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

`IndependentMdocVerifier.verify(byte[] credential, JWK expectedHolderKey, Optional<X509Certificate> iaca,
Instant at, Options options)` takes the credential as a wallet received it (a bare `IssuerSigned`, or the draft-13
`Document {docType, issuerSigned}`, whose `issuerSigned` is read from the received bytes) and returns a
`VerificationReport` of named checks, each `PASS`, `FAIL` or `SKIPPED`. A failed check carries **every** problem it
found, each under a stable problem code (`VerificationReport.Problem`); `IndependentMdocVerifier.PROBLEM_CODES` is the
whole table, and a code ending in `:*` takes a parameter (`untyped:birth_date`, `fractionalSeconds:signed`,
`selfSigned:0`). A check reports `error` when it throws unexpectedly and `notRun` when the credential did not parse;
neither can be an accepted gap.

| Check | Rule | Problem codes |
| --- | --- | --- |
| `credential.shape` | the credential is the bare `IssuerSigned` OpenID4VCI Appendix A.2 returns, not the draft-13 `Document {docType, issuerSigned}` | `documentWrapper` |
| `issuerSigned.parse` | the IssuerSigned parses at all (no top-level key or namespace twice, every item `#6.24`); a missing `issuerAuth` or `x5chain` is a failed check, not an exception | `malformed` |
| `issuerAuth.untagged` | IssuerAuth is the untagged `COSE_Sign1` (ISO/IEC 18013-5 9.1.2.4; RFC 9052 4.2 tags it only as `#6.18`) | `tagged` |
| `issuerAuth.signature.multipaz`, `issuerAuth.signature.authlete` | COSE_Sign1 verifies with the `x5chain` (label 33) leaf, by both oracles; a tag-18 COSE_Sign1 (the draft-13 Document) is unwrapped, not re-encoded | `noAlg`, `unsupportedAlg`, `invalid`; `notCoseSign1`, `noX5chain`, `invalid` |
| `mso.payloadTag24` | the COSE payload is `#6.24(bstr .cbor MobileSecurityObject)` (9.1.2.4) | `notTag24` |
| `mso.parse` | Multipaz's `MobileSecurityObject.fromDataItem` accepts the MSO as sent: a Multipaz-based wallet reads the credential through exactly this parser. Every other MSO check reads its fields from the wire with Multipaz's CBOR, so a refusal here does not cascade | `refused` |
| `mso.nameSpaces` | the namespaces as received: not empty, no empty namespace, each in `valueDigests`, no `elementIdentifier` twice; then Multipaz `IssuerNamespaces.validate` plus `validateAgainstMso` (when Multipaz has an MSO model), whose warnings are reported | `empty`, `emptyNamespace:<ns>`, `noValueDigests:<ns>`, `duplicateIdentifier:<ns>/<id>`, `multipazStructural`, `multipazAgainstMso` |
| `mso.valueDigests` | every `IssuerSignedItem` hashes, **over the bytes as received**, to its `valueDigests` entry under the MSO's declared algorithm; every `#6.24` head is the preferred encoding; the wire item count equals Multipaz's | `badAlgorithm`, `empty`, `noItems`, `nonPreferredHead:<ns>/<id>`, `noNamespace:<ns>`, `noEntry:<ns>/<id>`, `mismatch:<ns>/<id>`, `duplicateHidden` |
| `mso.valueDigests.calculateDigest` | Multipaz's `IssuerSignedItem.calculateDigest` agrees — a second opinion only, because it re-encodes: a non-preferred encoding such as `18 00` for `0` passes here and fails `mso.valueDigests`, which is the point | `badAlgorithm`, `noEntry:<ns>/<id>`, `mismatch:<ns>/<id>` |
| `mso.valueDigests.digestIdsUnique` | `digestID`s unique within each namespace (9.1.2.5) | `duplicate:<ns>/<digestID>` |
| `mso.deviceKey` | `deviceKeyInfo.deviceKey` is the holder key by the COSE labels and by Multipaz's `CoseKey`: EC2 P-256/384/521 by x and y, OKP Ed25519 by x (kty 1, crv 6, no `y`; Nimbus cannot turn an OKP JWK into a JCA key, so x is the comparison); a COSE_Key carrying `d` (label -4) fails | `noHolder`, `unsupportedHolder`, `missing`, `privateKey`, `kty`, `crv`, `x`, `y`, `yOnOkp`, `multipazUnreadable`, `multipazMismatch` |
| `mso.docType` | equals the expected doctype, and a draft-13 `Document`'s `docType` equals the MSO's | `missing`, `mismatch`, `documentMismatch` |
| `mso.validityInfo` | ordered from the dates **as sent**, tagged or not, every rule evaluated: `signed <= validFrom < validUntil`, `validFrom <= expectedUpdate < validUntil`, `at` inside `validFrom..validUntil`; Multipaz must read the same instants, and its `MobileSecurityObject.validate` findings (when it can read the MSO as sent) map onto the same codes. A repaired parse cannot decide the window | `missing:<field>`, `notDate:<field>`, `signedAfterValidFrom`, `validFromNotBeforeValidUntil`, `expectedUpdateBeforeValidFrom`, `expectedUpdateNotBeforeValidUntil`, `notYetValid`, `expired`, `multipazDisagrees:<field>`, `multipazRejects` |
| `mso.validityInfo.tdateTags` | `signed`, `validFrom`, `validUntil` and `expectedUpdate` are `#6.0(tstr)`, RFC 3339 with whole seconds and `Z`, a real calendar instant (9.1.2.4, gap G1); each field and each way it misses is its own code | `missing:<field>`, `untagged:<field>`, `notTdate:<field>`, `notRfc3339:<field>`, `fractionalSeconds:<field>`, `notZulu:<field>`, `notCalendar:<field>` |
| `x5chain.iaca` | each certificate issued by the next, the last by the supplied IACA, all valid at `at`; then JDK PKIX and `X509CertChain.validate`; **strict mode without an IACA fails** rather than skipping | `noAnchorSupplied`, `onlyAnchor`, `notIssuedBy:<i>`, `notAnchored`, `notValidAt:<i>`/`notValidAt:anchor`, `pkix:<reason>`, `multipaz` |
| `x5chain.noSelfSigned` | no self-signed certificate in `x5chain` (HAIP) | `selfSigned:<i>` |
| `x5chain.serialNumber` | every `x5chain` serial is positive and at most 20 octets (RFC 5280 4.1.2.2; keymanager's are negative half the time, gap G27) | `nonPositive`, `zero` (also non-positive), `tooLong` |
| `mdl.elementTypes` | every problem with `org.iso.18013.5.1`, not the first: Table 5 mandatory elements, elements outside the doctype, types from Multipaz's `DrivingLicense` (`tstr`, `uint`, simple true/false, `bstr`), and Table 5 where Multipaz 0.102.0 disagrees: `issue_date`/`expiry_date` are full-date **or** tdate, `portrait_capture_date` is tdate, `driving_privileges` follows 7.2.4 (`vehicle_category_code`, full-date sub-dates, `codes[].code`). `full-date` is `#6.1004(tstr)` strictly parsed (`2026-99-99` fails), `tdate` as above; an unknown attribute type fails | `noNamespace`, `missing:<id>`, `untyped:<id>`, `notInDocType:<id>`, `unmodelled:<id>` |

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

Each sample carries the problems it is known to have, one problem code per line with the reason and the work package
that fixes it:

```
x5chain.iaca:noAnchorSupplied # G13: the keymanager x5chain is the master-signed leaf alone, there is no IACA to anchor it; M-06
x5chain.serialNumber:nonPositive # G27: keymanager drew this serial from SecureRandom.nextLong(); M-06/keymanager provider
mso.validityInfo.tdateTags:fractionalSeconds:signed # G1: the legacy utils.MDocProcessor writes milliseconds; legacy path only
mdl.elementTypes:untyped:portrait # G2: the legacy utils.MDocProcessor writes the base64 portrait as a tstr; legacy path only
```

The lines M-02/M-03 removed (G1 and G8 on the core path, G3's `missing:*`, G9's `selfSigned:0`) are listed per sample in
[`docs/design/20-mdl-issuer.md`](../docs/design/20-mdl-issuer.md) M-01.

`AcceptedGaps.assertMatches(report, sample)` fails on a reported problem whose `<check>:<code>` is not listed, on a
listed code the check no longer reports ("gap no longer present, remove ... from <sample>.gaps"), and on any skipped
check. A gap names one problem, never a whole check: with `mso.validityInfo:signedAfterValidFrom` declared, an expired
credential still fails on `mso.validityInfo:expired`, and a new `mdl.elementTypes:untyped:family_name` fails next to
the declared `missing:*` lines. A bare check name, the old `?` marker, an unknown check or code, `error`/`notRun` and a
line without a reason are refused. There is no optional gap: a producer whose output varies from run to run decides
from the bytes it wrote (`certify-service`'s `MdocSampleWriter` declares `x5chain.serialNumber:nonPositive` exactly
when the received leaf serial is `<= 0`; `zero` and `tooLong` are separate codes nobody declares), so the gate is exact
on every run.

## Samples, and the two other stacks

`MdocSamples.write(directory, producer, surface, credential, holder, docType, gaps)` records a credential as
`<TestClass>-<surface>` plus everything another verifier needs, raw CBOR and sidecars only (`certify-service` writes
the same files with its own `golden/MdocSampleWriter`, because it must not depend on this module):

| File | Content |
| --- | --- |
| `<name>.mdoc` | the credential exactly as issued: an `IssuerSigned`, or the draft-13 `Document {docType, issuerSigned}`, whose `issuerSigned` the readers slice out of the received bytes |
| `<name>.holder.jwk` | the holder public JWK, expected to equal the MSO deviceKey |
| `<name>.doctype` | the docType the credential configuration asked for |
| `<name>.gaps` | the problems the sample is known to have, one `<check>:<code> # <reason>` per line (`AcceptedGaps`) |
| `<name>.iaca.pem` | the IACA, written only when the chain carries a self-signed anchor behind the leaf |

The first write of a producer in a JVM deletes that producer's earlier samples. The producers are
`certify-format-mdoc`'s `MdocIndependentVerificationTest` (`formatter` and `ed25519`: the formatter's own output for a
P-256 and an Ed25519 holder, signed by a DSC whose IACA stays out of the x5chain) and `certify-service`'s
`IssuanceGoldenTest`/`IssuanceGoldenCoreTest` (`legacy`, `oid4vci`) and `D13GoldenReplayTest` (`d13`). Two consumers
read them:

- `certify-conformance-mdoc` re-verifies every sample with this module (see its README note: it must run after the
  producing tests, which the parent `<modules>` order guarantees in a reactor build);
- `.github/workflows/rebuild-ci.yml` installs `docs/design/tools/requirements-verify.txt` in a venv on Python 3.12
  (`actions/setup-python`), runs `docs/design/tools/test_verify_mdoc.py`, and runs `docs/design/tools/verify_mdoc.py`
  over every sample, passing the doctype, the IACA, the holder key and the gaps from the sidecars. It reports the
  **same problem codes** for the rules it implements (its `PROBLEM_CODES` table is held to this module's by
  `ProblemCodeRegistryTest`): it hashes the items over the bytes as received (SHA-256/384/512, pymdoccbor's
  SHA-256-only check as a second opinion), and checks the shape, the IssuerAuth tag, the pymdoccbor signature, the
  namespaces, digestIDs, deviceKey, docType, window, tdate encoding, chain, self-signed certificates and serials. A
  reported problem the sidecar does not list fails, and so does a listed code of a rule it implements that is no longer
  reported; codes only this module reports (Multipaz, Authlete, PKIX, Table 5 typing) are notes there. Then every
  mutation under `target/mdoc-mutations/` (today: `MdocIndependentVerificationTest-expired-g8`, an expired re-signed
  credential with only G8 declared) must fail on the problem its `.expect` sidecar names.

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
    -Dtest='IssuanceGolden*,*Mdoc*,*Conformance*,D13Golden*,WireIssuerSignedItems*,*Gaps*,ProblemCodeRegistry*' \
    -Dsurefire.failIfNoSpecifiedTests=false
```

The module's own tests (`WireIssuerSignedItemsTest`: the CBOR framing matrix; `MdocVerifierRulesTest`: the date,
element, serial, runner, problem-code and gap rules; `ProblemCodeRegistryTest`: `verify_mdoc.py` knows the same codes)
need no other module.
