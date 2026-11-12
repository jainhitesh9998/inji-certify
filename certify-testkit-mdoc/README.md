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
| `issuerAuth.signature.multipaz`, `issuerAuth.signature.authlete` | COSE_Sign1 verifies with the `x5chain` (label 33) leaf, by both oracles |
| `mso.payloadTag24` | the COSE payload is `#6.24(bstr .cbor MobileSecurityObject)` (9.1.2.4) |
| `mso.nameSpaces` | Multipaz `IssuerNamespaces.validate` on the namespaces as received plus `validateAgainstMso`: duplicate `elementIdentifier`, duplicate `digestID`, missing fields, salt length. Its errors fail, its warnings are reported |
| `mso.valueDigests` | every `IssuerSignedItem` hashes, **over the bytes as received**, to its `valueDigests` entry under the MSO's declared algorithm; every namespace in `nameSpaces` has a digest table; the verified count equals the item count |
| `mso.valueDigests.calculateDigest` | Multipaz's `IssuerSignedItem.calculateDigest` agrees — a second opinion only, because it re-encodes: a non-preferred encoding such as `18 00` for `0` passes here and fails `mso.valueDigests`, which is the point |
| `mso.valueDigests.digestIdsUnique` | `digestID`s unique within each namespace (9.1.2.5) |
| `mso.deviceKey` | `deviceKeyInfo.deviceKey` is the holder key (EC2 P-256/384/521, OKP Ed25519) by Multipaz's parse and by the COSE labels; an OKP key must not carry a `y` label |
| `mso.docType` | equals the expected doctype |
| `mso.validityInfo` | `signed <= validFrom < validUntil`, `expectedUpdate` (when present) after `signed` and before `validUntil`, `at` inside `validFrom..validUntil`, plus Multipaz's own `MobileSecurityObject.validate` |
| `mso.validityInfo.tdateTags` | `signed`, `validFrom`, `validUntil` and `expectedUpdate` are `#6.0(tstr)` with whole seconds (9.1.2.4, gap G1) |
| `x5chain.iaca` | PKIX to the supplied IACA plus `X509CertChain.validate`; **strict mode without an IACA fails** rather than skipping |
| `x5chain.noSelfSigned` | no self-signed certificate in `x5chain` (HAIP) |
| `mdl.elementTypes` | element types and mandatory elements against Multipaz's `DrivingLicense`: `full-date` is `#6.1004(tstr)` `YYYY-MM-DD`, `tdate` is `#6.0`, `bool` is a simple true/false, numbers are `uint`, binaries are `bstr`, `driving_privileges` is an array of maps typed through its sub-attributes, and an unknown attribute type fails |

### Skipped is not passed

`VerificationReport.passed()` and `assertAllPassed()` only accept `PASS`. A check that did not run is `SKIPPED` and
still fails the assertion unless the caller names it: `assertAllPassed(Set.of(CHECK_TDATE_TAGS, ...))`.
`skippedNames()` exists so a test can assert *exactly* which checks were not performed — the interesting failure is a
check that quietly stopped running.

`Options.baseline(doctype)` runs everything today's output can already satisfy; the rest is skipped with the gap that
blocks it (G1 tdate precision, G2 element typing, G9 the trust anchor in `x5chain`, M-06 chain-to-IACA).
`Options.strict(doctype)` runs all of them and is the gate M-02/M-03/M-06 switch the default output over to.

## Samples, and the two other stacks

`MdocSamples.write(directory, name, issuerSignedCbor, holder, docType)` records a credential plus everything another
verifier needs, raw CBOR and sidecars only:

| File | Content |
| --- | --- |
| `<name>.mdoc` | the `IssuerSigned` exactly as issued |
| `<name>.holder.jwk` | the holder public JWK, expected to equal the MSO deviceKey |
| `<name>.doctype` | the docType the credential configuration asked for |
| `<name>.iaca.pem` | the IACA, written only when the chain carries a self-signed anchor behind the leaf |

The producing tests are `certify-format-mdoc`'s `MdocIndependentVerificationTest`
(`certify-format-mdoc/target/mdoc-samples/`) and `certify-service`'s `IssuanceGoldenTest` on both issuance paths
(`certify-service/target/mdoc-samples/`). Two consumers read them:

- `certify-conformance-mdoc` re-verifies every sample with this module (see its README note: it must run after the
  producing tests, which the parent `<modules>` order guarantees in a reactor build);
- `.github/workflows/rebuild-ci.yml` installs `docs/design/tools/requirements-verify.txt` in a venv and runs
  `docs/design/tools/verify_mdoc.py` over every sample, passing the doctype and the IACA from the sidecars. The script
  fails on an empty `nameSpaces`, on a namespace the MSO has no digests for, on a verified count that does not match
  the item count, and on a non-SHA-256 `digestAlgorithm` unless `--allow-partial` asks for a partial run.

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
mvn -B -ntp -pl certify-testkit-mdoc,certify-format-mdoc test -Dtest='*Mdoc*'
mvn -B -ntp -pl certify-testkit-mdoc,certify-service,certify-conformance-mdoc test -Dtest='*Mdoc*,*Conformance*'
```
