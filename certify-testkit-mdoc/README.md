# certify-testkit-mdoc

The independent ISO/IEC 18013-5 verifier the mDoc tests lean on (work package **M-01** in
[`docs/design/20-mdl-issuer.md`](../../docs/design/20-mdl-issuer.md), decision **D9**). Certify's formatter tests
can only prove the writer agrees with itself; this module proves the bytes are readable by software Certify does
not maintain.

**Test-only.** Nothing in production depends on it. `certify-format-mdoc`, `certify-service` and their tests
consume it with `<scope>test</scope>`; its Kotlin dependencies therefore never reach a deployed artifact.

## What verifies what

| Stack | Used for |
| --- | --- |
| [OpenWallet Foundation Multipaz](https://github.com/openwallet-foundation/multipaz) `org.multipaz:multipaz-jvm` **0.102.0** (pinned) | CBOR, COSE_Sign1, MSO, `IssuerNamespaces`, `x5chain`, COSE_Sign1 signature, per-item digests, `X509CertChain.validate`, and `DrivingLicense` element types |
| [Authlete](https://github.com/authlete/cbor) `com.authlete:cbor` **1.19** | second, independent COSE_Sign1 parse and `COSEVerifier` oracle |
| `org.multipaz:multipaz-doctypes-jvm` **0.102.0** | `DrivingLicense` element types and mandatory elements |
| JDK PKIX | the chain-to-IACA trust decision (check 6) |

`IndependentMdocVerifier.verify(byte[] issuerSignedCbor, JWK expectedHolderKey, Optional<X509Certificate> iaca,
Instant at, Options options)` returns a `VerificationReport` of named, individually explained checks;
`assertAllPassed()` turns it into an `AssertionError` that lists the clauses that broke.

| Check | Rule |
| --- | --- |
| `issuerAuth.signature.multipaz`, `issuerAuth.signature.authlete` | COSE_Sign1 verifies with the `x5chain` (label 33) leaf, by both oracles |
| `mso.valueDigests` | every `IssuerSignedItem` digest (over the tag-24 encoded bytes) equals its `valueDigests` entry under the MSO's declared `digestAlgorithm` |
| `mso.valueDigests.digestIdsUnique` | `digestID`s unique within each namespace (9.1.2.5) |
| `mso.deviceKey` | `deviceKeyInfo.deviceKey` equals the holder JWK (EC2 P-256, OKP Ed25519) |
| `mso.docType` | equals the expected doctype |
| `mso.validityInfo` | parses; `signed <= at` within `validFrom..validUntil`; strict mode requires tag-0 seconds-only `tdate` |
| `x5chain.iaca` | when an IACA is passed: PKIX to that anchor plus `X509CertChain.validate` |
| `x5chain.noSelfSigned` | no self-signed certificate in `x5chain` (HAIP) |
| `mdl.elementTypes` | element types and mandatory elements match Multipaz's `DrivingLicense` for `org.iso.18013.5.1` |

`Options.baseline(doctype)` is what today's output passes; `Options.strict(doctype)` turns on the three rules
that need M-02 (seconds-only `tdate`, `x5chain` without anchor), M-03 (typed elements, binary portrait) and
M-06 (chain to the configured IACA). The tests that need those are `@Disabled` with the work package named.

## Kotlin, on purpose

Multipaz is a Kotlin multiplatform library built against **Kotlin 2.2.21** and needs `kotlin.time.Instant`, which
does not exist in the 1.9.22 that Spring Boot 3.2's BOM pins. The parent POM keeps the pin in
`multipaz.kotlin.version` (plus `multipaz.kotlinx.coroutines.version` and `multipaz.kotlinx.serialization.version`)
and this module's `dependencyManagement` applies them, so the Kotlin runtime is exactly Multipaz's. `certify-service`
declares the same stdlib version for its QR path (pixelpass needs `kotlin.text.HexExtensionsKt`, present in 2.x).

`com.android.keyattestation:keyattestation` (a runtime dependency of the Android flavour, not on Maven Central) is
excluded: the JVM verifier never calls it.

## Sample credentials and the CI second opinion

`MdocIndependentVerificationTest` writes what it verifies to `certify-format-mdoc/target/mdoc-samples/`
(`*.mdoc` raw CBOR, `*.b64url` text). `.github/workflows/rebuild-ci.yml` installs `pymdoccbor==1.4.0` in a venv and
runs `docs/design/tools/verify_mdoc.py` over every sample, so a credential must satisfy two independent stacks.
`pymdoccbor` computes SHA-256 digests only; the script says so when the MSO declares another algorithm.
