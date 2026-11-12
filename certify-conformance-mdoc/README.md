# certify-conformance-mdoc

The cross-module mDoc conformance run of **M-01** ([`docs/design/20-mdl-issuer.md`](../../docs/design/20-mdl-issuer.md),
gap G24). It knows nothing about how a credential is written: it reads the `IssuerSigned` samples the other modules'
tests record and verifies each one with [`certify-testkit-mdoc`](../certify-testkit-mdoc/README.md) — Multipaz for the
CBOR, the MSO, the namespaces, the digests, the `x5chain` and the element types, Authlete for a second COSE_Sign1
oracle, and JDK PKIX for the chain to the IACA.

**Test-only.** Never published (`maven.deploy.skip`, `skipPublishing`), and it must never appear on the runtime
classpath of `certify-service`.

## Samples it verifies

| Sample (`<module>/<TestClass>-<surface>`) | Written by |
| --- | --- |
| `certify-format-mdoc/MdocIndependentVerificationTest-formatter` | the formatter's own output (JCA dev key) |
| `certify-format-mdoc/MdocIndependentVerificationTest-ed25519-fixture` | the same, re-signed with an Ed25519 deviceKey (the formatter cannot bind one yet, G6) |
| `certify-service/IssuanceGoldenTest-legacy` | `POST /issuance/credential` on the legacy service |
| `certify-service/IssuanceGoldenTest-oid4vci` | `POST /oid4vci/credential` |
| `certify-service/IssuanceGoldenCoreTest-legacy`, `-oid4vci` | both paths with the compatibility path served by the core |
| `certify-service/D13GoldenReplayTest-d13` | the draft-13 surface: a `Document {docType, issuerSigned}` with a tag-18 IssuerAuth |

`VcIssuancePluginGoldenTest` is not a producer: its `mso_mdoc` credential is a plugin's opaque bytes, passed through.
Each sample is `<name>.mdoc` (the credential as received) plus `<name>.holder.jwk`, `<name>.doctype`, `<name>.gaps`
and, when the chain carries one, `<name>.iaca.pem`.

## Run it after the tests that write the samples

The parent POM lists this module after `certify-service` and `certify-format-mdoc`, so a reactor build runs the
producing tests first:

```bash
mvn -B -ntp -pl certify-testkit-mdoc,certify-format-mdoc,certify-service,certify-conformance-mdoc \
    -am test -Dtest='IssuanceGolden*,*Mdoc*,*Conformance*,D13Golden*,WireIssuerSignedItems*' -Dsurefire.failIfNoSpecifiedTests=false
```

Surefire passes the reactor's start (`maven.build.timestamp`) as `mdoc.samples.buildStart`. A sample older than that
was not written by this build: with `CI` set it fails the run, locally it is reported and skipped. So
`mvn -pl certify-conformance-mdoc test` on its own verifies nothing (a skipped test with a message), and with `CI` set
it fails.

## What it asserts

- every current sample passes every check (`Options.strict`) except exactly the gaps its `.gaps` sidecar declares: an
  unlisted failure fails, and a listed gap that passes fails with "gap no longer present, remove it from
  <sample>.gaps" (a `?` gap, drawn at random by the product, may do either);
- a draft-13 `Document`'s `docType` equals the configured one;
- with `CI` set: exactly the samples in `EXPECTED_SAMPLES`, all written after the build started.
