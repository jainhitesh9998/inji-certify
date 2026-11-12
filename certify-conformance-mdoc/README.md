# certify-conformance-mdoc

The cross-module mDoc conformance run of **M-01** ([`docs/design/20-mdl-issuer.md`](../../docs/design/20-mdl-issuer.md),
gap G24). It knows nothing about how a credential is written: it reads the `IssuerSigned` samples the other modules'
tests record and verifies each one with [`certify-testkit-mdoc`](../certify-testkit-mdoc/README.md) — Multipaz for the
CBOR, the MSO, the namespaces, the digests, the `x5chain` and the element types, Authlete for a second COSE_Sign1
oracle, and JDK PKIX for the chain to the IACA.

**Test-only.** Never published (`maven.deploy.skip`, `skipPublishing`), and it must never appear on the runtime
classpath of `certify-service`.

## Samples it verifies

| Directory | Written by |
| --- | --- |
| `../certify-service/target/mdoc-samples/` | `IssuanceGoldenTest` — both mDoc issuance paths through the running service (`/issuance/credential` and `/oid4vci/credential`) |
| `../certify-format-mdoc/target/mdoc-samples/` | `MdocIndependentVerificationTest` — the formatter's own output |

Each sample is `<name>.mdoc` (raw CBOR) plus `<name>.holder.jwk`, `<name>.doctype` and, when the chain carries one,
`<name>.iaca.pem`.

## Run it after the tests that write the samples

The parent POM lists this module after `certify-service` and `certify-format-mdoc`, so a reactor build runs the
producing tests first:

```bash
mvn -B -ntp -pl certify-testkit-mdoc,certify-format-mdoc,certify-service,certify-conformance-mdoc \
    -am test -Dtest='IssuanceGoldenTest,*Mdoc*,*Conformance*' -Dsurefire.failIfNoSpecifiedTests=false
```

`mvn -pl certify-conformance-mdoc test` on its own has nothing to verify: it resolves `certify-testkit-mdoc` from the
reactor, not from `~/.m2`, and the sample directories are empty unless the producing tests ran. Locally that is a
skipped test with a message; with `CI` set it is a failure, so a CI job that stopped producing samples goes red
instead of passing quietly.

## What it asserts

- every sample verifies with the independent stack, under the checks today's output can satisfy;
- the skipped checks are *exactly* the open gaps (`mso.validityInfo.tdateTags`, `x5chain.noSelfSigned`,
  `mdl.elementTypes`, and `x5chain.iaca` when the sample has no IACA sidecar) — a check that stopped running fails the
  test;
- no two modules write the same sample name.
