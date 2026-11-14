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
| `certify-format-mdoc/MdocIndependentVerificationTest-formatter` | the formatter's own output: the Table 5 mDL of `MdlFixtures`, a P-256 holder, a JCA DSC issued by a test IACA (`without-anchor`) |
| `certify-format-mdoc/MdocIndependentVerificationTest-ed25519` | the same for an Ed25519 holder, bound as the OKP deviceKey (G6, fixed by M-02) |
| `certify-service/IssuanceGoldenTest-legacy` | `POST /issuance/credential` on the legacy service |
| `certify-service/IssuanceGoldenTest-oid4vci` | `POST /oid4vci/credential` |
| `certify-service/IssuanceGoldenCoreTest-legacy`, `-oid4vci` | both paths with the compatibility path served by the core |
| `certify-service/D13GoldenReplayTest-d13` | the draft-13 surface: a `Document {docType, issuerSigned}` with a tag-18 IssuerAuth (0.14.0 wire compatibility, decision log 2026-09-19) |
| `certify-service/MdocStatusListSampleTest-oid4vci`, `-d13` | M-11e: an mDL that carries `status.status_list`, whose list is a CWT signed by its own Document Signer, through `/oid4vci` and through the draft-13 surface, against an `x509-file` dev-mode IACA |
| `certify-service/MdocStatusListSampleTest-revoked` | the same mDL after `POST /credentials/status` and the batch job: the re-signed list reports `1` (INVALID) at its index |

`VcIssuancePluginGoldenTest` is not a producer: its `mso_mdoc` credential is a plugin's opaque bytes, passed through.
Each sample is `<name>.mdoc` (the credential as received) plus `<name>.holder.jwk`, `<name>.doctype`, `<name>.gaps`
and, when the chain carries one, `<name>.iaca.pem`. A sample whose MSO carries `status.status_list` also carries the list
itself, `<name>.statuslist.cwt` (the body as served) with `<name>.statuslist.ct` (its `Content-Type`), and — when the list
must report something other than VALID at its index — `<name>.statuslist.status` (`0` VALID, the default when absent,
or `1` INVALID; ISO/IEC 18013-5 second edition 12.3.6.1 admits no other mDoc status).

## Run it after the tests that write the samples

The parent POM lists this module after `certify-service` and `certify-format-mdoc`, so a reactor build runs the
producing tests first:

```bash
mvn -B -ntp -pl certify-testkit-mdoc,certify-format-mdoc,certify-service,certify-conformance-mdoc \
    -am test -Dtest='IssuanceGolden*,*Mdoc*,*Conformance*,D13Golden*,WireIssuerSignedItems*,*Gaps*,ProblemCodeRegistry*' \
    -Dsurefire.failIfNoSpecifiedTests=false
```

Surefire passes the reactor's start (`maven.build.timestamp`) as `mdoc.samples.buildStart`. A sample older than that
was not written by this build: with `CI` set it fails the run, locally it is reported and skipped. So
`mvn -pl certify-conformance-mdoc test` on its own verifies nothing (a skipped test with a message), and with `CI` set
it fails.

## What it asserts

- every current sample, verified as received (`Options.strict`), reports exactly the problem codes its `.gaps`
  sidecar declares: a reported `<check>:<code>` the sidecar does not list fails, a listed one no longer reported fails
  with "gap no longer present, remove ... from <sample>.gaps", and a skipped check fails. One accepted problem cannot
  hide another in the same check (an expired credential fails with G8's `signedAfterValidFrom` declared). The
  declared gaps per sample are listed in `docs/design/20-mdl-issuer.md` M-01;
- a draft-13 sample declares its two 0.14.0 shape deviations, `credential.shape:documentWrapper` and
  `issuerAuth.untagged:tagged`, and its `Document.docType` must equal the MSO's (`mso.docType:documentMismatch`
  otherwise); the legacy and `/oid4vci` samples pass both shape checks;
- with `CI` set: exactly the samples in `EXPECTED_SAMPLES`, all written after the build started.
