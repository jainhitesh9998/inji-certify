# P1-07 certify-format-mdoc

Branch: `wp/p1-07-mdoc-formatter` off `design/extensibility`. Phase 1. Size: M. Depends on: P1-01, P1-03, P1-11.

## Goal

`mso_mdoc` (ISO/IEC 18013-5) on the new core with the IssuerSigned structure the legacy path issues, the IssuerAuth through `certify-signing`, verified with plain JCA.

## Scope

- Module `certify-format-mdoc`: `MdocProcessor` is certify-service's `MDocProcessor` moved without its Spring, keymanager and certify-core dependencies (local constants, `MdocProperties` under `certify.format.mdoc.*` with the same defaults as `mosip.certify.mdoc.*`, `FormatException` instead of `CertifyException`, no `signMSO`); `MdocFormatter` builds the salted, digested namespaces and the MSO (device key from the holder's `did:jwk`), signs the IssuerAuth with `CoseEnvelope` and `CoseHeaderPolicy.mdocIssuerAuth()` (alg protected, x5chain unprotected, untagged) and returns the base64url CBOR IssuerSigned; `metadataFragment` = `format` + `doctype`. Auto-configured; wired into certify-service.
- `/oid4vci/credential` now issues `mso_mdoc` (new-surface golden: IssuerAuth verified with JCA against the x5chain leaf, MSO summary recorded).

## Not in this slice

The legacy `MDocCredential`/`MDocProcessor` stay for the compatibility path until P1-13; `x509` providers and `CertificateChainPolicy` for IACA-issued DSC chains (P3); DeviceResponse/presentation.

## Acceptance criteria

- [x] `MdocFormatterTest`: IssuerAuth verified with JCA against the embedded certificate, MSO fields, device key from the holder, template errors.
- [x] `IssuanceGoldenTest.oid4vciMdocIssuanceGoldenAndIndependentVerification`; legacy goldens unchanged; ArchUnit unchanged.
- [x] Full `certify-service` suite green: 893 tests.
