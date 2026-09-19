# R-05 Legacy credential classes: no kernel signing path, no shadowed fields, no unused parameter

Branch: `wp/r-05-credential-classes` off `design/extensibility`. Refactor slice per `R-00-refactor-charter.md`, area "Formats and templating (legacy)", smallest files first (`credential/*`).

## What was wrong

`Credential` (the base of `W3CJsonLD`, `SDJWT`, `MDocCredential`) took MOSIP keymanager's `SignatureService` in its constructor for a base `addProof` that signed through the kernel's `jwsSign`; every subclass overrides `addProof`, so that path and the constructor parameter were dead, and they kept `io.mosip.kernel` imports in the credential package (rule 2 wants them only in the keymanager module). `W3CJsonLD` declared its own `SignatureServicev2 signatureService`, shadowing the base field and never read. `SDJWT` and `W3CJsonLD` each re-declared the `KeyProviderRegistry` the base already injects. `addProof` took a `headers` argument that every caller passed as `""` or `null` and no implementation read.

## Files changed

| File | What was wrong | What changed |
| --- | --- | --- |
| `credential/Credential.java` | kernel `SignatureService` field and constructor parameter; a dead base `addProof` through the kernel; `keyProviders` private though subclasses need it | constructor `Credential(VCFormatter)`; `addProof` abstract with the `headers` parameter gone; `keyProviders` protected; no kernel imports |
| `credential/W3CJsonLD.java` | unused shadowing `SignatureServicev2` field, duplicate `KeyProviderRegistry`, kernel imports | removed; constructor `W3CJsonLD(VCFormatter)` |
| `credential/SDJWT.java` | duplicate `KeyProviderRegistry`, kernel import | removed; constructor `SDJWT(VCFormatter)` |
| `credential/MDocCredential.java` | kernel import for the constructor | constructor `MDocCredential(VCFormatter)` |
| `services/CertifyIssuanceServiceImpl.java`, `services/StatusListCredentialService.java` | passed `""` as headers | six-argument `addProof` |
| `test/.../credential/*Test.java`, `services/CertifyIssuanceServiceImplTest.java`, `services/StatusListCredentialServiceTest.java` | mocks of the kernel service, the base-class signing test, seven-argument stubs | the mocks and kernel imports are gone, the dead test with them; the anonymous `Credential` in `CredentialTest` implements the abstract method; stubs have six arguments |

No behaviour change: the LD, SD-JWT and mDoc signing paths already went through `certify-signing`; goldens unchanged. The credential package imports nothing from `io.mosip.kernel` now.

## Acceptance criteria

- [x] `CredentialTest`, `MDocCredentialTest`, `SDJWTTest`, `W3CJsonLDTest`, `CertifyIssuanceServiceImplTest`, `StatusListCredentialServiceTest`, `IssuanceGoldenTest`, `D13GoldenReplayTest`, `VcIssuancePluginGoldenTest` green; no golden changed.
- [x] Full `certify-service` suite green (1034, reverse order); CI: the integration-branch run after merge.
