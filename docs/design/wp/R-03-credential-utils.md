# R-03 One `CredentialUtils`, helpers next to their only caller

Branch: `wp/r-03-credential-utils` off `design/extensibility`. Refactor slice per `R-00-refactor-charter.md`, area "Legacy issuance orchestration" (cheap cleanups only; the legacy services go with the compat-core flip).

## What was wrong

Two classes named `CredentialUtils` in two packages (`services`, `utils`), one holding a single SVG digest helper, the other a grab-bag of five static helpers of which one was dead and three had exactly one caller each; `VCIssuanceUtil.validateAndGetClientNonce` took the caller's `Logger` as a parameter although the class has its own.

## Files changed

| File | What was wrong | What changed |
| --- | --- | --- |
| `services/CredentialUtils.java` | A second class of the same name for one method | deleted; `getDigestMultibase` moved to `utils/CredentialUtils` |
| `utils/CredentialUtils.java` | `isVC2_0Request` unused in main code; `generateLdProof`, `generateDataIntegrityProof` used only by `W3CJsonLD`; `toJsonMap` used only by `CertifyIssuanceServiceImpl` | keeps `getTemplateName` (three callers) and `getDigestMultibase` (two callers); final class, private constructor, javadoc that says what the keys are |
| `credential/W3CJsonLD.java` | Its two proof-building steps lived in a utils class | `generateLdProof` and `generateDataIntegrityProof` are private static methods here, unchanged in body |
| `services/CertifyIssuanceServiceImpl.java` | `toJsonMap` imported statically from utils | private static method here; the `String` and `Map` branches that both called `JSONObject.wrap` are one branch |
| `services/VCIssuanceServiceImpl.java`, `services/CertifyIssuanceServiceImpl.java` | passed `log` into a static helper | call `validateAndGetClientNonce(cache, proof, nonceEndpoint)` |
| `utils/VCIssuanceUtil.java` | `Logger log` parameter shadowing the class logger | parameter removed |
| `vcformatters/VelocityTemplatingEngineImpl.java`, `oid4vci/RenderMethodDigestListener.java` | imported `services.CredentialUtils` | import `utils.CredentialUtils` |
| `test/.../services/RenderUtilsTest.java`, `test/.../utils/CredentialUtilsTest.java` | one test class per helper class, mixed JUnit 4 and 5 annotations | one JUnit 4 test class: template names and the digest (value and missing algorithm); the dead helper's test is gone |

No behaviour change: the template keys, the digest, the LD proofs, the template model and the nonce checks are byte-identical (goldens).

## Acceptance criteria

- [x] `CredentialUtilsTest`, `IssuanceGoldenTest`, `D13GoldenReplayTest`, `VcIssuancePluginGoldenTest` and the legacy service tests green; no golden changed.
- [x] Full `certify-service` suite green (1035, reverse order); CI: the integration-branch run after merge.
