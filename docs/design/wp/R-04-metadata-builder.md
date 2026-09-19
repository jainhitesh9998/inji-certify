# R-04 Issuer metadata building out of the configuration service

Branch: `wp/r-04-metadata-builder` off `design/extensibility`. Refactor slice per `R-00-refactor-charter.md`, area "Configuration service" ("split metadata building from CRUD; keep the endpoints").

## What was wrong

`CredentialConfigurationServiceImpl` (509 lines) held two jobs: the v1 configuration CRUD with its validation, key-alias check and template storage, and the building of the compatibility surface's issuer metadata document (`/.well-known/openid-credential-issuer`) from the active rows, with the deployment's issuer, authorization servers, endpoints and display read from six `@Value` fields that only the second job used. The COSE algorithm table and a public `getCoseAlgorithm` sat in the same class for one caller.

## Files changed

| File | What was wrong | What changed |
| --- | --- | --- |
| `services/CredentialIssuerMetadataBuilder.java` (new) | | `build(rows)` returns the document: one `credential_configurations_supported` entry per row (`toSupportedDTO`, `standardClaims`, `mdocClaims`, `claim`), the signing algorithms per suite (COSE integers for mDoc, `coseAlgorithm` package-private), the deduplicated authorization servers, the endpoints and the display. The six metadata `@Value` fields and the signing-alg map moved here unchanged (same keys; no new lookups). |
| `services/CredentialConfigurationServiceImpl.java` | CRUD and metadata building in one class; six fields and eleven methods only the metadata half used | 345 lines: CRUD, validation, template storage and `protocolDefaults`; `fetchCredentialIssuerMetadata` keeps its filter (active rows of the default tenant) and delegates to the builder; unused imports gone |
| `test/.../CredentialConfigurationSupportedServiceImplTest.java` | set the metadata fields on the service by reflection | the same 45 tests; a real `CredentialIssuerMetadataBuilder` with the mapper mock is wired into the service in `setup`, the metadata fields are set on it, `mapToSupportedDTO` is invoked on it as `toSupportedDTO` |

No behaviour change: the compatibility metadata document is byte-identical (`IssuanceGoldenTest.issuerMetadataGolden`, `D13GoldenReplayTest`, `WellKnownControllerTest`).

## Acceptance criteria

- [x] `CredentialConfigurationSupportedServiceImplTest`, `WellKnownControllerTest`, `IssuanceGoldenTest`, `D13GoldenReplayTest`, `CredentialConfigurationV2Test` green; no golden changed.
- [x] Full `certify-service` suite green (1035, reverse order); CI: the integration-branch run after merge.
