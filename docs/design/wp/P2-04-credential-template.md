# P2-04 credential_template: versioned templates read by the registry

Branch: `wp/p2-04-credential-template` off `design/extensibility`. Phase 2. Size: S. Depends on: P2-01, P2-02.

## Goal

The `credential_template` table the 1.1.0 migration fills becomes the template source: the registry reads the template a configuration names by `template_id` and `template_version` (decoded text, engine and mode from the row) and falls back to the legacy base64 `vc_template` only when no row exists; the v1 config API mirrors every template it writes as version 1.

## Scope

- `CredentialTemplate` entity (`@IdClass(CredentialTemplateId)` on `(id, version)`, the tenant a column) and `CredentialTemplateRepository` (`findByIdAndVersion`, `findFirstByIdOrderByVersionDesc`); the H2 test schema gains the table.
- `JpaConfigurationRegistry.template(row)`: the named template row first (`TemplateRef` with the row's engine, id, version, mode and decoded content), the blob as fallback; the Velocity engine already accepts plain text or base64.
- `CredentialConfigurationServiceImpl.storeTemplate`: on add and update, the base64 `vc_template` is decoded into `credential_template` version 1 (`velocity`, `FULL_DOCUMENT`, md5 checksum of the blob) and `template_id`/`template_version` are set; an update rewrites version 1 in place (versioning comes with the v2 API).
- Tests: `JpaConfigurationRegistryTest.templateRowIsPreferredOverTheBlobAndTheBlobIsTheFallback`; `IssuanceGoldenTest` asserts its configurations render from the table, so every golden proves the decoded text renders identically.

## Outside scope

Template versions above 1, `CLAIMS_ONLY` templates and the `jsonmap` engine through the table, the v2 config API.

## Acceptance criteria

- [x] Registry test green; every golden (`IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest`, `VcIssuancePluginGoldenTest`, `TenancyIssuanceTest`, `StatusListPostgresTest`) unchanged with templates read from the table.
- [x] Full `certify-service` suite green (965 tests, 0 failures).
- [ ] CI green on the fork.

## Rules that apply

- Nothing renamed or dropped: `vc_template` stays the v1 API's contract and the fallback (rule 3, rule 7).
