# P2-06 The v2 configuration API with a preview dry run

Branch: `wp/p2-06-config-api-v2` off `design/extensibility`. Phase 2. Size: M. Depends on: P2-02 (v2 columns and read path), P2-04 (`credential_template`), P2-03 (tenant of the request).

## Goal

The Phase 2 exit criterion "`/v2/credential-configurations` with typed `FormatConfig` and `/preview`" (docs/design/11-roadmap.md): operators write the domain model the new core reads (the 1.1.0 JSONB columns) instead of the v1 column-per-field DTO, templates are versioned, and a configuration is rendered through the core before it is committed so a broken template is refused at save time, not at the first wallet request (docs/design/07-templating.md).

## Scope

- `POST`, `GET`, `GET /{id}`, `PUT /{id}`, `DELETE /{id}` on `/v2/credential-configurations` (`CredentialConfigurationV2Controller`, `CredentialConfigurationV2Service`), scoped to the tenant of the request (`AuthorizationContext.getTenantId()`, the `TenantResolver` of P2-03).
- The model (`CredentialConfigurationV2`): `id`, `scope`, `format`, `formatConfig` (the `format_config` column as is: `context`, `types`, `claims`, `vct`, `sdClaims`, `sdJwtClaims`, `doctype`, `mdocClaims`), `signing` (`provider`, `alias`, `alg`, `cryptosuite`, `didUrl`), `template` (`engine`, `mode`, `content`, read-only `version`), `issuanceStrategy`, `dataSourceId`, `status` (`mechanism`, `purposes`), `display` (`display`, `order`), `protocol` (the three metadata lists plus `overrides`, deployment defaults when absent), `qr`, `pluginConfigurations`, write-only `sampleClaims`; read-only `configId`, `active`, `configVersion`, timestamps.
- Every write fills the JSONB columns and mirrors every legacy column (`CredentialConfigurationV2Mapper.apply`: comma-joined `context`/`credential_type`, `key_manager_app_id`/`ref_id` from the alias, `vc_template` as base64 for Velocity full documents, `claims`, `display`, the metadata lists), so the v1 API, the compatibility surfaces, the draft-13 adapter and the metadata builders see the row unchanged; `config_version` is 2.
- Templates: content goes to `credential_template` under the row's `config_id`; a changed content, engine or mode becomes the next version and the row points at it; unchanged content keeps its version.
- Dry run: a body with `sampleClaims` is rendered and built through the core (`IssuanceService.preview`, new on the interface, implemented by `DefaultIssuanceService` as render plus build without status, pre-sign listeners or signing) inside the write transaction; a failure answers `400 template_render_failed` and rolls the row back. `POST /{id}/preview` (`claims`, optional `holder`) runs the same on a saved row and returns the unsigned document.
- Errors: HTTP 400 `invalid_configuration`, `unsupported_format`, `unsupported_signature_algorithm`, `unknown_template_engine`, `template_render_failed`; 404 `configuration_not_found`; 409 `configuration_exists` (duplicate id or selector per tenant), as `{error, error_description}`.
- Security: the path matches the existing `**/credential-configurations/**` patterns in both URL lists, so no list changes (rule 9).
- Test `CredentialConfigurationV2Test`: create, mirrored columns, v1 `GET`, issuer metadata, issuance through `/oid4vci/credential`, preview, template version 2 on a changed template and unchanged on a repeat, list, delete; every refusal code and the rollback of a broken template.

## Outside scope

Typed per-format `FormatConfig` classes on the API (the raw `format_config` map is the contract for now; the formatters parse it), JSON Schema output validation of the preview, `CertificateChainPolicy` at save time (P3), per-tenant writes from another tenant's request, deprecating the v1 API (1.2.0 per docs/design/09), OpenAPI documentation of the new paths.

## Acceptance criteria

- [x] `CredentialConfigurationV2Test` green; `IssuanceGoldenTest` and the architecture tests green; no golden changed.
- [x] Full `certify-service` suite green (971 tests, 0 failures).
- [ ] CI green on the fork.
- [x] Decision logged: model shape, error shape, template versioning, dry run only with `sampleClaims`.
