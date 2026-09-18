# P1-08 TemplateEngine (first slice): Velocity as a module behind the SPI

Branch: `wp/p1-08-template-engine` off `design/extensibility`. Phase 1. Size: M. Depends on: P1-01.

## Goal

Templating becomes a pluggable seam without changing a rendered byte: the Velocity setup certify-service has always used lives in its own module, implements `io.mosip.certify.spi.TemplateEngine` for the new core, and the legacy `VCFormatter` renders through the same engine instance.

## Scope (this slice)

- Module `certify-template-velocity` (Velocity 1.7 + velocity-tools-generic 3.1, the versions certify-service pins): `VelocityRenderer` (UTF-8 in/out, `_dateTool` and `_esc` added when absent), `VelocityTemplateEngine` (`id = velocity`, modes FULL_DOCUMENT and CLAIMS_ONLY; the model reaches the template as today's templates expect: claims by name, `_issuer`, `_holderId`, `validFrom`/`validUntil` and `_validFrom`/`_validUntil` in Certify's timestamp form, template params; base64 or inline content; output must be a JSON object, otherwise `FormatException(template_render_failed)`), `VelocityTemplateAutoConfiguration` (rule 10).
- `VelocityTemplatingEngineImpl` (`VCFormatter`) no longer owns a `VelocityEngine`: `format` and `formatQRData` evaluate through the injected `VelocityRenderer` (created locally when no bean is present, so the 22 existing unit tests run unchanged). Its configuration lookups stay.

## Not in this slice

The `jsonmap` engine and the no-template path, engine selection per configuration (`TemplateRef.engine`), and moving the SD-JWT/mDoc claims mapping into the engines (decision log: standard claims mapping for those formats). `VCFormatter` keeps reading `credential_config` until the formatters (P1-05..07) take over.

## Acceptance criteria

- [x] Goldens unchanged (every template still renders byte-identically through the shared renderer).
- [x] `VelocityTemplateEngineTest`: model mapping, base64 content, params, tools, error reporting.
- [x] `VelocityTemplatingEngineImplTest` unchanged and green; ArchUnit unchanged (the "template engines do not read repositories" frozen list neither grows nor is touched).
- [x] Full `certify-service` suite green: 879 tests.
