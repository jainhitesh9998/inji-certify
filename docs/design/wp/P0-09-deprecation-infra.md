# P0-09 Deprecation headers, counters and kill switches

Branch: `wp/p0-09-deprecation-infra` off `develop`. Phase 0 (guardrails). Size: S. Depends on: none.

## Goal

Provide the mechanism every later deprecation uses, before any endpoint is deprecated.

## Scope

- A `@DeprecatedEndpoint(name, sunset)` annotation and a `HandlerInterceptor` that adds `Deprecation`, `Sunset` and `Link` headers, increments `certify.deprecated.calls{endpoint}` (Micrometer) and logs at most once per hour per endpoint.
- `mosip.certify.deprecated.<name>.enabled=false` returns `410 Gone` with a JSON error naming the replacement.
- OpenAPI: mark annotated handlers `deprecated: true` automatically.

## Acceptance criteria

- [ ] Unit tests for headers, counter, hourly log throttle and kill switch.
- [ ] No endpoint is annotated yet in this WP.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
