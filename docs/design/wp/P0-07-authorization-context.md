# P0-07 Request-scoped AuthorizationContext replacing the singleton ParsedAccessToken

Branch: `wp/p0-07-authorization-context` off `develop`. Phase 0 (guardrails). Size: S. Depends on: P0-01.

## Goal

Remove the request-state-in-a-singleton coupling first, because every later WP touches the classes that read it.

## Scope

- Introduce `AuthorizationContext` (claims, token hash, scheme, active, tenantId=`default`) as a `@RequestScope` bean (proxy mode) written by `AccessTokenValidationFilter` and `LocalAccessTokenValidationFilter`.
- Keep `ParsedAccessToken` as a delegating shim that reads from the request-scoped bean, so no other class changes in this WP; mark it `@Deprecated`.
- Cover with a concurrency test: two parallel requests with different tokens never see each other's claims.

## Acceptance criteria

- [ ] Goldens (P0-01) unchanged.
- [ ] Concurrency test passes.
- [ ] `PreAuthIssuanceServiceImpl` still works through the shim.

## Rules that apply

- Zero wire-byte change: goldens and signature vectors stay green.
- No edits outside the files this WP names without a note in the PR.
- Record any decision taken in `docs/design/12-risks-and-decisions.md`.
- Read `CLAUDE.md`, then `docs/design/05-target-architecture.md` and the section that owns this WP.
