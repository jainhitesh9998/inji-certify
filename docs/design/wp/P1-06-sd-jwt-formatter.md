# P1-06 certify-format-sd-jwt

Branch: `wp/p1-06-sd-jwt-formatter` off `design/extensibility`. Phase 1. Size: M. Depends on: P1-01, P1-03, P1-11.

## Goal

`dc+sd-jwt` (alias `vc+sd-jwt`) on the new core with the same payload shape and header the legacy path issues, the issuer JWS through `certify-signing`, verified by Nimbus and authlete's disclosure digests.

## Scope

- Module `certify-format-sd-jwt`: `SdJwtFormatter` — `build` turns the rendered document into the SD-JWT payload with `vct` (configuration), `iss` (the tenant's issuer identifier) and `cnf: {kid: <holder did>}` (today's shape; a spec finding stays open, see below), digests the claims named by the configuration's `sdClaim` JSON paths (`SdJsonUtils`, the service's SD utility moved into the module unchanged) and carries the disclosures as an attribute; `sign` produces the issuer JWS with `JwsHeaderPolicy.sdJwtVc()` (`typ dc+sd-jwt`, `kid`, `x5c`, `x5t#S256`) and appends `~<disclosure>~...~`. `_sd_alg` is omitted as today (sha-256 is the default). Auto-configured; wired into certify-service.
- `/oid4vci/credential` now issues SD-JWT too; both template engines resolve `_issuer` as DID → configuration `didUrl` → tenant identifier, and the adapter's tenant carries `mosip.certify.identifier`.

## Findings kept open (spec)

- `cnf` carries `kid: did:jwk:...` rather than the holder `jwk`; SD-JWT VC verifiers commonly expect `cnf.jwk`. Same on both surfaces for now (zero wire change); to change on the new surface with a decision.
- No `iat`/`exp`/`nbf` in the SD-JWT payload (RECOMMENDED by SD-JWT VC); the legacy template decides. Same as above.

## Acceptance criteria

- [x] `SdJwtFormatterTest`: issuer JWS verified with Nimbus, header fields, every disclosure's digest present in `_sd`, non-SD claims in clear, alias, metadata, SD path validation.
- [x] `IssuanceGoldenTest.oid4vciSdJwtIssuanceGoldenAndIndependentVerification`: the golden SD-JWT configuration through the new surface, Nimbus-verified against `jwks.json`; goldens `v2/oid4vci/dc+sd-jwt-*`.
- [x] Legacy goldens unchanged; ArchUnit unchanged.
- [x] Full `certify-service` suite green:  tests.
