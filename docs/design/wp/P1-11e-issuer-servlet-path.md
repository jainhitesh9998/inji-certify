# P1-11e The new surface's issuer identifier carries the servlet path

Branch: `wp/p1-11e-issuer-servlet-path` off `design/extensibility`. Phase 1 fix. Size: XS. Depends on: P1-11.

## Goal

Found by the compose smoke run of `docs/design/VALIDATE.md`: the stack sets `mosip.certify.identifier` to the bare domain (`http://localhost:8090`) and appends `server.servlet.path` to every legacy endpoint, so `Oid4vciIssuer.derive(identifier)` advertised `http://localhost:8090/oid4vci/credential` while the endpoint lives at `http://localhost:8090/v1/certify/oid4vci/credential`. A wallet following the new-surface metadata could never reach it. The design names the identifier `{domain}{servletPath}/oid4vci` (docs/design/09-api-compatibility.md).

## Scope

- `Oid4vciIssuer.derive(identifier, servletPath, configured)`: the servlet path is appended unless the identifier already ends with it (the test profile's `http://localhost:8090/v1/certify` stays as it is, so every golden is unchanged); `certify.oid4vci.issuer-identifier` still wins.
- `Oid4vciIssuanceConfiguration` passes `server.servlet.path`.
- `Oid4vciIssuerTest` covers the bare domain, the already-suffixed identifier, an empty or root servlet path and the configured override.

## Acceptance criteria

- [ ] `Oid4vciIssuerTest`, `IssuanceGoldenTest`, `TenancyIssuanceTest`, `D13GoldenReplayTest` green; no golden changed.
- [ ] Full `certify-service` suite green.
- [ ] The compose smoke run advertises `http://localhost:8090/v1/certify/oid4vci/...` and issues through it.
- [ ] CI green on the fork.
