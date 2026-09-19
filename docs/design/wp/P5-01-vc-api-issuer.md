# P5-01 VC-API issuer adapter: `/vc-api/credentials/issue` and `/vc-api/credentials/status`

Branch: `wp/p5-01-vc-api-issuer` off `design/extensibility`. Phase 5 (pulled forward on the owner's "then add vc api as well once that refactory is done"). Size: M. Depends on: P1-11 (core, `IssuanceStrategy.SUPPLIED`), P2-06 (v2 configuration API), P1-10a (status lists, ledger).

## Goal

The adapter row of `05-target-architecture.md` (`certify-protocol-vcapi`: "`/vc-api/credentials/issue`, `/vc-api/credentials/status`; client-credential auth", namespaced to avoid today's `POST /credentials/status`) and capability gap "VC-API issuer" of `04-capability-gaps.md`: an issuer coordinator hands Certify a credential body and gets it back signed, without templates, holder tokens or proofs.

## Specification followed

W3C VCALM (the CCG VC-API, moved to `w3c/vcalm`; `oas.yaml` at the time of writing, `0.0.3-unstable`):

- `POST /credentials/issue`: request `{credential, options}`; `options.credentialId` (a handle when the credential has no `id`), `options.mandatoryPointers` (selective disclosure); `201` with `{verifiableCredential}`; `400` when "the provided value of 'issuer' does not match the expected configuration" or the request is otherwise bad.
- `POST /credentials/status`: request `{credentialId, credentialStatus {type, statusPurpose, statusListIndex?, statusListCredential?, id?}, status: boolean}`; `200` (no body), `400`, `404` "Credential not found".
- Errors are `ProblemDetails` `{type, title, detail}` (`application/problem+json`); the `type` is the VC Data Model URL for its error names (`MALFORMED_VALUE_ERROR`, `PARSING_ERROR`) and `urn:mosip:certify:vc-api:<TITLE>` otherwise.
- Security: the specification lists OAuth 2.0 bearer, zCap, DID auth and network rules; this slice offers HTTP Basic client credentials (see decisions).

## Scope

- `VcApiProperties` (`certify.protocol.vc-api.enabled` default false, `clients.<id>.secret`, `clients.<id>.credential-configurations`); `VcApiConfiguration` (the `/vc-api/**` security chain, stateless, no CSRF, no holder-token filter) and `VcApiClientAuthFilter` (HTTP Basic, constant-time secret comparison, `401` with `WWW-Authenticate: Basic realm="vc-api"` and problem details); all present only when enabled.
- `VcApiController`:
  - `POST /vc-api/credentials/issue`: picks the `ldp_vc` configuration with `issuanceStrategy = SUPPLIED` whose stored `@context` and `type` sets equal the credential's (as the draft-13 handler matches), refuses `mandatoryPointers` (`400 NOT_SUPPORTED`), an issuer other than the configuration's DID (`400 ISSUER_MISMATCH`), no matching configuration (`400 NOT_CONFIGURED`), a client whose `credential-configurations` list excludes it (`403 FORBIDDEN`); runs `IssuanceCommand` with the supplied body, `ProtocolVersion.VC_API`, `Authorization("client_credentials", {client_id})` and `options` as protocol params; answers `201 {verifiableCredential}`.
  - `POST /vc-api/credentials/status`: validates the body; takes `statusListCredential` and `statusListIndex` from the request when given, else looks the credential up in the ledger by `credentialId` and picks the entry of the requested `statusPurpose` (`404` when the credential or the entry is unknown); applies it through today's `CredentialStatusService`; `200` without a body.
- The H2 test schema gains the `ledger` table (mirroring the PostgreSQL DDL) so the status endpoint's lookup runs in the service tests.
- `AuthorizationPolicy.SCOPE`: a `SUPPLIED` configuration reached through `VC_API` needs no holder token (the adapter authenticated the client); the CLI rule is unchanged.
- `VcApiIssuanceTest`: a `SUPPLIED` `ldp_vc` configuration created through the v2 API (no template); a registered client's credential body comes back with an `Ed25519Signature2020` proof that danubetech verifies against did.json; missing, wrong and unknown clients get `401`; malformed body, unknown type, issuer mismatch and `mandatoryPointers` get `400` problem details; a client without the configuration gets `403`; the status endpoint answers `400` for a malformed body and `404` for an unknown credential. `StatusListPostgresTest.vcApiStatusUpdateFindsTheEntryThroughTheLedger`: a credential issued with a Bitstring status is revoked through `/vc-api/credentials/status` by its id alone, the bit flips after the batch step, and an unknown purpose answers `404`.

## Outside scope

OAuth 2.0 bearer tokens for clients (client credentials from `certify-as` or eSignet), zCap and DID auth; `options.credentialId` as a ledger key when the credential has no `id` (the ledger keys by `credential.id`); VC 2.0 `validFrom` defaults for supplied bodies (the body is signed as given); tenancy (default tenant); the W3C CCG `vc-api-issuer-test-suite` run (needs a public host, like the OIDF run).

## Acceptance criteria

- [x] `VcApiIssuanceTest`, `IssuanceGoldenTest`, `D13GoldenReplayTest` green; no golden changed; the compatibility and `/oid4vci` surfaces untouched. `StatusListPostgresTest` (6, with the VC-API status scenario) green.
- [x] Full `certify-service` suite green (1038, reverse order); CI: the integration-branch run after merge.
- [x] Decision row (client authentication), release note, `09-api-compatibility.md` and `14-configuration.md` rows updated.
