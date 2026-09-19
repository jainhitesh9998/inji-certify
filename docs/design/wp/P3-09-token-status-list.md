# P3-09 Token Status List for SD-JWT VC and mDoc

Branch: `wp/p3-09-token-status-list` off `design/extensibility`. Phase 3. Size: M. Depends on: P1-10a (status tables and batch job), P3-08 (x509-file chains).

## Goal

Item 5 of docs/design/17-conformance-gaps.md and the decision of 2026-09-18 (Token Status List for SD-JWT and mDoc): HAIP requires `status.status_list` (draft-ietf-oauth-status-list) on SD-JWT VC, and the conformance suite verifies the list against the uploaded trust anchor.

## Scope

- `TokenStatusListService`: lists are `status_list_credential` rows of type `TokenStatusList` (decision: the existing tables, no migration), the document being the signed list JWT (`typ statuslist+jwt`, `sub` the list URI, `iat`, `exp`, `ttl`, `status_list.bits` 1, `status_list.lst` zlib-compressed and base64url, least significant bit first as section 4.1 says); indices come from `status_list_available_indices` through the existing index provider; a full list is closed and the next one created. The list is signed with `certify.status.token-status-list.key-ref` (`provider:alias`, keymanager's EC key when absent), `alg` and `x5c` inclusion (`without-anchor` by default).
- `TokenStatusListProvider` (`status_config.mechanism = TokenStatusList`, formats `dc+sd-jwt`, `vc+sd-jwt`, `mso_mdoc`): `status.status_list = {idx, uri}` on the SD-JWT payload or the mDoc MSO.
- `GET /credentials/token-status-list/{id}` serves the list as `application/statuslist+jwt`.
- `StatusListUpdateBatchJob.updateStatusList` re-signs token lists from the same `credential_status_transaction` rows it uses for Bitstring lists.
- `StatusListPostgresTest.tokenStatusListForSdJwt`: an SD-JWT VC under the x509-file dev CA with `status.status_list`, the served list (typ, anchor-free `x5c`, signature, `sub`, bit clear), a revocation through the batch job (bit set, list re-signed).

- Finding fixed on the way: the v2 configuration API passed `null` into the entity's `@NotNull` metadata lists for a format without a deployment default (`dc+sd-jwt` in a context that only configures `ldp_vc`); it falls back to empty values now.

- Finding fixed on the way (CI red on the P3-08 merge): `DIDDocumentUtil` reads every `credential_config` row for the DID document and treated a provider-prefixed key (`x509-file:sdjwt-es256`, written by `PkiSdJwtIssuanceTest` into the H2 database every test context shares) as a keymanager alias, failing the whole document for every context that ran after it on Linux. It now resolves prefixed keys through the registry and leaves a key it cannot resolve out of the document with an error log.

## Outside scope

The CWT form of the list for mDoc verifiers (`application/statuslist+cwt`), `/credentials/status` resolving an SD-JWT's list entry through the ledger (the ledger stores Bitstring entries today), status list aggregation, `status_list` referenced tokens with more than one bit.

## Acceptance criteria

- [x] `StatusListPostgresTest` (all scenarios), `StatusListPostgresCoreTest`, `IssuanceGoldenTest` green; no golden changed.
- [x] Full `certify-service` suite green (995, reverse order too); CI: see the integration-branch run after merge.
