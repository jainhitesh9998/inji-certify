# P1-10 Status provider and issuance listeners (first slice)

Branch: `wp/p1-10-status-ledger` off `design/extensibility`. Phase 1. Size: M. Depends on: P1-01, P1-11.

## Goal

The new surface does what the legacy issuance does around signing: assign a Bitstring Status List entry, give the credential its `id`, and write the ledger entry — through the SPI hooks, over today's services and tables.

## Scope

- `BitstringStatusProvider` (`mechanism = BitstringStatusList`, `ldp_vc`): for VC 2.0 documents of a configuration with status purposes, `StatusListCredentialService.addCredentialStatus` assigns the entry (same lists, same indices, same `credentialStatus` shape); `update` is not offered yet (status changes go through `/credentials/status`, P5).
- `CredentialIdListener` (`beforeSign`): `mosip.certify.data-provider-plugin.id-field-prefix-uri` + UUID as `id` for `ldp_vc` documents without one, as the legacy `VCFormatter` injects.
- `LedgerListener` (`onIssued`, `mosip.certify.issuer.ledger-enabled`): `CredentialLedgerServiceImpl.storeLedgerEntry` with the credential id, the configuration's issuer DID and credential type, the status detail read from the signed document, and the indexed attributes read from the plugin's data — which `DataProviderPluginDataSource` now keeps in the claim set's provenance (`data`).
- `DefaultIssuanceService` already runs status providers between `build` and `beforeSign` and listeners after signing; the adapter's configuration collects every bean.

## Findings

- Status lists need PostgreSQL: `StatusListCredentialService.initializeAvailableIndices` inserts indices with a native `generate_series` query, which H2 cannot execute; the H2-based golden context cannot attach a status entry end to end (the legacy tests mock the service). A Testcontainers-based golden for status attachment is the follow-up (P0-05 infrastructure exists).

## Acceptance criteria

- [x] `StatusAndLedgerTest`: status entry attached only to VC 2.0 documents with purposes; ledger entry with the plugin data's indexed attributes and the signed document's status detail; ledger disabled honoured; credential id from the prefix.
- [x] Goldens (metadata re-recorded for the added VC 2.0 status configuration) and ArchUnit unchanged otherwise.
- [x] Full `certify-service` suite green: 897 tests.
