# P3-02 Issuance transactions and the notification endpoint

Branch: `wp/p3-02-issuance-transactions` off `design/extensibility`. Phase 3. Size: S. Depends on: P2-01 (the `issuance_transaction` table), P1-11 (the core path on `/oid4vci`).

## Goal

The `issuance_transaction` table the 1.1.0 migration created gets its first writer, and the new surface gains the OpenID4VCI 1.0 Notification Endpoint (section 10): every credential response on `POST /oid4vci/credential` carries a `notification_id`, the wallet reports `credential_accepted`, `credential_failure` or `credential_deleted` to `POST /oid4vci/notification` under the same access token, and the issuer metadata advertises `notification_endpoint`. This is the bookkeeping that deferred and batch issuance build on later (docs/design/08, `issuance_transaction`; docs/design/11, phase P3).

## Scope

- `IssuanceTransaction` entity and `IssuanceTransactionRepository` over the 1.1.0 table (no schema change; H2 `schema.sql` gains the table for the test contexts).
- `IssuanceTransactionListener` (`IssuanceListener.onIssued`): one row per completed issuance through the core, state `ISSUED`, id and `notification_id` equal to the core's transaction id, tenant, access-token hash, configuration id, protocol version, holder bindings (kind, value, kid, proof type), credential ids, `expires_at` = now + `certify.protocol.oid4vci-v1.notification.retention` (default one day). Failures are not recorded: the core has no transaction id for them yet.
- `Oid4vciCredentialController` adds `notification_id` to the credential response; `Oid4vciIssuer.notificationEndpoint()`; `notification_endpoint` in both the default and the per-tenant metadata document (`CredentialIssuerMetadataDTO`, `TenantIssuerMetadata`).
- `Oid4vciNotificationController`: `POST /oid4vci/notification` (JSON `notification_id`, `event`, optional `event_description`), 204 on success and the row moves to `NOTIFIED`; `400 invalid_notification_request` for a missing id or unknown event, `400 invalid_notification_id` when no row matches the id and the caller's access token; `401 invalid_token` without a token.
- `IssuanceTransactionHousekeeping`: a scheduled purge of rows past `expires_at` every `certify.protocol.oid4vci-v1.notification.purge-interval` (default one hour).
- Goldens: `notification_id` joins the volatile keys; the three v2 goldens that carry the new field or endpoint are re-recorded (`ldp_vc-response`, `ldp_vc-status-response`, `openid-credential-issuer`). `goldens/v1` and `goldens/d13` are untouched: the compatibility surfaces neither carry `notification_id` nor advertise the endpoint.
- Test `Oid4vciNotificationTest`: issuance writes the row with the expected columns, the wallet's report flips it to `NOTIFIED`, the two error codes, the purge, and the metadata field.

## Outside scope

Deferred issuance (`transaction_id`, `/oid4vci/deferred_credential`, state `DEFERRED`), batch issuance, recording failed attempts, a notification endpoint on the draft-13 surface (draft 13 defines one, but 0.14.0 never advertised it and the goldens fix the metadata document), forwarding wallet events to an `IssuanceListener` hook, an admin view of transactions.

## Acceptance criteria

- [x] `Oid4vciNotificationTest` green; `IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest`, `StatusListPostgresTest`, `TenancyIssuanceTest` green; `goldens/v1` and `goldens/d13` byte-identical.
- [x] Full `certify-service` suite green (969 tests, 0 failures).
- [ ] CI green on the fork.
- [x] Decision logged: `notification_id` is the core transaction id; retention and purge defaults.
