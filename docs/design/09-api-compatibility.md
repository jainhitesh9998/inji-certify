# API compatibility and deprecation

> Part of the Inji Certify extensibility design. Baseline: `develop` at `a1cfd63` (1.0.0-beta.1-SNAPSHOT). Index: [README.md](./README.md).

Develop carries the OpenID4VCI 1.0 endpoint set, so the compatibility work is backwards: bring the 0.14.0 surface back as a deprecated adapter for wallets that still speak draft 13, alias the config-API rename that already shipped, and then apply one rule to everything: deprecate with headers and counters, remove no earlier than two minor releases after the replacement, and never inside a patch release. Release numbers below follow develop's `1.0.0-beta.1` line.

| Endpoint | On develop | Decision | Replacement | Removal |
| --- | --- | --- | --- | --- |
| `POST /issuance/credential` (1.0 body) | Present | Keep, served by `oid4vci-v1`; when `oid4vci-d13` is enabled the same path also accepts the 0.14.0 body, dispatching on `credential_configuration_id` versus `format` | none | none |
| `POST /issuance/vd11/credential`, `/vd12/credential`, `GET /.well-known/openid-credential-issuer?version=`, `GET /issuance/.well-known/*` | Removed | Restore in `oid4vci-d13` from `e54539a`, marked deprecated from day one with headers and counters; deployments without draft-13 wallets leave the adapter off | 1.0 endpoints | After counters read zero for one full release |
| `c_nonce` inside the `invalid_proof` error, `acceptance_token` | Removed | Restored inside `oid4vci-d13` only | `POST /nonce` | Same as above |
| `POST /nonce` | Present, advertised only when `mosip.certify.allow-c-nonce=true` | Keep; the switch becomes a per-adapter setting, on by default for `oid4vci-v1` and mandatory under `profile=haip` | none | none |
| `GET /.well-known/openid-credential-issuer`, `did.json`, `jwks.json`, `oauth-authorization-server` | Present | Keep; keys from `KeyPublisher`; metadata cached and invalidated on config writes | none | none |
| `POST /oauth/iae` | Present (`/oauth/iar` in 0.14.0) | Keep; add `/oauth/iar` as a deprecated alias for one release so 0.14.0 clients do not break twice | `/oauth/iae` | 1.2.0 |
| `POST /oauth/token`, `POST /pre-authorized-data`, `GET /credential-offer-data/{id}` | Present | Keep in `certify-as`; offers and codes persisted in 1.2.0 | none | none |
| `/credential-configurations` (POST, GET, PUT, DELETE) | Present; the field is `claims` (`credentialSubjectDefinition` in 0.14.0) | v1 accepts both names on input and returns `claims`; add `/v2/credential-configurations` in 1.1.0 with the domain model and a `/{id}/preview` dry run; deprecate v1 in 1.2.0 | v2 | 2.0.0 |
| `POST /credentials/status`, `GET /credentials/status-list/{id}`, `POST /ledger-search` | Present | Keep; backed by `StatusProvider` and the ledger port | none | none |
| `GET /rendering-template/{id}` | Present | Keep; the template id becomes per configuration | none | none |
| `/system-info/*` | Present | Keep at the same paths, served by the keymanager provider module; absent when another provider is active | none | none |
| New in 1.1.0 and 1.2.0 |  | `/oid4vci/deferred_credential`, `/oid4vci/notification`; `/vc-api/credentials/issue`, `/vc-api/credentials/status`; optional `/t/{tenant}/...` prefix once a `TenantResolver` other than the default is configured |  |  |

Plugin and property compatibility follow the same rule. `certify-integration-api` `1.0.0-beta.1` interfaces stay published; `LegacyDataProviderAdapter` and `LegacyExternalIssuerAdapter` wrap them into the new SPI. `mosip.certify.integration.data-provider-plugin` is honoured and mapped to a `CredentialDataSource` whose id is the bean name; `mosip.certify.plugin-mode` becomes the default `issuance_strategy` for configurations that do not set one; `mosip.certify.signing.provider` defaults to `keymanager`; `mosip.certify.allow-c-nonce` maps to the `oid4vci-v1` adapter's nonce setting. Old property names resolve through an `EnvironmentPostProcessor` alias table with a one-time warning; `mosip.certify.authn.filter-urls` is replaced by matchers each adapter registers, with the old list still honoured. All aliases are removed in 2.0.0.

Mechanics for every deprecated surface:

- Headers `Deprecation: @<unix-time>` (RFC 9745), `Sunset: <HTTP-date>` (RFC 8594) and `Link: <docs-url>; rel="deprecation"`.
- Micrometer counter `certify.deprecated.calls{endpoint}` and a warning log at most once per hour per endpoint, so operators can see who still calls what before removal.
- A per-endpoint kill switch `mosip.certify.deprecated.<name>.enabled=false` so a deployment can rehearse the removal.
- `deprecated: true` in `docs/stoplight_docs/inji-certify-openapi.yaml`, and a "Deprecated in this release / Removed in this release" section in `docs/technical_docs/Releases.md` every release.
- Golden tests recorded from 0.14.0 lock the draft-13 adapter and golden tests recorded from develop lock the 1.0 adapter, byte for byte, before either is touched.
