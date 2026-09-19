# Changes in the extensibility rebuild (unreleased, `design/extensibility`)

## Draft-13 endpoints restored and deprecated

The OpenID4VCI draft-13 credential endpoints of release 0.14.0 are served again by the `oid4vci-d13` adapter (on by default, `certify.protocol.oid4vci-d13.enabled`): the 0.14.0 body on `POST /issuance/credential`, `POST /issuance/vd12/credential` and `POST /issuance/vd11/credential`. They are deprecated from this release: every answer carries `Deprecation` and `Link` headers, calls are counted in `certify.deprecated.calls{endpoint=oid4vci-d13-credential|oid4vci-d13-versioned-credential}`, and `mosip.certify.deprecated.<endpoint>.enabled=false` answers `410 Gone`. Replacement: `POST /oid4vci/credential` (OpenID4VCI 1.0). Removal no earlier than two minor releases after this one.

## Notification endpoint on the new surface

`POST /oid4vci/credential` answers with a `notification_id` and the issuer metadata under `/oid4vci` advertises `notification_endpoint`: wallets report `credential_accepted`, `credential_failure` or `credential_deleted` to `POST /oid4vci/notification` (OpenID4VCI 1.0 section 10) with the access token of the issuance. Every issuance through the new surface is recorded in the `issuance_transaction` table created by the 1.1.0 migration and purged after `certify.protocol.oid4vci-v1.notification.retention` (default one day). The compatibility endpoints are unchanged.

## v2 configuration API

`POST`, `GET`, `PUT` and `DELETE /v2/credential-configurations` take and return the configuration model the rebuilt core reads (`formatConfig`, `signing`, `template`, `issuanceStrategy`, `status`, `display`, `protocol`), version templates in `credential_template`, and dry-run a body that carries `sampleClaims` through the template engine and formatter before saving it (`400 template_render_failed` otherwise). `POST /v2/credential-configurations/{id}/preview` renders a saved configuration against given claims without signing. Rows written through v2 carry every v1 column too, so `/credential-configurations` (v1), the compatibility endpoints and the issuer metadata see them unchanged. The v1 API is unchanged and not yet deprecated.

## Single-use nonces and batch issuance on the new surface

A `c_nonce` from `POST /oid4vci/nonce` now authorises one credential request: after the credentials are issued the nonce is dropped, and a replayed proof answers `400 invalid_nonce` (`certify.protocol.oid4vci-v1.nonce.single-use=false` restores the previous behaviour). The issuer metadata under `/oid4vci` advertises `batch_credential_issuance.batch_size` (`certify.protocol.oid4vci-v1.batch.size`, default 10); a request whose `proofs` exceed it answers `400 invalid_credential_request`. The compatibility endpoints and the draft-13 endpoints are unchanged.

## Path-based tenants

`certify.tenancy.resolver=path` serves each configured tenant under `{domain}{servletPath}/t/{tenant}/oid4vci/...` with `.../t/{tenant}/oid4vci` as its Credential Issuer Identifier, next to the host resolver. Unconfigured path tenants answer as the default tenant. A tenant may also set `certify.tenancy.tenants.<id>.display` and `.authorization-servers` for its metadata document; token validation still uses the deployment's authorization server.

## Tenant DID documents

With `certify.tenancy` enabled, a tenant configured with `issuer-did` issues under that DID (the proof's `verificationMethod` is `<tenant did>#<kid>`) and `GET /.well-known/did.json` on the tenant's host publishes the deployment's keys under the tenant's DID, so a verifier resolves the tenant's credentials from the tenant's own document. Single-tenant deployments are unchanged.

## Compatibility credential endpoint deprecated

`POST /issuance/credential` with the 1.0.0-beta.1 body (`credential_configuration_id`, `proofs`) keeps working and is deprecated from this release: every answer carries `Deprecation` and `Link` headers, calls are counted in `certify.deprecated.calls{endpoint=oid4vci-v1-compat-credential}`, and `mosip.certify.deprecated.oid4vci-v1-compat-credential.enabled=false` answers `410 Gone`. Replacement: `POST /oid4vci/credential` (OpenID4VCI 1.0, advertised by `GET /oid4vci/.well-known/openid-credential-issuer`). `POST /nonce` stays. Removal no earlier than two minor releases after this one, never in a patch.

## Pre-authorized offers may name a subject

`POST /pre-authorized-data` accepts an optional `subject` next to `claims`: the identifier the data provider resolves (for the CSV plugin, the row id). It becomes the access token's `sub`, so plugins that look the record up by `sub` work in the pre-authorized code flow without eSignet. Offers with `claims` behave as before.

## Authorization code flow in Certify's own authorization server

Once a client is registered under `certify.as.clients.<client-id>.redirect-uris`, the authorization server metadata advertises `authorization_endpoint`, `pushed_authorization_request_endpoint` and `require_pushed_authorization_requests`, and wallets run the authorization code flow with pushed requests and PKCE (`S256`) against `POST /oauth/par`, `GET /oauth/authorize` and `POST /oauth/token`. The subject of an authorization comes from `certify.as.authorization.subject-mode`: `none` (default) refuses, `fixed` approves every request for `certify.as.authorization.fixed-subject` without user interaction, which is meant for conformance runs and demos only. Deployments without registered clients see no change.

# Changes in release 0.11.0

## Removal of  Artifactory dependency

```text
artifactory_url_env - this field is removed from configure_start.sh to remove dependency on artifactory
any new plugin to be added can be added by volume mount to loader_path

is_glowroot_env - this field is removed from configure_start.sh to remove dependency on glowroot apm



```
moved client.zip to build time dependency in dockerfile - addition of new hsm-client zip can be done by adding it to volume mount in docker-compose or helm charts with same structure as [client.zip](https://raw.githubusercontent.com/mosip/artifactory-ref-impl/v1.3.0-beta.1/artifacts/src/hsm/client.zip)

---

# Changes in release 0.12.0

## Restructure of credential_template table

Step-by-Step Migration guide for upgrade from 0.11.0 to 0.12.0 is available at [Migration Guide](./Migration_Guide_0.11.0_To_0.12.0.md)