# Changes in the extensibility rebuild (unreleased, `design/extensibility`)

## Draft-13 endpoints restored and deprecated

The OpenID4VCI draft-13 credential endpoints of release 0.14.0 are served again by the `oid4vci-d13` adapter (on by default, `certify.protocol.oid4vci-d13.enabled`): the 0.14.0 body on `POST /issuance/credential`, `POST /issuance/vd12/credential` and `POST /issuance/vd11/credential`. They are deprecated from this release: every answer carries `Deprecation` and `Link` headers, calls are counted in `certify.deprecated.calls{endpoint=oid4vci-d13-credential|oid4vci-d13-versioned-credential}`, and `mosip.certify.deprecated.<endpoint>.enabled=false` answers `410 Gone`. Replacement: `POST /oid4vci/credential` (OpenID4VCI 1.0). Removal no earlier than two minor releases after this one.

## Notification endpoint on the new surface

`POST /oid4vci/credential` answers with a `notification_id` and the issuer metadata under `/oid4vci` advertises `notification_endpoint`: wallets report `credential_accepted`, `credential_failure` or `credential_deleted` to `POST /oid4vci/notification` (OpenID4VCI 1.0 section 10) with the access token of the issuance. Every issuance through the new surface is recorded in the `issuance_transaction` table created by the 1.1.0 migration and purged after `certify.protocol.oid4vci-v1.notification.retention` (default one day). The compatibility endpoints are unchanged.

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