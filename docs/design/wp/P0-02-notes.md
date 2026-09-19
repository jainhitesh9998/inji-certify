# P0-02 notes: 0.14.0 (draft 13) against develop (OpenID4VCI 1.0), same inputs

Recorded with `docs/design/wp/p0-02-recorder/` from `e54539a`; compared with `goldens/legacy-develop` recorded from develop. Every
difference below is something `oid4vci-d13` (P1-12) must reproduce, or a defect to decide on before the adapter ships.

## Credential request and response

| Aspect | 0.14.0 (`goldens/legacy-0.14.0`) | develop (`goldens/legacy-develop`) |
| --- | --- | --- |
| Request body | `format` (required) plus `credential_definition{@context,type}` for `ldp_vc`, `vct` for `vc+sd-jwt`, `doctype` (optional `claims`) for `mso_mdoc`; one `proof{proof_type,jwt}` | `credential_configuration_id` plus `proofs{jwt:[...]}` |
| Configuration selection | first configuration whose `scope` is in the token's `scope`, whose `format` matches, and whose context and type lists match the request's (same size, all types contained) / `vct` equal / `doctype` equal | by `credential_configuration_id` |
| Paths | `/issuance/credential`, `/issuance/vd12/credential`, `/issuance/vd11/credential` (same body; the vd11 and vd12 responses echo `format`) | `/issuance/credential` only |
| `c_nonce` | from the access token claims `c_nonce` and `c_nonce_expires_in` (the token endpoint returns both), or from the `invalid_proof` error; no nonce endpoint | `POST /nonce`; the token carries no nonce |
| Wrong or missing nonce | HTTP 400 `{"error":"invalid_proof","error_description":"invalid_proof","c_nonce":"<fresh>","c_nonce_expires_in":300}`; the fresh nonce is cached per access token and must be used next | HTTP 400 `{"error":"invalid_nonce","error_description":"c_nonce is invalid or expired"}` |
| Proof JWT | `typ openid4vci-proof+jwt`, `aud` = `mosip.certify.identifier`, `nonce`, `iat`; `jwk` or `kid` header | same |
| Success body | `{"credential": ...}` (JSON-LD object for `ldp_vc`, string otherwise); `format` only on vd11 and vd12; `acceptance_token`, `c_nonce`, `c_nonce_expires_in` are declared and null | `{"credentials":[{"credential": ...}]}` |
| SD-JWT | format string and `typ` are `vc+sd-jwt` (`dc+sd-jwt` is accepted by the validator but not issued); header `alg ES256, kid, x5c, x5t#S256`; payload `iss` = identifier, `vct`, `cnf`, `_sd`, no `iat`/`exp` | `dc+sd-jwt`; payload otherwise identical |
| mDoc | base64url of a Document `{docType, issuerSigned}`; `issuerAuth` carries the COSE_Sign1 tag 18; the MSO payload is not wrapped in tag 24; `validityInfo` has `validFrom` and `validUntil` only (ISO/IEC 18013-5 requires `signed`) | bare `IssuerSigned`, untagged `issuerAuth`, `signed` present |
| `ldp_vc` | identical document and proof (`Ed25519Signature2020`, `issuanceDate`/`expirationDate`, holder `id`, contexts from the template) | identical |
| Unknown type | HTTP 400 `invalid_credential_request`, "No matching ldp_vc credential configuration found for scope: sample_vc_ldp" | HTTP 400 `invalid_credential_request`, "No credential configuration found for credential_configuration_id" |
| Unsupported format | HTTP 400 `unsupported_credential_format` | n/a (format comes from the configuration) |
| Missing proof | HTTP 400 `invalid_proof` (bean validation on `proof`) | HTTP 400 `invalid_proof` |

## Discovery

| Aspect | 0.14.0 | develop |
| --- | --- | --- |
| `GET /.well-known/openid-credential-issuer` | `?version=latest` (default), `vd12`, `vd11`; unknown version answers HTTP 200 with the MOSIP `errors[]` envelope (`UNSUPPORTED_METADATA_VERSION`) | one document, no `version` |
| Same documents under `/issuance/.well-known/openid-credential-issuer` and `/issuance/.well-known/did.json` (marked `@Deprecated` in the controller) | present | absent |
| `latest` shape | `credential_configurations_supported` map; per configuration `format`, `scope`, `credential_definition{@context,type,credentialSubject{claim:{display}}}` (ldp_vc), `vct` + `claims` (SD-JWT), `doctype` + `claims` (mDoc), `display`, `order`, `cryptographic_binding_methods_supported`, `credential_signing_alg_values_supported`, `proof_types_supported`; no `credential_metadata`, no `nonce_endpoint`; `authorization_servers` = [`mosip.certify.domain.url`] | `credential_metadata{display,claims[{path,display}]}`, `nonce_endpoint`, `authorization_servers` lists the external AS and itself |
| `vd12` shape | `credentials_supported` map keyed by configuration id; `cryptographic_suites_supported` replaces `credential_signing_alg_values_supported`; `credential_endpoint` is `/issuance/vd12/credential` | n/a |
| `vd11` shape | `credentials_supported` array, each entry with `id`; `credential_endpoint` is `/issuance/vd11/credential` | n/a |
| `did.json`, `jwks.json`, `oauth-authorization-server` | same shapes as develop (`assertionMethod` names the DID, not a key: finding stands) | same |

## Pre-authorized code flow

Offer and offer-fetch bodies are identical. The 0.14.0 token response carries `c_nonce` and `c_nonce_expires_in`
(develop dropped them); the access token claims carry `c_nonce` and `c_nonce_expires_in` too. Shared findings, both
releases: `client_id` is empty, `sub` holds the offer claims as JSON, `aud` doubles the servlet path when
`mosip.certify.identifier` already contains it (test-profile property `mosip.certify.oauth.access-token.audience`).

## What `oid4vci-d13` must restore

1. The draft-13 request DTO (`format`, `credential_definition`, `vct`, `doctype`, `claims`, single `proof`) and the scope-plus-format configuration match, on `/issuance/credential` (when the body has `format`), `/issuance/vd12/credential` and `/issuance/vd11/credential`.
2. `c_nonce` from the access token or from the previous `invalid_proof` error, with the error body above; `c_nonce`/`c_nonce_expires_in` in the token response of `certify-as`.
3. The response shape (`credential`, `format` echo on vd11/vd12, null `acceptance_token`).
4. `vc+sd-jwt` as format string and `typ`.
5. The mDoc Document wrapper with tagged `issuerAuth` (bytes wallets of that era parse); whether to add `signed` (spec) is a decision for P1-12.
6. Versioned metadata (`latest`, `vd12`, `vd11`) and the `/issuance/.well-known/*` aliases; whether the unknown-version answer stays HTTP 200 is a decision for P1-12.

## Findings about 0.14.0 itself

- `validityInfo` lacks `signed`, which ISO/IEC 18013-5 9.1.2.4 requires; develop fixed it.
- The H2 test schema of 0.14.0 predates its `CredentialConfig` entity (see the recorder README), so no 0.14.0 test ever inserted a configuration through the repository.
- The unknown metadata version error is an HTTP 200 envelope (same class as develop's `/pre-authorized-data` finding).
