# Compliance and conformance testing

> Part of the Inji Certify extensibility design. Baseline: `develop` at `a1cfd63` (1.0.0-beta.1-SNAPSHOT). Index: [README.md](./README.md).

The OpenID Foundation conformance suite is the gate for OpenID4VCI 1.0 and HAIP; draft 13 has no official suite, so it is held by golden tests recorded from 0.14.0 and by interop wallets; VC-API is covered by the W3C CCG issuer test suite; DPoP already has a 26-scenario Postman suite on develop that moves into CI. All of them run against one `conformance` Spring profile that seeds deterministic data, configurations and keys.

| Target | Tool | Checks | Cadence |
| --- | --- | --- | --- |
| OpenID4VCI 1.0 issuer | OpenID Foundation conformance suite, self-hosted from its Docker image in CI (confirm the current issuer test-plan names and whether the pinned release covers 1.0 final) | Issuer metadata, nonce endpoint, credential request and response shapes, proof validation, error codes, deferred and notification when advertised | Nightly; certification submission once green |
| HAIP | Same suite, HAIP profile plan | `dc+sd-jwt` and `mso_mdoc` output, key attestation in proofs, PAR, PKCE, DPoP and wallet attestation at the AS, encrypted responses | Nightly with `profile=haip` |
| DPoP at the credential endpoint | The 26-scenario collection under `docs/postman_collections/authorization_code_flow/data_provider_plugin/README-mock-identity-dpop.md`, run with Newman | Scheme rules, downgrade guard, `htm`/`htu`/`ath`/`jkt`, freshness, replay | Per PR |
| Draft 13 (existing wallets) | Golden request and response files recorded from 0.14.0 (REST-assured), plus interop runs with the Inji Wallet and mimoto versions in production and two third-party wallets | Byte-exact responses of the `oid4vci-d13` adapter | Per PR (goldens); weekly (interop) |
| OpenID4VCI 1.0 as develop ships it | Golden files recorded from develop before Phase 1 | Byte-exact responses of the `oid4vci-v1` adapter through the refactor | Per PR |
| Signing | Golden signature vectors per path recorded from keymanager before Phase 1 (EdDSA and RSA compare by bytes; ECDSA compares by verification, since it is randomised) | The envelope builders reproduce keymanager output | Per PR |
| VC-API issuer | W3C CCG `vc-api-issuer-test-suite` (Node) | `/credentials/issue` request and `options` handling, error codes, VC 2.0 plus Data Integrity output | Nightly |
| Format validity | SD-JWT verified with `authlete/sd-jwt` (already a dependency) and `sd-jwt-vc` vectors; mDoc decoded and verified with an independent library in a test module; Data Integrity checked against W3C vectors for `eddsa-rdfc-2022` and `ecdsa-rdfc-2019`; VC 2.0 JSON Schema | Signed artefacts verify with code Certify did not write | Per PR |
| Plugin SPI | `certify-spi-testkit`: a contract test each plugin repo runs against its `CredentialDataSource`, `ExternalIssuer`, `CredentialFormatter`, `KeyProvider` or `TemplateEngine` | Behaviour on missing claims, exceptions, timeouts, nulls, unsupported algorithms | In each plugin repo's CI |
| Database | Testcontainers PostgreSQL replacing H2; a migration test that applies the Flyway chain to a 0.14.0 dump and a develop dump, then runs the row-by-row read-path comparison | Migrations, backfills, rollbacks, JSONB and index behaviour | Per PR |
| Architecture | ArchUnit rules from the target architecture section | Dependency direction, keymanager only in its provider, no format constants outside formatters | Per PR |
| Regression | Existing `api-test` TestNG rig | 1.0 adapter, config API, status and ledger | Per push, as today in `push-trigger.yml` |

The `conformance` profile: in-memory `CredentialDataSource` with fixed claims, embedded AS enabled, `dc+sd-jwt`, `mso_mdoc` and `ldp_vc` configurations seeded by Flyway test migrations, the `jca` key provider with checked-in test keys (so no HSM or keymanager tables are needed), and the issuer URL set to the address the suite container can reach (`host.docker.internal` when self-hosted).

Test pyramid for the rebuilt code:

1. Unit: formatters, envelope builders, proof validators and template engines, driven by spec test vectors and the `jca` provider.
2. Component: `IssuanceService` with an in-memory `CredentialRegistry` and fake SPI implementations, no Spring context; the same harness the CLI uses.
3. Adapter: MockMvc golden tests per protocol module; one golden set per protocol version.
4. End to end: docker-compose plus the conformance, DPoP and interop jobs above.
