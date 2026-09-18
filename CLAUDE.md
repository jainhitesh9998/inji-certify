# CLAUDE.md

This branch carries the extensibility rebuild of Inji Certify. Read this file first, then `docs/design/README.md`. `AGENTS.md` describes the code as built on `develop` and remains the reference for current behaviour, endpoints, properties and the plugin model; do not edit its as-built sections unless the behaviour they describe has changed.

## What is being built

Inji Certify (`develop`, 1.0.0-beta.1) is an OpenID4VCI 1.0 credential issuer whose issuance, formatting, templating, signing and configuration are fused in one Spring Boot module. The rebuild re-layers it without changing what wallets or operators see: a protocol-agnostic core (`certify-core`) behind `certify-spi`, protocol adapters (`oid4vci-v1` serving a new spec-clean surface under `/oid4vci` with its own issuer identifier plus today's paths in deprecated compatibility mode, `oid4vci-d13` restored from release 0.14.0 and on by default, `vc-api`), a signing library (`certify-signing`) shared with a command-line tool (`certify-cli`), MOSIP kernel-keymanager kept as the embedded default key provider (it already covers PKCS#11, PKCS#12 and offline HSM keystores) next to cloud KMS, Vault, file and X.509 providers for issuers with their own PKI or no keymanager at all, Velocity kept as the default template engine next to a JSON mapping engine, and Flyway-managed additive migrations. Full design: `docs/design/`.

## Non-negotiables, in priority order

1. Spec correctness. Every credential, metadata document, error and header follows the specification it claims: OpenID4VCI 1.0 (and draft 13 on the compatibility surface), HAIP, W3C VC Data Model 1.1 and 2.0, Data Integrity cryptosuites, SD-JWT VC, ISO/IEC 18013-5, RFC 9449 DPoP. When the code and the spec disagree, the spec wins and the deviation is fixed behind the compatibility surface, never carried into the new one. Conformance suites and independent verifiers are the proof, not our own tests.
2. Structural soundness of the VC. An issued credential must verify with libraries Certify did not write, carry a complete and valid certificate chain or verification method, have correct types, contexts, validity fields, status entries and disclosures, and be rejected before signing when it would not. Every credential format Certify issues must be verified in the test suite by an independent third-party verifier (a library or tool Certify does not maintain), and that suite is a merge gate. Output validation and `CertificateChainPolicy` are mandatory steps, not options.
3. Easy upgrade for previous-version users. A deployment on 0.14.0 or 1.0.0-beta.1 upgrades by running migrations and restarting: same endpoints, same plugins, same properties, same keymanager setup, same signature bytes, with deprecations announced by headers and counters and removed only after two minor releases.

Every other rule below serves these three; when they conflict, this order decides.

## Rules that every change must respect

1. Zero wire-byte change until Phase 3. The golden tests (`goldens/v1`, `goldens/d13`) and the signature vectors are the definition of "unchanged"; if a change cannot keep them green, the change is wrong.
2. Keymanager stays an embedded library and the default provider. It is wrapped as `certify-keyprovider-keymanager`, which carries its component scan, `mosip.keymanager.dao.enabled=false` JPA wiring and `initKeys`; it is never called over HTTP; `io.mosip.kernel` imports live only in that module once WP P1-02 lands. Existing deployments keep the same jar, properties, tables, key policies and rotation, `kid` values and signature bytes. Other key managers plug in above it through `KeyProvider`; PKI formats (mDoc/mDL, SD-JWT `x5c`) use the `x509` providers and `CertificateChainPolicy` (`docs/design/06a-x509-pki-and-mdoc.md`).
3. Every database change is additive, shipped as a Flyway migration with a rollback script under `db_upgrade_script`, backfilled in the same migration, and rehearsed on a develop dump. Nothing is renamed or dropped before the 2.0.0 sunset. `spring.jpa.hibernate.ddl-auto` stays `none`.
4. Tenant-ready, single-tenant by default: new core types carry `tenantId` (default `default`), new tenant-scoped tables get `tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'`, and no entity embeds the tenant in its identity.
5. `certify-core` and `certify-signing` import no Spring Web, JPA, Velocity or danubetech types; adapters depend only on `certify-core` and `certify-authz`; format strings are switched only inside formatter modules. ArchUnit enforces this with a frozen violation list that may only shrink.
6. Every deprecated surface gets `Deprecation`, `Sunset` and `Link` headers, a `certify.deprecated.calls` counter, a kill switch, an OpenAPI `deprecated` flag and a line in `docs/technical_docs/Releases.md`. Removal happens no earlier than two minor releases after the replacement and never in a patch.
7. Old plugin interfaces (`certify-integration-api`), property names and the v1 config API keep working through adapters and aliases until 2.0.0.
8. A decision not already in `docs/design/12-risks-and-decisions.md` is asked, not assumed; the answer is appended to the decision log before the PR opens.

## Repository map: today and target

| Concern | Today (develop) | Target module |
| --- | --- | --- |
| HTTP issuance, nonce, metadata | `certify-service/.../controller/*`, `core/dto/*` | `certify-protocol-oid4vci-v1`, `certify-protocol-oid4vci-d13`, `certify-protocol-vcapi` |
| Issuance orchestration | `services/CertifyIssuanceServiceImpl`, `services/VCIssuanceServiceImpl` | `certify-core` (`IssuanceService`, `CredentialRegistry`) |
| Formats | `credential/W3CJsonLD`, `SDJWT`, `MDocCredential`, `utils/MDocProcessor`, `utils/SDJsonUtils` | `certify-format-ldp-vc`, `-sd-jwt`, `-mdoc`, `-jwt-vc` |
| Templating | `vcformatters/VelocityTemplatingEngineImpl`, `VCFormatter` | `certify-template-velocity`, `certify-template-jsonmap` |
| Signing | `proofgenerators/*`, `credential/*.addProof`, `MDocProcessor.signMSO`, `utils/AccessTokenJwtUtil` | `certify-signing` (envelopes, `AlgorithmRegistry`, `KeyPublisher`) |
| Keys | keymanager wiring in `CertifyServiceApplication`, `config/AppConfig`, `services/JwksServiceImpl`, `utils/DIDDocumentUtil` | `certify-keyprovider-keymanager` (default), `-jca`, `-x509-file`, `-x509-pkcs11`, `-x509-kms`, `-kms-*`, `-vault` |
| Auth | `filter/AccessTokenValidationFilter`, `dpop/DpopProofValidator`, `core/dto/ParsedAccessToken` | `certify-authz` (`AuthorizationContext`, Bearer, DPoP) |
| Proofs | `proof/JwtProofValidator`, `proof/DID*ProofManager` | `certify-spi` `ProofValidator` + `HolderKeyResolver` implementations |
| Status, ledger, QR, audit | `services/StatusList*`, `services/CredentialLedgerServiceImpl`, `signQrEntries`, `AuditPlugin` | `StatusProvider` and `IssuanceListener` implementations |
| Embedded AS, presentation during issuance | `controller/OAuthController`, `services/Iar*`, `services/PreAuthorizedCodeService`, `verify-core` | `certify-as` |
| Persistence | `entity/*`, `repository/*`, `db_scripts/`, `db_upgrade_script/` | `certify-persistence` with Flyway locations `core`, `keymanager`, `verify`, `as` |
| Plugins | `certify-integration-api` | `certify-spi` (new) + `certify-integration-api` (kept, adapters) |
| CLI | none | `certify-cli` |

## Working on a work package

- All work is pushed to branches on `jainhitesh9998/inji-certify`; never open a pull request against `inji/inji-certify`. The integration branch is `design/extensibility`.
- Specs live in `docs/design/wp/`; pick one whose dependencies are merged. Branch `wp/<id>-<slug>` from `design/extensibility`; merge back after the gates pass (a PR inside the fork is optional, for review); keep a change under roughly 800 lines excluding recorded goldens and generated SQL.
- CI is `.github/workflows/rebuild-ci.yml` (GitHub Actions on the fork, Docker available, so Testcontainers runs).
- Before code: read the spec, the design section that owns it, and the classes it names. Record goldens or vectors before touching the code they protect.
- Stay inside the files the spec names; list anything else under "Outside scope" in the PR.
- Copy the spec's acceptance checklist into the PR and tick each item with evidence.

## Commands

```bash
mvn -B -q -DskipTests -Dgpg.skip=true install     # build all modules (JAVA_HOME on JDK 21)
mvn -B -pl certify-service test                   # unit tests
mvn -B -pl certify-service test -Dtest=GoldenReplayTest,SignatureVectorTest   # wire and signature guards (after P0-01, P0-03)
mvn -B -pl certify-service test -Dtest='*ArchitectureTest'                     # ArchUnit (after P0-06)
mvn -B -Dgpg.skip=true verify -Ptestcontainers    # repository and migration tests on PostgreSQL (after P0-05)
mvn -B -pl certify-service spring-boot:run -Dspring-boot.run.profiles=local    # run with TestBearer tokens and the mock CSV data provider
docker compose -f docker-compose/docker-compose-injistack/docker-compose.yml up   # full local stack, see its README
```

Java 21 and Maven 3.9 are required; Docker is required for Testcontainers and the conformance jobs. Two local-build facts that are not obvious:

- Maven must itself run on JDK 21, not just have a JDK 21 on `PATH`: JDK 23 and later disable implicit annotation processing, so Lombok never runs and `certify-integration-api` fails with `cannot find symbol setClientId`. On macOS: `export JAVA_HOME=$(/usr/libexec/java_home -v 21)` before any `mvn` command.
- The parent pom binds `maven-gpg-plugin:sign` to `verify` for Maven Central publishing; add `-Dgpg.skip=true` to every `verify` or `install` locally and in CI.
- `certify-service/pom.xml` lists `jitpack.io` first among repositories, and `verify-core`'s POM pulls transitive repositories (`sovrin`, with a broken TLS certificate). Maven asks JitPack to build any coordinate it cannot find locally and JitPack hangs for minutes. Locally, pass `-s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true` (routes `jitpack.io` and `sovrin` to Central; keeps `google` because `verify-core` needs `com.android.identity` from maven.google.com). The only JitPack-only artifact, `com.github.multiformats:java-multibase`, must be in `~/.m2` (fetch it once with `curl` from `https://jitpack.io/com/github/multiformats/java-multibase/v1.1.1/`).
- Testcontainers needs a running Docker daemon; on macOS start Docker Desktop and, if detection fails, `export DOCKER_HOST=unix://$HOME/.docker/run/docker.sock`. Docker Engine 29 removed API versions below 1.44, so the pinned Testcontainers 1.21.4 and docker-java 3.5.3 in the parent pom must not be downgraded.
- In a `git worktree`, add `-Dmaven.gitcommitid.skip=true` (the `git-commit-id-plugin` cannot read a worktree's HEAD).
- Full local recipe: `export JAVA_HOME=$(/usr/libexec/java_home -v 21); mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -DskipTests install` (about 10 s once dependencies are cached); baseline on `develop`: 858 tests green.

## Where things are decided

`docs/design/12-risks-and-decisions.md` holds the decision log; decisions already taken include: draft-13 adapter on by default; new `/oid4vci` surface with today's paths deprecated; keymanager embedded default; `x509-file` first extra provider with dev-mode generation; shared-schema tenancy; Velocity default with standard claims mapping for SD-JWT and mDoc; Token Status List for SD-JWT and mDoc; HAIP on both the resource-server and `certify-as` sides; IAE supported behind a flag in `certify-as`. `docs/design/11-roadmap.md` holds phases, exit criteria and order. `docs/design/13-automated-development.md` holds the operating model for agents and reviewers.

## Glossary

`IssuanceCommand` the protocol-agnostic request the core executes; `CredentialConfiguration` the domain model behind `credential_config`; `KeyRef` an opaque provider-plus-alias key reference (`keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN`); `HolderBinding` the holder key extracted from a proof; envelope builders the JWS, COSE, CWT, Data Integrity and legacy LD signers in `certify-signing`; goldens the recorded request and response pairs; vectors the recorded signatures per signing path; `TenantContext` the tenant, issuer identifier and key namespace of a request, `default` unless a `TenantResolver` says otherwise.
