# Configuration revamp

> Part of the Inji Certify extensibility design. Baseline: `develop` at `a1cfd63`. Index: [README.md](./README.md).

Configuration today is one 180-key properties file read through 78 scattered `@Value` lookups, twelve of them SpEL map literals, with issuer identity spelled six ways and endpoint security kept as hand-edited URL lists. The revamp binds every module's settings to a typed, validated `@ConfigurationProperties` record under one namespace, keeps every old key working through an alias layer, derives endpoint security from the adapters instead of lists, and moves per-credential knobs into the credential configuration.

## How configuration works on develop

| Aspect | Today | Evidence |
| --- | --- | --- |
| Source | Spring Cloud Config (`bootstrap.properties`, `spring_config_url_env`, profile `certify-default.properties` in the inji-config repository); `application-local.properties` for local runs | `certify-service/src/main/resources`, `docker-compose/.../config/certify-default.properties` |
| Binding | 78 distinct `@Value("${...}")` keys in 30+ classes; four `@ConfigurationProperties` classes (`MDocConfig`, `VelocityEnvConfig`, `IndexedAttributesConfig`, `JsonLdContextLoaderProperties`) | `grep -r @Value certify-service/src/main/java` |
| Structured values | SpEL literals parsed at injection: `mosip.certify.signature-algo.key-alias-mapper` (map of alg to list of [appId, refId] pairs), `credential-config.cryptographic-binding-methods-supported`, `credential-signing-alg-values-supported`, `proof-types-supported`, `cache.size`, `cache.expire-in-seconds`, `credential-config.as-mapping`, `authn.allowed-audiences`, `authn.filter-urls`, `credential-config.issuer.display`, `security.auth.*-urls` | `@Value("#{${...}}")` in `CredentialConfigurationServiceImpl`, `SecurityConfig`, `AccessTokenValidationFilter`, `SimpleCacheConfig`, `RedisCacheConfig` |
| Issuer identity | Six overlapping keys: `mosip.certify.domain.url`, `mosip.certify.identifier`, `mosip.certify.discovery.issuer-id`, `mosip.certify.oauth.issuer`, `mosip.certify.authorization.url`, `mosip.certify.authn.issuer-uri`, plus `mosipbox.public.url` | `application-local.properties:22-26, 81, 92, 308` |
| Per-credential knobs held globally | `data-provider-plugin.did-url`, `rendering-template-id`, `vc-expiry-duration`, `id-field-prefix-uri`, `velocity-template.env-configs.*`, `credential-status.allowed-status-purposes`, `status-list.*` | `CertifyIssuanceServiceImpl`, `VelocityTemplatingEngineImpl`, `StatusListCredentialService` |
| Mode switches | `mosip.certify.plugin-mode`, `mosip.certify.integration.scan-base-package`, `integration.data-provider-plugin`, `integration.vci-plugin`, `integration.audit-plugin`, `allow-c-nonce` | `@ConditionalOnProperty` on the two issuance services and the plugins |
| Endpoint security | Three URL lists that must be edited for every new endpoint: `security.ignore-auth-urls`, `security.ignore-csrf-urls`, `authn.filter-urls` (exact-path match) | `SecurityConfig`, `AccessTokenValidationFilter.shouldNotFilter` |
| Caches | Cache names, sizes and TTLs as three parallel lists/maps that must agree (`cache.names`, `cache.size`, `cache.expire-in-seconds`) | `SimpleCacheConfig`, `RedisCacheConfig`, `VCICacheService.validateCacheConfiguration` |
| Keymanager | 35 `mosip.kernel.*` keys (HSM type and path, certificate defaults, key policy, `dao.enabled`) mixed into the same file | `application-local.properties:180-260` |
| Validation | None at startup beyond what Spring needs; a wrong SpEL literal fails at first use with a `SpelEvaluationException`; unknown keys are silently ignored | |
| Documentation | Hand-written tables in `docs/technical_docs/*.md`; no generated reference | |

## What it costs

- Adding an endpoint means editing three URL lists in every deployment's config repository, or it is silently unauthenticated (`shouldNotFilter` returns true for unknown paths).
- Adding a signing algorithm means editing three SpEL maps in step (`key-alias-mapper`, `credential-signing-alg-values-supported`, and per-format binding methods), and a typo surfaces as a runtime SpEL error.
- A second issuer, tenant or credential-type-specific DID cannot be expressed because identity and DID are global.
- Plugin selection is a class name in a property plus a package scan; two data sources cannot coexist.
- Operators cannot tell which keys exist, which are required, or which are deprecated; there is no generated reference and no startup check.

## Target

One namespace, `certify.*`, one typed record per module, validated at startup, documented from metadata, with every 0.14.0 and 1.0.0-beta.1 key still accepted through aliases.

| Namespace | Owner module | Holds | Replaces |
| --- | --- | --- | --- |
| `certify.issuer` | core | `identifier` (the one issuer URL), `did`, `display[]`, `tenant-default` | `domain.url`, `identifier`, `discovery.issuer-id`, `data-provider-plugin.did-url`, `credential-config.issuer.display` |
| `certify.protocol.oid4vci-v1` | oid4vci-v1 adapter | `enabled`, `base-path` (`/oid4vci`), `compat-paths.enabled`, `nonce-endpoint.enabled`, `encryption.*`, `profile` (`none`/`haip`), `deferred.enabled`, `notification.enabled`, `key-attestation.attesters.<id>.jwks\|trust-anchor`, `key-attestation.clock-skew` (P3-10), `did-web-holders.enabled\|timeout` (P3-11), `offers.default-issuer` (`legacy` default \| `oid4vci`: the surface a `POST /pre-authorized-data` without `issuer` mints for; M-09, D5), `offers.max-claims-bytes` (8192) and `offers.max-claims-values` (256): the most an offer's `claims` may hold as UTF-8 JSON and as JSON values at any depth, `invalid_request` above either (F-21 review round 2; the mDL profile sets 1024 and 32) | `allow-c-nonce`, `cnonce-expire-seconds`, `supported.jwt-proof-alg` |
| `certify.protocol.oid4vci-d13` | oid4vci-d13 adapter | `enabled` (default true), `versioned-paths.enabled` | new |
| `certify.offer-page` | offer page | `enabled` (false; P5-02), `demo-subjects[].{id, label, credential-configuration-ids[]}` (F-15: the subjects the page offers in place of a typed id, served by `GET /offer/demo-subjects`; operator-configured only, empty by default, validated at bind time — the record is bound only when `enabled=true`, so a bad list in a deployment that does not serve the page never stops startup) | new |
| `certify.protocol.vc-api` | vc-api adapter | `enabled` (false), `clients.<id>.secret`, `clients.<id>.credential-configurations` (P5-01; bearer-token clients later) | new |
| `certify.authz` | authz | `issuer-uri`, `jwk-set-uri`, `audiences[]`, `jws-algorithms[]`, `dpop.*` (allowed algorithms, max age, skew, jti ttl), `local-test-tokens.enabled` | `authn.*`, `dpop.*`, `security.*`, profile `local` |
| `certify.signing` | signing | `default-provider`, `providers.keymanager.*` (alias table, kid strategy), `providers.jca.*` (path, password, `dev-mode`), `header-policy.<format>.*`, `key-expiry.*` (row below); the x509-file provider is `certify.keyprovider.x509-file` (row below) | `signature-algo.key-alias-mapper`, `credential-config.credential-signing-alg-values-supported`, `credential-config.cryptographic-binding-methods-supported`, `credential-config.proof-types-supported`, `status-list.signature-*`, `status-list.key-manager-ref-id` |
| `certify.signing.key-expiry` | service (`SigningKeyExpiry`, M-05) | `warn-days` (`30`: a current signing key expiring within that many days is logged at WARN), `reconcile-interval` (`PT1H`; zero or negative turns the periodic reconciliation of the gauge `certify.signing.key.expires_in_days{keyRef}` off, the report at startup still runs) | new |
| `certify.keyprovider.x509-file` | `certify-keyprovider-x509-file` (P3-01, dev CA P3-08, M-05) | `enabled` (false), `id` (`x509-file`, the provider part of `x509-file:<alias>`), `path` (the PKCS#12 file), `password`, `dev-mode` (false: generate the listed keys and create the file when missing; never in production), `purpose` (`vc-signing`), `ca-alias` (`dev-ca`) and `ca-subject` (`CN=Inji Certify Dev CA`) for the dev CA that signs `plain` keys, `keys[].{alias, algorithm, subject, profile, validity-days}` (`profile` `plain` default \| `mdoc-dsc`, an Annex B Document Signer under the IACA; `validity-days` unset: 365 plain, 457 for a Document Signer), `iaca.{alias, country, state, common-name, issuer-alt-name, crl-uri, validity-years, algorithm}` (dev mode: an Annex B IACA, `alias` default `iaca`, 20 years and ES256 when unset; `crl-uri` `https://<host>/v1/certify/mdoc/iaca/<id>.crl` so Certify serves it), `pem-keys[].{alias, key, key-password, chain}` (a Document Signer key and its `[DSC, IACA]` chain from PEM files). Aliases are lower case with at most one `@` (`name` or `name@version`), checked at bind time; every stored setting is compared with the keystore at each start | new (never released; the provider has read `certify.keyprovider.x509-file.*` since P3-01) |
| `certify.keyprovider.keymanager` | `certify-keyprovider-keymanager` | `certificate-cache-ttl` (`PT60S`) | new |
| `certify.format.mdoc` | `certify-format-mdoc` | `mso-validity` (Duration, `P90D`, at least one minute; capped at the DSC `notAfter` and an mDL's `expiry_date`), `validity-period-years` (deprecated fallback when `mso-validity` is unset), `digest-algorithm` (`SHA-256` \| `SHA-384` \| `SHA-512`), `mso-version` (`1.0`, the only value accepted). Element types are not a property: `formatConfig.elementTypes` of a credential configuration (v2 API) types elements outside the built-in `org.iso.18013.5.1` table | `mosip.certify.mdoc.validity-period-years`, `mosip.certify.mdoc.digest-algorithm` (1.0.0-beta.1 `MDocConfig`), read below the new keys; the deciding key is logged once at startup |
| `certify.status.token-status-list` | service (Token Status List) | `key-ref` (`provider:alias`, e.g. `x509-file:sdjwt-es256`; keymanager's EC key when unset), `alg` (`ES256`), `x5c` (`without-anchor`), `size-bits` (`131072`), `ttl` (`PT1H`: lists carry `exp = iat + 2 ttl` and are signed again when served with less than `ttl` left, expired, or under another URI), `renew-wait` (`PT5S`: how long a request for an expired list waits for the re-sign before 503 with `Retry-After`), `renew-backoff` (`PT30S`: no new re-sign attempt for that long after one failed) | new |
| `certify.templates` | templates | `default-engine`, `velocity.params.*`, `validation.enabled` | `data-provider-plugin.velocity-template.env-configs.*`, `vcformat.vc.expiry` |
| `certify.credentials.defaults` | core | `validity` (`P730D`), `id-prefix`, `rendering-template-id`, `status.purposes[]`, `status.mechanism` — defaults that each credential configuration may override | `data-provider-plugin.vc-expiry-duration`, `id-field-prefix-uri`, `rendering-template-id`, `credential-status.allowed-status-purposes`, `statuslist.*` |
| `certify.ledger` | listeners | `enabled`, `indexed-attributes.*` | `issuer.ledger-enabled`, `indexed-mappings.*` |
| `certify.plugins` | core | `data-sources[]` (id, class or bean, config), `external-issuers[]`, `audit`, `scan-packages[]` | `plugin-mode`, `integration.*` |
| `certify.pki` | service (`io.mosip.certify.trust`, M-06/M-08) | `trust-anchors.mdoc-iaca[].{id, certificate, crl}` (IACA trust anchors, PEM or DER; `id` optional), `trust-anchors.crl-refresh-interval` (`PT5M`; zero or negative turns CRL re-reading and dev-mode CRL renewal off), `trust-anchors.dev-crl-validity` (`P7D`), `stale-crl-grace` (`PT24H`), `publication.enabled` (false) | new |
| `certify.datasource.file` | file data source (`certify-service`, M-10a) | `sources.<id>.{path, key-claim, binary-fields}` — one JSON file per source, registered by the module itself; `key-claim` defaults to `sub`; the compose mDL profile's id is `mdldemo` | new |
| `certify.as` | certify-as | `enabled`, `issuer`, `token.*`, `pre-authorized.*`, `pre-authorized-grant.advertise-anonymous-access`, `iae.*`, `verify.*`, `par.enabled`, `dpop-bound-tokens.enabled`, `client-attestation.*` | `oauth.*`, `pre-auth.*`, `iar.*`, `iae.*`, `verify.*`, `vp-request.*`, `authorization.*`, `credential-offer-url`, `credential-config.as-mapping` |
| `certify.cache` | app | `type`, `redis.*`, and one map `entries.<name>.{size,ttl}` | `cache.names`, `cache.size`, `cache.expire-in-seconds`, `*-cache-expire-seconds` |
| `certify.db` | persistence | `migrate-only`, `flyway.*` passthrough | new |
| `certify.tenancy` | core | `enabled`, `resolver` (`fixed`/`host`/`path`), `tenants.<id>.*` overrides of `certify.issuer` and `certify.signing` | new |
| `certify.deprecated.<name>.enabled` | app | kill switches | in place since P0-09 |
| `mosip.kernel.*` | keymanager provider | unchanged; keymanager owns its keys | |

`certify.datasource.file.sources.<id>` is the built-in file data source, a convenience over `certify.plugins.data-sources[]`: a
plugin-provided source is named there with its class or bean, while a JSON file is declared with only its `path` (plus
`key-claim`, `binary-fields`) and needs no code. Both share one id space — a credential configuration's `dataSourceId`
selects either kind — so a file source may not take the reserved id `data-provider-plugin`. A credential configuration
without `dataSourceId` keeps using the data-provider plugin when file sources are registered. Ids containing `-` (such
as `mdl-demo`) are fine in properties and YAML files but cannot be set through environment variables
(`CERTIFY_DATASOURCE_FILE_SOURCES_MDL_DEMO_PATH` binds `mdl.demo`), which is why the compose mDL profile uses
`mdldemo`; a deployment configured only through environment variables should use a dash-free id.

`certify.pki.trust-anchors.mdoc-iaca` lists the ISO/IEC 18013-5 IACAs mDoc Document Signers are checked against
(`docs/design/20-mdl-issuer.md` M-06); the x509-file provider's IACAs join them automatically when that provider is
enabled. With at least one anchor the mDoc DSC policy is enforced on every surface; with none, mDocs sign as before and
the service logs once that the policy is not enforced. Every certificate must pass the Annex B IACA profile and every CRL
the CRL profile at startup, or the service does not start. An anchor's `id` names its downloads under `/mdoc/iaca`
(M-08); unset, it is the `<id>` of the IACA's CRL distribution point `…/mdoc/iaca/<id>.crl`, else its subject key
identifier in lower-case hex; an IACA whose CRL distribution point is `…/mdoc/iaca/<x>.crl` with an `<x>` that is not
its id, or not a valid id, refuses startup. `certify.pki.stale-crl-grace` is how long an anchor's CRL may be past its
`nextUpdate` before mDoc signing under it is refused (`CRL_STALE`); past it at startup the service logs an ERROR and starts, since
only mDoc signing under that IACA is affected; `PT0S` refuses as soon as it passes. In a list the entries bind as `certify.pki.trust-anchors.mdoc-iaca[0].certificate`, or
`CERTIFY_PKI_TRUSTANCHORS_MDOCIACA_0_CERTIFICATE` from the environment.

Rules:

- Each namespace is a Java record annotated `@ConfigurationProperties` and `@Validated`, bound once, injected as a whole; no `@Value` in `certify-core`, `certify-signing`, formatters or adapters (an ArchUnit rule from Phase 1). Structured values are YAML lists and maps, never SpEL literals; the alias layer parses the old SpEL forms into the new shape for as long as the old keys exist.
- Aliases: an `EnvironmentPostProcessor` maps every old key to its new key (a table in `certify-app`, generated into the docs), logs one warning per old key at startup, and is removed in 2.0.0. Deployments do not have to change a single key to upgrade.
- Startup validation: unknown `mosip.certify.*` and `certify.*` keys are listed in one warning; missing required keys and invalid values fail fast with the key name; every namespace has a `validate()` for cross-field rules (a configured signing provider must exist, a HAIP profile must have the nonce endpoint on).
- Endpoint security is declared by the adapters: each registers its paths and their authentication requirement (`HOLDER_TOKEN`, `CLIENT_CREDENTIALS`, `PUBLIC`, `ADMIN`) with `certify-authz`; the three URL lists disappear, and a new endpoint cannot be unauthenticated by omission.
- Per-credential knobs live in the credential configuration (`format_config`, `signing_config`, `status_config`, `template`), with `certify.credentials.defaults` as the fallback; global values are read only when a configuration is silent.
- Reference documentation is generated: `spring-boot-configuration-processor` produces `spring-configuration-metadata.json`, and a build step renders `docs/config-reference.md` with key, type, default, description, since, deprecated-by.
- Profiles: `local` (TestBearer tokens, mock data), `dev` (JCA dev keys, no keymanager tables), `conformance` (seeded configurations, fixed data), `prod` defaults; the profile names are the only place behaviour switches on a profile.
- Secrets (`spring.datasource.password`, keystore passwords, `mosip.kernel.keymanager.hsm.keystore-pass`) are read from environment or secret references, never committed in property files; the docker-compose and Helm values show the pattern.

## Migration path

| Phase | Change | Operator impact |
| --- | --- | --- |
| P0 (done) | `certify.deprecated.*` kill switches | none |
| P1 | Typed records for `certify.authz`, `certify.signing`, `certify.issuer` with the alias layer; ArchUnit rule against `@Value` in core and signing; startup warning for unknown keys | none; old keys keep working, warnings show the new names |
| P2 | `certify.credentials.defaults`, `certify.templates`, `certify.plugins`, `certify.cache` records; per-credential overrides in `credential_config`; generated `docs/config-reference.md` | none required; new keys documented |
| P3 | Adapter-declared endpoint security replaces the URL lists; `certify.protocol.*` records; `certify.as` record | the three URL lists become no-ops with a warning |
| P5 | `certify.tenancy` record; `certify.db` | none |
| 2.0.0 | Alias layer removed; old keys rejected at startup with the new name in the message | config repository updated once, using the generated mapping table |

Old-to-new mapping for the keys every deployment sets today:

| Old key | New key |
| --- | --- |
| `mosip.certify.domain.url`, `mosip.certify.identifier`, `mosip.certify.discovery.issuer-id` | `certify.issuer.identifier` |
| `mosip.certify.data-provider-plugin.did-url` | `certify.issuer.did` |
| `mosip.certify.credential-config.issuer.display` | `certify.issuer.display[]` |
| `mosip.certify.authn.issuer-uri`, `authn.jwk-set-uri`, `authn.allowed-audiences` | `certify.authz.issuer-uri`, `certify.authz.jwk-set-uri`, `certify.authz.audiences[]` |
| `mosip.certify.authn.filter-urls`, `security.ignore-auth-urls`, `security.ignore-csrf-urls` | removed; adapters declare their paths |
| `mosip.certify.dpop.*` | `certify.authz.dpop.*` |
| `mosip.certify.signature-algo.key-alias-mapper` | `certify.signing.providers.keymanager.aliases.<alg>[]` |
| `mosip.certify.credential-config.credential-signing-alg-values-supported` | removed; `AlgorithmRegistry` |
| `mosip.certify.credential-config.cryptographic-binding-methods-supported`, `proof-types-supported` | `certify.protocol.oid4vci-v1.binding-methods.<format>[]`, `certify.protocol.oid4vci-v1.proof-types.*` |
| `mosip.certify.plugin-mode`, `integration.data-provider-plugin`, `integration.vci-plugin`, `integration.scan-base-package` | `certify.plugins.data-sources[]`, `certify.plugins.external-issuers[]`, `certify.plugins.scan-packages[]`; strategy per credential configuration |
| `mosip.certify.data-provider-plugin.vc-expiry-duration`, `id-field-prefix-uri`, `rendering-template-id` | `certify.credentials.defaults.validity`, `.id-prefix`, `.rendering-template-id`, overridable per configuration |
| `mosip.certify.data-provider-plugin.velocity-template.env-configs.*` | `certify.templates.velocity.params.*` |
| `mosip.certify.allow-c-nonce`, `cnonce-expire-seconds` | `certify.protocol.oid4vci-v1.nonce-endpoint.enabled`, `.ttl` |
| `mosip.certify.oauth.*`, `pre-auth.*`, `iar.*`, `iae.*`, `verify.*`, `vp-request.*`, `credential-offer-url`, `credential-config.as-mapping` | `certify.as.*` |
| `mosip.certify.cache.names`, `cache.size`, `cache.expire-in-seconds`, `*-cache-expire-seconds` | `certify.cache.entries.<name>.{size,ttl}` |
| `mosip.certify.issuer.ledger-enabled`, `indexed-mappings.*` | `certify.ledger.enabled`, `certify.ledger.indexed-attributes.*` |
| `mosip.certify.status-list.*`, `statuslist.*`, `data-provider-plugin.credential-status.allowed-status-purposes` | `certify.credentials.defaults.status.*` |
| `mosip.kernel.*` | unchanged |
