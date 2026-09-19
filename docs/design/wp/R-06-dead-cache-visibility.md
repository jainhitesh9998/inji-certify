# R-06 A cache nobody read, and methods only their class calls

Branch: `wp/r-06-dead-cache-visibility` off `design/extensibility`. Refactor slice per `R-00-refactor-charter.md`, areas "Formats and templating (legacy)" and "Status, ledger, cache" (small, mechanical).

## What was wrong

`VelocityTemplatingEngineImpl.getCachedCredentialConfig` declared `@Cacheable("credentialConfig")` but is only called from within its own class, so the Spring proxy never intercepted it and the cache was never written (documented Spring behaviour for self-invocation). The two configuration services nevertheless evicted that cache on every update and delete, one of them through a `CredentialCacheKeyGenerator` bean whose only job was to compute the key of an entry that never existed, with a second database read per eviction. `StatusListCredentialService` exposed five methods that only the class itself calls.

## Files changed

| File | What was wrong | What changed |
| --- | --- | --- |
| `vcformatters/VelocityTemplatingEngineImpl.java` | `@Cacheable` on a self-invoked `protected` method; a "cache miss" log for a cache that never hit | annotation gone, method private, log says what happens |
| `services/CredentialConfigurationServiceImpl.java` | `@Caching` with an eviction of the dead cache keyed through `@credentialCacheKeyGenerator` (an extra row read per call) and three comments explaining the trade-off | one `@CacheEvict` of the issuer metadata cache, as before; constant and comments gone |
| `configv2/CredentialConfigurationV2Service.java` | the same dead eviction under `LEGACY_CONFIG_CACHE` on create, update and delete | one `@CacheEvict` of the issuer metadata cache |
| `utils/CredentialCacheKeyGenerator.java`, its test | a bean for the dead eviction | deleted |
| `services/StatusListCredentialService.java` | `findStatusListById`, `generateStatusListCredential`, `findOrCreateStatusList`, `findNextAvailableIndex` public with no caller outside the class; `findSuitableStatusList` likewise | package-private (the test shares the package); `findSuitableStatusList` private |

No behaviour change: the metadata cache evictions stay; the `credentialConfig` cache name may remain in `mosip.certify.cache.names` of existing deployments (an empty cache, harmless).

- Finding fixed on the way (F-01, its own commit): the gate run of this slice failed `ecdsaSecp256r1Signature2019GoldenAndJcaVerification` once; the cause is `DIDDocumentUtil` encoding the P-256 X coordinate minimal-length (a stray zero byte for 1 key in 256), not this slice. Fixed with fixed-width coordinates in the DID document and in `DIDkeysProofManager`, with regression tests that search for such a key.

## Acceptance criteria

- [x] `VelocityTemplatingEngineImplTest`, `CredentialConfigurationSupportedServiceImplTest`, `CredentialConfigurationV2Test`, `StatusListCredentialServiceTest`, `IssuanceGoldenTest` green; no golden changed.
- [x] Full `certify-service` suite green (1034, reverse order, after F-01); CI: the integration-branch run after merge.
