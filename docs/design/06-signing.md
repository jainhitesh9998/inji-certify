# Signing extensibility

> Part of the Inji Certify extensibility design. Baseline: `develop` at `a1cfd63` (1.0.0-beta.1-SNAPSHOT). Index: [README.md](./README.md).

Certify signs through seven distinct paths into MOSIP keymanager, speaks four algorithm vocabularies mapped in three places, and derives its public keys twice; none of it can run outside the Spring service. The design below keeps keymanager as the default provider, adds file, PKCS#11, KMS and remote providers behind one contract, and makes the same code usable from a CLI.

| # | Path | Used by | Keymanager call | Hard-coded in the path | Key chosen by |
| --- | --- | --- | --- | --- | --- |
| 1 | Legacy LD suites with JWS proof (`RsaSignature2018`, `Ed25519Signature2018`, `EcdsaKoblitzSignature2016`, `EcdsaSecp256k1Signature2019`) | `W3CJsonLD` via one `ProofGenerator` class per suite | `jwsSign`, detached, `b64=false` | JWS alg per class (`RS256`, `EdDSA`, `ES256K`) | `credential_config.key_manager_app_id` / `ref_id` |
| 2 | Legacy LD suites with multibase proof (`Ed25519Signature2020`, `EcdsaSecp256r1Signature2019`) | same | `signv2`, base58btc `proofValue` | alg per class | same |
| 3 | Data Integrity cryptosuites (`eddsa-rdfc-2022`, `eddsa-jcs-2022`, `ecdsa-rdfc-2019`, `ecdsa-jcs-2019`) | `W3CJsonLD` through danubetech `LdSigner` and `KeymanagerByteSigner` | `signv2`, base58btc decoded to bytes | static instance cache keyed `appId:refId:alg` (`KeymanagerByteSignerFactory`) | same |
| 4 | SD-JWT | `SDJWT.addProof` (`:120-143`) | `jwsSignV2` | `typ: dc+sd-jwt`, `x5c` chain on, `x5t#S256` on, `b64` header on, empty `certificateUrl` | same |
| 5 | mDoc MSO | `MDocProcessor.signMSO` | `coseSign1` | `includeCertificate` unprotected header; JOSE-to-COSE algorithm mapping inside keymanager | same |
| 6 | Claim-169 QR | `Credential.signQRData` (`:125-142`) | `cwtSign` | `x5c` and `kid` protected headers; issuer = `mosip.certify.domain.url` | `qr_signature_algo`, first `key-alias-mapper` entry |
| 7 | Access tokens (embedded AS) | `AccessTokenJwtUtil` (`:126`) | `jwsSign` | `CERTIFY_SERVICE` application id | fixed |

Two more paths ride on the table: the status-list VC is signed through path 2 or 3 with keys from `mosip.certify.status-list.*` properties (`StatusListCredentialService.java:53-71`), and `Credential.addProof`'s default `jwsSign` with `certificateUrl = didUrl` (`:96-115`) is dead code now that `jwt_vc_json` is gone.

Around the paths:

- Key identity is keymanager's `(appId, refId)` pair. It is a public API field (`CredentialConfigurationDTO.keyManagerAppId`, `keyManagerRefId`), a table column, a validation rule against `mosip.certify.signature-algo.key-alias-mapper` (`CredentialConfigurationServiceImpl.java:185-220`), and the argument of every signing call.
- Key bootstrap is `AppConfig.initKeys` (`:131-162`): four fixed application ids (`CERTIFY_VC_SIGN_RSA`, `_ED25519`, `_EC_K1`, `_EC_R1`) created only when `plugin-mode=DataProvider`; no rotation, no per-configuration keys.
- Public keys are derived twice from X.509: `JwksServiceImpl` walks `key-alias-mapper` plus `CERTIFY_SERVICE` (`:58-72`) and extracts Ed25519 by SPKI byte offsets (`:189-196`); `DIDDocumentUtil` walks every credential configuration via `findAll()` (`:289-291`) and chooses the verification-method type by cryptosuite.
- Four algorithm vocabularies (JOSE `ES256`, LD suite `Ed25519Signature2020`, Data Integrity `eddsa-rdfc-2022`, COSE `-7`) are mapped in three places: the `credential-signing-alg-values-supported` property, `COSE_ALGORITHM_INTEGER_MAP`, and danubetech's `findCryptosuitesForJwsAlgorithm`.
- Every signing class is a Spring `@Component` with `@Value` properties; keymanager itself is Spring plus JPA over `key_alias`, `key_store`, `key_policy_def`. Nothing here can be instantiated from a `main()`.

What other key stores need from Certify, so the contract covers them from the start:

| Provider | Where the key lives | Sign primitive | Certificate chain | Notes |
| --- | --- | --- | --- | --- |
| MOSIP keymanager, embedded library (default, unchanged) | DB-encrypted keys or HSM through keymanager's own PKCS#11 configuration | keymanager builds JWS, COSE and CWT envelopes itself, in-process | X.509 in `key_store` | Stays the default provider, same jar, same tables, same properties; no network call is introduced |
| PKCS#11 direct (SoftHSM, Luna, nCipher, YubiHSM) | HSM | raw signature in-process (DER ECDSA, PKCS#1 v1.5 or PSS, EdDSA where supported) | operator-supplied PEM chain | Envelope building must live in Certify |
| Cloud KMS through the vendor SDK (AWS KMS, GCP Cloud KMS, Azure Key Vault) | managed | raw signature, 10 to 50 ms per call, Ed25519 not universal | issued outside, supplied as PEM | Optional module; provider declares supported algorithms; batch signing needs concurrency |
| HashiCorp Vault Transit | managed | raw signature | optional | Optional module, same shape as KMS |
| File and JCA (PKCS#12, PEM) | file | raw signature in-process | self-signed or supplied | Tests, CLI, development, conformance runs |

The contract in `certify-signing` (no Spring Web, no JPA):

```java
public interface KeyProvider {
    String id();
    SigningKey resolve(KeyRef ref);                          // KeyRef = provider + alias + optional version
    List<PublicKeyDescriptor> publicKeys(KeyFilter filter);  // kid, jwk, x5c, alg, notBefore, notAfter, purpose
    Set<SignatureAlgorithm> supportedAlgorithms();
    default void ensureKeys(List<KeyRequirement> required) {}   // derived from configurations at boot
}

public interface Signer {
    byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm alg);                     // mandatory
    default Optional<String> signJws(JwsInput in, SigningKey key) { return Optional.empty(); } // native envelope
    default Optional<byte[]> signCose(CoseInput in, SigningKey key) { return Optional.empty(); }
}

// Envelope builders: formatters call these and never a provider directly
JwsEnvelope.sign(payload, JwsHeaderPolicy, key, signer)          // compact or detached, b64, typ, kid | x5c | x5t#S256
CoseEnvelope.sign1(payload, CoseHeaderPolicy, key, signer)       // COSE_Sign1, alg as integer, x5chain
CwtEnvelope.sign(claims, CwtHeaderPolicy, key, signer)
DataIntegrityEnvelope.sign(document, cryptosuite, key, signer)   // danubetech LdSigner over a ByteSigner that calls signRaw
LdLegacyEnvelope.sign(document, suite, key, signer)              // the six ProofGenerator classes become one table-driven class

AlgorithmRegistry   // one table: JOSE alg <-> COSE int <-> LD suite <-> DI cryptosuite <-> JCA name <-> curve
KidStrategy         // keymanager thumbprint (today) | RFC 7638 JWK thumbprint | x5t#S256 | custom
KeyPublisher        // JWKS and DID document from KeyProvider.publicKeys(); verification-method type from the registry
```

Each envelope builder tries the provider's native `signJws` or `signCose` first and falls back to `signRaw` plus in-Certify encoding, so keymanager keeps producing byte-identical output while a KMS produces the same envelope from a raw signature. Per-format header policy (`typ`, `x5c` on or off, `kid` strategy, `b64`) becomes data in `SigningConfig`, with today's values as defaults.

How existing keymanager support is kept. MOSIP keymanager is a library today and stays one: `kernel-keymanager-service` moves from `certify-service/pom.xml` into `certify-keyprovider-keymanager`, which `certify-app` includes by default, so a deployment that changes nothing keeps the same jar, the same `mosip.kernel.*` properties, the same four tables, the same HSM or SoftHSM configuration, the same `kid` values and byte-identical signatures. The provider module carries the wiring that `CertifyServiceApplication` and `AppConfig` carry today (the `io.mosip.kernel.*` component scan, `@EnableJpaRepositories`, `@EntityScan`, `initKeys`), and `mosip.certify.signing.provider` defaults to `keymanager`. Nothing in this design calls keymanager over HTTP.

| Today | After the change | Visible to an existing deployment |
| --- | --- | --- |
| `kernel-keymanager-service` in `certify-service` | Same dependency in `certify-keyprovider-keymanager`, on the classpath by default | No |
| `key_manager_app_id`, `key_manager_ref_id`, `signature_algo`, `signature_crypto_suite` columns and DTO fields | Read as `KeyRef{provider: keymanager, alias: appId/refId}`; v1 config API keeps accepting and returning them | No |
| `mosip.certify.signature-algo.key-alias-mapper` | Becomes the keymanager provider's alias table; same property name | No |
| `AppConfig.initKeys` creating `CERTIFY_VC_SIGN_*` keys in DataProvider mode | `KeymanagerKeyProvider.ensureKeys` creating the same keys from the same constants, plus any key a configuration names | No |
| `mosip.kernel.keymanager.signature.kid.prepend` | Honoured by the keymanager `KidStrategy` | No |
| `/system-info/certificate`, `/uploadCertificate`, `/generate-csr`, `/upload-ca-certificate` | Served by the keymanager provider module at the same paths | No |
| JWKS and `did.json` built from certificates | Built from `KeyProvider.publicKeys()` with the keymanager provider producing the same `kid`, `x5c` and verification methods, locked by golden tests | No |
| Seven direct keymanager call sites | One provider behind the envelope builders; the envelope builders call keymanager's native `jwsSign`, `jwsSignV2`, `signv2`, `coseSign1` and `cwtSign` through `signJws` and `signCose` so the bytes on the wire do not change | No |

Configuration for the new model: `SigningConfig` per credential configuration is `{ keyRef, alg, cryptosuite?, headerPolicy? }`. Key rotation is a `KeyRef` without a version resolving to the current key, with `publicKeys()` returning overlapping keys during the window, and the status-list re-sign job using the same path. A second provider is added by putting its module on the classpath and naming it in a configuration's `keyRef`; two providers can be active at once, so one credential type can sign with keymanager while another signs with a PKCS#11 token.

Signing from a command line. `certify-cli` (picocli; a GraalVM native image is optional) builds the same `IssuanceCommand` the HTTP adapters build, with `AuthorizationContext.NONE`, and uses whichever key provider the operator names:

| Command | What it does | Registry and keys |
| --- | --- | --- |
| `certify sign --in credential.json --format ldp_vc --suite eddsa-rdfc-2022 --key jca:issuer.p12#issuer` | `SUPPLIED` strategy: sign a prepared document, print the signed credential | No database; file or PKCS#11 key |
| `certify issue --config farmer.json --claims claims.json --key keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN` | `TEMPLATE` strategy: render and sign one credential from a configuration file | In-memory registry; keymanager provider boots a minimal Spring context (no web) against the keymanager tables and HSM configuration |
| `certify batch --config farmer.json --claims-csv farmers.csv --out ./signed/` | Pre-issue many credentials offline; optional ledger and status-list writes when `--db` is given | Same as `issue`; concurrency bounded by the provider |
| \`certify keys list | jwks | did-doc --provider pkcs11 --config hsm.yaml\` |
| `certify template render --engine velocity --template t.vm --claims sample.json` | Dry-run a template against sample claims (see the templating section) | None |
| `certify verify --in signed.json` | Verify a credential with the same verification libraries the tests use | None |

The constraint to state plainly: keymanager is Spring plus JPA, so a CLI using the keymanager provider must reach the keymanager database and HSM configuration; air-gapped or scripted signing uses the PKCS#11 or PKCS#12 provider with keys exported or generated for that purpose. Both are supported by the same `KeyProvider` contract.

Migration: Phase 1 introduces `certify-signing`, wraps keymanager as the first provider and routes all seven paths through the envelope builders with byte-identical output locked by golden tests; Phase 2 adds `signing_config` to the configuration model; the `jca` provider ships with the test kit in Phase 1 to keep the seam honest; PKCS#11 and one KMS provider follow in Phase 5 with the CLI. An ArchUnit rule restricts `io.mosip.kernel` imports to `certify-keyprovider-keymanager` from Phase 0.
