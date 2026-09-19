# P3-11 `did:web` holder keys behind a switch; `did:key` in the advertised default

Branch: `wp/p3-11-did-web-holders` off `design/extensibility`. Phase 3. Size: S. Depends on: V-01 (holder key validation).

## Goal

The owner's decision of 2026-09-19 on the finding of V-01: the shipped default advertises `did:jwk` and `did:key` (what the resolvers handle), and `did:web` holders are a configuration choice that works when switched on, instead of an advertised method no resolver honoured.

## Scope

- `DIDwebProofManager` (`io.mosip.certify.proof`, the fourth `JwtProofKeyManager`): `kid` of the form `did:web:host[:path...]#fragment` resolves to `https://host/[path/]did.json` (`/.well-known/did.json` without a path, a port percent-encoded as `%3A`), the document's `id` must be the DID, and the verification method whose `id` is the `kid` (absolute or `#fragment`) supplies the key as `publicKeyJwk` or `publicKeyMultibase`; the key gets the `kid` so the JWS key selector matches. The bound identifier is the `kid` as sent, like `did:key`.
- `DidDocumentFetcher`: HTTPS only, no redirects, `Accept: application/did+json, application/json`, a timeout; tests substitute a stub.
- `DidWebHolderConfiguration`: the fetcher and the manager exist only with `certify.protocol.oid4vci-v1.did-web-holders.enabled=true` (`Oid4vciProperties.DidWebHolders(enabled=false, timeout=PT5S)`). `JwtProofValidator` accepts a `did:web` `kid` in its header check and dispatches to the manager only when it is present, so both surfaces behave as before when the switch is off.
- `DIDkeysProofManager`: the multicodec decoding is `fromMultibase(String)` (shared with `publicKeyMultibase`), `withKid` sets the `kid` on every key type (before: P-256 and, since V-01, RSA).
- Defaults: `application-local.properties` advertises `{'did:jwk','did:key'}` for `ldp_vc` and `dc+sd-jwt` (the compose profile already did); `did:web` is added per deployment or per configuration when the switch is on.
- Tests: `DIDwebProofManagerTest` (DID to URL, `publicKeyJwk`, `publicKeyMultibase` with a relative fragment id, unknown method, mismatched document id, fetch failure); `HolderDidMethodsTest` gains `kid did:web:wallet.example#key-1` on both surfaces with a stubbed fetcher and asserts `did:web` in the advertised methods when configured.

## Outside scope

DID document caching, `did:web` for the issuer side (unchanged, `DIDDocumentUtil`), other DID methods (`did:ion`, `did:ebsi`), verification relationships (`authentication`, `assertionMethod`) beyond the method id match.

## Acceptance criteria

- [x] `DIDwebProofManagerTest`, `DIDkeysProofManagerTest`, `JwtProofValidatorTest`, `JwtProofValidatorAdapterTest`, `HolderDidMethodsTest`, `IssuanceGoldenTest` green; no golden changed (the goldens pin their own binding methods).
- [x] Full `certify-service` suite green (1036, reverse order); CI: the integration-branch run after merge.
- [x] Decision rows (records confirmed; `did:key` default, `did:web` configurable) in `12-risks-and-decisions.md`; release note; `18-compatibility-validation.md` updated.
