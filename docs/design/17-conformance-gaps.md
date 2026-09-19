# 17. Conformance: what the OpenID Foundation issuer test needs and what is missing

Written on 2026-09-19 from the OpenID Foundation certification page ("OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test an Issuer") and the HAIP 1.0 profile. The suite acts as a wallet against a publicly reachable issuer; it does **not** support the pre-authorized code flow ("HAIP mandates the use of the authorization code flow"), it requires client attestation, and it verifies credentials and status lists against trust anchors the tester uploads.

## What the suite drives

| The suite needs | Certify today (`design/extensibility`) |
| --- | --- |
| Issuer metadata over HTTPS at a public host; `scope` per configuration; `nonce_endpoint`; `batch_credential_issuance` present or absent | New surface metadata under `/oid4vci` with scope, nonce, notification and batch (P1-11, P3-02, P3-03). Public HTTPS is a deployment matter (`docs/design/15-deployment.md`) |
| Authorization code flow, wallet-initiated (scope) and issuer-initiated (credential offer with the `authorization_code` grant and `issuer_state`), with PKCE `S256` and pushed authorization requests, redirecting to `https://www.certification.openid.net/test/a/<alias>/callback` with a code | Certify's own AS has the pre-authorized code grant and the presentation-during-issuance code grant (`/oauth/iae`, PKCE `S256`); no `authorization_endpoint`, no PAR, no `issuer_state`, no redirect-based code delivery |
| Attestation-based client authentication (`OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers, HAIP Appendix E) at the OAuth endpoints, against the attestation issuer's JWKS or `x5c` the tester configures | Not implemented; the token endpoint takes `client_id` only |
| DPoP-bound access tokens (`token_type: DPoP`, `cnf.jkt`) | The resource server validates DPoP proofs (`DpopProofValidator` from develop); the own AS issues Bearer tokens only |
| `dc+sd-jwt` with an `x5c` chain to the uploaded trust anchor (the anchor itself not in `x5c`, the signing certificate not self-signed); `mso_mdoc` with `x5chain` to the anchor | SD-JWT is signed with the keymanager key and a `kid` (no `x5c`); mDoc carries `x5chain` from keymanager's certificate (self-signed today). `certify-signing` already knows `x5c`/`x5t#S256` header policies and `CertificateChain`; the `x509-file` provider (P3-01) generates a self-signed dev chain; `CertificateChainPolicy` is designed (docs/design/06a) but not built |
| Token Status List (`status.status_list` in SD-JWT VC, the status list JWT signed under a trust anchor) | Bitstring Status List for `ldp_vc` only (P1-10a) |
| `jwt` proofs with nonce; optionally `key_attestation` in the proof header (Appendix D) | `jwt` proofs with nonce, single-use (P3-03); `key_attestation` validated against configured attesters and the `attestation` proof type accepted (P3-10) |
| Credential response encryption and signed metadata, if advertised | Neither advertised nor implemented |
| Notification endpoint, if advertised | P3-02 |

## The gaps, in the order they unblock the test

1. **Authorization code flow in `certify-as`** (blocks everything: without it the suite cannot obtain a token). `authorization_endpoint`, `pushed_authorization_request_endpoint`, PKCE `S256`, `scope` mapped to a configuration, issuer-initiated offers with `issuer_state`, the code delivered by redirect, the token endpoint's `authorization_code` grant reused from the IAE work. Decision needed: how the AS establishes the subject in this flow (see below).
2. **Client attestation** at PAR and token endpoints (HAIP Appendix E): validate the attestation JWT against the configured attestation issuer keys and the PoP JWT (audience the AS, nonce optional, `jti` replay).
3. **DPoP at the token endpoint**: bind the token to the wallet key (`cnf.jkt`), answer `token_type: DPoP`, and make the resource-server check enforce the binding.
4. **PKI for SD-JWT VC and mDoc**: sign both with a certificate chain from an `x509` provider (a dev CA plus leaf, since HAIP forbids a self-signed signing certificate), `x5c`/`x5chain` without the anchor, `CertificateChainPolicy` before every signature, and the trust anchor published for the tester.
5. **Token Status List** for SD-JWT VC and mDoc: a `StatusProvider` that allocates indices, the status list JWT (and CWT for mDoc) signed under the same chain, a status list URI, and the revocation path already used by Bitstring.
6. **Key attestation** in `jwt` proofs: parse and validate the `key_attestation` JWT when present, refuse when the configuration requires it. Done in P3-10 (`docs/design/wp/P3-10-key-attestation.md`).
7. **Credential response encryption** (`credential_response_encryption` in metadata, JWE credential responses) and **signed metadata**: optional for the suite, part of the 1.0 feature set.
8. **Deployment for the run**: HTTPS issuer identifier on a public host reachable from the suite's IP, a registered redirect URI, the trust anchors and client attestation material exported for the tester. Runbook: `19-conformance-run.md`; the run itself needs the owner's public host.

Rough effort at the pace of this branch: 1 to 3 together about two to three days, 4 and 5 about two days, 6 and 7 about half a day each, 8 an afternoon.

## Decisions needed before item 1

- **Subject in the authorization code flow.** The suite only needs a code back after the redirect. Options: (a) presentation during issuance as today (`/oauth/iae`), which the suite does not speak; (b) a `certify.as.authorization.subject-mode=fixed` setting for conformance and demos that approves every request for a configured subject without user interaction; (c) delegate the authorization endpoint to eSignet. Recommendation: (b) behind a flag for the conformance run, (a) kept for the Inji wallet, (c) unchanged for production deployments that already use eSignet.
- **PKI source.** The `x509-file` provider with a generated dev CA and leaf for the conformance run; keymanager's CSR flow or an operator-supplied PKCS#12 for production.
- **Where Token Status List rows live.** Reuse `status_list_credential` and `status_list_available_indices` with a new format column, or a new table (additive either way).
