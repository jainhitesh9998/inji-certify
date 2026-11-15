# P5-03 Demo wallet: keep issued mDLs and present them to verifiers

> Part of the Inji Certify extensibility design: [20-mdl-issuer.md](../20-mdl-issuer.md) (the public demo, D12, M-09,
> F-21) and the offer page of P5-02/F-15. Planning document, 2026-11-14, written against `ad01e047` (F-21 review
> round 3, on `design/extensibility` `9cac1116`; M-11c `7de07e8e` is not in it). Work packages are branched as
> `wp/p5-03<letter>-<slug>` from `design/extensibility`. The three owner decisions below are recorded in
> [12-risks-and-decisions.md](../12-risks-and-decisions.md) (2026-11-14). Nothing else here is decided until the owner
> answers section 7 (CLAUDE.md rule 8); the answers go into the decision log before the first PR.

## 0. Summary

**What the owner asked.** The public demo's offer page (`/v1/certify/offer/` on `https://credentials.loremipsum.co.in`)
already plays a wallet: it redeems an OpenID4VCI 1.0 pre-authorized offer for an ISO/IEC 18013-5 mDL with a WebCrypto
P-256 key and shows the result. It keeps neither the credential nor the key, and it cannot present. The owner wants to
test verifiers with it, so the page wallet must keep issued mDLs and present them with selective disclosure.

**Owner decisions (2026-11-14, recorded).**

1. **Both protocols.** First OpenID4VP 1.0 (final, 9 July 2025): a verifier's QR code or link is scanned or pasted,
   the verifier and the requested claims are shown, the user can untick claims, and a DeviceResponse holding only the
   chosen IssuerSignedItems is returned. Second, the ISO/IEC TS 18013-7 REST "device retrieval to a website" flow.
   - **Correction.** The question put to the owner called this flow "Annex B (REST)". That label was wrong. In TS
     18013-7:2025 (contents read) and in the 2024 edition's DTS draft the REST/website flow is **Annex A**, "Mechanisms
     for device retrieval to a website". Annex B is "Use of OID4VP to retrieve an mdoc" (it pins OID4VP draft 18). Annex C, which exists only in
     the 2025 edition, is the Digital Credentials API. The owner's choice meant the REST flow, so this plan reads it as
     Annex A (section 1.4).
2. **Target verifiers end to end:** the EUDI reference verifier (`verifier.eudiw.dev`; backend
   `eu-digital-identity-wallet/eudi-srv-verifier-endpoint`, renamed from `eudi-srv-web-verifier-endpoint-23220-4-kt`),
   the Multipaz web verifier (`verifier.multipaz.org`) and Paradym verification (Animo).
3. **Non-goals:** in-person ISO 18013-5 sharing (device engagement QR then BLE or NFC: a browser cannot be a BLE
   peripheral) and the W3C Digital Credentials API (TS 18013-7:2025 Annex C, OpenID4VP 1.0 Appendix A: a web page cannot
   register as a DC API wallet).

**What the research found** (section 2 has the evidence).

| | EUDI | Multipaz | Paradym |
| --- | --- | --- | --- |
| How the page gets the request | QR (`haip-vp://` or `openid4vp://`), or same-device: the UI's editable "Authorization Endpoint" accepts our `https://…/offer/wallet` | **no QR**: the verifier tab navigates itself to `haip-vp://?…`; its scheme field is not validated, so `https://<host>/v1/certify/offer/wallet#` hands the request to our page on the same device | QR of `openid4vp://?request_uri&client_id`, or of an `https://paradym.id/invitation?request_uri=…` link |
| client_id prefix | `x509_hash` | `x509_san_dns:verifier.multipaz.org` | `x509_hash` (template signer `certificate`) or, by default, `decentralized_identifier:did:web` with Ed25519 |
| Response | `direct_post.jwt` (A128GCM/A256GCM) | `direct_post.jwt` (no enc list: A128GCM) | `direct_post.jwt` (A128GCM/A256GCM/A128CBC-HS256) |
| Handover checked | OpenID4VP 1.0 `OpenID4VPHandover` only | OpenID4VP 1.0 only | OpenID4VP 1.0 (the draft-18 `mdocGeneratedNonce` handover only for a "legacy" wallet setting) |
| **Trust in our IACA** | **yes**: `issuer_chain` PEM per transaction, or the UI's "Configure issuer chain" | **no**: four hard-coded IACAs; the result is still shown, marked "Not in trust list" | **yes**: Trust → Trusted Entities (PEM upload), linked as the template's `trustedIssuers` |
| **CORS** on request_uri / response_uri | open (any `Origin` echoed; tested) | **none** (`OPTIONS` 404; tested) | **none** in Credo; hosted endpoints unverified |
| 18013-7 Annex A | no | **yes** (`mdoc://` engagement, CBOR over HTTP POST, no CORS) | no |

No verifier still expects the older ISO 18013-7 Annex B `OID4VPHandover` with `mdocGeneratedNonce` for an OpenID4VP 1.0
request. The page implements OpenID4VP 1.0 B.2.6.1 only.

**Consequences for the design.**

- **The relay.** Multipaz, and very likely Paradym, cannot be read cross-origin, so the request object must be fetched
  server-side. The plan adds a narrow relay under `/offer/wallet/relay` with an explicit host allow-list and SSRF
  controls (4.9, P5-03f). EUDI needs none.
- **Multipaz trust.** The hosted Multipaz verifier cannot trust our IACA whatever the page does. It still verifies and
  shows the device and issuer signatures and the claims, marked "Not in trust list". CI runs Multipaz's own verifier
  code in-process with our IACA trusted (D-P5-03-5).
- **The REST flow (Annex A).** Only Multipaz offers it, and it invokes the wallet by navigating its own tab to
  `mdoc://…`. A web page can never receive that URI: `registerProtocolHandler` accepts only `web+` schemes and a fixed
  safelist. So the live test needs a pasted URI or a Multipaz-specific shortcut. It is planned last, behind an owner
  decision (D-P5-03-8).
- **The strongest independent gate** is the OpenID Foundation conformance suite's certifiable
  `oid4vp-1final-wallet-haip-test-plan` for `iso_mdl`:
  - it computes the B.2.6.1 transcript, checks device and issuer signatures with Multipaz, fails any element that was
    not requested, and carries wallet negative tests (bad signature, bad `typ`, mismatched client_id, bad prefix);
  - it runs self-hosted from pinned images (`release-v5.3.4`);
  - with the EUDI verifier container and Multipaz in-process, it forms the merge gates (4.14).

**Work packages** (section 5). Each slice is under about 800 changed lines, vendored files and recorded fixtures
excluded.

| WP | What | Size | After |
| --- | --- | --- | --- |
| P5-03a | keep issued mDLs: non-extractable key, IndexedDB, CBOR encoder and byte-exact reader, wallet page shell, CSP, harness infrastructure | ~750 planned, ~1,950 built (overrun noted in its section) | - |
| P5-03b | DeviceResponse and the OpenID4VP 1.0 SessionTranscript; `@owf/mdoc` and Multipaz checks; fixtures | ~750 planned, ~1,580 built (overrun noted in its section) | a |
| P5-03c | request intake and verifier authentication: links, request_uri GET/POST, JAR, `x509_hash`/`x509_san_dns`, X.509 reader, request checks panel | ~800 | a |
| P5-03d | DCQL and consent: matching, `trusted_authorities` (aki), `claim_sets`, `credential_sets`, `values`, unticking, test mode | ~600 | b, c |
| P5-03e | the response: `direct_post`/`direct_post.jwt` (ECDH-ES JWE), delivery, `redirect_uri`, decline, replay guard, log; `jose` and Multipaz `VerificationSession` gates | ~700 | d |
| P5-03f | the relay (server): allow-listed request-object and response forwarding, SSRF controls, nginx | ~650 | c |
| P5-03g | camera: `BarcodeDetector`, vendored jsQR 1.4.0 | ~300 | c |
| P5-03h | conformance and interop: OIDF HAIP wallet plan and EUDI verifier container in CI, live runbook for the three verifiers | ~600 | e, f |
| P5-03i | (D-P5-03-8) ISO/IEC TS 18013-7 Annex A | ~800 | e, f |

**Owner questions** (section 7), each with a recommendation:

| # | Question |
| --- | --- |
| D-P5-03-4 | the server relay for verifiers without CORS |
| D-P5-03-5 | Multipaz cannot trust our IACA |
| D-P5-03-6 | what the page keeps, and by default |
| D-P5-03-7 | verifier test mode, beyond unticking claims |
| D-P5-03-8 | Annex A: build now, build later, or not |
| D-P5-03-9 | Paradym's default `did:web` verifier identity |
| D-P5-03-10 | how the page presents a verifier it cannot check against a trusted list |
| D-P5-03-11 | CSP and Permissions-Policy on the offer pages |
| D-P5-03-12 | how often the conformance and interop jobs run |
| D-P5-03-13 | moving the CI harness from Node 20 (end of life) to Node 24 |

## 1. What the specifications require

Clause labels: **VP** = OpenID4VP 1.0 Final (published 9 July 2025, https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), **HAIP** = OpenID4VC HAIP 1.0 Final (24 December 2025), **ISO5** = ISO/IEC 18013-5:2021, **ISO7** = ISO/IEC TS 18013-7 (2024 first edition, 2025 second edition), RFC 7518 (JWA), RFC 7516 (JWE), RFC 7638 (JWK thumbprint), RFC 9052 (COSE), RFC 9101 (JAR), RFC 5280.

### 1.1 OpenID4VP 1.0 (the wallet's obligations)

| Clause | Requirement (quoted or paraphrased closely) | Where the page meets it |
| --- | --- | --- |
| VP §5 | "Verifiers MUST include the typ Header Parameter in Request Objects with the value oauth-authz-req+jwt … Wallets MUST NOT process Request Objects where the typ Header Parameter is not present or does not have the value oauth-authz-req+jwt." | 4.5 R2 |
| VP §5.8 | "the aud claim MUST be "https://self-issued.me/v2", when Static Discovery metadata is used" (a Verifier obligation) | 4.5 R5 (a finding when absent, refused when different) |
| VP §5.1, §5.10 | `request_uri_method=post`: "a supporting Wallet MUST send the request using the HTTP POST method", `application/x-www-form-urlencoded`, `Accept: application/oauth-authz-req+jwt`; `wallet_metadata` and `wallet_nonce` both optional; "the Verifier MUST use it as the wallet_nonce value in the signed authorization request object" | 4.4 |
| VP §5.10.1 | a missing `wallet_nonce` after the wallet sent one: "the Wallet MUST terminate request processing"; the `client_id` parameter and the request object's `client_id` "MUST be identical, including the Client Identifier Prefix" | 4.5 R3, R4 |
| VP §5.10.2 | "If the Verifier responds with any HTTP error response, the Wallet MUST terminate the process." | 4.4 |
| VP §5.9.3 `x509_san_dns` | the value "MUST be a DNS name and match a dNSName Subject Alternative Name (SAN) … entry in the leaf certificate"; "The Wallet MUST validate the signature and the trust chain"; outside the DC API, unless the client is trusted otherwise, "the FQDN of the redirect_uri value MUST match the Client Identifier without the prefix" | 4.5 R6, R8; trust chain: section 6 deviation 1 |
| VP §8.2 | "The response_uri value MUST be a value that the client would be permitted to use as redirect_uri when following the rules defined in Section 5.9" | 4.5 R8 |
| VP §5.9.3 `x509_hash` | "The value of x509_hash is the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate"; "The Wallet MUST validate the signature and the trust chain of the X.509 leaf certificate" | 4.5 R7 |
| VP §5.9.3 `redirect_uri` | "Requests using the redirect_uri Client Identifier Prefix cannot be signed"; `origin` "MUST NOT" be accepted in requests | 4.5 R9 |
| VP §5.1, §8.3 | every JWK in `client_metadata.jwks` "MUST have a kid"; "The alg parameter MUST be present in the JWKs. The JWE alg algorithm used MUST be equal to the alg value of the chosen jwk"; "If the selected public key contains a kid parameter, the JWE MUST include the same value in the kid JWE Header Parameter"; `enc` from `encrypted_response_enc_values_supported`, "allowing for the default value of A128GCM"; `apu`/`apv` only in a non-normative note | 4.8 |
| VP §8.3.1 | `direct_post.jwt`: the JWT in the form field `response`; "If a Wallet is unable to generate an encrypted response, it MAY send an error response without encryption" | 4.8 |
| VP §8.1, B.2.5 | `vp_token` is a JSON object keyed by credential query `id`, each value "an array of one or more Presentations", exactly one when `multiple` is false; for mdoc `"<base64url-encoded DeviceResponse>"`; no entry for an optional query without a match | 4.7, 4.8 |
| VP §8.2 | `direct_post`: form-encoded; a request carrying `redirect_uri` together with `direct_post`: "the Wallet MUST return an invalid_request"; the response URI answers 200 JSON; when it holds `redirect_uri`, "the Wallet MUST redirect the user agent to this URI" | 4.8 |
| VP §8.5 | errors: `invalid_request`, `access_denied` (no matching credential, no consent), `vp_formats_not_supported`, `invalid_request_uri_method`, `invalid_transaction_data`, `wallet_unavailable`; posted with `state` to the response URI (example in §8.2) | 4.8 |
| VP §6.1, §6.1.1.1 | credential query `id`, `format`, `meta` required; `multiple` false by default; `trusted_authorities` type `aki`: the base64url KeyIdentifier "MUST match with the AuthorityKeyIdentifier element of an X.509 certificate in the certificate chain present in the Credential"; "Every Credential returned by the Wallet SHOULD match" | 4.6 |
| VP §6.2, §6.4.2 | `credential_sets[].options` (required), `required` (default true); "If the Wallet cannot deliver all non-optional Credentials … it MUST NOT return any Credential(s)"; "Credentials not matching the respective constraints … MUST NOT be returned" | 4.6 |
| VP §6.3, §6.4.1 | `claims[].path`, `id` (required with `claim_sets`), `values` ("SHOULD return the claim only if the type and value of the claim both match exactly", CBOR converted to JSON); claims absent: no selectively disclosable claim is requested; claims without `claim_sets`: all of them; with `claim_sets`: "the Wallet SHOULD return the first option that it can satisfy. If the Wallet cannot satisfy any of the options, it MUST NOT return any claims"; "Wallets MUST NOT send selectively disclosable claims that have not been selected"; "If the Wallet cannot deliver all claims requested … it MUST NOT return the respective Credential" | 4.6; the test-mode exception is section 6 deviation 2 |
| VP §7.2.1 | an mdoc claims path is exactly `[namespace, elementIdentifier]`, two strings; otherwise an error | 4.6 |
| VP B.2.2 - B.2.4 | `vp_formats_supported.mso_mdoc.{issuerauth_alg_values, deviceauth_alg_values}` (COSE ids); `meta.doctype_value` required; `intent_to_retain` = ISO5 8.3.2.1.2.1 IntentToRetain | 4.6, 4.7 |
| **VP B.2.6.1** (Invocation via Redirects) | "the SessionTranscript CBOR structure as defined in Section 9.1.5.1 in [ISO.18013-5] MUST be used with the following changes: DeviceEngagementBytes MUST be null. EReaderKeyBytes MUST be null. Handover MUST be the OpenID4VPHandover"; `OpenID4VPHandover = ["OpenID4VPHandover", OpenID4VPHandoverInfoHash]`, the hash is SHA-256 over the CBOR of `OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]`; `clientId` with its prefix; "If the response is encrypted, e.g., using direct_post.jwt, the third element MUST be the JWK SHA-256 Thumbprint as defined in [RFC7638], encoded as a Byte String, of the Verifier's public key used to encrypt the response. Otherwise, the third element MUST be null"; values from the signed request object | 4.7 |
| VP B.2.6.1 vectors | for `client_id` `x509_san_dns:example.com`, nonce `exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA`, the example JWK (`x` `DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0`, `y` `XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc`) and `https://example.com/response`: thumbprint `4283ec92…669047`, `SHA-256(info)` `048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac`, SessionTranscript `83f6f682714f70656e494434565048616e646f7665725820048bc053…aad38ac` (both recomputed with `node:crypto` for this plan) | P5-03b acceptance |
| VP §9, §13.1.2 | wallet invocation: any custom scheme or https link; `openid4vp://` with static configuration values | 4.4 |
| VP §15.8.1 | "Untrusted or unrecognized Request URI endpoints SHOULD be rejected or require End-User confirmation before proceeding." | 4.5 consent; section 6 deviation 1 |

### 1.2 HAIP 1.0 (what a HAIP wallet must do, and the page's answer)

| Clause | Wallet requirement | The page |
| --- | --- | --- |
| HAIP §5 | "the Wallet MUST accept the Client Identifier Prefix x509_hash"; the trust anchor MUST NOT be in `x5c` and the signing certificate MUST NOT be self-signed (Verifier obligations) | `x509_hash` and `x509_san_dns`; both Verifier obligations are request-check findings (4.5) |
| HAIP §5 | "The DCQL query and response MUST be used" | DCQL only (`presentation_definition` was removed in VP 1.0) |
| HAIP §5 | ECDH-ES with P-256 MUST be supported; "Wallets MUST support A128GCM or A256GCM, or both. If both are supported, the Wallet SHOULD use A256GCM"; Verifiers send ephemeral keys per request | both; A256GCM preferred when offered (4.8) |
| HAIP §5 | the `aki` Trusted Authority Query "MUST be supported" | 4.6 |
| HAIP §5.1 | `haip-vp://` MAY be supported; signed requests by `request_uri`; `direct_post.jwt` MUST; same-device MUST, cross-device permitted | `haip-vp` links accepted; same-device through `/offer/wallet` (4.4); a `haip-vp` request that is unsigned or not `direct_post.jwt` is a request-check finding |
| HAIP §5.3.1 | "each ISO mdoc MUST be returned in a separate DeviceResponse" | one document per DeviceResponse (4.7) |
| HAIP §7 | ES256 (`-7` or `-9`) is the minimum for `deviceSignature` | ES256; the label follows the verifier's `deviceauth_alg_values` (4.7) |
| HAIP §4.5.1 (key attestation), wallet attestation | not applicable to a page with software keys | non-goal (4.15) |

### 1.3 ISO/IEC 18013-5:2021 (the mdoc structures)

Clause numbers below are confirmed through implementations and VP/HAIP references. The ISO text itself was not
readable (1.6). The second edition renumbers clauses, so cite ":2021".

| Clause | Structure |
| --- | --- |
| ISO5 8.3.2.1.2.1 | `IntentToRetain` (DCQL `intent_to_retain`) |
| ISO5 8.3.2.1.2.2 | `DeviceResponse = {"version": "1.0", ? "documents": [+Document], ? "documentErrors", "status": uint}`; `Document = {"docType", "issuerSigned": {? "nameSpaces": {ns: [+IssuerSignedItemBytes]}, "issuerAuth"}, "deviceSigned": {"nameSpaces": DeviceNameSpacesBytes, "deviceAuth": {"deviceSignature" // "deviceMac"}}, ? "errors"}`; `IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)`; `DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)` |
| ISO5 8.3.2.1.2.3 | status 0 = OK |
| ISO5 9.1.1, 9.1.1.5 | session encryption (Annex A only): ECDH, HKDF-SHA256 with salt SHA-256(SessionTranscriptBytes), info "SKDevice"/"SKReader", AES-256-GCM, IV = 8-byte identifier (reader `0…0`, mdoc `0…01`) ‖ 4-byte counter from 1 |
| ISO5 9.1.2.4, 9.1.2.5 | MSO signing; digests over the IssuerSignedItemBytes (tag 24 included) |
| ISO5 9.1.3.4 | `DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]`, `DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)` |
| ISO5 9.1.3.5 / 9.1.3.6 | mdoc MAC / mdoc ECDSA-EdDSA authentication; `deviceSignature` is a COSE_Sign1 with a detached payload (DeviceAuthenticationBytes) |
| ISO5 9.1.5.1 | `SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]` |

### 1.4 ISO/IEC TS 18013-7: which annex is which

| Edition | Annex A | Annex B | Annex C |
| --- | --- | --- | --- |
| TS 18013-7:2024 (first; DTS 2024-02-13 read) | device retrieval to a website (REST) | OID4VP (draft 18) | none |
| **TS 18013-7:2025** (second, published 2025-05, still a TS; contents and foreword read from the IEC preview) | **"Mechanisms for device retrieval to a website"** (p. 9) | "Use of OID4VP to retrieve an mdoc" (p. 15), still citing "OID4VP … Draft 18, April 2023" | "Digital credentials API retrieval" (p. 39), added in this edition |

**The owner's choice is Annex A.** "Annex B (REST)" was a mislabel: Annex B is the draft-18 OID4VP profile, whose
handover (`[clientIdHash, responseUriHash, nonce]` with `mdocGeneratedNonce` in the JWE `apu`) no target verifier uses
for an OpenID4VP 1.0 request.

Annex A as implemented by Multipaz (its wallet was "Tested against https://reader.rdw.mdoc.online/TestAnnexA2.html",
PR #1583; the ISO text of Annex A was not readable):

1. The reader publishes `mdoc://<base64url ReaderEngagement>` (ISO7:2025 A.4; IANA provisional `mdoc` scheme). The
   ReaderEngagement has the DeviceEngagement shape: version `"1.1"`, `EReaderKey` in the Security field, retrieval
   method `[4, 1, {0: <https URI>}]` (type 4 = HTTP), OriginInfos at key 5.
2. The mdoc POSTs `application/cbor` `{"deviceEngagementBytes": #6.24(bstr DeviceEngagement)}` to that URI, its
   DeviceEngagement carrying a fresh `EDeviceKey` on the reader key's curve and OriginInfo `{cat: 1, type: 1, details:
   {domain}}` (A.3.2: "The value of the "domain" element may be an empty string"). No SessionEstablishment is sent.
3. The reader answers `SessionData {"data": AES-GCM(SKReader, DeviceRequest)}`; the mdoc POSTs `SessionData {"data":
   AES-GCM(SKDevice, DeviceResponse)}`; the reader answers `{"status": 20}` (session termination).
4. `SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, bstr SHA-256(#6.24(bstr ReaderEngagement))]`
   (Multipaz `verifier.kt:1040-1052`, `uriSchemePresentment.kt:259-280`; the German BMI architecture page says the
   same; older Multipaz code used the ReaderEngagementBytes themselves). UNVERIFIED against ISO7:2025.

### 1.5 JOSE, X.509, WebCrypto

- RFC 7518 §4.6: ECDH-ES direct key agreement. Concat KDF with SHA-256 (§4.6.2); `keydatalen` = the `enc` key size;
  `AlgorithmID` = len32 ‖ the `enc` value; `PartyUInfo`/`PartyVInfo` = len32 ‖ decoded `apu`/`apv` (length 0 when
  absent); `SuppPubInfo` = `keydatalen` as uint32. For 128/256-bit keys this is one SHA-256 round over
  `00000001 ‖ Z ‖ OtherInfo`, truncated. WebCrypto has no Concat KDF; it is written by hand.
- RFC 7516 §7.1 compact JWE; RFC 7638 thumbprint over `{"crv","kty","x","y"}`.
- RFC 9052 §4.4 `Sig_structure = ["Signature1", protected, external_aad, payload]`; RFC 9053 §2.1 ECDSA signature =
  `r ‖ s`, which is what WebCrypto returns (W3C WebCrypto §23.7.1).
- W3C WebCrypto (Level 2 FPWD 2025-04-22): ECDH P-256 `deriveBits` (Chrome 41, Firefox 34, Safari 11); AES-GCM;
  `CryptoKey` is `[Serializable]` and storable in IndexedDB with its non-extractable flag (§5.2, §13.5). Checked on
  Node 24 for this plan: a non-extractable P-256 key survives `structuredClone`, still signs, and refuses
  `exportKey`.

### 1.6 Not verified

- The ISO texts (18013-5:2021, TS 18013-7:2025 Annex A body) are paywalled. Clause numbers come from implementations,
  VP, HAIP and the IEC contents preview.
- Paradym's deployed Credo version, and whether its hosted endpoints send CORS headers (no account was used).
- Whether Paradym enforces `issuerauth_alg_values` against our IssuerAuth `-7`: Credo v0.7.4 advertises
  `[-9, -51, -19]`, and `main` adds `-7`.
- Current browser behaviour for non-extractable keys stored in IndexedDB on Chrome, Firefox and Safari: spec-backed,
  not run. P5-03a's manual check covers it.
- Safari's seven-day cap on script-writable storage (WebKit ITP) may delete the kept credentials and keys of a
  visitor who does not return. Recalled, not fetched; the page says so.

## 2. What the target verifiers do

Read on 2026-11-14 from source and, where the service is public, from live requests. Appendix A lists the commits.
No real mDL presentation was tried; P5-03h does that.

### 2.1 Side by side

| | EUDI reference verifier | Multipaz web verifier | Paradym verification |
| --- | --- | --- | --- |
| Hosted at | `verifier.eudiw.dev` (UI), `verifier-backend.eudiw.dev` (API) | `verifier.multipaz.org` | `paradym.id` (SaaS; requests by API key) |
| Source read | backend `eudi-srv-verifier-endpoint` v0.12.0 (`19537e72`; `main` `fd46c1fd` has the same `src/main`), UI `eudi-web-verifier` `b29584d1` | `multipaz` tag 0.102.0 `a015c9d9` and `main` `fd37ff10` (the hosted build is newer than 0.102.0) | closed; Credo v0.7.4 `93907de`, `main` `c1aec02`; `identity-common-ts` `816eb0f` (`@owf/mdoc` 0.9.3, `@openid4vc/openid4vp` 0.9.2); docs and OpenAPI |
| How a request starts | UI, or `POST /ui/presentations/v2` (needs an intended use; hosted: `TEST-01`) | the page's protocol menu, "URI scheme (OpenID4VP 1.0)" | API only: `POST /v1/wallets/{walletId}/openid4vc/verification/request` with a presentation template; "not currently supported from the dashboard" |
| What the wallet gets | QR / link `haip-vp://?client_id&request_uri&request_uri_method` (UI default profile `haip`); scheme and "Authorization Endpoint" editable; `https://wallet.example.org/present` was accepted | the verifier tab runs `window.location = response.uri`, i.e. `haip-vp://?client_id&request_uri` (`verifier.js:1047`); no QR anywhere; the URI is `request.scheme + "://" + "?client_id=…&request_uri=…"` with the scheme unvalidated (`verifier.kt:1287-1294`) | `authorizationRequestDeeplinkQrUri` (`openid4vp://?request_uri&client_id`) or `authorizationRequestQrUri` (`https://paradym.id/invitation?request_uri=…`) |
| client_id | `x509_hash:IwslPFHb…ZhTyE` (hosted; recomputed from the leaf); `x509_san_dns` and `pre-registered` configurable | `x509_san_dns:verifier.multipaz.org` (leaf SAN `DNS:verifier.multipaz.org`) | template signer `certificate`: `x509_hash`; **default** signer `did:web`: `decentralized_identifier:did:web:…`, Ed25519 (EdDSA JWS) unless `keyType: "P-256"` |
| Request object | signed ES256, `typ oauth-authz-req+jwt`, `x5c` = the leaf only (`CN=Web Verifier (PROD)`, issued by `CN=PID Issuer CA 02`, SAN `URI:https://verifier.eudiw.dev`); `aud https://self-issued.me/v2`; `verifier_info` with a registration certificate, so ~23 KB; **fetchable once** (a second GET or POST is 400) | signed ES256, `x5c` leaf only; **no `aud`, no `state`**; `expected_origins` | signed, `typ oauth-authz-req+jwt`, `aud https://self-issued.me/v2`, `iat`, `exp`, `state`; optional `verifier_info` |
| `request_uri_method` | `get` default; `post` supported and echoes `wallet_nonce`; a posted `wallet_metadata` without `client_id_prefixes_supported`, `response_modes_supported`, `issuer` and `response_types_supported` makes it refuse | GET only | GET only |
| Query | DCQL only; the UI's mDL query: `{"credentials":[{"id":"query_0","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","family_name"],"intent_to_retain":false},…]}]}` | DCQL only (id `cred1`) | DCQL only; `trusted_authorities [{type: "aki", values: [<SKI of the trusted certificate>]}]` when a trusted entity is linked |
| Response mode | `direct_post.jwt` (HAIP forces it); `direct_post` per transaction | `direct_post.jwt`; `direct_post` when "Encrypt Response" is off | `direct_post.jwt`; `direct_post` with `requireResponseEncryption: false` |
| JWE | `ECDH-ES`; `encrypted_response_enc_values_supported ["A128GCM","A256GCM"]`; one P-256 key `{use enc, alg ECDH-ES, kid <uuid>}`; `apu`/`apv` ignored; plaintext `{state, vp_token}`; no `cty` | `ECDH-ES`; no enc list (VP default A128GCM; it accepts A128/192/256GCM); `kid "response-encryption-key"`; `apu`/`apv` read, not checked | `ECDH-ES`; `["A128GCM","A256GCM","A128CBC-HS256"]`; `kid` optional, must match when sent; `alg`, `enc`, `epk`, `apu`, `apv` in the protected header; `apu`/`apv` fed into the KDF when present |
| `vp_token` | `{<id>: [<b64url DeviceResponse>]}`; under HAIP exactly one document | same | same; exactly one document |
| `state` | required, inside the JWE | absent on this API | required, must match; post to `response_uri` exactly as given (it carries `?session=`) |
| Handover checked | `OpenID4VPHandover` only (`DocumentValidator.kt:563-594`, `HandoverInfo.kt:66-76`) | `OpenID4VPHandover` only (`verifier.kt:1359-1382`; library `VerificationUtil.vpSessionTranscript`) | `OpenID4VPHandover` for v1 (`MdocDeviceResponse.ts:373-383`; `@owf/mdoc` `SessionTranscript.forOid4Vp`); the draft-18 handover with `mdocGeneratedNonce` from `apu` only for a "legacy" (draft 21) wallet |
| `mso_mdoc` algorithms | issuerauth and deviceauth `[-7,-35,-36]` | `[-9,-7]` | `[-9,-51,-19]` (v0.7.4); `main` adds `-7` |
| Verifies | during `direct_post`, with walt.id `waltid-mdoc-credentials` 0.11.0: status 0, chain, validity, docType, digests (SHA-256/512 only), issuer and device signatures, a status entry if present; 400 `InvalidVpToken` otherwise, and the transaction stays open | `MdocDocument.verify` (Multipaz) | `@owf/mdoc` via Credo; a DS certificate needs `C`, which must equal `issuing_country`; the DS certificate's AKI must match a `trusted_authorities` value |
| **Trust in our IACA** | **yes**: `issuer_chain` (PEM) at transaction init, or the UI's "Configure issuer chain" (kept in session storage); each certificate becomes a PKIX anchor, revocation off; a malformed PEM is 400 `InvalidIssuerChain` (tested); without a trust validator configured every issuer is trusted | **no**: `getIssuerTrustManager()` holds four IACAs (Multipaz TestApp, Google ID pass US and ROW, Multipaz Test Issuer; `verifier.kt:1451-1510`); no UI, URL or setting; the "Issuer Identifiers" field only filters DCQL. The page still lists every element with "Issuer: Not in trust list (<subject>)" | **yes**: Trust → Trusted Entities, paste or upload one PEM/CRT/CER/DER certificate (a root is allowed), or `POST /v1/wallets/{walletId}/trusted-entities`; link it in the template's `trustedIssuers`. With no trusted entity the template "will accept ANY issuer" |
| **CORS** | **open**: `cors.*` defaults `origins=*` (`VerifierContext.kt:454-477`); preflight 200 echoing `Origin` on `/wallet/request.jwt/{id}` and `/wallet/direct_post/{id}`, and on real answers (tested) | **none**: no CORS plugin (`runServer.kt:82-92`); GET of the request object 200 without `Access-Control-Allow-Origin`; `OPTIONS` 404 (tested) | **none** in Credo (no middleware; Animo's own playground adds `cors()` itself); hosted endpoints UNVERIFIED |
| Annex A | no | yes: `POST /verifier/annexABegin` gives `mdoc://<ReaderEngagement>`, the tab navigates to it; `POST …/annexARequest?sessionId=` CBOR (any content type), no CORS | no |
| CI | image `ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:v0.12.0` = `sha256:b56390f2078f9ce705f2b20db86fdd52297c0a587dd4110c82f173c223a3a07f` (amd64) | no image; `org.multipaz:multipaz-jvm` 0.102.0 (already pinned) carries `VerificationUtil`/`VerificationSession`; `multipaz-verifier`/`multipaz-server` 0.102.0 on Maven Central | none (SaaS) |

### 2.2 What each verifier means for the page

- **EUDI.** Works directly from the browser (CORS open), cross-device by QR or same-device by setting "Authorization
  Endpoint" to `https://<host>/v1/certify/offer/wallet`.
  - The request object is single-use. The page must never fetch it twice: no retry, no relay fallback, and a reload
    must not re-fetch it (4.4).
  - The owner pastes `https://<host>/v1/certify/mdoc/iaca/lorem-ipsum-demo.pem` into "Configure issuer chain".
  - Under HAIP, an MSO `status` entry is fetched and checked. After M-11 the demo mDL carries one; EUDI fetches it
    server-side, so CORS on Certify's list does not matter.
  - EUDI's mDoc library supports SHA-256 and SHA-512 MSO digests only. Certify's demo uses SHA-256.
- **Multipaz.**
  - **Getting the request:** same-device only, by typing `https://<host>/v1/certify/offer/wallet#` into the scheme field.
    The verifier tab then navigates to `…/offer/wallet#://?client_id=…&request_uri=…`. The fragment never reaches a
    server.
  - **Transport:** the request object and the response must go through the relay (no CORS). The relay must return the
    response's `redirect_uri` (`/verifier_redirect.html?sessionId=…`), which is the only place the legacy UI shows the
    result.
  - **Request quirks:** the request lacks `aud` and `state`; the page records both as findings and proceeds.
  - **Trust:** fails by construction (D-P5-03-5).
  - 0.102.0's server did not URL-decode the form body. The hosted `main` does.
- **Paradym.**
  - **Setup:** the owner needs a Paradym project and API key, a trusted entity holding the IACA PEM, and an mdoc
    presentation template for `org.iso.18013.5.1.mDL` whose verifier signer is `certificate` (D-P5-03-9).
  - **Transport:** the request object goes through the relay (Credo has no CORS). The response may go by a `no-cors`
    form POST; it is CORS-safelisted, and cross-device needs no answer.
  - **Trust and AKI:** the `trusted_authorities` `aki` value is the IACA's SKI. Our DS certificates carry AKI = IACA
    SKI (Annex B DS profile, M-04), so they match.
  - **Algorithm risk:** if the deployed Credo predates `-7` in its advertised lists, our IssuerAuth (`-7`) and an ES256
    `deviceSignature` labelled `-7` may be refused. The page labels the device signature `-9` when the verifier lists
    `-9` and not `-7` (4.7); the IssuerAuth cannot change (rule 1). Unverified; P5-03h finds out.

### 2.3 The OpenID Foundation conformance suite as a verifier

`gitlab.com/openid/conformance-suite` `release-v5.3.4` (`23353b3`, 2026-10-26; `master` `daca6ad` identical in the
files read):

- **Plans:** `oid4vp-1final-wallet-haip-test-plan` (certifiable; fixes `direct_post.jwt` + `x509_hash` +
  `request_uri_signed`) and `oid4vp-1final-wallet-test-plan` (alpha; variants `client_id_prefix`
  `x509_san_dns`/`x509_hash`/`redirect_uri`/…, `response_mode` `direct_post`/`direct_post.jwt`). Both offer
  `credential_format=iso_mdl`.
- **Checks:** the B.2.6.1 transcript (`AbstractCreateVP1FinalIsoMdocRedirectSessionTranscript.java:36-88`); Multipaz
  0.101.0 `DeviceResponseParser` for issuer and device signatures, exactly one document; `CheckOnlyRequestedMdocElementsDisclosed`
  (FAILURE); `EnsureMdocDeviceSignedElementsEmpty`.
- **Trust and revocation:** chain to `credential.trust_anchor_pem` (FAILURE under HAIP when missing or failing); the
  DSC's CRL is fetched (FAILURE under HAIP when unreachable).
- **Negative modules:** a bad request-object signature, an invalid or missing `typ`, a mismatched client_id and an
  invalid prefix must be refused without calling `response_uri` (these end REVIEW and wait for a screenshot). A
  missing nonce and `redirect_uri` with `direct_post` must be answered `invalid_request`; a non-matching required
  credential and a claim not in the credential are covered too.
- **Driving it:** the suite publishes `authorization_endpoint?client_id&request_uri`, readable from
  `GET /api/runner/{id}` (`browser.urls`) or the log's `redirect_to`. For `iso_mdl` the response URI answers
  `redirect_uri=<base>/callback#<code_verifier>`, which the wallet must open within 30 s; the callback page POSTs
  `location.hash` as `text/plain`, and a harness may replay that POST.
- **Running it:** prebuilt images `registry.gitlab.com/openid/conformance-suite:release-v5.3.4`, `…/nginx`,
  `mongo:6.0.13`; `https://localhost.emobix.co.uk:8443` with a self-signed certificate; ~3 GiB. Precedent:
  `idfoundry/oid4vcgo` `.github/workflows/oid4vp-conformance.yml` runs the HAIP plan for `iso_mdl` daily (not as a
  gate, after one `:latest` regression).
- **Not covered:** Annex A. Annex B exists only in the alpha ID2/ID3 plans, with `mdocGeneratedNonce` in `apu`.

## 3. The page today (`ad01e047`)

| What | Where | Why it matters |
| --- | --- | --- |
| One page with one inline script (~600 lines); `qrcode.min.js` (vendored, no licence header, no pin) and `cbor.js` (ours) by `src` | `static/offer/index.html:100-700` | the harness runs only inline scripts and stubs both `src` files (`check-offer-page.mjs:740-772`), so nothing in `cbor.js` is exercised by it |
| The holder key is generated **extractable** and dropped after the proof | `proofJwt`: `generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign"])` | a key kept for presentation must be non-extractable; exporting the public JWK does not need an extractable private key |
| The credential is shown and dropped | `renderMdoc` | nothing to present later |
| `cbor.js` decodes tag 24 one level further and keeps no byte ranges | `cbor.js:220-225` | an IssuerSignedItemBytes cannot be re-emitted byte for byte from the decoded value, and the digest covers those bytes (ISO5 9.1.2.5) |
| No CBOR encoder | `cbor.js` | DeviceResponse, DeviceAuthentication and the handover need one |
| No `Content-Security-Policy` or `Permissions-Policy` | `OfferPageController.page()`, `certify-nginx.conf` | storing usable keys raises the cost of any script injection on the origin |
| nginx lets three things under `/offer/` through: `qrcode.min.js`, `cbor.js`, `demo-subjects` | `certify-nginx.conf:30-32`; guard `check-public-guard.sh:141-147,256-262` | every new script or path needs an allow-list row and guard lines (`/offer/other.js` is a 403 test today) |
| `/offer/**` has its own permit-all chain, CSRF off, stateless | `OfferPageSecurityConfiguration` | new paths under `/offer/` need no entry in the security URL lists (rule 9) |
| `certify.offer-page.{enabled, demo-subjects[]}`, a record validated at bind time | `OfferPageProperties` | the wallet's settings extend it (rule 9) |
| The live mDL: `org.iso.18013.5.1.mDL`, namespace `org.iso.18013.5.1`, 15 elements (`family_name`, `given_name`, `birth_date`, `issue_date`, `expiry_date`, `issuing_country`, `issuing_authority`, `document_number`, `portrait`, `driving_privileges`, `un_distinguishing_sign`, `sex`, `age_over_18`, `nationality`, `resident_city`); MSO validity `P30D`; ES256 DSC under IACA `lorem-ipsum-demo`; no status entry until M-11 (F-21) | `config/mdl/holders.json`, `certify-mdl.properties:80` | fixtures and e2e queries use these |
| CI runs the harness on Node 20 | `rebuild-ci.yml:196-205` | Node 20 reached end of life on 2026-04-30; P5-03a moves to 24 (the harness's 943 checks pass on 24 locally) |

## 4. Design

### 4.1 Pages and files

The wallet gets a page of its own, `wallet.html`, served at `{servletPath}/offer/wallet`. It shares the offer page's
origin, so it shares the IndexedDB. Keeping it apart leaves the issuance page and its 943 harness checks almost
untouched. The offer page only gains the "Keep" checkbox and a link to the wallet.

| File (under `certify-service/src/main/resources/static/offer/`) | Role | Slice |
| --- | --- | --- |
| `index.html` (existing) | issuance; non-extractable key; "Keep this credential in this browser"; link to the wallet | a |
| `wallet.html` (new; no inline script) | kept credentials; scan or paste a request; verifier card and request checks; consent; result; log | a, c-e, g |
| `cbor.js` (existing) | + `Cbor.encode`, `Cbor.Raw`, `Cbor.Tagged`, `Cbor.spans`, `Cbor.decodeTyped` (typed map keys, 4.3); `Cbor.decode` unchanged | a |
| `mdoc.js` | IssuerSigned reader, storage checks, DeviceResponse, SessionTranscripts | a, b, i |
| `wallet-store.js` | IndexedDB | a |
| `x509.js` | DER reader: names, SAN, AKI/SKI, validity, SPKI import, certificate signature check | c |
| `oid4vp.js` | links, request fetch, request checks, DCQL, response assembly | c, d, e |
| `jwe.js` | ECDH-ES + Concat KDF + AES-GCM compact JWE; RFC 7638 thumbprint | e |
| `scan.js` | camera, `BarcodeDetector`, fallback decoder | g |
| `jsqr.min.js` (vendored) | QR decoder where `BarcodeDetector` is missing | g |
| `wallet.js` | the wallet page's controller: DOM only, no protocol logic | a, c-e, g |
| `annexa.js` | Annex A engagement and session encryption | i |

Each protocol module exposes pure functions on one global (`Cbor`, `Mdoc`, `X509`, `Oid4vp`, `Jwe`, `AnnexA`). The
harness calls them directly and also drives them through the page.

### 4.2 Holder keys and storage

- **Key generation.** `proofJwt` generates the pair with `extractable=false` and returns `{jwt, keyPair}`. The proof's
  bytes do not change: its `jwk` header comes from the public key, which WebCrypto always lets the page export.
- **What is kept** (D-P5-03-6). Only `mso_mdoc` credentials, when "Keep this credential in this browser" is ticked
  (default on, shown only for `mso_mdoc` configurations). The page sends one proof, so it keeps the first credential of
  the response; any further ones are shown, not kept, and the page says so.
- **IndexedDB.** Database `certify-demo-wallet`, version 1:

  | Store | keyPath | Record |
  | --- | --- | --- |
  | `credentials` | `id` (`crypto.randomUUID()`) | `{id, format: "mso_mdoc", docType, issuerSigned: Uint8Array (the bytes as received, base64url-decoded), privateKey: CryptoKey (ECDSA P-256, non-extractable, ["sign"]), publicJwk: {kty, crv, x, y}, credentialIssuer, credentialConfigurationId, storedAt, validFrom, validUntil, label}` |
  | `answered` | `key` = base64url(SHA-256(UTF-8(client_id) ‖ 0x00 ‖ UTF-8(nonce))) | `{key, at}`; entries older than 24 h dropped on open |
  | `log` | auto-increment | `{at, clientId, verifierName, responseUri, credentialId, disclosed: [[ns, element], …], responseMode, findings, outcome}`; the last 100 kept; never leaves the browser |

- **Checks before a credential is kept.** Every one must pass; a failure keeps nothing and names the check.
  1. The bytes decode as an IssuerSigned (`{? nameSpaces, issuerAuth}`), and the IssuerAuth payload as a tag-24 MSO.
  2. `MSO.docType` equals the configuration's `doctype` in the issuer metadata the run fetched.
  3. `MSO.deviceKeyInfo.deviceKey` is an EC2 P-256 COSE_Key (`1: 2, -1: 1`) whose `-2`/`-3` equal the held key's
     `x`/`y` (ISO5 9.1.2.4).
  4. Every IssuerSignedItemBytes hashes, under the MSO `digestAlgorithm` (SHA-256/384/512), to
     `valueDigests[ns][digestID]` (ISO5 9.1.2.5). The page never later presents an item the issuer did not sign.
  5. At most 256 KiB per IssuerSigned and at most 50 credentials; the 51st is refused with "delete one first".

  Check 1 reads the structure from the bytes the page will carry, not only from decoded values (a decoder resolves
  tags and, in a display form, renders keys of different types alike), so it also refuses what the CDDL and COSE do
  not allow (P5-03a review rounds 1-4; decision log, P5-03a review round 3 and 4 rows):
  - an IssuerSigned key other than the text keys `nameSpaces` and `issuerAuth`: `IssuerSigned = {? "nameSpaces":
    IssuerNameSpaces, "issuerAuth": IssuerAuth}` is a closed map (ISO5 8.3.2.1.2), and `NameSpace = tstr`;
  - a tag (55799 self-described CBOR, 1 epoch date, 24 embedded CBOR, or any other) around a field the CDDL leaves
    untagged: the IssuerSigned map, `nameSpaces`, a namespace's array, the COSE_Sign1 elements and the x5chain
    certificates; the COSE_Sign1 itself is untagged or tag 18 only (RFC 9052 §4.2), and each IssuerSignedItemBytes is
    tag 24 (ISO5 8.3.2.1.2);
  - an `x5chain` array with one element: `COSE_X509 = bstr / [2*certs: bstr]` (RFC 9360 §2), so one certificate is a
    bare bstr;
  - a header label that is not an `int` or a `tstr` (RFC 9052 §1.5 and §3: `label = int / tstr`; labels compare by
    type, so `1` and `"1"` are two labels and both are kept);
  - a label in both the protected and the unprotected header (RFC 9052 §3: a label MUST NOT occur in both);
  - a value a decision reads that is not of its CDDL type, read from its first byte (a decoder reads `#6.99(2)` and
    `2.0` as 2): `docType` and `digestAlgorithm` a tstr; `valueDigests`, its DigestIDs maps, `deviceKeyInfo` and
    `deviceKey` a map; each Digest a bstr; the deviceKey's `kty` (1) and `crv` (-1) an int or a tstr, `x` (-2) a bstr
    and `y` (-3) a bstr or a bool (RFC 9052 §7, RFC 9053 §7.1.1); the MSO a bstr inside the tag 24 holding an untagged
    map; and each IssuerSignedItemBytes a tag 24 around a bstr holding an untagged map whose `digestID` is a uint and
    whose `elementIdentifier` is a tstr (ISO5 8.3.2.1.2). Other MSO and item values (`version`, `validityInfo`,
    `random`, `elementValue`) decide nothing in P5-03a and are not checked.
- **Deleting.** "Delete" removes a record and with it the only reference to its key. "Delete everything" calls
  `indexedDB.deleteDatabase("certify-demo-wallet")`. Nothing is stored server-side, ever.
- **No storage.** If `indexedDB` is missing or `open` fails (some private modes), the page says so once and issuance
  works as today. The wallet page notes that Safari may clear site storage after seven days without a visit (1.6).

### 4.3 Reading a kept IssuerSigned without changing a byte

- `Cbor.spans(bytes, depth)` walks one data item and returns its decoded value plus the `[start, end)` byte range of
  every array element and map value down to `depth`.
- Map keys keep their types wherever a decision rests on them (P5-03a review round 3): `Cbor.spans` and
  `Cbor.decodeTyped` give each map as a `Map` keyed by a number for an integer key and a string for a text key, and a
  path segment keeps that type (`[33]` and `["33"]` are two paths). A key that is the same data item twice is refused,
  with keys compared as RFC 8949 §5.6.1 says (P5-03a review round 4): integers by value under any head, text strings
  bytewise under any head or chunking, `+0.0` and `-0.0` as one key, NaNs as one key exactly when their significands
  (zero-extended at the right to 64 bits) are equal, and a bignum (tag 2 or 3) as the integer it carries; a bignum key
  whose value an integer head holds is refused (RFC 8949 §3.4.3: the integer is its only meaningful form). Text is
  read strictly: invalid UTF-8, including a code point split across chunks, is refused (§3.2.3, §5.3.1), and a leading
  U+FEFF is kept in a definite string and in every chunk, so `"x"` and `"\ufeffx"` are two keys. The content of tags
  2, 3 and 24 is a byte string by its own first byte, never a tagged one. `Cbor.decode` keeps its plain objects
  for the offer page's display, and refuses a map whose keys render alike (`1` and `"1"`) rather than overwrite one.
- `Mdoc.readIssuerSigned(bytes)` builds on it and returns `{nameSpaces: {ns: [{elementIdentifier, digestID,
  elementValue, raw}]}, issuerAuth: {raw, alg, x5chain: [der…], mso}}`. Each `raw` is the **exact** byte range of an
  IssuerSignedItemBytes (tag-24 header, bstr header and content) or of the IssuerAuth COSE_Sign1 in the kept bytes.
  Definite- and indefinite-length input both work, because the ranges come from the input itself.
- `Cbor.encode(value)` uses **preferred serialization** (RFC 8949 §4.1: shortest argument, definite lengths). It
  encodes `null`, booleans, integers (safe numbers and BigInt), `Uint8Array` (bstr), strings (tstr), arrays, and `Map`
  (keys in insertion order; the page inserts them in ISO5's CDDL order).
  - `Cbor.Tagged(tag, value)` and `Cbor.Raw(bytes)` are also accepted. `Raw` is emitted verbatim; its constructor
    decodes it once and refuses anything that is not exactly one well-formed item.
  - Floats, `undefined` and other types throw.
- A DeviceResponse therefore carries the issued IssuerSignedItemBytes and IssuerAuth as **slices of the kept bytes**,
  never re-encoded values. This is the first property the gates test (4.14).

### 4.4 Taking a request in

- **Sources.**
  - A scan (4.10) or a pasted link.
  - **Same-device invocation:** a verifier navigates to `https://<host>/v1/certify/offer/wallet?client_id=…&request_uri=…`
    (EUDI's "Authorization Endpoint" field), or to `…/offer/wallet#://?client_id=…&request_uri=…` (Multipaz's scheme
    field set to `https://<host>/v1/certify/offer/wallet#`). The page reads `location.search` and `location.hash`
    once, then calls `history.replaceState` back to the bare wallet URL, so a reload never re-fetches a single-use
    request object.
- **Accepted links.** Schemes `openid4vp`, `haip-vp`, `eudi-openid4vp`, `mdoc-openid4vp` and `https` (for `https` the
  link only carries parameters); at most 8 KiB.
  - Parameters: `client_id`, `request_uri` and `request_uri_method` (`get` by default, or `post`); or `request` (a JAR
    by value); or, only with the `redirect_uri:` prefix, plain unsigned parameters.
  - A link without `client_id`, such as Paradym's `https://paradym.id/invitation?request_uri=…`, is accepted. The
    client_id is then taken from the verified JAR, and the request checks show that the link named none.
  - The paste field also takes a request object itself (a compact JWS), checked exactly like a fetched one. This is
    the fallback for a verifier the page cannot read and the relay does not list (D-P5-03-4 (b)).
- **Fetching** the request object.
  - `request_uri` must be `https`; `http` is allowed only while the page itself is served from `localhost` or
    `127.0.0.1` (local stacks, the CI jobs).
  - When its host is on the relay list (`GET /offer/wallet/config`, 4.9), the page fetches **only** through the relay;
    otherwise **only** directly, with `redirect: "error"`. Never both, and never twice: the page keeps the set of
    request URIs it has fetched.
  - The request carries `Accept: application/oauth-authz-req+jwt`.
  - For `post`, the form body is `wallet_nonce=<16 random bytes, base64url>` and nothing else. `wallet_metadata` is
    not sent (VP §5.10 makes both optional), because EUDI refuses a `wallet_metadata` that omits fields it treats as
    required (2.1). The JAR must then carry the same `wallet_nonce` (R4).
  - Any non-200 answer stops processing (VP §5.10.2).
- **Limits.** The request object is at most 64 KiB (EUDI's is ~23 KB); JSON nesting at most 16 levels; DCQL at most 20
  credential queries, 100 claims per query, 20 `claim_sets` and 20 `credential_sets`; `x5c` at most 5 certificates of
  at most 8 KiB each. Anything larger is refused and nothing is sent.

### 4.5 Checking the request and the verifier

**Refused, nothing sent.** The panel names the rule.

| # | Rule | Source |
| --- | --- | --- |
| R1 | the request object is not a compact JWS of three base64url parts, or its header or payload is not a JSON object, or it is over a limit (4.4); the request_uri answered non-200 | VP §5.10.2 |
| R2 | header `typ` is absent or not `oauth-authz-req+jwt` | VP §5 |
| R3 | the link's `client_id` differs from the JAR's (when the link has one) | VP §5.10.1 |
| R4 | `wallet_nonce` sent and the JAR's is missing or different | VP §5.10.1 |
| R5 | `aud` present and not `https://self-issued.me/v2` (the page sends no wallet metadata, so static discovery applies); `exp` in the past; `iat` more than 5 minutes ahead | VP §5.8, RFC 9101 |
| R6 | `x509_san_dns`: no `x5c`; the leaf has no dNSName SAN equal to the client_id value; the JWS does not verify with the leaf's key | VP §5.9.3 |
| R7 | `x509_hash`: base64url(SHA-256(leaf DER)) differs from the client_id value; the JWS does not verify with the leaf's key | VP §5.9.3 |
| R8 | `response_uri` is missing or not `https` (`http` only for a localhost page); for `x509_san_dns` its host differs from the DNS name; for `redirect_uri:` it differs from the client_id value | VP §5.9.3, §8.2 |
| R9 | prefixes: `origin` refused (VP says MUST NOT); `redirect_uri` with a signed request refused; `decentralized_identifier`, `verifier_attestation`, `openid_federation` and pre-registered (no prefix) refused as "not supported by this demo wallet" (D-P5-03-9) | VP §5.9.3 |
| R10 | `x5c`: a certificate that does not parse; the leaf outside its validity (5 minutes skew); a certificate whose signature does not verify with the next one's key (ECDSA P-256/384/521 or RSA, WebCrypto); a JWS `alg` other than ES256/ES384/ES512/PS256/RS256 | VP §5.9.3 |
| R11 | `response_type` other than `vp_token`; `response_mode` other than `direct_post`/`direct_post.jwt` | VP §5.6, §8.2 |

**Answered with an error response** (VP §8.5). After the checks above pass, the page shows the error and a button
"Send error response", which posts `error`, `error_description` and `state` to `response_uri`. These are exactly the
cases where the OIDF suite expects one (2.3).

| Case | Error |
| --- | --- |
| no `nonce` | `invalid_request` |
| `redirect_uri` together with `direct_post`/`direct_post.jwt` | `invalid_request` |
| no `dcql_query` (or only `scope`), or a DCQL that breaks 4.6 step 1 | `invalid_request` (`invalid_scope` for an unknown scope) |
| `transaction_data` present | `invalid_transaction_data` |
| `direct_post.jwt` without a usable key or `enc` (4.8) | `vp_formats_not_supported`, sent unencrypted (VP §8.3.1 MAY) |
| no kept credential satisfies the query, or the user declines | `access_denied` |

**Findings: shown, not blocking.** These are the request-check list that makes the page useful for testing verifiers.

- `aud` absent (Multipaz).
- `state` absent.
- The leaf is self-signed, or `x5c` carries a self-signed root (HAIP §5).
- A `haip-vp` link whose request is not signed by `request_uri`, or is not `direct_post.jwt`.
- The `request_uri` host is not the client's DNS name (VP §15.8.1).
- `client_metadata.vp_formats_supported.mso_mdoc.issuerauth_alg_values` does not list the kept credential's IssuerAuth
  algorithm.
- The request object's media type is not `application/oauth-authz-req+jwt`.
- Unknown request parameters.

**The verifier card**, shown before any consent:

- the client_id (prefix explained);
- the leaf's subject (CN, O, C), SAN entries, issuer DN and validity;
- SHA-256 fingerprints of the leaf and of the topmost certificate;
- "No trusted list: this demo cannot tell you who this verifier is" (deviation 1);
- `client_metadata.client_name`, labelled "as the verifier names itself";
- for EUDI, a summary of `verifier_info`'s registration certificate (its JWS payload decoded as text, labelled
  unverified);
- the `response_uri` host;
- the request checks.

All text goes in through `textContent`, and no remote image (`logo_uri`) is loaded.

### 4.6 DCQL and consent

1. **Validate the query.** Credential query ids match `^[A-Za-z0-9_-]+$` and are unique; `format` and `meta` are
   present; for `mso_mdoc`, `meta.doctype_value` is a string; every `claims[].path` is exactly two strings (VP §7.2.1);
   claim `id`s are present and unique when `claim_sets` is; `claim_sets` and `credential_sets[].options` name existing
   ids; `claim_sets` never appears without `claims`. A violation is `invalid_request` (4.5).
2. **Candidates per credential query.** Only `format: "mso_mdoc"` can match. A candidate is a kept credential whose
   `docType` equals `doctype_value` and which is valid now (`validFrom ≤ now < validUntil`; an expired one only in test
   mode).
   - `trusted_authorities` type `aki`: keep only credentials where a certificate in the IssuerAuth `x5chain` has an
     AuthorityKeyIdentifier whose base64url KeyIdentifier is among `values` (VP §6.1.1.1; HAIP §5).
   - Types `etsi_tl` and `openid_federation` cannot be evaluated by the page. The candidate stays, with a finding.
3. **Claims.**
   - Without `claims`, nothing selectively disclosable is requested: the DeviceResponse carries the IssuerAuth and no
     `nameSpaces` (VP §6.4.1).
   - With `claims` and no `claim_sets`, every listed path must exist in the candidate.
   - With `claim_sets`, the first satisfiable option is preselected (VP §6.4.1 SHOULD), and the user may switch to
     another satisfiable option.
   - `values`: the element, converted CBOR→JSON (tstr, int, bool; `full-date`/`tdate` as their strings; a bstr never
     matches), must equal one of `values` in type and value. A non-matching element counts as absent (VP §6.3, §6.4.1).
4. **Credential sets.**
   - Without `credential_sets`, every credential query is required.
   - With them, each `required` set (the default) takes its first option whose ids all have a satisfying candidate.
   - Optional sets are offered with an unticked box (least disclosure).
   - `multiple: true` still returns one presentation (an array of one is valid, VP §8.1). Several candidates for one
     query give a picker.
5. **Consent.** One row per requested element, all ticked: the namespace and element, its value (the portrait as an
   image), and an "intends to retain" badge when `intent_to_retain` is true.
   - Elements that were not requested are never offered: a wallet "MUST NOT send selectively disclosable claims that
     have not been selected" (VP §6.4).
   - The user may untick any row (owner direction). Unticking a required element turns the button into "Share anyway",
     with the warning "The verifier asked for <element>. A conformant wallet must not send this credential without it
     (OpenID4VP 1.0 §6.4.1); the verifier should refuse it." The log marks the presentation as non-conformant
     (deviation 2).
6. **Nothing satisfies the query.**
   - The page says which query failed and why (doctype, missing elements, `values`, `trusted_authorities`, expired),
     and offers "Send access_denied" or "Close without answering".
   - In test mode it also offers "Share what this wallet has" (deviation 2).
   - An optional query without a match gets no entry in `vp_token` (VP §8.1).

### 4.7 The DeviceResponse

`Mdoc.deviceResponse(record, chosen, sessionTranscript, options)` builds, with map keys in this order (ISO5
8.3.2.1.2.2):

```
DeviceResponse = {
  "version": "1.0",
  "documents": [ {
    "docType": MSO.docType,
    "issuerSigned": {
      "nameSpaces": { ns: [ Raw(item.raw) for each chosen item of ns, in kept order ] },  ; absent when nothing is chosen
      "issuerAuth": Raw(issuerAuth.raw)
    },
    "deviceSigned": {
      "nameSpaces": Tagged(24, h'a0'),                            ; DeviceNameSpacesBytes: d8 18 41 a0
      "deviceAuth": { "deviceSignature": [ h'a10126', {}, null, sig ] }   ; COSE_Sign1, untagged, detached payload
    }
  } ],
  "status": 0
}
```

- **What is signed.** `DeviceAuthenticationBytes = Tagged(24, encode(["DeviceAuthentication", SessionTranscript,
  docType, Tagged(24, h'a0')]))` (ISO5 9.1.3.4). `sig` = ECDSA P-256/SHA-256 over `encode(["Signature1", protected,
  h'', DeviceAuthenticationBytes])` (RFC 9052 §4.4; the payload is detached, ISO5 9.1.3.6). WebCrypto's 64-byte `r‖s`
  is the COSE form.
- **The algorithm label.** The protected header is `{1: -7}` (`a1 01 26`). It becomes `{1: -9}` (`a1 01 28`, ESP256,
  the same algorithm fully specified) only when the verifier's `deviceauth_alg_values` lists `-9` and not `-7` (Paradym
  v0.7.4, 2.2). HAIP §7 allows either.
- **The key** is the record's own `privateKey`. Before signing, the page re-checks that the record's public JWK equals
  the MSO `deviceKey` (4.2 check 3). A record whose key was swapped refuses to sign: this is the "key from another
  credential" negative test.
- **SessionTranscript** for OpenID4VP: `[null, null, ["OpenID4VPHandover", SHA-256(encode([client_id, nonce,
  jwkThumbprint or null, response_uri]))]]` (VP B.2.6.1). The values come from the signed request object; the
  thumbprint is the 32-byte RFC 7638 SHA-256 of the JWK the response is encrypted to, or `null` for `direct_post`.
- **`vp_token`**: `{ <credential query id>: [ base64url(DeviceResponse) ] }`, with one DeviceResponse holding one
  document per answered query (HAIP §5.3.1).

### 4.8 The response

- **Payload.** `{"vp_token": {...}, "state": <the request's state, when it has one>}`. No `iss`, `aud` or `exp`:
  Credo would treat all three together as a signed response.
- **`direct_post`:** `POST response_uri`, `application/x-www-form-urlencoded`, fields `vp_token` (the JSON object
  serialised) and `state`.
- **`direct_post.jwt`:** one field, `response` = a compact JWE (RFC 7516 §7.1), built by `jwe.js`.
  - **Key:** the first JWK in `client_metadata.jwks.keys` with `kty` `EC`, `crv` `P-256`, `alg` `ECDH-ES` (VP §8.3:
    the JWE alg must equal the JWK's `alg`) and `use` absent or `enc`. More than 8 keys, or none usable, is the
    `vp_formats_not_supported` case (4.5). A key the page cannot use is skipped (the OIDF module
    `ignores-unusable-encryption-key`).
  - **`enc`:** `A256GCM` if `encrypted_response_enc_values_supported` lists it (HAIP §5 SHOULD), else `A128GCM` if it
    lists that or the list is absent (the VP default). Anything else is `vp_formats_not_supported`.
  - **Protected header:** `{"alg":"ECDH-ES","enc":…,"kid":<the JWK's kid, which VP §8.3 requires to be copied>,"epk":{"kty":"EC","crv":"P-256","x":…,"y":…}}`.
    No `apu`/`apv`: VP has them only in a note, EUDI and Multipaz ignore them, and Paradym feeds them into the KDF only
    when present. No `cty`, no `typ`.
  - **Key agreement:** `Z` = WebCrypto `deriveBits({name: "ECDH", public: verifierKey}, ephemeralPrivate, 256)`, with
    a fresh non-extractable ephemeral key per response.
  - **CEK:** Concat KDF (1.5): `SHA-256(00000001 ‖ Z ‖ len32(enc) ‖ enc ‖ 00000000 ‖ 00000000 ‖ uint32(keydatalen))`,
    truncated to 128 or 256 bits.
  - **Encryption:** AES-GCM with a 96-bit random IV and a 128-bit tag; AAD = ASCII(BASE64URL(protected header)). The
    WebCrypto output is split at `length - 16` into ciphertext and tag.
  - **Compact form:** `b64u(header) + ".." + b64u(iv) + "." + b64u(ciphertext) + "." + b64u(tag)` (empty encrypted key
    for direct key agreement).
- **Delivery.**
  - To a host on the relay list: through the relay.
  - Otherwise: `fetch(response_uri, {method: "POST", body, redirect: "error"})`. A form POST is a CORS-safelisted
    request, so the verifier receives it even when its answer cannot be read.
  - Never sent twice. A `TypeError` is reported as "sent; the verifier's answer could not be read from a web page (no
    CORS, or the network failed)", not as a failure.
- **The answer.** A 200 JSON with an `https` `redirect_uri` makes the page navigate the tab there after showing it for
  2 seconds (VP §8.2 MUST; the OIDF `iso_mdl` callback must be opened within 30 s). Other answers show their status and
  at most 2 KiB of body as text.
- **After sending.** The page records `answered` and a `log` entry. A second request with the same client_id and nonce
  is refused ("already answered") unless test mode resends it (D-P5-03-7).

### 4.9 Transport and the relay

| Verifier | Request object | Response | Where the user sees the result |
| --- | --- | --- | --- |
| EUDI | direct (CORS open) | direct (CORS open) | the EUDI UI, which polls; the page shows 200 `{}` |
| Multipaz | relay | relay (the page needs `redirect_uri`) | the page navigates to `redirect_uri` (`/verifier_redirect.html?sessionId=…`) |
| Paradym | relay | direct form POST (delivered; answer unreadable), or relay if the host is listed | the Paradym dashboard or API |
| OIDF suite, EUDI container (CI) | direct (local hosts, CORS) | direct | the suite's log / the container's API |

**The relay** (P5-03f, D-P5-03-4) is `POST {servletPath}/offer/wallet/relay` with a JSON body. It is not a general
proxy.

- **Operations:**
  - `{"op": "request-object", "uri", "method": "get"|"post", "wallet_nonce"?}`. A POST forwards `wallet_nonce` only.
    The answer is `{status, content_type, body}`, with the body only for a 200 whose media type is
    `application/oauth-authz-req+jwt` or `application/jwt`.
  - `{"op": "response", "uri", "form": {…}}`. The form may only be `response`, or `vp_token` + `state`, or `error`,
    `error_description` and `state`. The answer is `{status, content_type, body}`, the body as text, at most 16 KiB.
  - With P5-03i, `{"op": "annex-a", "uri", "cbor": <base64>}`, which POSTs `application/cbor` and answers
    `{status, cbor}`.
- **Configuration.** `certify.offer-page.wallet.relay.{enabled=false, allowed-hosts=[], connect-timeout=PT3S,
  timeout=PT5S, max-request-bytes=16384, max-response-bytes=65536, max-concurrent=8}`, a nested record of
  `OfferPageProperties` checked at bind time. Hosts are lower-case DNS names: no wildcard, IP literal or port; at most
  16. The mDL profile sets `verifier.multipaz.org,paradym.id`. `GET /offer/wallet/config` publishes the list to the
  page.
- **URL.** `https` only; port absent or 443; host exactly on the list; no userinfo, no fragment; at most 2048
  characters.
- **DNS.** Every resolved address must be public. Refused: loopback, any-local, link-local, RFC 1918, CGNAT
  `100.64/10`, `0/8`, `192.0.0/24`, `198.18/15`, documentation ranges, multicast, `fc00::/7`, `fe80::/10`, and the
  IPv4-mapped or IPv4-compatible forms of these. The checked addresses are pinned through httpclient5's `DnsResolver`
  (already on the runtime classpath, I6), so the connection goes exactly where the check looked; there is no rebinding
  window.
- **What is not forwarded.** No redirects (`disableRedirectHandling()`: a 3xx is returned as its status), no cookies,
  no authentication, none of the client's headers; `User-Agent: certify-demo-wallet-relay/1`. A response larger than
  `max-response-bytes` is cut off with 502 `relay_response_too_large`. More than `max-concurrent` relays at once is
  503.
- **Logs:** op, host, status and duration. Never a body: it carries personal data, and for `direct_post` it carries
  the plaintext DeviceResponse.
- **Trust.** The relay cannot forge a request: the page verifies the JAR signature itself. It sees no keys, and only
  ciphertext for `direct_post.jwt`.
- **nginx.** An allow-list row `"~^(POST|OPTIONS) /v1/certify/offer/wallet/relay$"` with its own `limit_req` zone (10
  a minute, burst 10, keyed per client as D12 keys it) and `client_max_body_size 16k`. No security URL list entry: the
  `/offer/**` chain covers it (rule 9).

### 4.10 Camera

- `navigator.mediaDevices.getUserMedia({video: {facingMode: "environment"}, audio: false})` feeds a muted,
  `playsinline` `<video>`.
  - At most 6 frames a second are sampled.
  - The tracks stop on a result, on "Cancel", on `visibilitychange` to hidden, and on `pagehide`.
  - A secure context is required (https, or `localhost`).
  - No camera, a refusal or an `OverconstrainedError` falls back to the paste field, which is always shown.
- **Decoder.** `BarcodeDetector` when `"BarcodeDetector" in window` and `getSupportedFormats()` includes `qr_code`
  (Chrome on Android, macOS and ChromeOS). Otherwise vendored **jsQR 1.4.0** (Apache-2.0, 2021-04-24, one UMD file,
  ~131 KB minified, no worker) over a canvas's `getImageData`: Windows and Linux Chrome, Firefox, and Safari (behind a
  flag there).
- **Pinning.** `jsqr.min.js` keeps its licence header. Its SHA-256 goes in `docs/design/tools/vendored-offer.sha256`,
  checked by `shasum -a 256 -c` in CI together with `qrcode.min.js` (whose origin the file records as unverified).
- **What a scan yields** goes through the same parser as a pasted link. A scan never sends anything by itself.

### 4.11 ISO/IEC TS 18013-7 Annex A (P5-03i, only with D-P5-03-8 (a) or (b))

- **Input.** An `mdoc://<base64url ReaderEngagement>` URI, pasted, scanned, or carried in the wallet page's own URL.
  `AnnexA.parseReaderEngagement` checks:
  - version `1.x`;
  - cipher suite 1;
  - an `EReaderKey` that is EC2 P-256;
  - exactly one retrieval method of type 4 (HTTP) whose URI is `https` (or a localhost page's `http`).
- **Session.**
  1. A fresh ECDH P-256 `EDeviceKey`.
  2. `DeviceEngagement` = version `"1.1"`, Security `[1, #6.24(EDeviceKey COSE_Key)]`, OriginInfo
     `[{cat: 1, type: 1, details: {domain: ""}}]`.
  3. `SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, bstr SHA-256(#6.24(bstr ReaderEngagement))]` (1.4).
  4. `SKDevice`/`SKReader` = HKDF-SHA256 (WebCrypto native) over Z, salt SHA-256(`#6.24(bstr SessionTranscript)`),
     info `"SKDevice"`/`"SKReader"`, 32 bytes.
  5. AES-256-GCM with IV = identifier ‖ counter (ISO5 9.1.1.5).
- **Exchange.** POST `{"deviceEngagementBytes": …}`; decrypt the DeviceRequest. Show the reader's request, and its
  ReaderAuth certificate chain when present, the same way as 4.5. Consent per element as in 4.6, where each requested
  element of `nameSpaces` with its `IntentToRetain` stands in for a DCQL claim. Then POST the encrypted DeviceResponse,
  built by the same `Mdoc.deviceResponse` with this transcript, and expect `{"status": 20}`.
- **Transport.** The relay `annex-a` op for allow-listed hosts (Multipaz has no CORS); otherwise a direct `fetch` with
  `Content-Type: application/cbor`, which needs CORS.

### 4.12 Fixtures

`WalletFixtureRecorderTest` (certify-format-mdoc test scope; writes the committed copy only with
`-Dwallet.fixture.record=true`, like the golden recorders) writes `docs/design/tools/fixtures/wallet/` through Certify's
own `MdocFormatter`, with an Annex B IACA and DSC built by `certify-pki`. The bytes are Certify's.

| File | What | Recorded by |
| --- | --- | --- |
| `iaca.pem` | the test IACA | P5-03b |
| `iaca.crl` | the IACA's CRL (CRL DP `http://crl.wallet-ci.test/iaca.crl`, which the OIDF job serves; 4.14) | P5-03h, the only run that checks the DSC's revocation |
| `mdl-a.issuersigned`, `mdl-a.holder.jwk` | an `org.iso.18013.5.1.mDL` with the 15 demo elements of `mdl-demo-1`, and its holder's private JWK (`"comment": "TEST KEY - NOT SECRET"`) | P5-03b |
| `mdl-b.issuersigned`, `mdl-b.holder.jwk` | a second mDL for another holder (a second credential to choose between) | P5-03d |
| `pid.issuersigned`, `pid.holder.jwk` | an `eu.europa.ec.eudi.pid.1` mdoc with four elements (a query for another doctype; `credential_sets` with two doctypes) | P5-03d |
| `clock.txt` | an instant inside every fixture's validity. The harness pins it for the **verifiers** (`expected.json`'s `now`, the `@owf/mdoc` probe's `now` and the Multipaz `atTime`); the **page** is not given it, because the page makes no decision by the clock: it discloses what the user ticks and leaves the time checks to the verifier (P5-03e's expired-credential check is the exception, and it is outside test mode) | P5-03b |
| `verifier/` | made by `make-verifier.sh` (OpenSSL; its output committed): a test CA; leaves `verifier.example` and `other.example` (dNSName SANs) with P-256 keys; a P-256 JWE key pair with `kid`; a README with the commands | P5-03c (the request objects it signs); P5-03e reads its JWE key |
| `hosted/` | the three request objects captured from `verifier-backend.eudiw.dev` on 2026-11-14 (`x509_hash`, ~23 KB, `verifier_info`) and one from `verifier.multipaz.org` (no `aud`, no `state`), for parsing tests under the faked clock | P5-03c |

**Deferred (owner decision, 2026-11-15).** P5-03b records `iaca.pem`, `mdl-a` and `clock.txt` only. `mdl-b`, `pid`,
`iaca.crl`, `verifier/` and `make-verifier.sh` move to the slice that first reads each one, in the table's last column,
and each slice's acceptance checklist names the files it must record before it starts. P5-03b's "a key from another
credential" negative test therefore does **not** use `mdl-b`: the harness generates a `HOLDER_B` P-256 key, keeps
`mdl-a`'s record with it and asserts the page refuses to sign, and a sample signed with that key is what both verifiers
must reject.

The committed fixture keeps the harness and the probes deterministic and offline. The CI interop jobs need fresh MSOs,
so the recorder also runs in the normal build, writing to `certify-format-mdoc/target/wallet-fixture/` with the real
clock.

### 4.13 Headers

The `OfferPageController` answers `/offer/` and `/offer/wallet` with (D-P5-03-11):

- `Content-Security-Policy: default-src 'none'; script-src 'self' 'sha256-<the offer page's inline script>';
  style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' https:; frame-ancestors 'none';
  base-uri 'none'; form-action 'none'; object-src 'none'`.
  - The hash is computed once at startup from the bytes served, so it cannot drift from the page.
  - `wallet.html` has no inline script.
  - `connect-src` adds `http://localhost:* http://127.0.0.1:*` only when the request's own host is one of those.
- `Permissions-Policy: camera=(self)` on the wallet page, `camera=()` on the offer page.
- `Referrer-Policy: no-referrer`: the wallet URL can carry request parameters for a moment.
- `Cache-Control: no-store` on the wallet page.

### 4.14 Independent verification (non-negotiable 2)

| Gate | Library or tool (pinned) | What it proves | Where | Slice |
| --- | --- | --- | --- | --- |
| page behaviour | `check-offer-wallet.mjs` (plain Node, faked DOM, fetch, IndexedDB and clock) | flows, refusals, nothing sent before consent, byte identity, absent elements | CI, every push | a-g, i |
| DeviceResponse | `@owf/mdoc` 0.9.3 (Apache-2.0) with its reference crypto context (`@peculiar/x509`, `@noble/curves`), exact `package-lock.json` | issuer signature to the fixture IACA, device signature over the transcript computed by **its own** `SessionTranscript.forOid4Vp`, docType, disclosed set | `docs/design/tools/wallet-probe/`, CI | b |
| DeviceResponse | Multipaz 0.102.0 `DeviceResponse.fromDataItem(…).verify(sessionTranscript, …, atTime)` + `TrustManager` (the existing pin) | the same, second library | `certify-testkit-mdoc` `IndependentDeviceResponseVerifier`, run by `certify-conformance-mdoc` `WalletPresentationConformanceTest` | b |
| JWE | `jose` 6.2.17 (MIT) `compactDecrypt` with the verifier's private key | the page's JWE decrypts; header `alg`/`enc`/`kid`/`epk` | `wallet-probe` | e |
| OpenID4VP verifier logic | Multipaz 0.102.0 `VerificationUtil.generateVerificationSessionForDcql` → request → the page's code (a Node driver, run as a subprocess) → `processOpenID4VPUriSchemeResponse(mapOf("response" to jwe))` → `verify(…)` with our IACA trusted | Multipaz's own verifier session accepts the page end to end, `x509_san_dns`, encrypted | `certify-conformance-mdoc` `MultipazVerifierSessionTest` (skipped without `node` locally, failing with `CI` set) | e |
| conformance | OIDF conformance suite `release-v5.3.4` (images by digest): `oid4vp-1final-wallet-haip-test-plan` `iso_mdl` (`x509_hash`, `direct_post.jwt`), plus `oid4vp-1final-wallet-test-plan` `iso_mdl` with `x509_san_dns` + `direct_post` | full protocol, only requested elements, wallet negative tests (signature, `typ`, client_id, prefix, missing nonce, `redirect_uri` with `direct_post`) | CI job `wallet-conformance` (D-P5-03-12) | h |
| interop | EUDI verifier `eudi-srv-verifier-endpoint` v0.12.0 (`sha256:b56390f2…a07f`), `issuer_chain` = the fresh fixture IACA | a real verifier's validation accepts the page's response | CI job `wallet-interop-eudi` (D-P5-03-12) | h |
| live | the three hosted verifiers, by the owner, following section 8 | the demo works where people will try it | manual, recorded in PROGRESS | h |

- **How the OIDF job is driven.**
  1. A Node driver (`docs/design/tools/wallet-conformance.mjs`) starts each test through the suite's REST API.
  2. It reads `browser.urls` and feeds the URL to the page's code, which runs in the harness DOM with Node's real
     `fetch` (TLS verification off for the suite's self-signed origin only).
  3. It presses "Share" on behalf of the user and replays the `iso_mdl` callback POST.
- **Its outcomes.**
  - The refusal modules end REVIEW. The driver accepts REVIEW only when the harness proves the page sent nothing to the
    suite's `response_uri`, and uploads a rendered image of the refusal panel as the screenshot (as the `idfoundry`
    precedent uploads a stand-in).
  - HAIP requires the DSC's CRL: the job serves the fixture's `iaca.crl` from a static container with the network
    alias `crl.wallet-ci.test`, and the suite gets `credential.trust_anchor_pem` = `iaca.pem`.
- **The EUDI job.** The container gets a generated P-256 access-certificate keystore (`x509_san_dns:verifier` and
  `x509_hash`), the mDL attestation classification, and an intended use with a self-made registration certificate.
  The driver posts `POST /ui/presentations/v2` with `issuer_chain`, runs the page on the returned URI, then requires
  `GET /ui/presentations/{tx}` to answer the `vp_token`. Re-validation through
  `/utilities/validations/msoMdoc/deviceResponse` must pass.

### 4.15 Non-goals

- In-person ISO 18013-5 (device engagement QR, BLE, NFC) and the W3C Digital Credentials API (TS 18013-7:2025 Annex C;
  VP Appendix A): owner decision 3.
- ISO 18013-7 Annex B (OID4VP draft 18, `mdocGeneratedNonce`): no target needs it for OpenID4VP 1.0.
- `deviceMac` (ISO5 9.1.3.5), which needs a reader key that OpenID4VP does not provide.
- Presenting SD-JWT VC or `ldp_vc`; `transaction_data` (answered `invalid_transaction_data`).
- The `verifier_attestation` and `openid_federation` prefixes; `decentralized_identifier` unless D-P5-03-9 says so.
- Key attestation, wallet attestation, a WSCD (the keys are browser software keys).
- Registering as the system handler for `openid4vp://`, `haip-vp://` or `mdoc://`: impossible from a web page.
- Server-side storage of anything the wallet keeps; exporting or importing a wallet.
- A trusted list of verifiers (deviation 1); a signed VICAL.
- CORS on Certify's own endpoints for other origins (not needed: the page is same-origin).

### 4.16 Compatibility

- **Issuance wire bytes: none change.** The offer page's proof JWT keeps its header and claims; only the key's
  extractability changes, and that is invisible on the wire. No golden, vector, Flyway migration, table, endpoint
  outside `/offer/**`, or security list changes.
- **With `certify.offer-page.enabled=false`** (the default), nothing here is reachable. With it on and
  `certify.offer-page.wallet.enabled=false` (the default), the offer page is today's page plus the new response headers
  (D-P5-03-11), and `/offer/wallet*` answers 404.
- **Runtime classpath unchanged.** The relay uses httpclient5 5.2.3, already there. Node packages live only in
  `docs/design/tools/wallet-probe/`, and Multipaz stays test-only.

## 5. Work packages

All packages share the invariants and brief below.

**Invariants.**

- **I1 (rule 1): no wire-byte change to issuance.**
  - `goldens/legacy-develop`, `goldens/legacy-0.14.0` and `goldens/oid4vci-1.0` replay byte for byte
    (`IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest`), and `SignatureVectorTest` is green.
  - No package changes main code in `certify-core`, `certify-signing`, `certify-issuance`, `certify-format-*`,
    `certify-pki` or a controller outside `io.mosip.certify.offer`.
- **I2: the offer page's issuance behaves as before.** `node docs/design/tools/check-offer-page.mjs` keeps all 943
  checks. The count may grow; an existing check is edited only where the package says so and why. The proof JWT keeps
  its header and claims (`checkCredentialRequest`).
- **I3: nginx guards stay green.** `docs/design/tools/check-public-guard.sh` keeps its 230 lines green; a new path adds
  a `pass` line and `403` lines for its evasions. `check-public-overlay.sh` stays green.
- **I4: everything is switched off by default.** Everything is behind `certify.offer-page.enabled` (default `false`);
  the wallet is also behind `certify.offer-page.wallet.enabled` (default `false`), and the relay behind
  `certify.offer-page.wallet.relay.enabled` (default `false`). With a switch off, its paths answer 404
  (`OfferPageDisabledTest`, new `OfferWalletDisabledTest`).
- **I5 (rules 9, 10): configuration and wiring.**
  - New settings are components of `OfferPageProperties` only: typed, checked at bind time, documented in
    `14-configuration.md`. No `@Value`.
  - No entry in the `mosip.certify.security.*` URL lists: the `/offer/**` chain covers every new path.
  - No `@Import` on the application class and no new `scanBasePackages` entry; new classes go in `io.mosip.certify.offer`
    beside the existing ones.
- **I6: no new production dependency.** `docs/design/tools/check-runtime-classpath.sh` passes with
  `certify-service/runtime-classpath.txt` unchanged. Node packages live only under `docs/design/tools/wallet-probe/`,
  with an exact `package-lock.json`.
- **I7:** `*ArchitectureTest` is green; frozen stores only shrink.
- **I8:** the M-01 and M-11 gates (`MdocSampleConformanceTest`, `verify_mdoc.py`) hold every existing sample to its
  `.gaps`.
- **I9: nothing leaves without consent.**
  - Nothing goes to a verifier before the user presses "Share", "Share anyway", "Send error response" or "Send
    access_denied".
  - Nothing goes to a host the protocol does not name. In particular, no pre-authorized code, transaction code, access
    token, private key or kept credential.
  - The harness asserts this on every flow by recording every `fetch`.

**Brief for the coder.**

- Read this document, `20-mdl-issuer.md` (D2, D12, M-09, F-21), the P5-03 rows of `12-risks-and-decisions.md`, the
  page (`static/offer/index.html`, `cbor.js`), `check-offer-page.mjs` (how it fakes the DOM and fetch, and its "cannot
  check" list), and the classes named in the package.
- Stay inside the files named; list anything else under "Outside scope" in the commit message.
- Run long commands in the foreground (never in the background), run the full test suite, and commit before reporting.
- Local commands. Never run `install` from a worktree: the `~/.m2` is shared.

  ```bash
  export JAVA_HOME=$(/usr/libexec/java_home -v 21)
  M="mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -Dmaven.gitcommitid.skip=true"
  $M verify                                              # Java (from P5-03b on)
  node docs/design/tools/check-offer-page.mjs            # 943+ checks
  node docs/design/tools/check-offer-wallet.mjs          # writes target/wallet-samples/
  (cd docs/design/tools/wallet-probe && npm ci && node probe.mjs ../../../../target/wallet-samples)
  docs/design/tools/check-public-guard.sh                # Docker
  ```

- Each package ends with its acceptance checklist ticked, each item with the test or command that proves it.

### P5-03a Keep issued mDLs in the browser

Branch `wp/p5-03a-keep-mdl`. Depends on nothing. Planned at about 750 lines (the fake IndexedDB about 150); built at
about 1,950 lines of production code (about 500 of them comments citing the clauses), 2,700 of harness and 400 of
Java tests, fixtures and the lockfile excluded.

**Overrun.** The plan sized a reader that checks decoded values and a store used by one tab. Four review rounds showed
both were wrong: a decoded value can differ from the bytes the page later presents (tags resolve to what they carry,
keys of different types render alike, floats and bignums read as integers), so the reader checks each structure a
decision rests on from the bytes, keeps map keys' types and compares them as RFC 8949 §5.6.1 does (`cbor.js` grew from
about 260 to 770 lines, `mdoc.js` is 480); and IndexedDB connections are shared across tabs, so "Delete everything"
waits for other tabs, the wallet page follows deletes made elsewhere, and a keep waiting behind one reports per run.
The harness grew with each refusal, since every one has a negative test. The later packages keep their estimates;
P5-03b and P5-03c reuse this reader and store rather than adding to them.

**Files.**

- `static/offer/index.html`: `proofJwt` returns a non-extractable pair; the "Keep" checkbox (`mso_mdoc` only, ticked);
  keeping the first credential after a 200; a link to `wallet` when `GET /offer/wallet/config` answers 200.
- `static/offer/cbor.js` (4.3); new `static/offer/mdoc.js` (`readIssuerSigned`, `checkKeepable`), new
  `wallet-store.js`, new `wallet.html` and `wallet.js` (the list, a details view rendering the elements as
  `renderMdoc` does, "Delete", "Delete everything").
- `io/mosip/certify/offer/OfferPageProperties.java`: a `Wallet wallet` component (`enabled`, default `false`).
- `io/mosip/certify/offer/OfferPageController.java`: `GET /offer/wallet` and `GET /offer/wallet/config` (`{"relay":
  {"hosts": []}}`, `no-store`), both only with `wallet.enabled`; the headers of 4.13 on every page answer.
- `docker-compose/docker-compose-injistack/certify-nginx.conf`: rows for `offer/wallet`, `offer/wallet/config` and
  `offer/(qrcode\.min|cbor|mdoc|wallet-store|wallet)\.js`.
- `docker-compose/docker-compose-injistack/config/certify-mdl.properties`: `certify.offer-page.wallet.enabled=true`.
- `docs/design/tools/check-public-guard.sh`: `pass` for each new path; `403` for POST, a trailing segment, `.map` and
  an unlisted `offer/x.js`.
- `docs/design/tools/check-offer-page.mjs`:
  - exports `openPage`, `parseMarkup` and the check helpers, and runs its own sections only when executed directly;
  - `openPage(…, {scripts: "real"})` evaluates the page's own `src` scripts from `static/offer/` (a `src` outside that
    directory fails the run);
  - a fake IndexedDB whose records are cloned with `structuredClone`, so a `CryptoKey` stays non-extractable as in a
    browser (checked on Node 24);
  - the 943 checks keep the `Cbor` stub.
- New `docs/design/tools/check-offer-wallet.mjs`.
- `.github/workflows/rebuild-ci.yml`: `node-version: '24'`, and a step running `check-offer-wallet.mjs`.
- Tests: `OfferPageTest` (the wallet page and scripts served; headers), new `OfferWalletDisabledTest`,
  `OfferPageSecurityTest`.
- `docs/design/14-configuration.md`, `docs/technical_docs/Releases.md`.

**Spec.** 4.2, 4.3, 4.13.

**Acceptance checklist.**

- [ ] `proofJwt`'s key: `privateKey.extractable === false`; `exportKey("jwk", privateKey)` rejects;
  `checkCredentialRequest` is unchanged and green.
- [ ] Issuing the fixture mDL through the page keeps exactly one record.
  - Setup: the harness's credential endpoint answers `mdl-a.issuersigned`, and `generateKey` hands the page `mdl-a`'s
    key, imported non-extractable.
  - The record's `issuerSigned` equals the fixture bytes, and its `privateKey` signs a challenge that verifies with the
    fixture's public key.
- [ ] Checks 1-5 of 4.2 each refuse with their own message and keep nothing. The cases:
  - undecodable bytes;
  - another doctype than the configuration's;
  - `mdl-b`'s credential with `mdl-a`'s key;
  - one element's value changed (digest mismatch);
  - 257 KiB;
  - the 51st credential.
- [ ] With "Keep" unticked, a non-`mso_mdoc` configuration, or no IndexedDB, nothing is kept and the issuance result
  is as today.
- [ ] "Delete" removes one record; "Delete everything" deletes the database; the list follows both.
- [ ] `Cbor.encode` reproduces RFC 8949 Appendix A for every type it supports:
  - integers 0, 23, 24, 255, 256, 65535, 65536, 2^32, 2^53+1 (BigInt), -1, -25, -2^64 (BigInt);
  - `h''`, `h'01020304'`, `""`, `"IETF"`, `"ü"`;
  - `[]`, `[1, [2, 3]]`, `{}`, `Map{1: 2, 3: 4}`;
  - and `Tagged(24, h'a0')` = `d8 18 41 a0`.

  `Raw` refuses a non-item and two items.
- [ ] `Mdoc.readIssuerSigned(mdl-a)`: every `raw` slice is a tag-24 item whose digest equals the MSO's, and the slices
  with their array headers reassemble the fixture's `nameSpaces` value byte for byte.
- [ ] `/offer/` and `/offer/wallet` carry the headers of 4.13. The harness recomputes the inline script's hash from the
  page it parsed and finds it in the CSP.
- [ ] Manual, recorded in the PR: Chrome, Firefox and Safari keep a credential across a reload, and DevTools shows the
  key non-extractable.
- [ ] I1-I9 hold; the guard is green with the new lines.

**Negative tests.**

- A credential response with two credentials keeps only the first and says so.
- An IssuerAuth whose payload is not tag 24 is refused.
- A P-384 `deviceKey` is refused: the page holds P-256 keys only.
- `/offer/wallet` with `wallet.enabled=false` answers 404.

**Non-goals.** Presentation; storing SD-JWT VC or `ldp_vc`.

### P5-03b DeviceResponse and its independent verification

Branch `wp/p5-03b-device-response`. Depends on P5-03a. About 750 lines planned; about 1,580 built, fixtures and
lockfile excluded (413 of harness, 294 of probe, 323 of Java verifier, 260 of conformance test, 190 of `mdoc.js`).

**Overrun.** Plan 4.14 names **two** independent verifiers for a DeviceResponse (`@owf/mdoc` in Node, Multipaz in Java),
and each needs its own crypto context, its own named checks, its own reading of the disclosed set and its own negatives;
that is the 750-line estimate's blind spot, not one package doing two jobs (owner decision, 2026-11-15, decision log).

**Files.**

- `static/offer/mdoc.js`: `Mdoc.oid4vpSessionTranscript({clientId, nonce, jwkThumbprint, responseUri})` and
  `Mdoc.deviceResponse(record, chosen, sessionTranscript, {alg})` (4.7).
- New `certify-format-mdoc/src/test/java/io/mosip/certify/format/mdoc/WalletFixtureRecorder.java` and the committed
  `docs/design/tools/fixtures/wallet/{iaca.pem, mdl-a.issuersigned, mdl-a.holder.jwk, clock.txt}` (4.12). The rest of
  4.12's files are the later slices' (owner decision, 2026-11-15).
- `docs/design/tools/check-offer-wallet.mjs`: the presentation sections. It writes each DeviceResponse with its inputs
  to `$WALLET_SAMPLES_DIR` (default `target/wallet-samples/`) as `<name>/{device-response.cbor, transcript.json,
  expected.json, iaca.pem}`.
- New `docs/design/tools/wallet-probe/{package.json, package-lock.json, probe.mjs, README.md}`: `@owf/mdoc` 0.9.3 with
  its reference context, `jose` 6.2.17 (used from P5-03e). Versions are exact, and `npm ci` is the only install.
- New `certify-testkit-mdoc/src/main/java/io/mosip/certify/testkit/mdoc/IndependentDeviceResponseVerifier.java` (Multipaz
  `DeviceResponse.fromDataItem`, `verify(sessionTranscript, null, null, null, atTime, …)`, `TrustManager` with the
  sample's IACA; it returns the disclosed `(namespace, element)` set and named check results like
  `IndependentMdocVerifier`).
- New `certify-conformance-mdoc/src/test/java/io/mosip/certify/conformance/mdoc/WalletPresentationConformanceTest.java`.
- `.github/workflows/rebuild-ci.yml`: after the Node harness, run `npm ci` once for `wallet-probe` (the storage
  cross-check installs; the probe step reuses it), `node probe.mjs`, then
  `mvn -pl certify-conformance-mdoc test -Dtest=WalletPresentationConformanceTest -Dwallet.samples.required=true` over
  the samples. The property is what makes a missing samples directory a failure, and only that step passes it:
  `mvn verify` runs before the harness, so it must skip there (review round 1, finding 1).

**Acceptance checklist.**

- [ ] The VP B.2.6.1 vectors (1.1) are reproduced byte for byte: `jwkThumbprint` of the example JWK, the
  `OpenID4VPHandoverInfo` hex, its SHA-256, the handover and the SessionTranscript. The `null`-thumbprint form is
  computed and cross-checked with `@owf/mdoc`'s `SessionTranscript.forOid4Vp`.
- [ ] For `mdl-a` and a request for `family_name`, `birth_date`, `portrait` and `age_over_18`:
  - every disclosed IssuerSignedItemBytes equals its slice in the kept IssuerSigned byte for byte, and `issuerAuth`
    equals the kept IssuerAuth byte for byte;
  - none of the 11 other elements' IssuerSignedItemBytes, `random`, encoded value or identifier occurs anywhere in the
    DeviceResponse bytes (searched as byte strings);
  - `deviceSigned.nameSpaces` is exactly `d8 18 41 a0`, `status` is 0 and `version` is `"1.0"`;
  - the device signature verifies with `node:crypto` over a DeviceAuthenticationBytes that the harness builds with its
    own small encoder, not `cbor.js`.
- [ ] With `{alg: -9}` the protected header is `a1 01 28`, and both libraries accept it.
- [ ] `probe.mjs` verifies every positive sample with `Verifier.verifyDeviceResponse` (`trustedCertificates:
  [{issuance: [iaca]}]`, `now` from `clock.txt`) and reads back exactly the expected elements. Every negative sample
  fails the expected check.
- [ ] `WalletPresentationConformanceTest` verifies the same samples with Multipaz: issuer signature, chain to the IACA,
  device signature over the transcript, digests, docType and the disclosed set.
- [ ] I1-I9 hold.

**Negative tests.** Each is a harness check and a sample that both libraries must reject.

- The transcript used another `nonce`, `client_id`, `response_uri` or thumbprint than the verifier's: the device
  signature fails.
- One disclosed item is re-encoded (same value, other map key order): the digest does not match.
- "A key from another credential": the page refuses to sign when the signature it makes does not verify under the
  record's own public key, and when the record's public key is not the MSO's `deviceKey`. The harness generates a
  `HOLDER_B` key for this test (`mdl-b` is P5-03d's, 4.12); a sample signed with it fails the device signature in both
  libraries.
- An unticked element is absent from the bytes, and both libraries report only the ticked set.
- Namespaces with no chosen element are omitted, never sent as empty arrays (ISO5 `[+ IssuerSignedItemBytes]`).

**Non-goals.** Requests, verifier authentication, encryption, transport.

### P5-03c Request intake and verifier authentication

Branch `wp/p5-03c-request-intake`. Depends on P5-03a; runs in parallel with P5-03b. About 800 lines.

**Files.**

- New `static/offer/x509.js`:
  - DER/ASN.1 reader for certificates: subject and issuer names, validity, SAN (dNSName, URI), AKI and SKI, basic
    constraints, SPKI;
  - `X509.importPublicKey` (SPKI → WebCrypto, EC P-256/384/521 and RSA);
  - `X509.verifyIssuedBy(cert, issuer)` (ECDSA-with-SHA256/384/512 with the DER signature converted to `r‖s`;
    RSA-PKCS1 and RSA-PSS).
- New `static/offer/oid4vp.js`: link parsing (4.4), `fetchRequestObject`, `checkRequest` (R1-R11, the error cases and
  the findings of 4.5).
- `static/offer/wallet.js`, `wallet.html`: paste field; same-device invocation from `location`; the verifier card; the
  request checks; "Send error response". The response itself comes in P5-03e; until then a valid request ends at the
  card.
- `certify-nginx.conf`, `check-public-guard.sh`: `x509.js`, `oid4vp.js`.
- `check-offer-wallet.mjs`: intake sections, with the fixture verifier (signing JARs with `node:crypto`) and the hosted
  request objects of 4.12.

**Acceptance checklist.**

- [ ] The 4.12 fixtures this package reads are recorded first: `verifier/` (built by `make-verifier.sh`, committed with
  its README) and `hosted/` (the captured EUDI and Multipaz request objects). They were deferred from P5-03b by the
  owner decision of 2026-11-15, so this slice owns them.
- [ ] Links: each accepted scheme; `https` with parameters; `?…` and `#://?…` same-device forms (the page replaces its
  history entry); `request=` by value; `redirect_uri:` plain parameters; a link without `client_id` (the client_id
  comes from the JAR and a finding is shown).
- [ ] `request_uri_method=post` sends exactly `wallet_nonce` (form) with the `Accept` header, and checks the echo.
- [ ] A pasted request object (compact JWS) goes through the same checks as a fetched one.
- [ ] A request object is fetched at most once per page lifetime: a second scan of the same link says "already
  fetched", and nothing is requested.
- [ ] The captured hosted EUDI JAR (`x509_hash`) and Multipaz JAR (`x509_san_dns`) pass R1-R11 under the faked clock.
  Their cards show the leaf subject, issuer and fingerprints. Multipaz shows the findings "no aud" and "no state".
- [ ] Each of the four error cases of 4.5 offers "Send error response", and the POST it sends carries `error`,
  `error_description` and `state`.
- [ ] A kept credential whose IssuerAuth carries `x5chain` only in the protected header is refused before its chain is
  read or validated: ISO5 9.1.2.4 puts `x5chain` in the unprotected header. P5-03a still reads it from either bucket
  (it validates no chain) and refuses a label in both; the deferral is the decision log's P5-03a review round 3 row.
  P5-03d's `trusted_authorities` `aki` filter relies on this: it matches the chain this check has placed.
- [ ] I1-I9 hold. In particular, no flow in this package sends anything to `response_uri` without a press.

**Negative tests.** Each refuses, names the rule, and the fetch log shows no request to `response_uri`.

- A JAR whose signature has one bit flipped (R6/R7).
- `typ` absent; `typ` `JWT` (R2).
- The link's `client_id` differs from the JAR's (R3).
- `wallet_nonce` missing or different in the JAR (R4).
- `aud` `https://other.example` (R5).
- `x509_san_dns:verifier.example` signed by the `other.example` leaf (R6).
- `x509_hash` of another certificate (R7).
- `response_uri` on `other.example` under `x509_san_dns:verifier.example` (R8).
- `response_uri` `http://…` on a non-localhost page (R8).
- `origin:` and `decentralized_identifier:` prefixes (R9); a signed `redirect_uri:` request (R9).
- An `x5c` whose intermediate does not sign the leaf, and an expired leaf (R10).
- A request object of 64 KiB + 1, 6 certificates in `x5c`, and DCQL with 21 credential queries (R1, limits).
- request_uri answering 302 (refused, `redirect: "error"`), 404 and 500 (R1).

**Non-goals.** DCQL, consent, the response, the relay (P5-03f), scanning (P5-03g).

### P5-03d DCQL and consent

Branch `wp/p5-03d-dcql-consent`. Depends on P5-03b and P5-03c. About 600 lines.

**Files.** `oid4vp.js` (`Oid4vp.matchDcql`), `wallet.js`/`wallet.html` (the consent panel and test mode), and
`check-offer-wallet.mjs`.

**Spec.** 4.6, and D-P5-03-7 as answered.

**Acceptance checklist.**

- [ ] The 4.12 fixtures this package reads are recorded first: `mdl-b.issuersigned`/`mdl-b.holder.jwk` and
  `pid.issuersigned`/`pid.holder.jwk`. They were deferred from P5-03b by the owner decision of 2026-11-15, so this
  slice owns them: the second credential and the second doctype are what `credential_sets`, a query for another
  doctype and "no matching credential" are about.
- [ ] The EUDI UI's mDL query and the OIDF `mdl` query match `mdl-a` with exactly the requested rows ticked. No row is
  offered for an element that was not requested.
- [ ] `claim_sets` `[["age"], ["dob"]]` over `age_over_18`/`birth_date` preselects `age`, and the user can switch to
  `dob`.
- [ ] `values: [true]` on `age_over_18` matches `mdl-a`, and `values: ["XX"]` on `issuing_country` does not.
- [ ] `trusted_authorities [{type: "aki", values: [<fixture IACA SKI, base64url>]}]` matches; another SKI excludes the
  credential and says why; `etsi_tl` keeps the credential with a finding.
- [ ] `credential_sets`:
  - a required mDL and an optional PID: the mDL is preselected and the PID offered unticked;
  - a required `[[mdl], [pid]]`: the first option that matches is preselected;
  - an optional query without a match is absent from `vp_token`.
- [ ] A query without `claims` presents the IssuerAuth with no `nameSpaces`.
- [ ] Unticking a required element shows the warning and "Share anyway", and the log marks the presentation
  non-conformant.
- [ ] A query for `eu.europa.ec.eudi.pid.1` with only `mdl-a` kept ends at "no matching credential", offering "Send
  access_denied".
- [ ] I1-I9 hold.

**Negative tests.**

- A claims path of three elements, or one with a number, is `invalid_request`.
- `claim_sets` naming an unknown claim id is `invalid_request`.
- Duplicate credential query ids are `invalid_request`.
- An expired kept credential is not a candidate outside test mode.
- A DCQL query for another doctype matches nothing, and nothing is sent until "Send access_denied" is pressed.

**Non-goals.** Formats other than `mso_mdoc`; matching on issuer identity other than `aki`.

### P5-03e The response

Branch `wp/p5-03e-response`. Depends on P5-03d. About 700 lines.

**Files.**

- New `static/offer/jwe.js`.
- `oid4vp.js`: `buildResponse` and `deliver`.
- `wallet.js`/`wallet.html`: Share and Decline, the result, `redirect_uri`, the log view, the replay guard.
- `certify-nginx.conf`, `check-public-guard.sh` for `jwe.js`.
- `check-offer-wallet.mjs`.
- `wallet-probe/probe.mjs` (`jose`).
- New `certify-conformance-mdoc/src/test/java/io/mosip/certify/conformance/mdoc/MultipazVerifierSessionTest.java`,
  with its driver `docs/design/tools/wallet-driver.mjs`. The driver runs the page's modules headless: request object
  in on stdin, form fields out on stdout.
- `.github/workflows/rebuild-ci.yml`: `setup-node` before the Maven step, so the test finds `node`.

**Spec.** 4.7, 4.8.

**Acceptance checklist.**

- [ ] `direct_post`: the form has exactly `vp_token` (a JSON object keyed by the query id, an array of one base64url
  DeviceResponse) and `state`. The transcript's thumbprint is `null`.
- [ ] `direct_post.jwt`: `jose` `compactDecrypt` with the fixture verifier's private key recovers `{vp_token, state}`.
  - The header has `alg` `ECDH-ES`, the JWK's `kid`, a P-256 `epk`, and no `apu`, `apv`, `cty` or `typ`.
  - `enc` is `A256GCM` when offered, else `A128GCM` (verifier lists `["A128GCM","A256GCM"]`,
    `["A128GCM","A256GCM","A128CBC-HS256"]`, none, and `["A128GCM"]`).
  - The transcript's thumbprint is that JWK's.
- [ ] `MultipazVerifierSessionTest`: Multipaz's own `VerificationSession` (`x509_san_dns:verifier.example`, encrypted)
  accepts the driver's response. `verify` reports `trusted` with the fixture IACA in its `TrustManager`, and exactly
  the requested claims.
- [ ] A 200 with `redirect_uri` navigates there after 2 s; without one the page shows the answer; a `TypeError` is
  reported as "sent; answer unreadable" and nothing is resent.
- [ ] "Decline" sends `error=access_denied` and `state`.
- [ ] I1-I9 hold.

**Negative tests.**

- The same client_id and nonce a second time are refused as "already answered", and nothing is sent.
- A key the page cannot use (`P-384`, `alg` `ECDH-ES+A128KW`, no `kid`) is skipped in favour of a usable one. With none
  usable, the result is `vp_formats_not_supported`, sent unencrypted only on a press.
- `encrypted_response_enc_values_supported: ["A128CBC-HS256"]` alone is `vp_formats_not_supported`.
- The JWE tampered in one ciphertext byte fails `jose`.
- A `redirect_uri` that is `http:` or `javascript:` is shown, never followed.
- For a host on the relay list the response goes only through the relay (the fetch log shows no direct POST).

**Non-goals.** `transaction_data`; signed responses (`iss`/`aud`/`exp` in the payload); A128CBC-HS256.

### P5-03f The relay (only with D-P5-03-4 (a))

Branch `wp/p5-03f-relay`. Depends on P5-03c. About 650 lines.

**Files.**

- New `io/mosip/certify/offer/WalletRelayController.java`, `WalletRelayClient.java` (httpclient5: pinned
  `DnsResolver`, no redirects, size and time limits) and `PublicAddressPolicy.java`.
- `OfferPageProperties.java` (`wallet.relay.*`); `OfferPageController` fills `GET /offer/wallet/config`.
- `oid4vp.js`: the page's use of the relay.
- `certify-nginx.conf` (row, `limit_req` zone, body cap) and `check-public-guard.sh` (pass, 403, 429, 413 lines).
- `config/certify-mdl.properties` (`relay.enabled=true`, `allowed-hosts=verifier.multipaz.org,paradym.id`).
- `14-configuration.md`, `Releases.md`.
- Tests: `WalletRelayControllerTest` (MockMvc), `WalletRelayClientTest` (a local `HttpServer` on loopback, reached by
  a test-only address policy), `PublicAddressPolicyTest`, `OfferPagePropertiesTest`.

**Spec.** 4.9.

**Acceptance checklist.**

- [ ] `request-object` GET and POST (with `wallet_nonce`) to an allow-listed host return `{status, content_type, body}`.
- [ ] A non-JAR media type returns the status without a body.
- [ ] `response` forwards exactly the allowed form fields and returns the verifier's status and text body.
- [ ] The page uses the relay for a listed host and directly otherwise, never both.
- [ ] Bind-time refusals: a wildcard host, an IP literal, a port, an upper-case host and 17 hosts each stop startup with
  a message naming the entry.
- [ ] nginx: public `POST /v1/certify/offer/wallet/relay` passes; GET is 403; an 11th request a minute is 429; a 17 KiB
  body is 413.
- [ ] Logs carry op, host, status and duration, and no body (a test greps the captured log for the JWE and the nonce).
- [ ] I1-I9 hold; the runtime classpath is unchanged.

**Negative tests.** All of these are SSRF and abuse cases.

- A host not on the list.
- `http://` to a listed host.
- Port 8443.
- Userinfo `https://a@verifier.multipaz.org/`.
- A listed host whose DNS answers `127.0.0.1`, `10.0.0.1`, `169.254.169.254`, `::1`, `::ffff:10.0.0.1` or
  `fd00::1`: each refused before connecting.
- A 302 to another host: returned as 302, not followed.
- An answer of 64 KiB + 1: 502.
- A 6 s answer: 504.
- Nine concurrent relays: the ninth gets 503.
- An extra form field (`foo`) or an unknown op: 400.
- A request body over 16 KiB: 413.

**Non-goals.** Forwarding arbitrary headers; caching; any host the operator did not list.

### P5-03g Camera

Branch `wp/p5-03g-camera`. Depends on P5-03c. About 300 lines, `jsqr.min.js` excluded.

**Files.** New `static/offer/scan.js`, vendored `static/offer/jsqr.min.js` (jsQR 1.4.0, Apache-2.0 header kept), new
`docs/design/tools/vendored-offer.sha256`, `wallet.html`/`wallet.js`, `certify-nginx.conf`, `check-public-guard.sh`,
`rebuild-ci.yml` (`shasum -a 256 -c`), `check-offer-wallet.mjs`, and a `NOTICE` line for jsQR.

**Spec.** 4.10.

**Acceptance checklist.**

- [ ] With a fake `BarcodeDetector` the page uses it.
- [ ] Without one, the page calls `jsQR` with the frame's data, width and height. The harness feeds a QR image of a
  fixture link rendered by `qrcode.min.js` into the real `jsqr.min.js` and gets the link back.
- [ ] Tracks are stopped on result, cancel, hidden and `pagehide`.
- [ ] A refused camera leaves the paste field working.
- [ ] A scanned link goes through the same checks, and nothing is sent by a scan alone.
- [ ] The pinned hashes match. The guard passes `jsqr.min.js` and `scan.js` and refuses `jsqr.min.js.map`.
- [ ] Manual, recorded in the PR: Android Chrome (`BarcodeDetector`), and iOS Safari and Windows Chrome (jsQR), each
  scanning the EUDI QR.
- [ ] I1-I9 hold.

**Non-goals.** Torch, zoom, scanning from images on disk.

### P5-03h Conformance and interop

Branch `wp/p5-03h-conformance`. Depends on P5-03e and P5-03f. About 600 lines, CI configuration included.

**Files.**

- New `docs/design/tools/wallet-conformance.mjs` (the OIDF driver, 4.14) and `docs/design/tools/wallet-interop-eudi.mjs`.
- New `docs/design/tools/conformance/` (suite plan configs, the expected-results file mapping REVIEW to "nothing sent",
  the EUDI env, a keystore script).
- `.github/workflows/rebuild-ci.yml`: jobs `wallet-conformance` and `wallet-interop-eudi`, cadence per D-P5-03-12.
  Images are pinned by digest: the OIDF `release-v5.3.4` server, nginx and `mongo:6.0.13`; EUDI `sha256:b56390f2…`.
- `docs/design/20-mdl-issuer.md` (the wallet row of the demo matrix), `docker-compose/docker-compose-injistack/config/mdl/README.md`
  ("Testing verifiers with the page wallet": section 8 of this plan, kept current), and a `docs/design/wp/PROGRESS.md`
  entry with the live results.

**Acceptance checklist.**

- [ ] The 4.12 fixture this package reads is recorded first: `iaca.crl` (CRL DP `http://crl.wallet-ci.test/iaca.crl`,
  served by the job's static container). It was deferred from P5-03b by the owner decision of 2026-11-15; HAIP needs
  the DSC's revocation state, and this job is the only run that checks it.
- [ ] The OIDF `oid4vp-1final-wallet-haip-test-plan` (`iso_mdl`) passes every module that a wallet without the DC API
  can pass, with REVIEW only on the refusal modules, each backed by the harness proof that nothing was sent.
- [ ] The plain plan passes with `x509_san_dns` + `direct_post`.
- [ ] The suite logs no `CheckOnlyRequestedMdocElementsDisclosed` failure.
- [ ] The EUDI container accepts the page's response for the UI's mDL query in `haip` profile, and its
  `/utilities/validations/msoMdoc/deviceResponse` re-validation passes with `issuer_chain` = the fresh fixture IACA.
- [ ] Live, by the owner (section 8): EUDI shows the disclosed elements as trusted; Multipaz shows them with "Not in
  trust list" and a valid device response; Paradym shows a verified presentation against the trusted entity. Each is
  recorded with date and outcome in PROGRESS.
- [ ] I1-I9 hold.

**Negative tests.** The suite's own negative modules, listed in 2.3. EUDI: a second POST of the same response is
answered 400, observed and recorded (no change expected on the page).

**Non-goals.** Certifying the page with the OpenID Foundation; running the suite against the live host.

### P5-03i ISO/IEC TS 18013-7 Annex A (only with D-P5-03-8 (a) or (b))

Branch `wp/p5-03i-annex-a`. Depends on P5-03e and P5-03f. About 800 lines.

**Files.**

- New `static/offer/annexa.js`.
- `mdoc.js` (the Annex A transcript).
- `wallet.js`/`wallet.html` (an `mdoc://` link; the DeviceRequest panel).
- `WalletRelayController` (`annex-a` op).
- `certify-nginx.conf`, `check-public-guard.sh`.
- `check-offer-wallet.mjs`.
- New `certify-conformance-mdoc/src/test/java/io/mosip/certify/conformance/mdoc/MultipazAnnexAReaderTest.java`: an
  in-process HTTP reader built on Multipaz 0.102.0 (`SessionEncryption`, `DeviceRequestGenerator`,
  `DeviceResponse.verify`) that drives `wallet-driver.mjs --annex-a <mdoc:// URI>`.

**Spec.** 1.4, 4.11.

**Acceptance checklist.**

- [ ] The Multipaz reader accepts the page's DeviceResponse: session decryption, device signature over the Annex A
  transcript, the IACA chain, and exactly the requested elements.
- [ ] Session keys and IVs match Multipaz's for the same ECDH inputs. The harness computes them independently with
  `node:crypto` HKDF and checks one recorded exchange.
- [ ] Live (owner): the URI from `verifier.multipaz.org`'s `annexABegin` (pasted) yields a result on its session.
- [ ] I1-I9 hold.

**Negative tests.**

- A ReaderEngagement with a P-384 key, two retrieval methods, or an `http` URI on a non-localhost page.
- A SessionData whose tag fails.
- A counter replayed.
- A DeviceRequest for another doctype: nothing is sent until the user declines, then status 20 is sent.

**Non-goals.** BLE, NFC, Wi-Fi Aware, reader authentication beyond showing the chain, `deviceMac`.

**Order.** P5-03a, then P5-03b and P5-03c in parallel, then P5-03d and P5-03e. P5-03f and P5-03g can start once
P5-03c is merged. P5-03h comes after P5-03e and P5-03f, and P5-03i last. The demo is usable with EUDI after P5-03e,
with Multipaz and Paradym after P5-03f, and by camera after P5-03g.

## 6. Demo-only deviations (recorded in the decision log with the answers to section 7)

| # | Deviation | Clause | Why it is acceptable here, and how the page shows it |
| --- | --- | --- | --- |
| 1 | No trusted list for verifiers. The page checks the `x5c` signatures up to the topmost certificate and their validity, and binds the client_id to the leaf (R6/R7), but reaches no trust anchor. | VP §5.9.3 "The Wallet MUST validate the signature and the trust chain"; §15.8.1 | A demo has no ecosystem trust list; §15.8.1 allows end-user confirmation for unrecognised endpoints. The card says "No trusted list: this demo cannot tell you who this verifier is", shows the top certificate's issuer and fingerprints, and nothing is sent without "Share" (D-P5-03-10). |
| 2 | A credential that does not satisfy the query can be sent: required elements unticked (owner direction), or "Share what this wallet has" in test mode. | VP §6.4.1 and §6.4.2 MUST NOT | For testing that verifiers refuse incomplete presentations. Explicit "Share anyway", a warning that cites the clause, and the log marks it. Never the default. |
| 3 | Test-mode actions (D-P5-03-7): an expired credential, a credential outside `trusted_authorities`, resending the last response. | VP §6.1 (SHOULD), §14.1 | For testing a verifier's validity, trust and replay checks. Off unless switched on for that presentation. |
| 4 | With the relay (D-P5-03-4 (a)), the request object and, for allow-listed hosts, the response pass through Certify's server. | VP §5.10, §8.2 (wallet-to-verifier transport) | The JAR is verified in the page, so the relay cannot forge it. A `direct_post.jwt` response is ciphertext to Certify. A `direct_post` response is plaintext in transit and is never logged. |
| 5 | Software keys in browser storage, with no key or wallet attestation; Safari may clear them. | HAIP §4.4.1, §4.5.1 (issuance side) | A demo wallet. The wallet page says so. |

## 7. Decisions for the owner (rule 8)

D-P5-03-1 to -3 are the owner decisions of section 0, already recorded.

**Answered 2026-11-14: the owner took every recommendation below** (D-P5-03-4 (a) with (c) as outreach, -5 (a)+(b), -6 (a), -7 (b), -8 (a), -9 (a), -10 (a), -11 (a), -12 (a), -13 (a)); recorded in `docs/design/12-risks-and-decisions.md`. P5-03f and P5-03i are therefore in scope.

| # | Question | Options | Recommendation |
| --- | --- | --- | --- |
| D-P5-03-4 | Multipaz (no CORS) and Paradym (Credo has no CORS) cannot be read from a web page on another origin. How does the page get their request objects (and Multipaz's `redirect_uri`)? | (a) a narrow server relay on Certify (4.9, P5-03f): two operations, an explicit https host allow-list (`verifier.multipaz.org`, `paradym.id` in the mDL profile), public addresses only with the address pinned, no redirects, size, time and concurrency limits, nginx rate limit 10/min, off by default; (b) no relay: EUDI works end to end, and for the other two the user fetches the request object with `curl` and pastes it (the paste field accepts a compact JWS). Responses go by form POST, so Multipaz's result page is never reached; (c) ask the Multipaz and Animo maintainers to send CORS headers on their wallet endpoints | **(a), and (c) as outreach.** (a) is the only option that makes two of the three named verifiers work from the page today. The allow-list keeps it from being an open proxy. (b) stays available as the fallback whatever is chosen. |
| D-P5-03-5 | The hosted Multipaz verifier trusts four hard-coded IACAs and cannot be given ours. | (a) accept its live result: every element shown, device and issuer signatures checked, "Issuer: Not in trust list". The trusted path is proven in CI by Multipaz's own `VerificationSession` with our IACA (`MultipazVerifierSessionTest`); (b) ask the Multipaz maintainers to add `lorem-ipsum-demo` or to accept a user-supplied IACA; (c) host a Multipaz verifier (a small `main` on `multipaz-verifier` 0.102.0 with our IACA and CORS) on the demo host | **(a) + (b).** (c) would test our own deployment of their code, not the verifier people use, and adds a service to the public host. |
| D-P5-03-6 | What does the page keep, and by default? | (a) `mso_mdoc` only, "Keep this credential in this browser" ticked by default; (b) `mso_mdoc` only, opt-in; (c) every format kept, presentation for `mso_mdoc` only | **(a).** The data is synthetic (D2), and the owner wants to test verifiers. Deleting is one click, and nothing leaves the browser. |
| D-P5-03-7 | Beyond unticking required claims (owner direction), which non-conformant actions may the page offer for verifier negative testing? | (a) none; (b) a per-presentation "Verifier test mode", off by default, enabling: presenting an expired credential, presenting one outside `trusted_authorities`, "Share what this wallet has" when a required query cannot be satisfied, and resending the last response to the same request (replay); (c) (b) plus deliberate corruption (another transcript, a bad device signature, re-encoded items) | **(b).** These test a verifier's validity, trust, completeness and replay checks, which is what the owner wants the page for. Corruption (c) belongs in the CI negative samples, not on a public page. |
| D-P5-03-8 | ISO/IEC TS 18013-7 Annex A (the REST flow the owner chose). Only Multipaz offers it, and it starts it by navigating its own tab to `mdoc://…`, which a web page cannot receive; its endpoints have no CORS. | (a) build P5-03i last. Proof in CI against an in-process Multipaz 0.102.0 reader. Live via the relay, with the `mdoc://` URI pasted (from the network panel of the Multipaz tab: the `annexABegin` answer); (b) as (a), plus a relay operation that starts a Multipaz Annex A session from the page (couples Certify to Multipaz's private API); (c) defer and record that no target verifier can hand an Annex A engagement to a web page; build when one can (the RDW reader at `reader.rdw.mdoc.online/TestAnnexA2.html`, which Multipaz tested against, is unverified) | **(a).** It honours the owner's choice with an independent proof in CI, at the cost of an awkward live step. Go or no-go after P5-03h; (c) is the cheaper honest alternative if the owner prefers. |
| D-P5-03-9 | Paradym's default verifier identity is `decentralized_identifier:did:web:…` with an Ed25519 key; the `certificate` signer gives `x509_hash`. | (a) the runbook sets the template's verifier signer to `certificate`, and the page refuses `decentralized_identifier` (R9); (b) also support `decentralized_identifier:did:web`: the DID document fetched through the relay, `kid` selection, EdDSA (WebCrypto Ed25519, current Chrome, Firefox and Safari) and ES256; about 250 more lines in P5-03c/f | **(a)**, and (b) only if the owner's Paradym plan cannot use the certificate signer. HAIP requires `x509_hash`, not DIDs. |
| D-P5-03-10 | How the page presents a verifier it cannot check against a trusted list (deviation 1). | (a) validate what can be validated, show the certificate details, and require "Share"; (b) (a) plus an operator list `certify.offer-page.wallet.known-verifiers[] {name, ca-sha256}` served to the page, labelled "known to this demo", never refusing others; (c) refuse verifiers outside a list | **(a).** (b) can come later if visitors are confused. (c) defeats testing arbitrary verifiers. |
| D-P5-03-11 | Response headers on the offer pages: `Content-Security-Policy` (the inline script by hash), `Permissions-Policy`, `Referrer-Policy` (4.13). | (a) on both pages; (b) only on the wallet page; (c) none | **(a).** Keeping usable keys on the origin raises the stakes of any script injection. The headers are not issuance wire bytes, and no golden covers the page. |
| D-P5-03-12 | How often the OIDF conformance and EUDI interop jobs run (Docker; about 6-8 minutes together). | (a) a merge gate on pushes that touch `static/offer/**`, `docs/design/tools/wallet*` or the fixtures, plus nightly on `design/extensibility`; (b) nightly only, informational; (c) manual | **(a).** Non-negotiable 2 makes independent verification a merge gate. Images pinned by digest keep upstream regressions out (the one precedent had to pin after a `:latest` break). |
| D-P5-03-13 | CI runs the harness on Node 20, end of life since 2026-04-30. | (a) Node 24 (current LTS; the 943 checks pass on it); (b) Node 22; (c) keep 20 | **(a)**, in P5-03a. |

## 8. Testing the three verifiers on the live demo (runbook, for P5-03h)

Nothing here has been run. `<host>` is `credentials.loremipsum.co.in`. The IACA is
`https://<host>/v1/certify/mdoc/iaca/lorem-ipsum-demo.pem`. First issue an mDL on `https://<host>/v1/certify/offer/`
with "Keep this credential in this browser" ticked.

**EUDI** (`https://verifier.eudiw.dev`):

1. In the menu, choose "Configure issuer chain" and paste the IACA PEM. It is kept in the tab's session storage and
   sent as `issuer_chain`.
2. Choose the mDL and its attributes. Profile `haip` (or `openid4vp`); `request_uri_method` `get` or `post`.
3. Pick a device mode:
   - **Cross-device:** keep `haip-vp://` and scan the QR with the wallet page's camera on a phone.
   - **Same-device:** set "Authorization Endpoint" to `https://<host>/v1/certify/offer/wallet`; the verifier's link
     opens the wallet page.
4. On the wallet page, expect the card `x509_hash:…`, `CN=Web Verifier (PROD)` issued by `CN=PID Issuer CA 02`. Untick
   what you like, then press "Share".
5. Expect EUDI to show the disclosed elements. If an element was unticked against the query, expect a refusal.

**Multipaz** (`https://verifier.multipaz.org`), same device only:

1. Protocol "URI scheme (OpenID4VP 1.0)"; "Sign Request" and "Encrypt Response" on.
2. Set "URI scheme for invocation" to `https://<host>/v1/certify/offer/wallet#`.
3. Request the mDL. The tab opens the wallet page with the request in its fragment, and the request object comes
   through the relay.
4. Expect the card `x509_san_dns:verifier.multipaz.org` and the findings "no aud", "no state".
5. Press "Share". The page opens Multipaz's result page. Expect the elements listed, the device response valid, and
   "Issuer: Not in trust list" (D-P5-03-5).

**Paradym** (`https://paradym.id`, a project with an API key):

1. Choose Trust → Trusted Entities → add a certificate: paste the IACA PEM, credential type mdoc.
2. Create a presentation template: format `mdoc`, type `org.iso.18013.5.1.mDL`, the attributes to request,
   `trustedIssuers` = that entity, verifier signer `certificate` (D-P5-03-9). The wallet's OpenID4VC version must be
   `v1`.
3. Create a request with `POST https://api.paradym.id/v1/wallets/{walletId}/openid4vc/verification/request`, body
   `{"presentationTemplateId": "<id>", "requireResponseEncryption": true}`, authenticated with the project's API key
   (Paradym docs, "Verify credentials").
4. Scan `authorizationRequestDeeplinkQrUri` with the wallet page, or paste `authorizationRequestDeeplinkUri`. Expect
   the card `x509_hash:…`, and a DCQL `trusted_authorities` `aki` equal to the IACA's SKI, which matches the kept mDL.
5. Press "Share", then read the verification in the dashboard. If Paradym refuses the algorithm (`-7` not in its list,
   2.2), record it. That is the open risk.

**Annex A** (only with P5-03i), on Multipaz:

1. Choose protocol "URI scheme (18013-7 Annex A)" and request. The tab tries to open `mdoc://…` and nothing happens.
2. In the tab's network panel, copy `uri` from the `annexABegin` answer and paste it into the wallet page.

Record each outcome, with the date, verifier version if shown, and screenshots, in `docs/design/wp/PROGRESS.md`.

## 9. When the packages land

- `12-risks-and-decisions.md`: D-P5-03-4 to -13 as answered, and the deviations of section 6, before the first PR.
  P5-03a can open after D-P5-03-6, -11 and -13 are answered.
- `20-mdl-issuer.md`: the status line and the P5-03 pointer gain the merged commits, and the wallet row of the demo's
  wallet/verifier matrix.
- `docker-compose/docker-compose-injistack/config/mdl/README.md`: "Testing verifiers with the page wallet" (section 8).
- `14-configuration.md`: `certify.offer-page.wallet.*`. `docs/technical_docs/Releases.md`: the wallet page, the
  relay, and the new headers on the offer page.
- `docs/design/VALIDATE.md`: the wallet harness, the probe and the two CI jobs.

## Appendix A. Sources

| Source | Location read |
| --- | --- |
| OpenID4VP 1.0 Final (9 July 2025) | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html (§5, §5.1, §5.8, §5.9.3, §5.10, §6, §7.2, §8, §9, §13.1.2, §14.1, §15.8, Appendix B.2) |
| HAIP 1.0 Final (24 December 2025) | https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html (§5, §5.1, §5.3.1, §7, A.1.2) |
| ISO/IEC TS 18013-7:2025 contents and foreword | IEC preview https://ocp-api.iec.ch/api/publications/107660/view?hasAccess=false&language=en&previewLanguage=en&media=PDF |
| ISO/IEC DTS 18013-7 (2024-02-13) clauses 1-6.4.4 | https://cdn.standards.iteh.ai/samples/82772/ed7c226e282a4f30adf769f9f31d7f39/ISO-IEC-DTS-18013-7.pdf |
| IANA `mdoc` URI scheme (provisional) | https://www.iana.org/assignments/uri-schemes/prov/mdoc |
| BMI architecture, REST API flow | https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/content/archive/flows/PID-AuthenticatedChannel-eIDcard-RESTAPI/ |
| RFC 7518 §4.6 (ECDH-ES, Concat KDF), RFC 7516, RFC 7638, RFC 9052, RFC 9101, RFC 5280 | https://www.rfc-editor.org/ |
| W3C Web Cryptography Level 2 (FPWD 2025-04-22) | https://www.w3.org/TR/webcrypto-2/ (§5.2, §13.5, §23.7.1, §24.4.2) |
| MDN `BarcodeDetector`, `registerProtocolHandler` | browser-compat-data `api/BarcodeDetector.json`; https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler |
| EUDI verifier backend | github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint v0.12.0 `19537e72`, `main` `fd46c1fd`; image digest from the GHCR registry API; live `verifier-backend.eudiw.dev` (transaction init, request objects, CORS preflight), 2026-11-14 |
| EUDI verifier UI | github.com/eu-digital-identity-wallet/eudi-web-verifier `b29584d1` (v0.13.0 + 11) |
| Multipaz | github.com/openwallet-foundation/multipaz tag 0.102.0 `a015c9d9`, `main` `fd37ff10`; live `verifier.multipaz.org` (request object, CORS), 2026-11-14 |
| Paradym | https://docs.paradym.id/llms-full.txt, https://api.paradym.id/openapi.json (2026-11-14) |
| Credo | github.com/openwallet-foundation/credo-ts v0.7.4 `93907de`, `main` `c1aec02`; `animo/openid4vc-playground` `460fe0e` |
| `@owf/mdoc`, `@openid4vc/openid4vp` | github.com/openwallet-foundation-labs/identity-common-ts `816eb0f`; npm `@owf/mdoc@0.9.3` |
| `jose` | npm `jose@6.2.17` (MIT, 2026-11-09) |
| jsQR | npm `jsqr@1.4.0` (Apache-2.0, 2021-04-24) |
| OIDF conformance suite | gitlab.com/openid/conformance-suite `release-v5.3.4` `23353b3`, `master` `daca6ad`; https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/ |
| Suite run in GitHub Actions (precedent) | github.com/idfoundry/oid4vcgo `.github/workflows/oid4vp-conformance.yml` `f29d786` |
