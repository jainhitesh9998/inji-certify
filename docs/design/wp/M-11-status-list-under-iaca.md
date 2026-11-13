# M-11 Token Status List for `mso_mdoc` that wallets accept (G23)

> Part of the Inji Certify extensibility design: [20-mdl-issuer.md](../20-mdl-issuer.md), gap G23, milestone M-11.
> Planning document, 2026-11-13, written against `design/extensibility` at `8c25a6a5`. Work packages are branched as
> `wp/m-11<letter>-<slug>` from `design/extensibility`. Nothing below is decided until the owner answers section 6
> (CLAUDE.md rule 8). The answers go into [12-risks-and-decisions.md](../12-risks-and-decisions.md) before the first PR.

## 0. Summary

**What fails in production.** The public demo (`https://credentials.loremipsum.co.in`, `mdl-operator`, offline IACA
`CN=Lorem Ipsum Demo IACA`) issues mDLs whose MSO carries `status.status_list {idx, uri}`. The list at that `uri` is an
`application/statuslist+jwt`. It is signed by keymanager's development key (`x5c` = `CN=www.example.com
(CERTIFY_VC_SIGN_EC_R1-EC_SECP256R1_SIGN)`, issued by keymanager's `ROOT`), which does not chain to the IACA. Paradym
Wallet downloads the mDL, fetches the list ten times in one second, and fails the import.

**Why: three causes, each enough to fail on its own.**

1. **Format.** Paradym's mdoc library is `@owf/mdoc` 0.9.1, the version locked by `animo/paradym-wallet` `main`. It
   sends `Accept: application/statuslist+cwt` and refuses a JWT with `JwtNotSupportForStatusListError`. The library
   cites ISO/IEC 18013-5 second edition 12.3.6.3: the list must be a Status List Token "in CWT format, since the
   IssuerAuth structure is a CWT". Certify answers a JWT whatever the `Accept`.
   - The ten requests are consistent with batch issuance: Certify advertises `batch_size` 10
     (`Oid4vciProperties.Batch`, default 10), and Credo verifies the credentials of a batch in parallel, each one
     fetching the list (`OpenId4VciHolderService.ts:1502-1506`).
2. **Signer.** The keymanager certificate does not chain to the IACA. ISO 12.3.6.2 makes the IACA the trust point when
   the MSO names no `certificate`, so Multipaz and SpruceID isomdl reject the list too.
3. **Trust path in Credo.** For a received credential, Paradym trusts the top certificate of the presented `x5chain`.
   Under HAIP the `x5chain` carries no IACA, so that top certificate is our Document Signer. Credo then requires the
   status list's validated chain to *equal* the mdoc's issuance chain, unless the wallet configures dedicated status
   certificates, and Paradym configures none.
   - So in Paradym, **only a list signed by the Document Signer that signed the mDL passes**.
   - The dedicated "status signer under the IACA" that the M-11 note and the demo configuration assumed would still
     fail there, even though Multipaz and isomdl would accept it.

**Recommended design (ten lines).**

1. `mso_mdoc` entries go into CWT lists: `application/statuslist+cwt`, a tagged COSE_Sign1 (tag 18, never CWT tag
   61). SD-JWT VC lists stay JWT, byte for byte.
2. Protected header `{1: alg, 16: "application/statuslist+cwt", 33: x5chain}`, unprotected header `{}`, no `kid`. The
   `x5chain` is the signer chain without the IACA.
3. Claims `{2 sub = the MSO uri, 4 exp (always present, capped at the signer's notAfter), 6 iat, 65533 {"lst",
   "bits": 1}, 65534 ttl}`, in RFC 8949 §4.2.1 bytewise order at both levels.
4. Default signer: **the Document Signer that signed the mDLs on that list**, with the same certificate and the same
   `x5chain` as their IssuerAuth. Lists are partitioned by DSC certificate. No new certificate, no offline step.
5. A rotated DSC keeps signing its own lists until its `notAfter`; the MSO validity is already capped there (D7). After
   that the list is retired.
6. Option: a dedicated signer (`signer: dedicated`) issued offline by the IACA, with EKU `id-kp-oauthStatusSigning`
   `1.3.6.1.5.5.7.3.45` (assigned by IANA 2026-06-12), KU `digitalSignature`, at most 457 days, the IACA's CRL DP, and
   `certify-cli pki status-signer issue`. It fits EUDI-style ecosystems but does not work in Paradym today.
7. The endpoint answers each list in its own single format whatever the `Accept`; 503 with `Retry-After` on renewal
   failure as today; 410 once the list is retired.
8. Before every list signature: the chain is valid now, the leaf is not self-signed, and, once IACAs are configured,
   the leaf chains to one of them, is not revoked, and the CRL is not stale.
9. Merge gate: Multipaz 0.102.0 `CompressedStatusList.fromCwt` against the IACA, Authlete COSE, an emulation of
   Credo's equal-chain rule, and (owner's choice) `@owf/mdoc` itself. All run on samples the service tests write;
   pycose runs in CI and the smoke check runs against the live host.
10. `certify.status.token-status-list.mdoc.token-format=jwt` restores today's behaviour for new mDLs. No database
    migration.

**Work packages** (section 5). M-11a to M-11f fix the demo; M-11g and M-11h add the dedicated signer if the owner
wants it now.

| WP | What | Size |
| --- | --- | --- |
| M-11a | COSE `typ` and protected `x5chain` in `certify-signing` | ~250 |
| M-11b | independent status-list verifier in `certify-testkit-mdoc` | ~600 |
| M-11c | CWT codec, signer pinning, signer policy | ~450 |
| M-11d | CWT lists in the service: storage, renewal, endpoint, batch job | ~650 |
| M-11e | issuance binding: the DSC that signs the mDL signs its list; purpose rule; gate samples | ~550 |
| M-11f | smoke, Python verifier, compose comments, docs, decision log | ~600 |
| M-11g (optional) | `certify-pki` status-signer profile and `certify-cli pki status-signer` | ~650 |
| M-11h (optional) | dedicated-signer mode in the service and x509-file | ~450 |

**Owner decisions** (section 6), each with a recommendation:

- D-M11-1, who signs: the DSC by default, the dedicated signer as an option. This retracts the "a Document Signer must
  not sign it" note in `certify-mdl.properties:78-79`.
- D-M11-2, one format per list (this refines D8).
- D-M11-3, CWT by default for new mDLs.
- D-M11-4, no database migration.
- D-M11-5, only the `revocation` purpose for mDoc.
- D-M11-6, reissue the demo's older mDLs.
- D-M11-7, retired lists answer 410.
- D-M11-8, add the `@owf/mdoc` probe to CI.
- D-M11-9, the dedicated signer's profile details.
- D-M11-10, no `status_list.certificate` in the MSO.

## 1. What the specifications require

Clause labels used in section 5: **TSL** = draft-ietf-oauth-status-list-21, **ISO2** = ISO/IEC 18013-5 second
edition, **HAIP** = OpenID4VC HAIP 1.0, **VCI** = OpenID4VCI 1.0.

### 1.1 IETF Token Status List: draft-ietf-oauth-status-list-21

State, read on 2026-11-13: revision 21 of 21 June 2026. The IESG state is "RFC Ed Queue"; no RFC number has been
assigned yet (datatracker). The text was fetched from `https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt`.

| Clause | Requirement (quoted) |
| --- | --- |
| TSL §5.2 | "The Status List Token MUST be encoded as a "CBOR Web Token (CWT)" according to [RFC8392]. The Status List Token MUST NOT be tagged with the CWT tag defined in Section 6 of [RFC8392]. The COSE message MUST either be the tagged COSE_Sign1_Tagged (18) or COSE_Mac0_Tagged (17)" |
| TSL §5.2 | protected header "16 (type): REQUIRED. The type of the CWT MUST be application/statuslist+cwt or the registered CoAP Content-Format ID". The CoAP ID is still "TBD" (§14.8), so only the string can be used. |
| TSL §5.2 | claims "2 (subject): REQUIRED … MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token"; "6 (issued at): REQUIRED"; "4 (expiration time): RECOMMENDED"; "65534 (time to live): RECOMMENDED. Unsigned integer"; "65533 (status list): REQUIRED" |
| TSL §4.3 | `StatusList = { bits: 1 / 2 / 4 / 8, lst: bstr, ? aggregation_uri: tstr }`. Example: byte array `[0xb9, 0xa3]` encodes as `lst` = `78dadbb918000217015d`, which is our test vector. |
| TSL §4.1, §11.1 | bits are indexed "from least significant bit to most significant bit"; Certify already does this (`TokenStatusListService.set`) |
| TSL §5.1 | (JWT) `typ` "MUST be statuslist+jwt"; `sub`, `iat` REQUIRED; `exp`, `ttl` RECOMMENDED |
| TSL §6.3 | for COSE, StatusListInfo carries `idx` (uint) and `uri` (tstr), as Certify writes them; the draft's examples cite ISO mdoc as a Referenced Token |
| TSL §7.1 | 0x00 VALID, 0x01 INVALID, 0x02 SUSPENDED |
| TSL §8.1 | "The Status Provider MUST return the Status List Token in response to an HTTP GET request to the URI provided in the Referenced Token"; media types `application/statuslist+jwt` and `application/statuslist+cwt` are used "for HTTP based Content negotiation" |
| TSL §8.2 | "the Status Provider MUST use the following content-type"; the CWT body is "the binary encoding as defined in Section 9.2.1 of [RFC8392]"; "Relying Parties MUST prioritize the exp and ttl claims within the Status List Token over the HTTP headers" |
| TSL §8.3 | step 4a: "The subject claim (sub or 2) … MUST be equal to the uri claim"; step 4c: "If the expiration time is defined (exp or 4), it MUST be checked"; step 6: an out-of-bounds index "MUST be rejected" |
| TSL §10, §14.9 | EKU `id-kp-oauthStatusSigning`: "A certificate's issuer explicitly delegates Status List Token signing authority by issuing an X.509 certificate containing the KeyPurposeId defined below". In the draft the OID is `1.3.6.1.5.5.7.3.TBD`; IANA has since assigned **45** (section 1.5). |
| TSL §11.3 | "If the Issuer of the Referenced Token is the same entity as the Status Issuer, then the same key that is embedded into the Referenced Token may be used for the Status List Token. In this case the Status List Token may use: … the same x5chain value or an x5t or kid parameter referencing to the same key as used in the Referenced Token for COSE." For a different entity, the keys "may be cryptographically linked, e.g. by a Certificate Authority … and the Status Issuer's certificate should utilize extended key usage (Section 10)". |
| TSL §11.5, §13.7 | clients bound `exp`/`ttl` to reasonable ranges; "Both ttl and exp are RECOMMENDED" |
| TSL §13.9 | "within an ecosystem, a choice for specific formats is made. Within such an ecosystem, only support for those selected variants is required". For mdoc, ISO made that choice: CWT (1.2). |

### 1.2 ISO/IEC 18013-5 second edition (ISO2)

**State.** ISO/IEC DIS 18013-5 (ISO project 91081), stage 40.60 "Close of voting", 2026-03-27 (iss.rs catalogue).
iso.org answered 403. HAIP 1.0 cites it as "ISO/IEC 18013-5:xxxx … edition 2". I could not read the text; it is
paywalled and not published as an IS to my knowledge.

**Method.** The table gives clause 12.3.6 as four independent implementations quote or describe it. "Quoted" means a
verbatim sentence from at least one of them. Treat the clause numbers as those of the CD/DIS.

| Clause | Content | Source |
| --- | --- | --- |
| 12.3.6 | MSO `Status = { ? "status_list": StatusListInfo, ? "identifier_list": IdentifierListInfo, * tstr => RFU }` | `@owf/mdoc` `models/status.ts:10-26`; Multipaz `RevocationStatus.kt:47-58` (StatusListInfo `{idx, uri, ? certificate: bstr}`) |
| 12.3.6.1 | mDL statuses are VALID and INVALID only: "no other status besides 'revoked'" (quoted) | `@owf/mdoc` `mso-revocation-list.ts` (doc comment of `verifyStatusListToken`) |
| 12.3.6.2 | trust point = `StatusListInfo.certificate` if present, else the IACA that issued the Document Signer; "The top certificate of the token x5chain must be the trust point or be signed by it" | isomdl `status_list/mod.rs:106-107,150-152`; Multipaz `CachingRevocationChecker.kt:208` (`status.certificate ?: issuerCert`) |
| 12.3.6.3 | the list is a Status List Token "in CWT format, since the IssuerAuth structure is a CWT" (quoted) | `@owf/mdoc` 0.9.1 `dist/index.mjs:100-102,2682-2683` |
| 12.3.6.3 | "The CWT shall contain the x5chain in the protected header that contains the certificate or chain of certificates used to verify the signature" (quoted) | `@owf/mdoc` `mso-revocation-list.ts:93-95`; isomdl `mod.rs:164` ("12.3.6.3: in the protected header. The MSO has its `x5chain` in the unprotected one") |
| 12.3.6.3 | "The exp claim shall be present." (quoted) | `@owf/mdoc` `mso-revocation-list.ts:229,374`; isomdl `mod.rs:41` |
| 12.3.6.3 | the TSL extended key usage is optional | isomdl `x509/validation/mod.rs:631-633`; Credo `TokenStatusListModuleConfig.ts:15` ("optional in ISO/IEC 18013-5") and `mdocUtil.ts:118-121` |
| 12.3.6.3 | algorithms: ES256/ES384, and also ES512, EdDSA and brainpool curves | isomdl `mod.rs:204-205` |
| 12.3.6.4 | the alternative identifier list, `typ` `application/identifierlist+cwt` | `@owf/mdoc` 0.9.1 `index.mjs:2377` |
| 12.3.6.5 | `bits` shall be 1 | isomdl `mod.rs:140` |

ISO/IEC 18013-5:2021 itself (the first edition) has no MSO revocation mechanism and no `status` key in the MSO, to my
reading. Its Annex B Table B.3 gives the Document Signer EKU `1.0.18013.5.1.2`, critical (D11).

**The EKU question.** RFC 5280 §4.2.1.12 says: "If the extension is present, then the certificate MUST only be used for
one of the purposes indicated." Whether signing the MSO revocation list falls under the mDL Document Signer purpose
depends on ISO2 text I could not read. Three things support "yes":

- TSL §11.3 explicitly allows the Referenced Token's own key.
- isomdl says: "The document signer key may also sign the list (draft-10 11.3), so no key purpose is required"
  (`validation/mod.rs:632-633`).
- Multipaz's own OpenID4VCI issuer signs its CWT and JWT lists with its Document Signer, whose EKU is the mDL DS OID
  (`multipaz-openid4vci/.../request/statusList.kt:75-92`, `multipaz-server/.../ServerIdentity.kt:465-478`).

Credo, for its part, exempts a list signed with the credential's key from its EKU check
(`assertStatusListSignerKeyPurpose.ts:18-19`).

### 1.3 OpenID4VC High Assurance Interoperability Profile 1.0 (Final, 24 December 2025)

| Clause | Requirement (quoted) |
| --- | --- |
| HAIP §5.3.1 (mdocs) | "The Credential Issuer MAY include the MSO revocation mechanism in the issued mdoc. When doing so, it MUST use one of the mechanisms defined in ISO/IEC 18013-5 ([ISO.18013-5.second.edition])." |
| HAIP §6.1 (SD-JWT VC only) | "The public key used to validate the signature on the Status List Token … MUST be included in the x5c JOSE header of the Token. The X.509 certificate of the trust anchor MUST NOT be included … The X.509 certificate signing the request MUST NOT be self-signed." This is the JOSE analogue; Certify applies the same anchor and self-signed rules to the CWT's `x5chain`. |
| HAIP §6.1 | "Each Credential MUST have its own unique, unpredictable status list index". Already met: `DatabaseStatusListIndexProvider.java:104` allocates `ORDER BY RANDOM()`, one index per credential of a batch. |
| HAIP §7 | ES256 MUST be supported for validating "the status information of the Verifiable Credential" |

### 1.4 OpenID4VCI 1.0 (Final)

VCI places no requirement on credential status:

- A.2.4 only says the `mso_mdoc` credential is "the base64url-encoded representation of the CBOR-encoded IssuerSigned
  structure".
- §14.7 lists "Token Status List draft -12" as a pre-final reference.
- The `status` it defines belongs to key attestations (Appendix D.1, "supported revocation check mechanisms").
- §12.2.4 `batch_credential_issuance.batch_size` is what makes a wallet fetch the list once per credential of a batch
  (section 0).

### 1.5 Supporting registries and RFCs

| Source | What it fixes |
| --- | --- |
| IANA "SMI Security for PKIX Extended Key Purpose" (1.3.6.1.5.5.7.3), file updated 2026-11-12 | value **45**, `id-kp-oauthStatusSigning`, reference `RFC-ietf-oauth-status-list-21`, registered 2026-06-12. Credo already uses `OauthStatusSigning = '1.3.6.1.5.5.7.3.45'` (`X509Certificate.ts:47`). |
| RFC 9052 §4.2 | `COSE_Sign1_Tagged = #6.18(COSE_Sign1)` |
| RFC 9596 §2 | COSE header `typ` (label 16), a `tstr` media type or a `uint` content format |
| RFC 9360 §2 | `x5chain` (label 33): one certificate as a `bstr`, several as an array, end-entity first; the end-entity certificate "MUST be integrity protected by COSE", for example by carrying `x5chain` in the protected header |
| RFC 8392 §3.1, §6 | CWT claim keys (2 sub, 4 exp, 6 iat) as NumericDate; CWT tag 61, which TSL §5.2 forbids here |
| RFC 8949 §4.2.1 | deterministic map-key order: keys `1, 16, 33` and `2, 4, 6, 65533, 65534` in that order |

### 1.6 Not verified

- The ISO2 text itself, and whether its Annex B adds a status-list signer profile or EKU. No implementation refers to
  one; isomdl says the EKU is optional.
- Which Paradym build is in the app stores. I read `main`'s lockfile. The observed behaviour (a JWT refused after the
  download succeeded) matches `@owf/mdoc` 0.9.1.
- Talao: not examined; it fails before the status check.

## 2. What wallets and verifiers do

Repositories were read at these heads, shallow clones made on 2026-11-13:

- `openwallet-foundation/credo-ts` `8114e84d` (2026-11-12)
- `animo/paradym-wallet` `a5d722d6` (2026-11-12)
- `openwallet-foundation-labs/identity-common-ts` `975c3fb4` (2026-11-13), which is `@owf/mdoc` HEAD
- npm tarballs `@owf/mdoc@0.9.1`, `@owf/token-status-list@0.6.0` and `@credo-ts/core@0.8.0-alpha-20261030133527`
- `openwallet-foundation/multipaz` `6b4be590` (2026-11-12), and its tag `0.102.0` (Certify's test pin)
- `spruceid/isomdl` `9087dcf5` (2026-10-26)
- `eu-digital-identity-wallet/eudi-lib-android-wallet-core` `d5e2c51c` (statium 0.6.0)
- `eudi-lib-kmp-statium` `d9509240`
- `eudi-srv-statuslist-py` `5da16aea`

| Verifier | Formats for mdoc | `Accept` it sends | Where `x5chain` must be | Trust for the list signer | EKU | Claims checked | Caching |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `@owf/mdoc` 0.9.1 (Paradym, Credo 0.8 alpha) | **CWT only**; JWT → `JwtNotSupportForStatusListError` (`index.mjs:2691-2696`) | `application/statuslist+cwt` (`@owf/token-status-list` 0.6.0 `index.mjs:471-478`) | protected, or unprotected only when a protected `x5t` binds it (RFC 9360) | the `status` certificates of the trusted entry the issuance chain ended in, falling back to the `issuance` certificates (`index.mjs:2874`) | none in the library | `typ` = `application/statuslist+cwt`; `sub` = uri; `iat` required and not in the future; `exp` required (ISO2 12.3.6.3); status at `idx` must be 0 | none; fetched on every verify |
| `@owf/mdoc` HEAD (0.10.0-alpha) | CWT preferred, JWT accepted as a lenient fallback ("a JWT is NOT allowed by § 12.3.6.3", `mso-revocation-list.ts:319-320`) | `application/statuslist+cwt,application/statuslist+jwt` | same | same | none | same | none |
| Credo `Mdoc.verify` / receipt (`OpenId4VciHolderService.ts:1502-1506`, `Mdoc.ts:231-269`) | via `@owf/mdoc` | via `@owf/mdoc` | via `@owf/mdoc` | **without dedicated `status` certificates, the list's validated chain must equal the mdoc's issuance chain** (`mdocUtil.ts:76-115`, also in 0.8.0-alpha `mdocUtil.mjs:52-70`) | `requireStatusSigningKeyPurpose` (default **false**): EKU `1.3.6.1.5.5.7.3.45` plus `digitalSignature`, unless the list key is the credential key (`assertStatusListSignerKeyPurpose.ts:14-25`) | as `@owf/mdoc` | none |
| Paradym Wallet (`apps/wallet/src/config/paradym.ts:63-67`) | as Credo | as Credo | as Credo | `getTrustedCertificatesForVerification` returns `[certificateChain[last]]` as plain strings. Legacy strings become `{issuance: [cert]}` with no `status` (`convertLegacyTrustedCertificates.ts:4-9`). **With our HAIP `x5chain` = `[DSC]`, the trusted certificate is the DSC.** | off | as Credo | none |
| Multipaz 0.102.0 / HEAD `CachingRevocationChecker` | CWT or JWT, chosen by response `Content-Type` (`CachingRevocationChecker.kt:208-284`) | `application/statuslist+cwt, application/statuslist+jwt;q=0.9` | protected or unprotected (`validateCwt.kt:141-142`) | root = `status_list.certificate ?: issuerCert`, where `issuerCert` is the IACA its trust manager resolved for the mdoc (`RevocationInfo.kt:37-47`); chain = `x5chain` plus that root, with basic validation (`validateJwt.kt:337-348`, `X509CertChain.kt:117-153`) | none | `typ` = `application/statuslist+cwt` as `tstr` (`CompressedStatusList.kt:238`); `sub` = uri; `exp` (or `iat` + `maxValidity` when absent) not passed, and not more than `maxValidity` (365 days) ahead (`validateCwt.kt:96-119`) | storage-backed, honours `ETag`/`Last-Modified`, else `exp`/`ttl` |
| Multipaz's own issuer (`multipaz-openid4vci/.../statusList.kt:26-94`) | serves CWT or JWT by `Accept` | n/a | protected `{alg, typ, x5chain without root}`, tagged 18 (`buildCwt.kt:80-93,103`) | **signed with its Document Signer** (`ServerIdentity.CREDENTIAL_SIGNING`, EKU mDL DS) | DS EKU | n/a | n/a |
| SpruceID isomdl reader (`src/definitions/status_list/mod.rs`) | **CWT only** (`STATUS_LIST_CWT_TYPE`, `:29`) | `application/statuslist+cwt` | **protected only** (`:164-166`) | trust point = MSO `certificate`, else the IACA; walks to the trust point; checks the signer chain against its CRL (`validation/mod.rs:620-680`) | none required | `typ`, `sub` = uri, `iat`, **`exp` required** (`:41,80`), `bits` = 1 (`:140-142`), ES256/ES384 only (`:204-238`) | caches `ttl`/`exp`, falls back to the cached token until `exp` (spruceid/isomdl#146) |
| EUDI wallet core plus statium 0.6.0 (`DocumentStatusResolver.kt:224-236`) | **CWT for `MsoMdocFormat`**, JWT for SD-JWT VC | `application/statuslist+cwt` (`GetStatusListTokenKtorOps.kt:56`) | protected or unprotected (`VerifyStatusListTokenSignatureCwtX5c.kt:41`) | signature by the `x5chain` leaf; with a trust configuration, ETSI "revocation" trusted lists (`TrustEvaluatingCwtSignatureVerifier.kt`) | none | `typ` as `tstr` (`GetStatusListToken.kt:161-168`), `sub` = uri, time claims with skew (`:150-151`) | per client |
| EUDI status-list service (issuer side, `app/status_list_format.py:100-136`) | issues CWT for mdoc | n/a | protected `{1: -7, 16: "application/statuslist+cwt", 33: cert}`, unprotected `{}`, no `kid`, tag 18 | a per-country signing certificate | n/a | `2, 4, 6, 65534, 65533` | n/a |

Where each candidate passes. ✓ means it passes; ✗ means it fails, with the reason.

| Candidate list | Paradym (Credo, trust = presented top) | Credo with dedicated `status` certificates | Multipaz (IACA) | isomdl (IACA) | EUDI (signature / ETSI) |
| --- | --- | --- | --- | --- | --- |
| today: JWT, keymanager | ✗ format | ✗ format | ✗ trust | ✗ format | ✗ format |
| CWT, keymanager key | ✗ trust | ✗ trust | ✗ trust | ✗ trust | ✓ / ✗ |
| CWT, dedicated signer issued by the IACA (EKU .45) | **✗ chain ≠ issuance chain** | ✓ when the IACA is configured as a `status` certificate | ✓ | ✓ | ✓ / ecosystem |
| CWT, **signed by the DSC that signed the mDL** | ✓ | ✓ | ✓ | ✓ | ✓ / ecosystem |
| CWT, signed by a newer DSC after rotation | ✗ | ✓ | ✓ | ✓ | ✓ / ecosystem |

The last row is why lists must be bound to the DSC that signed their mDLs (section 4.3).

## 3. Certify today

| Item | Where | Gap |
| --- | --- | --- |
| The list token is a JWT only, `typ statuslist+jwt`, signed by `key-ref` (keymanager `CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN` when unset) | `TokenStatusListService.java:340-361` | TSL §5.2 / ISO2 12.3.6.3 (CWT); ISO2 12.3.6.2 (trust) |
| The endpoint answers JWT for every `Accept` (`produces` includes `*/*`) | `TokenStatusListController.java:29-33` | TSL §8.1-8.2 |
| `CoseHeaderPolicy` cannot put `typ` (16) or `x5chain` in the protected header | `certify-signing/.../CoseHeaderPolicy.java`, `CoseEnvelope.java:38-67` | TSL §5.2; ISO2 12.3.6.3 |
| `CwtEnvelope` tags with 61 or not at all; the claim map order is undefined | `CwtEnvelope.java:17-25` | TSL §5.2 (tag 18, never 61) |
| Lists are shared by purpose across formats (an SD-JWT VC and an mDL can share one) | `TokenStatusListService.allocate`, `:115-128` | one format per list (TSL §13.9) |
| Status is attached before the signing key is resolved, so a list cannot be bound to the signer | `DefaultIssuanceService.java:206-216` | needed for 4.3 |
| The demo comment "A Document Signer must not sign it" | `docker-compose/docker-compose-injistack/config/certify-mdl.properties:75-79` | to be revised (D-M11-1) |
| Index allocation is random (HAIP §6.1); `bits` = 1 (ISO2 12.3.6.5); LSB-first order (TSL §4.1); `sub` = uri and re-signing when stale (F-10) | `DatabaseStatusListIndexProvider.java:104`; `TokenStatusListService.java` | already correct; keep |
| `batch_size` 10 | `Oid4vciProperties.java:34` | explains the 10 fetches; no change |

## 4. Recommended design

### 4.1 The token

```
d2                                     tag 18: COSE_Sign1_Tagged (RFC 9052 §4.2); never tag 61 (TSL §5.2)
  84                                   array(4)
    59 xxxx <protected bstr>           bstr .cbor { 1: alg, 16: typ, 33: x5chain }  keys in this order (RFC 8949 §4.2.1)
      a3
        01 26                          1  alg  = -7 (ES256; -35 ES384, -36 ES512, -8 EdDSA from the signer key)
        10 78 1a 6170706c69636174696f6e2f7374617475736c6973742b637774
                                       16 typ  = "application/statuslist+cwt" (TSL §5.2, RFC 9596; tstr, not the CoAP id)
        18 21 59 xxxx <DER>            33 x5chain = the signer chain without the IACA: one bstr, or an array of bstr (RFC 9360)
    a0                                 unprotected = {}; no kid (TSL §11.3: x5chain identifies the key)
    59 xxxx <payload bstr>             bstr .cbor {
      a5
        02 78 .. "https://<host>/v1/certify/credentials/token-status-list/<id>"   2 sub = the MSO status_list.uri
        04 1a <exp>                    4 exp = min(iat + 2·ttl, signer notAfter) (ISO2 12.3.6.3: shall be present)
        06 1a <iat>                    6 iat = signing time, whole seconds
        19 fffd a2 63 6c7374 59 xxxx <zlib bytes> 64 62697473 01   65533 {"lst": bstr, "bits": 1} (TSL §4.3)
        19 fffe 19 0e10                65534 ttl = certify.status.token-status-list.ttl in seconds (default 3600)
    58 40 <r||s>                       signature
```

- The HTTP body is these bytes, raw (TSL §8.2), with `Content-Type: application/statuslist+cwt`.
- Stored in `status_list_credential.vc_document` as described in 4.4.
- The protected header for ES256 and one certificate begins `a3 01 26 10 78 1a 61 70 70 6c …`. This is the same
  prefix as the draft's example, `a2 01 26 10 78 1a …`, with `x5chain` added.

### 4.2 Who signs

**Default, `signer: document-signer`.** The list is signed by the Document Signer whose IssuerAuth carries the mDLs
indexed in it, with the same certificate and the same `x5chain` (`CoseHeaderPolicy.mdocIssuerAuth()` chain inclusion,
`WITHOUT_ANCHOR`), but in the protected header. This is TSL §11.3's "same key … same x5chain value" model. It is the
only option Paradym accepts today, it is what Multipaz's reference issuer does, and it needs no new certificate.

**Option, `signer: dedicated`.** A certificate issued by the IACA for this purpose only (4.7), named by
`certify.status.token-status-list.mdoc.key-ref`. This is TSL §10/§11.3's delegated model, and EUDI's model of a
separate status-list provider. It passes Multipaz, isomdl and Credo verifiers configured with `status` certificates,
but not Paradym (section 2).

**What the issuer never does:** sign an mDoc list with a key that does not chain to a configured IACA when IACAs are
configured; carry the IACA in the list's `x5chain`; or add `status_list.certificate` to the MSO (D-M11-10). That last
one would pin a single signer for the MSO's life, and Credo ignores it anyway.

### 4.3 Lists bound to a signer

- **A list is created for one signer.** Its first token records the signer's pinned key reference and the SHA-256 of
  the leaf certificate (4.4).
- **Allocation.** For `mso_mdoc` with `token-format: cwt`, `allocate` takes the newest `AVAILABLE` list of type
  `TokenStatusListCwt` whose purpose matches and whose recorded leaf SHA-256 equals the leaf of the key that signs this
  mDL (the `SigningContext` resolved for the issuance, 4.6). If there is none, it creates one, signed by that key.
- **Rotation.** After a DSC rotation (x509-file versioned aliases, M-05), new mDLs go to new lists. Old lists are
  re-signed by their own pinned version (`x509-file:mdl-dsc@2026-11`) while its certificate is valid.
  - No mDL outlives its DSC: `validUntil <= DSC notAfter` (D7, G8).
  - A rotated DSC must stay in the keystore, as `pki dsc rotate` already keeps it (certify-cli Recipe 3), and must stay
    unrevoked unless it was compromised. Revoking it invalidates its mDLs anyway.
- **Retirement.** Once the pinned signer's certificate is past `notAfter`, the list is not re-signed. It is served as
  stored while its `exp` holds, then answered **410 Gone** without `Retry-After` (D-M11-7). The token's `exp` is never
  later than the signer's `notAfter`.
- **Dedicated mode.** Lists are bound to the configured `key-ref` itself, not a version, and are re-signed with its
  current version. Trust comes from the IACA, so moving a list to a new signer is safe there.

### 4.4 Storage (no migration, D-M11-4)

- `status_list_credential` rows of the new `credential_type` **`TokenStatusListCwt`** (the JWT lists keep
  `TokenStatusList`).
- `vc_document` holds a small JSON envelope. It is internal to Certify; the token is what is served:

```json
{"v":1,"signer":{"mode":"document-signer","keyRef":"x509-file:mdl-dsc@2026-11","x5tS256":"<base64url SHA-256 of the leaf DER>"},"token":"<base64url, unpadded, of the CWT bytes>"}
```

- `capacity_in_kb`, `credential_status`, `status_purpose` and the index table are used exactly as for JWT lists.
- No schema change, `ddl-auto` stays `none`; the P3-09 decision ("reuse, no migration") holds.

### 4.5 Endpoint

`GET /credentials/token-status-list/{id}`, unchanged path:

| Row type | Answer |
| --- | --- |
| `TokenStatusList` (JWT) | exactly as today: `200`, `Content-Type: application/statuslist+jwt`, the JWT, for any `Accept`; `503` with `Retry-After` when unusable and not renewable |
| `TokenStatusListCwt` | `200`, `Content-Type: application/statuslist+cwt`, the raw CWT, for **any** `Accept` (RFC 9110 §12.5.1 lets a server "disregard the header field"; D-M11-2); `503` with `Retry-After` as for JWT; **`410`** once retired |
| none | `404` |

No new `Cache-Control`, since TSL §8.2 makes `exp`/`ttl` authoritative. HEAD keeps working through Spring's GET
mapping. Public exposure through nginx is unchanged: `/v1/certify/credentials/` is already open to the public host.

### 4.6 Configuration (typed, rule 9)

`TokenStatusListProperties` (`certify.status.token-status-list.*`) gains a nested record `mdoc`:

| Property | Default | Meaning |
| --- | --- | --- |
| `certify.status.token-status-list.mdoc.token-format` | `cwt` | `cwt`: `mso_mdoc` entries go to CWT lists (ISO2 12.3.6.3). `jwt`: today's behaviour (shared JWT lists signed by `key-ref`); a WARN at startup names ISO2 12.3.6.3 |
| `certify.status.token-status-list.mdoc.signer` | `document-signer` | `document-signer` or `dedicated` (`dedicated` refused at startup until M-11h) |
| `certify.status.token-status-list.mdoc.key-ref` | none | `provider:alias` of the dedicated signer; required with `dedicated`, refused otherwise |

`key-ref`, `alg`, `x5c`, `size-bits`, `ttl`, `renew-wait` and `renew-backoff` keep their meaning. `key-ref` signs JWT
lists only. `size-bits` and `ttl`, and the renewal settings, apply to CWT lists too.

### 4.7 Checks before a list is signed (`StatusListSignerPolicy`)

Every check fails with `IllegalStateException("<RULE>: …")`. On renewal that becomes the existing back-off and 503
path; at issuance it becomes `FormatException("status_list_unavailable")`.

- **Always:**
  - `STATUS_SIGNER_NO_CHAIN`: the signing key has no certificate.
  - `STATUS_SIGNER_SELF_SIGNED`: the leaf is self-signed.
  - `CertificateChainPolicy.check(chain, now)`, which yields `STATUS_SIGNER_EXPIRED`, `STATUS_SIGNER_NOT_YET_VALID` and
    `CHAIN_LINK_INVALID`.
  - `STATUS_SIGNER_CARRIES_ANCHOR`: the `x5chain` to be emitted contains a self-signed certificate.
  - "Self-signed" means subject and issuer names are equal, the test `CertificateChain.withoutAnchor()` itself uses, so
    a self-issued key-rollover intermediate counts as self-signed. `CoseEnvelope` (`M-11a`) already refuses an empty
    chain (`STATUS_SIGNER_NO_CHAIN`), a self-signed leaf (`STATUS_SIGNER_SELF_SIGNED`) and a self-signed certificate
    further up the emitted chain (`STATUS_SIGNER_CARRIES_ANCHOR`) before a token is signed.
- **Once `TrustAnchorRegistry` holds an `mdoc-iaca` anchor** (the D16 enforcement switch):
  - `STATUS_SIGNER_NO_TRUSTED_IACA`: the leaf, or the last certificate of the chain, was not issued by a configured
    IACA (AKI = SKI, else issuer name, plus signature).
  - `STATUS_SIGNER_REVOKED`: the anchor's CRL lists the leaf.
  - `CRL_STALE`: past `nextUpdate` plus `certify.pki.stale-crl-grace`, as for mDoc signing.
  - `STATUS_SIGNER_PURPOSE`: the leaf's EKU contains neither `1.0.18013.5.1.2` (`document-signer` mode) nor
    `1.3.6.1.5.5.7.3.45` (`dedicated` mode), or KU lacks `digitalSignature`.
- **Without anchors:** none of the second group runs; an INFO line at startup, as `MdocAutoConfiguration` does for
  mDoc.

### 4.8 Dedicated signer profile (only with D-M11-1 (b) or (c); M-11g, M-11h)

Built by `certify-pki` as `IsoMdocProfiles.statusSigner(...)` and checked by `AnnexBValidator.validateStatusSigner`.
The figures are D-M11-9's recommendation.

| Field | Value | Basis |
| --- | --- | --- |
| issuer | the IACA subject, DER unchanged | ISO2 12.3.6.2 (trust point = IACA) |
| subject | `C` (and `ST` if the IACA has one) copied from the IACA; `CN` required (e.g. `Lorem Ipsum Demo Status List Signer`); `O` optional | mirrors the DS (Annex B Table B.3) |
| serial | `Serials.random()`: positive, at least 63 random bits, at most 20 octets | RFC 5280 §4.1.2.2 |
| validity | default 365 days, at most 457 (the DS cap), clamped to the IACA | D-M11-9 |
| key | EC P-256 (ES256) default; P-384/P-521 allowed; never the IACA key | HAIP §7; isomdl supports P-256/P-384 only, so P-256 |
| keyUsage | `digitalSignature`, critical, nothing else | Credo `requiredKeyUsages` |
| extendedKeyUsage | `1.3.6.1.5.5.7.3.45` only, **critical**; never together with `1.0.18013.5.1.2` | TSL §10, IANA; RFC 5280 §4.2.1.12 |
| authorityKeyIdentifier / subjectKeyIdentifier | AKI = IACA SKI; SKI present | RFC 5280 §4.2.1.1-2 |
| issuerAltName | copied from the IACA | as the DS |
| cRLDistributionPoints | the IACA's | isomdl checks the signer chain against the CRL |
| basicConstraints | absent | end entity, as the DS |
| signature | the IACA's ECDSA algorithm | Annex B |

`x509-file` derives the purpose `status-list-signer` from EKU `.45`. Such a key is checked at startup against its
IACA, signs no credential, and is not published in the JWKS or DID document; verifiers get it from `x5chain`.

### 4.9 Independent verification (non-negotiable 2)

| Layer | Library | Where |
| --- | --- | --- |
| merge gate, JVM | Multipaz `org.multipaz.revocation.CompressedStatusList.fromCwt(cwt, iaca, mapOf(SUB to uri), at)` (present at tag `0.102.0`, the existing pin) for trust via the IACA, `typ`, `sub` and `exp`; Authlete `com.authlete:cbor` 1.19 `COSEVerifier` as the second signature oracle; plus structural checks and **Credo's equal-chain rule** emulated | `certify-testkit-mdoc` `IndependentStatusListVerifier` (M-11b), run by `certify-conformance-mdoc` on every sample whose MSO carries `status_list` |
| CI second opinion | `pycose` 1.1.0, `cbor2` 5.9.0, `cryptography` 50.0.2 (already pinned in `requirements-verify.txt`) | `docs/design/tools/verify_status_list.py` (M-11f) |
| Paradym's own code (D-M11-8) | `@owf/mdoc` and `@owf/token-status-list` at the versions Paradym locks, called as Credo calls them (`trustedCertificates: [{issuance: [<top of x5chain>]}]`) | `docs/design/tools/owf-probe/` with an exact lockfile (M-11f) |
| live | `smoke.py --mdl`, which fetches with `Accept: application/statuslist+cwt` | M-11f |

### 4.10 Compatibility

- **JWT lists**: rows, bytes, headers, signer, renewal and batch updates exactly as today. SD-JWT VC entries keep going
  to JWT lists.
- **mDLs issued before the change** point to JWT lists and keep doing so (D-M11-6).
- **Draft-13 and compat-core surfaces** go through `DefaultIssuanceService`, so they get the same CWT lists (D1
  precedent: "Both surfaces. Spec correctness wins"). The legacy `utils.MDocProcessor` path (compat-core off) attaches
  no Token Status List and is not touched.
- **Goldens and vectors**: none records a Token Status List for `mso_mdoc` (`StatusListPostgresTest` covers SD-JWT).
  The mDoc IssuerAuth and claim-169 CWT header bytes must not move (M-11a). Any golden that changes is a defect, not a
  re-record.
- **Classpath**: no new production dependency; Multipaz stays test-only.

### 4.11 Non-goals

The ISO2 identifier list (12.3.6.4), status-list aggregation (TSL §9), historical resolution (TSL §8.4), CORS on the
list endpoint (TSL §8.1 SHOULD; native wallets do not need it), `ETag`/`Last-Modified`, multi-bit statuses for mDoc,
per-tenant lists, signed VICAL, a JWT form of mDoc lists, and changes to how SD-JWT VC lists are signed (HAIP §6.1 for
SD-JWT is a separate gap).

## 5. Work packages

Every package below shares these:

**Invariants.**

- **I1**: `goldens/legacy-develop`, `goldens/legacy-0.14.0` and `goldens/oid4vci-1.0` replay byte for byte
  (`IssuanceGoldenTest`, `IssuanceGoldenCoreTest`, `D13GoldenReplayTest`).
- **I2**: the mDoc IssuerAuth (`CoseHeaderPolicy.mdocIssuerAuth()`: protected `{1:-7}`, unprotected `{33: x5chain}`,
  untagged) and the claim-169 CWT (`CoseHeaderPolicy.cwt()`: tag 61 around tag 18, protected `[alg, kid]`) produce the
  same header bytes as before.
- **I3**: `docs/design/tools/check-runtime-classpath.sh` passes with `certify-service/runtime-classpath.txt` unchanged.
- **I4**: JWT lists (`credential_type = TokenStatusList`) are created, served, renewed and updated as before, with
  `certify.status.token-status-list.key-ref`/`alg`/`x5c`. No Flyway migration; `ddl-auto` stays `none`.
- **I5**: the M-01 gate holds every existing sample to its existing `.gaps`.
- **I6**: `*ArchitectureTest` green; frozen stores only shrink; `certify-signing` and `certify-pki` import no Spring.
- **I7**: `docs/design/tools/check-bc169-linkage.sh` green.

**Brief for the coder.**

- Read this document, `20-mdl-issuer.md` (D1, D7, D16, M-01, M-05, M-06) and the classes named in the package.
- Stay inside the files named; list anything else under "Outside scope" in the commit message.
- Run long commands in the foreground (never in the background), run the full test suite, and commit before reporting.
- Local build:

  ```bash
  export JAVA_HOME=$(/usr/libexec/java_home -v 21)
  M="mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -Dmaven.gitcommitid.skip=true"
  $M verify      # from the repo root; never `install` from a worktree (the ~/.m2 is shared)
  ```

- Each package ends with its acceptance checklist ticked, with the test or command that proves each item.

### M-11a COSE `typ` and protected `x5chain` (certify-signing)

Branch `wp/m-11a-cose-status-headers`. Depends on nothing. About 250 lines.

**Files.**

- `certify-signing/src/main/java/io/mosip/certify/signing/CoseHeaderPolicy.java`
- `CoseEnvelope.java`
- `CwtEnvelope.java`
- New test `certify-signing/src/test/java/io/mosip/certify/signing/CoseStatusListHeaderTest.java`

**Spec.**

1. `CoseHeaderPolicy` gains two components appended after `kidInProtected`: `String typ` (COSE label 16, RFC 9596;
   `null` = absent) and `boolean x5chainInProtected`.
   - Keep the 3-argument and 4-argument constructors; they pass `null` and `false`.
   - The compact constructor refuses, with `IllegalArgumentException`:
     - `x5chainInProtected` with `x5chain == NONE`;
     - a `typ` that does not match `^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$`.
2. New factory `CoseHeaderPolicy.statusListCwt()` returns
   `new CoseHeaderPolicy(WITHOUT_ANCHOR, null, true, false, "application/statuslist+cwt", true)`.
   - Constant `CoseEnvelope.LABEL_TYP = 16`.
   - The Javadoc cites TSL §5.2 and ISO2 12.3.6.3.
3. `CoseEnvelope.sign1Locally`:
   - **Only when `policy.typ() != null || policy.x5chainInProtected()`**, build the protected header with
     `CBORObject.NewOrderedMap()` (cbor 4.5.6 has it), inserting 1 (`alg`), 4 (`kid`, only if `kidInProtected`), 16
     (`typ` as a text string), then 33 (`x5chain`: a `bstr` for one certificate, an array of `bstr` for more, the same
     selection as today). Put nothing of that chain in the unprotected header.
   - Otherwise keep today's code path **unchanged**, so I2 holds by construction.
4. New `CwtEnvelope.signOrdered(LinkedHashMap<Integer, CBORObject> claims, CoseHeaderPolicy policy, SigningKey key,
   Signer signer)`:
   - The payload is a `NewOrderedMap` in the iteration order of `claims`.
   - The result is `CoseEnvelope.sign1(...)`; tag 18 comes from `policy.tagged()`, and it is **never** wrapped in tag 61.
   - The existing `sign(...)` is untouched.

**Acceptance checklist.**

- [ ] `statusListCwt()` with ES256 and a one-certificate chain gives:
  - first byte `0xd2`; second byte `0x84`;
  - protected bytes starting `a3 01 26 10 78 1a` followed by the 26 ASCII bytes of `application/statuslist+cwt`, then
    `18 21 59`;
  - unprotected exactly `a0`.
- [ ] A two-certificate chain gives `x5chain` as an array `82 59 … 59 …` in the protected header.
- [ ] `signOrdered` with claims `2, 4, 6, 65533, 65534` encodes the payload keys in that order (`02 … 04 … 06 … 19 fffd
  … 19 fffe`).
- [ ] The signature verifies with plain JCA (`SHA256withECDSA` over `Sig_structure`, r‖s converted to DER) and with
  Authlete `COSEVerifier`.
- [ ] I2: unit tests compare the protected and unprotected bytes of `mdocIssuerAuth()` and `cwt()` for a fixed key and
  payload with hex recorded **before** the change; the existing golden tests pass.
- [ ] I1-I7 hold.

**Negative tests.**

- `x5chainInProtected` with `NONE` is refused, and so is a `typ` without a protected chain: draft-21 §5.2 pairs the
  protected `typ` with the protected `x5chain`, and the encoder would otherwise put 33 in the protected header against
  the caller's instruction.
- `typ` values `"statuslist+cwt"` (no type) and `"a b/c"` are refused.
- A key with no chain, and a chain that is a lone self-signed certificate under `WITHOUT_ANCHOR`, are **refused when
  the token is signed** (`SigningException`, `STATUS_SIGNER_NO_CHAIN` / `STATUS_SIGNER_SELF_SIGNED`). The legacy
  `withoutAnchor()` keeps a lone self-signed certificate, and `mdocIssuerAuth()` keeps forwarding it — a test proves
  that is unchanged (I2) — so the status-list header path refuses it instead of emitting a token that carries its own
  trust anchor; `[DSC, IACA]` emits the DSC alone and `[DSC, intermediate, IACA]` emits `[DSC, intermediate]`.
- A `FULL` chain over `[DSC, intermediate, IACA]` is refused with `STATUS_SIGNER_CARRIES_ANCHOR` (a self-signed
  certificate above the leaf); a `LEAF` policy inspects and emits only the end entity, so `[DSC, IACA]` signs with the DSC;
  the refusals run before a provider's native `signCose` is asked, so a provider that builds the envelope cannot skip them.
- `signOrdered` refuses claim keys that break RFC 8949 §4.2.1's bytewise lexicographic order of the encoded keys,
  refuses an untagged status-list policy, and its output never starts with `d8 3d` (tag 61).

**Non-goals:** any change to how mDoc IssuerAuth or claim-169 are built.

### M-11b Independent status-list verifier (certify-testkit-mdoc, certify-conformance-mdoc)

Branch `wp/m-11b-status-verifier`. Depends on nothing (in parallel with M-11a). About 600 lines.

**Files.**

- New `certify-testkit-mdoc/src/main/java/io/mosip/certify/testkit/mdoc/IndependentStatusListVerifier.java`
- `ProblemCodeRegistryTest` and `MdocSamples` (the sample reader learns two sidecars)
- `certify-conformance-mdoc/.../MdocSampleConformanceTest.java`
- New test `IndependentStatusListVerifierTest.java`

The test builds its fixtures **with Multipaz itself**, not with Certify code: `X509Cert.Builder` (or `MdocUtil`) for an
IACA and a DSC, and `CompressedStatusList.serializeAsCwt(AsymmetricKey.X509CertifiedExplicit(...), uri)` for a valid
token.

**API.**

```java
public static VerificationReport verify(byte[] body, String contentType, String uri, long idx,
        List<X509Certificate> issuerAuthX5chain, X509Certificate iaca /* nullable */, Instant at, StatusListOptions options)
public record StatusListOptions(boolean strict, int expectedStatus /* 0, or 1 for a revoked sample */,
                                boolean requireIssuanceChain /* true */) {}
public static VerificationReport.Check mso(String malformed /* null when absent or well formed */)
```

`expectedStatus` is 0 or 1 only: ISO2 12.3.6.1 allows an mdoc no status besides revoked, and `bits` is 1 (12.3.6.5).

`verify` runs `TOKEN_CHECKS` over the token; `mso` runs `statusList.mso` over the sample's own
`status.status_list` reference (present, absent, or present-but-malformed). `CHECKS` is the two together, in report
order. The conformance run puts the credential's checks and these in **one** report, matched against the sample's one
`.gaps` sidecar (review round 1).

Call Multipaz's `suspend` functions through the existing `IndependentMdocVerifier.await` pattern
(`IndependentMdocVerifier.java:1524`).

**Merge gate.** `statusList.chain` runs Multipaz's own `CompressedStatusList.fromCwt(cwt, iaca, {SUB: uri}, at)` —
the reader `CachingRevocationChecker` uses, and the gate §4.9 names — not a reimplementation of its rules. Kotlin
mangles the method name because `maxValidity: Duration` is a value class (`fromCwt-myKFqkg`), so the synthetic
`$default` bridge is called through one reflective adapter that passes mask 16 (keeping Multipaz's 365-day
`maxValidity`) and fails loudly if a Multipaz upgrade changes the signature. Its refusal is `statusList.chain:untrusted`
per the table, but only when no more specific check (envelope, `typ`, signature, claims, list) already failed, so one
mutation still fires one code; the direct `trustedRootCertificateChainValidator` call stays as the trust decision on its
own, so a `fromCwt` refusal caused by a claim does not also fail the chain and a genuine chain failure is reported even
when a claim is wrong. This is what refuses an `exp` more than 365 days after `at` on a DSC valid for the Annex B 457
days.

**Checks and problem codes** (registered beside `IndependentMdocVerifier.PROBLEM_CODES`; a failed check carries
**every** problem it found):

| Check | Codes | Clause |
| --- | --- | --- |
| `statusList.mso` | `malformed` (the MSO's `status.status_list` is present but not `{uri: tstr, idx: uint}`: typed `uri`, negative/text `idx`, `status_list` not a map; a `status` that is not a map. A `status` map without `status_list` — an `identifier_list` only, or RFU keys — is valid and absent) | ISO2 12.3.6 |
| `statusList.http` | `contentType` (not `application/statuslist+cwt`, parameters ignored) | TSL §8.2 |
| `statusList.envelope` | `notTagged18` (untagged, a tag other than 17/18/61, or any tag stack other than exactly `[18]` — `18(18(…))` and the self-describe `55799(18(…))` included), `cwtTag61`, `mac0`, `detachedPayload`, `duplicateKey` (a map of the protected header, the unprotected header or the claims, or a map nested in them such as `status_list`, carries a key twice; read on the wire with Authlete's decoder, which keeps every pair, before any header or claim is read; keys compared recursively as RFC 8949 §5.6.1 data items — integers by value at any width, strings by content, arrays element-wise, maps as unordered pair sets, tags by number and content, simple values by value, floats by numeric value at any width with `-0.0` = `0.0` and every NaN one key (stricter than §5.6.1's significand rule) — so `02` and `18 02`, or `{1: 1, 2: 2}` and `{2: 2, 1: 1}`, are one key; every other token check is then `notRun`, because a decoder keeps one value or the other — Multipaz the last. A part Authlete cannot decode though Multipaz did, such as a text string that is not UTF-8, makes the token `notTagged18`) | TSL §5.2, RFC 9052 §4.2; RFC 8949 §3.4.6; `@owf/cose` 0.6.0; RFC 9052 §3 ("if a label appears multiple times, the message MUST be rejected as malformed"), RFC 8392 §7.2 steps 1 and 7, RFC 8949 §5.3.1 |
| `statusList.typ` | `missing`, `unprotected`, `notText`, `wrong` | TSL §5.2 |
| `statusList.x5chain` | `missing`, `unprotectedOnly`, `carriesAnchor` (any self-signed certificate), `serialNumber` (≤ 0 or > 20 octets) | ISO2 12.3.6.3; HAIP §6.1 analogue; RFC 5280 §4.1.2.2 |
| `statusList.signature` | `invalid:multipaz`, `invalid:authlete` | TSL §5.2 rule 2 |
| `statusList.chain` | `untrusted` (Multipaz `fromCwt` against `iaca` refuses, reported when the token's state is not defective in a way `fromCwt` itself refuses on — its rule set, in its own order, read from `ValidateCwtKt.validateCwt-efNRYWU`, `CompressedStatusList$Companion.fromCborMap`/`fromStatusListClaim` and the `CompressedStatusList` constructor: the body decodes, at most one tag 18 (an untagged COSE_Sign1 is accepted), the payload is a map; then `exp` (an integer, refused when before `at`, `exp == at` accepted) and **maxValidity** (`exp` more than 365 days after `at`), both decided before anything below; without `exp`, `iat` present and at most 5 s ahead; then protected `typ`, the SUB check, the signature; `ttl` an integer only when `exp` is absent; and the presence/type of `status_list`, `lst` (bstr, never inflated) and `bits` (a `Uint` narrowed to an `int` by `l2i`, then 1, 2, 4 or 8 — so `4294967297` is accepted as 1). `at` is compared at the millisecond precision `fromCwt` receives. maxValidity, which no check names, is suppressed only when `fromCwt` never reaches it — a parse failure, a duplicate key, a detached payload, a tag stack other than none or `[18]`, a non-integer `exp` — so `typ`, `sub`, the signature, `bits`, `lst`, `ttlInvalid`, `expAfterSigner`, `iatAfterExp`, `idxOutOfRange` and `statusMismatch` next to it cannot hide it, and the message names it), `noAnchorSupplied` | ISO2 12.3.6.2 |
| `statusList.issuanceChain` | `differs` (the token `x5chain` is not certificate-for-certificate equal to `issuerAuthX5chain`) | Credo `mdocUtil.ts:76-115` |
| `statusList.claims` | `subMismatch`, `iatMissing`, `iatFuture` (> `at` + 5 s, Multipaz `validateCwt`'s own clock allowance), `iatAfterExp`, `expMissing`, `expired` (`at` ≥ `exp`, `at` at full precision: RFC 8392 §3.1.4 takes RFC 7519 §4.1.4, "the current date/time MUST be before the expiration date/time"; Multipaz 0.102.0 refuses only `exp < at`, so exactly at `exp` only this check refuses), `expAfterSigner` (exp > leaf `notAfter`), `ttlInvalid` | TSL §5.2, §8.3 4a/4c; ISO2 12.3.6.3; RFC 8392 §3.1.4, RFC 7519 §4.1.4 |
| `statusList.list` | `missing` (no `status_list` claim, or not a map), `bitsNotOne`, `lstNotZlib` (including raw DEFLATE without the zlib wrapper), `idxOutOfRange`, `statusMismatch:<n>` (read with Multipaz's `StatusList.get`) | ISO2 12.3.6.5; TSL §4.3, §4.1, §8.3 step 6 |
| `statusList.signerPurpose` | `ekuMissing`, `kuMissing`: only when the token leaf's public key differs from the IssuerAuth leaf's | Credo `assertStatusListSignerKeyPurpose.ts:14-25` with `requireStatusSigningKeyPurpose` |

**Samples.**

- A producer writes `<sample>.statuslist.cwt` (the response body as received) and `<sample>.statuslist.ct` (the
  `Content-Type`) beside `<sample>.mdoc`.
- `MdocSamples` reads three outcomes of the MSO's `status.status_list`: absent (including a `status` map without
  `status_list`, e.g. `identifier_list` only, which 12.3.6 makes valid), `{uri: tstr, idx: uint}`, or
  present-but-malformed with the reason (an unreadable IssuerAuth or MSO answers absent, which is M-01's check).
- `MdocSampleConformanceTest`: the credential's checks and the status list's join one report, held to the sample's one
  `.gaps` sidecar exactly both ways like M-01 — an undeclared problem fails, a declared one no longer reported fails
  ("gap no longer present"). Of the status-list checks only `statusList.mso:malformed` may be declared; every other
  `statusList.*` line is refused when the sidecar is parsed, because M-11e's samples must pass those (a status list
  that fails any other check is a defect the sample must not ship). When the MSO carries a well-formed
  `status.status_list`, both sidecars are required and the list is verified with `iaca` = the sample's `.iaca.pem`
  (when present) and `issuerAuthX5chain` = the sample's IssuerAuth `x5chain`; a present-but-malformed reference fails as
  `statusList.mso:malformed` instead of being skipped.
- No producer writes these sidecars yet (M-11e does; its samples must pass with no `statusList.*` gap other than a
  declared `statusList.mso:malformed`).

**Review round 1 (2026-11-13).** Fixed here: `fromCwt` is actually run (the major above); the malformed-MSO skip
became `statusList.mso:malformed`; the gap set is one per sample across both reports; the whole tag stack is recorded
and only exactly `[18]` is accepted (`55799` refused, as `@owf/cose` 0.6.0's `Cwt.decodeCoseStructure` refuses
anything that is not the `Sign1`/`Mac0` tag itself; RFC 8949 §3.4.6 only permits, does not require, tolerance);
`iatFuture` aligned to Multipaz's 5 s; `iatAfterExp`, `statusList.list:missing` and `statusList.mso:malformed` added;
`expectedStatus` restricted to 0/1; the bit at `idx` read with Multipaz's `StatusList`.

**Review round 2 (2026-11-13, approved with minors).** Fixed here: the `fromCwt` refusal is suppressed only by the
codes `fromCwt` itself decides, so a maxValidity breach next to a `ttlInvalid`/`expAfterSigner`/`iatAfterExp`/
`idxOutOfRange`/`statusMismatch` is still `chain:untrusted`; only `statusList.mso:malformed` may be declared as a
`statusList.*` gap and any other line is refused when the sidecar is parsed; a broken or unrecognised `fromCwt` adapter
(the mangled Kotlin name, a changed Multipaz) is resolved lazily and reported as the non-declarable `error` code with
the descriptive message, never as `chain:untrusted`; a `status` map without `status_list` (IdentifierList-only) is
valid and absent, not malformed; Authlete is handed the wire bytes (it decodes tag 18, `61(18)` and `55799(18(…))`
itself) and falls back to the unwrapped array only for a tag stack whose envelope check already failed
(`18(18(…))`). Tests: `aMaxValidityRefusalIsNotHiddenByACodeFromCwtNeverChecks`,
`oneGapSetCoversBothReportsAndOnlyTheMalformedMsoGapIsDeclarable`,
`theFromCwtAdapterResolvesAgainstThePinnedMultipazJar`, `aBrokenFromCwtAdapterIsAnErrorNotAnUntrustedChain`,
`authleteVerifiesTheWireBytesOfAMultipazBuiltToken`, and the IdentifierList-only absent case. **Review round 3 (2026-11-13, approved with one minor and two nits).** Fixed here: the suppression is decided from
the token's state (tags, payload, `sub`/`exp`/`iat`/`ttl`/`status_list`/`bits`/`lst`) against the bytecode of
`validateCwt`/`fromCborMap`/`fromStatusListClaim`/the constructor, not from check names, because several codes also
cover shapes `fromCwt` accepts — an untagged COSE_Sign1, `bits` 2/4/8, a `iat` with `exp` present, a garbage `lst` bstr
and a `ttl` with `exp` present all used to suppress its maxValidity refusal and no longer do (a non-integer `ttl`
explains only in the exp-absent branch `fromCborMap` reads); the `untrusted` message now says "most likely
maxValidity" and names it only when `exp > at + 365 days`; the test seam is `volatile`. Probes are one test each
(`aBitsValueMultipazAcceptsDoesNotHideItsMaxValidityRefusal`, `anUntaggedCoseSign1DoesNotHideMultipazsMaxValidityRefusal`,
`aFutureIatNextToAnExpDoesNotHideMultipazsMaxValidityRefusal`, `aGarbageLstBstrDoesNotHideMultipazsMaxValidityRefusal`,
`aTextTtlExplainsMultipazsRefusal`, renamed in round 4).

**Review round 4 (2026-11-13, GPT-6.1 Sol two blockers, Opus one minor and nits; fixed on `wp/m-11b-r5`).**
(1) Duplicate map keys passed: a correctly signed payload with `sub` twice — a wrong uri first, the expected one second
— passed every check, because Multipaz's decoder keeps the last value and Authlete checks bytes only. RFC 8949 §5.3.1
makes such a map invalid, RFC 9052 §3 requires a repeated header label to be "rejected as malformed", and RFC 8392
§7.2 steps 1 and 7 reject a CWT that is not valid CBOR or whose claims are not a valid CBOR map; the verifier now reads
the wire again with Authlete's decoder (no tag processor, every pair kept) right after the COSE_Sign1 array is
recognised and before any header or claim is read, compares keys as RFC 8949 §5.6.1 data items (Authlete's preferred
re-encoding of each decoded key), and reports `statusList.envelope:duplicateKey` with every other token check `notRun`.
Without the walk, three of the signed mutations pass every check (claims `sub`, the `18 02` duplicate, `bits` 2 then 1)
and the header duplicates are misreported as signature failures. (2) `expired` fired only for `exp < at`; RFC 7519
§4.1.4 (through RFC 8392 §3.1.4 and TSL §5.2) makes the token invalid on and after `exp`, so it now fires for
`at ≥ exp`, `at` at full precision. Multipaz 0.102.0 shares the off-by-one (`exp.compareTo(now) >= 0` passes), so at
exactly `exp` `fromCwt` accepts and no chain code is added. (3) maxValidity is decided where `validateCwt` decides it,
right after `exp` and before typ, sub, the signature and the list, so a wrong `typ` or `sub` next to an `exp` 400 days
out is `{typ:[wrong], chain:[untrusted]}` / `{claims:[subMismatch], chain:[untrusted]}` and the chain message names
maxValidity as the reason. (4) `bits` is mirrored as Multipaz reads it — `Uint`, `l2i`, then 1/2/4/8 — so
`4294967297` is `bitsNotOne` here and accepted by `fromCwt`; the mirror's `exp`/`iat` comparisons use the millisecond
`at` `fromCwt` receives (a whole-second mirror charges `fromCwt`'s "expired" half a second after `exp` to the chain as
`untrusted`). A differential test, `theFromCwtMirrorAgreesWithFromCwtTokenByToken`, holds the mirror (package-private
`fromCwtRefusesOnAReportedDefect(body, uri, at)`) to `fromCwt` itself over 20 token shapes at three instants (`at`,
`at` + 500 ms, `at` + 100 ns).
(5) `aTextTtlExplainsMultipazsRefusal` became `aTextTtlNextToAnExpIsOnlyTtlInvalid` (no refusal happens with `exp`
present), and the exp-absent branch has its own tests (text `ttl`: `{claims:[expMissing, ttlInvalid]}`; future `iat`:
`{claims:[iatFuture, expMissing]}`; no chain code).

**Review round 5 (2026-11-13, Opus approved with one minor and three nits; GPT-6.1 Sol one major; fixed on
`wp/m-11b-r5`).** (1) Keys were compared as Authlete's re-encoded bytes, which RFC 8949 §5.6.1 does not do for maps
("the same set of pairs regardless of their order"): claim 999 = `{ {1: 1, 2: 2}: 1, {2: 2, 1: 1}: 2 }` passed every
check, Multipaz `fromCwt` included. Keys are now compared by `DuplicateKeys.dataItem`, a recursive generic-data-model
identity (integers by value, strings by content, arrays element-wise, maps as pair multisets, tags by number and
content, simple values by value, floats by numeric value across widths with `-0.0` = `0.0`). NaN: §5.6.1 makes NaNs
equivalent when their significands zero-extended to 64 bits are equal; every NaN is one key here, which is stricter,
because Authlete decodes every half-precision NaN to one canonical NaN (the significand is gone) and JavaScript's
SameValueZero `Map` and Java's `Double.equals` collapse NaN keys anyway. Without it the map-keyed and float-keyed tokens
pass every check. (2) The `fromCwt` mirror now has the "expired" `validateCwt` derives without `exp`: `exp` = `iat` +
maxValidity for an `iat` at or before now, refused when before now, which `expMissing` explains; without it an `iat` 366
days old with no `exp` was `{claims:[expMissing], chain:[untrusted]}`. The differential test gained `iat` 364/365/366
days ago. (3) The branch where Authlete cannot decode what Multipaz decoded is reached by a real token: a claim holding a
text string that is not UTF-8 (`61 ff`), which Multipaz decodes to U+FFFD and Authlete refuses, is `notTagged18` with
every other check `notRun`; ignoring the branch lets it pass. (4) The `expired` message says "exactly at exp this check
alone refuses" only when Multipaz, handed `at` in milliseconds, accepts `exp`.

**Open (unchanged):** an algorithm allow-list (isomdl accepts only ES256/ES384) —
owner decision later.

**Acceptance checklist.**

- [ ] A Multipaz-built token (its `buildCwt`: protected `typ` and `x5chain` without root, tag 18) passes every check
  against its IACA.
- [ ] Each code in the table is triggered by a dedicated mutation test, and no other code fires. Mutations are made by
  re-encoding the token with Authlete or PeterO CBOR and re-signing where the mutation needs it.
- [ ] `ProblemCodeRegistryTest` lists the new codes (Python's table follows in M-11f).
- [ ] I1-I7 hold; `certify-service` still does not depend on `certify-testkit-mdoc` (I3).

**Negative tests.** The mutation tests above, plus:

- a token signed by a key whose certificate chains to a different IACA (`statusList.chain:untrusted`);
- a token with the right signer but `x5chain` only in the unprotected header (`statusList.x5chain:unprotectedOnly`);
- a JWT body with `Content-Type` `application/statuslist+jwt` (`statusList.http:contentType`, and the envelope check
  reports that it is not CBOR);
- a DSC valid for the Annex B 457 days with `exp` 400 days out (`statusList.chain:untrusted`: `fromCwt`'s
  `maxValidity`);
- `18(18(…))` and `55799(18(…))` (`statusList.envelope:notTagged18`);
- every malformed `status.status_list` shape (`statusList.mso:malformed`);
- a correctly signed token whose claims (`sub`), nested `status_list` (`bits`), protected header (`typ`) or unprotected
  header (`kid`) carries a key twice, with the conflicting values in both orders, and a key repeated in a
  non-preferred encoding, a map key repeated with its pairs in another order, float keys of one value in two widths,
  `0.0`/`-0.0`, two NaNs and array keys of other integer widths (`statusList.envelope:duplicateKey`, every other token
  check `notRun`), while an integer, its tagged form, a bignum, a float and a simple value of one number stay distinct;
- a claim holding a text string that is not UTF-8 (`statusList.envelope:notTagged18`: Multipaz reads U+FFFD, Authlete
  refuses);
- a token evaluated exactly at its `exp`, and a nanosecond after it (`statusList.claims:expired`, `fromCwt` accepting).

### M-11c CWT codec, signer pinning, signer policy (certify-service, certify-issuance)

Branch `wp/m-11c-status-cwt-codec`. Depends on M-11a. About 450 lines.

**Files.**

- New `certify-service/src/main/java/io/mosip/certify/status/TokenStatusListCwt.java`
- New `StatusListSigners.java`
- New `StatusListSignerPolicy.java`
- Tests `TokenStatusListCwtTest`, `StatusListSignersTest`, `StatusListSignerPolicyTest`
- `TokenStatusListService` only to make `encode`/`decode`/`set`/`get` reusable by the codec; no behaviour change.

**Spec.**

1. `TokenStatusListCwt.encode(String sub, Instant iat, Instant exp, Duration ttl, byte[] bits, SigningContext signing)`
   returns `byte[]`.
   - The claims are a `LinkedHashMap` with: 2 → `sub` (text); 4 → `exp.getEpochSecond()`; 6 →
     `iat.getEpochSecond()`; 65533 → an ordered map `{"lst": zlib(bits), "bits": 1}` (raw bytes, `Deflater`
     `BEST_COMPRESSION` as `TokenStatusListService.encode` uses before base64url); 65534 → `ttl.getSeconds()`.
   - Signed with `CwtEnvelope.signOrdered(claims, CoseHeaderPolicy.statusListCwt(), signing.key(), signing.signer())`.
   - `iat` and `exp` are whole seconds, with `exp > iat`; otherwise `IllegalArgumentException`.
2. `TokenStatusListCwt.decode(byte[])` returns
   `record Decoded(String sub, Instant iat, Instant exp, Long ttl, int bits, byte[] lst, List<X509Certificate> x5chain)`,
   without verifying the signature.
   - Refuses (`IllegalStateException`) anything that is not tag 18 around a 4-array, has no protected
     `16 == "application/statuslist+cwt"` or no protected 33, lacks 2, 6, 4 or 65533, or has `bits` other than 1.
3. `StatusListSigners.pin(SigningContext)` returns `record Pinned(KeyRef keyRef, String x5tS256)`.
   - `x5tS256` is the base64url SHA-256 of the leaf DER.
   - `keyRef`: if `signing.key().descriptor().kid()` equals the configured alias or starts with `alias + "@"` (the JCA
     family: x509-file, jca), it is `KeyRef.parse(provider + ":" + kid)`; otherwise it is the configured ref
     (keymanager).
   - It then resolves the pinned ref through `KeyProviderRegistry` and checks that the leaf SHA-256 is unchanged; if
     not, it keeps the configured ref and logs DEBUG.
4. `StatusListSigners.resolve(Pinned)` returns the `SigningContext` for re-signing.
   - Resolve `keyRef`; if the leaf SHA-256 no longer equals `x5tS256` (keymanager rotated under the same ref), throw
     `IllegalStateException("STATUS_SIGNER_GONE: …")`.
   - If the leaf is past `notAfter`, throw `StatusListRetiredException` (new; extends `IllegalStateException`).
5. `StatusListSignerPolicy.check(SigningContext signing, Instant now, Mode mode)` enforces the rules of 4.7, using the
   `TrustAnchorRegistry` bean (`TrustAnchorRegistry.EMPTY` when absent) and `AnnexBValidator.CLOCK_SKEW`.
   - `Mode` is `DOCUMENT_SIGNER` or `DEDICATED`.
   - Each rule is a distinct message prefix.
   - `StatusListSignerPolicy` must still run before every `signOrdered`: the envelope refuses only an empty chain, a
     self-signed leaf, or an emitted chain that carries a self-signed certificate (`M-11a`), and checks no EKU,
     validity, revocation or IACA.
   - A `SigningException` from `M-11a`'s envelope whose message starts with `STATUS_SIGNER_` is mapped like the
     policy's `IllegalStateException`: renewal back-off and `503`, and at issuance `status_list_unavailable`.

**Acceptance checklist.**

- [ ] `zlib([0xb9, 0xa3])` equals `78dadbb918000217015d` (TSL §4.3 example).
- [ ] A token from `encode` is accepted by `IndependentStatusListVerifier` (M-11b, test scope) against an x509-file
  dev-mode IACA and DSC, with `issuerAuthX5chain = [DSC]`.
- [ ] The payload contains `19fffd a2 63 6c7374 … 64 62697473 01` (RFC 8949 §4.2.1 order; `signOrdered` checks only
  top-level keys, so this nested order is the codec's job).
- [ ] `decode(encode(...))` round-trips every claim.
- [ ] `pin` gives `x509-file:mdl-dsc@<version>` for a versioned x509-file key and `keymanager:APP/REF` for keymanager.
- [ ] Each policy rule has a test that fails with exactly its prefix; with no anchors only the "always" group runs.
- [ ] I1-I7 hold.

**Negative tests.**

- `decode` refuses a tag-61 token, an untagged token, `typ` in the unprotected header, `x5chain` unprotected only,
  missing `exp`, and `bits` = 2.
- `resolve` refuses a rotated keymanager key (`STATUS_SIGNER_GONE`) and an expired DSC (retired).
- The policy refuses:
  - a keymanager-signed DSC once an IACA is configured (`STATUS_SIGNER_NO_TRUSTED_IACA`);
  - a DSC that the CRL revokes;
  - a stale CRL;
  - a DSC-mode signer without the mDL EKU;
  - a dedicated-mode signer without EKU `.45`.

### M-11d CWT lists in the service (certify-service)

Branch `wp/m-11d-status-cwt-lists`. Depends on M-11c. About 650 lines.

**Files.**

- `status/TokenStatusListService.java`
- `TokenStatusListController.java`
- `TokenStatusListProperties.java`
- `TokenStatusListUnavailableException.java`, if needed
- `services/StatusListUpdateBatchJob.java` (route the new type, `:138`)
- `repository/StatusListCredentialRepository.java` (one derived query)
- Tests `TokenStatusListCwtServiceTest`, `TokenStatusListControllerCwtTest`; extend `TokenStatusListFreshnessTest`;
  `StatusListPostgresTest.tokenStatusListCwtForMdoc`

**Spec.**

1. Constants: `TYPE_CWT = "TokenStatusListCwt"`, `MEDIA_TYPE_CWT = "application/statuslist+cwt"`.
2. Properties: add `@DefaultValue Mdoc mdoc` with `record Mdoc(@DefaultValue("cwt") String tokenFormat,
   @DefaultValue("document-signer") String signer, String keyRef)`.
   - The compact constructor refuses unknown values.
   - `dedicated` is refused with "available from M-11h" in this package.
   - `key-ref` without `dedicated` is refused.
   - With `token-format: jwt` the service logs one WARN at startup citing ISO/IEC 18013-5 second edition 12.3.6.3.
3. `allocateCwt(String purpose, SigningContext signing)` returns an `Entry`, under `@Transactional`.
   - `pinned = StatusListSigners.pin(signing)`, then `StatusListSignerPolicy.check(signing, now, DOCUMENT_SIGNER)`.
   - Candidates are `findByCredentialTypeAndStatusPurposeAndCredentialStatusOrderByCreatedDtimesDesc(TYPE_CWT,
     purpose, AVAILABLE)` (a new derived query returning a `List`), filtered by the envelope's `signer.x5tS256 ==
     pinned.x5tS256`.
   - Cache list id → `x5tS256` in a `ConcurrentHashMap`; the signer of a list never changes.
   - The first candidate gets `indexProvider.acquireIndex`; when full, mark it `FULL` and create the next one. With no
     candidate, `createCwt(purpose, signing, pinned)`.
4. `createCwt` stores the 4.4 envelope with a token from `TokenStatusListCwt.encode(uri(id), now, min(now + 2·ttl, leaf
   notAfter), ttl, zero bits, signing)`.
5. Serving: `Optional<Served> served(String listId)`, with `record Served(String mediaType, byte[] body)`. For `TYPE`
   rows it returns what `jwt(listId)` returns today; keep `jwt()` for existing callers and tests. For `TYPE_CWT` rows:
   - The **same freshness state machine** (`FRESH` / `RENEW` / `UNUSABLE`, `renew-wait`, `renew-backoff`,
     compare-and-set through `replaceDocument` on the stored envelope), using `TokenStatusListCwt.decode` for `sub`
     and `exp`.
   - Re-signing goes through `StatusListSigners.resolve(envelope.signer)`, then the policy, then `encode` with the same
     bits and a new `iat`/`exp`.
   - `StatusListRetiredException`: no re-sign attempt. Serve as stored while `exp > now`; afterwards throw
     `TokenStatusListGoneException` (new).
6. `update(list, statuses)` (batch job): for `TYPE_CWT` it re-signs with the list's pinned signer. The batch job routes
   `TYPE_CWT` rows the same way as `TYPE` rows.
7. Controller:
   - `TYPE` rows keep the current code path verbatim (`ResponseEntity<String>`, header `application/statuslist+jwt`).
   - `TYPE_CWT` rows answer `ResponseEntity<byte[]>` with `Content-Type: application/statuslist+cwt`.
   - `TokenStatusListGoneException` → `410` with no body. Unusable → `503` + `Retry-After`, as today.
   - Declare the mapping without a restrictive `produces` (G30 lesson) and set `Content-Type` in the response, so any
     `Accept` (`application/statuslist+jwt`, `application/json`, `text/html`, `*/*`, none) gets the list's own format.

**Acceptance checklist.**

- [ ] A JWT row: body, `Content-Type` and status identical before and after, for the five `Accept` values above. Pin
  them in a test recorded **before** the change.
- [ ] A CWT row: `200`, `Content-Type: application/statuslist+cwt`, body accepted by `IndependentStatusListVerifier`
  for all five `Accept` values; HEAD answers 200 with the same headers.
- [ ] Freshness: a CWT list signed in the past (`Clock` injected) is re-signed when served with the same bits, with a
  new `iat`, an `exp` capped at the signer `notAfter`, and the same signer leaf.
- [ ] A batch update sets the bit and re-signs with the pinned version even after a newer DSC version was added to the
  provider (rotation).
- [ ] A list whose DSC expired: served as stored until `exp`, then `410`, with no re-sign attempt logged.
- [ ] `StatusListPostgresTest.tokenStatusListCwtForMdoc` (Testcontainers) creates, allocates, revokes and re-serves
  on PostgreSQL.
- [ ] I1-I7 hold, I4 especially: `StatusListPostgresTest.tokenStatusListForSdJwt` unchanged and green.

**Negative tests.**

- A stored envelope whose token was tampered with (one bit of `lst` flipped without re-signing) is still served as
  stored; the verifier test catches it. The point is that the service never trusts its own row for the signer: renewal
  re-reads `signer` and checks `x5tS256` against the resolved key.
- `sub` mismatch after a domain change → re-signed with the new `sub`.
- The signer fails (stub `Signer` throws) → back-off, then 503 + `Retry-After`.
- A revoked DSC at renewal → 503 (policy refusal), never an unsigned or old-`exp` body.

### M-11e Issuance binding: the DSC that signs the mDL signs its list (certify-spi, certify-issuance, certify-format-mdoc, certify-service)

Branch `wp/m-11e-status-binding`. Depends on M-11d and M-11b. About 550 lines.

**Files.**

- `certify-spi/src/main/java/io/mosip/certify/spi/StatusProvider.java`
- `certify-spi/.../CredentialFormatter.java`
- `certify-issuance/.../DefaultIssuanceService.java`
- `certify-format-mdoc/.../MdocFormatter.java`
- `certify-service/.../status/TokenStatusListProvider.java`
- The v2 configuration validation (the class that answers `invalid_configuration` for `/v2/credential-configurations`)
- Sample writer and test: `MdocStatusListSampleTest` (new, `certify-service`)
- `certify-conformance-mdoc` expected-sample list

**Spec.**

1. SPI, additive:

   ```java
   // StatusProvider
   record StatusBinding(SigningContext signing, String statusListTokenFormat) {}
   default UnsignedCredential attach(UnsignedCredential c, CredentialConfiguration cfg, IssuanceContext ctx, StatusBinding b) {
       return attach(c, cfg, ctx);
   }
   // CredentialFormatter
   default String statusListTokenFormat() { return "jwt"; }   // MdocFormatter returns "cwt" (ISO2 12.3.6.3)
   ```

   Token-format identifiers are not credential-format identifiers, so rule 5 holds: only the formatter module says that
   an mDoc wants CWT.
2. `DefaultIssuanceService`:
   - Resolve `SigningContext signing = keyProviders.signingContext(signingConfig(configuration, context))` **before**
     the status block (today at `:216`, after `:211`).
   - Call the 4-argument `attach` with `new StatusBinding(signing, formatter.statusListTokenFormat())`.
   - Sign with that same `signing`.
   - Nothing else moves. An unresolvable key now fails before an index is consumed, with the same exception mapping as
     before (`FormatException` → `callerError`, others unchanged); test it.
3. `TokenStatusListProvider` overrides the 4-argument `attach`:
   - If `binding.statusListTokenFormat()` is `cwt` and `properties.mdoc().tokenFormat()` is `cwt`, call
     `lists.allocateCwt(purpose, binding.signing())`.
   - Otherwise keep today's `lists.allocate(purpose)`.
   - For the CWT path, `configuration.status().purposes()` must be exactly `["revocation"]`; otherwise throw
     `FormatException("status_list_unavailable", "ISO/IEC 18013-5 second edition 12.3.6.1: an mDoc status list
     carries only revoked/valid")`.
4. The v2 configuration API refuses on create and update, with `400 invalid_configuration` naming `status.purposes`,
   any `mso_mdoc` configuration whose `status.mechanism` is `TokenStatusList` and whose `purposes` is not
   `["revocation"]` (D-M11-5). The v1 API is untouched; rows stored through it are caught at issuance (point 3).
5. `MdocStatusListSampleTest` (Spring Boot, x509-file dev mode with Annex B IACA and DSC, as `IacaTrustAnchorsTest`
   sets up):
   - Issue one mDL through `/oid4vci` with `TokenStatusList`.
   - `GET` its `uri` with `Accept: application/statuslist+cwt`.
   - Write `target/mdoc-samples/MdocStatusListSampleTest-oid4vci.{mdoc,holder.jwk,doctype,iaca.pem,statuslist.cwt,statuslist.ct}`.
   - Revoke it through `/credentials/status` and the batch job; check in-test with `IndependentStatusListVerifier`
     (`expectedStatus = 1`) that the bit is set and the token is re-signed by the same DSC.
   - Add the sample to the CI expected list of `certify-conformance-mdoc`.
6. The draft-13 surface: one more sample `…-d13` from the same test, through the draft-13 endpoint. It declares the
   draft-13 shape codes (`credential.shape:documentWrapper`, `issuerAuth.untagged:tagged`) exactly as
   `D13GoldenReplayTest-d13` does, and no `statusList.*` code.

**Acceptance checklist.**

- [ ] Both new samples pass `MdocSampleConformanceTest` with no `statusList.*` gap, including
  `statusList.issuanceChain` (the list `x5chain` equals the IssuerAuth `x5chain`) and `statusList.chain` (Multipaz
  against the dev IACA).
- [ ] With `certify.status.token-status-list.mdoc.token-format=jwt` the mDL's `uri` names a `TokenStatusList` (JWT)
  row exactly as before M-11 (a test).
- [ ] An SD-JWT VC issued in the same context still gets a JWT list entry (I4).
- [ ] Two DSC versions: an mDL signed before a rotation and one after reference different lists; each list's `x5chain`
  equals its mDL's.
- [ ] I1-I7 hold; the full suite is green, also in reverse order (as F-10 did).

**Negative tests.**

- `purposes: ["suspension"]` on a v2 save → 400; a v1-stored row with `suspension` → issuance refused with
  `status_list_unavailable`.
- Once an IACA is configured, a keymanager DSC is refused at issuance before an index is consumed (`MdocDscPolicy` and
  `StatusListSignerPolicy`); a test counts the free indices before and after.
- A `StatusProvider` that implements only the 3-argument `attach` still works (default method).

### M-11f Smoke, Python verifier, compose comments, documentation (tools, docs, compose config)

Branch `wp/m-11f-status-ops`. Depends on M-11e. About 600 lines.

**Files.**

- `docs/design/tools/smoke_mdl.py`, `test_smoke_mdl.py`
- New `docs/design/tools/verify_status_list.py`, `test_verify_status_list.py`
- `.github/workflows/rebuild-ci.yml`, one step after the `verify_mdoc.py` step
- `docker-compose/docker-compose-injistack/config/certify-mdl.properties` (the Status block, `:75-79`)
- `config/mdl/README.md` ("Status list" in the overview, "The public host" last paragraph)
- `docs/design/20-mdl-issuer.md` (status line, D8 refinement, G23 row, M-11 section)
- `docs/design/14-configuration.md`
- `docs/technical_docs/Releases.md`
- `docs/design/12-risks-and-decisions.md` (the rows of section 6 as answered)
- `docs/design/wp/PROGRESS.md`
- With D-M11-8 (b): `docs/design/tools/owf-probe/{package.json,package-lock.json,probe.mjs}`

**Spec.**

1. `smoke_mdl.py status()`:
   - `GET` the MSO `uri` with `Accept: application/statuslist+cwt`.
   - Require `200` and `Content-Type: application/statuslist+cwt`.
   - Decode with `cbor2`: tag 18; protected `16 == "application/statuslist+cwt"`; protected 33 present.
   - Verify ES256/384/512 with `cryptography` over `["Signature1", protected, b"", payload]` (r‖s to DER with
     `encode_dss_signature`).
   - Check: `2 == uri`; `6 <= now + 60`; `4 > now`; `bits == 1`; `lst` inflates; bit at `idx` clear.
   - The token `x5chain` equals the IssuerAuth `x5chain` (`--status-signer dedicated` skips this one check and reports
     it as skipped).
   - The leaf passes `openssl verify -x509_strict -crl_check` against `--iaca` and the CRL the run already downloaded.
   - `--status-format jwt` keeps today's JWT check for a deployment running with `token-format=jwt`.
2. `verify_status_list.py` implements the M-11b table except the Multipaz-only parts.
   - Chain to `--iaca` with `cryptography` `verify_directly_issued_by`.
   - Same problem codes, held equal to Java's by `ProblemCodeRegistryTest`.
   - CI runs it on every sample with a `.statuslist.cwt` sidecar.
   - `test_verify_status_list.py` mutations mirror M-11b's.
3. `owf-probe` (if chosen):
   - A Node 20 script with **exact** pins of `@owf/mdoc` and `@owf/token-status-list` at the versions Paradym locks
     (0.9.1 and 0.6.0 today; bump together with Paradym).
   - It calls `Holder.verifyIssuerSigned` on each sample with `trustedCertificates: [{issuance: [<top of x5chain>]}]`
     (Paradym's `paradym.ts:63-67`) and a `fetch` that serves the sample's sidecar.
   - It then applies Credo's `assertMdocStatusListChainsMatchIssuanceChain` logic (reimplemented in 15 lines,
     `mdocUtil.ts:79-115`, cited).
   - It fails the CI step on any failure; `npm ci` from the lockfile only.
4. Compose comments (`certify-mdl.properties:75-79`) say:
   - the list is a CWT signed by the Document Signer that signs the mDL (D-M11-1);
   - why (ISO2 12.3.6.3, Paradym);
   - the escape hatch;
   - and they remove the "must not sign it" sentence.

   Nothing changes in `certify-mdl-dev.properties` or `certify-mdl-operator.properties` for the default mode.
5. Docs:
   - 20-mdl-issuer.md G23 → fixed by M-11 (commits), D8 refined by D-M11-2, the M-11 section replaced by a pointer to
     this plan plus a "Done" paragraph.
   - Releases.md: new `mso_mdoc` status lists are CWT; the escape hatch; older mDLs keep JWT lists.
   - 14-configuration.md: the three properties.

**Acceptance checklist.**

- [ ] `smoke.py --mdl` passes in `mdl-dev` (throwaway project with `docker-compose.public.yaml`, as VALIDATE.md 6f)
  with the new check.
- [ ] `test_smoke_mdl.py` and `test_verify_status_list.py` green.
- [ ] CI runs `verify_status_list.py` (and the probe, if chosen) on the M-11e samples; a mutation sample proves each
  step can fail.
- [ ] `check-public-overlay.sh` and `check-public-guard.sh` unchanged and green (no new secret, no new route).
- [ ] The decision rows are appended; PROGRESS.md has the entry.
- [ ] I1-I7 hold.

**Negative tests:** the smoke parser refuses a JWT body, tag 61, an unprotected `x5chain`, a missing `exp`, and an
`x5chain` that differs from the IssuerAuth one (unit tests on recorded bytes).

### M-11g (optional) Status-list signer profile and CLI (certify-pki, certify-cli)

Branch `wp/m-11g-status-signer-pki`. Depends on nothing (can run beside M-11c-f); only with D-M11-1 (b) or (c). About
650 lines.

**Files.**

- `certify-pki/.../IsoMdocProfiles.java` (new `StatusSignerBuilder`, constant
  `OAUTH_STATUS_SIGNING_EKU = "1.3.6.1.5.5.7.3.45"`, `STATUS_SIGNER_MAX_VALIDITY = Duration.ofDays(457)`)
- `AnnexBValidator.java` (`validateStatusSigner(X509Certificate signer, X509Certificate iaca)`)
- `certify-cli/.../PkiCommand.java` (`pki status-signer issue`; `pki check --profile status-signer`)
- `KeysCommand.java` (`keys import --profile status-signer`; `keys list` shows the purpose)
- `certify-cli/README.md` (Recipe 5)
- Tests `IsoMdocProfilesStatusSignerTest`, `AnnexBValidatorStatusSignerTest`, `PkiCommandTest` additions

**Spec.**

- The builder writes the 4.8 table.
- The validator returns named violations prefixed `SLS_`:
  - `SLS_ISSUER_MISMATCH`, `SLS_SIGNATURE_INVALID`, `SLS_AKI_MISMATCH`, `SLS_SKI_MISSING`;
  - `SLS_KU_MISSING`, `SLS_KU_NOT_CRITICAL`, `SLS_KU_EXTRA`;
  - `SLS_EKU_MISSING`, `SLS_EKU_NOT_CRITICAL`, `SLS_EKU_HAS_DS`;
  - `SLS_BASIC_CONSTRAINTS_CA`, `SLS_VALIDITY_TOO_LONG`, `SLS_OUTSIDE_IACA_VALIDITY`, `SLS_COUNTRY_MISMATCH`;
  - `SLS_CRL_DP_MISSING`, `SLS_SERIAL_INVALID`, `SLS_KEY_IS_IACA_KEY`, `SLS_CURVE`.
- CLI:

  ```
  certify pki status-signer issue --iaca <iaca.p12|iaca-key+cert.pem> [-p] [--iaca-alias iaca]
      ( --csr <req> --cn <name>
      | --generate ( -k <issuer.p12> --alias <name@version> | --key-out <key.pem> ) [--cn <name>] [--alg ES256] )
      [--validity-days 1..457, default 365] --out <chain.pem> [--overwrite]
  ```

  - It mirrors `dsc issue` (`PkiCommand.java:449-549`) in password handling, distinct paths, locks and canonical
    writes.
  - `--key-out` writes an encrypted PKCS#8 PEM under the issuer password (`-P` / `CERTIFY_KEYSTORE_PASSWORD`), with the
    writer `pki iaca create --pem-out` uses, and `rw-------`.
  - `--out` is `[signer, IACA]`, leaf first.
  - `pki crl issue --revoke <serial>` already works for any serial the IACA issued; add one test.

**Acceptance checklist.**

- [ ] Each `SLS_*` rule has a negative test.
- [ ] `PkiCommandTest`: issue by `--generate -k`, `--generate --key-out` and `--csr`.
- [ ] In CI: `openssl verify -x509_strict -crl_check -CAfile iaca.pem -CRLfile iaca.crl signer.pem` is `OK`, and
  `openssl x509 -ext extendedKeyUsage` prints `1.3.6.1.5.5.7.3.45` (critical).
- [ ] `pki check --profile status-signer` accepts it and refuses a DSC with `SLS_EKU_MISSING`.
- [ ] I6 (the `PkiArchitectureTest` rules) and I7 (BouncyCastle 1.69 linkage) hold.

### M-11h (optional) Dedicated-signer mode (certify-keyprovider-jca/x509-file, certify-service, compose)

Branch `wp/m-11h-status-signer-mode`. Depends on M-11e and M-11g. About 450 lines.

**Files.**

- `JcaKeyProvider.purposeOf` (EKU `.45` → `status-list-signer`, not publishable)
- `X509FileProperties.KeySpec.PROFILES` (+ `status-signer`)
- `MdocKeys` (dev-mode generation under the dev IACA; startup validation for keystore and `pem-keys` leaves with EKU
  `.45` through `validateStatusSigner`)
- `TokenStatusListProperties` (accept `dedicated`)
- `TokenStatusListService` (dedicated envelope: `signer.mode = dedicated`, `keyRef` = the configured unversioned ref;
  re-signed with its current version, policy `DEDICATED`)
- `certify-mdl-dev.properties` and `certify-mdl-operator.properties` (commented blocks for the dedicated variant)
- `MdocStatusListSampleTest` (a third sample `…-dedicated` declaring
  `statusList.issuanceChain:differs # dedicated signer (D-M11-1); Credo/Paradym need dedicated status trust anchors`)

**Acceptance checklist.**

- [ ] The dedicated sample passes Multipaz and isomdl-equivalent checks, and declares only that one gap.
- [ ] The JWKS and DID document do not list the status signer.
- [ ] Startup fails for a keystore `status-signer` entry that breaks an `SLS_*` rule.
- [ ] Rotation: lists are re-signed with the new version.
- [ ] I1-I7 hold.

## 6. Decisions for the owner (rule 8)

| # | Question | Options | Recommendation |
| --- | --- | --- | --- |
| D-M11-1 | Who signs `mso_mdoc` status lists? | (a) the Document Signer that signed the mDLs on the list; (b) a dedicated IACA-issued signer with EKU `1.3.6.1.5.5.7.3.45`; (c) both, per deployment | **(c), default (a)**. Build M-11a-f now, M-11g/h when an ecosystem asks for (b). (a) is the only option Paradym (Credo) accepts today (section 2); TSL §11.3 allows it; Multipaz's issuer does it; isomdl and Credo exempt it from EKU checks. Retract the "A Document Signer must not sign it" note: RFC 5280 §4.2.1.12 is satisfied if ISO2 12.3.6 counts the list as part of MSO signing, which every implementation read assumes. The ISO text itself was not readable (1.6). |
| D-M11-2 | How the endpoint uses `Accept` (refines D8) | (a) one format per list, `Accept` disregarded (RFC 9110 §12.5.1); (b) D8 as written: an mDoc list also as JWT by `Accept`, signed by the DSC; (c) `406` when `Accept` excludes the list's type | **(a)**. ISO2 12.3.6.3 makes CWT the mDoc format and TSL §13.9 expects one choice per ecosystem. No verifier we read needs JWT for mDoc. (c) would break clients that send `application/json` or nothing. |
| D-M11-3 | Default for existing deployments | (a) CWT for new `mso_mdoc` entries on every surface, escape hatch `mdoc.token-format=jwt` with a startup WARN; (b) opt-in | **(a)**: non-negotiable 1 and the D1 precedent; old lists and their mDLs are untouched. |
| D-M11-4 | Storage | (a) no migration: `credential_type = TokenStatusListCwt`, signer recorded in the stored envelope (4.4); (b) an additive Flyway table `token_status_list_binding` with rollback script and rehearsal | **(a)**: follows the P3-09 decision, no migration to rehearse, all within the existing columns. |
| D-M11-5 | Status purposes for `mso_mdoc` | (a) only `revocation` (ISO2 12.3.6.1), refused otherwise at v2 save and at issuance; (b) allow `suspension` lists, which mDL verifiers would read as INVALID | **(a)** |
| D-M11-6 | The demo's mDLs issued before M-11 | (a) reissue; their JWT lists stay as they are; (b) re-sign the old shared JWT lists as CWT under the current DSC | **(a)**: the MSOs last 30 days (`mso-validity=P30D`), and (b) would change bytes for SD-JWT entries sharing those lists. |
| D-M11-7 | A list whose pinned signer expired | (a) serve as stored until its `exp`, then `410 Gone`; (b) `503` + `Retry-After` as today; (c) re-sign with the current DSC | **(a)**: every mDL on it has expired (D7), so retrying cannot help; (c) breaks Credo's rule. |
| D-M11-8 | Paradym-equivalent check in CI | (a) Java emulation of Credo's rule only; (b) also a gating Node probe running `@owf/mdoc` and `@owf/token-status-list` at Paradym's exact versions (a new npm lockfile under `docs/design/tools/owf-probe`) | **(b)**: the failure we saw is in that library, and non-negotiable 2 asks for third-party verifiers. Node is already set up in CI (`rebuild-ci.yml:196`). |
| D-M11-9 | Dedicated-signer profile (only with (b)/(c) of D-M11-1) | EKU critical or not; validity cap 457 days (DS cap) or 1095; may the EKU also carry the DS OID; published in JWKS | **EKU `.45` only, critical; at most 457 days; not with the DS OID; not published** (4.8) |
| D-M11-10 | `status_list.certificate` in the MSO | (a) never; (b) the signer certificate, as the ISO2 12.3.6.2 trust point | **(a)**: the IACA fallback already works; (b) pins one signer for the MSO's life, adds about 500 bytes, and `@owf/mdoc` ignores it. |

## 7. Operator runbook for the live demo

Nothing here has been run. The commands follow `config/mdl/README.md` ("Operator PKI", "The public host"); paths are
those of this deployment. Run them as the deploying user on the deployment host, except the "Offline" block.

### 7.A Recommended, D-M11-1 (a): the Document Signer signs, no offline step

Preconditions:

- M-11a to M-11f are merged into `design/extensibility`.
- `~/.certify-mdl/deploy` (= `MDL_PKI_DIR`) holds `issuer.p12` with `mdl-dsc@2026-11`, `iaca.pem` and `iaca.crl`.
- The IACA key stays in `~/.certify-mdl/offline`; this path does not touch it.

```bash
# 1. Code and image (on the deployment host's checkout of the fork).
cd "$(git rev-parse --show-toplevel)"
git fetch origin && git checkout design/extensibility && git pull --ff-only
git log --oneline -1                                        # at or after the M-11f merge
export JAVA_HOME=$(/usr/libexec/java_home -v 21)            # Linux: the JDK 21 home
mvn -B -ntp -s .mvn/settings-local.xml -Dmaven.legacyLocalRepo=true -Dgpg.skip=true -DskipTests install

# 2. Configuration: nothing to add. The defaults are token-format=cwt, signer=document-signer. Check what the stack reads:
grep -n "token-status-list" docker-compose/docker-compose-injistack/config/certify-mdl*.properties
#    expect no "token-format=jwt" and no "mdoc.signer=dedicated"

# 3. Restart Certify only; the database, keystores and secrets are unchanged.
cd docker-compose/docker-compose-injistack
export MDL_PKI_PROFILE=mdl-operator MDL_PKI_DIR="$HOME/.certify-mdl/deploy"
export CERTIFY_PUBLIC_URL=https://credentials.loremipsum.co.in CERTIFY_SECRETS_DIR="$HOME/certify-mdl-secrets"
unset CERTIFY_KEYSTORE_PASSWORD
mdl_public() { docker compose -p certify-mdl -f docker-compose.yaml -f docker-compose.rebuild.yaml \
    -f docker-compose.mdl.yaml -f docker-compose.public.yaml "$@"; }
mdl_public build certify
mdl_public up -d --no-build certify
mdl_public logs --since 10m certify | grep -iE "token status|statuslist|status list|CRL|ERROR" | head -40
#    no ERROR; no "token-format=jwt" WARN

# 4. Smoke, which issues a fresh mDL and checks the CWT list (M-11f).
cd "$(git rev-parse --show-toplevel)"
.venv/bin/python docs/design/tools/smoke.py --mdl "$CERTIFY_PUBLIC_URL" --iaca "$MDL_PKI_DIR/iaca.pem"
#    expect "status list served as statuslist+cwt …" PASS and every other check as before

# 5. By hand, on the mDL the smoke run kept (its --out directory prints the MSO uri and idx).
URI='<status_list.uri from the smoke output>'; IDX='<idx>'; OUT="$(mktemp -d)"
curl -sS -D "$OUT/h" -o "$OUT/list.cwt" -H 'Accept: application/statuslist+cwt' "$URI"
grep -iE '^HTTP|^content-type' "$OUT/h"                     # 200, application/statuslist+cwt
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' -H 'Accept: application/statuslist+jwt' "$URI"
#    200 application/statuslist+cwt (one format per list, D-M11-2)
python3 -I docs/design/tools/verify_status_list.py --list "$OUT/list.cwt" --content-type application/statuslist+cwt \
    --uri "$URI" --idx "$IDX" --iaca "$MDL_PKI_DIR/iaca.pem" --mdoc '<the smoke run's .mdoc file>'
#    every check PASS, including statusList.issuanceChain (the list's x5chain equals the mDL's)
python3 -I - "$OUT/list.cwt" <<'EOF'
import sys, cbor2
t = cbor2.loads(open(sys.argv[1], 'rb').read()); p = cbor2.loads(t.value[0]); c = cbor2.loads(t.value[2])
print("tag", t.tag, "typ", p.get(16), "x5chain", "protected" if 33 in p else "MISSING", "unprotected", t.value[1])
print("sub", c[2], "iat", c[6], "exp", c[4], "ttl", c.get(65534), "bits", c[65533]["bits"])
EOF
#    tag 18, typ application/statuslist+cwt, x5chain protected, unprotected {}, bits 1

# 6. Wallets. Reissue from https://credentials.loremipsum.co.in/v1/certify/offer/ into Paradym: the import succeeds.
#    The proxy log shows one GET per credential of the batch, each 200:
cd docker-compose/docker-compose-injistack && mdl_public logs --since 10m certify-nginx | grep token-status-list | tail -12
#    mDLs issued before step 3 still point at the JWT list (D-M11-6): delete them in the wallet and reissue.
```

Rollback without a redeploy:

- Add `certify.status.token-status-list.mdoc.token-format=jwt` to `config/certify-mdl.properties` and run
  `mdl_public up -d --no-build --force-recreate certify`.
- New mDLs then get JWT list entries again. CWT lists already referenced keep being served and renewed.

### 7.B Only if the owner chooses the dedicated signer (D-M11-1 (b) or (c) with `dedicated`) and M-11g/h are merged

Paradym will still refuse these lists until it trusts the IACA as a status certificate (section 2); use 7.A for Paradym.

**Offline machine** (`~/.certify-mdl/offline` holds `iaca.p12`, `iaca.pem`, `iaca.crl` and the CRL inventory; the CLI
jar is built from the same commit):

```bash
cd "$HOME/.certify-mdl/offline"
CERTIFY_CLI_JAR='<checkout>/certify-cli/target/certify-cli.jar'; certify() { java -jar "$CERTIFY_CLI_JAR" "$@"; }
read -rs 'CERTIFY_IACA_PASSWORD?IACA password: '; echo; export CERTIFY_IACA_PASSWORD            # zsh; bash: read -rs -p
read -rs 'CERTIFY_KEYSTORE_PASSWORD?Issuer keystore password: '; echo; export CERTIFY_KEYSTORE_PASSWORD

# 1. The signer: a new key as an encrypted PKCS#8 PEM under the issuer keystore password, chain [signer, IACA] beside it.
certify pki status-signer issue --iaca iaca.p12 --generate --key-out mdl-status.key.pem \
    --cn "Lorem Ipsum Demo Status List Signer" --validity-days 365 --out mdl-status-chain.pem
#    serial=0x…  subject=CN=Lorem Ipsum Demo Status List Signer,ST=…,C=IN  notAfter=…

# 2. Independent checks before anything leaves the machine.
openssl x509 -in mdl-status-chain.pem -out mdl-status.pem
openssl verify -x509_strict -crl_check -CAfile iaca.pem -CRLfile iaca.crl mdl-status.pem          # mdl-status.pem: OK
openssl x509 -in mdl-status.pem -noout -ext keyUsage,extendedKeyUsage,crlDistributionPoints,authorityKeyIdentifier
#    Key Usage: critical, Digital Signature;  Extended Key Usage: critical, 1.3.6.1.5.5.7.3.45
certify pki check --chain mdl-status-chain.pem --profile status-signer --iaca iaca.pem --crl iaca.crl   # ok status-signer

# 3. Only the signer's two files go to the deployment directory; iaca.p12 and the inventory stay here.
install -m 0600 mdl-status.key.pem mdl-status-chain.pem "$HOME/.certify-mdl/deploy/"
unset CERTIFY_IACA_PASSWORD CERTIFY_KEYSTORE_PASSWORD
```

**Deployment host.** Uncomment the dedicated block that M-11h adds to `config/certify-mdl-operator.properties`. It reads
as follows; the key password reuses the `keystore_password` secret, so no new secret is needed:

```properties
certify.keyprovider.x509-file.pem-keys[0].alias=mdl-status@2026-11
certify.keyprovider.x509-file.pem-keys[0].key=/pki/mdl-status.key.pem
certify.keyprovider.x509-file.pem-keys[0].key-password=${CERTIFY_KEYSTORE_PASSWORD}
certify.keyprovider.x509-file.pem-keys[0].chain=/pki/mdl-status-chain.pem
certify.status.token-status-list.mdoc.signer=dedicated
certify.status.token-status-list.mdoc.key-ref=x509-file:mdl-status
```

Then:

- Restart and verify as in 7.A steps 3-5.
- `verify_status_list.py` then reports `statusList.issuanceChain:differs`, which is expected in this mode, and every
  other check passes.
- The startup log names the status signer as checked against the IACA.

File permissions are as the README says (`chown 1001:1001` on Linux when the container does not run as root). Before
the signer's `notAfter`, issue a new version (`--alias`/`--key-out` with a new `@yyyy-MM`) and add it as `pem-keys[1]`.

## 8. When the packages land

- `20-mdl-issuer.md`:
  - status line and G23 row → fixed, with commits;
  - D8 → refined by D-M11-2;
  - M-11 section → a short "Done" paragraph pointing here;
  - D16's enforcement switch also covers `StatusListSignerPolicy`.
- `12-risks-and-decisions.md`: D-M11-1 to D-M11-10 as answered, before the first PR (M-11a can open after D-M11-1 to -4
  are answered).
- `config/mdl/README.md` and `certify-mdl.properties` (M-11f); `certify-cli/README.md` Recipe 5 (M-11g).

## Appendix A. Sources

| Source | Location read |
| --- | --- |
| draft-ietf-oauth-status-list-21 | https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt; state on https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/ |
| IANA SMI numbers (PKIX extended key purposes, value 45) | https://www.iana.org/assignments/smi-numbers/smi-numbers.xml |
| HAIP 1.0 Final | https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html |
| OpenID4VCI 1.0 Final | https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html |
| ISO/IEC DIS 18013-5 (project 91081) state | https://iss.rs/en/project/show/iso:proj:91081 |
| `@owf/mdoc`, `@owf/token-status-list`, `@owf/cose` | github.com/openwallet-foundation-labs/identity-common-ts `975c3fb4`; npm `@owf/mdoc@0.9.1`, `@owf/token-status-list@0.6.0` |
| Credo | github.com/openwallet-foundation/credo-ts `8114e84d`; npm `@credo-ts/core@0.8.0-alpha-20261030133527` |
| Paradym Wallet | github.com/animo/paradym-wallet `a5d722d6` (`apps/wallet/src/config/paradym.ts`, `pnpm-lock.yaml`) |
| Multipaz | github.com/openwallet-foundation/multipaz `6b4be590` and tag `0.102.0` |
| isomdl | github.com/spruceid/isomdl `9087dcf5`; PR spruceid/isomdl#146 |
| EUDI | eu-digital-identity-wallet/eudi-lib-android-wallet-core `d5e2c51c`; eudi-lib-kmp-statium `d9509240`; eudi-srv-statuslist-py `5da16aea` |
