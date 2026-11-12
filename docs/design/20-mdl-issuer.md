# ISO 18013-5 mDL issuer on the OpenID4VCI 1.0 surface

> Part of the Inji Certify extensibility design. Index: [README.md](./README.md). Work packages `M-01`..`M-12` below; branch each as `wp/m-NN-<slug>` from `design/extensibility`.

Goal (owner, 2026-11-13): a standards-compliant `mso_mdoc` mDL issuer on the refactored code path (`/oid4vci`, `certify-core`, `certify-format-mdoc`, `certify-signing`, the x509 providers, `certify-cli`), callable from any OpenID4VCI 1.0 wallet that supports `mso_mdoc` (Multipaz, EUDI reference wallet, Inji Wallet), with ISO 18013-5 Annex B IACA and Document Signer certificate flows, publicly at `https://credentials.loremipsum.co.in`.

Standards: ISO/IEC 18013-5:2021 (data model 7.2, MSO 9.1.2, Annex B certificate profiles), OpenID4VCI 1.0 final (Appendix A.2 `mso_mdoc`, 12.2.2 metadata location), HAIP 1.0 (no trust anchor in `x5chain`), draft-ietf-oauth-status-list (`status.status_list` in the MSO), RFC 9360 (`x5chain`, label 33), RFC 5280.

## Decisions taken for this work (2026-11-13)

| # | Question | Decision | By |
| --- | --- | --- | --- |
| D1 | The mDoc formatter is shared with the draft-13 surface; apply the ISO fixes (seconds-only `tdate`, random unique digestIDs, `x5chain` without anchor, typed elements) there too? | Both surfaces. Spec correctness wins; re-record the `legacy-0.14.0` mDoc golden. | owner |
| D2 | Demo identity | Country `IN` in IACA, DSC and `issuing_country`; names say "Demo"/"Test" (IACA CN `Lorem Ipsum Demo IACA`, issuing authority `Lorem Ipsum Demo Issuing Authority`). Synthetic people and generated portraits only. | owner |
| D3 | Where the IACA private key lives | Offline: created with `certify-cli pki iaca create` outside the repository; only the DSC key, the `[DSC, IACA]` chain and the IACA-signed CRL are mounted into the stack. x509-file dev mode also generates Annex B certificates for local runs. | owner |
| D4 | Holder key types for the mDL | ES256 (P-256, EC2) and EdDSA (Ed25519, OKP, allowed by 18013-5 9.1.5.2) device keys and proofs. | owner |
| D5 | How an offer chooses its surface | Optional `issuer: "oid4vci" \| "legacy"` on `POST /pre-authorized-data`, default from `certify.protocol.oid4vci-v1.offers.default-issuer` (default `legacy`; the mDL profile sets `oid4vci`). | agent |
| D6 | Element typing | Built-in ISO 18013-5 table for namespace `org.iso.18013.5.1` plus an optional `formatConfig.elementTypes` override; the date heuristic stays only for untyped namespaces. | agent |
| D7 | MSO validity | `certify.format.mdoc.mso-validity` (Duration, default `P90D`), capped at the DSC `notAfter`; `signed`/`validFrom` = signing instant truncated to seconds. | agent |
| D8 | Status list for mDoc | Token Status List served as JWT (existing) and as CWT (`statuslist+cwt`) by `Accept` negotiation (M-11, after the core packages). | agent |
| D9 | Merge-gate verifier | Multipaz JVM (`org.multipaz`) in a test-only module, Authlete `com.authlete:cbor` as a second COSE oracle, `pymdoccbor` and `openssl verify -x509_strict` in CI. | agent |
| D10 | Demo data source | `FileCredentialDataSource` in `certify-service` (records keyed by `sub` from a JSON file; a binary field's file is read at startup and delivered to the template as base64url without padding — the contract M-03's `bstr` typing implements, decoding base64 and base64url, so a template may pass either; a missing key claim or record is `credential_request_denied`, not a 500); the mDL runs on the same compose stack as the farmer profile through an overlay. | agent |
| D11 | Annex B edition | 18013-5:2021 tables (IACA validity <= 20 years, DS validity <= 457 days, DS EKU `1.0.18013.5.1.2`, DS without basicConstraints). | agent |
| D12 | Public host exposure | nginx refuses admin APIs from non-local sources (`system-info`, `credential-configurations`, `v2/`, `credentials/status`, `ledger-search`, `vc-api`); the offer page and `/pre-authorized-data` stay public for the demo. | agent |
| D13 | AS metadata | advertise `pre-authorized_grant_anonymous_access_supported: true`, opt-in through `certify.as.pre-authorized-grant.advertise-anonymous-access` so an existing deployment's document keeps its bytes (refined 2026-11-13, decision log). | agent |
| D14 | Identifier | keep `https://<host>/v1/certify/oid4vci` (12.2.2 well-known mapping already in nginx). | agent |
| D15 | IACA publication | plain JSON list plus PEM/DER/CRL downloads; a signed VICAL later. | agent |
| D16 | Keymanager-held DSCs for `mso_mdoc` on `/oid4vci` | fail closed when the chain does not reach a configured IACA (master-signed certificates refused); the CSR flow through `certify-cli pki dsc issue --csr` is the supported keymanager route. | agent |

## As-is map

| Step | Where |
| --- | --- |
| HTTP entry, proof policy, batch | `certify-service/.../oid4vci/Oid4vciCredentialController.java:64-114`; errors `:137-145` (anything not an `IssuanceException` becomes 500 `server_error`) |
| Orchestration | `certify-issuance/.../DefaultIssuanceService.java:79-202` |
| Holder key | `JwtProofValidatorAdapter.java:106` (`HolderBinding.did(...)`; `jwk` header becomes `did:jwk`; `kid` stays `did:key:`/`did:jwk:`) |
| Data source | `oid4vci/DataProviderPluginDataSource.java:37-52` (only `CredentialDataSource`) |
| Build | `certify-format-mdoc/.../MdocFormatter.java:63-84`, `MdocProcessor.processTemplatedJson` `:51-121`, `addRandomSalts` `:154-181`, `calculateDigests` `:186-222`, `createMobileSecurityObject` `:405-435`, `createDeviceKeyInfo` `:440-483` |
| Status | `certify-service/.../status/TokenStatusListProvider.java:42-55` |
| Sign | `MdocFormatter.java:88-108` -> `CertificateChainPolicy.check` -> `CoseEnvelope.sign1` -> IssuerSigned, base64url |
| Metadata | `Oid4vciDiscoveryController.java:44-62` reuses `services/CredentialIssuerMetadataBuilder.java:68-187` (COSE integers `:95-113`, claims `:164-173`); tenants `TenantIssuerMetadata.java:69-114` |
| Offer, token, nonce, DPoP, notification | `PreAuthorizedCodeService` (offer `credential_issuer` = compatibility identifier `:250`, by reference only `:263-268`), `OAuthController`, `Oid4vciDiscoveryController.nonce`, `Oid4vciNotificationController` |
| Offer page | `offer/OfferPageController.java`, `static/offer/index.html` |
| Keys | x509-file `X509FileKeyProviders.java:18-56`, dev certificates `certify-keyprovider-jca/.../DevKeys.java` (no Annex B extensions, millisecond serials); keymanager leaf-only chain `KeymanagerKeyProvider.java:208-212`; CLI `keys generate|list|jwks` only |
| Compose | `certify_init.sql` seeds only `FarmerCredential`; no mDL configuration; init SQL runs before Flyway 1.1.0, so v2 fields are seeded through the v2 API |

Already correct on the wire: tag-24 IssuerSignedItems with digests over the tag-24 bytes, 24-byte `random`, `valueDigests {ns: {uint: bstr}}`, COSE_Key labels, protected header `{1: -7}`, `x5chain` label 33 (bstr for one, array for more), untagged COSE_Sign1 with a tag-24 MSO payload, `status.status_list {idx, uri}`.

## Gaps

Severity: B blocks wallets or verifiers, N not compliant, H nice to have.

| # | Gap | Clause | Evidence | Sev |
| --- | --- | --- | --- | --- |
| G1 | `tdate` with milliseconds | 18013-5 9.1.2.4 | `MdocConstants.java:19`, `MdocProcessor.java:77-88` | N |
| G2 | `portrait` and byte elements cannot be bstr | 18013-5 7.2.1 Table 5 | `MdocProcessor.java:137-143,300-365` | B |
| G3 | Element typing heuristic; no mandatory-element check | 18013-5 7.2.1 | `MdocProcessor.java:268-273,371-378` | N |
| G4 | `digestID` copied from template, duplicates overwrite, sequential | 18013-5 9.1.2.5 | `MdocProcessor.java:132,214` | N |
| G5 | Digest always SHA-256 whatever `digestAlgorithm` declares | 18013-5 9.1.2.5 | `MdocProcessor.java:213` vs `:410` | N |
| G6 | Device key only from EC2 `did:jwk`; Ed25519 and `did:key` fail; `alg -7` hard-coded; failures are 500 | 18013-5 9.1.2.4, 9.1.5.2; OID4VCI 8.3.1 | `MdocProcessor.java:440-483` | B |
| G7 | `docType` never compared with configuration `doctype` | 18013-5 9.1.2.4; A.2.2 | `MdocProcessor.java:96-97` | N |
| G8 | Validity from `ZonedDateTime.now()`, 2 years, beyond DSC `notAfter` | 18013-5 9.1.2.4, 9.3.3 | `MdocProcessor.java:76-89` | N |
| G9 | Default `x5chain=FULL` carries the IACA | HAIP; 18013-5 9.1.2.4 | `CoseHeaderPolicy.java:19-21` | N |
| G10 | Dev CA is not an IACA | Annex B IACA profile | `DevKeys.java:61-80` | N |
| G11 | Dev leaf is not a DSC (EKU, AKI/SKI, IAN, CRL DP, C) | Annex B DS profile | `DevKeys.java:83-103` | B |
| G12 | No DSC policy before signing | Annex B; 7.2.1 `issuing_country` | `CertificateChainPolicy.java:20-46` | N |
| G13 | Keymanager chain leaf-only and master-signed | Annex B | `KeymanagerKeyProvider.java:211` | N |
| G14 | No IACA, DSC-from-CSR, rotation, CRL, PEM import | Annex B | `certify-cli`, `X509FileKeyProviders` | B |
| G15 | No IACA or CRL publication | Annex B (CRL DP) | none | B |
| G16 | No DSC expiry gauge or rotation | 06a | `JcaKeyProvider.java:194-203` | H |
| G17 | Offer `credential_issuer` is the compatibility identifier | OID4VCI 4.1.1 | `PreAuthorizedCodeService.java:250` | B |
| G18 | Offers by reference only | OID4VCI 4.1 | `PreAuthorizedCodeService.java:263-268` | H |
| G19 | `/oid4vci` default document lacks issuer `display` | OID4VCI 12.2.4 | `Oid4vciDiscoveryController.java:52-62` | H |
| G20 | COSE alg map lacks ES384/ES512 | A.2.2 | `CredentialIssuerMetadataBuilder.java:38-42` | N |
| G21 | `cose_key` binding and proof algs only from the row | A.2.2 | `CredentialIssuerMetadataBuilder.java:133-134` | N |
| G22 | AS metadata lacks `pre-authorized_grant_anonymous_access_supported` | OID4VCI AS metadata | `OAuthAuthorizationServerMetadataDTO.java` | H |
| G23 | Status list JWT only, keymanager signer | status-list draft (CWT) | `TokenStatusListService` | N |
| G24 | No independent mDoc verifier in tests | CLAUDE.md non-negotiable 2 | `IssuanceGoldenTest.java:574-612` | N |
| G25 | Admin endpoints reachable on a public host | security | `config/certify-default.properties:38-42` | B |
| G26 | No mDL configuration, data source, seed or IACA in compose | | | B |
| G27 | Keymanager-generated certificate serials can be negative (`SecureRandom.nextLong()`, about half the keys); owner M-06 / keymanager provider | RFC 5280 4.1.2.2 | kernel-keymanager `CertificateUtility.generateX509Certificate`; M-01 check `x5chain.serialNumber` | N |

## Work packages

Each under about 800 lines excluding goldens and binaries.

### M-01 Independent mDoc verifier harness (G24)
- New test-only module `certify-testkit-mdoc` (in the parent `<modules>`), `IndependentMdocVerifier`: Java facade over Multipaz JVM (`org.multipaz`, pinned exact version, Kotlin deps confined to this module, test scope wherever used). Second COSE oracle: Authlete `com.authlete:cbor` `COSEVerifier`. `certify-service` does not depend on it at all: M-01's first attempt put the Multipaz Kotlin pin (2.2.21) in the service, which changed what the product ships. M-01 changes no product code: today's defects are named, per-sample accepted gaps that M-02/M-03 remove.
- `verify(byte[] credential, JWK holder, Optional<X509Certificate> iaca, Instant at, Options)` takes the credential as received (a bare IssuerSigned or the draft-13 Document, whose `issuerSigned` is read from the received bytes) and returns a report of named checks, each `PASS`, `FAIL` or `SKIPPED`, a failed check carrying **every** problem it found under a stable problem code (`IndependentMdocVerifier.PROBLEM_CODES`, e.g. `mso.validityInfo:expired`, `mdl.elementTypes:untyped:birth_date`, `x5chain.iaca:noAnchorSupplied`): the credential is the bare IssuerSigned (`credential.shape:documentWrapper`) and IssuerAuth the untagged COSE_Sign1 (`issuerAuth.untagged:tagged`, ISO/IEC 18013-5 9.1.2.4, RFC 9052 4.2); COSE_Sign1 signature by the `x5chain` leaf (both oracles, tag-18 COSE_Sign1 included); the MSO payload is tag 24; Multipaz's `MobileSecurityObject` parser accepts the MSO as sent (`mso.parse`: a Multipaz wallet reads it through exactly that parser); Multipaz `IssuerNamespaces.validate` + `validateAgainstMso`; every IssuerSignedItem digest equals `valueDigests` under the declared algorithm **hashed over the bytes as received** (`IssuerSignedItem.calculateDigest` re-encodes, so it is the second opinion, not the oracle); `deviceKey` equals the holder key by Multipaz's `CoseKey` and by the COSE labels (EC2 by x/y, OKP Ed25519 by x, no `d`); `docType`; the window ordered from the dates as sent (`signed <= validFrom < validUntil`, `validFrom <= expectedUpdate < validUntil`, `at` inside) plus Multipaz `MobileSecurityObject.validate`; strict `tdate` (tag 0, whole seconds, `Z`); chain validates to the IACA (strict fails without one); `x5chain` carries no self-signed certificate; every `x5chain` serial positive and at most 20 octets (RFC 5280 4.1.2.2, G27); element types of `org.iso.18013.5.1` against Table 5 (Multipaz `DrivingLicense` plus the Table 5 rows it gets wrong: `issue_date`/`expiry_date` full-date **or** tdate, `portrait_capture_date` tdate, `driving_privileges` per 7.2.4; `full-date` tag 1004 and `tdate` tag 0 parsed strictly). MSO fields are read from the wire with Multipaz's CBOR, so a parser refusal is one check, not a cascade. A skipped check never counts as a pass.
- Samples, not a dependency: the producing tests write each issued credential to `target/mdoc-samples/<TestClass>-<surface>`: the bytes as received (`.mdoc`, an IssuerSigned or the draft-13 Document), `.holder.jwk`, `.doctype`, `.gaps` and `.iaca.pem` when the chain carries one. Producers: `IssuanceGoldenTest` and `IssuanceGoldenCoreTest` (`legacy`, `oid4vci`), `D13GoldenReplayTest` (`d13`), `MdocIndependentVerificationTest` (`formatter`, `ed25519-fixture`); `VcIssuancePluginGoldenTest` passes a plugin's opaque bytes through and is not a producer. Each producer deletes its own earlier samples on its first write.
- `.gaps`: one `<check>:<code> # <reason>` line per problem the sample is known to have; a bare check name and the former `?` marker are refused, so one accepted problem cannot hide another in the same check (an expired credential fails with G8's `mso.validityInfo:signedAfterValidFrom` declared). A producer whose output varies decides from the bytes it wrote: `MdocSampleWriter` declares `x5chain.serialNumber:nonPositive` (G27) exactly when the received leaf serial is `<= 0`, and `zero`/`tooLong` are separate codes nobody declares. The draft-13 sample alone declares `credential.shape:documentWrapper` and `issuerAuth.untagged:tagged` (0.14.0 wire compatibility, decision log 2026-09-19). New test-only module `certify-conformance-mdoc`, listed after the producers, runs every check (`Options.strict`) on every sample as received and holds it to exactly its codes: an undeclared problem fails, a declared code no longer reported fails with "gap no longer present, remove it", and a skipped check fails. With `CI` set it also requires exactly the expected sample list, each written after the reactor build started (`maven.build.timestamp`); locally a stale sample is reported and skipped.
- `docs/design/tools/verify_mdoc.py` (pymdoccbor, exact pins in `docs/design/tools/requirements-verify.txt`, Python 3.12 via `actions/setup-python`) plus a CI step in `.github/workflows/rebuild-ci.yml` over those samples, with `--doctype`, `--iaca`, `--holder` and `--gaps` taken from the sidecars. It reports the same problem codes as the Java harness for the rules it implements (its `PROBLEM_CODES` table is held to Java's by `ProblemCodeRegistryTest`) and holds a sample to its `.gaps` the same way (codes only Java reports are notes): shape and IssuerAuth tag, pymdoccbor signature, digests over the bytes as received (SHA-256/384/512) and pymdoccbor's own check, duplicate elementIdentifier or digestID, a non-preferred `#6.24` head, empty `nameSpaces`, a namespace missing from `valueDigests`, a map key or namespace twice, the deviceKey (EC2 and OKP), docType, every validity rule, tdate encoding, chain to `--iaca`, self-signed certificates, serials. `test_verify_mdoc.py` holds its rules (a duplicated namespace key among them) and CI requires each mutation under `target/mdoc-mutations/` to fail on the problem its `.expect` names (the expired re-signed credential with only G8 declared).
- `docs/design/tools/check-runtime-classpath.sh` diffs `certify-service`'s resolved runtime classpath against the committed `certify-service/runtime-classpath.txt`; both test-only modules set `maven.deploy.skip` and `skipPublishing`.
- D9's `openssl verify -x509_strict` step is deferred to M-06 (decision log 2026-11-13): it needs an IACA to verify against, and no sample's chain carries one until the keymanager chain is completed from a configured anchor.
- Checks that today's output cannot pass yet (G1, G2, G6, G8, G9, G13, G27, chain to IACA) are the samples' declared gaps and enabled tests asserting the current failure, named after the gap; M-02/M-03/M-06 flip them and delete the lines.

### M-02 MSO and IssuerSigned wire fixes (G1, G4-G9)
- `MdocProcessor`, `MdocFormatter`, `MdocConstants`, `MdocProperties` (`msoValidity` Duration default `P90D`); `CoseHeaderPolicy.mdocIssuerAuth()` -> `WITHOUT_ANCHOR`; `DefaultIssuanceService` maps a formatter holder-key failure to `invalid_proof`.
- `tdate` `uuuu-MM-dd'T'HH:mm:ss'Z'` from `context.now()` truncated to seconds, tagged 0; validity decided in `sign()`: `validUntil = min(signed + msoValidity, DSC notAfter, mDL expiry_date)` truncated to seconds and strictly after `signed` (`mso-validity` at least one minute); configured digest algorithm used for computing and declaring; digestIDs random distinct uints in `0..2^31-1` per namespace, not a permutation of `0..n-1` (template IDs ignored); the IssuerAuth always carries `x5chain` (no chain, `x5c: none`, or `leaf` with intermediates -> `certificate_chain_invalid`; `x5c: none` refused at v2 save); `docType` must equal the configuration `doctype`; COSE_Key from a parsed JWK: EC2 P-256/384/521 and OKP Ed25519 (`{1:1, -1:6, -2:x}`), from `did:jwk`, `did:key` (multibase) or a raw JWK; no `alg` label; bad holder key -> `invalid_proof`.
- Re-record the `oid4vci-1.0` and `legacy-0.14.0` mDoc goldens (D1); enable the M-01 checks for G1 and G9; P-256 and Ed25519 holders pass Multipaz and pymdoccbor.
- Order `signed <= validFrom` in `sign()` itself (one instant for both, or `validFrom` derived from `signed`), not by truncating to seconds and hoping both fall in the same second: the golden tests' 2 ms data-provider delay (`IssuanceGoldenTest.answerAfterTwoMilliseconds`) makes the core path's `signed` later than its `validFrom` on every run, and a second boundary between them would still do it after truncation. Removing `mso.validityInfo:signedAfterValidFrom` (and `mso.parse:refused`) from the core samples' `.gaps` is the proof.

### M-03 ISO 18013-5 data model and element typing (G2, G3, G7)
- `MdocElementTypes` (built-in table for `org.iso.18013.5.1`, types and the mandatory set of Table 5), `MdocDataModelValidator`, typed conversion in `MdocProcessor`, optional `formatConfig.elementTypes`.
- Conversions: `bstr` from base64/base64url (portrait, `signature_usual_mark`, `biometric_template_*`), `full-date` (tag 1004), `tdate` (tag 0 over an RFC 3339 `tstr` in whole seconds, no fractional part), `uint`, `bool`, `driving_privileges` (array of maps; `issue_date`/`expiry_date` full-date; `codes[]`). Validation for `org.iso.18013.5.1.mDL`: mandatory elements, JPEG-only portrait (SOI/EOI, at most 1 MiB and 4096x4096 pixels read from the header, decoded without decoder warnings; JPEG 2000 not issued, decision log 2026-11-13), `issuing_country` alpha-2 equal to the DSC subject C (checked at sign), `un_distinguishing_sign` 1-3 upper-case letters (`IND` for India), `issuing_jurisdiction` an ISO 3166-2 subdivision of `issuing_country`, `expiry_date` after the issuance instant. The date heuristic applies only to untyped element values (identifiers, namespace names and `docType` stay `tstr`); a custom `array` type is a plain CBOR array (`driving_privileges` only by name); integers beyond `long` stay CBOR integers (uint/nint up to 64 bits, bignum beyond). Violation -> `FormatException("mdoc_data_model_invalid")`; the v2 preview surfaces it.

### M-04 `certify-pki`: Annex B profiles (G10, G11)
- New module, BouncyCastle only, no Spring/Web/JPA: `IsoMdocProfiles` (IACA and DS builders), `AnnexBValidator` (named violations for IACA, DS, CRL), `CrlBuilder`, `Csr` (PKCS#10 parse, proof-of-possession check), `Serials` (positive, up to 20 octets, at least 63 random bits).
- IACA: self-signed; C, CN; issuerAltName (URI or email); CRL DP; SKI; keyUsage keyCertSign+cRLSign critical; basicConstraints CA pathLen 0 critical; validity <= 20 years; ecdsa-with-SHA256/384/512. DS: issuer = IACA subject; C (and ST if present) equal to the IACA's; AKI = IACA SKI; SKI; keyUsage digitalSignature critical; EKU `1.0.18013.5.1.2` critical; issuerAltName; CRL DP; validity <= 457 days. CRL v2 with AKI, cRLNumber, thisUpdate, nextUpdate.
- Tests: validator positives and per-rule negatives; Multipaz chain validation (test scope); `openssl verify -x509_strict` and `openssl crl -CAfile` when OpenSSL is present (always in CI).

### M-05 x509-file and jca: Annex B dev mode, PEM import, rotation (G10, G11, G16)
- `X509FileProperties`, `X509FileKeyProviders`, `JcaKeyProvider`, `DevKeys` (delegate to `certify-pki`).
- Properties: `iaca.{alias,country,state,common-name,issuer-alt-name,crl-uri,validity-years,algorithm}`, `keys[].profile` (`plain` default | `mdoc-dsc`), `keys[].validity-days`, `pem-keys[].{alias,key,chain}`. Dev mode generates an Annex B IACA and DSCs when `iaca.*` is set; production loads a DSC key with `[DSC, IACA]`. Versioned aliases `mdl-dsc@2026-11`: `resolve(x509-file:mdl-dsc)` takes the newest valid entry; `publicKeys` lists all. Startup warning and gauge `certify.signing.key.expires_in_days{keyRef}`.
- Existing keystores and the P3-08 dev CA behaviour unchanged unless `profile: mdoc-dsc` or `iaca.*` is set.

### M-06 DSC policy and trust anchors (G12, G13)
- `certify-signing` `TrustAnchorRegistry` (`anchors(purpose)`, `crl(anchorId)`); `certify-format-mdoc` `MdocDscPolicy` (after the generic check in `MdocFormatter.sign`); `certify-service` `pki/FileTrustAnchorRegistry` with `PkiProperties` (`certify.pki.trust-anchors.mdoc-iaca[]: {id, certificate, crl}`; dev mode registers the x509-file IACA) through auto-configuration; `KeymanagerKeyProvider` completes leaf-only chains from a matching anchor (AKI or issuer DN); v2 preview runs the policy.
- Refuse `certificate_chain_invalid` (named rule) on: EKU, keyUsage or validity cap of the DSC; `signed` outside DSC validity; no configured IACA signed the DSC; country mismatch; IACA expired (D16).

### M-07 CLI: IACA flows (G14)
- `certify-cli` `PkiCommand`: `pki iaca create`, `pki dsc issue --csr|--generate`, `pki dsc rotate`, `pki crl issue`, `pki check --profile iaca|mdoc-dsc`; `KeysCommand`: `csr`, `import --key --chain`. Depends on `certify-pki`.
- `certify pki iaca create -k iaca.p12 -p <pw> --country IN --cn "Lorem Ipsum Demo IACA" --issuer-alt-uri https://credentials.loremipsum.co.in --crl-uri https://credentials.loremipsum.co.in/v1/certify/mdoc/iaca/<id>.crl`; `certify pki dsc issue --iaca iaca.p12 --csr dsc.csr --out dsc-chain.pem` (accepts a keymanager CSR) or `--generate -k issuer.p12 --alias mdl-dsc@2026-11`; `certify pki crl issue --iaca iaca.p12 [--revoke <serial>...] --next-update-days 30 --out iaca.crl`.
- README recipes: operator IACA plus DSC import; dev IACA plus DSC; DSC from a keymanager CSR.

### M-08 IACA and CRL publication (G15)
- `certify-service` `pki/IacaPublicationController` with its own security filter chain (as `OfferPageSecurityConfiguration`), off unless `certify.pki.publication.enabled`.
- `GET /mdoc/iaca` JSON `[{id, subject, country, sha256, notBefore, notAfter, pem, der, crl}]`; `/mdoc/iaca/{id}.pem` (`application/x-pem-file`), `.der` (`application/pkix-cert`), `.crl` (`application/pkix-crl`). The CRL is the operator file; in dev mode an IACA-signed CRL refreshed before `nextUpdate`.

### M-09 Surface, metadata and offers (G17-G22)
- `PreAuthorizedCodeService`/request DTO: `issuer` field and `certify.protocol.oid4vci-v1.offers.default-issuer` (D5); `credential_offer` by value when asked. `Oid4vciDiscoveryController`: issuer `display`. One COSE algorithm map (ES256 -7, ES384 -35, ES512 -36, EdDSA -8) for both metadata builders. AS metadata `pre-authorized_grant_anonymous_access_supported`. Offer page: issuer selector, `/oid4vci` default for mDoc, decode IssuerSigned in the page and show elements and portrait, link to `/mdoc/iaca`.
- Legacy goldens unchanged with the default; new golden: offer `credential_issuer` equals the `/oid4vci` metadata `credential_issuer`.

### M-10 Demo data source and compose mDL profile (G26)
- `FileCredentialDataSource` + `FileDataSourceProperties` (`certify.datasource.file.sources.<id>.{path,key-claim,binary-fields}`). Records are deeply immutable; a JSON file above 5 MiB, a binary file above 1 MiB and more than 50 MiB per source are refused while reading; symlinks are resolved before the directory containment check (so a ConfigMap's `..data/` links work and a link out of the directory does not); the id `data-provider-plugin` is reserved. `DefaultIssuanceService` takes a default data-source id so a configuration that names none still resolves to the data-provider plugin when further sources are registered.
- Binary field contract (D10): the file's bytes reach the template as base64url without padding; the formatter's `bstr` typing (M-03) decodes base64 and base64url, so a template may pass either encoding for `portrait` and the other byte elements.
- `docker-compose.mdl.yaml` overlay, `config/certify-mdl.properties`, `config/mdl/holders.json` (3 synthetic people), generated portraits (<10 KB JPEG, no real person), `config/mdl/mdl.vm`, `config/mdl/mdl-configuration.json` (v2 body: `mso_mdoc`, `org.iso.18013.5.1.mDL`, `cose_key`, proofs ES256 and EdDSA, signing x509-file `mdl-dsc` ES256 `without-anchor`, TokenStatusList, `dataSourceId mdl-demo`, claims with display), one-shot seed service posting to the v2 API (409 = seeded).
- `smoke.py`/`workflows.py` mDL run ending in `verify_mdoc.py` against `/mdoc/iaca/<id>.pem`.

### M-11 Token Status List as CWT for mDoc (G23)
- CWT `statuslist+cwt` via `CwtEnvelope` with `x5chain`, `Accept` negotiation on the list endpoint, signer under the IACA.

### M-12 Public deployment (G25)
- nginx denies admin APIs from non-local sources (D12); `mosip_certify_domain_url=https://credentials.loremipsum.co.in`; tunnel `certify-rebuild` ingress `credentials.loremipsum.co.in -> http://localhost:8091`; runbook and wallet matrix in this document; PROGRESS entry.
- Acceptance: `workflows.py https://credentials.loremipsum.co.in` green; a Multipaz/EUDI/Inji wallet obtains the mDL; IssuerAuth verifies against the downloaded IACA.

## Order

M-01, then M-02+M-03 (one formatter stream) in parallel with M-04 and M-09; then M-05, M-07, M-08; then M-06, M-10, M-11; M-12 last (nginx blocking before any public start).
