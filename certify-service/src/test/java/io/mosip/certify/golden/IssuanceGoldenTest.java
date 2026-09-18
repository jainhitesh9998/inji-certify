package io.mosip.certify.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import foundation.identity.jsonld.JsonLDObject;
import com.danubetech.dataintegrity.verifier.DataIntegrityProofLdVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.config.contextloader.StaticContextLoader;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.ClaimsDisplayFieldsConfigDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end goldens for develop's OpenID4VCI 1.0 surface: the real service (H2, PKCS#12 keymanager,
 * Velocity, keymanager signing) issues ldp_vc and dc+sd-jwt credentials through MockMvc; every credential
 * is verified with a library Certify did not write (danubetech for Data Integrity / LD proofs, Nimbus for
 * JWS) against what the service itself publishes (did.json, jwks.json); normalized responses are compared
 * with the recorded goldens under src/test/resources/goldens/v1.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"}) // local activates the TestBearer filter; test (last) wins for properties
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        // MockMvc requests carry no servlet path; the TestBearer filter matches exact paths
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        // the local profile file names the PostgreSQL dialect; this context runs on H2
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}, 'ES256K': {{'CERTIFY_VC_SIGN_EC_K1','EC_SECP256K1_SIGN'}}, 'RS256': {{'CERTIFY_VC_SIGN_RSA',''}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'Ed25519Signature2018': {'EdDSA'}, 'EcdsaSecp256r1Signature2019': {'ES256'}, 'EcdsaSecp256k1Signature2019': {'ES256K'}, 'eddsa-rdfc-2022': {'EdDSA'}, 'ecdsa-rdfc-2019': {'ES256'}, 'RsaSignature2018': {'RS256'}}",
        "mosip.certify.oauth.grant-types-supported=authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'dc+sd-jwt': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA','RS256','PS256'}}}"
})
class IssuanceGoldenTest {

    static final String LDP_ID = "GoldenLdpCredential";
    static final String SDJWT_ID = "GoldenSdJwtCredential";
    static final String DI_ID = "GoldenDataIntegrityCredential";
    static final String RSA_ID = "GoldenRsaCredential";
    static final String EC_R1_ID = "GoldenEcR1Credential";
    static final String EC_K1_ID = "GoldenEcK1Credential";
    static final String ED_2018_ID = "GoldenEd2018Credential";
    static final String SCOPE = "sample_vc_ldp"; // the scope LocalAccessTokenValidationFilter injects

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired StaticContextLoader staticContextLoader;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;   // proof audience
    @Value("${mosip.certify.domain.url}") String domainUrl;           // metadata credential_issuer (a second identity key, see docs/design/14-configuration.md)

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of(
                "fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(LDP_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(ldpConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(SDJWT_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(sdJwtConfig());
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(DI_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(ldpConfig(DI_ID, "golden-ldp-di.vm",
                    "https://www.w3.org/ns/credentials/v2", "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "eddsa-rdfc-2022"));
        }
        if (credentialConfigRepository.findByCredentialConfigKeyId(RSA_ID).isEmpty()) {
            CredentialConfigurationDTO rsa = ldpConfig(RSA_ID, "golden-ldp-rsa.vm",
                    "https://www.w3.org/2018/credentials/v1", "CERTIFY_VC_SIGN_RSA", "", "RS256", "RsaSignature2018");
            rsa.setCredentialTypes(List.of("VerifiableCredential", "GoldenRsaCredential")); // ldp_vc configs are unique per (context, types)
            credentialConfigurationService.addCredentialConfiguration(rsa);
        }
        addLegacySuiteConfig(EC_R1_ID, "golden-ldp-ecr1.vm", "CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN", "ES256", "EcdsaSecp256r1Signature2019");
        addLegacySuiteConfig(EC_K1_ID, "golden-ldp-eck1.vm", "CERTIFY_VC_SIGN_EC_K1", "EC_SECP256K1_SIGN", "ES256K", "EcdsaSecp256k1Signature2019");
        addLegacySuiteConfig(ED_2018_ID, "golden-ldp-ed2018.vm", "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "Ed25519Signature2018");
    }

    private void addLegacySuiteConfig(String id, String templateFile, String appId, String refId, String algo, String suite) throws Exception {
        if (credentialConfigRepository.findByCredentialConfigKeyId(id).isEmpty()) {
            CredentialConfigurationDTO dto = ldpConfig(id, templateFile, "https://www.w3.org/2018/credentials/v1", appId, refId, algo, suite);
            dto.setCredentialTypes(List.of("VerifiableCredential", id));
            credentialConfigurationService.addCredentialConfiguration(dto);
        }
    }

    // ---- goldens -------------------------------------------------------------------------------------

    @Test
    void issuerMetadataGolden() throws Exception {
        JsonNode metadata = getJson("/.well-known/openid-credential-issuer");
        assertEquals(domainUrl, metadata.get("credential_issuer").asText());
        assertTrue(metadata.get("credential_configurations_supported").has(LDP_ID));
        Goldens.assertGolden("v1/well-known/openid-credential-issuer", metadata);
    }

    @Test
    void ldpVcIssuanceGoldenAndIndependentVerification() throws Exception {
        MvcResult result = issue(LDP_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("GoldenCredential", credential.get("type").get(1).asText());
        assertEquals("Ed25519Signature2020", credential.get("proof").get("type").asText());
        assertEquals("Golden Farmer", credential.get("credentialSubject").get("fullName").asText());

        // independent verification: danubetech verifier with the key the service publishes in did.json
        byte[] publicKey = ed25519PublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new Ed25519Signature2020LdVerifier(publicKey).verify(jsonLd), "ldp_vc proof must verify with danubetech");

        Goldens.assertGolden("v1/issuance/ldp_vc-response", body);
    }

    @Test
    void sdJwtIssuanceGoldenAndIndependentVerification() throws Exception {
        MvcResult result = issue(SDJWT_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String sdJwt = body.get("credentials").get(0).get("credential").asText();
        String[] parts = sdJwt.split("~");
        assertTrue(parts.length >= 3, "issuer JWS plus two disclosures: " + parts.length);

        JWSObject jws = JWSObject.parse(parts[0]);
        assertEquals("dc+sd-jwt", jws.getHeader().getType().getType());
        assertNotNull(jws.getHeader().getX509CertChain(), "x5c is present");
        JsonNode payload = objectMapper.readTree(jws.getPayload().toString());
        assertEquals("GoldenCredential", payload.get("vct").asText());
        assertEquals(issuerIdentifier, payload.get("iss").asText(), "SD-JWT iss is mosip.certify.identifier");
        assertTrue(payload.has("_sd"), "selective disclosure digests present");
        assertEquals("1990-01-01", payload.get("dateOfBirth").asText(), "non-SD claim stays in clear");

        // independent verification with Nimbus against the JWKS the service publishes
        JWKSet jwks = JWKSet.parse(getJson("/.well-known/jwks.json").toString());
        JWK key = jwks.getKeyByKeyId(jws.getHeader().getKeyID());
        assertNotNull(key, "kid " + jws.getHeader().getKeyID() + " must be in jwks.json");
        assertTrue(jws.verify(new ECDSAVerifier(key.toECKey())), "SD-JWT issuer signature must verify with Nimbus");

        Goldens.assertGolden("v1/issuance/dc+sd-jwt-payload", payload);
        Goldens.assertGolden("v1/issuance/dc+sd-jwt-header", objectMapper.readTree(jws.getHeader().toString()));
    }

    @Test
    void dataIntegrityIssuanceGoldenAndIndependentVerification() throws Exception {
        MvcResult result = issue(DI_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("DataIntegrityProof", credential.get("proof").get("type").asText());
        assertEquals("eddsa-rdfc-2022", credential.get("proof").get("cryptosuite").asText());
        assertEquals("https://www.w3.org/ns/credentials/v2", credential.get("@context").get(0).asText());

        byte[] publicKey = ed25519PublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new DataIntegrityProofLdVerifier(new Ed25519_EdDSA_PublicKeyVerifier(publicKey)).verify(jsonLd),
                "eddsa-rdfc-2022 proof must verify with danubetech");

        Goldens.assertGolden("v1/issuance/ldp_vc-data-integrity-response", body);
    }

    @Test
    void rsaIssuanceGoldenAndIndependentVerification() throws Exception {
        MvcResult result = issue(RSA_ID, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("RsaSignature2018", credential.get("proof").get("type").asText());
        assertTrue(credential.get("proof").has("jws"));

        java.security.interfaces.RSAPublicKey publicKey = rsaPublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new RsaSignature2018LdVerifier(publicKey).verify(jsonLd), "RsaSignature2018 proof must verify with danubetech");

        Goldens.assertGolden("v1/issuance/ldp_vc-rsa-response", body);
    }

    @Test
    void ed25519Signature2018GoldenAndIndependentVerification() throws Exception {
        JsonNode body = issuedBody(ED_2018_ID);
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("Ed25519Signature2018", credential.get("proof").get("type").asText());
        assertTrue(credential.get("proof").has("jws"), "2018 suites carry a detached jws");
        byte[] publicKey = ed25519PublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier(publicKey).verify(jsonLd),
                "Ed25519Signature2018 proof must verify with danubetech");
        Goldens.assertGolden("v1/issuance/ldp_vc-ed25519-2018-response", body);
    }

    @Test
    void ecdsaSecp256k1Signature2019GoldenAndIndependentVerification() throws Exception {
        JsonNode body = issuedBody(EC_K1_ID);
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("EcdsaSecp256k1Signature2019", credential.get("proof").get("type").asText());
        assertTrue(credential.get("proof").has("jws"));
        JsonNode method = verificationMethod(credential.get("proof").get("verificationMethod").asText());
        assertEquals("EcdsaSecp256k1VerificationKey2019", method.get("type").asText());
        JWK jwk = JWK.parse(method.get("publicKeyJwk").toString());
        java.security.PublicKey publicKey = jwk.toECKey().toECPublicKey(com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton.getInstance());
        // danubetech canonicalizes and parses the detached JWS; the ES256K signature itself is checked by plain JCA
        com.danubetech.keyformats.crypto.ByteVerifier jca = new com.danubetech.keyformats.crypto.ByteVerifier(com.danubetech.keyformats.jose.JWSAlgorithm.ES256K) {
            @Override
            protected boolean verify(byte[] content, byte[] signature) throws java.security.GeneralSecurityException {
                java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA", "BC");
                verifier.initVerify(publicKey);
                verifier.update(content);
                try {
                    return verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(signature));
                } catch (com.nimbusds.jose.JOSEException e) {
                    throw new java.security.SignatureException(e);
                }
            }
        };
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new info.weboftrust.ldsignatures.verifier.EcdsaSecp256k1Signature2019LdVerifier(jca).verify(jsonLd),
                "EcdsaSecp256k1Signature2019 proof must verify with danubetech + JCA");
        Goldens.assertGolden("v1/issuance/ldp_vc-secp256k1-2019-response", body);
    }

    /**
     * EcdsaSecp256r1Signature2019 is Certify's own suite name (no registered LD suite, no third-party verifier exists);
     * verified here by canonicalizing with danubetech and checking the ECDSA signature with plain JCA against the
     * P-256 key in did.json. Logged as a spec finding in PROGRESS.md; the registered equivalent is ecdsa-rdfc-2019.
     */
    @Test
    void ecdsaSecp256r1Signature2019GoldenAndJcaVerification() throws Exception {
        JsonNode body = issuedBody(EC_R1_ID);
        JsonNode credential = body.get("credentials").get(0).get("credential");
        assertEquals("EcdsaSecp256r1Signature2019", credential.get("proof").get("type").asText());
        JsonNode method = verificationMethod(credential.get("proof").get("verificationMethod").asText());
        assertEquals("EcdsaSecp256r1VerificationKey2019", method.get("type").asText());
        byte[] multicodec = Multibase.decode(method.get("publicKeyMultibase").asText());
        byte[] compressed = Arrays.copyOfRange(multicodec, 2, multicodec.length); // strip 0x8024 (p256-pub)
        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
        java.security.PublicKey publicKey = java.security.KeyFactory.getInstance("EC", "BC").generatePublic(
                new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getCurve().decodePoint(compressed), spec));

        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        info.weboftrust.ldsignatures.LdProof proof = info.weboftrust.ldsignatures.LdProof.getFromJsonLDObject(jsonLd);
        byte[] signature = Multibase.decode(proof.getProofValue());
        info.weboftrust.ldsignatures.LdProof options = info.weboftrust.ldsignatures.LdProof.builder().base(proof).defaultContexts(false).build(); // as CredentialUtils.generateLdProof canonicalizes
        info.weboftrust.ldsignatures.LdProof.removeLdProofValues(options);
        info.weboftrust.ldsignatures.LdProof.removeFromJsonLdObject(jsonLd);
        byte[] hash = new info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer().canonicalize(options, jsonLd);
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(publicKey);
        verifier.update(hash);
        assertTrue(verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(signature)),
                "EcdsaSecp256r1Signature2019 proofValue must verify with JCA over the URDNA2015 hash");
        Goldens.assertGolden("v1/issuance/ldp_vc-secp256r1-2019-response", body);
    }

    /** The flow docs/design/VALIDATE.md drives by hand: offer, offer fetch, token; the access token is verified against jwks.json. */
    @Test
    void preAuthorizedCodeFlowGoldenAndAccessTokenVerification() throws Exception {
        MvcResult offerResult = mockMvc.perform(post("/pre-authorized-data").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", LDP_ID, "claims", Map.of("fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru"),
                        "expires_in", 600, "tx_code", "1234")))).andReturn();
        JsonNode offerBody = objectMapper.readTree(offerResult.getResponse().getContentAsString());
        assertEquals(200, offerResult.getResponse().getStatus(), offerBody.toString());
        assertTrue(offerBody.has("credential_offer_uri"), "offer response: " + offerBody);
        String offerUri = offerBody.get("credential_offer_uri").asText();
        assertTrue(offerUri.startsWith("openid-credential-offer://"), offerUri);
        String offerUrl = java.net.URLDecoder.decode(offerUri.substring(offerUri.indexOf("credential_offer_uri=") + "credential_offer_uri=".length()), StandardCharsets.UTF_8);
        String offerId = offerUrl.substring(offerUrl.lastIndexOf('/') + 1);
        Goldens.assertGolden("v1/pre-authorized/offer-uri", offerBody);

        JsonNode offer = getJson("/credential-offer-data/" + offerId);
        // Finding (PROGRESS.md): the offer names the issuer as mosip.certify.identifier (with servlet path) while the
        // issuer metadata's credential_issuer is mosip.certify.domain.url; OpenID4VCI requires the same identifier.
        assertEquals(issuerIdentifier, offer.get("credential_issuer").asText());
        assertNotEquals(domainUrl, offer.get("credential_issuer").asText(), "the two identity keys still differ (dual identity finding)");
        assertEquals(LDP_ID, offer.get("credential_configuration_ids").get(0).asText());
        JsonNode grant = offer.get("grants").get("urn:ietf:params:oauth:grant-type:pre-authorized_code");
        String code = grant.get("pre-authorized_code").asText();
        Goldens.assertGolden("v1/pre-authorized/credential-offer", offer);

        MvcResult tokenResult = mockMvc.perform(post("/oauth/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                .param("pre-authorized_code", code).param("tx_code", "1234")).andReturn();
        JsonNode token = objectMapper.readTree(tokenResult.getResponse().getContentAsString());
        assertEquals(200, tokenResult.getResponse().getStatus(), token.toString());
        assertEquals("Bearer", token.get("token_type").asText());
        SignedJWT accessToken = SignedJWT.parse(token.get("access_token").asText());
        JWKSet jwks = JWKSet.parse(getJson("/.well-known/jwks.json").toString());
        JWK key = jwks.getKeyByKeyId(accessToken.getHeader().getKeyID());
        assertNotNull(key, "access token kid " + accessToken.getHeader().getKeyID() + " must be in jwks.json");
        assertTrue(accessToken.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(key.toRSAKey())), "access token must verify with Nimbus");
        assertEquals(SCOPE, accessToken.getJWTClaimsSet().getStringClaim("scope"));
        Goldens.assertGolden("v1/pre-authorized/token-response", token);
        // Finding (PROGRESS.md): sub carries the offer claims as a JSON string in map order (PII inside the access token,
        // nondeterministic key order); parsed here so the golden is stable while the finding stands.
        com.fasterxml.jackson.databind.node.ObjectNode claims = (com.fasterxml.jackson.databind.node.ObjectNode) objectMapper.readTree(accessToken.getJWTClaimsSet().toString());
        claims.set("sub", objectMapper.readTree(claims.get("sub").asText()));
        Goldens.assertGolden("v1/pre-authorized/access-token-claims", claims);
        Goldens.assertGolden("v1/pre-authorized/access-token-header", objectMapper.readTree(accessToken.getHeader().toString()));
    }

    @Test
    void wrongNonceIsRejectedGolden() throws Exception {
        nonce();
        MvcResult result = issue(LDP_ID, proofJwt("not-the-nonce"));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        Goldens.assertGolden("v1/issuance/error-invalid-nonce", objectMapper.createObjectNode()
                .put("status", result.getResponse().getStatus()).set("body", Goldens.normalize(body)));
    }

    @Test
    void unknownConfigurationIsRejectedGolden() throws Exception {
        MvcResult result = issue("NoSuchCredential", proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        Goldens.assertGolden("v1/issuance/error-unknown-configuration", objectMapper.createObjectNode()
                .put("status", result.getResponse().getStatus()).set("body", Goldens.normalize(body)));
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private JsonNode getJson(String path) throws Exception {
        return objectMapper.readTree(mockMvc.perform(get(path)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private String nonce() throws Exception {
        return objectMapper.readTree(mockMvc.perform(post("/nonce")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private JsonNode issuedBody(String configurationId) throws Exception {
        MvcResult result = issue(configurationId, proofJwt(nonce()));
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        return body;
    }

    private JsonNode verificationMethod(String id) throws Exception {
        for (JsonNode method : getJson("/.well-known/did.json").get("verificationMethod")) {
            if (id.equals(method.get("id").asText())) {
                return method;
            }
        }
        throw new AssertionError("verification method " + id + " not in did.json");
    }

    private MvcResult issue(String configurationId, String proof) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
                "credential_configuration_id", configurationId,
                "proofs", Map.of("jwt", List.of(proof))));
        return mockMvc.perform(post("/issuance/credential")
                .header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
    }

    /** A holder proof as a wallet builds it: ES256, typ openid4vci-proof+jwt, public jwk in the header. */
    private String proofJwt(String nonce) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holder.toPublicJWK()).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().audience(issuerIdentifier).issueTime(new Date())
                .claim("nonce", nonce).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    private byte[] ed25519PublicKeyFromDidDocument(String verificationMethod) throws Exception {
        JsonNode did = getJson("/.well-known/did.json");
        for (JsonNode method : did.get("verificationMethod")) {
            if (verificationMethod.equals(method.get("id").asText())) {
                byte[] decoded = Multibase.decode(method.get("publicKeyMultibase").asText());
                return Arrays.copyOfRange(decoded, 2, decoded.length); // strip the 0xed01 multicodec prefix
            }
        }
        throw new AssertionError("verification method " + verificationMethod + " not in did.json: " + did);
    }

    private java.security.interfaces.RSAPublicKey rsaPublicKeyFromDidDocument(String verificationMethod) throws Exception {
        JsonNode did = getJson("/.well-known/did.json");
        for (JsonNode method : did.get("verificationMethod")) {
            if (verificationMethod.equals(method.get("id").asText())) {
                String pem = method.get("publicKeyPem").asText().replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
                return (java.security.interfaces.RSAPublicKey) java.security.KeyFactory.getInstance("RSA")
                        .generatePublic(new java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(pem)));
            }
        }
        throw new AssertionError("verification method " + verificationMethod + " not in did.json: " + did);
    }

    private static String template(String name) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates", name);
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Base64.getEncoder().encodeToString(Files.readString(path, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8));
    }

    private static MetaDataDisplayDTO display(String name) {
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(name);
        display.setLocale("en");
        return display;
    }

    private static ClaimsDTO claim(String name) {
        ClaimsDTO.Display display = new ClaimsDTO.Display();
        display.setName(name);
        display.setLocale("en");
        ClaimsDTO claims = new ClaimsDTO();
        claims.setDisplay(List.of(display));
        return claims;
    }

    private static CredentialConfigurationDTO ldpConfig() throws Exception {
        return ldpConfig(LDP_ID, "golden-ldp.vm", "https://www.w3.org/2018/credentials/v1",
                "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "Ed25519Signature2020");
    }

    private static CredentialConfigurationDTO ldpConfig(String id, String templateFile, String context, String appId,
                                                        String refId, String algo, String suite) throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(id);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(template(templateFile));
        dto.setContextURLs(List.of(context));
        dto.setCredentialTypes(List.of("VerifiableCredential", "GoldenCredential"));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId(appId);
        dto.setKeyManagerRefId(refId);
        dto.setSignatureAlgo(algo);
        dto.setSignatureCryptoSuite(suite);
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Golden Credential")));
        dto.setDisplayOrder(List.of("fullName", "dateOfBirth", "city"));
        dto.setClaims(Map.of("fullName", claim("Full name"), "dateOfBirth", claim("Date of birth"), "city", claim("City")));
        return dto;
    }

    private static CredentialConfigurationDTO sdJwtConfig() throws Exception {
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(SDJWT_ID);
        dto.setCredentialFormat("dc+sd-jwt");
        dto.setVcTemplate(template("golden-sdjwt.vm"));
        dto.setSdJwtVct("GoldenCredential");
        dto.setSdClaim("$.fullName,$.address.city");
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        dto.setKeyManagerRefId("EC_SECP256R1_SIGN");
        dto.setSignatureAlgo("ES256"); // SD-JWT configs carry no cryptosuite (SdJwtCredentialConfigValidator)
        dto.setScope(SCOPE);
        dto.setMetaDataDisplay(List.of(display("Golden SD-JWT Credential")));
        dto.setDisplayOrder(List.of("fullName", "dateOfBirth"));
        ClaimsDisplayFieldsConfigDTO fullName = new ClaimsDisplayFieldsConfigDTO();
        dto.setSdJwtClaims(Map.of("fullName", fullName));
        return dto;
    }
}
