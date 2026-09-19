package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.core.dto.ClaimsDTO;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Every holder key form the 1.0.0-beta.1 proof validator accepted still issues on the new surface and on the
 * compatibility surface, and binds the same subject identifier: an inline {@code jwk} header (P-256, Ed25519, RSA
 * with RS256 and PS256) becomes a {@code did:jwk}, a {@code kid} of the form {@code did:jwk:...#0} or
 * {@code did:key:...} (Ed25519 0xed01, P-256 0x1200, secp256k1 0xe701, RSA 0x1205 multicodecs) is carried as is.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.data-provider-plugin.id-field-prefix-uri=urn:uuid:",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:key','did:web'}}",
        "certify.protocol.oid4vci-v1.did-web-holders.enabled=true",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'RS256','PS256','ES256','ES256K','EdDSA'}}}"
})
class HolderDidMethodsTest {

    static final String CONFIG_ID = "HolderDidMethodsCredential";
    static final JOSEObjectType PROOF_TYP = new JOSEObjectType("openid4vci-proof+jwt");

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @MockBean io.mosip.certify.proof.DidDocumentFetcher didDocuments;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    /** A holder key as a wallet presents it: {@code kid == null} puts the public JWK in the header. */
    record Holder(String label, JWK key, JWSAlgorithm alg, String kid) {
        @Override
        public String toString() {
            return label;
        }
    }

    /** The key behind did:web:wallet.example#key-1; the stubbed fetcher serves its DID document. */
    static final ECKey DID_WEB_KEY = generateP256();

    static Stream<Holder> holders() throws Exception {
        ECKey p256 = new ECKeyGenerator(Curve.P_256).generate();
        ECKey k256 = new ECKeyGenerator(Curve.SECP256K1).provider(BouncyCastleProviderSingleton.getInstance()).generate();
        OctetKeyPair ed25519 = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        RSAKey rsa = new RSAKeyGenerator(2048).generate();
        return Stream.of(
                new Holder("jwk P-256 ES256", p256, JWSAlgorithm.ES256, null),
                new Holder("jwk Ed25519 EdDSA", ed25519, JWSAlgorithm.EdDSA, null),
                new Holder("jwk RSA RS256", rsa, JWSAlgorithm.RS256, null),
                new Holder("jwk RSA PS256", rsa, JWSAlgorithm.PS256, null),
                new Holder("kid did:jwk P-256", p256, JWSAlgorithm.ES256, didJwk(p256)),
                new Holder("kid did:key Ed25519", ed25519, JWSAlgorithm.EdDSA, didKey(new byte[]{(byte) 0xed, 0x01}, ed25519.getX().decode())),
                new Holder("kid did:key P-256", p256, JWSAlgorithm.ES256, didKey(new byte[]{(byte) 0x80, 0x24}, compressed("secp256r1", p256))),
                new Holder("kid did:key secp256k1", k256, JWSAlgorithm.ES256K, didKey(new byte[]{(byte) 0xe7, 0x01}, compressed("secp256k1", k256))),
                new Holder("kid did:key RSA", rsa, JWSAlgorithm.RS256, didKey(new byte[]{(byte) 0x85, 0x24},
                        new RSAPublicKey(rsa.getModulus().decodeToBigInteger(), rsa.getPublicExponent().decodeToBigInteger()).getEncoded("DER"))),
                new Holder("kid did:web P-256 (did-web-holders.enabled)", DID_WEB_KEY, JWSAlgorithm.ES256, "did:web:wallet.example#key-1"));
    }

    static ECKey generateP256() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Bound Farmer", "dateOfBirth", "1990-01-01", "city", "Pune")));
        when(didDocuments.fetch(any())).thenAnswer(inv -> {
            if (!"https://wallet.example/.well-known/did.json".equals(inv.getArgument(0).toString())) {
                throw new java.io.IOException("404 " + inv.getArgument(0));
            }
            return "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"did:web:wallet.example\",\"verificationMethod\":[{\"id\":\"did:web:wallet.example#key-1\","
                    + "\"type\":\"JsonWebKey2020\",\"controller\":\"did:web:wallet.example\",\"publicKeyJwk\":" + DID_WEB_KEY.toPublicJWK().toJSONString() + "}]}";
        });
        if (credentialConfigRepository.findByCredentialConfigKeyId(CONFIG_ID).isEmpty()) {
            credentialConfigurationService.addCredentialConfiguration(config());
        }
    }

    @ParameterizedTest
    @MethodSource("holders")
    void newSurfaceBindsTheHolder(Holder holder) throws Exception {
        String nonce = nonce("/oid4vci/nonce");
        MvcResult result = mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID,
                        "proofs", Map.of("jwt", List.of(proof(holder, nonce, issuerIdentifier + "/oid4vci"))))))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), holder + ": " + body);
        assertSubject(holder, body.get("credentials").get(0).get("credential"));
    }

    @ParameterizedTest
    @MethodSource("holders")
    void compatibilitySurfaceBindsTheHolder(Holder holder) throws Exception {
        String nonce = nonce("/nonce");
        MvcResult result = mockMvc.perform(post("/issuance/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", CONFIG_ID,
                        "proofs", Map.of("jwt", List.of(proof(holder, nonce, issuerIdentifier))))))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), holder + ": " + body);
        assertSubject(holder, body.get("credentials").get(0).get("credential"));
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"/oid4vci/.well-known/openid-credential-issuer", "/.well-known/openid-credential-issuer"})
    void metadataAdvertisesTheBindingMethodsAndProofAlgorithms(String path) throws Exception {
        JsonNode metadata = objectMapper.readTree(mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(path))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        JsonNode entry = metadata.get("credential_configurations_supported").get(CONFIG_ID);
        // H2 stores TEXT[] as VARCHAR and reads the list back as one bracketed element; PostgreSQL keeps the array
        List<String> raw = objectMapper.convertValue(entry.get("cryptographic_binding_methods_supported"), objectMapper.getTypeFactory().constructCollectionType(List.class, String.class));
        String bindingMethods = String.join(",", raw);
        assertTrue(bindingMethods.contains("did:jwk") && bindingMethods.contains("did:key") && bindingMethods.contains("did:web"), path + ": " + bindingMethods);
        assertEquals(List.of("RS256", "PS256", "ES256", "ES256K", "EdDSA"),
                objectMapper.convertValue(entry.get("proof_types_supported").get("jwt").get("proof_signing_alg_values_supported"), List.class), path);
    }

    private static void assertSubject(Holder holder, JsonNode credential) throws Exception {
        String id = credential.get("credentialSubject").get("id").asText();
        if (holder.kid() != null) {
            assertEquals(holder.kid(), id, holder.label());
            return;
        }
        assertTrue(id.startsWith("did:jwk:"), holder + ": " + id);
        JWK bound = JWK.parse(new String(Base64.getUrlDecoder().decode(id.substring("did:jwk:".length())), StandardCharsets.UTF_8));
        assertEquals(holder.key().toPublicJWK().computeThumbprint(), bound.computeThumbprint(), holder.label());
    }

    private String nonce(String path) throws Exception {
        return objectMapper.readTree(mockMvc.perform(post(path)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private static String proof(Holder holder, String nonce, String audience) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(holder.alg()).type(PROOF_TYP);
        if (holder.kid() == null) {
            header.jwk(holder.key().toPublicJWK());
        } else {
            header.keyID(holder.kid());
        }
        SignedJWT jwt = new SignedJWT(header.build(), new JWTClaimsSet.Builder().audience(audience).issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(signer(holder.key()));
        return jwt.serialize();
    }

    private static JWSSigner signer(JWK key) throws Exception {
        if (key instanceof ECKey ec) {
            ECDSASigner signer = new ECDSASigner(ec);
            signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
            return signer;
        }
        if (key instanceof OctetKeyPair okp) {
            return new Ed25519Signer(okp);
        }
        return new RSASSASigner((RSAKey) key);
    }

    private static String didJwk(JWK key) {
        return "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(key.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8)) + "#0";
    }

    private static String didKey(byte[] multicodec, byte[] key) {
        byte[] bytes = new byte[multicodec.length + key.length];
        System.arraycopy(multicodec, 0, bytes, 0, multicodec.length);
        System.arraycopy(key, 0, bytes, multicodec.length, key.length);
        return "did:key:" + Multibase.encode(Multibase.Base.Base58BTC, bytes);
    }

    private static byte[] compressed(String curve, ECKey key) {
        ECCurve ec = ECNamedCurveTable.getParameterSpec(curve).getCurve();
        return ec.createPoint(key.getX().decodeToBigInteger(), key.getY().decodeToBigInteger()).getEncoded(true);
    }

    private static CredentialConfigurationDTO config() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-ldp.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8).replace("\"GoldenCredential\": \"https://example.org/golden#GoldenCredential\"",
                "\"" + CONFIG_ID + "\": \"https://example.org/golden#" + CONFIG_ID + "\"").replace("\"GoldenCredential\"]", "\"" + CONFIG_ID + "\"]");
        CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
        dto.setCredentialConfigKeyId(CONFIG_ID);
        dto.setCredentialFormat("ldp_vc");
        dto.setVcTemplate(Base64.getEncoder().encodeToString(template.getBytes(StandardCharsets.UTF_8)));
        dto.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        dto.setCredentialTypes(List.of("VerifiableCredential", CONFIG_ID));
        dto.setDidUrl("did:web:localhost:certify");
        dto.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        dto.setKeyManagerRefId("ED25519_SIGN");
        dto.setSignatureAlgo("EdDSA");
        dto.setSignatureCryptoSuite("Ed25519Signature2020");
        dto.setScope("sample_vc_ldp");
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName(CONFIG_ID);
        display.setLocale("en");
        dto.setMetaDataDisplay(List.of(display));
        dto.setDisplayOrder(List.of("fullName"));
        ClaimsDTO claim = new ClaimsDTO();
        dto.setClaims(Map.of("fullName", claim));
        return dto;
    }
}
