package io.mosip.certify.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.upokecenter.cbor.CBORObject;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.db.FlywayDefaults;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.status.TokenStatusListService;
import org.flywaydb.core.Flyway;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * M-11e's escape hatch, proven through the surface a wallet uses (review round 1, minor 7): with
 * {@code certify.status.token-status-list.mdoc.token-format=jwt} an mDL issued through {@code /oid4vci} carries
 * {@code status.status_list} pointing at a {@code TokenStatusList} <b>JWT</b> row exactly as before M-11 (D-M11-3),
 * served as {@code application/statuslist+jwt}, and the entry it names is inside that list and VALID.
 *
 * <p>It has its own context — and therefore its own container and key store — because the token format is a deployment
 * setting: the main sample test runs the default ({@code cwt}), and a test cannot change a typed configuration bean for
 * one request. Kept apart, each context proves what it configures.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@Testcontainers(disabledWithoutDocker = true)
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "mosip.certify.batch.status-list-update.enabled=false",
        "certify.status.token-status-list.mdoc.token-format=jwt", // the escape hatch itself (D-M11-3)
        "certify.status.token-status-list.size-bits=8192",
        "certify.status.token-status-list.key-ref=x509-file:mdl-dsc@2026-11",
        "certify.keyprovider.x509-file.enabled=true",
        "certify.keyprovider.x509-file.dev-mode=true",
        "certify.keyprovider.x509-file.path=" + MdocStatusListJwtEscapeHatchTest.DIRECTORY + "/x509-file.p12",
        "certify.keyprovider.x509-file.password=mdoc-status-list",
        "certify.keyprovider.x509-file.iaca.country=IN",
        "certify.keyprovider.x509-file.iaca.common-name=Lorem Ipsum Sample IACA",
        "certify.keyprovider.x509-file.iaca.issuer-alt-name=https://certify.example.test/v1/certify/mdoc/iaca",
        "certify.keyprovider.x509-file.iaca.crl-uri=" + MdocStatusListJwtEscapeHatchTest.PUBLIC_BASE + "/mdoc/iaca/sample-iaca.crl",
        "certify.keyprovider.x509-file.keys[0].alias=mdl-dsc@2026-11",
        "certify.keyprovider.x509-file.keys[0].algorithm=ES256",
        "certify.keyprovider.x509-file.keys[0].subject=CN=Lorem Ipsum Sample DSC 2026",
        "certify.keyprovider.x509-file.keys[0].profile=mdoc-dsc",
        "mosip.certify.domain.url=" + MdocStatusListJwtEscapeHatchTest.PUBLIC_BASE,
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'ES256': {'ES256'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'mso_mdoc': {'cose_key'}, 'dc+sd-jwt': {'did:jwk','did:web'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256'}}}",
        "mosip.certify.oauth.grant-types-supported=authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect"
})
class MdocStatusListJwtEscapeHatchTest {

    static final String SCHEMA = "certify";
    static final String DIRECTORY = "target/mdoc-status-list-jwt-sample";
    static final String PUBLIC_BASE = "http://localhost:8090";
    static final String MDL = "org.iso.18013.5.1.mDL";
    static final String CONFIG = "MdocStatusListJwtEscapeHatch";
    static final String KEYMANAGER = "MdocStatusListJwtEscapeHatchKeymanager";

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");

    @DynamicPropertySource
    static void postgres(DynamicPropertyRegistry registry) throws Exception {
        String url = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/"
                + POSTGRES.getDatabaseName() + "?currentSchema=" + SCHEMA;
        DataSource dataSource = dataSource(url);
        Flyway.configure().dataSource(dataSource).schemas(SCHEMA).defaultSchema(SCHEMA)
                .locations(FlywayDefaults.DEFAULT_LOCATIONS.toArray(new String[0]))
                .baselineOnMigrate(true).baselineVersion(FlywayDefaults.BASELINE_VERSION).load().migrate();
        StatusListPostgresTest.seedKeyPolicies(dataSource);
        Path directory = Path.of(DIRECTORY);
        Files.createDirectories(directory);
        try (var files = Files.list(directory)) {
            for (Path file : files.toList()) {
                Files.delete(file);
            }
        }
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driverClassName", () -> "org.postgresql.Driver");
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.sql.init.mode", () -> "never");
        registry.add("mosip.kernel.keymanager.hsm.config-path", () -> DIRECTORY + "/keymanager.p12");
    }

    static DataSource dataSource(String url) {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(url);
        ds.setUser(POSTGRES.getUsername());
        ds.setPassword(POSTGRES.getPassword());
        return ds;
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired StatusListCredentialRepository listRepository;
    @Autowired DataSource dataSource;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of(
                "fullName", "Status List Holder", "dateOfBirth", "1990-01-01", "city", "Bengaluru")));
        if (listRepository.count() > 0) {
            return; // the configuration is written once for the class' database
        }
        configuration(CONFIG, MDL, "x509-file", "mdl-dsc@2026-11", "without-anchor");
        // a keymanager Document Signer: no configured IACA issued it, so the format refuses it before any index is taken,
        // whatever the status token format is (D-M11e-1)
        configuration(KEYMANAGER, MDL + ".keymanager", "keymanager", "CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN", null);
    }

    /** A v2 {@code mso_mdoc} entry with a {@code TokenStatusList}/{@code revocation} status block. */
    private void configuration(String id, String docType, String provider, String alias, String x5c) throws Exception {
        Map<String, Object> signing = new LinkedHashMap<>();
        signing.put("provider", provider);
        signing.put("alias", alias);
        signing.put("alg", "ES256");
        if (x5c != null) {
            signing.put("x5c", x5c); // ISO/IEC 18013-5 9.1.2.4: the IssuerAuth carries the DSC
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id);
        body.put("scope", "sample_vc_ldp");
        body.put("format", "mso_mdoc");
        body.put("formatConfig", Map.of("doctype", docType));
        body.put("signing", signing);
        body.put("template", Map.of("content", template().replace("\"" + MDL + "\"", "\"" + docType + "\"")));
        body.put("status", Map.of("mechanism", "TokenStatusList", "purposes", List.of("revocation")));
        body.put("display", Map.of("display", List.of(Map.of("name", id, "locale", "en")), "order", List.of("family_name")));
        MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body))).andReturn();
        assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
    }

    /**
     * The escape hatch does not weaken the Document Signer policy either: with {@code mdoc.token-format=jwt} a keymanager
     * DSC, which no configured IACA issued, is still refused before the status step takes an index (owner decision
     * D-M11e-1), and the mDL's JWT list would not have been usable by a wallet anyway.
     */
    @Test
    void aKeymanagerDocumentSignerIsRefusedBeforeAnIndexIsConsumed() throws Exception {
        long freeBefore = freeIndices();

        MvcResult refused = issue(KEYMANAGER);

        assertEquals(500, refused.getResponse().getStatus(), refused.getResponse().getContentAsString());
        String description = objectMapper.readTree(refused.getResponse().getContentAsString()).get("error_description").asText();
        assertTrue(description.contains("NO_TRUSTED_IACA"), description);
        assertEquals(freeBefore, freeIndices(), "no index was consumed by the refused mDL");
    }

    /** The mDL request of {@link #anMdlIssuedThroughTheSurfaceNamesAJwtList}, for a given configuration. */
    private MvcResult issue(String configurationId) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        String nonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andReturn().getResponse().getContentAsString())
                .get("c_nonce").asText();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci").issueTime(new Date())
                .claim("nonce", nonce).build();
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build(), claims);
        proof.sign(new ECDSASigner(holder));
        return mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                        "credential_configuration_id", configurationId,
                        "proofs", Map.of("jwt", List.of(proof.serialize())))))).andReturn();
    }

    /** Free (unassigned) status-list indices in the whole database: what a refused issuance must not touch. */
    private long freeIndices() throws Exception {
        try (java.sql.Connection c = dataSource.getConnection();
             java.sql.PreparedStatement ps = c.prepareStatement("SELECT count(*) FROM " + SCHEMA
                     + ".status_list_available_indices WHERE is_assigned = false");
             java.sql.ResultSet rows = ps.executeQuery()) {
            rows.next();
            return rows.getLong(1);
        }
    }

    /**
     * The escape hatch, through the wallet's surface: the {@code uri} in the MSO names a {@code TokenStatusList} <b>JWT</b>
     * row, the endpoint answers it as {@code application/statuslist+jwt} with {@code typ statuslist+jwt}, and the entry
     * the mDL names is inside that list and VALID.
     */
    @Test
    void anMdlIssuedThroughTheSurfaceNamesAJwtList() throws Exception {
        MvcResult issued = issue(CONFIG);
        JsonNode body = objectMapper.readTree(issued.getResponse().getContentAsString());
        assertEquals(200, issued.getResponse().getStatus(), body.toString());

        CBORObject issuerAuth = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(body.get("credentials").get(0)
                .get("credential").asText())).get("issuerAuth");
        if (issuerAuth.isTagged()) {
            issuerAuth = issuerAuth.Untag();
        }
        CBORObject mso = CBORObject.DecodeFromBytes(issuerAuth.get(2).GetByteString());
        if (mso.HasMostOuterTag(24)) {
            mso = CBORObject.DecodeFromBytes(mso.Untag().GetByteString());
        }
        CBORObject statusList = mso.get("status").get("status_list");
        String uri = statusList.get("uri").AsString();
        long idx = statusList.get("idx").AsInt64Value();
        String listId = uri.substring(uri.lastIndexOf('/') + 1);

        assertEquals(TokenStatusListService.TYPE, listRepository.findById(listId).orElseThrow().getCredentialType(),
                "token-format=jwt keeps the pre-M-11 JWT row for an mso_mdoc (D-M11-3)");
        MvcResult served = mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn();
        assertEquals(200, served.getResponse().getStatus());
        assertEquals(TokenStatusListService.MEDIA_TYPE, served.getResponse().getContentType());
        String jwt = served.getResponse().getContentAsString();
        assertEquals(TokenStatusListService.TYP, SignedJWT.parse(jwt).getHeader().getType().getType());
        assertEquals(uri, SignedJWT.parse(jwt).getJWTClaimsSet().getSubject(), "the list names the URI the mDL carries");

        Map<String, Object> claim = SignedJWT.parse(jwt).getJWTClaimsSet().getJSONObjectClaim("status_list");
        assertEquals(1, ((Number) claim.get("bits")).intValue(), "a Token Status List carries one bit per status");
        byte[] bits = TokenStatusListService.decode(String.valueOf(claim.get("lst")));
        assertTrue(idx < (long) bits.length * 8, "the index is inside the list it names");
        assertFalse(TokenStatusListService.get(bits, idx), "a fresh mDL is VALID");
        assertTrue(uri.startsWith(PUBLIC_BASE), uri);
    }

    private static String template() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-mdoc.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }
}
