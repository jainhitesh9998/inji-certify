package io.mosip.certify.golden;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.document.JsonDocument;
import com.danubetech.dataintegrity.verifier.DataIntegrityProofLdVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
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
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.config.contextloader.StaticContextLoader;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.db.FlywayDefaults;
import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.services.StatusListUpdateBatchJob;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageRequest;
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
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The status-list feature end to end on PostgreSQL, which H2 cannot run ({@code generate_series} in
 * {@code StatusListCredentialService.initializeAvailableIndices}): the database is prepared the way a deployment
 * prepares it (the Flyway chain, then the keymanager policy rows of {@code db_scripts/inji_certify/dml}), the service
 * starts on it with Flyway enabled, and a VC 2.0 {@code ldp_vc} with a revocation purpose is issued through the new
 * surface and through the compatibility surface. The credential, the Bitstring Status List credential it points to
 * and the re-signed list after a revocation are all verified with danubetech; the goldens are recorded under
 * {@code goldens/oid4vci-1.0/oid4vci}, {@code goldens/oid4vci-1.0/status-list} and {@code goldens/legacy-develop/issuance}.
 * Skipped without Docker.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"}) // local activates the TestBearer filters; test (last) wins for properties
@Testcontainers(disabledWithoutDocker = true)
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=true",
        "mosip.certify.indexed-mappings.city=$.city",
        "mosip.certify.data-provider-plugin.id-field-prefix-uri=urn:uuid:", // the ledger keys rows by credential id
        "mosip.certify.batch.status-list-update.enabled=false", // the test drives the batch step itself
        "mosip.certify.authn.filter-urls={'/issuance/credential'}",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}, 'ES256K': {{'CERTIFY_VC_SIGN_EC_K1','EC_SECP256K1_SIGN'}}, 'RS256': {{'CERTIFY_VC_SIGN_RSA',''}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'eddsa-rdfc-2022': {'EdDSA'}}",
        "mosip.certify.oauth.grant-types-supported=authorization_code,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA','RS256','PS256'}}}"
})
class StatusListPostgresTest {

    static final String SCHEMA = "certify";
    static final String STATUS_ID = IssuanceGoldenTest.STATUS_ID;
    static final String STATUS_LIST_PATH = "/v1/certify/credentials/status-list/";
    static final Path KEYSTORE = Path.of("target", "status-list-postgres.p12");

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");

    /** What a deployment does before the service starts: the Flyway job, then the keymanager policy rows from db_scripts. */
    @DynamicPropertySource
    static void postgres(DynamicPropertyRegistry registry) throws Exception {
        String url = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/"
                + POSTGRES.getDatabaseName() + "?currentSchema=" + SCHEMA;
        DataSource dataSource = dataSource(url);
        Flyway.configure().dataSource(dataSource).schemas(SCHEMA).defaultSchema(SCHEMA)
                .locations(FlywayDefaults.DEFAULT_LOCATIONS.toArray(new String[0]))
                .baselineOnMigrate(true).baselineVersion(FlywayDefaults.BASELINE_VERSION)
                .load().migrate();
        seedKeyPolicies(dataSource);
        Files.deleteIfExists(KEYSTORE); // fresh keys for the fresh key_alias table

        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driverClassName", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.flyway.enabled", () -> "true");   // the service validates the chain it starts on
        registry.add("spring.sql.init.mode", () -> "never");   // schema.sql and data.sql are H2 only
        registry.add("mosip.kernel.keymanager.hsm.config-path", () -> KEYSTORE.toString());
    }

    static DataSource dataSource(String url) {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(url);
        ds.setUser(POSTGRES.getUsername());
        ds.setPassword(POSTGRES.getPassword());
        return ds;
    }

    /** The rows of db_scripts/inji_certify/dml/certify-key_policy_def.csv, which init_db.sh loads with psql \COPY. */
    static void seedKeyPolicies(DataSource dataSource) throws Exception {
        List<String> lines = Files.readAllLines(locate("db_scripts/inji_certify/dml/certify-key_policy_def.csv"), StandardCharsets.UTF_8);
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement("INSERT INTO " + SCHEMA
                + ".key_policy_def (app_id, key_validity_duration, pre_expire_days, access_allowed, is_active, cr_by, cr_dtimes) VALUES (?, ?, ?, ?, ?, ?, NOW())")) {
            for (String line : lines.subList(1, lines.size())) {
                if (line.isBlank()) {
                    continue;
                }
                String[] f = line.split(",");
                ps.setString(1, f[0]);
                ps.setInt(2, Integer.parseInt(f[1]));
                ps.setInt(3, Integer.parseInt(f[2]));
                ps.setString(4, f[3]);
                ps.setBoolean(5, Boolean.parseBoolean(f[4]));
                ps.setString(6, f[5]);
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    static Path locate(String relative) {
        Path dir = Paths.get("").toAbsolutePath();
        while (dir != null) {
            Path candidate = dir.resolve(relative);
            if (Files.exists(candidate)) {
                return candidate;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException(relative + " not found above " + Paths.get("").toAbsolutePath());
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired CredentialConfigurationService credentialConfigurationService;
    @Autowired CredentialConfigRepository credentialConfigRepository;
    @Autowired StaticContextLoader staticContextLoader;
    @Autowired LedgerRepository ledgerRepository;
    @Autowired CredentialStatusTransactionRepository transactionRepository;
    @Autowired StatusListUpdateBatchJob batchJob;
    @Autowired Flyway flyway;
    @Autowired DataSource dataSource;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;
    @Value("${mosip.certify.domain.url}") String domainUrl;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of(
                "fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "city", "Bengaluru")));
        if (credentialConfigRepository.findByCredentialConfigKeyId(STATUS_ID).isEmpty()) {
            CredentialConfigurationDTO status = IssuanceGoldenTest.ldpConfig(STATUS_ID, "golden-ldp-status.vm",
                    "https://www.w3.org/ns/credentials/v2", "CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN", "EdDSA", "eddsa-rdfc-2022");
            status.setCredentialTypes(List.of("VerifiableCredential", STATUS_ID));
            status.setCredentialStatusPurposes(List.of("revocation"));
            credentialConfigurationService.addCredentialConfiguration(status);
        }
    }

    @Test
    void serviceStartsOnTheFlywayChain() throws Exception {
        try (Connection c = dataSource.getConnection()) {
            assertTrue(c.getMetaData().getURL().startsWith("jdbc:postgresql:"), c.getMetaData().getURL());
        }
        assertEquals(0, flyway.info().pending().length, "the service found nothing left to migrate");
        assertEquals(List.of("1.0.0.000", "1.0.0.001", "1.0.0.002", "1.0.0.003", "1.1.0.000"), // plus Flyway's own schema-creation row
                Arrays.stream(flyway.info().applied()).map(MigrationInfo::getVersion).filter(java.util.Objects::nonNull).map(Object::toString).toList());
    }

    @Test
    void oid4vciStatusIssuanceGoldenAndIndependentVerification() throws Exception {
        JsonNode body = issueOid4vci();
        JsonNode credential = body.get("credentials").get(0).get("credential");
        JsonNode status = credential.get("credentialStatus");
        assertNotNull(status, "credentialStatus expected: " + credential);
        assertEquals("BitstringStatusListEntry", status.get("type").asText());
        assertEquals("revocation", status.get("statusPurpose").asText());
        String listUrl = status.get("statusListCredential").asText();
        assertTrue(listUrl.startsWith(domainUrl + STATUS_LIST_PATH), listUrl);
        long index = Long.parseLong(status.get("statusListIndex").asText());
        assertEquals(listUrl + "#" + index, status.get("id").asText());
        verifyDataIntegrity(credential);
        Goldens.assertGolden("oid4vci-1.0/oid4vci/ldp_vc-status-response", body);

        // the list the entry points to is published, verifiable, and the entry's bit is clear
        JsonNode list = statusList(listUrl);
        assertEquals("BitstringStatusListCredential", list.get("type").get(1).asText());
        assertEquals(listUrl, list.get("id").asText());
        assertEquals("revocation", list.get("credentialSubject").get("statusPurpose").asText());
        assertFalse(bit(list.get("credentialSubject").get("encodedList").asText(), index), "a fresh entry is not revoked");
        verifyStatusList(list);
        Goldens.assertGolden("oid4vci-1.0/status-list/bitstring-status-list-credential", list);

        // the ledger row the new surface's listener writes carries the status entry and the indexed plugin data
        Ledger ledger = ledgerRepository.findByCredentialId(credential.get("id").asText()).orElseThrow();
        assertEquals(index, ledger.getCredentialStatusDetails().get(0).getStatusListIndex());
        assertEquals("revocation", ledger.getCredentialStatusDetails().get(0).getStatusPurpose());
        assertEquals("Bengaluru", ledger.getIndexedAttributes().get("city"));
    }

    @Test
    void revocationFlipsTheBitAndTheListIsResigned() throws Exception {
        JsonNode status = issueOid4vci().get("credentials").get(0).get("credential").get("credentialStatus");
        String listUrl = status.get("statusListCredential").asText();
        String listId = listUrl.substring(listUrl.lastIndexOf('/') + 1);
        long index = Long.parseLong(status.get("statusListIndex").asText());
        assertFalse(bit(statusList(listUrl).get("credentialSubject").get("encodedList").asText(), index));

        // today's update API takes the list id, not the URL the credential carries (finding in PROGRESS.md)
        MvcResult update = mockMvc.perform(post("/credentials/status").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "credentialStatus", Map.of("id", listId, "type", "BitstringStatusListEntry", "statusPurpose", "revocation",
                                "statusListIndex", index, "statusListCredential", listId),
                        "status", true)))).andReturn();
        assertEquals(200, update.getResponse().getStatus(), update.getResponse().getContentAsString());
        List<CredentialStatusTransaction> pending = transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, 100))
                .stream().filter(t -> listId.equals(t.getStatusListCredentialId())).toList();
        assertTrue(pending.stream().anyMatch(t -> Long.valueOf(index).equals(t.getStatusListIndex())), "transaction recorded");
        batchJob.updateStatusList(listId, pending); // what the scheduled job does every minute

        JsonNode list = statusList(listUrl);
        assertTrue(bit(list.get("credentialSubject").get("encodedList").asText(), index), "the revoked bit is set");
        verifyStatusList(list);
        assertTrue(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, 100)).stream()
                .noneMatch(t -> listId.equals(t.getStatusListCredentialId()) && Long.valueOf(index).equals(t.getStatusListIndex())), "transaction processed");
    }

    @Test
    void compatibilitySurfaceSharesTheListGolden() throws Exception {
        JsonNode viaNew = issueOid4vci().get("credentials").get(0).get("credential").get("credentialStatus");
        String proof = proofJwt(nonce("/nonce"), issuerIdentifier);
        MvcResult result = mockMvc.perform(post("/issuance/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                        "credential_configuration_id", STATUS_ID, "proofs", Map.of("jwt", List.of(proof)))))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        JsonNode credential = body.get("credentials").get(0).get("credential");
        JsonNode viaLegacy = credential.get("credentialStatus");
        assertEquals(viaNew.get("statusListCredential").asText(), viaLegacy.get("statusListCredential").asText(), "both surfaces draw from the same list");
        assertNotEquals(viaNew.get("statusListIndex").asText(), viaLegacy.get("statusListIndex").asText(), "each credential gets its own index");
        verifyDataIntegrity(credential);
        Goldens.assertGolden("legacy-develop/issuance/ldp_vc-status-response", body);
    }

    // ---- helpers -------------------------------------------------------------------------------------

    private JsonNode issueOid4vci() throws Exception {
        String proof = proofJwt(nonce("/oid4vci/nonce"), issuerIdentifier + "/oid4vci");
        MvcResult result = mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                        "credential_configuration_id", STATUS_ID, "proofs", Map.of("jwt", List.of(proof)))))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        return body;
    }

    private JsonNode statusList(String listUrl) throws Exception {
        assertTrue(listUrl.startsWith(domainUrl + STATUS_LIST_PATH), listUrl);
        return getJson("/credentials/status-list/" + listUrl.substring(listUrl.lastIndexOf('/') + 1));
    }

    private JsonNode getJson(String path) throws Exception {
        return objectMapper.readTree(mockMvc.perform(get(path)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private String nonce(String path) throws Exception {
        return objectMapper.readTree(mockMvc.perform(post(path)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
    }

    private String proofJwt(String nonce, String audience) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build();
        SignedJWT jwt = new SignedJWT(header, new JWTClaimsSet.Builder().audience(audience).issueTime(new Date()).claim("nonce", nonce).build());
        jwt.sign(new ECDSASigner(holder));
        return jwt.serialize();
    }

    /** Bit {@code index} of a Bitstring Status List {@code encodedList} (multibase base64url, GZIP, MSB first). */
    static boolean bit(String encodedList, long index) throws Exception {
        assertTrue(encodedList.startsWith("u"), "multibase base64url: " + encodedList.substring(0, 4));
        byte[] bytes;
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(Base64.getUrlDecoder().decode(encodedList.substring(1))))) {
            bytes = in.readAllBytes();
        }
        assertTrue(index / 8 < bytes.length, "index " + index + " inside the list of " + bytes.length + " bytes");
        return ((bytes[(int) (index / 8)] >> (7 - (int) (index % 8))) & 1) == 1;
    }

    private void verifyDataIntegrity(JsonNode credential) throws Exception {
        assertEquals("DataIntegrityProof", credential.get("proof").get("type").asText());
        assertEquals("eddsa-rdfc-2022", credential.get("proof").get("cryptosuite").asText());
        byte[] publicKey = ed25519PublicKeyFromDidDocument(credential.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(credential.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new DataIntegrityProofLdVerifier(new Ed25519_EdDSA_PublicKeyVerifier(publicKey)).verify(jsonLd),
                "eddsa-rdfc-2022 proof must verify with danubetech");
    }

    /** The status list credential must verify with danubetech and its proof type must survive JSON-LD expansion. */
    private void verifyStatusList(JsonNode list) throws Exception {
        assertEquals("Ed25519Signature2020", list.get("proof").get("type").asText());
        byte[] publicKey = ed25519PublicKeyFromDidDocument(list.get("proof").get("verificationMethod").asText());
        JsonLDObject jsonLd = JsonLDObject.fromJson(list.toString());
        jsonLd.setDocumentLoader(staticContextLoader);
        assertTrue(new Ed25519Signature2020LdVerifier(publicKey).verify(jsonLd), "status list credential must verify with danubetech");
        Set<String> proofTypes = expandedProofTypes(list);
        assertTrue(proofTypes.contains("https://w3id.org/security#Ed25519Signature2020"),
                "the proof type must be defined by the document's contexts or strict verifiers drop it; expanded types: " + proofTypes);
    }

    /** The {@code @type}s of the proof graph after JSON-LD expansion with the service's own context loader. */
    private Set<String> expandedProofTypes(JsonNode document) throws Exception {
        JsonArray expanded = JsonLd.expand(JsonDocument.of(new StringReader(document.toString()))).loader(staticContextLoader).get();
        Set<String> types = new HashSet<>();
        JsonArray proofs = expanded.getJsonObject(0).getJsonArray("https://w3id.org/security#proof");
        if (proofs == null) {
            return types;
        }
        for (JsonValue proof : proofs) {
            for (JsonValue node : proof.asJsonObject().getJsonArray("@graph")) {
                JsonObject object = node.asJsonObject();
                if (object.containsKey("@type")) {
                    object.getJsonArray("@type").forEach(v -> types.add(((JsonString) v).getString()));
                }
            }
        }
        return types;
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
}
