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
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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
        "certify.protocol.vc-api.enabled=true", // the VC-API status endpoint finds the entry through the ledger
        "certify.protocol.vc-api.clients.coordinator.secret=s3cret",
        "certify.keyprovider.x509-file.enabled=true",
        "certify.keyprovider.x509-file.dev-mode=true",
        "certify.keyprovider.x509-file.path=target/status-list-postgres-pki.p12",
        "certify.keyprovider.x509-file.password=pki-test",
        "certify.keyprovider.x509-file.keys[0].alias=sdjwt-es256",
        "certify.keyprovider.x509-file.keys[0].algorithm=ES256",
        "certify.status.token-status-list.key-ref=x509-file:sdjwt-es256",
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
    @Autowired io.mosip.certify.status.TokenStatusListService tokenStatusLists;
    @Autowired io.mosip.certify.status.TokenStatusListProperties tokenStatusListProperties;
    @Autowired io.mosip.certify.repository.StatusListCredentialRepository statusListRepository;
    @Autowired io.mosip.certify.services.StatusListCredentialService statusListCredentialService;
    @Autowired io.mosip.certify.services.StatusListIndexProvider statusListIndexProvider;
    @Autowired io.mosip.certify.issuance.KeyProviderRegistry keyProviders;
    @Autowired org.springframework.core.env.Environment environment;
    @Autowired Flyway flyway;
    @Autowired DataSource dataSource;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactionManager;
    @Autowired io.mosip.certify.core.spi.CredentialStatusService credentialStatusService;
    @Autowired io.mosip.certify.services.StatusListTransactionApplier applier;
    @Autowired io.mosip.certify.services.StatusListLockWait statusListLockWait;
    @Autowired org.springframework.context.ApplicationContext applicationContext;
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

    /** A Token Status List must never serve a Bitstring credential's entry: both share the table (found by the workflow run, F-05). */
    @Test
    void bitstringCredentialsDoNotLandOnATokenStatusList() throws Exception {
        tokenStatusListForSdJwt(); // leaves an AVAILABLE TokenStatusList row for the revocation purpose
        JsonNode status = issueOid4vci().get("credentials").get(0).get("credential").get("credentialStatus");
        String listUrl = status.get("statusListCredential").asText();
        JsonNode list = statusList(listUrl);
        assertTrue(list.has("credentialSubject") && list.get("credentialSubject").has("encodedList"), "the Bitstring entry points at a Bitstring list, not the token list: " + list.toString().substring(0, Math.min(200, list.toString().length())));
        assertEquals("BitstringStatusListEntry", status.get("type").asText());
    }

    /** VC-API: the coordinator names the credential, not the list; the ledger supplies the list and index (P5-01). */
    @Test
    void vcApiStatusUpdateFindsTheEntryThroughTheLedger() throws Exception {
        JsonNode credential = issueOid4vci().get("credentials").get(0).get("credential");
        JsonNode status = credential.get("credentialStatus");
        String listUrl = status.get("statusListCredential").asText();
        String listId = listUrl.substring(listUrl.lastIndexOf('/') + 1);
        long index = Long.parseLong(status.get("statusListIndex").asText());
        String basic = "Basic " + java.util.Base64.getEncoder().encodeToString("coordinator:s3cret".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        MvcResult update = mockMvc.perform(post("/vc-api/credentials/status").header("Authorization", basic).contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credentialId", credential.get("id").asText(),
                        "credentialStatus", Map.of("type", "BitstringStatusListEntry", "statusPurpose", "revocation"), "status", true)))).andReturn();
        assertEquals(200, update.getResponse().getStatus(), update.getResponse().getContentAsString());
        List<CredentialStatusTransaction> pending = transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, 100))
                .stream().filter(t -> listId.equals(t.getStatusListCredentialId()) && Long.valueOf(index).equals(t.getStatusListIndex())).toList();
        assertEquals(1, pending.size(), "one transaction for the credential's own entry");
        // F-19: pin the re-sign instant to one whose Instant.toString() carries no fractional second - the one form
        // in a thousand the strict reader refused ("could not be parsed at index 19") - so this scenario catches it
        // every run instead of rarely.
        pinBatchClock(Instant.parse("2026-11-13T15:00:23Z"));
        try {
            batchJob.updateStatusList(listId, pending);
        } finally {
            pinBatchClock(null);
        }
        JsonNode reSigned = statusList(listUrl);
        assertEquals("2026-11-13T15:00:23Z", reSigned.get("validFrom").asText(), "validFrom keeps the writer's form");
        assertTrue(bit(reSigned.get("credentialSubject").get("encodedList").asText(), index), "the revoked bit is set through VC-API");
        verifyStatusList(reSigned); // the re-signed list verifies, i.e. proof.created was derived from :23Z

        MvcResult unknownPurpose = mockMvc.perform(post("/vc-api/credentials/status").header("Authorization", basic).contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credentialId", credential.get("id").asText(),
                        "credentialStatus", Map.of("type", "BitstringStatusListEntry", "statusPurpose", "suspension"), "status", true)))).andReturn();
        assertEquals(404, unknownPurpose.getResponse().getStatus(), "no suspension entry for this credential");
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

    /** Token Status List (draft-ietf-oauth-status-list) for an SD-JWT VC signed under the x509-file dev CA: the credential's status.status_list, the served list JWT, and a revocation through the batch job. */
    @Test
    void tokenStatusListForSdJwt() throws Exception {
        String configId = "TokenStatusSdJwt";
        if (mockMvc.perform(get("/v2/credential-configurations/" + configId)).andReturn().getResponse().getStatus() == 404) {
            java.nio.file.Path template = java.nio.file.Path.of("src/test/resources/goldens/templates/golden-sdjwt.vm");
            if (!java.nio.file.Files.exists(template)) {
                template = java.nio.file.Path.of("certify-service").resolve(template);
            }
            Map<String, Object> body = new java.util.LinkedHashMap<>();
            body.put("id", configId);
            body.put("scope", "sample_vc_ldp");
            body.put("format", "dc+sd-jwt");
            body.put("formatConfig", Map.of("vct", configId, "sdClaims", List.of("$.fullName"), "sdJwtClaims", Map.of("fullName", Map.of("display", List.of(Map.of("name", "Full name", "locale", "en"))))));
            body.put("signing", Map.of("provider", "x509-file", "alias", "sdjwt-es256", "alg", "ES256", "x5c", "without-anchor"));
            body.put("template", Map.of("content", java.nio.file.Files.readString(template, java.nio.charset.StandardCharsets.UTF_8)));
            body.put("status", Map.of("mechanism", "TokenStatusList", "purposes", List.of("revocation")));
            body.put("display", Map.of("display", List.of(Map.of("name", configId, "locale", "en")), "order", List.of("fullName")));
            MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body))).andReturn();
            assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
        }
        String proof = proofJwt(nonce("/oid4vci/nonce"), issuerIdentifier + "/oid4vci");
        MvcResult result = mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                        "credential_configuration_id", configId, "proofs", Map.of("jwt", List.of(proof)))))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        SignedJWT credential = SignedJWT.parse(body.get("credentials").get(0).get("credential").asText().split("~")[0]);
        Map<String, Object> statusList = (Map<String, Object>) credential.getJWTClaimsSet().getJSONObjectClaim("status").get("status_list");
        long idx = ((Number) statusList.get("idx")).longValue();
        String uri = statusList.get("uri").toString();
        assertTrue(uri.startsWith(domainUrl + "/v1/certify/credentials/token-status-list/"), uri);
        String listId = uri.substring(uri.lastIndexOf('/') + 1);

        MvcResult fetched = mockMvc.perform(get("/credentials/token-status-list/" + listId).accept("application/statuslist+jwt")).andReturn();
        assertEquals(200, fetched.getResponse().getStatus());
        assertEquals("application/statuslist+jwt", fetched.getResponse().getContentType());
        SignedJWT list = SignedJWT.parse(fetched.getResponse().getContentAsString());
        assertEquals("statuslist+jwt", list.getHeader().getType().getType());
        assertEquals(1, list.getHeader().getX509CertChain().size(), "the leaf only, no anchor");
        java.security.cert.X509Certificate leaf = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(list.getHeader().getX509CertChain().get(0).decode()));
        assertTrue(list.verify(new com.nimbusds.jose.crypto.ECDSAVerifier((java.security.interfaces.ECPublicKey) leaf.getPublicKey())), "the list verifies with its x5c leaf");
        assertEquals(uri, list.getJWTClaimsSet().getSubject());
        Map<String, Object> claim = list.getJWTClaimsSet().getJSONObjectClaim("status_list");
        assertEquals(1, ((Number) claim.get("bits")).intValue());
        assertFalse(io.mosip.certify.status.TokenStatusListService.get(io.mosip.certify.status.TokenStatusListService.decode(claim.get("lst").toString()), idx), "fresh entry is not revoked");

        CredentialStatusTransaction revocation = new CredentialStatusTransaction();
        revocation.setCredentialId("token-status-" + idx);
        revocation.setStatusPurpose("revocation");
        revocation.setStatusValue(true);
        revocation.setStatusListCredentialId(listId);
        revocation.setStatusListIndex(idx);
        revocation.setCreatedDtimes(java.time.LocalDateTime.now());
        revocation.setIsProcessed(false);
        transactionRepository.save(revocation);
        batchJob.updateStatusList(listId, List.of(revocation));
        SignedJWT updated = SignedJWT.parse(mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn().getResponse().getContentAsString());
        Map<String, Object> after = updated.getJWTClaimsSet().getJSONObjectClaim("status_list");
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(io.mosip.certify.status.TokenStatusListService.decode(after.get("lst").toString()), idx), "revoked");
        assertTrue(updated.verify(new com.nimbusds.jose.crypto.ECDSAVerifier((java.security.interfaces.ECPublicKey) leaf.getPublicKey())), "the re-signed list verifies");
    }

    /**
     * Freshness of a served Token Status List (draft-ietf-oauth-status-list 5.1, 8.3) on PostgreSQL: a list signed long
     * ago (exp less than ttl away) and a list signed under another domain (sub not the URI the tokens carry) are both
     * signed again by GET, through the compare-and-set on vc_document, with the revoked bit kept.
     */
    @Test
    void tokenStatusListIsSignedAgainWhenStaleOrUnderAnotherUri() throws Exception {
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocate("revocation");
        String listId = entry.uri().substring(entry.uri().lastIndexOf('/') + 1);
        CredentialStatusTransaction revocation = new CredentialStatusTransaction();
        revocation.setCredentialId("token-status-fresh-" + entry.idx());
        revocation.setStatusPurpose("revocation");
        revocation.setStatusValue(true);
        revocation.setStatusListCredentialId(listId);
        revocation.setStatusListIndex(entry.idx());
        revocation.setCreatedDtimes(java.time.LocalDateTime.now());
        revocation.setIsProcessed(false);
        transactionRepository.save(revocation);
        batchJob.updateStatusList(listId, List.of(revocation));
        String fresh = mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn().getResponse().getContentAsString();
        assertEquals(fresh, mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn().getResponse().getContentAsString(),
                "a fresh list is served as stored");

        java.time.Duration ttl = tokenStatusListProperties.ttl();
        java.time.Instant longAgo = java.time.Instant.now().minus(ttl).minus(ttl).plusSeconds(120); // exp two minutes away
        signAgain(listId, environment.getProperty("mosip.certify.domain.url"), java.time.Clock.fixed(longAgo, java.time.ZoneOffset.UTC));
        assertServedFresh(listId, entry.idx(), ttl);

        signAgain(listId, "https://old-host.example.org", java.time.Clock.systemUTC());
        assertTrue(SignedJWT.parse(statusListRepository.findById(listId).orElseThrow().getVcDocument()).getJWTClaimsSet().getSubject()
                .startsWith("https://old-host.example.org/"));
        assertServedFresh(listId, entry.idx(), ttl);
    }

    /**
     * The compare-and-set the re-sign stores through, on PostgreSQL: a caller holding a document that is no longer the
     * stored one (the batch job or another instance replaced it) changes nothing, and is told so.
     */
    @Test
    void tokenStatusListReplaceDocumentIsACompareAndSet() throws Exception {
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocate("revocation");
        String listId = entry.uri().substring(entry.uri().lastIndexOf('/') + 1);
        String stored = statusListRepository.findById(listId).orElseThrow().getVcDocument();

        assertEquals(0, statusListRepository.replaceDocument(listId, "stale", "replacement"), "a stale previous document replaces nothing");
        assertEquals(stored, statusListRepository.findById(listId).orElseThrow().getVcDocument(), "the stored document is unchanged");
        assertEquals(0, statusListRepository.replaceDocument("no-such-list", stored, "replacement"));

        assertEquals(1, statusListRepository.replaceDocument(listId, stored, "replacement"), "the current document is replaced");
        assertEquals("replacement", statusListRepository.findById(listId).orElseThrow().getVcDocument());
        assertEquals(1, statusListRepository.replaceDocument(listId, "replacement", stored));
        assertEquals(stored, statusListRepository.findById(listId).orElseThrow().getVcDocument());
    }

    /** Stores the list signed again (same bits) by a service with another domain or clock, as an older deployment left it. */
    private void signAgain(String listId, String domain, java.time.Clock clock) {
        org.springframework.mock.env.MockEnvironment elsewhere = new org.springframework.mock.env.MockEnvironment()
                .withProperty("mosip.certify.domain.url", domain)
                .withProperty("server.servlet.path", environment.getProperty("server.servlet.path", ""));
        io.mosip.certify.status.TokenStatusListService elsewhereLists =
                new io.mosip.certify.status.TokenStatusListService(statusListRepository, statusListCredentialService,
                        statusListIndexProvider, keyProviders, tokenStatusListProperties, objectMapper, elsewhere, clock);
        // the service instance bypasses Spring's proxy in this helper, so the transaction the row lock needs is opened here
        new org.springframework.transaction.support.TransactionTemplate(transactionManager).executeWithoutResult(status ->
                elsewhereLists.update(statusListRepository.findById(listId).orElseThrow(), Map.of()));
    }

    private void assertServedFresh(String listId, long revokedIdx, java.time.Duration ttl) throws Exception {
        MvcResult fetched = mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn();
        assertEquals(200, fetched.getResponse().getStatus());
        String served = fetched.getResponse().getContentAsString();
        SignedJWT list = SignedJWT.parse(served);
        java.security.cert.X509Certificate leaf = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(list.getHeader().getX509CertChain().get(0).decode()));
        assertTrue(list.verify(new com.nimbusds.jose.crypto.ECDSAVerifier((java.security.interfaces.ECPublicKey) leaf.getPublicKey())), "the re-signed list verifies");
        assertEquals(tokenStatusLists.uri(listId), list.getJWTClaimsSet().getSubject(), "sub is the URI the referenced tokens carry");
        assertTrue(list.getJWTClaimsSet().getSubject().startsWith(domainUrl + "/v1/certify/credentials/token-status-list/"));
        assertTrue(list.getJWTClaimsSet().getExpirationTime().toInstant().isAfter(java.time.Instant.now().plus(ttl)), "at least ttl to go");
        Map<String, Object> claim = list.getJWTClaimsSet().getJSONObjectClaim("status_list");
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(io.mosip.certify.status.TokenStatusListService.decode(claim.get("lst").toString()), revokedIdx),
                "the revocation is kept");
        assertEquals(served, statusListRepository.findById(listId).orElseThrow().getVcDocument(), "the re-signed list is stored");
    }

    /**
     * M-11d on PostgreSQL: a CWT status list is created, allocated into, revoked through the batch job and re-served —
     * the section 4.4 envelope in {@code vc_document}, the type {@code TokenStatusListCwt}, no migration (D-M11-4), and
     * the endpoint answering {@code application/statuslist+cwt} whatever the {@code Accept} (D-M11-2). The token is read
     * back with {@link io.mosip.certify.status.TokenStatusListCwt}; the independent verifier runs on conformance samples
     * because Multipaz cannot be on this module's classpath (see the M-11d section of the plan).
     */
    @Test
    void tokenStatusListCwtForMdoc() throws Exception {
        io.mosip.certify.spi.SigningContext signing = keyProviders.signingContext(io.mosip.certify.spi.SigningConfig.of(
                io.mosip.certify.signing.KeyRef.parse("x509-file:sdjwt-es256"), io.mosip.certify.signing.SignatureAlgorithm.ES256));
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocateCwt("revocation", signing);
        String listId = entry.uri().substring(entry.uri().lastIndexOf('/') + 1);

        io.mosip.certify.entity.StatusListCredential row = statusListRepository.findById(listId).orElseThrow();
        assertEquals(io.mosip.certify.status.TokenStatusListService.TYPE_CWT, row.getCredentialType());
        assertEquals("revocation", row.getStatusPurpose());
        assertEquals(io.mosip.certify.entity.StatusListCredential.CredentialStatus.AVAILABLE, row.getCredentialStatus());
        io.mosip.certify.status.TokenStatusListService.StoredEnvelope envelope = tokenStatusLists.envelope(row.getVcDocument());
        assertEquals(io.mosip.certify.status.TokenStatusListService.ENVELOPE_VERSION, envelope.v());
        assertEquals(io.mosip.certify.status.TokenStatusListService.SIGNER_DOCUMENT, envelope.signer().mode());
        java.security.cert.X509Certificate signer = keyProviders.provider("x509-file")
                .resolve(io.mosip.certify.signing.KeyRef.parse("x509-file:sdjwt-es256")).chain().leaf().orElseThrow();
        assertEquals(io.mosip.certify.status.StatusListSigners.x5tS256(signer), envelope.signer().x5tS256());

        // a second entry for the same signer stays on the same list
        assertTrue(tokenStatusLists.allocateCwt("revocation", signing).uri().endsWith("/" + listId));

        // served as CWT for a client that asks for JWT: one format per list
        MvcResult fetched = mockMvc.perform(get("/credentials/token-status-list/" + listId)
                .accept("application/statuslist+jwt")).andReturn();
        assertEquals(200, fetched.getResponse().getStatus());
        assertEquals(io.mosip.certify.status.TokenStatusListService.MEDIA_TYPE_CWT, fetched.getResponse().getContentType());
        io.mosip.certify.status.TokenStatusListCwt.Decoded decoded = io.mosip.certify.status.TokenStatusListCwt.decode(
                fetched.getResponse().getContentAsByteArray());
        assertEquals(entry.uri(), decoded.sub(), "sub is the URI the mDL's status_list carries");
        assertEquals(1, decoded.bits());
        assertEquals(signer, decoded.x5chain().get(0), "the x5chain is the Document Signer leaf, never the anchor");
        assertFalse(io.mosip.certify.status.TokenStatusListService.get(decoded.lst(), entry.idx()), "a fresh entry is not revoked");

        // revoke through the batch job: the bit is set and the list re-signed by the same pinned signer
        CredentialStatusTransaction revocation = new CredentialStatusTransaction();
        revocation.setCredentialId("token-status-cwt-" + entry.idx());
        revocation.setStatusPurpose("revocation");
        revocation.setStatusValue(true);
        revocation.setStatusListCredentialId(listId);
        revocation.setStatusListIndex(entry.idx());
        revocation.setCreatedDtimes(java.time.LocalDateTime.now());
        revocation.setIsProcessed(false);
        transactionRepository.save(revocation);
        batchJob.updateStatusList(listId, List.of(revocation));

        io.mosip.certify.status.TokenStatusListCwt.Decoded revoked = io.mosip.certify.status.TokenStatusListCwt.decode(
                mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn()
                        .getResponse().getContentAsByteArray());
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(revoked.lst(), entry.idx()), "the revoked bit is set");
        assertEquals(signer, revoked.x5chain().get(0), "the re-signed list keeps its own signer");
        assertEquals(io.mosip.certify.status.TokenStatusListService.TYPE_CWT,
                statusListRepository.findById(listId).orElseThrow().getCredentialType());
        assertTrue(transactionRepository.findByIsProcessedFalseOrderByCreatedDtimesAsc(PageRequest.of(0, 100)).stream()
                .noneMatch(t -> listId.equals(t.getStatusListCredentialId()) && Long.valueOf(entry.idx()).equals(t.getStatusListIndex())),
                "the transaction is processed");
    }

    /**
     * Review round 1, major 2: two status updates on one CWT list, committed concurrently, must both keep their bit. Before
     * the fix each signed its caller's snapshot and saved the whole row, so the later commit reverted the earlier bit
     * (reproduced on PostgreSQL 15: bit0=false, bit1=true).
     */
    @Test
    void concurrentCwtUpdatesKeepBothBits() throws Exception {
        io.mosip.certify.spi.SigningContext signing = keyProviders.signingContext(io.mosip.certify.spi.SigningConfig.of(
                io.mosip.certify.signing.KeyRef.parse("x509-file:sdjwt-es256"), io.mosip.certify.signing.SignatureAlgorithm.ES256));
        io.mosip.certify.status.TokenStatusListService.Entry first = tokenStatusLists.allocateCwt("revocation", signing);
        io.mosip.certify.status.TokenStatusListService.Entry second = tokenStatusLists.allocateCwt("revocation", signing);
        String listId = first.uri().substring(first.uri().lastIndexOf('/') + 1);
        assertEquals(listId, second.uri().substring(second.uri().lastIndexOf('/') + 1));

        CredentialStatusTransaction a = pending("cwt-race-a-" + first.idx(), listId, first.idx());
        CredentialStatusTransaction b = pending("cwt-race-b-" + second.idx(), listId, second.idx());
        transactionRepository.saveAll(List.of(a, b));
        concurrently(2, List.of(() -> batchJob.updateStatusList(listId, List.of(a)),
                () -> batchJob.updateStatusList(listId, List.of(b))));

        io.mosip.certify.status.TokenStatusListCwt.Decoded decoded = io.mosip.certify.status.TokenStatusListCwt.decode(
                mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn()
                        .getResponse().getContentAsByteArray());
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(decoded.lst(), first.idx()), "the first bit survived");
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(decoded.lst(), second.idx()), "the second bit survived");
    }

    /** The same lost update existed on the JWT path (major 2, "check whether the JWT update path has it too"). */
    @Test
    void concurrentJwtUpdatesKeepBothBits() throws Exception {
        io.mosip.certify.status.TokenStatusListService.Entry first = tokenStatusLists.allocate("revocation");
        io.mosip.certify.status.TokenStatusListService.Entry second = tokenStatusLists.allocate("revocation");
        String listId = first.uri().substring(first.uri().lastIndexOf('/') + 1);
        assertEquals(listId, second.uri().substring(second.uri().lastIndexOf('/') + 1));

        CredentialStatusTransaction a = pending("jwt-race-a-" + first.idx(), listId, first.idx());
        CredentialStatusTransaction b = pending("jwt-race-b-" + second.idx(), listId, second.idx());
        transactionRepository.saveAll(List.of(a, b));
        concurrently(2, List.of(() -> batchJob.updateStatusList(listId, List.of(a)),
                () -> batchJob.updateStatusList(listId, List.of(b))));

        SignedJWT list = SignedJWT.parse(mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn()
                .getResponse().getContentAsString());
        byte[] bits = io.mosip.certify.status.TokenStatusListService.decode(
                list.getJWTClaimsSet().getJSONObjectClaim("status_list").get("lst").toString());
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(bits, first.idx()), "the first bit survived");
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(bits, second.idx()), "the second bit survived");
    }

    /**
     * Review round 1, major 2(c): marking a list {@code FULL} must not write its document. The index pool is exhausted
     * (so the next allocation marks the list FULL) and a revocation is committed first; the document must still hold it
     * afterwards, on PostgreSQL.
     */
    @Test
    void allocationMarkingFullKeepsTheCommittedRevocation() throws Exception {
        io.mosip.certify.spi.SigningContext signing = keyProviders.signingContext(io.mosip.certify.spi.SigningConfig.of(
                io.mosip.certify.signing.KeyRef.parse("x509-file:sdjwt-es256"), io.mosip.certify.signing.SignatureAlgorithm.ES256));
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocateCwt("revocation", signing);
        String listId = entry.uri().substring(entry.uri().lastIndexOf('/') + 1);
        CredentialStatusTransaction revocation = pending("cwt-full-" + entry.idx(), listId, entry.idx());
        transactionRepository.save(revocation);
        batchJob.updateStatusList(listId, List.of(revocation));
        String revoked = statusListRepository.findById(listId).orElseThrow().getVcDocument();

        // exhaust the pool without claiming: the next allocation finds no free index and marks the list FULL
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("DELETE FROM " + SCHEMA
                     + ".status_list_available_indices WHERE status_list_credential_id = ? AND is_assigned = false")) {
            ps.setString(1, listId);
            ps.executeUpdate();
        }
        io.mosip.certify.status.TokenStatusListService.Entry next = tokenStatusLists.allocateCwt("revocation", signing);
        assertFalse(listId.equals(next.uri().substring(next.uri().lastIndexOf('/') + 1)),
                "the full list takes no more indices; a new one was created");

        io.mosip.certify.entity.StatusListCredential full = statusListRepository.findById(listId).orElseThrow();
        assertEquals(io.mosip.certify.entity.StatusListCredential.CredentialStatus.FULL, full.getCredentialStatus());
        assertEquals(revoked, full.getVcDocument(), "marking the list FULL wrote no document and keeps the revocation");
    }

    /**
     * Review round 2, major 4 (GPT, reproduced on PostgreSQL 15): JWT {@code allocate()} read the list, a revocation was
     * committed, the pool was exhausted, and marking the list {@code FULL} saved the entity it had read, reverting the
     * revocation ({@code revokedBitKept=false}). Here the revocation commits from another thread inside the index call,
     * after the read and before the marking: a deterministic interleaving of that schedule.
     */
    @Test
    void jwtAllocationMarkingFullKeepsARevocationCommittedAfterItsRead() throws Exception {
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocate("revocation");
        String listId = listIdOf(entry);
        exhaustThePool(listId);
        CredentialStatusTransaction revocation = transactionRepository.save(pending("jwt-full-race-" + entry.idx(), listId, entry.idx()));
        io.mosip.certify.status.TokenStatusListService racing = new io.mosip.certify.status.TokenStatusListService(
                statusListRepository, statusListCredentialService,
                committingDuringTheIndexCall(listId, () -> batchJob.updateStatusList(listId, List.of(revocation))),
                keyProviders, tokenStatusListProperties, objectMapper, environment);

        // the service instance bypasses Spring's proxy, so allocate's transaction is opened here, as the proxy would
        io.mosip.certify.status.TokenStatusListService.Entry next = new org.springframework.transaction.support
                .TransactionTemplate(transactionManager).execute(status -> racing.allocate("revocation"));

        assertNotEquals(listId, listIdOf(next), "the full list takes no more indices");
        io.mosip.certify.entity.StatusListCredential full = statusListRepository.findById(listId).orElseThrow();
        assertEquals(io.mosip.certify.entity.StatusListCredential.CredentialStatus.FULL, full.getCredentialStatus());
        byte[] bits = io.mosip.certify.status.TokenStatusListService.decode(SignedJWT.parse(full.getVcDocument())
                .getJWTClaimsSet().getJSONObjectClaim("status_list").get("lst").toString());
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(bits, entry.idx()),
                "revokedBitKept: marking the list FULL wrote no document");
    }

    /** The same schedule through {@code allocateCwt}, which reads candidates as a projection and marks FULL alone. */
    @Test
    void cwtAllocationMarkingFullKeepsARevocationCommittedAfterItsRead() throws Exception {
        io.mosip.certify.spi.SigningContext signing = keyProviders.signingContext(io.mosip.certify.spi.SigningConfig.of(
                io.mosip.certify.signing.KeyRef.parse("x509-file:sdjwt-es256"), io.mosip.certify.signing.SignatureAlgorithm.ES256));
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocateCwt("revocation", signing);
        String listId = listIdOf(entry);
        exhaustThePool(listId);
        CredentialStatusTransaction revocation = transactionRepository.save(pending("cwt-full-race-" + entry.idx(), listId, entry.idx()));
        io.mosip.certify.status.TokenStatusListService racing = new io.mosip.certify.status.TokenStatusListService(
                statusListRepository, statusListCredentialService,
                committingDuringTheIndexCall(listId, () -> batchJob.updateStatusList(listId, List.of(revocation))),
                keyProviders, tokenStatusListProperties, objectMapper, environment);

        io.mosip.certify.status.TokenStatusListService.Entry next = new org.springframework.transaction.support
                .TransactionTemplate(transactionManager).execute(status -> racing.allocateCwt("revocation", signing));

        assertNotEquals(listId, listIdOf(next));
        io.mosip.certify.entity.StatusListCredential full = statusListRepository.findById(listId).orElseThrow();
        assertEquals(io.mosip.certify.entity.StatusListCredential.CredentialStatus.FULL, full.getCredentialStatus());
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(io.mosip.certify.status.TokenStatusListCwt.decode(
                java.util.Base64.getUrlDecoder().decode(tokenStatusLists.envelope(full.getVcDocument()).token())).lst(),
                entry.idx()), "revokedBitKept");
    }

    /**
     * Review round 2, major 3, on PostgreSQL: batch size 1 and thirty pending rows of a CWT list the job refuses
     * permanently (its stored token is not the one its envelope pins), ahead of one healthy JWT revocation. The job's
     * selection excludes the refused list in SQL ({@code NOT IN}), so the healthy row is published in the first run.
     */
    @Test
    void aQuarantinedListsStuckRowsDoNotStarveAHealthyList() throws Exception {
        StatusListUpdateBatchJob job = org.springframework.test.util.AopTestUtils.getTargetObject(batchJob);
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement("UPDATE " + SCHEMA
                + ".credential_status_transaction SET is_processed = true WHERE is_processed = false")) {
            ps.executeUpdate(); // what earlier tests left pending is theirs, not this run's
        }
        io.mosip.certify.spi.SigningContext signing = keyProviders.signingContext(io.mosip.certify.spi.SigningConfig.of(
                io.mosip.certify.signing.KeyRef.parse("x509-file:sdjwt-es256"), io.mosip.certify.signing.SignatureAlgorithm.ES256));
        io.mosip.certify.status.TokenStatusListService.Entry stuckEntry = tokenStatusLists.allocateCwt("revocation", signing);
        String stuck = listIdOf(stuckEntry);
        String document = statusListRepository.findById(stuck).orElseThrow().getVcDocument();
        String pin = tokenStatusLists.envelope(document).signer().x5tS256();
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement("UPDATE " + SCHEMA
                + ".status_list_credential SET vc_document = ? WHERE id = ?")) {
            ps.setString(1, document.replace(pin, java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32])));
            ps.setString(2, stuck);
            ps.executeUpdate();
        }
        for (int index = 0; index < 30; index++) {
            transactionRepository.save(pending("stuck-" + stuck + "-" + index, stuck, index));
        }
        io.mosip.certify.status.TokenStatusListService.Entry healthy = tokenStatusLists.allocate("revocation");
        String healthyList = listIdOf(healthy);
        CredentialStatusTransaction revocation = transactionRepository.save(pending("healthy-" + healthy.idx(), healthyList, healthy.idx()));

        Object batchSizeBefore = org.springframework.test.util.ReflectionTestUtils.getField(job, "batchSize");
        org.springframework.test.util.ReflectionTestUtils.setField(job, "batchSize", 1);
        org.springframework.test.util.ReflectionTestUtils.setField(job, "batchJobEnabled", true);
        net.javacrumbs.shedlock.core.LockAssert.TestHelper.makeAllAssertsPass(true);
        try {
            job.updateStatusLists();
        } finally {
            net.javacrumbs.shedlock.core.LockAssert.TestHelper.makeAllAssertsPass(false);
            org.springframework.test.util.ReflectionTestUtils.setField(job, "batchJobEnabled", false);
            org.springframework.test.util.ReflectionTestUtils.setField(job, "batchSize", batchSizeBefore);
            // the edited row must not be handed to a later test's allocation
            statusListRepository.updateCredentialStatus(stuck, io.mosip.certify.entity.StatusListCredential.CredentialStatus.FULL);
        }

        assertTrue(transactionRepository.findById(revocation.getTransactionLogId()).orElseThrow().getIsProcessed(),
                "the healthy row is processed in the first run");
        assertEquals(30, transactionRepository.findPending(PageRequest.of(0, 100)).stream()
                .filter(t -> stuck.equals(t.getStatusListCredentialId())).count(), "the refused list's rows all stay pending");
        SignedJWT list = SignedJWT.parse(mockMvc.perform(get("/credentials/token-status-list/" + healthyList)).andReturn()
                .getResponse().getContentAsString());
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(io.mosip.certify.status.TokenStatusListService.decode(
                list.getJWTClaimsSet().getJSONObjectClaim("status_list").get("lst").toString()), healthy.idx()),
                "and its revocation is published");
    }

    // ---- M-11d review round 4: one writer order per list, stale selections, indices outside a list ----------------

    /**
     * Finding 1 on PostgreSQL, through the real CWT service: run A (a second instance) selects the pending reinstatement
     * and pauses past its lease; run B applies it, a revocation is queued through the status API, and run B applies that
     * ({@code revoked=true, pending=0}). Run A resumes with its stale selection. Before the fix it applied the
     * reinstatement again ({@code revoked=false, pending=0}); the applier reads the list's pending rows again under the
     * row lock and finds none, so A writes nothing.
     */
    @Test
    void aStaleSelectionResumedAfterAnotherRunDoesNotUndoANewerRevocation() throws Exception {
        closeEveryPendingTransaction();
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocateCwt("revocation", dscSigning());
        String listId = listIdOf(entry);
        queue(listId, entry.idx(), false);
        StatusListUpdateBatchJob runB = org.springframework.test.util.AopTestUtils.getTargetObject(batchJob);
        String[] newest = new String[1];
        StatusListUpdateBatchJob runA = secondInstance(pausingAfterTheSelection(() -> {
            run(runB);                                   // B applies the reinstatement
            queue(listId, entry.idx(), true);
            run(runB);                                   // and then the revocation
            assertTrue(cwtBit(listId, entry.idx()), "revoked=true");
            assertEquals(0, pendingOn(listId), "pending=0");
            newest[0] = statusListRepository.findDocumentById(listId).orElseThrow();
        }));

        run(runA);                                       // A: selection, B's two runs, then A's stale rows

        assertNotNull(newest[0], "run A's selection paused while run B ran");
        assertTrue(cwtBit(listId, entry.idx()), "the newest state stands");
        assertEquals(0, pendingOn(listId));
        assertEquals(newest[0], statusListRepository.findDocumentById(listId).orElseThrow(), "run A wrote nothing");
    }

    /**
     * Finding 3 (G42), the reviewer's reproduction on PostgreSQL: node A's clock runs an hour ahead. It reinstates an
     * index; afterwards node B, whose clock is right, revokes it. Both rows are pending when the job runs, and A's
     * {@code cr_dtimes} is the later one. Ordered by {@code cr_dtimes} the job applied the revocation first and the
     * reinstatement on top (both processed, the bit valid); ordered by the database sequence it ends revoked.
     */
    @Test
    void aReinstatementFromAFastClockNodeDoesNotUndoALaterRevocation() throws Exception {
        closeEveryPendingTransaction();
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocateCwt("revocation", dscSigning());
        String listId = listIdOf(entry);
        queue(listId, entry.idx(), false);              // node A
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement("UPDATE " + SCHEMA
                + ".credential_status_transaction SET cr_dtimes = cr_dtimes + interval '1 hour'"
                + " WHERE status_list_credential_id = ? AND is_processed = false")) {
            ps.setString(1, listId);
            assertEquals(1, ps.executeUpdate(), "node A wrote its row with its clock an hour ahead");
        }
        queue(listId, entry.idx(), true);               // node B, later, with the right clock
        List<CredentialStatusTransaction> rows = transactionRepository.findPendingForList(listId, PageRequest.of(0, 10));
        assertEquals(List.of(false, true), rows.stream().map(CredentialStatusTransaction::getStatusValue).toList(), "sequence order");
        assertTrue(rows.get(0).getCreatedDtimes().isAfter(rows.get(1).getCreatedDtimes()), "the clocks disagree with it");

        run(org.springframework.test.util.AopTestUtils.getTargetObject(batchJob));

        assertTrue(cwtBit(listId, entry.idx()), "the later revocation is what the list says");
        assertEquals(0, pendingOn(listId), "both processed");
    }

    /**
     * Finding 3: ordering by the sequence alone is not enough if a lower id could commit after a higher one was
     * applied. A status change takes the list's row lock before its insert draws the id, and holds it to its commit — the
     * lock the job applies under — so a second change to the same list waits, draws the higher id, and commits after.
     * The sequence is not cached per session (CACHE 1, SERIAL's default), so ids are handed out in the order drawn.
     */
    @Test
    void aSecondStatusChangeWaitsForTheFirstsListLockSoTheSequenceIsTheCommitOrder() throws Exception {
        closeEveryPendingTransaction();
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(
                "SELECT cache_size FROM pg_sequences WHERE schemaname = ? AND sequencename = ?")) {
            ps.setString(1, SCHEMA);
            ps.setString(2, "credential_status_transaction_transaction_log_id_seq");
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), "the SERIAL sequence of transaction_log_id");
                assertEquals(1, rs.getLong(1), "ids are drawn in order: no per-session cache");
            }
        }
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocateCwt("revocation", dscSigning());
        String listId = listIdOf(entry);
        java.util.concurrent.CountDownLatch inserted = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            java.util.concurrent.Future<?> first = pool.submit(() -> new org.springframework.transaction.support
                    .TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                        queue(listId, entry.idx(), false); // inserted; its commit waits for the release below
                        inserted.countDown();
                        try {
                            assertTrue(release.await(60, java.util.concurrent.TimeUnit.SECONDS));
                        } catch (InterruptedException e) {
                            throw new IllegalStateException(e);
                        }
                    }));
            assertTrue(inserted.await(60, java.util.concurrent.TimeUnit.SECONDS));
            java.util.concurrent.Future<?> second = pool.submit(() -> queue(listId, entry.idx(), true));
            org.junit.jupiter.api.Assertions.assertThrows(java.util.concurrent.TimeoutException.class,
                    () -> second.get(1500, java.util.concurrent.TimeUnit.MILLISECONDS),
                    "the second change waits for the first one's list lock");
            release.countDown();
            first.get(60, java.util.concurrent.TimeUnit.SECONDS);
            second.get(60, java.util.concurrent.TimeUnit.SECONDS);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
        List<CredentialStatusTransaction> rows = transactionRepository.findPendingForList(listId, PageRequest.of(0, 10));
        assertEquals(List.of(false, true), rows.stream().map(CredentialStatusTransaction::getStatusValue).toList(),
                "the id order is the commit order");

        run(org.springframework.test.util.AopTestUtils.getTargetObject(batchJob));
        assertTrue(cwtBit(listId, entry.idx()));
        assertEquals(0, pendingOn(listId));
    }

    /**
     * M-11d merge (Opus review round 5, minor 1): the bounded wait is transaction-local. After a busy refusal and a
     * successful status change, every pooled connection reports {@code lock_timeout = 0}, so the bound never caps a
     * later lock wait elsewhere (keymanager, ShedLock, marking a list FULL), and the connection that hit SQLState
     * 55P03 is still in the pool (not evicted). A session-level {@code SET} instead of {@code SET LOCAL} fails this test.
     */
    @Test
    void theLockWaitNeverLeaksIntoPooledConnectionsAndABusyConnectionStaysPooled() throws Exception {
        closeEveryPendingTransaction();
        com.zaxxer.hikari.HikariDataSource pool = dataSource.unwrap(com.zaxxer.hikari.HikariDataSource.class);
        io.mosip.certify.status.TokenStatusListService.Entry lockedEntry = tokenStatusLists.allocate("revocation");
        String locked = listIdOf(lockedEntry);
        io.mosip.certify.status.TokenStatusListService.Entry freeEntry = tokenStatusLists.allocateCwt("revocation", dscSigning());
        String free = listIdOf(freeEntry);
        assertNotEquals(locked, free);
        org.springframework.transaction.support.TransactionTemplate tx =
                new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        java.util.concurrent.atomic.AtomicInteger busyPid = new java.util.concurrent.atomic.AtomicInteger();
        try (Connection holder = dataSource.getConnection()) {
            holder.setAutoCommit(false);
            lockListRow(holder, locked);
            Throwable refused = null;
            try {
                tx.executeWithoutResult(s -> {
                    applicationContext.getBean(jakarta.persistence.EntityManager.class).unwrap(org.hibernate.Session.class)
                            .doWork(c -> busyPid.set(backendPid(c)));
                    queue(locked, lockedEntry.idx(), true);
                });
            } catch (Throwable t) {
                refused = t;
            }
            assertTrue(refused instanceof io.mosip.certify.core.exception.StatusListBusyException, String.valueOf(refused));
            queue(free, freeEntry.idx(), true); // a successful change also ran SET LOCAL
            holder.rollback();
        }
        java.util.List<Connection> borrowed = new java.util.ArrayList<>();
        Set<Integer> pids = new HashSet<>();
        try {
            for (int i = 0; i < pool.getMaximumPoolSize(); i++) {
                Connection c = dataSource.getConnection();
                borrowed.add(c);
                pids.add(backendPid(c));
                try (java.sql.Statement st = c.createStatement(); java.sql.ResultSet rs = st.executeQuery("SHOW lock_timeout")) {
                    rs.next();
                    assertEquals("0", rs.getString(1), "pooled connection " + i + " kept a lock_timeout");
                }
            }
        } finally {
            for (Connection c : borrowed) c.close();
        }
        assertTrue(pids.contains(busyPid.get()), "the connection that hit 55P03 was evicted from the pool");
        closeEveryPendingTransaction();
    }

    private static int backendPid(Connection c) throws java.sql.SQLException {
        try (java.sql.Statement st = c.createStatement(); java.sql.ResultSet rs = st.executeQuery("SELECT pg_backend_pid()")) {
            rs.next();
            return rs.getInt(1);
        }
    }

    /**
     * Review round 5, finding 1 (PostgreSQL): the status-change path waits for a list's row lock at most
     * {@code certify.status.update.lock-wait}. Another connection holds the lock the batch job signs under
     * ({@code FOR NO KEY UPDATE}); a status change for that list through the service, {@code /credentials/status} and
     * the VC-API is refused within the bound as retryable — the MOSIP error wrapper with {@code status_list_busy_retry_later},
     * VC-API {@code 503} with {@code Retry-After} — and queues nothing, while a status change for another list goes
     * through meanwhile. Without the {@code lock_timeout} the three wait until the holder lets go, and this test fails.
     */
    @Test
    void aStatusChangeOnALockedListIsRefusedRetryablyWithinTheBoundAndQueuesNothing() throws Exception {
        closeEveryPendingTransaction();
        io.mosip.certify.status.TokenStatusListService.Entry lockedEntry = tokenStatusLists.allocate("revocation");
        String locked = listIdOf(lockedEntry);
        io.mosip.certify.status.TokenStatusListService.Entry otherEntry = tokenStatusLists.allocateCwt("revocation", dscSigning());
        String other = listIdOf(otherEntry);
        assertNotEquals(locked, other);
        java.time.Duration bound = statusListLockWait.lockWait();
        assertEquals(java.time.Duration.ofSeconds(5), bound, "the default certify.status.update.lock-wait");
        String basic = "Basic " + Base64.getEncoder().encodeToString("coordinator:s3cret".getBytes(StandardCharsets.UTF_8));
        String legacyBody = objectMapper.writeValueAsString(Map.of("credentialStatus", Map.of("id", locked,
                "type", "TokenStatusListEntry", "statusPurpose", "revocation", "statusListIndex", lockedEntry.idx(),
                "statusListCredential", locked), "status", true));
        String vcApiBody = objectMapper.writeValueAsString(Map.of("credentialId", "urn:uuid:not-needed",
                "credentialStatus", Map.of("type", "TokenStatusListEntry", "statusPurpose", "revocation",
                        "statusListCredential", locked, "statusListIndex", lockedEntry.idx()), "status", true));

        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(3);
        try (Connection holder = dataSource.getConnection()) {
            holder.setAutoCommit(false);
            try {
                lockListRow(holder, locked);
                java.util.concurrent.Future<Timed<Throwable>> service = pool.submit(() -> timed(() -> {
                    try {
                        queue(locked, lockedEntry.idx(), true);
                        return null;
                    } catch (Throwable refused) {
                        return refused;
                    }
                }));
                java.util.concurrent.Future<Timed<MvcResult>> legacy = pool.submit(() -> timed(() -> mockMvc.perform(
                        post("/credentials/status").contentType(MediaType.APPLICATION_JSON).content(legacyBody)).andReturn()));
                java.util.concurrent.Future<Timed<MvcResult>> vcApi = pool.submit(() -> timed(() -> mockMvc.perform(
                        post("/vc-api/credentials/status").header("Authorization", basic)
                                .contentType(MediaType.APPLICATION_JSON).content(vcApiBody)).andReturn()));
                awaitLockWaiters(3, bound);

                // meanwhile: another list is not held up
                long started = System.nanoTime();
                queue(other, otherEntry.idx(), true);
                java.time.Duration otherTook = java.time.Duration.ofNanos(System.nanoTime() - started);
                assertTrue(otherTook.compareTo(java.time.Duration.ofSeconds(2)) < 0, "another list's change took " + otherTook);
                assertFalse(service.isDone() || legacy.isDone() || vcApi.isDone(),
                        "the other list's change completed while the locked list's changes were still waiting");
                assertEquals(1, pendingOn(other));

                long limit = bound.plusSeconds(10).toMillis();
                Timed<Throwable> refused = service.get(limit, java.util.concurrent.TimeUnit.MILLISECONDS);
                Timed<MvcResult> legacyResult = legacy.get(limit, java.util.concurrent.TimeUnit.MILLISECONDS);
                Timed<MvcResult> vcApiResult = vcApi.get(limit, java.util.concurrent.TimeUnit.MILLISECONDS);
                for (Timed<?> call : List.of(refused, legacyResult, vcApiResult)) {
                    assertTrue(call.took().compareTo(bound.minusMillis(500)) >= 0, "waited for the lock: " + call.took());
                    assertTrue(call.took().compareTo(bound.plusSeconds(3)) < 0, "and no longer than the bound: " + call.took());
                }
                assertTrue(refused.value() instanceof io.mosip.certify.core.exception.StatusListBusyException, String.valueOf(refused.value()));
                assertEquals("status_list_busy_retry_later",
                        ((io.mosip.certify.core.exception.StatusListBusyException) refused.value()).getErrorCode());
                assertEquals(200, legacyResult.value().getResponse().getStatus(), "the legacy surface's error wrapper");
                assertTrue(legacyResult.value().getResponse().getContentAsString().contains("status_list_busy_retry_later"),
                        legacyResult.value().getResponse().getContentAsString());
                assertEquals(503, vcApiResult.value().getResponse().getStatus(), vcApiResult.value().getResponse().getContentAsString());
                assertEquals("5", vcApiResult.value().getResponse().getHeader("Retry-After"));
                assertTrue(vcApiResult.value().getResponse().getContentAsString().contains("status_list_busy_retry_later"));
                assertEquals(0, pendingOn(locked), "nothing was queued for the locked list");
            } finally {
                holder.rollback();
            }
        } finally {
            pool.shutdownNow();
        }
        queue(locked, lockedEntry.idx(), true); // the lock released: the same change goes through
        assertEquals(1, pendingOn(locked));
        closeEveryPendingTransaction();
    }

    /**
     * Review round 5, finding 1, the batch path (PostgreSQL): a run waits for a list's row lock at most
     * {@code certify.status.update.lock-wait}, then leaves that list's transactions pending and applies the other lists;
     * the next run, once the lock is free, applies the skipped list.
     */
    @Test
    void aBatchRunSkipsALockedListWithinTheBoundAndAppliesTheOthers() throws Exception {
        closeEveryPendingTransaction();
        io.mosip.certify.status.TokenStatusListService.Entry lockedEntry = tokenStatusLists.allocateCwt("revocation", dscSigning());
        String locked = listIdOf(lockedEntry);
        io.mosip.certify.status.TokenStatusListService.Entry freeEntry = tokenStatusLists.allocate("revocation");
        String free = listIdOf(freeEntry);
        queue(locked, lockedEntry.idx(), true); // the older: the run visits the locked list first
        queue(free, freeEntry.idx(), true);
        java.time.Duration bound = statusListLockWait.lockWait();
        StatusListUpdateBatchJob job = org.springframework.test.util.AopTestUtils.getTargetObject(batchJob);

        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newSingleThreadExecutor();
        try (Connection holder = dataSource.getConnection()) {
            holder.setAutoCommit(false);
            try {
                lockListRow(holder, locked);
                Timed<Object> run = pool.submit(() -> timed(() -> {
                    run(job);
                    return null;
                })).get(bound.plusSeconds(30).toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
                assertTrue(run.took().compareTo(bound.minusMillis(500)) >= 0, "the run waited for the lock: " + run.took());
                assertEquals(1, pendingOn(locked), "the locked list's transaction stays pending");
                assertFalse(cwtBit(locked, lockedEntry.idx()));
                assertEquals(0, pendingOn(free), "the list behind it is applied in the same run");
                byte[] bits = io.mosip.certify.status.TokenStatusListService.decode(SignedJWT.parse(
                        statusListRepository.findDocumentById(free).orElseThrow()).getJWTClaimsSet()
                        .getJSONObjectClaim("status_list").get("lst").toString());
                assertTrue(io.mosip.certify.status.TokenStatusListService.get(bits, freeEntry.idx()));
            } finally {
                holder.rollback();
            }
        } finally {
            pool.shutdownNow();
        }
        run(job);
        assertEquals(0, pendingOn(locked), "the next run applies the skipped list");
        assertTrue(cwtBit(locked, lockedEntry.idx()));
    }

    /** Takes a list's row lock as the batch job does ({@code for no key update}), in {@code holder}'s transaction. */
    private static void lockListRow(Connection holder, String listId) throws Exception {
        try (PreparedStatement ps = holder.prepareStatement("SELECT id FROM " + SCHEMA
                + ".status_list_credential WHERE id = ? FOR NO KEY UPDATE")) {
            ps.setString(1, listId);
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next(), "the list's row");
            }
        }
    }

    /** Waits until {@code count} sessions wait for a lock, so what follows happens while they wait. */
    private void awaitLockWaiters(int count, java.time.Duration within) throws Exception {
        long deadline = System.nanoTime() + within.toNanos();
        int waiting = 0;
        while (System.nanoTime() < deadline) {
            try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement(
                    "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()");
                 java.sql.ResultSet rs = ps.executeQuery()) {
                rs.next();
                waiting = rs.getInt(1);
            }
            if (waiting >= count) {
                return;
            }
            Thread.sleep(25);
        }
        throw new AssertionError(waiting + " session(s) wait for a lock, expected " + count);
    }

    private record Timed<T>(T value, java.time.Duration took) {
    }

    private static <T> Timed<T> timed(java.util.concurrent.Callable<T> call) throws Exception {
        long started = System.nanoTime();
        T value = call.call();
        return new Timed<>(value, java.time.Duration.ofNanos(System.nanoTime() - started));
    }

    /**
     * Finding 2 (G43) at the API on PostgreSQL: an index that is not on the list is refused before anything is queued,
     * through each surface's error mapping — the MOSIP error wrapper on {@code /credentials/status} (as for an unknown
     * list), {@code 400} on VC-API — for a negative index, 2^35 and the index equal to the list's size.
     */
    @Test
    void anIndexNotOnTheListIsRefusedAtTheApi() throws Exception {
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocate("revocation");
        String listId = listIdOf(entry);
        long size = tokenStatusLists.capacity(statusListRepository.findById(listId).orElseThrow()).orElseThrow();
        assertEquals(tokenStatusListProperties.sizeBits(), size);
        String basic = "Basic " + Base64.getEncoder().encodeToString("coordinator:s3cret".getBytes(StandardCharsets.UTF_8));
        for (long index : new long[]{-1L, 1L << 35, size}) {
            MvcResult legacy = mockMvc.perform(post("/credentials/status").contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(Map.of("credentialStatus", Map.of("id", listId,
                            "type", "TokenStatusListEntry", "statusPurpose", "revocation", "statusListIndex", index,
                            "statusListCredential", listId), "status", true)))).andReturn();
            assertTrue(legacy.getResponse().getContentAsString().contains("requested_index_is_out_of_bounds_for_status_list_capacity"),
                    index + ": " + legacy.getResponse().getContentAsString());
            MvcResult vcApi = mockMvc.perform(post("/vc-api/credentials/status").header("Authorization", basic)
                    .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of(
                            "credentialId", "urn:uuid:not-needed", "credentialStatus", Map.of("type", "TokenStatusListEntry",
                                    "statusPurpose", "revocation", "statusListCredential", listId, "statusListIndex", index),
                            "status", true)))).andReturn();
            assertEquals(400, vcApi.getResponse().getStatus(), index + ": " + vcApi.getResponse().getContentAsString());
        }
        assertEquals(0, pendingOn(listId), "nothing was queued");
        queue(listId, size - 1, true); // the last index is on the list
        assertEquals(1, pendingOn(listId));
    }

    /**
     * Finding 2 in the job on PostgreSQL, a JWT list: rows that bypassed the API (queued before this release, or written
     * by hand) with a negative index, 2^35 and the size are closed on their own, and the valid revocation queued behind
     * them is published in the same run; index 0, where 2^35 used to land, stays valid.
     */
    @Test
    void queuedIndicesNotOnTheListAreClosedAndTheValidOneBehindThemIsApplied() throws Exception {
        closeEveryPendingTransaction();
        io.mosip.certify.status.TokenStatusListService.Entry entry = tokenStatusLists.allocate("revocation");
        String listId = listIdOf(entry);
        long size = tokenStatusListProperties.sizeBits();
        transactionRepository.save(pending("bad-negative", listId, -1));
        transactionRepository.save(pending("bad-overflow", listId, 1L << 35));
        transactionRepository.save(pending("bad-size", listId, size));
        transactionRepository.save(pending("good", listId, size - 1));

        run(org.springframework.test.util.AopTestUtils.getTargetObject(batchJob));

        byte[] bits = io.mosip.certify.status.TokenStatusListService.decode(SignedJWT.parse(
                statusListRepository.findDocumentById(listId).orElseThrow()).getJWTClaimsSet()
                .getJSONObjectClaim("status_list").get("lst").toString());
        assertTrue(io.mosip.certify.status.TokenStatusListService.get(bits, size - 1), "the valid revocation is published");
        assertFalse(io.mosip.certify.status.TokenStatusListService.get(bits, 0), "2^35 does not land on index 0");
        assertEquals(0, pendingOn(listId), "every row is closed; nothing blocks the list");
    }

    private io.mosip.certify.spi.SigningContext dscSigning() {
        return keyProviders.signingContext(io.mosip.certify.spi.SigningConfig.of(
                io.mosip.certify.signing.KeyRef.parse("x509-file:sdjwt-es256"), io.mosip.certify.signing.SignatureAlgorithm.ES256));
    }

    /** A status change through the service the status APIs call: the list's lock, the index check, the insert. */
    private void queue(String listId, long idx, boolean value) {
        io.mosip.certify.core.dto.UpdateCredentialStatusRequest request = new io.mosip.certify.core.dto.UpdateCredentialStatusRequest();
        io.mosip.certify.core.dto.UpdateCredentialStatusRequest.CredentialStatusDto status =
                new io.mosip.certify.core.dto.UpdateCredentialStatusRequest.CredentialStatusDto();
        status.setStatusListCredential(listId);
        status.setStatusListIndex(idx);
        status.setStatusPurpose("revocation");
        request.setCredentialStatus(status);
        request.setStatus(value);
        credentialStatusService.updateCredentialStatus(request);
    }

    private long pendingOn(String listId) {
        return transactionRepository.findPendingForList(listId, PageRequest.of(0, 1000)).size();
    }

    private boolean cwtBit(String listId, long idx) {
        return io.mosip.certify.status.TokenStatusListService.get(io.mosip.certify.status.TokenStatusListCwt.decode(
                java.util.Base64.getUrlDecoder().decode(tokenStatusLists.envelope(
                        statusListRepository.findDocumentById(listId).orElseThrow()).token())).lst(), idx);
    }

    /** What earlier tests left pending is theirs: a whole-job run here must see only its own rows. */
    private void closeEveryPendingTransaction() throws Exception {
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement("UPDATE " + SCHEMA
                + ".credential_status_transaction SET is_processed = true WHERE is_processed = false")) {
            ps.executeUpdate();
        }
    }

    /** One scheduled run of {@code job}, as ShedLock would start it. */
    private static void run(StatusListUpdateBatchJob job) {
        Object enabled = org.springframework.test.util.ReflectionTestUtils.getField(job, "batchJobEnabled");
        org.springframework.test.util.ReflectionTestUtils.setField(job, "batchJobEnabled", true);
        net.javacrumbs.shedlock.core.LockAssert.TestHelper.makeAllAssertsPass(true);
        try {
            job.updateStatusLists();
        } finally {
            net.javacrumbs.shedlock.core.LockAssert.TestHelper.makeAllAssertsPass(false);
            org.springframework.test.util.ReflectionTestUtils.setField(job, "batchJobEnabled", enabled);
        }
    }

    /** Another instance of the job on the same database and the same applier, reading through {@code transactions}. */
    private StatusListUpdateBatchJob secondInstance(CredentialStatusTransactionRepository transactions) {
        StatusListUpdateBatchJob job = new StatusListUpdateBatchJob();
        org.springframework.test.util.ReflectionTestUtils.setField(job, "transactionRepository", transactions);
        org.springframework.test.util.ReflectionTestUtils.setField(job, "applier", applier);
        org.springframework.test.util.ReflectionTestUtils.setField(job, "tokenStatusLists",
                applicationContext.getBeanProvider(io.mosip.certify.status.TokenStatusListService.class));
        org.springframework.test.util.ReflectionTestUtils.setField(job, "tokenStatusListProperties",
                applicationContext.getBeanProvider(io.mosip.certify.status.TokenStatusListProperties.class));
        org.springframework.test.util.ReflectionTestUtils.setField(job, "meterRegistry",
                applicationContext.getBeanProvider(io.micrometer.core.instrument.MeterRegistry.class));
        org.springframework.test.util.ReflectionTestUtils.setField(job, "batchJobEnabled", true);
        org.springframework.test.util.ReflectionTestUtils.setField(job, "batchSize", 1000);
        return job;
    }

    /** The application's repository, except that the first selection runs {@code meanwhile} before it is returned. */
    private CredentialStatusTransactionRepository pausingAfterTheSelection(ThrowingRunnable meanwhile) {
        java.util.concurrent.atomic.AtomicReference<ThrowingRunnable> once = new java.util.concurrent.atomic.AtomicReference<>(meanwhile);
        return (CredentialStatusTransactionRepository) java.lang.reflect.Proxy.newProxyInstance(
                CredentialStatusTransactionRepository.class.getClassLoader(),
                new Class<?>[]{CredentialStatusTransactionRepository.class}, (proxy, method, args) -> {
                    Object result;
                    try {
                        result = method.invoke(transactionRepository, args);
                    } catch (java.lang.reflect.InvocationTargetException e) {
                        throw e.getCause();
                    }
                    if (method.getName().equals("findPending") || method.getName().equals("findPendingExcluding")) {
                        ThrowingRunnable pending = once.getAndSet(null);
                        if (pending != null) {
                            pending.run();
                        }
                    }
                    return result;
                });
    }

    private static String listIdOf(io.mosip.certify.status.TokenStatusListService.Entry entry) {
        return entry.uri().substring(entry.uri().lastIndexOf('/') + 1);
    }

    /** Takes the list's free indices away without assigning them: the next allocation finds the pool exhausted. */
    private void exhaustThePool(String listId) throws Exception {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("DELETE FROM " + SCHEMA
                     + ".status_list_available_indices WHERE status_list_credential_id = ? AND is_assigned = false")) {
            ps.setString(1, listId);
            ps.executeUpdate();
        }
    }

    /**
     * The application's index provider, except that the first call for {@code listId} first lets another writer commit
     * {@code commit} on another thread (its own transaction) and waits for it: the allocation has read the list by then and
     * has not yet learnt that its pool is exhausted.
     */
    private io.mosip.certify.services.StatusListIndexProvider committingDuringTheIndexCall(String listId, ThrowingRunnable commit) {
        java.util.concurrent.atomic.AtomicBoolean done = new java.util.concurrent.atomic.AtomicBoolean();
        return new io.mosip.certify.services.StatusListIndexProvider() {
            @Override
            public String getProviderName() {
                return "committing-during-the-index-call";
            }

            @Override
            public java.util.Optional<Long> acquireIndex(String id, Map<String, Object> options) {
                if (listId.equals(id) && done.compareAndSet(false, true)) {
                    java.util.concurrent.ExecutorService other = java.util.concurrent.Executors.newSingleThreadExecutor();
                    try {
                        other.submit(() -> {
                            commit.run();
                            return null;
                        }).get(60, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (Exception e) {
                        throw new IllegalStateException("the concurrent revocation failed", e);
                    } finally {
                        other.shutdownNow();
                    }
                }
                return statusListIndexProvider.acquireIndex(id, options);
            }
        };
    }

    private static CredentialStatusTransaction pending(String credentialId, String listId, long idx) {
        CredentialStatusTransaction txn = new CredentialStatusTransaction();
        txn.setCredentialId(credentialId);
        txn.setStatusPurpose("revocation");
        txn.setStatusValue(true);
        txn.setStatusListCredentialId(listId);
        txn.setStatusListIndex(idx);
        txn.setCreatedDtimes(java.time.LocalDateTime.now());
        txn.setIsProcessed(false);
        return txn;
    }

    /** Runs the given tasks at once and rethrows the first failure, so a lost update or a deadlock fails the test. */
    private static void concurrently(int threads, List<ThrowingRunnable> tasks) throws Exception {
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
        try {
            java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
            List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
            for (ThrowingRunnable task : tasks) {
                futures.add(pool.submit(() -> {
                    start.await();
                    task.run();
                    return null;
                }));
            }
            start.countDown();
            for (java.util.concurrent.Future<?> future : futures) {
                future.get(60, java.util.concurrent.TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

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

    /** The batch job writes {@code validFrom} from its clock; {@code null} restores the real one. */
    private void pinBatchClock(Instant instant) {
        batchJob.setClock(instant == null ? Clock.systemUTC() : Clock.fixed(instant, ZoneOffset.UTC));
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
