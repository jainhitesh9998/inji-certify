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
import com.upokecenter.cbor.CBORType;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.db.FlywayDefaults;
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.services.StatusListUpdateBatchJob;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.StatusConfig;
import io.mosip.certify.spi.StatusProvider;
import io.mosip.certify.spi.UnsignedCredential;
import io.mosip.certify.status.StatusListSignerPolicy;
import io.mosip.certify.status.TokenStatusListCwt;
import io.mosip.certify.status.TokenStatusListProperties;
import io.mosip.certify.status.TokenStatusListProvider;
import io.mosip.certify.status.TokenStatusListService;
import net.javacrumbs.shedlock.core.LockAssert;
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
import org.springframework.test.util.AopTestUtils;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * M-11e: the issuance binding of {@code docs/design/wp/M-11-status-list-under-iaca.md} section 5, on PostgreSQL (the
 * status-list tables need {@code generate_series}, which H2 cannot run) with the {@code x509-file} provider in dev mode
 * holding an Annex B IACA and two Document Signer versions.
 *
 * <p>It proves, end to end:
 * <ul>
 *   <li>an mDL issued through {@code /oid4vci} points at a CWT Status List Token signed by <b>its own</b> Document
 *   Signer — the list's {@code x5chain} equals the mDL's IssuerAuth {@code x5chain}, the rule Credo and Paradym apply
 *   (ISO/IEC 18013-5 second edition 12.3.6.3, TSL section 11.3);</li>
 *   <li>the same through the draft-13 surface, and the revocation of the first one through
 *   {@code POST /credentials/status} plus the batch job: the bit is set and the list is re-signed by the same
 *   Document Signer;</li>
 *   <li>three samples for {@code certify-conformance-mdoc} — {@code …-oid4vci}, {@code …-d13} and {@code …-revoked} (the
 *   last declaring {@code expectedStatus} 1) — each with the list its MSO points at and the configured IACA;</li>
 *   <li>two Document Signer versions get two lists, each with its own {@code x5chain};</li>
 *   <li>a keymanager DSC is refused at issuance once an IACA is configured, <b>before an index is consumed</b>;</li>
 *   <li>a stored purpose other than {@code revocation} is refused at issuance with {@code status_list_unavailable}
 *   (ISO/IEC 18013-5 second edition 12.3.6.1, D-M11-5) — the case the v2 API prevents at save time;</li>
 *   <li>{@code mdoc.token-format=jwt} keeps today's shared JWT list, and an SD-JWT VC in the same deployment still gets
 *   one (I4).</li>
 * </ul>
 * Skipped without Docker.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@Testcontainers(disabledWithoutDocker = true)
@TestPropertySource(properties = {
        "mosip.certify.issuer.ledger-enabled=false",
        "mosip.certify.authn.filter-urls={'/issuance/credential'}", // the draft-13 surface keeps its bearer filter list
        "mosip.certify.batch.status-list-update.enabled=false",       // the test drives the batch step itself
        "certify.status.token-status-list.size-bits=8192", // 1 KB of bits: the smallest size whose index pool matches it
        "certify.status.token-status-list.key-ref=x509-file:mdl-dsc@2026-11", // the JWT lists (I4) sign with this
        "certify.keyprovider.x509-file.enabled=true",
        "certify.keyprovider.x509-file.dev-mode=true",
        "certify.keyprovider.x509-file.path=" + MdocStatusListSampleTest.DIRECTORY + "/x509-file.p12",
        "certify.keyprovider.x509-file.password=mdoc-status-list",
        "certify.keyprovider.x509-file.iaca.country=IN",
        "certify.keyprovider.x509-file.iaca.common-name=Lorem Ipsum Sample IACA",
        "certify.keyprovider.x509-file.iaca.issuer-alt-name=https://certify.example.test/v1/certify/mdoc/iaca",
        "certify.keyprovider.x509-file.iaca.crl-uri=" + MdocStatusListSampleTest.PUBLIC_BASE + "/mdoc/iaca/sample-iaca.crl",
        "certify.keyprovider.x509-file.keys[0].alias=mdl-dsc@2026-11",
        "certify.keyprovider.x509-file.keys[0].algorithm=ES256",
        "certify.keyprovider.x509-file.keys[0].subject=CN=Lorem Ipsum Sample DSC 2026",
        "certify.keyprovider.x509-file.keys[0].profile=mdoc-dsc",
        "certify.keyprovider.x509-file.keys[1].alias=mdl-dsc@2027-01",
        "certify.keyprovider.x509-file.keys[1].algorithm=ES256",
        "certify.keyprovider.x509-file.keys[1].subject=CN=Lorem Ipsum Sample DSC 2027",
        "certify.keyprovider.x509-file.keys[1].profile=mdoc-dsc",
        "mosip.certify.domain.url=" + MdocStatusListSampleTest.PUBLIC_BASE,
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
class MdocStatusListSampleTest {

    static final String SCHEMA = "certify";
    static final String DIRECTORY = "target/mdoc-status-list-sample";
    static final String PUBLIC_BASE = "http://localhost:8090";
    /** The Annex B IACA of the x509-file dev mode; its anchor id is the name in its own CRL distribution point. */
    static final String IACA_ID = "sample-iaca";
    static final String MDL = "org.iso.18013.5.1.mDL";
    static final String CONFIG = "MdocStatusListX509";
    static final String ROTATED = "MdocStatusListRotated";
    static final String KEYMANAGER = "MdocStatusListKeymanager";
    static final String SUSPENSION = "MdocStatusListSuspension";
    static final String SDJWT = "MdocStatusListSdJwt";

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:15-alpine");

    /** What a deployment does before the service starts: the Flyway job, then the keymanager policy rows. */
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
                Files.delete(file); // fresh keys for the fresh key_alias table
            }
        }
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driverClassName", () -> "org.postgresql.Driver");
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.sql.init.mode", () -> "never"); // schema.sql and data.sql are H2 only
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
    @Autowired KeyProviderRegistry keyProviders;
    @Autowired TrustAnchorRegistry trustAnchors;
    @Autowired TokenStatusListService lists;
    @Autowired TokenStatusListProperties listProperties;
    @Autowired StatusListCredentialRepository listRepository;
    @Autowired CredentialConfigRepository configurations;
    @Autowired StatusListUpdateBatchJob batchJob;
    @Autowired DataSource dataSource;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of(
                "fullName", "Status List Holder", "dateOfBirth", "1990-01-01", "city", "Bengaluru")));
        mdocConfiguration(CONFIG, MDL, null, "mdl-dsc@2026-11");
        mdocConfiguration(ROTATED, MDL + ".rotated", null, "mdl-dsc@2027-01");
        mdocConfiguration(KEYMANAGER, MDL + ".keymanager", "keymanager", "CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN");
        mdocConfiguration(SUSPENSION, MDL + ".suspension", null, "mdl-dsc@2026-11");
        sdJwtConfiguration();
    }

    // ---- the samples ---------------------------------------------------------------------------------------------

    /**
     * The three samples of this package: an mDL through {@code /oid4vci}, one through the draft-13 surface, and the first
     * one again once it is revoked. Each carries the list its MSO points at and — because the mDL's {@code x5chain} is
     * {@code without-anchor} — the configured IACA the verifier anchors to (M-06, HAIP).
     */
    @Test
    void mdocSamplesThroughBothSurfacesAndTheirRevokedList() throws Exception {
        Proof proof = proof("/oid4vci/nonce", "/oid4vci");
        Issued issued = issueMdl(CONFIG, MDL, proof);
        assertTrue(io.mosip.certify.signing.CertificateLinks.issuedBy(issued.list().x5chain().get(0), IACA()),
                "the list's signer is issued by the configured IACA (ISO2 12.3.6.2)");
        assertEquals(leafOf(issued.credential()), issued.list().x5chain().get(0),
                "the list's x5chain is exactly the mDL's IssuerAuth x5chain (Credo's rule)");
        assertFalse(TokenStatusListService.get(issued.list().lst(), issued.idx()), "a fresh mDL is VALID");
        MdocSampleWriter.writeStatusList(issued.sample(), issued.body(), TokenStatusListCwt.MEDIA_TYPE, 0);

        Issued draft13 = issueMdlDraft13(CONFIG, MDL);
        assertEquals(issued.listUrn(), draft13.listUrn(), "both mDLs share the Document Signer's one list");
        MdocSampleWriter.writeStatusList(draft13.sample(), draft13.body(), TokenStatusListCwt.MEDIA_TYPE, 0);

        revoke(issued.listId(), issued.idx());
        Served renewed = served(issued.listId());
        assertTrue(TokenStatusListService.get(renewed.list().lst(), issued.idx()), "the revoked bit is set");
        assertEquals(leafOf(issued.credential()), renewed.list().x5chain().get(0),
                "the revocation re-signs the list with the same Document Signer");
        // the same credential, as its own sample: its own `.statuslist.*` sidecars say the list now reports INVALID
        Path revoked = MdocSampleWriter.write(getClass(), "revoked",
                Base64.getUrlEncoder().withoutPadding().encodeToString(issued.credential()), proof.holder(), MDL, List.of(), IACA());
        MdocSampleWriter.writeStatusList(revoked, renewed.body(), TokenStatusListCwt.MEDIA_TYPE, 1);
    }

    /** An SD-JWT VC issued in the same deployment still gets a Token Status List JWT entry, byte for byte (I4). */
    @Test
    void anSdJwtVcStillGetsAJwtListEntry() throws Exception {
        JsonNode body = issuedBody(credentialRequest(SDJWT, Map.of("proofs", Map.of("jwt", List.of(proof("/oid4vci/nonce", "/oid4vci").jwt())))));
        String compact = body.get("credentials").get(0).get("credential").asText().split("~")[0];
        Map<String, Object> status = SignedJWT.parse(compact).getJWTClaimsSet().getJSONObjectClaim("status");
        String uri = String.valueOf(((Map<?, ?>) status.get("status_list")).get("uri"));
        String listId = uri.substring(uri.lastIndexOf('/') + 1);
        assertEquals(TokenStatusListService.TYPE, listRepository.findById(listId).orElseThrow().getCredentialType(),
                "an SD-JWT VC keeps today's Token Status List JWT (I4)");
        MvcResult served = mockMvc.perform(get("/credentials/token-status-list/" + listId)).andReturn();
        assertEquals(200, served.getResponse().getStatus());
        assertEquals(TokenStatusListService.MEDIA_TYPE, served.getResponse().getContentType());
        assertEquals(TokenStatusListService.TYP, SignedJWT.parse(served.getResponse().getContentAsString()).getHeader().getType().getType());
    }

    // ---- the binding ---------------------------------------------------------------------------------------------

    /** Two Document Signer versions get two lists, and each list's {@code x5chain} is its own mDL's. */
    @Test
    void aRotatedDocumentSignerGetsItsOwnList() throws Exception {
        Issued first = issueMdl(CONFIG, MDL, proof("/oid4vci/nonce", "/oid4vci"));
        Issued rotated = issueMdl(ROTATED, MDL + ".rotated", proof("/oid4vci/nonce", "/oid4vci"));

        assertNotEquals(first.listId(), rotated.listId(), "a rotated Document Signer starts new lists (section 4.3)");
        assertNotEquals(leafOf(first.credential()), leafOf(rotated.credential()), "two different DSCs signed them");
        assertEquals(leafOf(first.credential()), first.list().x5chain().get(0));
        assertEquals(leafOf(rotated.credential()), rotated.list().x5chain().get(0));
        assertFalse(TokenStatusListService.get(first.list().lst(), first.idx()), "the list it points at says VALID");
    }

    /**
     * Once an IACA is configured the signer policy refuses a keymanager DSC ({@code STATUS_SIGNER_NO_TRUSTED_IACA}), and
     * the signing context is resolved before the status step, so the refusal consumes no index.
     */
    @Test
    void aKeymanagerDocumentSignerIsRefusedBeforeAnIndexIsConsumed() throws Exception {
        long freeBefore = freeIndices();

        MvcResult refused = credentialRequest(KEYMANAGER, Map.of("proofs", Map.of("jwt", List.of(proof("/oid4vci/nonce", "/oid4vci").jwt()))));

        assertEquals(500, refused.getResponse().getStatus());
        String description = objectMapper.readTree(refused.getResponse().getContentAsString()).get("error_description").asText();
        assertTrue(description.contains("status_list_unavailable") && description.contains(StatusListSignerPolicy.NO_TRUSTED_IACA),
                description);
        assertEquals(freeBefore, freeIndices(), "no index was consumed by the refused mDL");
    }

    /**
     * A row whose stored purpose is {@code suspension} — which the v2 API refuses to write, while a row written before
     * that rule (or by an operator's SQL) can exist (D-M11-5) — is refused at issuance instead of producing an mDL whose
     * list no verifier reads for its purpose.
     */
    @Test
    void aStoredSuspensionPurposeIsRefusedAtIssuance() throws Exception {
        try (Connection c = dataSource.getConnection(); PreparedStatement ps = c.prepareStatement("UPDATE " + SCHEMA
                + ".credential_config SET status_config = ?::jsonb WHERE credential_config_key_id = ?")) {
            ps.setString(1, "{\"mechanism\":\"TokenStatusList\",\"purposes\":[\"suspension\"]}");
            ps.setString(2, SUSPENSION);
            assertEquals(1, ps.executeUpdate());
        }
        long freeBefore = freeIndices();

        MvcResult refused = credentialRequest(SUSPENSION, Map.of("proofs", Map.of("jwt", List.of(proof("/oid4vci/nonce", "/oid4vci").jwt()))));

        assertEquals(500, refused.getResponse().getStatus());
        String description = objectMapper.readTree(refused.getResponse().getContentAsString()).get("error_description").asText();
        assertTrue(description.contains("status_list_unavailable") && description.contains("12.3.6.1"), description);
        assertEquals(freeBefore, freeIndices(), "no index was consumed by the refused mDL");
    }

    /** {@code mdoc.token-format=jwt} is today's shared JWT list, byte for byte (D-M11-3's escape hatch). */
    @Test
    void theJwtTokenFormatEscapeHatchKeepsTheSharedJwtList() {
        TokenStatusListProvider escapeHatch = new TokenStatusListProvider(lists,
                new TokenStatusListProperties(listProperties.keyRef(), listProperties.alg(), listProperties.x5c(),
                        listProperties.sizeBits(), listProperties.ttl(), listProperties.renewWait(), listProperties.renewBackoff(),
                        new TokenStatusListProperties.Mdoc(TokenStatusListProperties.Mdoc.FORMAT_JWT,
                                TokenStatusListProperties.Mdoc.SIGNER_DOCUMENT, null), listProperties.batch()));
        CredentialConfiguration configuration = new CredentialConfiguration(null, KEYMANAGER, "sample_vc_ldp", "mso_mdoc", null, null,
                SigningConfig.of(KeyRef.parse("x509-file:mdl-dsc@2026-11"), SignatureAlgorithm.ES256), null, null,
                new StatusConfig(TokenStatusListProvider.MECHANISM, List.of("revocation")), null, null);

        UnsignedCredential attached = escapeHatch.attach(new UnsignedCredential("mso_mdoc", Map.of("docType", MDL), Map.of()),
                configuration, null, new StatusProvider.StatusBinding(signing("mdl-dsc@2026-11"), "cwt"));

        String uri = listUri(attached);
        String listId = uri.substring(uri.lastIndexOf('/') + 1);
        assertEquals(TokenStatusListService.TYPE, listRepository.findById(listId).orElseThrow().getCredentialType(),
                "token-format=jwt keeps the pre-M-11 JWT row for an mso_mdoc");
        assertTrue(uri.startsWith(PUBLIC_BASE), uri);
    }

    // ---- helpers ------------------------------------------------------------------------------------------------

    /** An issued credential and the list its MSO points at, the sample it was written as, and the list as served. */
    private record Issued(Path sample, byte[] credential, String listUrn, long idx, TokenStatusListCwt.Decoded list, byte[] body) {
        String listId() {
            return listUrn.substring(listUrn.lastIndexOf('/') + 1);
        }
    }

    /** The list as the endpoint answered it: the token and its bytes (one GET, so the two cannot differ). */
    private record Served(TokenStatusListCwt.Decoded list, byte[] body) {}

    /** A holder key and the proof bound to it, so the sample records the device key the MSO carries. */
    private record Proof(ECKey holder, String jwt) {}

    private Issued issueMdl(String configurationId, String docType, Proof proof) throws Exception {
        JsonNode body = issuedBody(credentialRequest(configurationId,
                Map.of("proofs", Map.of("jwt", List.of(proof.jwt())))));
        String credential = body.get("credentials").get(0).get("credential").asText();
        byte[] issuerSigned = Base64.getUrlDecoder().decode(credential);
        StatusRef status = statusOf(issuerSigned);
        Served served = served(status.listId());
        Path sample = MdocSampleWriter.write(getClass(), "oid4vci", credential, proof.holder(), docType, List.of(), IACA());
        return new Issued(sample, issuerSigned, status.uri(), status.idx(), served.list(), served.body());
    }

    private Issued issueMdlDraft13(String configurationId, String docType) throws Exception {
        Proof proof = proof("/nonce", "");
        MvcResult result = mockMvc.perform(post("/issuance/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(Map.of("format", "mso_mdoc",
                        "doctype", docType, "proof", Map.of("proof_type", "jwt", "jwt", proof.jwt()))))).andReturn();
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        String credential = body.get("credential").asText();
        byte[] received = Base64.getUrlDecoder().decode(credential);
        StatusRef status = statusOf(issuerSignedOf(received));
        Served served = served(status.listId());
        Path sample = MdocSampleWriter.write(getClass(), "d13", credential, proof.holder(), docType,
                List.of(MdocSampleWriter.DOCUMENT_WRAPPER, MdocSampleWriter.TAGGED_ISSUER_AUTH), IACA());
        return new Issued(sample, received, status.uri(), status.idx(), served.list(), served.body());
    }

    /** The MSO's {@code status.status_list}: the list's URI and this credential's index (ISO2 12.3.6). */
    private record StatusRef(String uri, long idx) {
        String listId() {
            return uri.substring(uri.lastIndexOf('/') + 1);
        }
    }

    /** The {@code IssuerSigned} of a credential: the bytes themselves, or the draft-13 {@code Document}'s value. */
    private static byte[] issuerSignedOf(byte[] received) {
        CBORObject top = CBORObject.DecodeFromBytes(received);
        return top.getType() == CBORType.Map && top.ContainsKey("issuerSigned") ? top.get("issuerSigned").EncodeToBytes() : received;
    }

    private static StatusRef statusOf(byte[] issuerSigned) {
        CBORObject issuerAuth = CBORObject.DecodeFromBytes(issuerSigned).get("issuerAuth");
        if (issuerAuth.isTagged()) {
            issuerAuth = issuerAuth.Untag();
        }
        CBORObject mso = CBORObject.DecodeFromBytes(issuerAuth.get(2).GetByteString());
        if (mso.HasMostOuterTag(24)) {
            mso = CBORObject.DecodeFromBytes(mso.Untag().GetByteString());
        }
        CBORObject statusList = mso.get("status").get("status_list");
        return new StatusRef(statusList.get("uri").AsString(), statusList.get("idx").AsInt64Value());
    }

    private Served served(String listId) throws Exception {
        MvcResult result = mockMvc.perform(get("/credentials/token-status-list/" + listId)
                .header("Accept", TokenStatusListCwt.MEDIA_TYPE)).andReturn();
        assertEquals(200, result.getResponse().getStatus());
        assertEquals(TokenStatusListCwt.MEDIA_TYPE, result.getResponse().getContentType(),
                "the list is answered in its row's own format, whatever the Accept (D-M11-2)");
        byte[] body = result.getResponse().getContentAsByteArray();
        return new Served(TokenStatusListCwt.decode(body), body);
    }

    /** A status change through {@code POST /credentials/status}, then the batch job's application of it. */
    private void revoke(String listId, long idx) throws Exception {
        Map<String, Object> request = Map.of("credentialStatus", Map.of("statusPurpose", "revocation",
                "statusListCredential", listId, "statusListIndex", idx), "status", true);
        MvcResult queued = mockMvc.perform(post("/credentials/status").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))).andReturn();
        assertTrue(queued.getResponse().getStatus() == 200 || queued.getResponse().getStatus() == 204,
                queued.getResponse().getStatus() + " " + queued.getResponse().getContentAsString());
        StatusListUpdateBatchJob job = AopTestUtils.getTargetObject(batchJob);
        Object enabled = ReflectionTestUtils.getField(job, "batchJobEnabled");
        ReflectionTestUtils.setField(job, "batchJobEnabled", true);
        LockAssert.TestHelper.makeAllAssertsPass(true);
        try {
            job.updateStatusLists();
        } finally {
            LockAssert.TestHelper.makeAllAssertsPass(false);
            ReflectionTestUtils.setField(job, "batchJobEnabled", enabled);
        }
    }

    private MvcResult credentialRequest(String configurationId, Map<String, Object> proof) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("credential_configuration_id", configurationId);
        body.putAll(proof);
        return mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo")
                .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(body))).andReturn();
    }

    private JsonNode issuedBody(MvcResult result) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(200, result.getResponse().getStatus(), body.toString());
        return body;
    }

    /** Free (unassigned) status-list indices in the whole database: what a refused issuance must not touch. */
    private long freeIndices() throws Exception {
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement("SELECT count(*) FROM " + SCHEMA
                     + ".status_list_available_indices WHERE is_assigned = false");
             java.sql.ResultSet rows = ps.executeQuery()) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private String listUri(UnsignedCredential credential) {
        @SuppressWarnings("unchecked")
        Map<String, Object> status = (Map<String, Object>) credential.asMap().get("status");
        @SuppressWarnings("unchecked")
        Map<String, Object> statusList = (Map<String, Object>) status.get("status_list");
        return String.valueOf(statusList.get("uri"));
    }

    /**
     * A draft-13 (or {@code /oid4vci}) proof: ES256, {@code typ openid4vci-proof+jwt}, the holder's {@code jwk} in the
     * header, a nonce from {@code noncePath}, and the audience of the surface ({@code ""} for none, appended to the
     * issuer identifier).
     */
    private Proof proof(String noncePath, String surface) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        String nonce = noncePath == null ? null
                : objectMapper.readTree(mockMvc.perform(post(noncePath)).andReturn().getResponse().getContentAsString()).get("c_nonce").asText();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().audience(issuerIdentifier + surface).issueTime(new Date());
        if (nonce != null) {
            claims.claim("nonce", nonce);
        }
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(holder.toPublicJWK()).build(), claims.build());
        proof.sign(new ECDSASigner(holder));
        return new Proof(holder, proof.serialize());
    }

    private X509Certificate IACA() {
        return trustAnchors.anchor(TrustAnchorRegistry.MDOC_IACA, IACA_ID).orElseThrow().certificate();
    }

    private X509Certificate leafOf(byte[] credential) {
        return MdocSampleWriter.x5chain(credential).get(0);
    }

    private SigningContext signing(String alias) {
        return keyProviders.signingContext(SigningConfig.of(KeyRef.parse("x509-file:" + alias), SignatureAlgorithm.ES256));
    }

    /** A v2 {@code mso_mdoc} entry whose status block is {@code TokenStatusList}/{@code revocation} (the only v2-legal pair). */
    private void mdocConfiguration(String id, String docType, String provider, String alias) throws Exception {
        if (configurations.findByTenantIdAndCredentialConfigKeyId("default", id).isPresent()) {
            return;
        }
        Map<String, Object> signing = new LinkedHashMap<>();
        signing.put("provider", provider == null ? "x509-file" : provider);
        signing.put("alias", alias);
        signing.put("alg", "ES256");
        if (provider == null) {
            signing.put("x5c", "without-anchor"); // ISO/IEC 18013-5 9.1.2.4: the IssuerAuth carries the DSC
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

    /** An SD-JWT VC with the same status mechanism: its entries stay on JWT lists (section 4.10, I4). */
    private void sdJwtConfiguration() throws Exception {
        if (configurations.findByTenantIdAndCredentialConfigKeyId("default", SDJWT).isPresent()) {
            return;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", SDJWT);
        body.put("scope", "sample_vc_ldp");
        body.put("format", "dc+sd-jwt");
        body.put("formatConfig", Map.of("vct", "SampleStatusListCredential"));
        body.put("signing", Map.of("provider", "x509-file", "alias", "mdl-dsc@2026-11", "alg", "ES256", "x5c", "without-anchor"));
        body.put("template", Map.of("content", "{\"vct\":\"SampleStatusListCredential\",\"family_name\":\"${fullName}\"}"));
        body.put("status", Map.of("mechanism", "TokenStatusList", "purposes", List.of("revocation")));
        body.put("display", Map.of("display", List.of(Map.of("name", SDJWT, "locale", "en")), "order", List.of("family_name")));
        MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body))).andReturn();
        assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
    }

    private static String template() throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-mdoc.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }
}
