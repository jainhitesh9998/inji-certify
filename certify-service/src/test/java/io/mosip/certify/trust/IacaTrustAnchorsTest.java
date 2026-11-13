package io.mosip.certify.trust;

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
import io.mosip.certify.issuance.KeyProviderRegistry;
import io.mosip.certify.pki.AnnexBValidator;
import io.mosip.certify.pki.CrlBuilder;
import io.mosip.certify.pki.IsoMdocProfiles;
import io.mosip.certify.pki.Pem;
import io.mosip.certify.signing.CertificateLinks;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.TrustAnchorRegistry;
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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * M-06 and M-08 in the running service: the x509-file provider in dev mode with an Annex B IACA and a Document Signer,
 * two operator IACAs from files (one with a CRL), the DSC policy enforced on every surface, and the publication on.
 * The anchors are {@code operator-iaca} (configured id, CRL file), the second file's subject key identifier (no CRL),
 * {@code stale-iaca} (a CRL more than the grace past its nextUpdate at startup, with a Document Signer imported through
 * {@code pem-keys}; the service still starts) and {@code demo-iaca} (the x509-file IACA, named by its own CRL
 * distribution point, with a dev-mode CRL).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"local", "test"})
@TestPropertySource(properties = {
        "certify.keyprovider.x509-file.enabled=true",
        "certify.keyprovider.x509-file.dev-mode=true",
        "certify.keyprovider.x509-file.path=" + IacaTrustAnchorsTest.DIRECTORY + "/x509-file.p12",
        "certify.keyprovider.x509-file.password=trust-anchors-test",
        "certify.keyprovider.x509-file.iaca.country=IN",
        "certify.keyprovider.x509-file.iaca.common-name=Lorem Ipsum Demo Test IACA",
        "certify.keyprovider.x509-file.iaca.issuer-alt-name=https://certify.example.test/v1/certify/mdoc/iaca",
        "certify.keyprovider.x509-file.iaca.crl-uri=" + IacaTrustAnchorsTest.PUBLIC_BASE + "/mdoc/iaca/demo-iaca.crl",
        "certify.keyprovider.x509-file.keys[0].alias=mdl-dsc",
        "certify.keyprovider.x509-file.keys[0].algorithm=ES256",
        "certify.keyprovider.x509-file.keys[0].subject=CN=Lorem Ipsum Demo Test DSC",
        "certify.keyprovider.x509-file.keys[0].profile=mdoc-dsc",
        "certify.pki.publication.enabled=true",
        "certify.pki.trust-anchors.mdoc-iaca[0].id=operator-iaca",
        "certify.pki.trust-anchors.mdoc-iaca[0].certificate=" + IacaTrustAnchorsTest.DIRECTORY + "/operator-iaca.pem",
        "certify.pki.trust-anchors.mdoc-iaca[0].crl=" + IacaTrustAnchorsTest.DIRECTORY + "/operator-iaca.crl",
        "certify.pki.trust-anchors.mdoc-iaca[1].certificate=" + IacaTrustAnchorsTest.DIRECTORY + "/second-iaca.der",
        "certify.pki.trust-anchors.mdoc-iaca[2].id=stale-iaca",
        "certify.pki.trust-anchors.mdoc-iaca[2].certificate=" + IacaTrustAnchorsTest.DIRECTORY + "/stale-iaca.pem",
        "certify.pki.trust-anchors.mdoc-iaca[2].crl=" + IacaTrustAnchorsTest.DIRECTORY + "/stale-iaca.crl",
        "certify.keyprovider.x509-file.pem-keys[0].alias=stale-dsc",
        "certify.keyprovider.x509-file.pem-keys[0].key=" + IacaTrustAnchorsTest.DIRECTORY + "/stale-dsc.key",
        "certify.keyprovider.x509-file.pem-keys[0].chain=" + IacaTrustAnchorsTest.DIRECTORY + "/stale-dsc-chain.pem",
        "mosip.certify.issuer.ledger-enabled=false",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
        "mosip.certify.data-provider-plugin.did-url=did:web:localhost:certify",
        "mosip.certify.data-provider-plugin.vc-expiry-duration=P365D",
        "mosip.certify.signature-algo.key-alias-mapper={'EdDSA': {{'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN'}}, 'ES256': {{'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN'}}}",
        "mosip.certify.credential-config.credential-signing-alg-values-supported={'Ed25519Signature2020': {'EdDSA'}, 'ES256': {'ES256'}}",
        "mosip.certify.credential-config.cryptographic-binding-methods-supported={'ldp_vc': {'did:jwk','did:web'}, 'mso_mdoc': {'cose_key'}}",
        "mosip.certify.credential-config.proof-types-supported={'jwt': {'proof_signing_alg_values_supported': {'ES256','EdDSA'}}}"
})
class IacaTrustAnchorsTest {

    static final String DIRECTORY = "target/iaca-trust-anchors-test";
    static final String PUBLIC_BASE = "https://certify.example.test/v1/certify";
    /** A doctype of its own: mso_mdoc configurations are unique per doctype in the H2 every golden test shares. */
    static final String DOCTYPE = "org.iso.18013.5.1.mDL.trust-anchors";
    static final String X509_CONFIG = "TrustAnchorsMdlX509File";
    static final String KEYMANAGER_CONFIG = "TrustAnchorsMdlKeymanager";
    static final String STALE_CONFIG = "TrustAnchorsMdlStaleCrl";

    static final X509Certificate OPERATOR_IACA;
    static final X509Certificate SECOND_IACA;
    static final BigInteger REVOKED_SERIAL = BigInteger.valueOf(0x7a11_0000_beefL);

    static {
        try {
            Path directory = Path.of(DIRECTORY);
            if (Files.exists(directory)) {
                try (var files = Files.list(directory)) {
                    for (Path file : files.toList()) {
                        Files.delete(file);
                    }
                }
            }
            Files.createDirectories(directory);
            KeyPair operatorKeys = p256();
            OPERATOR_IACA = IsoMdocProfiles.iaca(operatorKeys).country("IN").commonName("Lorem Ipsum Operator IACA")
                    .issuerAltUri("https://certify.example.test").notBefore(Instant.now().minus(1, ChronoUnit.HOURS))
                    .crlDistributionPoint(PUBLIC_BASE + "/mdoc/iaca/operator-iaca.crl").build();
            Files.writeString(directory.resolve("operator-iaca.pem"), Pem.writeCertificate(OPERATOR_IACA));
            X509CRL crl = CrlBuilder.forIaca(OPERATOR_IACA, operatorKeys).crlNumber(BigInteger.valueOf(7))
                    .thisUpdate(Instant.now().minus(1, ChronoUnit.MINUTES)).revoke(REVOKED_SERIAL, Instant.now().minus(2, ChronoUnit.MINUTES)).build();
            Files.writeString(directory.resolve("operator-iaca.crl"), Pem.writeCrl(crl));
            SECOND_IACA = IsoMdocProfiles.iaca(p256()).country("IN").commonName("Lorem Ipsum Second IACA")
                    .issuerAltUri("https://second.example.test").crlDistributionPoint("https://second.example.test/crl/second.crl").build();
            Files.write(directory.resolve("second-iaca.der"), SECOND_IACA.getEncoded());
            // an IACA whose CRL is two days past its nextUpdate (more than the PT24H grace) when the service starts
            Instant since = Instant.now().minus(30, ChronoUnit.DAYS);
            KeyPair staleKeys = p256();
            X509Certificate staleIaca = IsoMdocProfiles.iaca(staleKeys).country("IN").commonName("Lorem Ipsum Stale CRL IACA")
                    .issuerAltUri("https://certify.example.test").notBefore(since)
                    .crlDistributionPoint(PUBLIC_BASE + "/mdoc/iaca/stale-iaca.crl").build();
            Files.writeString(directory.resolve("stale-iaca.pem"), Pem.writeCertificate(staleIaca));
            Files.writeString(directory.resolve("stale-iaca.crl"), Pem.writeCrl(CrlBuilder.forIaca(staleIaca, staleKeys)
                    .crlNumber(BigInteger.valueOf(3)).thisUpdate(Instant.now().minus(10, ChronoUnit.DAYS))
                    .nextUpdate(Instant.now().minus(2, ChronoUnit.DAYS)).build()));
            KeyPair staleDscKeys = p256();
            X509Certificate staleDsc = IsoMdocProfiles.ds(staleDscKeys, staleIaca, staleKeys).commonName("Lorem Ipsum Stale CRL DSC")
                    .notBefore(since).build();
            Files.writeString(directory.resolve("stale-dsc.key"), Pem.writePrivateKey(staleDscKeys.getPrivate()));
            Files.writeString(directory.resolve("stale-dsc-chain.pem"), Pem.writeCertificates(List.of(staleDsc, staleIaca)));
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired KeyProviderRegistry keyProviders;
    @Autowired TrustAnchorRegistry registry;
    @MockBean DataProviderPlugin dataProviderPlugin;
    @Value("${mosip.certify.identifier}") String issuerIdentifier;

    static KeyPair p256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    String secondId() {
        return CertificateLinks.subjectKeyIdentifierHex(SECOND_IACA).orElseThrow();
    }

    X509Certificate devIaca() {
        return registry.anchor(TrustAnchorRegistry.MDOC_IACA, "demo-iaca").orElseThrow().certificate();
    }

    @BeforeEach
    void setUp() throws Exception {
        when(dataProviderPlugin.fetchData(any())).thenAnswer(inv -> new JSONObject(Map.of("fullName", "Demo Holder", "dateOfBirth", "1990-01-01")));
    }

    // ---- M-08: publication ---------------------------------------------------------------------------------------

    @Test
    void theListNamesEveryAnchorWithItsDownloads() throws Exception {
        MvcResult result = mockMvc.perform(get("/mdoc/iaca")).andExpect(status().isOk()).andReturn();
        assertTrue(result.getResponse().getContentType().startsWith(MediaType.APPLICATION_JSON_VALUE));
        assertEquals("max-age=300, public", result.getResponse().getHeader("Cache-Control"));
        JsonNode list = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(List.of("operator-iaca", secondId(), "stale-iaca", "demo-iaca"), ids(list));
        JsonNode operator = list.get(0);
        assertEquals("IN", operator.get("country").asText());
        assertEquals(OPERATOR_IACA.getSubjectX500Principal().getName(), operator.get("subject").asText());
        assertEquals(java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(OPERATOR_IACA.getEncoded())),
                operator.get("sha256").asText());
        assertEquals(OPERATOR_IACA.getNotBefore().toInstant().toString(), operator.get("notBefore").asText());
        assertEquals(OPERATOR_IACA.getNotAfter().toInstant().toString(), operator.get("notAfter").asText());
        assertEquals("iaca/operator-iaca.pem", operator.get("pem").asText(), "relative to the list's own URL");
        assertEquals("iaca/operator-iaca.der", operator.get("der").asText());
        assertEquals("iaca/operator-iaca.crl", operator.get("crl").asText());
        assertTrue(list.get(1).get("crl").isNull(), "no CRL configured for the second IACA");
        assertEquals("iaca/demo-iaca.crl", list.get(3).get("crl").asText(), "dev mode issues the x509-file IACA's CRL");
    }

    @Test
    void certificatesDownloadAsPemAndDer() throws Exception {
        MvcResult pem = mockMvc.perform(get("/mdoc/iaca/operator-iaca.pem")).andExpect(status().isOk()).andReturn();
        assertEquals("application/x-pem-file", pem.getResponse().getContentType());
        assertEquals(OPERATOR_IACA, Pem.readCertificate(pem.getResponse().getContentAsString()));
        MvcResult der = mockMvc.perform(get("/mdoc/iaca/" + secondId() + ".der")).andExpect(status().isOk()).andReturn();
        assertEquals("application/pkix-cert", der.getResponse().getContentType());
        assertArrayEquals(SECOND_IACA.getEncoded(), der.getResponse().getContentAsByteArray());
        assertEquals("max-age=3600, public", der.getResponse().getHeader("Cache-Control"));
    }

    @Test
    void theCrlDownloadsAsDerAndVerifiesAgainstTheDownloadedIaca() throws Exception {
        MvcResult crlResult = mockMvc.perform(get("/mdoc/iaca/operator-iaca.crl")).andExpect(status().isOk()).andReturn();
        assertEquals("application/pkix-crl", crlResult.getResponse().getContentType());
        String cacheControl = crlResult.getResponse().getHeader("Cache-Control");
        assertTrue(cacheControl != null && cacheControl.matches("max-age=\\d+, public"), cacheControl);
        assertTrue(Long.parseLong(cacheControl.replaceAll("\\D", "")) <= 3600, "at most an hour, never past nextUpdate");
        X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(crlResult.getResponse().getContentAsByteArray()));
        assertTrue(crl.getRevokedCertificate(REVOKED_SERIAL) != null);
        X509Certificate iaca = Pem.readCertificate(mockMvc.perform(get("/mdoc/iaca/operator-iaca.pem")).andReturn().getResponse().getContentAsString());
        assertEquals(List.of(), AnnexBValidator.validateCrl(crl, iaca));
        opensslVerifiesCrl("operator-iaca", crlResult.getResponse().getContentAsByteArray(), iaca);
    }

    @Test
    void theDevDscCrlDistributionPointIsTheUrlThisIssuerServes() throws Exception {
        X509Certificate dsc = keyProviders.provider("x509-file").resolve(KeyRef.parse("x509-file:mdl-dsc")).chain().leaf().orElseThrow();
        List<String> points = FileTrustAnchorRegistry.crlDistributionPoints(dsc);
        assertEquals(List.of(PUBLIC_BASE + "/mdoc/iaca/demo-iaca.crl"), points, "the DSC copies its IACA's CRL distribution point");
        String path = points.get(0).substring(PUBLIC_BASE.length());
        MvcResult crlResult = mockMvc.perform(get(path)).andExpect(status().isOk()).andReturn();
        assertEquals("application/pkix-crl", crlResult.getResponse().getContentType());
        X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(crlResult.getResponse().getContentAsByteArray()));
        X509Certificate iaca = Pem.readCertificate(mockMvc.perform(get("/mdoc/iaca/demo-iaca.pem")).andReturn().getResponse().getContentAsString());
        assertEquals(devIaca(), iaca);
        assertTrue(CertificateLinks.issuedBy(dsc, iaca), "the DSC chains to the published IACA");
        assertEquals(List.of(), AnnexBValidator.validateCrl(crl, iaca));
        assertTrue(crl.getRevokedCertificate(dsc) == null);
        opensslVerifiesCrl("demo-iaca", crlResult.getResponse().getContentAsByteArray(), iaca);
    }

    @Test
    void unknownAnchorsMissingCrlsAndOtherFilesAreNotFound() throws Exception {
        mockMvc.perform(get("/mdoc/iaca/unknown.pem")).andExpect(status().isNotFound());
        mockMvc.perform(get("/mdoc/iaca/" + secondId() + ".crl")).andExpect(status().isNotFound());
        mockMvc.perform(get("/mdoc/iaca/operator-iaca.txt")).andExpect(status().isNotFound());
        mockMvc.perform(get("/mdoc/iaca/operator-iaca")).andExpect(status().isNotFound());
    }

    // ---- M-06: the DSC policy, enforced because anchors are configured --------------------------------------------

    @Test
    void anMdocSignedByTheDevDscIssuesThroughTheNewSurface() throws Exception {
        ensureConfiguration(X509_CONFIG, Map.of("provider", "x509-file", "alias", "mdl-dsc", "alg", "ES256", "x5c", "without-anchor"));
        MvcResult preview = mockMvc.perform(post("/v2/credential-configurations/" + X509_CONFIG + "/preview")
                .contentType(MediaType.APPLICATION_JSON).content("{\"claims\": {\"fullName\": \"Demo Holder\", \"dateOfBirth\": \"1990-01-01\"}}")).andReturn();
        assertEquals(200, preview.getResponse().getStatus(), preview.getResponse().getContentAsString());

        MvcResult issued = issue(X509_CONFIG);
        JsonNode body = objectMapper.readTree(issued.getResponse().getContentAsString());
        assertEquals(200, issued.getResponse().getStatus(), body.toString());
        CBORObject issuerSigned = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(body.get("credentials").get(0).get("credential").asText()));
        CBORObject x5chain = issuerSigned.get("issuerAuth").get(1).get(CBORObject.FromObject(33));
        X509Certificate carried = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(x5chain.GetByteString()));
        assertTrue(CertificateLinks.issuedBy(carried, devIaca()), "the IssuerAuth carries the DSC alone, issued by the published IACA");
    }

    @Test
    void anMdocSignedByAKeymanagerKeyIsRefusedByNameOnceIacasAreConfigured() throws Exception {
        // D16 as refined: keymanager's master-signed certificate was issued by no configured IACA, on any surface
        Map<String, Object> body = body(KEYMANAGER_CONFIG, Map.of("alias", "CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN", "alg", "ES256"));
        body.put("sampleClaims", Map.of("fullName", "Demo Holder", "dateOfBirth", "1990-01-01"));
        MvcResult dryRun = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body))).andReturn();
        String refusal = dryRun.getResponse().getContentAsString();
        assertEquals(400, dryRun.getResponse().getStatus(), refusal);
        assertTrue(refusal.contains("certificate_chain_invalid: DSC_NO_TRUSTED_IACA"), refusal);

        body.remove("sampleClaims"); // saved without a dry run, it is refused at preview and at issuance
        create(KEYMANAGER_CONFIG, body);
        MvcResult preview = mockMvc.perform(post("/v2/credential-configurations/" + KEYMANAGER_CONFIG + "/preview")
                .contentType(MediaType.APPLICATION_JSON).content("{\"claims\": {\"fullName\": \"Demo Holder\", \"dateOfBirth\": \"1990-01-01\"}}")).andReturn();
        assertEquals(400, preview.getResponse().getStatus());
        assertTrue(preview.getResponse().getContentAsString().contains("DSC_NO_TRUSTED_IACA"), preview.getResponse().getContentAsString());
        MvcResult issued = issue(KEYMANAGER_CONFIG);
        assertTrue(issued.getResponse().getStatus() >= 400, "no credential: " + issued.getResponse().getContentAsString());
        assertTrue(!issued.getResponse().getContentAsString().contains("\"credentials\""), issued.getResponse().getContentAsString());
    }

    /**
     * Round 2, items 2 and 4: an IACA whose CRL is past the grace at startup does not stop the service (this context
     * started with one); the v2 dry run and the preview of an mDoc configuration under that IACA answer 400 with
     * CRL_STALE, and issuance fails closed, while the other IACAs keep signing.
     */
    @Test
    void aStaleCrlAtStartupStartsTheServiceAndRefusesTheDryRunAndPreviewUnderItsIaca() throws Exception {
        Map<String, Object> body = body(STALE_CONFIG, Map.of("provider", "x509-file", "alias", "stale-dsc", "alg", "ES256",
                "x5c", "without-anchor"));
        body.put("sampleClaims", Map.of("fullName", "Demo Holder", "dateOfBirth", "1990-01-01"));
        MvcResult dryRun = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body))).andReturn();
        String refusal = dryRun.getResponse().getContentAsString();
        assertEquals(400, dryRun.getResponse().getStatus(), refusal);
        assertTrue(refusal.contains("certificate_chain_invalid: CRL_STALE"), refusal);

        body.remove("sampleClaims");
        create(STALE_CONFIG, body);
        MvcResult preview = mockMvc.perform(post("/v2/credential-configurations/" + STALE_CONFIG + "/preview")
                .contentType(MediaType.APPLICATION_JSON).content("{\"claims\": {\"fullName\": \"Demo Holder\", \"dateOfBirth\": \"1990-01-01\"}}")).andReturn();
        assertEquals(400, preview.getResponse().getStatus(), preview.getResponse().getContentAsString());
        assertTrue(preview.getResponse().getContentAsString().contains("CRL_STALE"), preview.getResponse().getContentAsString());
        MvcResult issued = issue(STALE_CONFIG);
        assertTrue(issued.getResponse().getStatus() >= 400, "no credential: " + issued.getResponse().getContentAsString());
        assertTrue(!issued.getResponse().getContentAsString().contains("\"credentials\""), issued.getResponse().getContentAsString());
    }

    // ---- helpers ----------------------------------------------------------------------------------------------------

    private void ensureConfiguration(String id, Map<String, Object> signing) throws Exception {
        create(id, body(id, signing));
    }

    private void create(String id, Map<String, Object> body) throws Exception {
        if (mockMvc.perform(get("/v2/credential-configurations/" + id)).andReturn().getResponse().getStatus() == 200) {
            return;
        }
        MvcResult created = mockMvc.perform(post("/v2/credential-configurations").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body))).andReturn();
        assertEquals(201, created.getResponse().getStatus(), created.getResponse().getContentAsString());
    }

    private Map<String, Object> body(String id, Map<String, Object> signing) throws Exception {
        Path path = Path.of("src/test/resources/goldens/templates/golden-mdoc.vm");
        if (!Files.exists(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        String template = Files.readString(path, StandardCharsets.UTF_8).replace("\"org.iso.18013.5.1.mDL\"", "\"" + DOCTYPE + "\"");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id);
        body.put("scope", "sample_vc_ldp"); // the local TestBearer token carries this scope
        body.put("format", "mso_mdoc");
        String doctype = id.equals(X509_CONFIG) ? DOCTYPE : id.equals(STALE_CONFIG) ? DOCTYPE + ".stale" : DOCTYPE + ".keymanager";
        body.put("formatConfig", Map.of("doctype", doctype));
        body.put("signing", new LinkedHashMap<>(signing));
        body.put("template", Map.of("content", id.equals(X509_CONFIG) ? template : template.replace(DOCTYPE, doctype)));
        body.put("display", Map.of("display", List.of(Map.of("name", id, "locale", "en")), "order", List.of("family_name")));
        return body;
    }

    private MvcResult issue(String configurationId) throws Exception {
        String nonce = objectMapper.readTree(mockMvc.perform(post("/oid4vci/nonce")).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString()).get("c_nonce").asText();
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holder.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().audience(issuerIdentifier + "/oid4vci").issueTime(new Date()).claim("nonce", nonce).build());
        proof.sign(new ECDSASigner(holder));
        return mockMvc.perform(post("/oid4vci/credential").header("Authorization", "TestBearer demo").contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("credential_configuration_id", configurationId,
                        "proofs", Map.of("jwt", List.of(proof.serialize())))))).andReturn();
    }

    private static List<String> ids(JsonNode list) {
        List<String> ids = new ArrayList<>();
        list.forEach(entry -> ids.add(entry.get("id").asText()));
        return ids;
    }

    /** {@code openssl crl -CAfile <iaca> -noout}: skipped without OpenSSL locally, failing with CI set (M-04 convention). */
    private static void opensslVerifiesCrl(String name, byte[] crlDer, X509Certificate iaca) throws Exception {
        boolean available;
        try {
            available = new ProcessBuilder("openssl", "version").redirectErrorStream(true).start().waitFor() == 0;
        } catch (java.io.IOException e) {
            available = false;
        }
        if (!available) {
            if (System.getenv("CI") != null) {
                fail("openssl is not on the PATH and CI is set: the independent CRL check must run");
            }
            org.junit.jupiter.api.Assumptions.abort("openssl is not on the PATH");
        }
        Path directory = Path.of(DIRECTORY);
        Path iacaFile = Files.writeString(directory.resolve(name + "-downloaded.pem"), Pem.writeCertificate(iaca));
        Path crlFile = Files.write(directory.resolve(name + "-downloaded.crl"), crlDer);
        Process process = new ProcessBuilder("openssl", "crl", "-inform", "DER", "-in", crlFile.toString(), "-CAfile",
                iacaFile.toString(), "-noout").redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "openssl did not finish");
        assertEquals(0, process.exitValue(), output);
        assertTrue(output.contains("verify OK"), output);
    }
}
