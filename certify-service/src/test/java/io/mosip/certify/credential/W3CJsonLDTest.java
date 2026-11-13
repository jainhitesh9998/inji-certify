package io.mosip.certify.credential;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.danubetech.dataintegrity.signer.LdSigner;
import com.danubetech.dataintegrity.signer.LdSignerRegistry;
import foundation.identity.jsonld.JsonLDException;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.proofgenerators.ProofGenerator;
import io.mosip.certify.proofgenerators.ProofGeneratorFactory;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.vcformatters.VCFormatter;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.LdProof;
import foundation.identity.jsonld.JsonLDObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class W3CJsonLDTest {

    @InjectMocks
    private W3CJsonLD w3cJsonLd;

    @Mock
    private VCFormatter vcFormatter;



    @Mock
    private ProofGenerator proofGenerator;

    @Mock
    private ProofGeneratorFactory proofGeneratorFactory;

    @Mock
    private DIDDocumentUtil didDocumentUtil;

    @Before
    public void setUp() {
        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        keyAliasMapper.put("Ed25519Signature2020", Arrays.asList(
                Arrays.asList("appID", "refID")));

        ReflectionTestUtils.setField(w3cJsonLd, "proofGeneratorFactory", proofGeneratorFactory);
        ReflectionTestUtils.setField(w3cJsonLd, "didDocumentUtil", didDocumentUtil);
        ReflectionTestUtils.setField(w3cJsonLd, "keyAliasMapper", keyAliasMapper);
        ReflectionTestUtils.setField(w3cJsonLd, "keyProviders", io.mosip.certify.signing.TestKeyProviders.registry("appID/refID", io.mosip.certify.signing.SignatureAlgorithm.EdDSA));
        when(proofGeneratorFactory.getProofGenerator(any())).thenReturn(Optional.of(proofGenerator));
    }

    @Test
    public void testCanHandleReturnsTrueForLdpVc() {
        assertTrue(w3cJsonLd.canHandle("ldp_vc"));
    }

    @Test
    public void testCanHandleReturnsFalseForOtherFormat() {
        assertFalse(w3cJsonLd.canHandle("jwt_vc"));
    }

    @Test
    public void testAddProofGeneratesCorrectVCResult() throws Exception {
        String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);
        when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

        VCResult<?> result = w3cJsonLd.addProof(vcJson, "RS256", "appID", "refID", "https://example.com/key", "Ed25519Signature2020");

        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test
    public void testAddProofGeneratesCorrectVCResult_ValidFrom() throws Exception {
        String vcJson = "{\"@context\":[],\"validFrom\":\"2023-01-01T00:00:00.000Z\"}";

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);
        when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

        VCResult<?> result = w3cJsonLd.addProof(vcJson, "RS256", "appID", "refID", "https://example.com/key", "Ed25519Signature2020");

        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test
    public void testAddProof_UsesCurrentTimeWhenNoDateProvided() throws Exception {
        String vcJson = "{\"@context\":[],\"id\":\"some-vc\"}"; // no issuanceDate or validFrom

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("TestProof");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("test".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("TestProof")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(), any(), anyMap())).thenReturn(ldProof);
        when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

        VCResult<?> result = w3cJsonLd.addProof(vcJson, "RS256", "appID", "refID", "https://example.com/key", "Ed25519Signature2020");

        assertNotNull(result);
        assertEquals("ldp_vc", result.getFormat());
        assertNotNull(result.getCredential());
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_WhenCanonicalizerFails_ThrowsCertifyException() throws Exception {
        String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";

        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("TestProof");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenThrow(new IOException("Mocked IO failure"));
        when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

        // This will trigger the catch and rethrow CertifyException
        w3cJsonLd.addProof(vcJson, "RS256", "appID", "refID", "https://example.com/key", "Ed25519Signature2020");
    }

    @Test
    public void testAddProof_DataIntegrityCryptoSuitePath() throws Exception {
        // Mock LdSignerRegistry and dependencies
        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        // Mock static method
        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            when(signer.getCanonicalizer(any())).thenReturn(canonicalizer);
            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doNothing().when(signer).initialize(any());
            doNothing().when(signer).sign(any(), any());

            when(canonicalizer.canonicalize(any(), any())).thenReturn("canonicalized".getBytes());
            when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            VCResult<?> result = w3cJsonLd.addProof(vcJson, "EdDSA", "appID", "refID", "https://example.com/key", "eddsa-rdfc-2022");

            assertNotNull(result);
            assertEquals("ldp_vc", result.getFormat());
            assertNotNull(result.getCredential());
        }
    }

    @Test
    public void testAddProof_NullHeaders() throws Exception {
        String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());

        LdProof ldProof = LdProof.builder()
                .type("RsaSignature2018")
                .created(new Date())
                .proofPurpose("assertionMethod")
                .verificationMethod(URI.create("https://example.com/key"))
                .build();

        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap())).thenReturn(ldProof);
        when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

        VCResult<?> result = w3cJsonLd.addProof(vcJson, "RS256", "appID", "refID", "https://example.com/key", "Ed25519Signature2020");
        assertNotNull(result);
        assertEquals("ldp_vc", result.getFormat());
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_DataIntegrityCryptoSuitePath_CanonicalizerThrows() throws Exception {
        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            when(signer.getCanonicalizer(any())).thenReturn(canonicalizer);
            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doNothing().when(signer).initialize(any());

            when(canonicalizer.canonicalize(any(), any())).thenThrow(new IOException("Mocked IO failure"));
            when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            w3cJsonLd.addProof(vcJson, "EdDSA", "appID", "refID", "https://example.com/key", "eddsa-rdfc-2022");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_DataIntegrityCryptoSuitePath_SignerInitializerThrows() throws Exception {
        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doThrow(new GeneralSecurityException("Signer Initialization failed.")).when(signer).initialize(any());
            when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());


            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            w3cJsonLd.addProof(vcJson, "EdDSA", "appID", "refID", "https://example.com/key", "eddsa-rdfc-2022");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_DataIntegrityCryptoSuitePath_CanonicalizerThrowsSecurityException() throws Exception {
        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            when(signer.getCanonicalizer(any())).thenReturn(canonicalizer);
            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doNothing().when(signer).initialize(any());

            when(canonicalizer.canonicalize(any(), any())).thenThrow(new GeneralSecurityException("Mocked IO failure"));
            when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            w3cJsonLd.addProof(vcJson, "EdDSA", "appID", "refID", "https://example.com/key", "eddsa-rdfc-2022");
        }
    }

    @Test(expected = CertifyException.class)
    public void testAddProof_DataIntegrityCryptoSuitePath_CanonicalizerThrowsJsonLdException() throws Exception {
        LdSigner signer = mock(LdSigner.class);
        com.danubetech.dataintegrity.canonicalizer.Canonicalizer canonicalizer = mock(com.danubetech.dataintegrity.canonicalizer.Canonicalizer.class);

        try (MockedStatic<LdSignerRegistry> registry = mockStatic(LdSignerRegistry.class)) {
            registry.when(() -> LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(anyString())).thenReturn(signer);

            when(signer.getCanonicalizer(any())).thenReturn(canonicalizer);
            doNothing().when(signer).setSigner(any());
            doNothing().when(signer).setCryptosuite(anyString());
            doNothing().when(signer).initialize(any());

            when(canonicalizer.canonicalize(any(), any())).thenThrow(new JsonLDException(new JsonLdError(JsonLdErrorCode.CONFLICTING_INDEXES)));
            when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());

            String vcJson = "{\"@context\":[],\"issuanceDate\":\"2023-01-01T00:00:00.000Z\"}";
            w3cJsonLd.addProof(vcJson, "EdDSA", "appID", "refID", "https://example.com/key", "eddsa-rdfc-2022");
        }
    }

    /**
     * F-19, the reported failure: {@code StatusListUpdateBatchJob} writes {@code validFrom} as {@code
     * Instant.toString()}, which omits the fraction of a second when it is zero, and the strict
     * {@code ...SSS'Z'} pattern refused {@code 2026-11-13T15:00:23Z} at index 19. A status list re-signed on such an
     * instant could not be re-signed at all (about one run in a thousand).
     */
    @Test
    public void testAddProofAcceptsTheStatusListValidFromWithoutAFraction() throws Exception {
        LdProof proof = proofFor("validFrom", "2026-11-13T15:00:23Z");

        assertEquals(proofSecondOf("2026-11-13T15:00:23Z"), proof.getCreated());
    }

    /**
     * F-19: every form {@code Instant.toString()} and the legacy {@code ...SSS'Z'} writer produce is read, and the
     * same instant gives the same proof {@code created} whichever form the document carries. The proof's {@code created}
     * is an XML Schema dateTime, i.e. seconds, so it is compared at that precision (a {@code Date} keeps milliseconds;
     * {@code LegacyW3cDateTimesTest} covers those).
     */
    @Test
    public void testAddProofReadsEveryInstantToStringFormAsTheSameProofCreated() throws Exception {
        for (String form : List.of("2026-11-13T15:00:23Z", "2026-11-13T15:00:23.123Z",
                "2026-11-13T15:00:23.123456Z", "2026-11-13T15:00:23.123456789Z")) {
            assertEquals(form, proofSecondOf(form), proofFor("validFrom", form).getCreated());
            assertEquals(form, proofSecondOf(form), proofFor("issuanceDate", form).getCreated());
        }
    }

    /**
     * The legacy reader's rule, asserted rather than restated: the wall clock of the value in the JVM's default zone,
     * at the seconds precision the proof's {@code created} is written with. Applying the {@code Z}/offset instead would
     * move {@code proof.created} on every deployment not on UTC, which is a wire change in the compatibility path (see
     * {@code LegacyW3cDateTimes}).
     */
    private static Date proofSecondOf(String value) {
        return Date.from(LocalDateTime.ofInstant(Instant.parse(value), ZoneOffset.UTC)
                .atZone(ZoneId.systemDefault()).toInstant().truncatedTo(ChronoUnit.SECONDS));
    }

    /** Signs one document on the legacy (proof generator) path and returns the proof options it was given. */
    private LdProof proofFor(String dateField, String value) throws Exception {
        Canonicalizer canonicalizer = mock(Canonicalizer.class);
        when(proofGenerator.getCanonicalizer()).thenReturn(canonicalizer);
        when(proofGenerator.getName()).thenReturn("RsaSignature2018");
        when(canonicalizer.canonicalize(any(LdProof.class), any(JsonLDObject.class)))
                .thenReturn("canonicalized".getBytes());
        when(proofGenerator.generateProof(any(LdProof.class), anyString(), anyMap()))
                .thenReturn(LdProof.builder().type("RsaSignature2018").created(new Date())
                        .proofPurpose("assertionMethod").verificationMethod(URI.create("https://example.com/key"))
                        .build());
        when(didDocumentUtil.getCertificateDataResponseDto(anyString(), anyString())).thenReturn(new CertificateResponseDTO());
        clearInvocations(proofGenerator);

        w3cJsonLd.addProof("{\"@context\":[],\"" + dateField + "\":\"" + value + "\"}", "RS256", "appID", "refID",
                "https://example.com/key", "Ed25519Signature2020");

        ArgumentCaptor<LdProof> proofOptions = ArgumentCaptor.forClass(LdProof.class);
        verify(proofGenerator).generateProof(proofOptions.capture(), anyString(), anyMap());
        return proofOptions.getValue();
    }
}
