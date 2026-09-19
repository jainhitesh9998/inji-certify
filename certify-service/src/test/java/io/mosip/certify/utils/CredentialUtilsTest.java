package io.mosip.certify.utils;

import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.core.constants.VCFormats;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class CredentialUtilsTest {

    @Test
    public void testGetTemplateNameFor_LDP_VC() {
        VCRequestDto request = new VCRequestDto();
        request.setFormat(VCFormats.LDP_VC);
        request.setContext(List.of("https://www.w3.org/ns/credentials/v2", "https://example.org/Person.json"));
        request.setType(List.of("VerifiableCredential", "UniversityCredential"));
        String expected = "UniversityCredential,VerifiableCredential::https://example.org/Person.json,https://www.w3.org/ns/credentials/v2::ldp_vc";
        assertEquals(expected, CredentialUtils.getTemplateName(request));
    }

    @Test
    public void testGetTemplateNameFor_MsoMdoc_VC() {
        VCRequestDto request = new VCRequestDto();
        request.setFormat(VCFormats.MSO_MDOC);
        request.setDoctype("org.iso.18013.5.1.mDL");
        assertEquals("mso_mdoc::org.iso.18013.5.1.mDL", CredentialUtils.getTemplateName(request));
    }

    @Test
    public void testGetTemplateNameFor_DCSDJWT_VC() {
        VCRequestDto request = new VCRequestDto();
        request.setFormat(VCFormats.DC_SD_JWT);
        request.setVct("test-vct");
        assertEquals("dc+sd-jwt::test-vct", CredentialUtils.getTemplateName(request));
    }

    @Test
    public void getDigestMultibase() {
        String svg = """
               <svg viewBox=".5 .5 3 4" fill="none" stroke="#20b2a" stroke-linecap="round"> <path d=" M1 4h-.001 V1h2v.001 M1 2.6 h1v.001"/> </svg>
                """;
        assertEquals("z4po9QkJj1fhMt6cxHSnDnAUat4PEVrerUGGsPHLxJnK5", CredentialUtils.getDigestMultibase(svg));
    }

    @Test
    public void getDigestMultibaseWithoutSha256() {
        try (MockedStatic<MessageDigest> mockedMessageDigest = Mockito.mockStatic(MessageDigest.class)) {
            mockedMessageDigest.when(() -> MessageDigest.getInstance("SHA-256")).thenThrow(NoSuchAlgorithmException.class);
            assertThrows(IllegalStateException.class, () -> CredentialUtils.getDigestMultibase("<svg></svg>"));
        }
    }
}
