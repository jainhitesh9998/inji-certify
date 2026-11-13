package io.mosip.certify.oid4vci;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.CredentialConfigurationSupportedDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.CredentialMetadataDTO;
import io.mosip.certify.core.dto.MetaDataDisplayDTO;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** OpenID4VCI 1.0 section 12.2.4 on the /oid4vci document: optional members absent rather than null, claims in display order. */
class Oid4vciMetadataDocumentTest {

    final ObjectMapper mapper = new ObjectMapper();

    @Test
    void nullDisplayMembersAreOmittedAndPresentOnesKept() {
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName("Mobile Driving Licence");
        display.setLocale("en");
        display.setBackgroundColor("#12107c");
        JsonNode raw = mapper.valueToTree(document(display, claims("given_name", "family_name")));
        JsonNode rawDisplay = raw.at("/credential_configurations_supported/mDL/credential_metadata/display/0");
        assertTrue(rawDisplay.has("logo") && rawDisplay.get("logo").isNull(), "the shared DTO serialises nulls (the compatibility bytes)");

        JsonNode finished = Oid4vciMetadataDocument.finish(raw, Map.of());
        JsonNode shown = finished.at("/credential_configurations_supported/mDL/credential_metadata/display/0");
        assertFalse(shown.has("logo"));
        assertFalse(shown.has("background_image"));
        assertFalse(shown.has("text_color"));
        assertEquals("#12107c", shown.get("background_color").asText());
        assertEquals("Mobile Driving Licence", shown.get("name").asText());
        assertFalse(finished.toString().contains("null"), finished.toString());
        assertTrue(raw.at("/credential_configurations_supported/mDL/credential_metadata/display/0").get("logo").isNull(), "the input is not modified");
    }

    @Test
    void aLogoObjectIsKept() {
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName("Farmer");
        MetaDataDisplayDTO.Logo logo = new MetaDataDisplayDTO.Logo();
        logo.setUri("https://issuer.example.org/logo.png");
        display.setLogo(logo);
        JsonNode finished = Oid4vciMetadataDocument.finish(mapper.valueToTree(document(display, claims("a"))), Map.of());
        JsonNode shown = finished.at("/credential_configurations_supported/mDL/credential_metadata/display/0/logo");
        assertEquals("https://issuer.example.org/logo.png", shown.get("uri").asText());
        assertFalse(shown.has("alt_text"));
    }

    @Test
    void claimsFollowTheDisplayOrderThenTheirPath() {
        CredentialIssuerMetadataDTO document = document(new MetaDataDisplayDTO(),
                claims("portrait", "issuing_country", "family_name", "birth_date", "given_name", "document_number"));
        JsonNode finished = Oid4vciMetadataDocument.finish(mapper.valueToTree(document),
                Map.of("mDL", List.of("family_name", "given_name", "birth_date", "portrait")));
        assertEquals(List.of("family_name", "given_name", "birth_date", "portrait", "document_number", "issuing_country"), elements(finished));
    }

    @Test
    void withoutAnOrderClaimsAreOrderedByPathNotByHash() {
        JsonNode finished = Oid4vciMetadataDocument.finish(mapper.valueToTree(document(new MetaDataDisplayDTO(),
                claims("zeta", "alpha", "mid"))), Map.of());
        assertEquals(List.of("alpha", "mid", "zeta"), elements(finished));
    }

    @Test
    void anOrderReadThroughH2AsOneBracketedElementIsSplit() {
        assertEquals(List.of("fullName", "dateOfBirth", "city"), Oid4vciMetadataDocument.names(List.of("[fullName, dateOfBirth, city]")));
        assertEquals(List.of("fullName", "city"), Oid4vciMetadataDocument.names(List.of("fullName", " city ")));
        assertEquals(List.of(), Oid4vciMetadataDocument.names(null));
    }

    static CredentialIssuerMetadataDTO document(MetaDataDisplayDTO display, List<CredentialMetadataDTO.Claims> claims) {
        CredentialMetadataDTO metadata = new CredentialMetadataDTO();
        metadata.setDisplay(List.of(display));
        metadata.setClaims(claims);
        CredentialConfigurationSupportedDTO supported = new CredentialConfigurationSupportedDTO();
        supported.setFormat("mso_mdoc");
        supported.setDocType("org.iso.18013.5.1.mDL");
        supported.setCredentialMetadataDTO(metadata);
        CredentialIssuerMetadataDTO document = new CredentialIssuerMetadataDTO();
        document.setCredentialIssuer("https://issuer.example.org/v1/certify/oid4vci");
        document.setCredentialConfigurationSupportedDTO(Map.of("mDL", supported));
        return document;
    }

    static List<CredentialMetadataDTO.Claims> claims(String... elements) {
        List<CredentialMetadataDTO.Claims> claims = new ArrayList<>();
        for (String element : elements) {
            CredentialMetadataDTO.Claims claim = new CredentialMetadataDTO.Claims();
            claim.setPath(List.of("org.iso.18013.5.1", element));
            claims.add(claim);
        }
        return claims;
    }

    static List<String> elements(JsonNode document) {
        List<String> names = new ArrayList<>();
        document.at("/credential_configurations_supported/mDL/credential_metadata/claims")
                .forEach(claim -> names.add(claim.get("path").get(claim.get("path").size() - 1).asText()));
        return names;
    }
}
