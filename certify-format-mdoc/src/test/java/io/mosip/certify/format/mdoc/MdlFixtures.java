package io.mosip.certify.format.mdoc;

import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.TenantContext;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A complete ISO/IEC 18013-5 Table 5 mDL, the keys it is signed with, and a fixed request clock. */
final class MdlFixtures {

    static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    static final String MDL_NAMESPACE = "org.iso.18013.5.1";
    /** A minimal JPEG: SOI, APP0/JFIF header, EOI. Synthetic, no person in it. */
    static final byte[] JPEG = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
            0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, (byte) 0xFF, (byte) 0xD9};
    static final String PORTRAIT = Base64.getEncoder().encodeToString(JPEG);
    /**
     * The instant the tests issue at: the current instant (F-09), carrying fractional seconds so that the truncation
     * ISO/IEC 18013-5 9.1.2.4 requires is visible, and inside the dev certificates' validity window.
     */
    static final Instant NOW = Instant.now();
    static final String HOLDER_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
            + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
    static final String HOLDER = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(HOLDER_JWK.getBytes());
    /** An Ed25519 public key (32 bytes) as a JWK: the OKP device key of ISO/IEC 18013-5 9.1.5.2. */
    static final String ED25519_JWK = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\","
            + "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}";
    static final String ED25519_HOLDER = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(ED25519_JWK.getBytes());

    static final JcaKeyProvider KEYS = provider();

    /** The tdate text of an instant: the pattern the MSO must carry (20 characters, no fractional seconds). */
    static String tdate(Instant instant) {
        return java.time.format.DateTimeFormatter.ofPattern(MdocConstants.TDATE_PATTERN)
                .withZone(java.time.ZoneOffset.UTC).format(instant.truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
    }

    private MdlFixtures() {}

    private static JcaKeyProvider provider() {
        JcaKeyProvider provider = JcaKeyProvider.devMode();
        // Annex B document signer certificates carry the country; the check at signing time compares it with issuing_country
        provider.generate("mdl-dsc", SignatureAlgorithm.ES256, "C=IN,CN=Lorem Ipsum Demo DSC,O=Lorem Ipsum Demo", "vc-signing");
        provider.generate("mdl-dsc-us", SignatureAlgorithm.ES256, "C=US,CN=Lorem Ipsum Demo DSC,O=Lorem Ipsum Demo", "vc-signing");
        provider.generateCa("mdl-iaca", SignatureAlgorithm.ES256, "C=IN,CN=Lorem Ipsum Demo IACA,O=Lorem Ipsum Demo", "vc-signing");
        provider.generateSignedBy("mdl-dsc-chained", SignatureAlgorithm.ES256, "C=IN,CN=Lorem Ipsum Demo DSC,O=Lorem Ipsum Demo",
                "vc-signing", "mdl-iaca");
        return provider;
    }

    static SigningKey dsc() {
        return KEYS.resolve(KeyRef.parse("jca:mdl-dsc"));
    }

    static SigningKey dscIssuedByAnotherCountry() {
        return KEYS.resolve(KeyRef.parse("jca:mdl-dsc-us"));
    }

    static SigningKey dscWithIaca() {
        return KEYS.resolve(KeyRef.parse("jca:mdl-dsc-chained"));
    }

    static SigningContext signing(SigningKey key) {
        return new SigningContext(new SigningConfig(key.ref(), key.algorithm(), null, null, null, "did:web:issuer.example"),
                key, KEYS);
    }

    static MdocProperties properties(Duration validity) {
        return new MdocProperties("SHA-256", "1.0", validity, null);
    }

    static MdocProperties properties(String digestAlgorithm, Duration validity) {
        return new MdocProperties(digestAlgorithm, "1.0", validity, null);
    }

    static IssuanceContext context() {
        return context(NOW);
    }

    static IssuanceContext context(Instant now) {
        return new IssuanceContext(TenantContext.DEFAULT, null, List.of(), ProtocolVersion.OID4VCI_1_0, "test", now, Map.of());
    }

    static CredentialConfiguration configuration(MdocFormatter formatter) {
        return configuration(formatter, MDL_DOCTYPE);
    }

    static CredentialConfiguration configuration(MdocFormatter formatter, String doctype) {
        return configuration(formatter, Map.of("docType", doctype));
    }

    static CredentialConfiguration configuration(MdocFormatter formatter, Map<String, Object> formatConfig) {
        return new CredentialConfiguration(null, "mdl", "mdl_scope", MdocFormatter.FORMAT, formatter.parseConfig(formatConfig), null,
                signing(dsc()).config(), null, null, null, null, null);
    }

    static HolderBinding holder() {
        return HolderBinding.did(HOLDER, "jwt");
    }

    /** A complete mDL: every mandatory element of Table 5 plus one optional one. */
    static Map<String, Object> mdl() {
        List<Map<String, Object>> items = new ArrayList<>();
        items.add(item("family_name", "Doe"));
        items.add(item("given_name", "Jane"));
        items.add(item("birth_date", "1990-01-01"));
        items.add(item("issue_date", "2024-01-01"));
        items.add(item("expiry_date", "2034-01-01"));
        items.add(item("issuing_country", "IN"));
        items.add(item("issuing_authority", "Lorem Ipsum Demo Issuing Authority"));
        items.add(item("document_number", "DL-0420110149646"));
        items.add(item("portrait", PORTRAIT));
        items.add(item("driving_privileges", List.of(privilege())));
        items.add(item("un_distinguishing_sign", "IN"));
        items.add(item("resident_city", "Bengaluru"));

        Map<String, Object> namespaces = new LinkedHashMap<>();
        namespaces.put(MDL_NAMESPACE, items);
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("docType", MDL_DOCTYPE);
        document.put("validityInfo", Map.of("validFrom", "${_validFrom}", "validUntil", "${_validUntil}", "signed", "${_signed}"));
        document.put("nameSpaces", namespaces);
        return document;
    }

    static Map<String, Object> item(String identifier, Object value) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("elementIdentifier", identifier);
        item.put("elementValue", value);
        return item;
    }

    static Map<String, Object> privilege() {
        Map<String, Object> privilege = new LinkedHashMap<>();
        privilege.put("vehicle_category_code", "B");
        privilege.put("issue_date", "2020-01-01");
        privilege.put("expiry_date", "2030-01-01");
        privilege.put("codes", List.of(Map.of("code", "01", "sign", "IN", "value", "B")));
        return privilege;
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> items(Map<String, Object> document, String namespace) {
        return (List<Map<String, Object>>) ((Map<String, Object>) document.get("nameSpaces")).get(namespace);
    }
}
