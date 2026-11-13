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
    /**
     * A small synthetic JPEG (64x80, 1419 bytes) of a drawn face silhouette, generated once with ImageIO and checked in
     * as base64: no real person, and small enough that a verifier can really decode it (7.2.1 portrait).
     */
    static final String PORTRAIT_BASE64 = "/9j/4AAQSkZJRgABAgAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PT"
            + "gyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCABQ"
            + "AEADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhBy"
            + "JxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKT"
            + "lJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAA"
            + "AAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRom"
            + "JygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExc"
            + "bHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD2qiiiuY1CiuT8T+LxpbtZWIV7sffc8rH/AImvP7vUr2/cvdXU"
            + "spP95jgfQdBUSmkaRptntlFeJ2mpXtg4e1upYiP7rHB+o6GvQPDHi8ao62V8FS7P3HHCyf4GiM0wlTaOsoooqzMKzNf1P+ydGnuhjzANsYP948"
            + "D/AB/CtOuK+IsxWzsYM8PIzn/gIA/9mpSdkVFXdjgHdpHZ3Ys7HJJPJNX7LQtU1FN9rZSuh6OflU/QnArZ8GeH49UuHvLtN1tAcBD0d+uD7D+o"
            + "rutI13StaE40u7juBbN5cgQEbT26jpwcEccVlGF1dmsp2dkeWXuhappyb7qylRB1cfMo+pGRVBHaN1dGKupyCDyDXsWr67pWiiAapdx24uW8uM"
            + "OCdx79B05GSeOa4Xxn4fj0u4S8tE2205wUHRH64Hsf6GiULK6CNS+jO50DU/7W0aC6OPMI2yAf3hwf8fxrTrivh1MWs76DPCSK4/4ECP8A2Wu1"
            + "rWLujKSs7BXFfEWEtZ2M+OEkZD/wIA/+y12tZmv6Z/a2jT2ox5hG6Mn+8OR/h+NEldBF2dyj4JRV8L25XqzuW+u4j+QFX9J0DS9D+0f2ZZx232"
            + "h98uwn5j+J4HJ4HHNcz4D1QRCbR7g7JVcvGG4P+0v1GM/nXTpq8I1afTrjbbzLhoN7f69CoyV9w2QQM4wD3og7oJq0hNW0DS9c+z/2nZx3P2d9"
            + "8W8n5T+B5HA4PHFUPGyK3he4LdVdCv13AfyJrQvdXhtbq3s4ts95NIqiBX+ZUz8znrgKMnnqcDvXMePNUEoh0e3O+VnDyBeT/sr9TnP5UTfuhB"
            + "XkP+HUJWzvp8cPIqD/AICCf/Zq7WszQNM/snRoLU48wDdIR/ePJ/w/CtOiKsgk7u4UUUUyTlfEnhM3839oac4hvRyRnAcjvns1Yk3iLU7WD7Hr"
            + "+jR3iL/z3jxn3zgqfqBXotFTy9UWpaWZ5vb65fzRtbeHdBgsVk+8baEfzAAH1Nb3hvwmbCb+0NRcTXp5AzkIT3z3auqoo5dbsHLSyCiiiqICii"
            + "igAooooAKKKKACiiigD//Z";
    static final byte[] JPEG = Base64.getDecoder().decode(PORTRAIT_BASE64);
    static final String PORTRAIT = PORTRAIT_BASE64;
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
        // every document signer is issued by an IACA (Annex B): the formatter refuses a self-signed signer certificate
        provider.generateCa("mdl-iaca", SignatureAlgorithm.ES256, "C=IN,CN=Lorem Ipsum Demo IACA,O=Lorem Ipsum Demo", "vc-signing");
        provider.generateCa("mdl-iaca-us", SignatureAlgorithm.ES256, "C=US,CN=Lorem Ipsum Demo IACA,O=Lorem Ipsum Demo", "vc-signing");
        provider.generateSignedBy("mdl-dsc", SignatureAlgorithm.ES256, "C=IN,CN=Lorem Ipsum Demo DSC,O=Lorem Ipsum Demo",
                "vc-signing", "mdl-iaca");
        provider.generateSignedBy("mdl-dsc-us", SignatureAlgorithm.ES256, "C=US,CN=Lorem Ipsum Demo DSC,O=Lorem Ipsum Demo",
                "vc-signing", "mdl-iaca-us");
        provider.generateSignedBy("mdl-dsc-chained", SignatureAlgorithm.ES256, "C=IN,CN=Lorem Ipsum Demo DSC,O=Lorem Ipsum Demo",
                "vc-signing", "mdl-iaca");
        // a plain self-signed dev key (G10/G11): what the formatter must refuse to sign with
        provider.generate("mdl-self-signed", SignatureAlgorithm.ES256, "C=IN,CN=Lorem Ipsum Demo Self-Signed,O=Lorem Ipsum Demo",
                "vc-signing");
        return provider;
    }

    static SigningKey dsc() {
        return KEYS.resolve(KeyRef.parse("jca:mdl-dsc"));
    }

    static SigningKey selfSignedSigner() {
        return KEYS.resolve(KeyRef.parse("jca:mdl-self-signed"));
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
        items.add(item("un_distinguishing_sign", "IND"));
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

    /** The document with one element removed, for the mandatory-element tests. */
    static Map<String, Object> without(String identifier) {
        Map<String, Object> document = mdl();
        List<Map<String, Object>> items = items(document, MDL_NAMESPACE);
        items.removeIf(item -> identifier.equals(item.get("elementIdentifier")));
        return document;
    }

    /** The document with one element's value replaced, or with the element added when it is optional and absent. */
    static Map<String, Object> with(String identifier, Object value) {
        Map<String, Object> document = mdl();
        List<Map<String, Object>> items = items(document, MDL_NAMESPACE);
        if (items.stream().noneMatch(item -> identifier.equals(item.get("elementIdentifier")))) {
            items.add(item(identifier, value));
        }
        for (Map<String, Object> item : items) {
            if (identifier.equals(item.get("elementIdentifier"))) {
                item.put("elementValue", value);
            }
        }
        return document;
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> items(Map<String, Object> document, String namespace) {
        return (List<Map<String, Object>>) ((Map<String, Object>) document.get("nameSpaces")).get(namespace);
    }
}
