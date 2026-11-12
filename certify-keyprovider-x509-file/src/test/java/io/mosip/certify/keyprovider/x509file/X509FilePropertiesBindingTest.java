package io.mosip.certify.keyprovider.x509file;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-05 binding: every new key is optional, so an existing deployment's configuration binds unchanged; {@code profile}
 * defaults to {@code plain} and {@code iaca.alias}/{@code iaca.algorithm} have defaults.
 */
class X509FilePropertiesBindingTest {

    private static X509FileProperties bind(Map<String, String> properties) {
        return new Binder(new MapConfigurationPropertySource(properties))
                .bind("certify.keyprovider.x509-file", Bindable.of(X509FileProperties.class))
                .orElseThrow(() -> new AssertionError("the properties did not bind"));
    }

    @Test
    void thePreM05ShapeStillBinds() {
        X509FileProperties properties = bind(Map.of(
                "certify.keyprovider.x509-file.enabled", "true",
                "certify.keyprovider.x509-file.path", "/keys/issuer.p12",
                "certify.keyprovider.x509-file.password", "pw",
                "certify.keyprovider.x509-file.dev-mode", "true",
                "certify.keyprovider.x509-file.keys[0].alias", "issuer-es256",
                "certify.keyprovider.x509-file.keys[0].algorithm", "ES256",
                "certify.keyprovider.x509-file.keys[0].subject", "CN=VC issuer"));

        assertEquals("x509-file", properties.id());
        assertEquals("vc-signing", properties.purpose());
        assertEquals("dev-ca", properties.caAlias());
        assertEquals("plain", properties.keys().get(0).profile(), "profile defaults to the P3-08 path");
        assertNull(properties.keys().get(0).validityDays());
        assertNull(properties.iaca());
        assertNull(properties.pemKeys());
    }

    @Test
    void theMdlShapeBinds() {
        java.util.Map<String, String> mdl = new java.util.HashMap<>();
        mdl.put("certify.keyprovider.x509-file.path", "/keys/issuer.p12");
        mdl.put("certify.keyprovider.x509-file.iaca.country", "IN");
        mdl.put("certify.keyprovider.x509-file.iaca.common-name", "Lorem Ipsum Demo IACA");
        mdl.put("certify.keyprovider.x509-file.iaca.issuer-alt-name", "https://credentials.example.test/mdoc/iaca");
        mdl.put("certify.keyprovider.x509-file.iaca.crl-uri", "https://credentials.example.test/iaca.crl");
        mdl.put("certify.keyprovider.x509-file.iaca.validity-years", "15");
        mdl.put("certify.keyprovider.x509-file.keys[0].alias", "mdl-dsc@2026-11");
        mdl.put("certify.keyprovider.x509-file.keys[0].algorithm", "ES256");
        mdl.put("certify.keyprovider.x509-file.keys[0].subject", "CN=Demo DSC");
        mdl.put("certify.keyprovider.x509-file.keys[0].profile", "mdoc-dsc");
        mdl.put("certify.keyprovider.x509-file.keys[0].validity-days", "400");
        mdl.put("certify.keyprovider.x509-file.pem-keys[0].alias", "mdl-dsc@2027-02");
        mdl.put("certify.keyprovider.x509-file.pem-keys[0].key", "/keys/dsc.key.pem");
        mdl.put("certify.keyprovider.x509-file.pem-keys[0].key-password", "secret");
        mdl.put("certify.keyprovider.x509-file.pem-keys[0].chain", "/keys/dsc.chain.pem");
        X509FileProperties properties = bind(mdl);

        assertEquals("iaca", properties.iaca().alias());
        assertNull(properties.iaca().algorithm(), "no implicit algorithm: dev mode generates ES256, and an IACA already"
                + " in the keystore is not compared with a value nobody set");
        assertEquals(15, properties.iaca().validityYears());
        assertTrue(properties.keys().get(0).mdocDsc());
        assertEquals(400, properties.keys().get(0).validityDays());
        assertEquals(Path.of("/keys/dsc.key.pem"), properties.pemKeys().get(0).key());
        assertEquals("secret", properties.pemKeys().get(0).keyPassword());
        assertEquals(Path.of("/keys/dsc.chain.pem"), properties.pemKeys().get(0).chain());
    }

    /** The JDK PKCS#12 keystore lower-cases aliases on reload, so an upper-case alias is refused while binding. */
    @Test
    void upperCaseAliasesAreRefusedWhileBinding() {
        for (String property : List.of("keys[0].alias", "pem-keys[0].alias", "iaca.alias", "ca-alias")) {
            java.util.Map<String, String> map = new java.util.HashMap<>();
            map.put("certify.keyprovider.x509-file.path", "/keys/issuer.p12");
            map.put("certify.keyprovider.x509-file." + property, "Mdl-DSC@2026-11");
            if (property.startsWith("keys")) {
                map.put("certify.keyprovider.x509-file.keys[0].algorithm", "ES256");
            }
            String message = rootMessage(assertThrows(BindException.class, () -> bind(map)));
            assertTrue(message.contains("upper-case") && message.contains("mdl-dsc@2026-11"), property + ": " + message);
        }
        assertEquals("mdl-dsc@2026-11", bind(Map.of("certify.keyprovider.x509-file.keys[0].alias", "mdl-dsc@2026-11",
                "certify.keyprovider.x509-file.keys[0].algorithm", "ES256")).keys().get(0).alias());
        String twoVersions = rootMessage(assertThrows(BindException.class, () -> bind(Map.of(
                "certify.keyprovider.x509-file.keys[0].alias", "mdl@a@b",
                "certify.keyprovider.x509-file.keys[0].algorithm", "ES256"))));
        assertTrue(twoVersions.contains("name@version"), twoVersions);
    }

    /** A misspelt profile is refused instead of silently generating a plain key where a Document Signer was meant. */
    @Test
    void anUnknownProfileIsRefusedWhileBinding() {
        for (String profile : List.of("mdoc_dsc", "MDOC-DSC", "dsc")) {
            String message = rootMessage(assertThrows(BindException.class, () -> bind(Map.of(
                    "certify.keyprovider.x509-file.keys[0].alias", "mdl-dsc",
                    "certify.keyprovider.x509-file.keys[0].algorithm", "ES256",
                    "certify.keyprovider.x509-file.keys[0].profile", profile))));
            assertTrue(message.contains("[plain, mdoc-dsc]"), message);
        }
    }

    private static String rootMessage(Throwable thrown) {
        Throwable cause = thrown;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage();
    }
}
