package io.mosip.certify.datasource.file;

import io.mosip.certify.issuance.IssuanceException;
import io.mosip.certify.spi.Authorization;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.DataSourceException;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.TenantContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Loading, key lookup, binary fields, symlinks, size bounds and the startup checks of {@link FileCredentialDataSource} (M-10). */
class FileCredentialDataSourceTest {

    @TempDir
    Path dir;

    private Path write(String name, String content) throws IOException {
        Path file = dir.resolve(name);
        Files.createDirectories(file.getParent() == null ? dir : file.getParent());
        Files.writeString(file, content);
        return file;
    }

    /** The context the core builds: the validated token claims carry the key the record is looked up by. */
    static IssuanceContext context(Map<String, Object> claims) {
        return new IssuanceContext(TenantContext.DEFAULT, new Authorization("Bearer", claims, "token-hash"), List.of(),
                ProtocolVersion.OID4VCI_1_0, "correlation", Instant.parse("2026-01-01T00:00:00Z"), Map.of());
    }

    static IssuanceContext subject(Object subject) {
        return context(subject == null ? Map.of() : Map.of("sub", subject));
    }

    @Test
    void returnsTheRecordTheKeyClaimSelects() throws Exception {
        Path file = write("holders.json", """
                {
                  "alice": {"given_name": "Asha", "age_over_18": true, "sex": 1,
                            "driving_privileges": [{"vehicle_category_code": "B", "issue_date": "2024-01-15"}]},
                  "bob": {"given_name": "Ravi"}
                }
                """);
        FileCredentialDataSource source = new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(file, "sub", List.of()));

        assertEquals("demo", source.id());
        assertEquals("sub", source.keyClaim());
        ClaimSet claims = source.fetch(subject("alice"), null);
        assertEquals("Asha", claims.get("given_name"));
        assertEquals(Boolean.TRUE, claims.get("age_over_18"));
        assertEquals(1, claims.get("sex"));
        assertEquals(List.of(Map.of("vehicle_category_code", "B", "issue_date", "2024-01-15")), claims.get("driving_privileges"));
        assertEquals("demo", claims.provenance().get(FileCredentialDataSource.PROVENANCE_SOURCE));
        assertEquals("Ravi", source.fetch(subject("bob"), null).get("given_name"));
    }

    @Test
    void aConfiguredKeyClaimIsReadFromTheTokenClaims() throws Exception {
        Path file = write("holders.json", """
                {"Asha-01": {"given_name": "Asha"}}
                """);
        FileCredentialDataSource source = new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(file, "uid", List.of()));

        assertEquals("Asha", source.fetch(context(Map.of("uid", "Asha-01", "sub", "ignored")), null).get("given_name"));
        DataSourceException e = assertThrows(DataSourceException.class, () -> source.fetch(subject("Asha-01"), null));
        assertEquals(FileCredentialDataSource.ERROR_NO_DATA, e.getErrorCode(), "the record is not selected by sub");
    }

    @Test
    void anUnknownOrMissingSubjectIsCredentialRequestDeniedAndNotAServerError() throws Exception {
        Path file = write("holders.json", """
                {"alice": {"given_name": "Asha"}}
                """);
        FileCredentialDataSource source = new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(file, "sub", List.of()));

        DataSourceException unknown = assertThrows(DataSourceException.class, () -> source.fetch(subject("carol"), null));
        assertEquals(IssuanceException.CREDENTIAL_REQUEST_DENIED, unknown.getErrorCode());
        assertEquals("credential_request_denied", unknown.getErrorCode(), "OpenID4VCI 1.0 section 8.3.1.2");
        assertNotEquals(IssuanceException.ISSUANCE_FAILED, unknown.getErrorCode(),
                "the adapters answer 500 for credential_issuance_failed and 400 for every other core code");

        DataSourceException absent = assertThrows(DataSourceException.class, () -> source.fetch(subject(null), null));
        assertEquals(FileCredentialDataSource.ERROR_NO_DATA, absent.getErrorCode());
        assertTrue(absent.getMessage().contains("'sub'"), absent.getMessage());
    }

    @Test
    void binaryFieldsAreReadOnceAndServedAsUnpaddedBase64url() throws Exception {
        byte[] jpeg = {(byte) 0xFF, (byte) 0xD8, 0x01, 0x02, 0x03, 0x3F, (byte) 0xFF, (byte) 0xD9};
        Path portraits = dir.resolve("img");
        Files.createDirectories(portraits);
        Files.write(portraits.resolve("face.jpg"), jpeg);
        Path file = write("holders.json", """
                {"alice": {"given_name": "Asha", "portrait": "img/face.jpg"}, "bob": {"given_name": "Ravi"}}
                """);
        FileCredentialDataSource source = new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(file, "sub", List.of("portrait")));

        Files.delete(portraits.resolve("face.jpg")); // the file was read at startup, never per request
        String portrait = (String) source.fetch(subject("alice"), null).get("portrait");
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(jpeg), portrait);
        assertFalse(portrait.contains("="), "base64url without padding, as an mDoc bstr takes it");
        assertTrue(portrait.chars().noneMatch(c -> c == '+' || c == '/'), "the URL alphabet, not the standard one");
        assertArrayEquals(jpeg, Base64.getUrlDecoder().decode(portrait));
        assertFalse(source.fetch(subject("bob"), null).claims().containsKey("portrait"),
                "a binary field a record does not name is simply absent");
    }

    @Test
    void nestedValuesAreImmutableAndASecondFetchIsUnaffected() throws Exception {
        Path file = write("holders.json", """
                {"alice": {"given_name": "Asha",
                           "driving_privileges": [{"vehicle_category_code": "B", "codes": [{"code": "01"}]}]}}
                """);
        FileCredentialDataSource source = new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(file, "sub", List.of()));

        Map<String, Object> record = source.fetch(subject("alice"), null).claims();
        assertThrows(UnsupportedOperationException.class, () -> record.put("given_name", "Mallory"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> privileges = (List<Map<String, Object>>) record.get("driving_privileges");
        assertThrows(UnsupportedOperationException.class, () -> privileges.add(Map.of()));
        assertThrows(UnsupportedOperationException.class, () -> privileges.get(0).put("vehicle_category_code", "C"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> codes = (List<Map<String, Object>>) privileges.get(0).get("codes");
        assertThrows(UnsupportedOperationException.class, () -> codes.get(0).put("code", "99"));

        Map<String, Object> again = source.fetch(subject("alice"), null).claims();
        assertEquals("Asha", again.get("given_name"));
        assertEquals("B", privileges.get(0).get("vehicle_category_code"));
        assertEquals("01", codes.get(0).get("code"));
    }

    @Test
    void absolutePathsAndPathsEscapingTheJsonDirectoryAreRefused() throws Exception {
        Path absolute = write("absolute.json", """
                {"alice": {"portrait": "%s"}}
                """.formatted(dir.resolve("face.jpg").toAbsolutePath()));
        IllegalStateException absoluteFailure = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(absolute, "sub", List.of("portrait"))));
        assertTrue(absoluteFailure.getMessage().contains("not absolute"), absoluteFailure.getMessage());

        for (String escaping : List.of("../outside.jpg", "img/../../outside.jpg", "..")) {
            Path file = write("escape-" + escaping.replaceAll("[^a-z]", "") + ".json", """
                    {"alice": {"portrait": "%s"}}
                    """.formatted(escaping));
            IllegalStateException failure = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                    new FileDataSourceProperties.Source(file, "sub", List.of("portrait"))), escaping);
            assertTrue(failure.getMessage().contains("escapes"), failure.getMessage());
        }
    }

    @Test
    void symlinksPointingOutsideTheJsonDirectoryAreRefused() throws Exception {
        Path outside = Files.createTempDirectory("mdl-outside");
        try {
            Files.writeString(outside.resolve("holders.json"), """
                    {"alice": {"given_name": "Mallory"}}
                    """);
            Files.writeString(outside.resolve("face.jpg"), "outside");
            Path linkedJson = dir.resolve("holders.json");
            Files.createSymbolicLink(linkedJson, outside.resolve("holders.json"));
            IllegalStateException fileLink = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                    new FileDataSourceProperties.Source(linkedJson, "sub", List.of())));
            assertTrue(fileLink.getMessage().contains("outside"), fileLink.getMessage());

            Path file = write("bin.json", """
                    {"alice": {"portrait": "face.jpg"}}
                    """);
            Files.createSymbolicLink(dir.resolve("face.jpg"), outside.resolve("face.jpg"));
            IllegalStateException binaryLink = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                    new FileDataSourceProperties.Source(file, "sub", List.of("portrait"))));
            assertTrue(binaryLink.getMessage().contains("'portrait'") && binaryLink.getMessage().contains("outside"),
                    binaryLink.getMessage());

            Path directoryJson = write("dir.json", """
                    {"alice": {"portrait": "linked/face.jpg"}}
                    """);
            Path linkedDirectory = dir.resolve("linked");
            Files.createSymbolicLink(linkedDirectory, outside);
            IllegalStateException directoryLink = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                    new FileDataSourceProperties.Source(directoryJson, "sub", List.of("portrait"))));
            assertTrue(directoryLink.getMessage().contains("outside"), directoryLink.getMessage());
        } finally {
            Files.deleteIfExists(outside.resolve("holders.json"));
            Files.deleteIfExists(outside.resolve("face.jpg"));
            Files.deleteIfExists(outside);
        }
    }

    @Test
    void aKubernetesConfigMapLayoutIsAccepted() throws Exception {
        // a ConfigMap volume: every key is a link into ..data/, which links to the versioned directory in the same dir
        Path versioned = dir.resolve("..2026_01_01_00_00_00");
        Files.createDirectories(versioned);
        byte[] jpeg = {(byte) 0xFF, (byte) 0xD8, 0x11, 0x22, (byte) 0xFF, (byte) 0xD9};
        Files.write(versioned.resolve("portrait-1.jpg"), jpeg);
        Files.writeString(versioned.resolve("holders.json"), """
                {"alice": {"given_name": "Asha", "portrait": "portrait-1.jpg"}}
                """);
        Files.createSymbolicLink(dir.resolve("..data"), versioned.getFileName());
        Path json = dir.resolve("holders.json");
        Files.createSymbolicLink(json, Path.of("..data", "holders.json"));
        Files.createSymbolicLink(dir.resolve("portrait-1.jpg"), Path.of("..data", "portrait-1.jpg"));

        FileCredentialDataSource source = new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(json, "sub", List.of("portrait")));

        assertEquals("Asha", source.fetch(subject("alice"), null).get("given_name"));
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(jpeg),
                source.fetch(subject("alice"), null).get("portrait"));
    }

    @Test
    void filesAboveTheSizeBoundsAreRefused() throws Exception {
        String largeValue = "x".repeat((int) FileCredentialDataSource.MAX_JSON_BYTES);
        Path large = write("large.json", "{\"alice\": {\"blob\": \"" + largeValue + "\"}}");
        IllegalStateException json = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(large, "sub", List.of())));
        assertTrue(json.getMessage().contains("demo") && json.getMessage().contains("larger than")
                && json.getMessage().contains("large.json"), json.getMessage());

        byte[] tooLarge = new byte[(int) FileCredentialDataSource.MAX_BINARY_BYTES + 1];
        Files.write(dir.resolve("big.jpg"), tooLarge);
        Path file = write("binary.json", """
                {"alice": {"portrait": "big.jpg"}}
                """);
        IllegalStateException binary = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(file, "sub", List.of("portrait"))));
        assertTrue(binary.getMessage().contains("'portrait'") && binary.getMessage().contains("'alice'")
                && binary.getMessage().contains("big.jpg") && binary.getMessage().contains("larger than"), binary.getMessage());
    }

    @Test
    void theAggregateBudgetIsEnforcedAcrossAllBinaryFiles() throws Exception {
        // each file is under the 1 MiB per-file cap, so only the per-source budget can refuse this
        Files.write(dir.resolve("face.jpg"), new byte[(int) FileCredentialDataSource.MAX_BINARY_BYTES]);
        StringBuilder json = new StringBuilder("{");
        for (int i = 0; i <= FileCredentialDataSource.MAX_TOTAL_BYTES / FileCredentialDataSource.MAX_BINARY_BYTES; i++) {
            if (i > 0) json.append(',');
            json.append("\"holder-").append(i).append("\": {\"portrait\": \"face.jpg\"}");
        }
        Path file = write("many.json", json.append('}').toString());

        IllegalStateException budget = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(file, "sub", List.of("portrait"))));
        assertTrue(budget.getMessage().contains("demo") && budget.getMessage().contains("in total")
                && budget.getMessage().contains("'portrait'") && budget.getMessage().contains("face.jpg"), budget.getMessage());
    }

    @Test
    void theReservedDataProviderPluginIdIsRefused() throws Exception {
        Path file = write("holders.json", """
                {"alice": {"given_name": "Asha"}}
                """);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("data-provider-plugin",
                new FileDataSourceProperties.Source(file, "sub", List.of())));
        assertTrue(e.getMessage().contains("reserved") && e.getMessage().contains("data-provider-plugin"), e.getMessage());
    }

    @Test
    void missingFilesAndMalformedJsonFailAtStartupWithTheFileNamed() throws Exception {
        Path absent = dir.resolve("absent.json");
        IllegalStateException missing = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(absent, "sub", List.of())));
        assertTrue(missing.getMessage().contains("absent.json") && missing.getMessage().contains("does not exist"), missing.getMessage());

        IllegalStateException malformed = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(write("bad.json", "{\"alice\": {\"a\": 1}"), "sub", List.of())));
        assertTrue(malformed.getMessage().contains("not readable JSON"), malformed.getMessage());

        IllegalStateException array = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(write("array.json", "[]"), "sub", List.of())));
        assertTrue(array.getMessage().contains("one JSON object"), array.getMessage());

        IllegalStateException notAnObject = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(write("scalar.json", "{\"alice\": 1}"), "sub", List.of())));
        assertTrue(notAnObject.getMessage().contains("record 'alice'") && notAnObject.getMessage().contains("not a JSON object"),
                notAnObject.getMessage());

        IllegalStateException missingPortrait = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(write("portrait.json", """
                        {"alice": {"portrait": "absent.jpg"}}
                        """), "sub", List.of("portrait"))));
        assertTrue(missingPortrait.getMessage().contains("missing or non-regular file"), missingPortrait.getMessage());

        // a repeated record key would leave one subject's data dependent on where the duplicate sits: refused, not
        // resolved last-wins
        IllegalStateException duplicate = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(write("duplicate.json", """
                        {"alice": {"given_name": "Asha"}, "alice": {"given_name": "Mallory"}}
                        """), "sub", List.of())));
        assertTrue(duplicate.getMessage().contains("not readable JSON") && duplicate.getMessage().toLowerCase().contains("duplicate"),
                duplicate.getMessage());

        // a second document after the first object is a deployment mistake, not data to ignore
        IllegalStateException trailing = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(write("trailing.json", """
                        {"alice": {"given_name": "Asha"}}
                        {"bob": {"given_name": "Ravi"}}
                        """), "sub", List.of())));
        assertTrue(trailing.getMessage().contains("not readable JSON") && trailing.getMessage().toLowerCase().contains("trailing"),
                trailing.getMessage());

        IllegalStateException noPath = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(null, "sub", List.of())));
        assertTrue(noPath.getMessage().contains(".path is required"), noPath.getMessage());
    }
}
