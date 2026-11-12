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

/** Loading, key lookup, binary fields and the startup checks of {@link FileCredentialDataSource} (M-10). */
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
    void anUnknownOrMissingSubjectIsTheCoreNoDataErrorAndNotAServerError() throws Exception {
        Path file = write("holders.json", """
                {"alice": {"given_name": "Asha"}}
                """);
        FileCredentialDataSource source = new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(file, "sub", List.of()));

        DataSourceException unknown = assertThrows(DataSourceException.class, () -> source.fetch(subject("carol"), null));
        assertEquals(IssuanceException.INVALID_CREDENTIAL_REQUEST, unknown.getErrorCode());
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
        assertTrue(missingPortrait.getMessage().contains("missing file"), missingPortrait.getMessage());

        IllegalStateException noPath = assertThrows(IllegalStateException.class, () -> new FileCredentialDataSource("demo",
                new FileDataSourceProperties.Source(null, "sub", List.of())));
        assertTrue(noPath.getMessage().contains(".path is required"), noPath.getMessage());
    }
}
