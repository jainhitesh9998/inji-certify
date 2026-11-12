package io.mosip.certify.datasource.file;

import io.mosip.certify.spi.ClaimSet;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The demo data of docs/design/20-mdl-issuer.md M-10 loads through {@link FileCredentialDataSource} and carries the
 * mandatory elements of an ISO/IEC 18013-5 Table 5 mDL: synthetic people (decision D2) with generated portraits.
 */
class MdlDemoDataTest {

    /** Elements without which the namespace is not a valid {@code org.iso.18013.5.1.mDL} (ISO/IEC 18013-5 Table 5). */
    static final List<String> MANDATORY = List.of("family_name", "given_name", "birth_date", "issue_date", "expiry_date",
            "issuing_country", "issuing_authority", "document_number", "portrait", "driving_privileges", "un_distinguishing_sign");

    private final Path holders = Path.of("..", "docker-compose", "docker-compose-injistack", "config", "mdl", "holders.json")
            .toAbsolutePath().normalize();

    @Test
    void theThreeDemoHoldersCarryACompleteMdlAndADecodablePortrait() throws Exception {
        assertTrue(Files.isRegularFile(holders), "the demo data must be committed at " + holders);
        FileCredentialDataSource source = new FileCredentialDataSource("mdl-demo",
                new FileDataSourceProperties.Source(holders, "sub", List.of("portrait")));

        Set<String> portraits = new HashSet<>();
        for (String subject : List.of("mdl-demo-1", "mdl-demo-2", "mdl-demo-3")) {
            ClaimSet claims = source.fetch(FileCredentialDataSourceTest.subject(subject), null);
            Map<String, Object> record = claims.claims();
            for (String element : MANDATORY) {
                assertTrue(record.containsKey(element), subject + " lacks " + element);
            }
            assertEquals("IN", record.get("issuing_country"));
            assertEquals("Lorem Ipsum Demo Issuing Authority", record.get("issuing_authority"));
            assertEquals("IND", record.get("un_distinguishing_sign"));

            LocalDate birth = LocalDate.parse((String) record.get("birth_date"));
            LocalDate issued = LocalDate.parse((String) record.get("issue_date"));
            LocalDate expiry = LocalDate.parse((String) record.get("expiry_date"));
            assertTrue(expiry.isAfter(LocalDate.now()), subject + " would be issued already expired");
            assertTrue(issued.isBefore(expiry) && birth.isBefore(issued), subject + " has inconsistent dates");

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> privileges = (List<Map<String, Object>>) record.get("driving_privileges");
            assertTrue(privileges != null && !privileges.isEmpty(), subject + " has no driving privileges");
            for (Map<String, Object> privilege : privileges) {
                assertTrue(privilege.keySet().containsAll(List.of("vehicle_category_code", "issue_date", "expiry_date")),
                        subject + " privilege " + privilege);
            }

            byte[] jpeg = Base64.getUrlDecoder().decode((String) record.get("portrait"));
            assertTrue(jpeg.length < 10 * 1024, subject + " portrait is " + jpeg.length + " bytes");
            assertEquals((byte) 0xFF, jpeg[jpeg.length - 2]);
            assertEquals((byte) 0xD9, jpeg[jpeg.length - 1], "the JPEG must end with FFD9");
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(jpeg));
            assertNotNull(image, subject + " portrait does not decode with ImageIO");
            assertEquals(160, image.getWidth());
            assertEquals(200, image.getHeight());
            portraits.add((String) record.get("portrait"));
        }
        assertEquals(3, portraits.size(), "every holder has its own portrait");
    }
}
