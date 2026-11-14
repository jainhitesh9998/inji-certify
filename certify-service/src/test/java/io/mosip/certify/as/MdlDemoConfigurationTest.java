package io.mosip.certify.as;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The mDL demo's credential configuration as the seed posts it (F-21, decision log 2026-11-13): it is the configuration
 * the demo issued before F-21 with exactly one member removed - {@code status} - so an issued MSO carries no
 * {@code status} at all (ISO/IEC 18013-5 makes it optional).
 *
 * <p>Why: the only list this stack can write today is a {@code statuslist+jwt} signed by keymanager's EC key, which does
 * not chain to the IACA, so a wallet that requires the list's signer under the mDL's IACA rejects the credential (gap
 * G23). <strong>M-11 restores the block</strong> - the CWT list signed by the Document Signer - and this test goes with
 * it, together with the restore step of its runbook (docs/design/wp/M-11-status-list-under-iaca.md section 7.A) and of
 * config/mdl/README.md.
 *
 * <p>The comparison is exact, not member by member: {@code mdl-configuration-with-status.json} is the committed file as
 * it was at {@code 9cac1116}, and the live file must be that text with {@link #STATUS_BLOCK} removed. A change to any
 * other byte (a claim, a signing algorithm, the template placeholder) fails here, so "only the status block" is measured
 * rather than asserted in prose.
 */
class MdlDemoConfigurationTest {

    /** The member F-21 removed, byte for byte: what the runbooks put back, and where (before {@code "display"}). */
    static final String STATUS_BLOCK = "  \"status\": {\n"
            + "    \"mechanism\": \"TokenStatusList\",\n"
            + "    \"purposes\": [\"revocation\"]\n"
            + "  },\n";

    /** {@code config/mdl/mdl-configuration.json} at {@code 9cac1116}, before the status block was removed. */
    private static final Path WITH_STATUS = Path.of("src/test/resources/mdl/mdl-configuration-with-status.json");

    private static String configuration() throws Exception {
        Path path = ComposeProperties.CONFIG.resolve("mdl").resolve("mdl-configuration.json");
        assertTrue(Files.isRegularFile(path), "the mDL configuration must be committed at " + path);
        return Files.readString(path);
    }

    private static String withStatus() throws Exception {
        Path path = WITH_STATUS;
        if (!Files.isRegularFile(path)) {
            path = Path.of("certify-service").resolve(path);
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    /**
     * The committed file is the pre-F-21 configuration minus the {@code status} member and nothing else. Restoring it is
     * one documented step (README, "Restoring the status list, after M-11"; M-11 section 7.A), followed by
     * {@code MDL_SEED_UPDATE=true} so {@code mdl-seed} replaces the stored configuration.
     */
    @Test
    void theConfigurationIsTheDemoMdlWithoutItsStatusEntry() throws Exception {
        String withStatus = withStatus();
        assertTrue(withStatus.contains(STATUS_BLOCK), "the recording must contain the block the runbooks restore");
        assertEquals(withStatus.replace(STATUS_BLOCK, ""), configuration(),
                "the demo configuration is the pre-F-21 file minus the status block, byte for byte");
        assertFalse(configuration().contains("\"status\""), "no status member, so the MSO is signed without one");
    }

    /** The block the README documents is the block this test removes: the two cannot drift apart. */
    @Test
    void theRunbooksRestoreBlockIsTheMemberThisConfigurationDropped() throws Exception {
        String readme = Files.readString(ComposeProperties.CONFIG.resolve("mdl").resolve("README.md"));
        int start = readme.indexOf("```json");
        assertTrue(start >= 0, "config/mdl/README.md must carry the restore block in a ```json fence");
        String documented = readme.substring(readme.indexOf('\n', start) + 1, readme.indexOf("```", start + 7));
        assertEquals(STATUS_BLOCK.strip(), documented.strip(),
                "the README's restore block is exactly the member the configuration lost");
    }
}
