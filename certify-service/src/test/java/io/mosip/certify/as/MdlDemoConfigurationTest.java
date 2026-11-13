package io.mosip.certify.as;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The mDL demo's credential configuration as the seed posts it (F-21, decision log 2026-11-13): it asks for no status
 * entry, so an issued MSO carries no {@code status} at all (ISO/IEC 18013-5 makes it optional).
 *
 * <p>Why: the only list this stack can write today is a {@code statuslist+jwt} signed by keymanager's EC key, which does
 * not chain to the IACA, so a wallet that requires the list's signer under the mDL's IACA rejects the credential (gap
 * G23). <strong>M-11 restores the block</strong> - the CWT list signed by the Document Signer - and this test then
 * asserts the opposite; nothing else in the configuration changes (its bytes are held by the seed run and the smoke
 * run, not here).
 */
class MdlDemoConfigurationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode configuration() throws Exception {
        Path path = ComposeProperties.CONFIG.resolve("mdl").resolve("mdl-configuration.json");
        assertTrue(Files.isRegularFile(path), "the mDL configuration must be committed at " + path);
        return MAPPER.readTree(Files.readString(path));
    }

    /**
     * No {@code status} block: the MSO is signed without a status entry. Restoring it is the one-step change M-11's
     * runbook (docs/design/wp/M-11-status-list-under-iaca.md, section 7.A) and config/mdl/README.md document, followed
     * by {@code MDL_SEED_UPDATE=true} so {@code mdl-seed} replaces the stored configuration.
     */
    @Test
    void theConfigurationAsksForNoStatusEntryUntilM11() throws Exception {
        JsonNode configuration = configuration();
        assertFalse(configuration.has("status"),
                "the demo mDL carries no status.status_list entry until M-11 (gap G23); restore the block then: "
                        + configuration.get("status"));
        // the rest of the configuration is still the mDL the demo issues, so the absence above is the only change
        assertTrue(configuration.get("id").asText().equals("org.iso.18013.5.1.mDL"), configuration.toString());
        assertTrue(configuration.get("format").asText().equals("mso_mdoc"), configuration.toString());
        assertTrue(configuration.get("formatConfig").get("doctype").asText().equals("org.iso.18013.5.1.mDL"));
        assertTrue(configuration.get("dataSourceId").asText().equals("mdldemo"), configuration.toString());
    }

    /**
     * The runbook's restore step is the block this configuration dropped, byte for byte: the fenced JSON block in
     * config/mdl/README.md ("Restoring the status list, after M-11") parses as the {@code status} member the v2 API
     * accepts, so re-enabling it is one documented copy and {@code MDL_SEED_UPDATE=true}, not a re-derivation.
     */
    @Test
    void theRunbooksRestoreBlockIsTheStatusMemberThisConfigurationDropped() throws Exception {
        Path readme = ComposeProperties.CONFIG.resolve("mdl").resolve("README.md");
        String text = Files.readString(readme);
        int start = text.indexOf("```json");
        assertTrue(start >= 0, "config/mdl/README.md must carry the restore block in a ```json fence");
        String block = text.substring(text.indexOf('\n', start) + 1, text.indexOf("```", start + 7));
        JsonNode documented = MAPPER.readTree("{" + block.trim().replaceAll(",$", "") + "}").get("status");
        assertTrue(documented != null && documented.isObject(), "the documented block must be a JSON object: " + block);
        assertTrue("TokenStatusList".equals(documented.get("mechanism").asText()), documented.toString());
        assertTrue(documented.get("purposes").size() == 1
                && "revocation".equals(documented.get("purposes").get(0).asText()), documented.toString());
        // the demo runs without it until M-11
        assertFalse(configuration().has("status"));
    }
}
