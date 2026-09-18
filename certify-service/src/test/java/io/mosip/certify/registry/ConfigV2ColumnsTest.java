package io.mosip.certify.registry;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.attributes.Claims;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class ConfigV2ColumnsTest {

    @Test
    void legacyColumnsBecomeTheV2ModelAsTheMigrationBackfillsThem() {
        CredentialConfig row = new CredentialConfig();
        row.setCredentialFormat("ldp_vc");
        row.setContext("https://www.w3.org/2018/credentials/v1");
        row.setCredentialType("VerifiableCredential,FarmerCredential");
        row.setSdClaim(null);
        Claims claims = new Claims();
        Claims.Display display = new Claims.Display();
        display.setName("Full name");
        display.setLocale("en");
        claims.setDisplay(List.of(display));
        row.setClaims(Map.of("fullName", claims));
        row.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        row.setKeyManagerRefId("ED25519_SIGN");
        row.setSignatureAlgo("EdDSA");
        row.setSignatureCryptoSuite("Ed25519Signature2020");
        row.setDidUrl("did:web:issuer");
        row.setCredentialStatusPurposes(List.of("revocation"));

        ConfigV2Columns.fill(row);

        assertEquals(2, row.getConfigVersion());
        assertEquals("default", row.getTenantId());
        assertEquals("TEMPLATE", row.getIssuanceStrategy());
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), row.getFormatConfig().get("context"));
        assertEquals(List.of("VerifiableCredential", "FarmerCredential"), row.getFormatConfig().get("types"));
        assertEquals("Full name", ((List<Map<?, ?>>) ((Map<?, ?>) ((Map<?, ?>) row.getFormatConfig().get("claims")).get("fullName")).get("display")).get(0).get("name"));
        assertFalse(row.getFormatConfig().containsKey("vct") || row.getFormatConfig().containsKey("sdClaims"), "nulls are stripped: " + row.getFormatConfig());
        assertEquals(Map.of("provider", "keymanager", "alias", "CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", "alg", "EdDSA",
                "cryptosuite", "Ed25519Signature2020", "didUrl", "did:web:issuer"), row.getSigningConfig());
        assertEquals(Map.of("mechanism", "BitstringStatusList", "purposes", List.of("revocation")), row.getStatusConfig());

        CredentialConfig prefixed = new CredentialConfig();
        prefixed.setCredentialFormat("mso_mdoc");
        prefixed.setDocType("org.iso.18013.5.1.mDL");
        prefixed.setKeyManagerAppId("x509-file:mdl-signer@2");
        prefixed.setSignatureAlgo("ES256");
        ConfigV2Columns.fill(prefixed);
        assertEquals("x509-file", prefixed.getSigningConfig().get("provider"), "a provider-prefixed key column keeps its provider");
        assertEquals("mdl-signer@2", prefixed.getSigningConfig().get("alias"));
        assertEquals("org.iso.18013.5.1.mDL", prefixed.getFormatConfig().get("doctype"));
        assertNull(prefixed.getStatusConfig());
    }
}
