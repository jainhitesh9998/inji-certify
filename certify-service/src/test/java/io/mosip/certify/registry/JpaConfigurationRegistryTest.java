package io.mosip.certify.registry;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.IssuanceStrategy;
import io.mosip.certify.spi.TemplateRef;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JpaConfigurationRegistryTest {

    final CredentialConfigRepository repository = mock(CredentialConfigRepository.class);
    final io.mosip.certify.repository.CredentialTemplateRepository templates = mock(io.mosip.certify.repository.CredentialTemplateRepository.class);
    final JpaConfigurationRegistry registry = new JpaConfigurationRegistry(repository, templates, new ObjectMapper(), "DataProvider");

    static CredentialConfig farmer() {
        CredentialConfig row = new CredentialConfig();
        row.setCredentialConfigKeyId("FarmerCredential");
        row.setStatus("active");
        row.setCredentialFormat("ldp_vc");
        row.setContext("https://www.w3.org/2018/credentials/v1");
        row.setCredentialType("FarmerCredential,VerifiableCredential");
        row.setVcTemplate("e30=");
        row.setDidUrl("did:web:issuer.example");
        row.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        row.setKeyManagerRefId("ED25519_SIGN");
        row.setSignatureAlgo("EdDSA");
        row.setSignatureCryptoSuite("Ed25519Signature2020");
        row.setScope("mock_identity_vc_ldp");
        row.setOrder(List.of("fullName"));
        row.setCredentialStatusPurposes(List.of("revocation", "suspension"));
        return row;
    }

    @Test
    void ldpRowMapsToATemplatedKeymanagerSignedConfiguration() {
        when(repository.findByTenantIdAndCredentialConfigKeyId("default", "FarmerCredential")).thenReturn(Optional.of(farmer()));

        CredentialConfiguration c = registry.byId("default", "FarmerCredential").orElseThrow();

        assertEquals("default", c.tenantId());
        assertEquals("FarmerCredential", c.id());
        assertEquals("mock_identity_vc_ldp", c.scope());
        assertEquals("ldp_vc", c.format());
        assertEquals("https://www.w3.org/2018/credentials/v1|FarmerCredential,VerifiableCredential", c.formatConfig().selectorKey());
        assertEquals(TemplateRef.Mode.FULL_DOCUMENT, c.template().mode());
        assertEquals("velocity", c.template().engine());
        assertEquals("e30=", c.template().content());
        assertEquals("keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN", c.signing().keyRef().toString());
        assertEquals(SignatureAlgorithm.EdDSA, c.signing().algorithm());
        assertEquals("Ed25519Signature2020", c.signing().cryptosuite());
        assertEquals("did:web:issuer.example", c.signing().issuerDid());
        assertEquals(IssuanceStrategy.TEMPLATE, c.strategy());
        assertEquals("BitstringStatusList", c.status().mechanism());
        assertEquals(List.of("revocation", "suspension"), c.status().purposes());
        assertEquals(List.of("fullName"), c.display().order());
        assertTrue(c.requiresHolderBinding());
    }

    @Test
    void v2ColumnsReadExactlyAsTheLegacyColumns() {
        CredentialConfiguration legacy = registry.toConfiguration(farmer());
        CredentialConfig v2 = farmer();
        ConfigV2Columns.fill(v2);
        assertTrue(JpaConfigurationRegistry.isV2(v2));
        CredentialConfiguration fromV2 = registry.toConfiguration(v2);

        assertEquals(legacy.tenantId(), fromV2.tenantId());
        assertEquals(legacy.id(), fromV2.id());
        assertEquals(legacy.format(), fromV2.format());
        assertEquals(legacy.formatConfig().selectorKey(), fromV2.formatConfig().selectorKey());
        assertEquals(legacy.formatConfig().raw(), fromV2.formatConfig().raw());
        assertEquals(legacy.signing().keyRef().toString(), fromV2.signing().keyRef().toString());
        assertEquals(legacy.signing().algorithm(), fromV2.signing().algorithm());
        assertEquals(legacy.signing().cryptosuite(), fromV2.signing().cryptosuite());
        assertEquals(legacy.signing().issuerDid(), fromV2.signing().issuerDid());
        assertEquals(legacy.status(), fromV2.status());
        assertEquals(legacy.strategy(), fromV2.strategy());
        assertEquals(legacy.template(), fromV2.template());
        assertEquals(legacy.display().order(), fromV2.display().order());

        CredentialConfig sd = farmer();
        sd.setCredentialFormat("dc+sd-jwt");
        sd.setSdJwtVct("FarmerCredential");
        sd.setSdClaim("$.fullName,$.address.city");
        sd.setContext(null);
        sd.setCredentialType(null);
        CredentialConfiguration sdLegacy = registry.toConfiguration(sd);
        ConfigV2Columns.fill(sd);
        CredentialConfiguration sdV2 = registry.toConfiguration(sd);
        assertEquals(sdLegacy.formatConfig().raw(), sdV2.formatConfig().raw());
        assertEquals("FarmerCredential", sdV2.formatConfig().selectorKey());

        CredentialConfig external = farmer();
        ConfigV2Columns.fill(external);
        external.setIssuanceStrategy("SUPPLIED");
        external.setDataSourceId("vc-api");
        CredentialConfiguration supplied = registry.toConfiguration(external);
        assertEquals(IssuanceStrategy.SUPPLIED, supplied.strategy(), "a v2 row may name its strategy");
        assertEquals("vc-api", supplied.dataSourceId());
        external.setIssuanceStrategy("TEMPLATE");
        assertEquals(IssuanceStrategy.TEMPLATE, registry.toConfiguration(external).strategy(), "the backfilled default still follows the plugin mode");
    }

    @Test
    void lookupsAreScopedToTheTenant() {
        CredentialConfig acme = farmer();
        acme.setTenantId("acme");
        when(repository.findByTenantIdAndCredentialConfigKeyId("acme", "FarmerCredential")).thenReturn(Optional.of(acme));
        when(repository.findByTenantId("acme")).thenReturn(List.of(acme));
        assertEquals("acme", registry.byId("acme", "FarmerCredential").orElseThrow().tenantId());
        assertTrue(registry.byId("default", "FarmerCredential").isEmpty(), "another tenant's row is not visible");
        assertEquals(1, registry.all("acme").size());
        assertTrue(registry.all("default").isEmpty());
        assertTrue(registry.byId(null, "FarmerCredential").isEmpty());
    }

    @Test
    void templateRowIsPreferredOverTheBlobAndTheBlobIsTheFallback() {
        CredentialConfig row = farmer();
        row.setConfigId("cfg-1");
        row.setTemplateId("cfg-1");
        row.setTemplateVersion(1);
        io.mosip.certify.entity.CredentialTemplate stored = new io.mosip.certify.entity.CredentialTemplate();
        stored.setId("cfg-1");
        stored.setVersion(1);
        stored.setEngine("velocity");
        stored.setMode("FULL_DOCUMENT");
        stored.setContent("{\"issuer\": \"${_issuer}\"}");
        when(templates.findByIdAndVersion("cfg-1", 1)).thenReturn(Optional.of(stored));
        CredentialConfiguration c = registry.toConfiguration(row);
        assertEquals("cfg-1", c.template().templateId());
        assertEquals(1, c.template().version());
        assertEquals("{\"issuer\": \"${_issuer}\"}", c.template().content(), "the decoded text of the template row");
        assertEquals("did:web:issuer.example", c.template().params().get("didUrl"));

        row.setTemplateVersion(null);
        when(templates.findFirstByIdOrderByVersionDesc("cfg-1")).thenReturn(Optional.empty());
        assertEquals("e30=", registry.toConfiguration(row).template().content(), "no row, the legacy blob");
        assertEquals("FarmerCredential", registry.toConfiguration(row).template().templateId());
    }

    @Test
    void selectorsResolvePerFormat() {
        CredentialConfig sd = farmer();
        sd.setCredentialConfigKeyId("FarmerSdJwt");
        sd.setCredentialFormat("dc+sd-jwt");
        sd.setSdJwtVct("FarmerCredential");
        sd.setSignatureAlgo("ES256");
        sd.setSignatureCryptoSuite(null);
        sd.setKeyManagerAppId("CERTIFY_VC_SIGN_EC_R1");
        sd.setKeyManagerRefId("EC_SECP256R1_SIGN");
        CredentialConfig mdl = farmer();
        mdl.setCredentialConfigKeyId("Mdl");
        mdl.setCredentialFormat("mso_mdoc");
        mdl.setDocType("org.iso.18013.5.1.mDL");
        mdl.setVcTemplate(null);
        mdl.setSignatureAlgo(null);
        mdl.setCredentialSigningAlgValuesSupported(List.of("ES256"));
        when(repository.findByTenantIdAndCredentialFormatAndCredentialTypeAndContext("default", "ldp_vc", "FarmerCredential,VerifiableCredential", "https://www.w3.org/2018/credentials/v1")).thenReturn(Optional.of(farmer()));
        when(repository.findByTenantIdAndCredentialFormatAndSdJwtVct("default", "dc+sd-jwt", "FarmerCredential")).thenReturn(Optional.of(sd));
        when(repository.findByTenantIdAndCredentialFormatAndDocType("default", "mso_mdoc", "org.iso.18013.5.1.mDL")).thenReturn(Optional.of(mdl));

        assertEquals("FarmerCredential", registry.bySelector("default", "ldp_vc", "https://www.w3.org/2018/credentials/v1|FarmerCredential,VerifiableCredential").orElseThrow().id());
        CredentialConfiguration sdJwt = registry.bySelector("default", "dc+sd-jwt", "FarmerCredential").orElseThrow();
        assertEquals("keymanager:CERTIFY_VC_SIGN_EC_R1/EC_SECP256R1_SIGN", sdJwt.signing().keyRef().toString());
        assertNull(sdJwt.signing().cryptosuite());
        CredentialConfiguration mdoc = registry.bySelector("default", "mso_mdoc", "org.iso.18013.5.1.mDL").orElseThrow();
        assertEquals(TemplateRef.Mode.NONE, mdoc.template().mode(), "no template on the row");
        assertEquals(SignatureAlgorithm.ES256, mdoc.signing().algorithm(), "algorithm from the signing-alg values when the row has none");
        assertTrue(registry.bySelector("default", "ldp_vc", "no-separator").isEmpty());
        assertTrue(registry.bySelector("default", "jwt_vc_json", "x").isEmpty());
    }

    @Test
    void inactiveRowsOtherTenantsAndExternalModeAreHandled() {
        CredentialConfig inactive = farmer();
        inactive.setStatus("inactive");
        when(repository.findByTenantIdAndCredentialConfigKeyId("default", "FarmerCredential")).thenReturn(Optional.of(inactive));
        when(repository.findByTenantId("default")).thenReturn(List.of(inactive, farmer()));

        assertTrue(registry.byId("default", "FarmerCredential").isEmpty());
        assertEquals(1, registry.all("default").size());
        assertTrue(registry.all("acme").isEmpty());
        assertTrue(registry.byId("acme", "FarmerCredential").isEmpty());

        JpaConfigurationRegistry external = new JpaConfigurationRegistry(repository, templates, new ObjectMapper(), "VCIssuance");
        assertEquals(IssuanceStrategy.EXTERNAL, external.toConfiguration(farmer()).strategy());
        assertFalse(external.toConfiguration(farmer()).template().params().isEmpty());
    }

    @Test
    void providerPrefixedKeyColumnSelectsAnotherProvider() {
        CredentialConfig row = farmer();
        row.setKeyManagerAppId("x509-file:issuer-es256@abc");
        row.setKeyManagerRefId(null);
        row.setSignatureAlgo("ES256");
        CredentialConfiguration c = registry.toConfiguration(row);
        assertEquals("x509-file", c.signing().keyRef().provider());
        assertEquals("issuer-es256", c.signing().keyRef().alias());
        assertEquals("abc", c.signing().keyRef().version());
    }

    @Test
    void rowWithoutAnyAlgorithmIsAConfigurationError() {
        CredentialConfig broken = farmer();
        broken.setSignatureAlgo(null);
        broken.setCredentialSigningAlgValuesSupported(null);
        assertThrows(IllegalStateException.class, () -> registry.toConfiguration(broken));
    }
}
