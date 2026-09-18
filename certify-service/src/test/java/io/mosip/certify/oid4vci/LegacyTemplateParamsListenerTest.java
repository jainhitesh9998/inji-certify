package io.mosip.certify.oid4vci;

import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatConfig;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.StatusConfig;
import io.mosip.certify.spi.TemplateRef;
import io.mosip.certify.spi.TenantContext;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LegacyTemplateParamsListenerTest {

    static final IssuanceContext CONTEXT = new IssuanceContext(TenantContext.defaultTenant("http://issuer/v1/certify", null), null, List.of(),
            ProtocolVersion.OID4VCI_1_0, "c", Instant.parse("2026-09-19T10:00:00Z"), Map.of());
    static final TemplateRef TEMPLATE = new TemplateRef("velocity", "c", null, TemplateRef.Mode.FULL_DOCUMENT, "{}", Map.of());

    static CredentialConfiguration configuration(String format, Map<String, Object> raw, TemplateRef template) {
        return new CredentialConfiguration(null, "c", "s", format, new FormatConfig.Generic(raw, "k"), template,
                new SigningConfig(KeyRef.parse("keymanager:A"), SignatureAlgorithm.EdDSA, "Ed25519Signature2020", null, null, "did:web:issuer"),
                null, null, StatusConfig.NONE, null, null);
    }

    @Test
    void legacyTemplateNamesMatchCredentialUtils() {
        assertEquals("GoldenCredential,VerifiableCredential::https://www.w3.org/2018/credentials/v1::ldp_vc",
                LegacyTemplateParamsListener.templateName("ldp_vc", Map.of("context", "https://www.w3.org/2018/credentials/v1", "credentialType", "VerifiableCredential,GoldenCredential")));
        assertEquals("dc+sd-jwt::GoldenCredential", LegacyTemplateParamsListener.templateName("vc+sd-jwt", Map.of("vct", "GoldenCredential")));
        assertEquals("mso_mdoc::org.iso.18013.5.1.mDL", LegacyTemplateParamsListener.templateName("mso_mdoc", Map.of("docType", "org.iso.18013.5.1.mDL")));
    }

    @Test
    void legacyModelParametersAreAddedForTemplatedConfigurationsOnly() {
        VelocityEnvConfig env = new VelocityEnvConfig();
        env.setEnvConfigs(Map.of("uin_length", 10));
        LegacyTemplateParamsListener listener = new LegacyTemplateParamsListener(env, new MockEnvironment()
                .withProperty("mosip.certify.data-provider-plugin.did-url", "did:web:issuer")
                .withProperty("mosip.certify.data-provider-plugin.id-field-prefix-uri", "urn:uuid:")
                .withProperty("mosip.certify.data-provider-plugin.vc-expiry-duration", "P365D"));
        ClaimSet claims = new ClaimSet(Map.of("fullName", "x"), Map.of());
        HolderBinding holder = new HolderBinding(HolderBinding.Kind.DID, "did:jwk:abc", null, "jwt");

        ClaimSet ldp = listener.beforeRender(claims, configuration("ldp_vc", Map.of("context", "https://www.w3.org/2018/credentials/v1", "credentialType", "VerifiableCredential,GoldenCredential"), TEMPLATE), CONTEXT, holder);
        assertEquals("GoldenCredential,VerifiableCredential::https://www.w3.org/2018/credentials/v1::ldp_vc", ldp.claims().get("templateName"));
        assertEquals("did:web:issuer", ldp.claims().get("didUrl"));
        assertEquals("did:jwk:abc", ldp.claims().get("_holderId"));
        assertEquals("2026-09-19T10:00:00.000Z", ldp.claims().get("validFrom"));
        assertEquals("2027-09-19T10:00:00.000Z", ldp.claims().get("validUntil"));
        assertTrue(ldp.claims().get("credentialId").toString().startsWith("urn:uuid:"));
        assertEquals(Map.of("uin_length", 10), ldp.claims().get("envConfigs"));
        assertEquals("x", ((Map<?, ?>) ldp.claims().get("rootContext")).get("fullName"));
        assertEquals("x", ldp.claims().get("fullName"));

        ClaimSet sd = listener.beforeRender(claims, configuration("dc+sd-jwt", Map.of("vct", "GoldenCredential"), TEMPLATE), CONTEXT, holder);
        assertEquals("GoldenCredential", sd.claims().get("vct"));
        assertEquals(Map.of("kid", "did:jwk:abc"), sd.claims().get("cnf"));
        assertEquals("http://issuer/v1/certify", sd.claims().get("iss"));

        ClaimSet mdoc = listener.beforeRender(claims, configuration("mso_mdoc", Map.of("docType", "org.iso.18013.5.1.mDL"), TEMPLATE), CONTEXT, holder);
        assertEquals("org.iso.18013.5.1.mDL", mdoc.claims().get("_doctype"));

        assertSame(claims, listener.beforeRender(claims, configuration("ldp_vc", Map.of(), TemplateRef.NONE), CONTEXT, holder), "untemplated configurations are left alone");
    }
}
