package io.mosip.certify.format.sdjwt;

import com.authlete.sd.Disclosure;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatConfig;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningConfig;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.TenantContext;
import io.mosip.certify.spi.UnsignedCredential;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The issuer JWS is verified with Nimbus; the disclosures are matched to the _sd digests with authlete's Disclosure. */
class SdJwtFormatterTest {

    static final JcaKeyProvider KEYS = JcaKeyProvider.devMode();
    static final IssuanceContext CONTEXT = new IssuanceContext(TenantContext.defaultTenant("https://issuer.example/v1/certify", null), null, List.of(),
            ProtocolVersion.OID4VCI_1_0, "c", Instant.parse("2026-09-18T10:00:00Z"), Map.of());
    final SdJwtFormatter formatter = new SdJwtFormatter(new ObjectMapper());

    CredentialConfiguration configuration(String sdClaim) {
        FormatConfig config = formatter.parseConfig(Map.of("vct", "FarmerCredential", "sdClaim", sdClaim));
        return new CredentialConfiguration(null, "farmer-sd", "farmer_vc", "dc+sd-jwt", config, null,
                SigningConfig.of(KeyRef.parse("jca:dev-es256"), SignatureAlgorithm.ES256), null, null, null, null, null);
    }

    SigningContext signing() {
        SigningKey key = KEYS.resolve(KeyRef.parse("jca:dev-es256"));
        return new SigningContext(SigningConfig.of(key.ref(), SignatureAlgorithm.ES256), key, KEYS);
    }

    @Test
    void buildsAVerifiableSdJwtWithDigestsAndDisclosures() throws Exception {
        Map<String, Object> claims = Map.of("fullName", "Golden Farmer", "dateOfBirth", "1990-01-01", "address", Map.of("city", "Bengaluru", "pin", "560001"));
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(claims), configuration("$.fullName,$.address.city"), CONTEXT, HolderBinding.did("did:jwk:abc", "jwt"));
        IssuedCredential issued = formatter.sign(unsigned, signing(), CONTEXT);

        String sdJwt = (String) issued.credential();
        assertTrue(sdJwt.endsWith("~"));
        String[] parts = sdJwt.split("~");
        assertEquals(3, parts.length, "issuer JWS plus two disclosures");
        JWSObject jws = JWSObject.parse(parts[0]);
        assertEquals("dc+sd-jwt", jws.getHeader().getType().getType());
        assertEquals("ES256", jws.getHeader().getAlgorithm().getName());
        assertEquals("dev-es256", jws.getHeader().getKeyID());
        assertNotNull(jws.getHeader().getX509CertChain());
        assertNotNull(jws.getHeader().getX509CertSHA256Thumbprint());
        ECDSAVerifier verifier = new ECDSAVerifier((ECKey) signing().key().descriptor().toJwk());
        verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        assertTrue(jws.verify(verifier), "issuer JWS verifies with Nimbus");

        Map<String, Object> payload = jws.getPayload().toJSONObject();
        assertEquals("FarmerCredential", payload.get("vct"));
        assertEquals("https://issuer.example/v1/certify", payload.get("iss"));
        assertEquals(Map.of("kid", "did:jwk:abc"), payload.get("cnf"));
        assertEquals("1990-01-01", payload.get("dateOfBirth"), "non-SD claim stays in clear");
        assertFalse(payload.containsKey("fullName"), "SD claim removed from the clear payload");
        assertFalse(payload.containsKey("_sd_alg"), "as today: _sd_alg omitted (sha-256 is the default)");
        List<?> topDigests = (List<?>) payload.get("_sd");
        List<?> addressDigests = (List<?>) ((Map<?, ?>) payload.get("address")).get("_sd");
        assertEquals("560001", ((Map<?, ?>) payload.get("address")).get("pin"));
        for (int i = 1; i < parts.length; i++) {
            Disclosure disclosure = Disclosure.parse(parts[i]);
            String digest = disclosure.digest();
            assertTrue(topDigests.contains(digest) || addressDigests.contains(digest), "disclosure " + disclosure.getClaimName() + " has a digest in the payload");
        }
        assertEquals("dc+sd-jwt", issued.format());
    }

    @Test
    void aliasMetadataAndErrors() {
        assertTrue(formatter.handles("vc+sd-jwt") && formatter.handles("dc+sd-jwt"));
        assertEquals(Map.of("format", "dc+sd-jwt", "vct", "FarmerCredential"), formatter.metadataFragment(configuration(""), ProtocolVersion.OID4VCI_1_0));
        FormatException e = assertThrows(FormatException.class, () -> formatter.build(ClaimSet.of(Map.of("fullName", "x")), configuration("$.nope"), CONTEXT, HolderBinding.NONE));
        assertEquals(SdJwtFormatter.ERROR_SD_CLAIMS, e.getErrorCode());
        UnsignedCredential none = formatter.build(ClaimSet.of(Map.of("fullName", "x")), configuration(""), CONTEXT, HolderBinding.NONE);
        assertFalse(none.asMap().containsKey("cnf"), "no holder, no cnf");
        assertFalse(none.asMap().containsKey("_sd"), "no SD paths, no digests");
    }
}
