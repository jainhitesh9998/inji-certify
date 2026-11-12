package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.ProtocolVersion;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.UnsignedCredential;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import io.mosip.certify.signing.CoseHeaderPolicy;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.spi.SigningConfig;

import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The IssuerAuth is verified with plain JCA against the x5chain leaf; the MSO is decoded with the CBOR library. */
class MdocFormatterTest {

    static final IssuanceContext CONTEXT = MdlFixtures.context();
    static final String HOLDER = MdlFixtures.HOLDER;

    final MdocFormatter formatter = new MdocFormatter(new ObjectMapper(), MdlFixtures.properties(Duration.ofDays(90)));

    SigningContext signing() {
        return MdlFixtures.signing(MdlFixtures.dsc());
    }

    CredentialConfiguration configuration() {
        return MdlFixtures.configuration(formatter);
    }

    @Test
    void issuerSignedVerifiesWithJcaAndCarriesTheHolderKey() throws Exception {
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(MdlFixtures.mdl()), configuration(), CONTEXT, HolderBinding.did(HOLDER, "jwt"));
        IssuedCredential issued = formatter.sign(unsigned, signing(), CONTEXT);

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode((String) issued.credential()));
        CBORObject items = issuerSigned.get("nameSpaces").get(MdlFixtures.MDL_NAMESPACE);
        assertEquals(12, items.size());
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        assertEquals(4, issuerAuth.size());
        assertFalse(issuerAuth.isTagged());
        byte[] protectedBytes = issuerAuth.get(0).GetByteString();
        assertEquals(-7, CBORObject.DecodeFromBytes(protectedBytes).get(CBORObject.FromObject(1)).AsInt32());
        CBORObject x5chain = issuerAuth.get(1).get(CBORObject.FromObject(33));
        byte[] leafDer = x5chain.getType() == CBORType.Array ? x5chain.get(0).GetByteString() : x5chain.GetByteString();
        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(leafDer));
        byte[] payload = issuerAuth.get(2).GetByteString();
        byte[] sigStructure = CBORObject.NewArray().Add("Signature1").Add(protectedBytes).Add(new byte[0]).Add(payload).EncodeToBytes();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(leaf.getPublicKey());
        verifier.update(sigStructure);
        assertTrue(verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(issuerAuth.get(3).GetByteString())), "IssuerAuth verifies with JCA");

        CBORObject msoWrapped = CBORObject.DecodeFromBytes(payload);
        CBORObject mso = msoWrapped.HasMostOuterTag(24) ? CBORObject.DecodeFromBytes(msoWrapped.Untag().GetByteString()) : msoWrapped;
        assertEquals("org.iso.18013.5.1.mDL", mso.get("docType").AsString());
        assertEquals("1.0", mso.get("version").AsString());
        assertEquals("SHA-256", mso.get("digestAlgorithm").AsString());
        assertEquals(12, mso.get("valueDigests").get(MdlFixtures.MDL_NAMESPACE).size());
        CBORObject deviceKey = mso.get("deviceKeyInfo").get("deviceKey");
        assertEquals(2, deviceKey.get(CBORObject.FromObject(1)).AsInt32());
        assertArrayEquals(Base64.getUrlDecoder().decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), deviceKey.get(CBORObject.FromObject(-2)).GetByteString());
        for (String field : List.of("signed", "validFrom", "validUntil")) {
            assertTrue(mso.get("validityInfo").ContainsKey(field));
        }
        assertEquals("org.iso.18013.5.1.mDL", issued.attributes().get("docType"));
        assertEquals("mso_mdoc", issued.format());
    }

    @Test
    void metadataAndTemplateErrors() {
        assertEquals("org.iso.18013.5.1.mDL", formatter.metadataFragment(configuration(), ProtocolVersion.OID4VCI_1_0).get("doctype"));
        assertEquals("mso_mdoc", formatter.metadataFragment(configuration(), ProtocolVersion.OID4VCI_1_0).get("format"));
        FormatException e = assertThrows(FormatException.class, () -> formatter.build(ClaimSet.of(Map.of("docType", "x")), configuration(), CONTEXT, HolderBinding.did(HOLDER, "jwt")));
        assertEquals(MdocConstants.ERROR_TEMPLATE, e.getErrorCode(), "the template's docType differs from the configuration's");
        assertThrows(FormatException.class, () -> formatter.build(ClaimSet.of(MdlFixtures.mdl()), configuration(), CONTEXT, HolderBinding.NONE), "the device key needs a holder");
    }

    @Test
    void aConfigurationWithoutADoctypeIsATemplateError() {
        CredentialConfiguration configuration = new CredentialConfiguration(null, "mdl", "mdl_scope", MdocFormatter.FORMAT,
                formatter.parseConfig(Map.of()), null, signing().config(), null, null, null, null, null);
        FormatException e = assertThrows(FormatException.class, () -> formatter.build(ClaimSet.of(MdlFixtures.mdl()),
                configuration, CONTEXT, HolderBinding.did(HOLDER, "jwt")));
        assertEquals(MdocConstants.ERROR_TEMPLATE, e.getErrorCode());
    }

    @Test
    void anExplicitMsoValidityWinsOverTheLegacyPeriod() {
        // decision D7: mso-validity first, the deprecated validity-period-years only as a fallback, otherwise P90D
        assertEquals(Duration.ofDays(90), new MdocProperties("SHA-256", "1.0", Duration.ofDays(90), 2).validity());
        assertEquals(Duration.ofDays(730), new MdocProperties("SHA-256", "1.0", null, 2).validity());
        assertEquals(Duration.ofDays(90), new MdocProperties("SHA-256", "1.0", null, null).validity(),
                "the P90D default is applied in validity(), not by the binder");
    }

    @Test
    void invalidMsoSettingsAreRefusedAtStartup() {
        // ISO/IEC 18013-5 9.1.2.4 defines only MSO version 1.0
        assertThrows(IllegalArgumentException.class, () -> new MdocProperties("SHA-256", "2.0", null, null));
        assertThrows(IllegalArgumentException.class, () -> new MdocProperties("SHA-256", "1.0", Duration.ZERO, null));
        assertThrows(IllegalArgumentException.class, () -> new MdocProperties("SHA-256", "1.0", Duration.ofDays(-1), null));
        assertThrows(IllegalArgumentException.class, () -> new MdocProperties("SHA-256", "1.0", null, 0));
    }

    @Test
    void validityNeverPrecedesTheSigningInstant() {
        Instant signed = Instant.parse("2024-01-01T00:00:00Z");
        FormatException expired = assertThrows(FormatException.class,
                () -> MdocProcessor.validityInfo(signed, Duration.ofDays(90), Instant.parse("2023-12-31T23:59:59Z")));
        assertEquals("certificate_chain_invalid", expired.getErrorCode(),
                "a DSC that expired before the signing instant is a chain fault, refused before the later checks");
    }

    @Test
    void aFullX5chainCannotCarryASelfSignedAnchor() {
        SigningContext full = new SigningContext(new SigningConfig(MdlFixtures.dsc().ref(), MdlFixtures.dsc().algorithm(), null, null,
                new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.FULL, null, false), null), MdlFixtures.dsc(), MdlFixtures.KEYS);
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(MdlFixtures.mdl()), configuration(), CONTEXT,
                HolderBinding.did(HOLDER, "jwt"));
        FormatException refused = assertThrows(FormatException.class, () -> formatter.sign(unsigned, full, CONTEXT));
        assertEquals("certificate_chain_invalid", refused.getErrorCode());
        assertTrue(refused.getMessage().contains("self-signed"), refused.getMessage());
    }
}
