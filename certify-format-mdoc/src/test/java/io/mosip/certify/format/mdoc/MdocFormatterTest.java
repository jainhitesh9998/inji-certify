package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import io.mosip.certify.keyprovider.jca.JcaKeyProvider;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
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

import java.io.ByteArrayInputStream;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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

    static final JcaKeyProvider KEYS = JcaKeyProvider.devMode();
    static final IssuanceContext CONTEXT = new IssuanceContext(TenantContext.DEFAULT, null, List.of(), ProtocolVersion.OID4VCI_1_0, "c",
            Instant.now() /* the dev certificates are valid from two days before the run */, Map.of());
    // the holder key as the proof carries it: did:jwk of a P-256 public JWK
    static final String HOLDER_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
    static final String HOLDER = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(HOLDER_JWK.getBytes());

    final MdocFormatter formatter = new MdocFormatter(new ObjectMapper(), new MdocProperties("SHA-256", "1.0", 2));

    static Map<String, Object> document() {
        return Map.of("docType", "org.iso.18013.5.1.mDL",
                "validityInfo", Map.of("validFrom", "${_validFrom}", "validUntil", "${_validUntil}", "signed", "${_signed}"),
                "nameSpaces", Map.of("org.iso.18013.5.1", List.of(
                        Map.of("digestID", 0, "elementIdentifier", "family_name", "elementValue", "Farmer"),
                        Map.of("digestID", 1, "elementIdentifier", "birth_date", "elementValue", "1990-01-01"))));
    }

    SigningContext signing() {
        SigningKey key = KEYS.resolve(KeyRef.parse("jca:dev-es256"));
        return new SigningContext(new SigningConfig(key.ref(), SignatureAlgorithm.ES256, null, null, null, "did:web:issuer.example"), key, KEYS);
    }

    CredentialConfiguration configuration() {
        return new CredentialConfiguration(null, "mdl", "mdl_scope", "mso_mdoc", formatter.parseConfig(Map.of("docType", "org.iso.18013.5.1.mDL")), null,
                signing().config(), null, null, null, null, null);
    }

    @Test
    void issuerSignedVerifiesWithJcaAndCarriesTheHolderKey() throws Exception {
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(document()), configuration(), CONTEXT, HolderBinding.did(HOLDER, "jwt"));
        IssuedCredential issued = formatter.sign(unsigned, signing(), CONTEXT);

        CBORObject issuerSigned = CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode((String) issued.credential()));
        CBORObject items = issuerSigned.get("nameSpaces").get("org.iso.18013.5.1");
        assertEquals(2, items.size());
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
        assertEquals(2, mso.get("valueDigests").get("org.iso.18013.5.1").size());
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
        assertEquals(MdocConstants.ERROR_TEMPLATE, e.getErrorCode(), "validityInfo is mandatory");
        assertThrows(FormatException.class, () -> formatter.build(ClaimSet.of(document()), configuration(), CONTEXT, HolderBinding.NONE), "the device key needs a holder");
    }
}
