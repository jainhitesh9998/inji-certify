package io.mosip.certify.signing;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-11a: the COSE header rules a Status List Token for {@code mso_mdoc} needs (draft-ietf-oauth-status-list-21
 * section 5.2; ISO/IEC 18013-5 second edition 12.3.6.3): COSE header 16 ({@code typ}) as the text string
 * {@code application/statuslist+cwt}, {@code x5chain} (label 33) in the <em>protected</em> header, tag 18 and never
 * the CWT tag 61, and claims in RFC 8949 section 4.2.1 order.
 *
 * <p>The invariants this test guards, from docs/design/wp/M-11-status-list-under-iaca.md section 5:
 * <ul>
 *   <li>I2: the mdoc IssuerAuth ({@link CoseHeaderPolicy#mdocIssuerAuth()}) and the claim-169 CWT
 *       ({@link CoseHeaderPolicy#cwt()}) header bytes are byte-identical to what {@code 4f1ebcf1} produced. The
 *       expected hex in {@code *RECORDED} constants was captured by running the untouched code at {@code 4f1ebcf1}
 *       over this same fixture, before a line of this package changed.</li>
 *   <li>I1: the goldens ({@code IssuanceGoldenTest}, {@code IssuanceGoldenCoreTest}, {@code D13GoldenReplayTest})
 *       replay byte for byte; the full suite runs them.</li>
 * </ul>
 *
 * <p>The fixture is fixed: an EC P-256 key and three certificates generated once with OpenSSL (IACA self-signed,
 * an intermediate, and a Document Signer leaf issued by the intermediate), embedded as DER here so every header byte
 * this test compares is reproducible. Only the ECDSA signature itself is random.
 *
 * <p>RFC 8949 section 4.2.1 orders map entries by the bytewise lexicographic order of the encoded keys; the claims and
 * the nested StatusList map are asserted against that order. The status-list header path refuses a signer chain that
 * would be empty or carry a self-signed certificate, while the legacy IssuerAuth path keeps forwarding whatever chain
 * the provider holds — both are asserted here.
 */
class CoseStatusListHeaderTest {

    private static final String STATUS_LIST_MEDIA_TYPE = "application/statuslist+cwt";
    private static final String STATUS_LIST_URI = "https://issuer.example/token-status-list/1";
    private static final byte[] PAYLOAD = "mobile-security-object".getBytes(StandardCharsets.UTF_8);

    // ---- fixture: generated once with OpenSSL 3 (EC P-256, certificates valid 2026-2126) ------------------------

    /** CN=M-11a Test IACA, self-signed, serial 1: the trust anchor. */
    private static final String IACA_DER =
            "MIIBZzCCAQ2gAwIBAgIBATAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9NLTExYSBUZXN0IElBQ0EwIBcNMjYxMTEzMTQ0ODI3WhgPMjEyNjEwMjAxNDQ4MjdaMBoxGDAWBgNVBAMMD00tMTFhIFRlc3QgSUFDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAmjS7Obdj7QJaaAHmtKgW61pBC9cHJoe4X4VfVS4P+Nl2br3m0HQeEbxPJgu4bdNDwwqREfxjks/H/mSbAmIEmjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSa5RywkMPD0kOKd1oanI4SbmSeOTAKBggqhkjOPQQDAgNIADBFAiEAlelvK0anr66uqSeoO8oCMr6vm9wd0wvgHaljaVxBCTcCIGYhZ6S9qchjr5ASpwtnJplyfKNK+5vEDs/txpvy7ajS";

    /** CN=M-11a Test Intermediate, CA, serial 2, issued by the IACA. */
    private static final String INTERMEDIATE_DER =
            "MIIBjzCCATagAwIBAgIBAjAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA9NLTExYSBUZXN0IElBQ0EwIBcNMjYxMTEzMTQ0ODI3WhgPMjEyNjEwMjAxNDQ4MjdaMCIxIDAeBgNVBAMMF00tMTFhIFRlc3QgSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEh/MWpZPqK2pRwSx1mVx90ZDDII2OwuBxYbBUA//jsh+qV+W/+7OOa88IT+fJH64U/NTa9S1kra/slqhG0Hq19KNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0OBBYEFNHmcTllDrwcIwclTqGS+fhnpyp2MB8GA1UdIwQYMBaAFJrlHLCQw8PSQ4p3WhqcjhJuZJ45MAoGCCqGSM49BAMCA0cAMEQCICyvFoLC5gaJC73FwdCggWcuhwSaH0nqWl818sHpJVK1AiB/B1CKo2MgmyEDSVAOm1JY8zBD72YJ4KGa6H8NgIJ8gA==";

    /** CN=M-11a Test Document Signer, serial 3, issued by the intermediate, EKU 1.0.18013.5.1.2. */
    private static final String LEAF_DER =
            "MIIBqzCCAVKgAwIBAgIBAzAKBggqhkjOPQQDAjAiMSAwHgYDVQQDDBdNLTExYSBUZXN0IEludGVybWVkaWF0ZTAgFw0yNjExMTMxNDQ4MjdaGA8yMTI2MTAyMDE0NDgyN1owJTEjMCEGA1UEAwwaTS0xMWEgVGVzdCBEb2N1bWVudCBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQOfFQnsT7gn5ZkbmzmawzaHvRuv8GSSZl7NF1LbB2MVS8YybwxogFNcaqeLBlu6qxQ9Mnn5rhMzkjGWPpMB2dao3QwcjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDASBgNVHSUECzAJBgcogYxdBQECMB0GA1UdDgQWBBSM6U+msypg3Dku5vwBykBRBQYOGjAfBgNVHSMEGDAWgBTR5nE5ZQ68HCMHJU6hkvn4Z6cqdjAKBggqhkjOPQQDAgNHADBEAiB7Cf8E83CKLHpuBQoTECsRXX/Zy2UwW64aEGaR3tUEoQIgW79EwH7lnBLQyynn3MUpFXkNFRnGaGf2Bgy15UpUSco=";

    /** PKCS#8 for the Document Signer key. */
    private static final String LEAF_PRIVATE_KEY_DER =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOF+zCWHqEAlJXAQowWS81d+cLW/0mpQ5YvspaWTsojOhRANCAAQOfFQnsT7gn5ZkbmzmawzaHvRuv8GSSZl7NF1LbB2MVS8YybwxogFNcaqeLBlu6qxQ9Mnn5rhMzkjGWPpMB2da";

    private static final X509Certificate IACA = cert(IACA_DER);
    private static final X509Certificate INTERMEDIATE = cert(INTERMEDIATE_DER);
    private static final X509Certificate LEAF = cert(LEAF_DER);
    private static final PrivateKey PRIVATE_KEY = privateKey(LEAF_PRIVATE_KEY_DER);

    /** {@code [leaf, IACA]}: {@code WITHOUT_ANCHOR} drops the self-signed IACA, so one certificate is emitted. */
    private static final SigningKey ONE_CERT = key(CertificateChain.of(LEAF, IACA));
    /** {@code [leaf, intermediate]}: no self-signed certificate at the top, so both are emitted. */
    private static final SigningKey TWO_CERTS = key(CertificateChain.of(LEAF, INTERMEDIATE));
    /** {@code [leaf, intermediate, IACA]}: the IACA is dropped and the intermediate stays. */
    private static final SigningKey THREE_CERTS = key(CertificateChain.of(LEAF, INTERMEDIATE, IACA));
    /** A key whose chain is just a self-signed certificate. */
    private static final SigningKey SELF_SIGNED = key(CertificateChain.of(IACA));
    /** A key a provider reports without any certificate. */
    private static final SigningKey NO_CHAIN = key(CertificateChain.EMPTY);

    private static final Signer SIGNER = new JcaSigner();

    // ---- I2: recorded at 4f1ebcf1, before this package touched CoseEnvelope -------------------------------------

    /** {@code mdocIssuerAuth()} protected header of {@code 4f1ebcf1}. */
    private static final String MDOC_ISSUERAUTH_PROTECTED_RECORDED = "a10126";

    /** {@code mdocIssuerAuth()} unprotected header of {@code 4f1ebcf1} for {@code [leaf, IACA]}: one {@code bstr}. */
    private static final String MDOC_ISSUERAUTH_UNPROTECTED_RECORDED =
            "a118215901af308201ab30820152a003020102020103300a06082a8648ce3d04030230223120301e06035504030c174d2d313161205465"
            + "737420496e7465726d6564696174653020170d3236313131333134343832375a180f32313236313032303134343832375a302531233021"
            + "06035504030c1a4d2d313161205465737420446f63756d656e74205369676e65723059301306072a8648ce3d020106082a8648ce3d0301"
            + "07034200040e7c5427b13ee09f96646e6ce66b0cda1ef46ebfc19249997b345d4b6c1d8c552f18c9bc31a2014d71aa9e2c196eeaac50f4"
            + "c9e7e6b84cce48c658fa4c07675aa3743072300c0603551d130101ff04023000300e0603551d0f0101ff04040302078030120603551d25"
            + "040b3009060728818c5d050102301d0603551d0e041604148ce94fa6b32a60dc392ee6fc01ca405105060e1a301f0603551d2304183016"
            + "8014d1e67139650ebc1c2307254ea192f9f867a72a76300a06082a8648ce3d040302034700304402207b09ff04f3708a2c7a6e050a1310"
            + "2b115d7fd9cb65305bae1a106691ded504a102205bbf44c07ee59c12d0cb29e7dcc52915790d1519c66867f6060cb5e54a5449ca";

    private static final String MDOC_ISSUERAUTH_UNPROTECTED_WITH_INTERMEDIATE_RECORDED =
            "a11821825901af308201ab30820152a003020102020103300a06082a8648ce3d04030230223120301e06035504030c174d2d3131612054"
            + "65737420496e7465726d6564696174653020170d3236313131333134343832375a180f32313236313032303134343832375a3025312330"
            + "2106035504030c1a4d2d313161205465737420446f63756d656e74205369676e65723059301306072a8648ce3d020106082a8648ce3d03"
            + "0107034200040e7c5427b13ee09f96646e6ce66b0cda1ef46ebfc19249997b345d4b6c1d8c552f18c9bc31a2014d71aa9e2c196eeaac50"
            + "f4c9e7e6b84cce48c658fa4c07675aa3743072300c0603551d130101ff04023000300e0603551d0f0101ff04040302078030120603551d"
            + "25040b3009060728818c5d050102301d0603551d0e041604148ce94fa6b32a60dc392ee6fc01ca405105060e1a301f0603551d23041830"
            + "168014d1e67139650ebc1c2307254ea192f9f867a72a76300a06082a8648ce3d040302034700304402207b09ff04f3708a2c7a6e050a13"
            + "102b115d7fd9cb65305bae1a106691ded504a102205bbf44c07ee59c12d0cb29e7dcc52915790d1519c66867f6060cb5e54a5449ca5901"
            + "933082018f30820136a003020102020102300a06082a8648ce3d040302301a3118301606035504030c0f4d2d3131612054657374204941"
            + "43413020170d3236313131333134343832375a180f32313236313032303134343832375a30223120301e06035504030c174d2d31316120"
            + "5465737420496e7465726d6564696174653059301306072a8648ce3d020106082a8648ce3d0301070342000487f316a593ea2b6a51c12c"
            + "75995c7dd190c3208d8ec2e07161b05403ffe3b21faa57e5bffbb38e6bcf084fe7c91fae14fcd4daf52d64adafec96a846d07ab5f4a363"
            + "3061300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204301d0603551d0e04160414d1e67139650ebc1c23"
            + "07254ea192f9f867a72a76301f0603551d230418301680149ae51cb090c3c3d2438a775a1a9c8e126e649e39300a06082a8648ce3d0403"
            + "02034700304402202caf1682c2e606890bbdc5c1d0a081672e87049a1f49ea5a5f35f2c1e92552b502207f07508aa363209b210349500e"
            + "9b5258f33043ef6609e0a19ae87f0d80827c80";

    /** {@code cwt()} protected header of {@code 4f1ebcf1}: {@code {1: -7, 4: "m11a"}} in the protected header. */
    private static final String CLAIM_169_PROTECTED_RECORDED = "a2012604446d313161";

    /** {@code cwt()} unprotected header of {@code 4f1ebcf1}: empty. */
    private static final String CLAIM_169_UNPROTECTED_RECORDED = "a0";

    /** The claim-169 payload of {@code 4f1ebcf1} for {@code {1: iss, 169: "claim-169"}}. */
    private static final String CLAIM_169_PAYLOAD_RECORDED =
            "a2017668747470733a2f2f6973737565722e6578616d706c6518a969636c61696d2d313639";

    // ---- the Status List Token COSE profile ----------------------------------------------------------------

    @Test
    void statusListCwtIsATaggedSign1WithTheTypAndChainInTheProtectedHeader() throws Exception {
        byte[] token = CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), ONE_CERT, SIGNER);

        // RFC 9052 section 4.2: 0xd2 = tag 18, 0x84 = array(4). Never CWT tag 61 (0xd8 0x3d): TSL section 5.2
        assertEquals((byte) 0xd2, token[0], "a Status List Token is COSE_Sign1_Tagged (18)");
        assertEquals((byte) 0x84, token[1], "and a four-element COSE_Sign1 array");

        CBORObject sign1 = untag(token, CoseEnvelope.TAG_COSE_SIGN1);
        String protectedHex = hex(sign1.get(0).GetByteString());

        String typHex = hex(STATUS_LIST_MEDIA_TYPE.getBytes(StandardCharsets.US_ASCII));
        assertEquals(52, typHex.length(), "\"" + STATUS_LIST_MEDIA_TYPE + "\" is 26 ASCII bytes");
        assertEquals("a3012610781a", protectedHex.substring(0, 12),
                "map(3), 1: -7 (ES256), then 16 (typ) as text(26): a3 01 26 10 78 1a");
        assertEquals(typHex, protectedHex.substring(12, 12 + 52), "16 typ = application/statuslist+cwt (TSL section 5.2)");
        assertEquals("1821", protectedHex.substring(64, 68), "33 (x5chain) follows typ, in RFC 8949 section 4.2.1 order");
        assertEquals("59", protectedHex.substring(68, 70), "one certificate travels as a single bstr (RFC 9360 section 2)");

        CBORObject protectedHeader = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString());
        assertEquals(STATUS_LIST_MEDIA_TYPE, protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_TYP)).AsString());
        assertEquals(16, CoseEnvelope.LABEL_TYP);
        assertEquals(CBORType.ByteString, protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN)).getType(),
                "the chain is integrity protected, and it is the leaf alone: the IACA is the verifier's trust anchor");
        assertArrayEquals(LEAF.getEncoded(),
                protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN)).GetByteString());
        assertNotNull(protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_ALG)));

        assertEquals("a0", hex(sign1.get(1).EncodeToBytes()),
                "unprotected header is empty: no kid (x5chain identifies the key, TSL section 11.3) and no chain");
    }

    @Test
    void aTwoCertificateChainTravelsAsAProtectedArrayOfBstr() throws Exception {
        byte[] token = CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), TWO_CERTS, SIGNER);
        CBORObject sign1 = untag(token, CoseEnvelope.TAG_COSE_SIGN1);
        String protectedHex = hex(sign1.get(0).GetByteString());
        String typHex = hex(STATUS_LIST_MEDIA_TYPE.getBytes(StandardCharsets.US_ASCII));
        assertEquals("a3012610781a" + typHex + "18218259", protectedHex.substring(0, 12 + 52 + 8),
                "an array(2) of bstr follows label 33");

        CBORObject x5chain = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString())
                .get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
        assertEquals(CBORType.Array, x5chain.getType());
        assertEquals(2, x5chain.size());
        assertArrayEquals(LEAF.getEncoded(), x5chain.get(0).GetByteString(), "end-entity first");
        assertArrayEquals(INTERMEDIATE.getEncoded(), x5chain.get(1).GetByteString());
        assertEquals("a0", hex(sign1.get(1).EncodeToBytes()), "the chain does not also travel unprotected");
    }

    @Test
    void signOrderedEncodesTheClaimKeysInTheRfc8949Order() {
        byte[] token = CwtEnvelope.signOrdered(statusListClaims(), CoseHeaderPolicy.statusListCwt(), ONE_CERT, SIGNER);
        CBORObject sign1 = untag(token, CoseEnvelope.TAG_COSE_SIGN1);
        byte[] payload = sign1.get(2).GetByteString();
        String payloadHex = hex(payload);

        assertTrue(payloadHex.startsWith("a502782a"),
                "map(5), 2 (sub) as text(42): the first claim in order, got " + payloadHex.substring(0, 8));
        assertEquals(hex(STATUS_LIST_URI.getBytes(StandardCharsets.US_ASCII)), payloadHex.substring(8, 8 + 84));

        int exp = payloadHex.indexOf("041a");
        int iat = payloadHex.indexOf("061a");
        int statusList = payloadHex.lastIndexOf("19fffd");
        int ttl = payloadHex.lastIndexOf("19fffe");
        assertTrue(0 < exp && exp < iat && iat < statusList && statusList < ttl,
                "claims 2, 4, 6, 65533, 65534 encode in that order, got " + payloadHex);

        List<Integer> keys = new ArrayList<>();
        for (CBORObject key : CBORObject.DecodeFromBytes(payload).getKeys()) {
            keys.add(key.AsInt32());
        }
        assertEquals(List.of(2, 4, 6, 65533, 65534), keys);

        // the nested StatusList map follows section 4.2.1 too: a2, "lst" -> bstr(2) b9a3, "bits" -> 1
        assertTrue(payloadHex.contains("19fffd" + "a2636c7374" + "42b9a3" + "6462697473" + "01"),
                "65533 encodes {lst: h'b9a3', bits: 1} with lst first, got " + payloadHex);
        List<String> statusListKeys = new ArrayList<>();
        CBORObject.DecodeFromBytes(payload).get(CBORObject.FromObject(65533)).getKeys()
                .forEach(key -> statusListKeys.add(key.AsString()));
        assertEquals(List.of("lst", "bits"), statusListKeys);
    }

    @Test
    void signOrderedNeverWrapsTheTokenInTheCwtTag() {
        for (CoseHeaderPolicy policy : List.of(CoseHeaderPolicy.statusListCwt(), CoseHeaderPolicy.cwt())) {
            String tokenHex = hex(CwtEnvelope.signOrdered(statusListClaims(), policy, ONE_CERT, SIGNER));
            assertFalse(tokenHex.startsWith("d83d"), "tag 61 is forbidden for a Status List Token (TSL section 5.2): "
                    + tokenHex.substring(0, 8));
        }
        CBORObject token = CBORObject.DecodeFromBytes(CwtEnvelope.signOrdered(statusListClaims(),
                CoseHeaderPolicy.statusListCwt(), ONE_CERT, SIGNER));
        assertTrue(token.isTagged());
        assertEquals(String.valueOf(CoseEnvelope.TAG_COSE_SIGN1), token.getMostOuterTag().toString(),
                "the only tag is 18");
    }

    @Test
    void theSignatureVerifiesWithPlainJca() throws Exception {
        CBORObject sign1 = untag(CwtEnvelope.signOrdered(statusListClaims(), CoseHeaderPolicy.statusListCwt(),
                ONE_CERT, SIGNER), CoseEnvelope.TAG_COSE_SIGN1);
        byte[] protectedBytes = sign1.get(0).GetByteString();
        byte[] signature = sign1.get(3).GetByteString();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(LEAF.getPublicKey());
        verifier.update(CoseEnvelope.sigStructure(protectedBytes, new byte[0], sign1.get(2).GetByteString()));
        assertTrue(verifier.verify(ECDSA.transcodeSignatureToDER(signature)),
                "SHA256withECDSA over Sig_structure, R||S converted to DER");
    }

    @Test
    void theSignatureVerifiesWithAuthleteCose() throws Exception {
        // the production shape: the DSC alone under the IACA, one certificate as a single bstr (RFC 9360 section 2)
        byte[] token = CwtEnvelope.signOrdered(statusListClaims(), CoseHeaderPolicy.statusListCwt(), ONE_CERT, SIGNER);
        CBORItem item = new CBORDecoder(token).next();
        assertTrue(item instanceof CBORTaggedItem);
        CBORTaggedItem tagged = (CBORTaggedItem) item;
        assertEquals(18L, tagged.getTagNumber().longValue());
        COSESign1 coseSign1 = COSESign1.build(tagged.getTagContent());
        assertEquals(STATUS_LIST_MEDIA_TYPE, coseSign1.getProtectedHeader().getParameters().get(CoseEnvelope.LABEL_TYP),
                "Authlete reads typ (16) as the media type; its getContentType() is the deprecated label 3");
        assertEquals(List.of(LEAF), coseSign1.getProtectedHeader().getX5Chain(),
                "Authlete reads a one-certificate protected x5chain as [leaf], end-entity first");
        assertTrue(new COSEVerifier(LEAF.getPublicKey()).verify(coseSign1),
                "a second, independent COSE implementation accepts the signature and the protected chain");

        // and the array form, which a signer with an intermediate emits
        byte[] twoCertificates = CwtEnvelope.signOrdered(statusListClaims(), CoseHeaderPolicy.statusListCwt(),
                THREE_CERTS, SIGNER);
        COSESign1 withIntermediate = COSESign1.build(((CBORTaggedItem) new CBORDecoder(twoCertificates).next()).getTagContent());
        assertEquals(List.of(LEAF, INTERMEDIATE), withIntermediate.getProtectedHeader().getX5Chain());
        assertTrue(new COSEVerifier(LEAF.getPublicKey()).verify(withIntermediate));
    }

    // ---- I2: what mDoc IssuerAuth and claim 169 emit must not move ----------------------------------------------

    @Test
    void mdocIssuerAuthHeaderBytesAreIdenticalTo4f1ebcf1() {
        CBORObject sign1 = untag(CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.mdocIssuerAuth(), ONE_CERT, SIGNER),
                CoseEnvelope.TAG_COSE_SIGN1);
        assertEquals(MDOC_ISSUERAUTH_PROTECTED_RECORDED, hex(sign1.get(0).GetByteString()),
                "I2: mdocIssuerAuth protected header {1: -7} is unchanged");
        assertEquals(MDOC_ISSUERAUTH_UNPROTECTED_RECORDED, hex(sign1.get(1).EncodeToBytes()),
                "I2: mdocIssuerAuth keeps x5chain (33) in the unprotected header, unchanged");
        assertFalse(CBORObject.DecodeFromBytes(sign1.get(0).GetByteString())
                        .ContainsKey(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN)),
                "nothing moved into the protected header on the mdoc path");
    }

    @Test
    void mdocIssuerAuthWithAnIntermediateHeaderBytesAreIdenticalTo4f1ebcf1() {
        CBORObject sign1 = untag(CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.mdocIssuerAuth(), TWO_CERTS, SIGNER),
                CoseEnvelope.TAG_COSE_SIGN1);
        assertEquals(MDOC_ISSUERAUTH_PROTECTED_RECORDED, hex(sign1.get(0).GetByteString()));
        assertEquals(MDOC_ISSUERAUTH_UNPROTECTED_WITH_INTERMEDIATE_RECORDED, hex(sign1.get(1).EncodeToBytes()),
                "I2: the array form of x5chain in the unprotected header is unchanged");
    }

    @Test
    void claim169CwtHeaderBytesAreIdenticalTo4f1ebcf1() {
        LinkedHashMap<Integer, Object> claims = new LinkedHashMap<>();
        claims.put(1, "https://issuer.example");
        claims.put(169, "claim-169");
        CBORObject outer = CBORObject.DecodeFromBytes(CwtEnvelope.sign(claims, CoseHeaderPolicy.cwt(), ONE_CERT, SIGNER, true));
        assertTrue(outer.isTagged());
        assertEquals(String.valueOf(CwtEnvelope.TAG_CWT), outer.getMostOuterTag().toString(), "claim 169 keeps CWT tag 61");
        CBORObject sign1 = untag(outer.UntagOne().EncodeToBytes(), CoseEnvelope.TAG_COSE_SIGN1);
        assertEquals(CLAIM_169_PROTECTED_RECORDED, hex(sign1.get(0).GetByteString()),
                "I2: the claim-169 protected header [alg, kid] is unchanged");
        assertEquals(CLAIM_169_UNPROTECTED_RECORDED, hex(sign1.get(1).EncodeToBytes()),
                "I2: no unprotected header on claim 169");
        assertEquals(CLAIM_169_PAYLOAD_RECORDED, hex(sign1.get(2).GetByteString()), "I2: the claim map is unchanged");
    }

    // ---- negative and adversarial ---------------------------------------------------------------------------

    @Test
    void aProtectedChainWithoutAChainPolicyIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.NONE,
                null, true, false, STATUS_LIST_MEDIA_TYPE, true));
        assertThrows(IllegalArgumentException.class, () -> new CoseHeaderPolicy(null,
                null, true, false, STATUS_LIST_MEDIA_TYPE, true));
        assertThrows(IllegalArgumentException.class, () -> new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.NONE,
                null, true, false, null, true));
        // the legacy header shapes keep working with NONE
        assertNotNull(new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.NONE, null, true, true));
        assertNotNull(new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.NONE, null, true, true, null, false));
    }

    @Test
    void aTypNeedsTheProtectedChain() {
        // draft-ietf-oauth-status-list-21 section 5.2 pairs the protected typ with the protected x5chain: a token that
        // names its type and leaves the chain unprotected would be identified as a Status List Token and fail the
        // header rules applied to it, so the policy is refused instead of silently encoding 33 protected while the
        // caller asked for the opposite
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class, () -> new CoseHeaderPolicy(
                JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR, null, true, false, STATUS_LIST_MEDIA_TYPE, false));
        assertTrue(refused.getMessage().contains("protected header"), refused.getMessage());
        assertTrue(new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR, null, true, false,
                STATUS_LIST_MEDIA_TYPE, true).x5chainInProtected(), "the same policy with the chain protected is accepted");
    }

    @Test
    void aTypThatIsNotAMediaTypeIsRefused() {
        for (String typ : List.of("statuslist+cwt", "a b/c", "", "application/status list", "application/",
                "/statuslist+cwt", "application/statuslist+cwt;foo=bar")) {
            assertThrows(IllegalArgumentException.class, () -> new CoseHeaderPolicy(
                    JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR, null, true, false, typ, true), typ);
        }
        for (String typ : List.of("application/statuslist+cwt", "application/statuslist+jwt", "application/vnd.a-b_c.d+e")) {
            assertEquals(typ, new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR, null, true, false, typ, true).typ());
        }
    }

    @Test
    void aStatusListTokenRefusesAKeyWithoutAChain() {
        SigningException refused = assertThrows(SigningException.class,
                () -> CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), NO_CHAIN, SIGNER));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_NO_CHAIN: "), refused.getMessage());
        // the same token under a signer with a certificate is issued: the refusal is about the missing chain only
        assertNotNull(CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), ONE_CERT, SIGNER));
    }

    @Test
    void aStatusListTokenRefusesASelfSignedSigner() {
        // CertificateChain.withoutAnchor() keeps a lone self-signed certificate; the Status List Token header path must
        // refuse it rather than carry the signer's own trust anchor (the verifier supplies the IACA, ISO2 12.3.6.2)
        SigningException refused = assertThrows(SigningException.class,
                () -> CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), SELF_SIGNED, SIGNER));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_SELF_SIGNED: "), refused.getMessage());
        assertTrue(refused.getMessage().contains("CN=M-11a Test IACA"), refused.getMessage());

    }

    @Test
    void aStatusListTokenRefusesAChainThatCarriesItsAnchor() {
        // FULL emits [leaf, intermediate, IACA]: the self-signed certificate is further up, not the leaf, so this is the
        // CARRIES_ANCHOR rule of the plan's section 4.7, not SELF_SIGNED
        CoseHeaderPolicy full = new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.FULL, null, true, false,
                STATUS_LIST_MEDIA_TYPE, true);
        SigningException refused = assertThrows(SigningException.class,
                () -> CoseEnvelope.sign1(PAYLOAD, full, THREE_CERTS, SIGNER));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_CARRIES_ANCHOR: "), refused.getMessage());
        assertTrue(refused.getMessage().contains("CN=M-11a Test IACA"), refused.getMessage());
    }

    @Test
    void aLeafPolicyInspectsAndEmitsOnlyTheEndEntity() throws Exception {
        // x5chain leaf under [leaf, IACA] emits the DSC alone; the IACA the provider also holds is never inspected, so
        // the token is not refused for a certificate it does not carry
        CoseHeaderPolicy leaf = new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.LEAF, null, true, false,
                STATUS_LIST_MEDIA_TYPE, true);
        CBORObject sign1 = untag(CoseEnvelope.sign1(PAYLOAD, leaf, ONE_CERT, SIGNER), CoseEnvelope.TAG_COSE_SIGN1);
        CBORObject x5chain = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString())
                .get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
        assertEquals(CBORType.ByteString, x5chain.getType());
        assertArrayEquals(LEAF.getEncoded(), x5chain.GetByteString());
        assertEquals("a0", hex(sign1.get(1).EncodeToBytes()));
    }

    @Test
    void theRefusalsRunBeforeAProviderThatBuildsTheEnvelopeItself() {
        // a provider overriding Signer.signCose builds the whole COSE_Sign1 and would otherwise skip the chain rules
        Signer nativeSigner = new Signer() {
            @Override
            public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
                throw new AssertionError("signRaw must not be reached: the provider builds the envelope");
            }

            @Override
            public Optional<byte[]> signCose(Signer.CoseInput input, SigningKey key) {
                return Optional.of(new byte[]{(byte) 0xd2, (byte) 0x80});
            }
        };
        SigningException noChain = assertThrows(SigningException.class,
                () -> CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), NO_CHAIN, nativeSigner));
        assertTrue(noChain.getMessage().startsWith("STATUS_SIGNER_NO_CHAIN: "), noChain.getMessage());
        SigningException selfSigned = assertThrows(SigningException.class,
                () -> CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), SELF_SIGNED, nativeSigner));
        assertTrue(selfSigned.getMessage().startsWith("STATUS_SIGNER_SELF_SIGNED: "), selfSigned.getMessage());

        // a usable chain reaches the provider untouched
        assertArrayEquals(new byte[]{(byte) 0xd2, (byte) 0x80},
                CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), ONE_CERT, nativeSigner));
        // and the legacy paths never consult the protected form, so their handling of a provider is unchanged (I2)
        assertArrayEquals(new byte[]{(byte) 0xd2, (byte) 0x80},
                CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.mdocIssuerAuth(), SELF_SIGNED, nativeSigner));
        assertArrayEquals(new byte[]{(byte) 0xd2, (byte) 0x80},
                CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.mdocIssuerAuth(), NO_CHAIN, nativeSigner));
    }

    @Test
    void theProtectedChainIsTheSignerChainWithoutTheAnchor() throws Exception {
        // [leaf, IACA] -> the leaf alone: withoutAnchor() drops the self-signed trust anchor
        CBORObject sign1 = untag(CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), ONE_CERT, SIGNER),
                CoseEnvelope.TAG_COSE_SIGN1);
        CBORObject x5chain = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString())
                .get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
        assertEquals(CBORType.ByteString, x5chain.getType());
        assertArrayEquals(LEAF.getEncoded(), x5chain.GetByteString());
        assertFalse(hex(x5chain.GetByteString()).contains(hex(IACA.getEncoded())), "the IACA is absent");

        // [leaf, intermediate, IACA] -> [leaf, intermediate], end-entity first
        CBORObject withIntermediate = untag(
                CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.statusListCwt(), THREE_CERTS, SIGNER),
                CoseEnvelope.TAG_COSE_SIGN1);
        CBORObject chain = CBORObject.DecodeFromBytes(withIntermediate.get(0).GetByteString())
                .get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
        assertEquals(CBORType.Array, chain.getType());
        assertEquals(2, chain.size());
        assertArrayEquals(LEAF.getEncoded(), chain.get(0).GetByteString());
        assertArrayEquals(INTERMEDIATE.getEncoded(), chain.get(1).GetByteString());
    }

    @Test
    void theLegacyIssuerAuthStillKeepsALoneSelfSignedCertificate() throws Exception {
        // the refusal above is scoped to the protected status-list form: the mdoc IssuerAuth and the claim-169 CWT
        // paths are untouched (I2), including for a lone self-signed certificate, where withoutAnchor() keeps it
        CBORObject sign1 = untag(CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.mdocIssuerAuth(), SELF_SIGNED, SIGNER),
                CoseEnvelope.TAG_COSE_SIGN1);
        CBORObject x5chain = sign1.get(1).get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
        assertEquals(CBORType.ByteString, x5chain.getType());
        assertArrayEquals(IACA.getEncoded(), x5chain.GetByteString());
        assertEquals(MDOC_ISSUERAUTH_PROTECTED_RECORDED, hex(sign1.get(0).GetByteString()),
                "and the protected header is still {1: -7} alone");

        CBORObject withoutChain = untag(
                CoseEnvelope.sign1(PAYLOAD, CoseHeaderPolicy.mdocIssuerAuth(), NO_CHAIN, SIGNER),
                CoseEnvelope.TAG_COSE_SIGN1);
        assertEquals("a0", hex(withoutChain.get(1).EncodeToBytes()), "a key without a certificate still emits no x5chain");
    }

    @Test
    void signOrderedRefusesClaimsOutOfRfc8949Order() {
        LinkedHashMap<Integer, CBORObject> reversed = new LinkedHashMap<>();
        reversed.put(4, CBORObject.FromObject(1767225600L));
        reversed.put(2, CBORObject.FromObject(STATUS_LIST_URI));
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> CwtEnvelope.signOrdered(reversed, CoseHeaderPolicy.statusListCwt(), ONE_CERT, SIGNER));
        assertTrue(refused.getMessage().contains("bytewise lexicographic"), refused.getMessage());

        // 65533 and 65534 encode as 19 fffd and 19 fffe: reversing them breaks the same rule
        LinkedHashMap<Integer, CBORObject> tail = new LinkedHashMap<>();
        tail.put(2, CBORObject.FromObject(STATUS_LIST_URI));
        tail.put(4, CBORObject.FromObject(1767225600L));
        tail.put(6, CBORObject.FromObject(1767139200L));
        tail.put(65534, CBORObject.FromObject(3600));
        tail.put(65533, CBORObject.NewOrderedMap()
                .Add("lst", CBORObject.FromObject(new byte[]{(byte) 0xb9, (byte) 0xa3}))
                .Add("bits", CBORObject.FromObject(1)));
        assertThrows(IllegalArgumentException.class,
                () -> CwtEnvelope.signOrdered(tail, CoseHeaderPolicy.statusListCwt(), ONE_CERT, SIGNER));
    }

    @Test
    void signOrderedRefusesAnUntaggedStatusListPolicy() {
        CoseHeaderPolicy untagged = new CoseHeaderPolicy(JwsHeaderPolicy.ChainInclusion.WITHOUT_ANCHOR, null, false,
                false, STATUS_LIST_MEDIA_TYPE, true);
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> CwtEnvelope.signOrdered(statusListClaims(), untagged, ONE_CERT, SIGNER));
        assertTrue(refused.getMessage().contains("never untagged"), refused.getMessage());
    }

    // ---- helpers ---------------------------------------------------------------------------------------------

    private static LinkedHashMap<Integer, CBORObject> statusListClaims() {
        LinkedHashMap<Integer, CBORObject> claims = new LinkedHashMap<>();
        claims.put(2, CBORObject.FromObject(STATUS_LIST_URI));
        claims.put(4, CBORObject.FromObject(1767225600L));
        claims.put(6, CBORObject.FromObject(1767139200L));
        // RFC 8949 section 4.2.1: "lst" (63 6c 73 74) sorts before "bits" (64 62 69 74 73), bytewise lexicographic
        claims.put(65533, CBORObject.NewOrderedMap()
                .Add("lst", CBORObject.FromObject(new byte[]{(byte) 0xb9, (byte) 0xa3}))
                .Add("bits", CBORObject.FromObject(1)));
        claims.put(65534, CBORObject.FromObject(3600));
        return claims;
    }

    /** The COSE_Sign1 of a token, with an optional outer tag checked and removed (RFC 9052 section 4.2). */
    private static CBORObject untag(byte[] token, int expectedTag) {
        CBORObject outer = CBORObject.DecodeFromBytes(token);
        if (outer.isTagged()) {
            assertEquals(String.valueOf(expectedTag), outer.getMostOuterTag().toString());
            outer = outer.UntagOne();
        }
        assertEquals(CBORType.Array, outer.getType());
        assertEquals(4, outer.size());
        return outer;
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private static X509Certificate cert(String base64Der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64Der)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static PrivateKey privateKey(String base64Der) {
        try {
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64Der)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static SigningKey key(CertificateChain chain) {
        return new SigningKey(KeyRef.parse("x509-file:m11a-dsc"),
                new PublicKeyDescriptor("m11a", SignatureAlgorithm.ES256, LEAF.getPublicKey(), chain, null, null, "mdoc-dsc"),
                PRIVATE_KEY);
    }

    /** Signs through plain JCA with the fixture key, in the R||S wire form a key provider returns. */
    private static final class JcaSigner implements Signer {

        @Override
        public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
            try {
                Signature signature = Signature.getInstance(algorithm.jcaName());
                signature.initSign(PRIVATE_KEY);
                signature.update(data);
                return ECDSA.transcodeSignatureToConcat(signature.sign(), algorithm.concatLength());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
