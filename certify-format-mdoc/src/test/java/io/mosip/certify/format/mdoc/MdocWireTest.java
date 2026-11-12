package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.UnsignedCredential;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Byte-level checks of the ISO/IEC 18013-5 wire the mDoc formatter produces: {@code tdate} tag 0 with 20 characters
 * (9.1.2.4), the tag-24 MSO wrapper, the declared digest algorithm and per-namespace digest identifiers (9.1.2.5),
 * Table 5 element types (7.2.1), the device key COSE_Key (9.1.2.4, 9.1.5.2) and the x5chain without trust anchor.
 */
class MdocWireTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private MdocFormatter formatter() {
        return formatter(MdlFixtures.properties(Duration.ofDays(90)));
    }

    private MdocFormatter formatter(MdocProperties properties) {
        return new MdocFormatter(MAPPER, properties);
    }

    private IssuedCredential issue(MdocFormatter formatter, Map<String, Object> document, SigningContext signing) {
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(document), MdlFixtures.configuration(formatter),
                MdlFixtures.context(), MdlFixtures.holder());
        return formatter.sign(unsigned, signing, MdlFixtures.context());
    }

    private String issue(Map<String, Object> document) {
        return (String) issue(formatter(), document, MdlFixtures.signing(MdlFixtures.dsc())).credential();
    }

    private static CBORObject issuerSigned(String credential) {
        return CBORObject.DecodeFromBytes(Base64.getUrlDecoder().decode(credential));
    }

    private static CBORObject payload(CBORObject issuerSigned) {
        return CBORObject.DecodeFromBytes(issuerSigned.get("issuerAuth").get(2).GetByteString());
    }

    private static CBORObject mso(CBORObject issuerSigned) {
        CBORObject payload = payload(issuerSigned);
        assertTrue(payload.HasMostOuterTag(24), "the MSO payload is wrapped in tag 24");
        return CBORObject.DecodeFromBytes(payload.Untag().GetByteString());
    }

    /** {@code digestID -> decoded IssuerSignedItem} for a namespace, plus the tag-24 bytes each digest covers. */
    private static Map<Integer, CBORObject> itemsById(CBORObject issuerSigned, String namespace) {
        Map<Integer, CBORObject> items = new LinkedHashMap<>();
        CBORObject array = issuerSigned.get("nameSpaces").get(namespace);
        for (int i = 0; i < array.size(); i++) {
            CBORObject tagged = array.get(i);
            assertTrue(tagged.HasMostOuterTag(24), "IssuerSignedItem must be #6.24(bstr .cbor)");
            CBORObject item = CBORObject.DecodeFromBytes(tagged.Untag().GetByteString());
            items.put(item.get("digestID").AsInt32(), item);
        }
        return items;
    }

    private static Map<Integer, byte[]> tag24Bytes(CBORObject issuerSigned, String namespace) {
        Map<Integer, byte[]> out = new LinkedHashMap<>();
        CBORObject array = issuerSigned.get("nameSpaces").get(namespace);
        for (int i = 0; i < array.size(); i++) {
            CBORObject tagged = array.get(i);
            CBORObject item = CBORObject.DecodeFromBytes(tagged.Untag().GetByteString());
            out.put(item.get("digestID").AsInt32(), tagged.EncodeToBytes());
        }
        return out;
    }

    @Test
    void validityInfoIsSecondsOnlyTdateTaggedZero() {
        CBORObject mso = mso(issuerSigned(issue(MdlFixtures.mdl())));
        CBORObject validityInfo = mso.get("validityInfo");
        CBORObject signed = validityInfo.get("signed");
        assertTrue(signed.HasMostOuterTag(0), "tdate is #6.0(tstr)");
        String text = signed.Untag().AsString();
        assertEquals(20, text.length(), "RFC 3339 without fractional seconds is 20 characters: " + text);
        assertTrue(text.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z"), text);
        assertEquals(MdlFixtures.tdate(MdlFixtures.NOW), text, "the formatter context's clock, truncated to seconds");
        assertTrue(validityInfo.get("validFrom").HasMostOuterTag(0));
        assertEquals(text, validityInfo.get("validFrom").Untag().AsString(), "validFrom is the signing instant");
        assertEquals(MdlFixtures.tdate(MdlFixtures.NOW.plus(Duration.ofDays(90))), validityInfo.get("validUntil").Untag().AsString(),
                "signed + 90 days (P90D)");
        assertNotEquals(text, validityInfo.get("validUntil").Untag().AsString());
    }

    @Test
    void validityNeverOutlivesTheDocumentSigner() {
        X509Certificate leaf = MdlFixtures.dsc().chain().leaf().orElseThrow();
        // 400 days exceeds the dev certificate's 365, so the DSC notAfter wins
        String credential = issue(formatter(MdlFixtures.properties(Duration.ofDays(400))), MdlFixtures.mdl(),
                MdlFixtures.signing(MdlFixtures.dsc())).credential().toString();
        CBORObject validUntil = mso(issuerSigned(credential)).get("validityInfo").get("validUntil");
        assertEquals(MdlFixtures.tdate(leaf.getNotAfter().toInstant()), validUntil.Untag().AsString(),
                "validUntil is capped at the DSC notAfter");
    }

    @Test
    void msoPayloadIsWrappedInTag24() {
        CBORObject issuerAuth = issuerSigned(issue(MdlFixtures.mdl())).get("issuerAuth");
        byte[] encodedPayload = issuerAuth.get(2).GetByteString();
        assertEquals((byte) 0xD8, encodedPayload[0], "tag 24 is encoded as D8 18 (two-byte tag)");
        assertEquals((byte) 0x18, encodedPayload[1]);
        CBORObject payload = CBORObject.DecodeFromBytes(encodedPayload);
        assertTrue(payload.HasMostOuterTag(24));
        assertEquals(CBORType.ByteString, payload.Untag().getType(), "#6.24 wraps a byte string, not a nested map");
        assertFalse(issuerAuth.isTagged(), "IssuerAuth is untagged inside IssuerSigned");
    }

    @Test
    void digestsUseTheDeclaredAlgorithm() throws Exception {
        String credential = issue(formatter(MdlFixtures.properties("SHA-384", Duration.ofDays(90))), MdlFixtures.mdl(),
                MdlFixtures.signing(MdlFixtures.dsc())).credential().toString();
        CBORObject issuerSigned = issuerSigned(credential);
        CBORObject mso = mso(issuerSigned);
        assertEquals("SHA-384", mso.get("digestAlgorithm").AsString());
        CBORObject digests = mso.get("valueDigests").get(MdlFixtures.MDL_NAMESPACE);
        Map<Integer, byte[]> bytes = tag24Bytes(issuerSigned, MdlFixtures.MDL_NAMESPACE);
        for (Map.Entry<Integer, byte[]> entry : bytes.entrySet()) {
            byte[] expected = MessageDigest.getInstance("SHA-384").digest(entry.getValue());
            assertArrayEquals(expected, digests.get(CBORObject.FromObject(entry.getKey())).GetByteString(),
                    "digestID " + entry.getKey() + " is the SHA-384 digest over the tag-24 IssuerSignedItem");
        }
        // and a SHA-256 digest of the same item must not match, so the declared algorithm is really the one used
        assertFalse(java.util.Arrays.equals(MessageDigest.getInstance("SHA-256").digest(bytes.values().iterator().next()),
                digests.get(CBORObject.FromObject(bytes.keySet().iterator().next())).GetByteString()));
    }

    @Test
    void digestIdsAreARandomPermutationPerNamespace() {
        Set<Integer> expected = new HashSet<>();
        for (int i = 0; i < 12; i++) {
            expected.add(i);
        }
        Set<String> orders = new HashSet<>();
        for (int run = 0; run < 12; run++) {
            CBORObject issuerSigned = issuerSigned(issue(MdlFixtures.mdl()));
            Set<Integer> ids = itemsById(issuerSigned, MdlFixtures.MDL_NAMESPACE).keySet();
            assertEquals(expected, ids, "digestIDs are 0..n-1, unique within the namespace");
            orders.add(ids.toString() + "@" + itemOrder(issuerSigned));
        }
        assertTrue(orders.size() > 1, "the digestIDs are shuffled per issuance, not assigned in template order");
    }

    private static String itemOrder(CBORObject issuerSigned) {
        List<String> identifiers = new ArrayList<>();
        CBORObject array = issuerSigned.get("nameSpaces").get(MdlFixtures.MDL_NAMESPACE);
        for (int i = 0; i < array.size(); i++) {
            identifiers.add(CBORObject.DecodeFromBytes(array.get(i).Untag().GetByteString()).get("elementIdentifier").AsString()
                    + ":" + CBORObject.DecodeFromBytes(array.get(i).Untag().GetByteString()).get("digestID").AsInt32());
        }
        return String.join(",", identifiers);
    }

    @Test
    void templateDigestIdsAreIgnored() {
        Map<String, Object> document = MdlFixtures.mdl();
        List<Map<String, Object>> items = MdlFixtures.items(document, MdlFixtures.MDL_NAMESPACE);
        for (int i = 0; i < items.size(); i++) {
            items.get(i).put("digestID", 99); // duplicates the old processor would have overwritten
        }
        Set<Integer> ids = itemsById(issuerSigned(issue(document)), MdlFixtures.MDL_NAMESPACE).keySet();
        assertEquals(12, ids.size());
        assertFalse(ids.contains(99), "the template's digestID is not carried to the wire");
    }

    @Test
    void elementValuesAreTypedByTable5() {
        CBORObject issuerSigned = issuerSigned(issue(MdlFixtures.mdl()));
        Map<Integer, CBORObject> items = itemsById(issuerSigned, MdlFixtures.MDL_NAMESPACE);
        Map<String, CBORObject> byIdentifier = new LinkedHashMap<>();
        items.forEach((id, item) -> byIdentifier.put(item.get("elementIdentifier").AsString(), item.get("elementValue")));

        CBORObject portrait = byIdentifier.get("portrait");
        assertEquals(CBORType.ByteString, portrait.getType(), "portrait is a bstr (7.2.1 Table 5)");
        assertEquals(2, portrait.EncodeToBytes()[0] >> 5, "major type 2 on the wire");
        assertArrayEquals(MdlFixtures.JPEG, portrait.GetByteString());

        CBORObject birthDate = byIdentifier.get("birth_date");
        assertTrue(birthDate.HasMostOuterTag(1004), "birth_date is a full-date (#6.1004)");
        assertEquals("1990-01-01", birthDate.Untag().AsString());

        CBORObject privileges = byIdentifier.get("driving_privileges");
        assertEquals(CBORType.Array, privileges.getType());
        assertEquals("B", privileges.get(0).get("vehicle_category_code").AsString());
        assertEquals(1004, privileges.get(0).get("issue_date").getMostOuterTag().ToInt32Checked());
        assertEquals("01", privileges.get(0).get("codes").get(0).get("code").AsString());

        assertEquals(CBORType.TextString, byIdentifier.get("family_name").getType());
        assertEquals(CBORType.TextString, byIdentifier.get("un_distinguishing_sign").getType());
    }

    @Test
    void deviceKeyIsACoseKeyWithoutAlgLabel() {
        CBORObject deviceKey = mso(issuerSigned(issue(MdlFixtures.mdl()))).get("deviceKeyInfo").get("deviceKey");
        assertEquals(2, deviceKey.get(CBORObject.FromObject(1)).AsInt32(), "kty EC2");
        assertEquals(1, deviceKey.get(CBORObject.FromObject(-1)).AsInt32(), "crv P-256");
        assertArrayEquals(Base64.getUrlDecoder().decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
                deviceKey.get(CBORObject.FromObject(-2)).GetByteString());
        assertArrayEquals(Base64.getUrlDecoder().decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"),
                deviceKey.get(CBORObject.FromObject(-3)).GetByteString());
        assertFalse(deviceKey.ContainsKey(CBORObject.FromObject(3)), "no alg label on a device key");
        assertFalse(deviceKey.ContainsKey(CBORObject.FromObject(2)), "no kid label unless the proof hands one over");
    }

    @Test
    void ed25519HolderBecomesAnOkpDeviceKey() {
        UnsignedCredential unsigned = formatter().build(ClaimSet.of(MdlFixtures.mdl()), MdlFixtures.configuration(formatter()),
                MdlFixtures.context(), HolderBinding.did(MdlFixtures.ED25519_HOLDER, "jwt"));
        Map<?, ?> deviceKey = (Map<?, ?>) ((Map<?, ?>) unsigned.asMap().get("deviceKeyInfo")).get("deviceKey");
        assertEquals(1, deviceKey.get(1), "kty OKP");
        assertEquals(6, deviceKey.get(-1), "crv Ed25519");
        assertArrayEquals(Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"), (byte[]) deviceKey.get(-2));
        assertFalse(deviceKey.containsKey(3), "no alg label on a device key");
    }

    @Test
    void didKeyHoldersAreDecoded() {
        // Ed25519 did:key = multicodec 0xed01 (a two-byte varint) plus the 32-byte key, base58btc multibase
        byte[] ed25519 = Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        byte[] ed25519Multicodec = new byte[ed25519.length + 2];
        ed25519Multicodec[0] = (byte) 0xed;
        ed25519Multicodec[1] = 0x01;
        System.arraycopy(ed25519, 0, ed25519Multicodec, 2, ed25519.length);
        String ed25519DidKey = "did:key:" + Multibase.encode(Multibase.Base.Base58BTC, ed25519Multicodec);

        Map<Object, Object> okp = MdocCoseKey.fromHolder(ed25519DidKey, MAPPER);
        assertEquals(1, okp.get(1));
        assertEquals(6, okp.get(-1));
        assertArrayEquals(ed25519, (byte[]) okp.get(-2));

        // the P-256 did:key of the fixture JWK, compressed: multicodec 0x1200 (0x80 0x24 varint) plus the point
        String p256DidKey = "did:key:" + Multibase.encode(Multibase.Base.Base58BTC, compressedP256());
        Map<Object, Object> ec2 = MdocCoseKey.fromHolder(p256DidKey, MAPPER);
        assertEquals(2, ec2.get(1));
        assertEquals(1, ec2.get(-1));
        assertArrayEquals(Base64.getUrlDecoder().decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), (byte[]) ec2.get(-2));
        assertArrayEquals(Base64.getUrlDecoder().decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"), (byte[]) ec2.get(-3));
    }

    /** The fixture holder's P-256 point in compressed form, prefixed with the P-256 multicodec. */
    private static byte[] compressedP256() {
        byte[] x = Base64.getUrlDecoder().decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(x, 0, uncompressed, 1, 32);
        System.arraycopy(Base64.getUrlDecoder().decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"), 0, uncompressed, 33, 32);
        byte[] compressed = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1").getCurve()
                .decodePoint(uncompressed).getEncoded(true);
        byte[] prefixed = new byte[compressed.length + 2];
        prefixed[0] = (byte) 0x80;
        prefixed[1] = 0x24;
        System.arraycopy(compressed, 0, prefixed, 2, compressed.length);
        return prefixed;
    }

    @Test
    void x5chainDropsTheSelfSignedAnchor() throws Exception {
        String credential = issue(formatter(), MdlFixtures.mdl(), MdlFixtures.signing(MdlFixtures.dscWithIaca())).credential().toString();
        CBORObject x5chain = issuerSigned(credential).get("issuerAuth").get(1).get(CBORObject.FromObject(33));
        // RFC 9360: one certificate travels as a bstr, more than one as an array; here only the DSC is left
        int certificates = x5chain.getType() == CBORType.Array ? x5chain.size() : 1;
        assertEquals(1, certificates, "only the DSC travels; the IACA is the verifier's trust anchor (HAIP)");
        byte[] der = x5chain.getType() == CBORType.Array ? x5chain.get(0).GetByteString() : x5chain.GetByteString();
        assertEquals(MdlFixtures.dscWithIaca().chain().leaf().orElseThrow().getSubjectX500Principal(),
                ((X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificate(new java.io.ByteArrayInputStream(der))).getSubjectX500Principal());
        assertFalse(java.util.Arrays.equals(MdlFixtures.dscWithIaca().chain().root().orElseThrow().getEncoded(), der),
                "the self-signed IACA is not carried");
    }

    @Test
    void unusableHolderKeysAreInvalidProof() {
        FormatException missing = assertThrows(FormatException.class, () -> formatter().build(ClaimSet.of(MdlFixtures.mdl()),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(), HolderBinding.NONE));
        assertEquals("invalid_proof", missing.getErrorCode(), "the core answers 400 invalid_proof, not 500");

        FormatException secp256k1 = assertThrows(FormatException.class, () -> formatter().build(ClaimSet.of(MdlFixtures.mdl()),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(),
                HolderBinding.did("did:jwk:" + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("{\"kty\":\"EC\",\"crv\":\"secp256k1\"}".getBytes()), "jwt")));
        assertEquals("invalid_proof", secp256k1.getErrorCode());
    }

    @Test
    void invalidMdlDocumentsAreRefused() {
        FormatException missing = assertThrows(FormatException.class, () -> formatter().build(ClaimSet.of(MdlFixtures.without("given_name")),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(), MdlFixtures.holder()));
        assertEquals("mdoc_data_model_invalid", missing.getErrorCode());
        assertTrue(missing.getMessage().contains("given_name"), missing.getMessage());

        FormatException portrait = assertThrows(FormatException.class, () -> formatter().build(
                ClaimSet.of(MdlFixtures.with("portrait", Base64.getEncoder().encodeToString("not a jpeg".getBytes()))),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(), MdlFixtures.holder()));
        assertEquals("mdoc_data_model_invalid", portrait.getErrorCode());
        assertTrue(portrait.getMessage().contains("JPEG"), portrait.getMessage());

        FormatException country = assertThrows(FormatException.class, () -> formatter().build(
                ClaimSet.of(MdlFixtures.with("issuing_country", "in")), MdlFixtures.configuration(formatter()),
                MdlFixtures.context(), MdlFixtures.holder()));
        assertEquals("mdoc_data_model_invalid", country.getErrorCode());

        // the DSC belongs to IN, the document claims US: refused at signing time, where the certificate is known
        UnsignedCredential unsigned = formatter().build(ClaimSet.of(MdlFixtures.with("issuing_country", "US")),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(), MdlFixtures.holder());
        FormatException mismatch = assertThrows(FormatException.class,
                () -> formatter().sign(unsigned, MdlFixtures.signing(MdlFixtures.dsc()), MdlFixtures.context()));
        assertEquals("mdoc_data_model_invalid", mismatch.getErrorCode());
        assertTrue(mismatch.getMessage().contains("US") && mismatch.getMessage().contains("IN"), mismatch.getMessage());
    }

    @Test
    void aTemplateDocTypeMustMatchTheConfiguration() {
        Map<String, Object> document = new LinkedHashMap<>(MdlFixtures.mdl());
        document.put("docType", "org.iso.18013.5.1.mDL.other");
        FormatException mismatch = assertThrows(FormatException.class, () -> formatter().build(ClaimSet.of(document),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(), MdlFixtures.holder()));
        assertEquals(MdocConstants.ERROR_TEMPLATE, mismatch.getErrorCode());
        assertTrue(mismatch.getMessage().contains("org.iso.18013.5.1.mDL.other"), mismatch.getMessage());
    }

    @Test
    void untypedNamespacesKeepTheDateHeuristicAndTakeOverrides() {
        Map<String, Object> document = MdlFixtures.mdl();
        List<Map<String, Object>> custom = new ArrayList<>();
        custom.add(MdlFixtures.item("issued_on", "2020-05-05"));
        custom.add(MdlFixtures.item("photo", Base64.getEncoder().encodeToString(MdlFixtures.JPEG)));
        custom.add(MdlFixtures.item("level", "3"));
        ((Map<String, Object>) document.get("nameSpaces")).put("org.example.custom", custom);

        // without a type table the date heuristic and plain strings still apply
        CBORObject heuristic = issuerSigned(issue(document));
        Map<String, CBORObject> values = valuesByIdentifier(heuristic, "org.example.custom");
        assertTrue(values.get("issued_on").HasMostOuterTag(1004), "untyped YYYY-MM-DD keeps the tag-1004 heuristic");
        assertEquals(CBORType.TextString, values.get("photo").getType(), "untyped values stay as the template wrote them");

        // with formatConfig.elementTypes the same namespace is typed
        Map<String, Object> typedConfig = Map.of("docType", MdlFixtures.MDL_DOCTYPE,
                "elementTypes", Map.of("org.example.custom", Map.of("photo", "bstr", "level", "uint")));
        MdocFormatter formatter = formatter();
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(document), MdlFixtures.configuration(formatter, typedConfig),
                MdlFixtures.context(), MdlFixtures.holder());
        IssuedCredential issued = formatter.sign(unsigned, MdlFixtures.signing(MdlFixtures.dsc()), MdlFixtures.context());
        Map<String, CBORObject> typed = valuesByIdentifier(issuerSigned((String) issued.credential()), "org.example.custom");
        assertEquals(CBORType.ByteString, typed.get("photo").getType());
        assertEquals(CBORType.Integer, typed.get("level").getType());
    }

    private static Map<String, CBORObject> valuesByIdentifier(CBORObject issuerSigned, String namespace) {
        Map<String, CBORObject> values = new LinkedHashMap<>();
        itemsById(issuerSigned, namespace).forEach((id, item) ->
                values.put(item.get("elementIdentifier").AsString(), item.get("elementValue")));
        return values;
    }

    @Test
    void anUnknownConfiguredElementTypeIsATemplateError() {
        FormatException unknown = assertThrows(FormatException.class, () -> formatter().parseConfig(
                Map.of("docType", MdlFixtures.MDL_DOCTYPE, "elementTypes", Map.of("org.example.custom", Map.of("photo", "jpeg")))));
        assertEquals(MdocConstants.ERROR_TEMPLATE, unknown.getErrorCode());
        assertTrue(unknown.getMessage().contains("jpeg"), unknown.getMessage());
    }
}
