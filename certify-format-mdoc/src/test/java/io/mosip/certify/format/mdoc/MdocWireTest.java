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
    void digestIdsAreRandomDistinctUints() {
        Set<String> runs = new HashSet<>();
        for (int run = 0; run < 12; run++) {
            CBORObject issuerSigned = issuerSigned(issue(MdlFixtures.mdl()));
            List<Integer> ids = new ArrayList<>(itemsById(issuerSigned, MdlFixtures.MDL_NAMESPACE).keySet());
            assertEquals(12, ids.size(), "one digestID per element");
            assertEquals(12, new HashSet<>(ids).size(), "digestIDs are unique within the namespace");
            for (int id : ids) {
                assertTrue(id >= 0, "digestID is a uint: " + id);
            }
            runs.add(ids + "@" + itemOrder(issuerSigned));
        }
        assertTrue(runs.size() > 1, "the digestIDs are random per issuance, not a permutation of 0..n-1");
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
    void typedTextIsNeverGuessedAsADate() {
        // document_number and the code sign/value are tstr in Table 5: a YYYY-MM-DD-looking value stays text
        Map<String, Object> privilege = new LinkedHashMap<>();
        privilege.put("vehicle_category_code", "B");
        privilege.put("codes", List.of(Map.of("code", "01", "sign", "2024-01-01", "value", "2024-01-02")));
        Map<String, Object> document = MdlFixtures.with("document_number", "2024-01-01");
        MdlFixtures.items(document, MdlFixtures.MDL_NAMESPACE).stream()
                .filter(item -> "driving_privileges".equals(item.get("elementIdentifier")))
                .forEach(item -> item.put("elementValue", List.of(privilege)));

        Map<String, CBORObject> values = valuesByIdentifier(issuerSigned(issue(document)), MdlFixtures.MDL_NAMESPACE);
        assertEquals(CBORType.TextString, values.get("document_number").getType(),
                "a tstr typed by Table 5 is not run through the YYYY-MM-DD heuristic");
        assertFalse(values.get("document_number").isTagged(), "no tag 1004 on a typed text element");
        CBORObject code = values.get("driving_privileges").get(0).get("codes").get(0);
        assertEquals(CBORType.TextString, code.get("sign").getType());
        assertFalse(code.get("sign").isTagged());
        assertEquals(CBORType.TextString, code.get("value").getType());
        assertFalse(code.get("value").isTagged());
    }

    @Test
    void issueAndExpiryDateTakeTdateOrFullDate() {
        Map<String, Object> document = MdlFixtures.with("issue_date", "2024-01-01T10:15:30Z");
        Map<String, CBORObject> values = valuesByIdentifier(issuerSigned(issue(document)), MdlFixtures.MDL_NAMESPACE);
        assertTrue(values.get("issue_date").HasMostOuterTag(0), "a tdate-shaped issue_date is #6.0");
        assertEquals("2024-01-01T10:15:30Z", values.get("issue_date").Untag().AsString());
        assertTrue(values.get("expiry_date").HasMostOuterTag(1004), "a full-date-shaped expiry_date is #6.1004");
        // inside driving_privileges the dates stay full-date even when a tdate would be accepted at top level
        assertEquals(1004, values.get("driving_privileges").get(0).get("issue_date").getMostOuterTag().ToInt32Checked());
    }

    @Test
    void impossibleDatesAreRefused() {
        for (String[] element : new String[][] {{"birth_date", "2023-02-31"}, {"expiry_date", "2024-13-01"},
                {"issue_date", "2023-02-31T10:00:00Z"}, {"portrait_capture_date", "2023-02-31T10:00:00Z"}}) {
            FormatException e = assertThrows(FormatException.class, () -> formatter().build(
                    ClaimSet.of(MdlFixtures.with(element[0], element[1])), MdlFixtures.configuration(formatter()),
                    MdlFixtures.context(), MdlFixtures.holder()), element[0] + " " + element[1]);
            assertEquals("mdoc_data_model_invalid", e.getErrorCode(), element[0] + " " + element[1]);
        }
    }

    @Test
    void portraitMustBeADecodableImage() {
        // a JPEG header with no image behind it is refused
        FormatException fake = assertThrows(FormatException.class, () -> formatter().build(
                ClaimSet.of(MdlFixtures.with("portrait", Base64.getEncoder().encodeToString(
                        new byte[] {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, 0x00, 0x01, 0x02, 0x03}))),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(), MdlFixtures.holder()));
        assertEquals("mdoc_data_model_invalid", fake.getErrorCode());
        assertTrue(fake.getMessage().contains("decode"), fake.getMessage());

        // a JP2 signature box followed by ftyp is accepted (ImageIO has no JP2 reader by default)
        byte[] jp2 = new byte[32];
        byte[] signature = {0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, (byte) 0x87, 0x0A};
        System.arraycopy(signature, 0, jp2, 0, signature.length);
        byte[] ftyp = {0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x6A, 0x70, 0x32, 0x20};
        System.arraycopy(ftyp, 0, jp2, signature.length, ftyp.length);
        formatter().build(ClaimSet.of(MdlFixtures.with("portrait", Base64.getEncoder().encodeToString(jp2))),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(), MdlFixtures.holder());
    }

    @Test
    void duplicateElementIdentifiersWithinANamespaceAreRefused() {
        Map<String, Object> document = MdlFixtures.mdl();
        MdlFixtures.items(document, MdlFixtures.MDL_NAMESPACE).add(MdlFixtures.item("given_name", "Jane again"));
        FormatException duplicate = assertThrows(FormatException.class, () -> formatter().build(ClaimSet.of(document),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(), MdlFixtures.holder()));
        assertEquals("mdoc_data_model_invalid", duplicate.getErrorCode());
        assertTrue(duplicate.getMessage().contains("given_name"), duplicate.getMessage());
    }

    @Test
    void drivingPrivilegesFollowTheCddl() {
        Map<String, Object> emptyCodes = new LinkedHashMap<>();
        emptyCodes.put("vehicle_category_code", "B");
        emptyCodes.put("codes", List.of());
        Map<String, Object> unknownKey = new LinkedHashMap<>();
        unknownKey.put("vehicle_category_code", "B");
        unknownKey.put("restrictions", "glasses");
        for (Map<String, Object> privilege : List.of(emptyCodes, unknownKey)) {
            FormatException e = assertThrows(FormatException.class, () -> formatter().build(
                    ClaimSet.of(MdlFixtures.with("driving_privileges", List.of(privilege))), MdlFixtures.configuration(formatter()),
                    MdlFixtures.context(), MdlFixtures.holder()));
            assertEquals("mdoc_data_model_invalid", e.getErrorCode());
        }
    }

    @Test
    void table5ValueRangesAreChecked() {
        for (String[] element : new String[][] {{"sex", "3"}, {"nationality", "India"}, {"resident_country", "in"},
                {"height", "9223372036854775808"}}) {
            FormatException e = assertThrows(FormatException.class, () -> formatter().build(
                    ClaimSet.of(MdlFixtures.with(element[0], element[1])), MdlFixtures.configuration(formatter()),
                    MdlFixtures.context(), MdlFixtures.holder()), element[0] + " " + element[1]);
            assertEquals("mdoc_data_model_invalid", e.getErrorCode(), element[0] + " " + element[1]);
        }
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

    @Test
    void anEvenYCompressedP256DidKeyIsDecoded() {
        byte[] x = Base64.getUrlDecoder().decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
        byte[] y = Base64.getUrlDecoder().decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(x, 0, uncompressed, 1, 32);
        System.arraycopy(y, 0, uncompressed, 33, 32);
        org.bouncycastle.math.ec.ECCurve curve = org.bouncycastle.jce.ECNamedCurveTable
                .getParameterSpec("secp256r1").getCurve();
        org.bouncycastle.math.ec.ECPoint point = curve.decodePoint(uncompressed);
        if (point.getAffineYCoord().toBigInteger().testBit(0)) {
            point = point.negate(); // choose the even-y representative so the compressed prefix is 0x02
        }
        byte[] compressed = point.getEncoded(true);
        assertEquals(0x02, compressed[0] & 0xFF, "an even y compresses with prefix 02");
        byte[] prefixed = new byte[compressed.length + 2];
        prefixed[0] = (byte) 0x80;
        prefixed[1] = 0x24;
        System.arraycopy(compressed, 0, prefixed, 2, compressed.length);

        Map<Object, Object> ec2 = MdocCoseKey.fromHolder(
                "did:key:" + Multibase.encode(Multibase.Base.Base58BTC, prefixed), MAPPER);
        assertEquals(2, ec2.get(1));
        assertEquals(1, ec2.get(-1));
        assertArrayEquals(x, (byte[]) ec2.get(-2));
        assertArrayEquals(org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, point.getAffineYCoord().toBigInteger()),
                (byte[]) ec2.get(-3), "the even y is recovered from the compressed point");
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
    void ageOverAnyTwoDigitThresholdIsABool() {
        Map<String, CBORObject> values = valuesByIdentifier(
                issuerSigned(issue(MdlFixtures.with("age_over_21", "true"))), MdlFixtures.MDL_NAMESPACE);
        assertEquals(CBORType.Boolean, values.get("age_over_21").getType(),
                "age_over_NN matches age_over_\\d{2}, not a fixed list of ten thresholds");
        assertTrue(values.get("age_over_21").AsBoolean());
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

        // an EC point that is not on the curve is refused, not encoded as a COSE_Key
        String offCurve = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"AQ\"}";
        FormatException point = assertThrows(FormatException.class, () -> formatter().build(ClaimSet.of(MdlFixtures.mdl()),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(),
                HolderBinding.did("did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(offCurve.getBytes()), "jwt")));
        assertEquals("invalid_proof", point.getErrorCode());
        assertTrue(point.getMessage().contains("not on"), point.getMessage());

        // an Ed25519 x that is not exactly 32 bytes is refused, never zero-padded into a different key
        String shortEd25519 = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\""
                + Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.Arrays.copyOf(
                        Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"), 31))
                + "\"}";
        FormatException shortKey = assertThrows(FormatException.class, () -> formatter().build(ClaimSet.of(MdlFixtures.mdl()),
                MdlFixtures.configuration(formatter()), MdlFixtures.context(),
                HolderBinding.did("did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(shortEd25519.getBytes()), "jwt")));
        assertEquals("invalid_proof", shortKey.getErrorCode());
        assertTrue(shortKey.getMessage().contains("32"), shortKey.getMessage());
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
                "elementTypes", Map.of("org.example.custom", Map.of("photo", "bstr", "level", "uint", "issued_on", "tstr")));
        MdocFormatter formatter = formatter();
        UnsignedCredential unsigned = formatter.build(ClaimSet.of(document), MdlFixtures.configuration(formatter, typedConfig),
                MdlFixtures.context(), MdlFixtures.holder());
        IssuedCredential issued = formatter.sign(unsigned, MdlFixtures.signing(MdlFixtures.dsc()), MdlFixtures.context());
        Map<String, CBORObject> typed = valuesByIdentifier(issuerSigned((String) issued.credential()), "org.example.custom");
        assertEquals(CBORType.ByteString, typed.get("photo").getType());
        assertEquals(CBORType.Integer, typed.get("level").getType());
        assertEquals(CBORType.TextString, typed.get("issued_on").getType(), "a typed tstr is not tagged as a date");
        assertFalse(typed.get("issued_on").isTagged());
    }

    @Test
    void anOverrideCannotChangeATable5Element() {
        FormatException changed = assertThrows(FormatException.class, () -> formatter().parseConfig(Map.of(
                "docType", MdlFixtures.MDL_DOCTYPE,
                "elementTypes", Map.of(MdlFixtures.MDL_NAMESPACE, Map.of("document_number", "uint")))));
        assertEquals(MdocConstants.ERROR_DATA_MODEL, changed.getErrorCode());
        assertTrue(changed.getMessage().contains("document_number"), changed.getMessage());
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
