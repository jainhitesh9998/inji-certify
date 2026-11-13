package io.mosip.certify.status;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import io.mosip.certify.signing.CertificateChain;
import io.mosip.certify.signing.CertificateLinks;
import io.mosip.certify.signing.CoseEnvelope;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.spi.SigningContext;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static io.mosip.certify.status.StatusListTestKeys.DSC;
import static io.mosip.certify.status.StatusListTestKeys.DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.IACA;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M-11c: the CWT codec of a Token Status List (docs/design/wp/M-11-status-list-under-iaca.md section 5).
 * draft-ietf-oauth-status-list-21 section 5.2 makes an mDoc's list a CWT, ISO/IEC 18013-5 second edition 12.3.6.3
 * forbids the CWT tag 61 and requires {@code exp} and the signer chain in the protected header, and RFC 8949 section
 * 4.2.1 orders the claim map and the nested StatusList map bytewise.
 *
 * <p>What this test proves, item by item:
 * <ul>
 *   <li>{@code zlib([0xb9, 0xa3])} is {@code 78dadbb918000217015d}, the draft's section 4.3 example, so the {@code lst}
 *   bytes are the draft's;</li>
 *   <li>the payload carries {@code 19fffd a2 63 6c7374 <bstr> 64 62697473 01} — the nested order {@code signOrdered}
 *   cannot check, since it only sees top-level keys — and {@code {lst, bits}} is the draft's StatusList;</li>
 *   <li>{@link TokenStatusListCwt#decode} round-trips every claim of {@link TokenStatusListCwt#encode}, and refuses
 *   every other shape a stored or replayed token could have;</li>
 *   <li>an independent COSE implementation (Authlete) and plain JCA accept the signature over the production shape,
 *   with the chain that verifies against the IACA — the M-11b verifier's checks, without M-11b (not merged yet);</li>
 *   <li>encode refuses inputs it cannot represent faithfully, so no ambiguous token is signed.</li>
 * </ul>
 */
class TokenStatusListCwtTest {

    private static final String SUB = "https://issuer.example.test/v1/certify/credentials/token-status-list/1";
    private static final Instant IAT = Instant.parse("2026-11-13T10:00:00Z");
    private static final Duration TTL = Duration.ofHours(1);
    private static final Instant EXP = IAT.plus(TTL).plus(TTL);
    private static final long TTL_SECONDS = 3600;

    /** A list of the default {@code size-bits} (131072), one index set, so the compressed stream is not the draft's toy. */
    private static final byte[] BITS = new byte[16 * 1024];

    static {
        TokenStatusListService.set(BITS, 42, true);
    }

    private static final SigningContext SIGNING = StatusListTestKeys.context(DSC_KEYS, DSC, IACA);

    // ---- the draft's own bytes ---------------------------------------------------------------------------------

    @Test
    void zlibOfTheDraftExampleIsTheDraftsBytes() {
        // TSL section 4.3: the byte array [0xb9, 0xa3] encodes as lst = 78dadbb918000217015d
        assertEquals("78dadbb918000217015d",
                HexFormat.of().formatHex(TokenStatusListService.zlib(new byte[]{(byte) 0xb9, (byte) 0xa3})));
        // and the JWT form of the same bytes is its base64url, so both forms of one list agree
        assertEquals("eNrbuRgAAhcBXQ", TokenStatusListService.encode(new byte[]{(byte) 0xb9, (byte) 0xa3}));
    }

    @Test
    void theDraftExampleEncodesAsTheDraftSays() {
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, new byte[]{(byte) 0xb9, (byte) 0xa3}, SIGNING);
        String payloadHex = HexFormat.of().formatHex(payload(token));
        assertTrue(payloadHex.contains("19fffd" + "a2" + "63" + "6c7374" + "4a" + "78dadbb918000217015d"
                        + "64" + "62697473" + "01"),
                "claim 65533 = {lst: h'b9a3', bits: 1}, lst first (RFC 8949 section 4.2.1), got " + payloadHex);
    }

    // ---- the token's shape and claims -------------------------------------------------------------------------

    @Test
    void theTokenIsATaggedSign1WithTheProtectedTypAndChain() throws Exception {
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        assertEquals((byte) 0xd2, token[0], "COSE_Sign1_Tagged (18), never the CWT tag 61 (TSL section 5.2)");
        assertEquals((byte) 0x84, token[1], "a four-element COSE_Sign1");
        assertFalse(HexFormat.of().formatHex(token).startsWith("d83d"), "tag 61 is forbidden here");

        CBORObject sign1 = sign1(token);
        CBORObject protectedHeader = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString());
        assertEquals(TokenStatusListCwt.MEDIA_TYPE, protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_TYP)).AsString());
        assertEquals(CBORType.ByteString, protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN)).getType());
        assertArrayEquals(DSC.getEncoded(), protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN)).GetByteString(),
                "WITHOUT_ANCHOR emits the DSC alone: the IACA is the verifier's trust anchor (ISO2 12.3.6.2)");
        assertEquals("a0", HexFormat.of().formatHex(sign1.get(1).EncodeToBytes()),
                "the unprotected header is empty: no kid, no chain (TSL section 11.3)");
    }

    @Test
    void thePayloadEncodesTheStatusListMapInRfc8949Order() {
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        byte[] payload = payload(token);
        String payloadHex = HexFormat.of().formatHex(payload);

        assertTrue(payloadHex.startsWith("a502"), "map(5), claim 2 first: " + payloadHex.substring(0, 8));
        assertEquals(HexFormat.of().formatHex(SUB.getBytes(StandardCharsets.UTF_8)),
                payloadHex.substring(8, 8 + SUB.length() * 2));

        List<Integer> keys = new ArrayList<>();
        CBORObject.DecodeFromBytes(payload).getKeys().forEach(key -> keys.add(key.AsInt32()));
        assertEquals(List.of(TokenStatusListCwt.CLAIM_SUB, TokenStatusListCwt.CLAIM_EXP, TokenStatusListCwt.CLAIM_IAT,
                TokenStatusListCwt.CLAIM_STATUS_LIST, TokenStatusListCwt.CLAIM_TTL), keys,
                "RFC 8949 section 4.2.1: 02, 04, 06, 19 fffd, 19 fffe");

        // the nested map is the codec's job: signOrdered only checks the top-level keys
        assertTrue(payloadHex.contains("19fffd" + "a2" + "636c7374" + "58")
                        || payloadHex.contains("19fffd" + "a2" + "636c7374" + "59"),
                "claim 65533 is map(2), \"lst\" (63 6c 73 74) first, then a bstr of the zlib stream: " + payloadHex);
        assertTrue(payloadHex.endsWith("6462697473" + "01" + "19fffe" + "190e10"),
                "then \"bits\" (64 62 69 74 73) = 1, then 65534 = 3600 (19 0e10), got " + payloadHex);
    }

    @Test
    void decodeRoundTripsEveryClaim() {
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        TokenStatusListCwt.Decoded decoded = TokenStatusListCwt.decode(token);
        assertEquals(SUB, decoded.sub());
        assertEquals(IAT, decoded.iat());
        assertEquals(EXP, decoded.exp());
        assertEquals(TTL_SECONDS, decoded.ttl());
        assertEquals(1, decoded.bits());
        assertArrayEquals(TokenStatusListService.zlib(BITS), decoded.lst(), "lst is the zlib stream of the bits");
        assertArrayEquals(BITS, TokenStatusListService.inflate(decoded.lst()), "and it inflates to them");
        assertTrue(TokenStatusListService.get(TokenStatusListService.inflate(decoded.lst()), 42),
                "index 42 is the set one, least significant bit first (TSL section 4.1)");
        assertFalse(TokenStatusListService.get(TokenStatusListService.inflate(decoded.lst()), 41));
        assertEquals(List.of(DSC), decoded.x5chain());
    }

    @Test
    void encodingTheSameClaimsTwiceIsDeterministicApartFromTheSignature() {
        // RFC 8949 section 4.2.1 order is fixed by the codec, not left to a hash map's iteration order: only the ECDSA
        // signature may differ between two tokens over the same claims
        byte[] first = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        byte[] second = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        assertEquals(HexFormat.of().formatHex(sign1(first).get(0).GetByteString()),
                HexFormat.of().formatHex(sign1(second).get(0).GetByteString()), "the protected header is byte-identical");
        assertEquals(HexFormat.of().formatHex(payload(first)), HexFormat.of().formatHex(payload(second)),
                "and so is the claim map");
    }

    @Test
    void aTokenWithoutTheRecommendedTtlDecodesWithNoTtl() {
        // claim 65534 is RECOMMENDED (TSL section 5.2), so a token that omits it is still this profile
        byte[] token = mutate(TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING),
                (protectedHeader, unprotectedHeader, payload) ->
                        payload.Remove(CBORObject.FromObject(TokenStatusListCwt.CLAIM_TTL)));
        assertEquals(null, TokenStatusListCwt.decode(token).ttl());
    }

    // ---- independent verification (M-11b's checks without M-11b) -----------------------------------------------

    @Test
    void anIndependentCoseImplementationAcceptsTheTokenAndItsChain() throws Exception {
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        CBORItem item = new CBORDecoder(token).next();
        assertTrue(item instanceof CBORTaggedItem, "Authlete reads a tagged item");
        CBORTaggedItem tagged = (CBORTaggedItem) item;
        assertEquals(18L, tagged.getTagNumber().longValue());
        COSESign1 coseSign1 = COSESign1.build(tagged.getTagContent());
        assertEquals(TokenStatusListCwt.MEDIA_TYPE,
                coseSign1.getProtectedHeader().getParameters().get(CoseEnvelope.LABEL_TYP),
                "Authlete reads typ (16) as the media type");
        assertEquals(List.of(DSC), coseSign1.getProtectedHeader().getX5Chain(),
                "the protected x5chain is the signer chain without the IACA (RFC 9360 section 2)");
        assertTrue(new COSEVerifier(DSC.getPublicKey()).verify(coseSign1),
                "a second, independent COSE implementation accepts the signature");

        // the trust path Multipaz's CompressedStatusList.fromCwt walks: the chain's leaf is issued by the IACA it is
        // given as the trust anchor (ISO/IEC 18013-5 second edition 12.3.6.2)
        assertTrue(CertificateLinks.issuedBy(DSC, IACA), "the DSC chains to the IACA");

        // and plain JCA over Sig_structure, the wire form of the signature
        CBORObject sign1 = sign1(token);
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(DSC.getPublicKey());
        verifier.update(CoseEnvelope.sigStructure(sign1.get(0).GetByteString(), new byte[0],
                sign1.get(2).GetByteString()));
        assertTrue(verifier.verify(ECDSA.transcodeSignatureToDER(sign1.get(3).GetByteString())));
    }

    // ---- encode refuses what it cannot represent ----------------------------------------------------------------

    @Test
    void encodeRefusesClaimsItCannotRepresent() {
        assertThrows(IllegalArgumentException.class,
                () -> TokenStatusListCwt.encode(" ", IAT, EXP, TTL, BITS, SIGNING), "a blank sub names no uri");
        assertThrows(IllegalArgumentException.class,
                () -> TokenStatusListCwt.encode(SUB, IAT, IAT, TTL, BITS, SIGNING), "exp == iat");
        assertThrows(IllegalArgumentException.class,
                () -> TokenStatusListCwt.encode(SUB, IAT, IAT.minusSeconds(1), TTL, BITS, SIGNING), "exp before iat");
        assertThrows(IllegalArgumentException.class,
                () -> TokenStatusListCwt.encode(SUB, IAT, EXP, Duration.ofSeconds(-1), BITS, SIGNING), "negative ttl");
        assertThrows(IllegalArgumentException.class,
                () -> TokenStatusListCwt.encode(SUB, IAT, EXP, null, BITS, SIGNING), "no ttl");
        // whole seconds: a fractional exp that truncates onto iat is refused rather than signed as a zero-length token
        assertThrows(IllegalArgumentException.class,
                () -> TokenStatusListCwt.encode(SUB, IAT, IAT.plusMillis(500), TTL, BITS, SIGNING));
    }

    @Test
    void encodeRefusesASignerNoVerifierCouldAnchor() {
        SigningContext noChain = StatusListTestKeys.context(DSC_KEYS, CertificateChain.EMPTY);
        SigningException refused = assertThrows(SigningException.class,
                () -> TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, noChain));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_NO_CHAIN: "), refused.getMessage());
        // and the policy's mapping turns it into the one exception the service handles
        RuntimeException mapped = StatusListSignerPolicy.refusal(refused);
        assertEquals(IllegalStateException.class, mapped.getClass());
        assertEquals(refused.getMessage(), mapped.getMessage());
    }

    // ---- decode refuses every other shape ----------------------------------------------------------------------

    @Test
    void decodeRefusesATag61Token() {
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        byte[] cwt = CBORObject.FromObjectAndTag(CBORObject.DecodeFromBytes(token), 61).EncodeToBytes();
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(cwt));
        assertTrue(refused.getMessage().contains("tag 61"), refused.getMessage());
    }

    @Test
    void decodeRefusesAnUntaggedToken() {
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        byte[] untagged = CBORObject.DecodeFromBytes(token).UntagOne().EncodeToBytes();
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(untagged));
        assertTrue(refused.getMessage().contains("untagged"), refused.getMessage());
    }

    @Test
    void decodeRefusesATypInTheUnprotectedHeader() {
        byte[] token = mutate(TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING),
                (protectedHeader, unprotectedHeader, payload) -> {
                    CBORObject typ = protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_TYP));
                    protectedHeader.Remove(CBORObject.FromObject(CoseEnvelope.LABEL_TYP));
                    unprotectedHeader.Add(CBORObject.FromObject(CoseEnvelope.LABEL_TYP), typ);
                });
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(token));
        assertTrue(refused.getMessage().contains("no protected typ"), refused.getMessage());
    }

    @Test
    void decodeRefusesAnX5chainOnlyInTheUnprotectedHeader() {
        byte[] token = mutate(TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING),
                (protectedHeader, unprotectedHeader, payload) -> {
                    CBORObject chain = protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
                    protectedHeader.Remove(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
                    unprotectedHeader.Add(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN), chain);
                });
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(token));
        assertTrue(refused.getMessage().contains("no protected x5chain"), refused.getMessage());
    }

    @Test
    void decodeRefusesAMissingExp() {
        byte[] token = mutate(TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING),
                (protectedHeader, unprotectedHeader, payload) ->
                        payload.Remove(CBORObject.FromObject(TokenStatusListCwt.CLAIM_EXP)));
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(token));
        assertTrue(refused.getMessage().contains("no claim 4 (exp)"), refused.getMessage());
    }

    @Test
    void decodeRefusesBitsOtherThanOne() {
        byte[] token = mutate(TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING),
                (protectedHeader, unprotectedHeader, payload) ->
                        payload.get(CBORObject.FromObject(TokenStatusListCwt.CLAIM_STATUS_LIST))
                                .set(CBORObject.FromObject("bits"), CBORObject.FromObject(2)));
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(token));
        assertTrue(refused.getMessage().contains("status_list.bits is 2"), refused.getMessage());
    }

    @Test
    void decodeRefusesEveryOtherShape() {
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, SIGNING);
        List<byte[]> refused = List.of(
                // not CBOR at all
                new byte[]{(byte) 0xff, (byte) 0xff},
                // tag 18 around an array of three
                CBORObject.FromObjectAndTag(CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0]))
                        .Add(CBORObject.NewMap()).Add(CBORObject.FromObject(new byte[0])), 18).EncodeToBytes(),
                // the wrong typ
                mutate(token, (protectedHeader, unprotectedHeader, payload) -> protectedHeader
                        .set(CBORObject.FromObject(CoseEnvelope.LABEL_TYP), CBORObject.FromObject("application/statuslist+jwt"))),
                // a typ that is not a text string
                mutate(token, (protectedHeader, unprotectedHeader, payload) -> protectedHeader
                        .set(CBORObject.FromObject(CoseEnvelope.LABEL_TYP), CBORObject.FromObject(1))),
                // an empty x5chain array
                mutate(token, (protectedHeader, unprotectedHeader, payload) -> protectedHeader
                        .set(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN), CBORObject.NewArray())),
                // an x5chain that is not a bstr
                mutate(token, (protectedHeader, unprotectedHeader, payload) -> protectedHeader
                        .set(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN), CBORObject.FromObject("chain"))),
                // no sub, no iat, no status_list, no lst
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.Remove(CBORObject.FromObject(TokenStatusListCwt.CLAIM_SUB))),
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.Remove(CBORObject.FromObject(TokenStatusListCwt.CLAIM_IAT))),
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.Remove(CBORObject.FromObject(TokenStatusListCwt.CLAIM_STATUS_LIST))),
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.get(CBORObject.FromObject(TokenStatusListCwt.CLAIM_STATUS_LIST))
                                .Remove(CBORObject.FromObject("lst"))),
                // a sub that is not text, and an iat that is not an integer
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_SUB), CBORObject.FromObject(2))),
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_IAT), CBORObject.FromObject("now"))),
                // a status_list that is not a map
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_STATUS_LIST), CBORObject.FromObject(1))));
        for (byte[] candidate : refused) {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> TokenStatusListCwt.decode(candidate), HexFormat.of().formatHex(candidate));
            assertTrue(failure.getMessage().startsWith("Not a CWT Status List Token: "), failure.getMessage());
        }
    }

    // ---- helpers ----------------------------------------------------------------------------------------------

    /** The COSE_Sign1 of a token, with the outer tag checked and removed. */
    private static CBORObject sign1(byte[] token) {
        CBORObject outer = CBORObject.DecodeFromBytes(token);
        assertTrue(outer.isTagged());
        assertEquals(String.valueOf(CoseEnvelope.TAG_COSE_SIGN1), outer.getMostOuterTag().toString());
        return outer.UntagOne();
    }

    private static byte[] payload(byte[] token) {
        return sign1(token).get(2).GetByteString();
    }

    /** Changes a token's protected header, unprotected header and claim map in place. */
    @FunctionalInterface
    private interface Mutation {
        void accept(CBORObject protectedHeader, CBORObject unprotectedHeader, CBORObject claims);
    }

    /** Re-encodes a token with its protected header, unprotected header and claim map changed, without re-signing. */
    private static byte[] mutate(byte[] token, Mutation mutation) {
        CBORObject outer = CBORObject.DecodeFromBytes(token);
        int tag = Integer.parseInt(outer.getMostOuterTag().toString());
        CBORObject sign1 = outer.UntagOne();
        CBORObject protectedHeader = CBORObject.DecodeFromBytes(sign1.get(0).GetByteString());
        CBORObject unprotectedHeader = sign1.get(1);
        CBORObject claims = CBORObject.DecodeFromBytes(sign1.get(2).GetByteString());
        mutation.accept(protectedHeader, unprotectedHeader, claims);
        CBORObject rebuilt = CBORObject.NewArray()
                .Add(CBORObject.FromObject(protectedHeader.EncodeToBytes()))
                .Add(unprotectedHeader)
                .Add(CBORObject.FromObject(claims.EncodeToBytes()))
                .Add(sign1.get(3));
        return CBORObject.FromObjectAndTag(rebuilt, tag).EncodeToBytes();
    }
}
