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
import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.Signer;
import io.mosip.certify.signing.SigningKey;
import io.mosip.certify.signing.TrustAnchorRegistry;
import io.mosip.certify.spi.SigningContext;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static io.mosip.certify.status.StatusListTestKeys.DSC;
import static io.mosip.certify.status.StatusListTestKeys.DSC_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED;
import static io.mosip.certify.status.StatusListTestKeys.EXPIRED_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.IACA;
import static io.mosip.certify.status.StatusListTestKeys.NO_EKU;
import static io.mosip.certify.status.StatusListTestKeys.NO_EKU_KEYS;
import static io.mosip.certify.status.StatusListTestKeys.OTHER_CA;
import static io.mosip.certify.status.StatusListTestKeys.UNTRUSTED;
import static io.mosip.certify.status.StatusListTestKeys.UNTRUSTED_KEYS;
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
 *   <li>{@code encode} runs {@link StatusListSignerPolicy#check} before it signs — there is no public path that signs
 *   without it — and an expired, revoked, untrusted or wrongly-purposed signer is refused with its rule prefix and
 *   nothing is signed;</li>
 *   <li>{@code zlib([0xb9, 0xa3])} is {@code 78dadbb918000217015d}, the draft's section 4.3 example, so the {@code lst}
 *   bytes are the draft's;</li>
 *   <li>the payload carries {@code 19fffd a2 63 6c7374 <bstr> 64 62697473 01} — the nested order {@code signOrdered}
 *   cannot check, since it only sees top-level keys — and {@code {lst, bits}} is the draft's StatusList;</li>
 *   <li>{@link TokenStatusListCwt#decode} round-trips every claim of {@link TokenStatusListCwt#encode}, and refuses
 *   every other shape a stored or replayed token could have, malformed COSE and unfaithful claims included;</li>
 *   <li>an independent COSE implementation (Authlete) and plain JCA accept the signature over the production shape,
 *   with the chain that verifies against the IACA — the M-11b verifier's checks, without M-11b (not merged yet);</li>
 *   <li>encode refuses inputs it cannot represent faithfully, so no ambiguous token is signed.</li>
 * </ul>
 */
class TokenStatusListCwtTest {

    private static final String SUB = "https://issuer.example.test/v1/certify/credentials/token-status-list/1";
    /** The signing instant the policy judges, and the token's {@code iat}; the fixture certificates are relative to now. */
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final Instant IAT = NOW.minusSeconds(60);
    private static final Duration TTL = Duration.ofHours(1);
    private static final Instant EXP = IAT.plus(TTL).plus(TTL);
    private static final long TTL_SECONDS = 3600;

    /** A list of the default {@code size-bits} (131072), one index set, so the compressed stream is not the draft's toy. */
    private static final byte[] BITS = new byte[16 * 1024];

    static {
        TokenStatusListService.set(BITS, 42, true);
    }

    private static final SigningContext SIGNING = StatusListTestKeys.context(DSC_KEYS, DSC, IACA);
    private static final StatusListSignerPolicy POLICY = StatusListSignerPolicy.notEnforced();
    private static final StatusListSignerPolicy.Mode MODE = StatusListSignerPolicy.Mode.DOCUMENT_SIGNER;
    private static final AtomicInteger SIGNED = new AtomicInteger();

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
        String payloadHex = HexFormat.of().formatHex(payload(
                encode(SUB, IAT, EXP, TTL, new byte[]{(byte) 0xb9, (byte) 0xa3}, SIGNING)));
        assertTrue(payloadHex.contains("19fffd" + "a2" + "63" + "6c7374" + "4a" + "78dadbb918000217015d"
                        + "64" + "62697473" + "01"),
                "claim 65533 = {lst: h'78dadbb918000217015d', bits: 1}, lst first (RFC 8949 section 4.2.1), got "
                        + payloadHex);
    }

    // ---- the token's shape and claims -------------------------------------------------------------------------

    @Test
    void theTokenIsATaggedSign1WithTheProtectedTypAndChain() throws Exception {
        byte[] token = encode(BITS);
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
        byte[] payload = payload(encode(BITS));
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
        TokenStatusListCwt.Decoded decoded = TokenStatusListCwt.decode(encode(BITS));
        assertEquals(SUB, decoded.sub());
        assertEquals(IAT, decoded.iat());
        assertEquals(EXP, decoded.exp());
        assertEquals(TTL_SECONDS, decoded.ttl());
        assertEquals(1, decoded.bits());
        assertArrayEquals(BITS, decoded.lst(), "lst is the bit array the wire lst inflates to");
        assertTrue(TokenStatusListService.get(decoded.lst(), 42),
                "index 42 is the set one, least significant bit first (TSL section 4.1)");
        assertFalse(TokenStatusListService.get(decoded.lst(), 41));
        assertEquals(List.of(DSC), decoded.x5chain());
    }

    @Test
    void encodingTheSameClaimsTwiceIsDeterministicApartFromTheSignature() {
        // RFC 8949 section 4.2.1 order is fixed by the codec, not left to a hash map's iteration order: only the ECDSA
        // signature may differ between two tokens over the same claims
        byte[] first = encode(BITS);
        byte[] second = encode(BITS);
        assertEquals(HexFormat.of().formatHex(sign1(first).get(0).GetByteString()),
                HexFormat.of().formatHex(sign1(second).get(0).GetByteString()), "the protected header is byte-identical");
        assertEquals(HexFormat.of().formatHex(payload(first)), HexFormat.of().formatHex(payload(second)),
                "and so is the claim map");
    }

    @Test
    void aTokenWithoutTheRecommendedTtlDecodesWithNoTtl() {
        // claim 65534 is RECOMMENDED (TSL section 5.2), so a token that omits it is still this profile
        byte[] token = mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                payload.Remove(CBORObject.FromObject(TokenStatusListCwt.CLAIM_TTL)));
        assertEquals(null, TokenStatusListCwt.decode(token).ttl());
    }

    // ---- the policy runs before anything is signed -------------------------------------------------------------

    @Test
    void encodeRunsThePolicyBeforeItSigns() {
        StatusListSignerPolicy enforced = new StatusListSignerPolicy(anchors(IACA));
        X509CRL revoking = StatusListTestKeys.crl(NOW.minus(1, ChronoUnit.HOURS), NOW.plus(20, ChronoUnit.DAYS),
                DSC.getSerialNumber());
        SIGNED.set(0);

        refusedEncode(StatusListSignerPolicy.EXPIRED, counting(EXPIRED_KEYS, EXPIRED, IACA), enforced);
        refusedEncode(StatusListSignerPolicy.REVOKED, counting(DSC_KEYS, DSC, IACA),
                new StatusListSignerPolicy(anchorsWithCrl(IACA, revoking)));
        refusedEncode(StatusListSignerPolicy.NO_TRUSTED_IACA, counting(UNTRUSTED_KEYS, UNTRUSTED, OTHER_CA), enforced);
        refusedEncode(StatusListSignerPolicy.PURPOSE, counting(NO_EKU_KEYS, NO_EKU, IACA), enforced);

        assertEquals(0, SIGNED.get(), "a refused signer never reaches the signer");
        // the same contexts sign once the policy accepts them: the refusals above are the policy's, not the codec's
        byte[] token = TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, counting(DSC_KEYS, DSC, IACA), enforced,
                NOW, MODE);
        assertTrue(SIGNED.get() > 0);
        assertEquals(SUB, TokenStatusListCwt.decode(token).sub());
    }

    @Test
    void noPublicPathSignsWithoutThePolicy() {
        // reflection, so a second public signing entry point cannot be added without failing here
        for (Method method : TokenStatusListCwt.class.getDeclaredMethods()) {
            if (!Modifier.isPublic(method.getModifiers())) {
                continue;
            }
            if (method.getName().equals("encode")) {
                assertTrue(Arrays.asList(method.getParameterTypes()).contains(StatusListSignerPolicy.class),
                        "encode must take the policy: " + method);
                assertTrue(Arrays.asList(method.getParameterTypes()).contains(Instant.class),
                        "and the instant it judges the policy at: " + method);
            } else {
                assertEquals("decode", method.getName(), "encode is the only public signing path: " + method);
            }
        }
    }

    // ---- independent verification (M-11b's checks without M-11b) -----------------------------------------------

    @Test
    void anIndependentCoseImplementationAcceptsTheTokenAndItsChain() throws Exception {
        byte[] token = encode(BITS);
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
                () -> encode(" ", IAT, EXP, TTL, BITS, SIGNING), "a blank sub names no uri");
        assertThrows(IllegalArgumentException.class,
                () -> encode(SUB, IAT, IAT, TTL, BITS, SIGNING), "exp == iat");
        assertThrows(IllegalArgumentException.class,
                () -> encode(SUB, IAT, IAT.minusSeconds(1), TTL, BITS, SIGNING), "exp before iat");
        assertThrows(IllegalArgumentException.class,
                () -> encode(SUB, IAT, EXP, Duration.ofSeconds(-1), BITS, SIGNING), "negative ttl");
        assertThrows(IllegalArgumentException.class,
                () -> encode(SUB, IAT, EXP, Duration.ZERO, BITS, SIGNING), "zero ttl");
        assertThrows(IllegalArgumentException.class,
                () -> encode(SUB, IAT, EXP, Duration.ofMillis(500), BITS, SIGNING), "a sub-second ttl truncates to 0");
        assertThrows(IllegalArgumentException.class,
                () -> encode(SUB, IAT, EXP, null, BITS, SIGNING), "no ttl");
        // whole seconds: a fractional exp that truncates onto iat is refused rather than signed as a zero-length token
        assertThrows(IllegalArgumentException.class,
                () -> encode(SUB, IAT, IAT.plusMillis(500), TTL, BITS, SIGNING));
    }

    @Test
    void encodeRefusesAnExpiryAfterTheSignerCertificate() {
        Instant after = DSC.getNotAfter().toInstant().plusSeconds(1);
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> encode(SUB, IAT, after, TTL, BITS, SIGNING));
        assertTrue(refused.getMessage().contains("notAfter"), refused.getMessage());
        // and one that ends exactly at notAfter is accepted (notAfter is inclusive, RFC 5280 section 4.1.2.5)
        assertEquals(DSC.getNotAfter().toInstant(),
                TokenStatusListCwt.decode(encode(SUB, IAT, DSC.getNotAfter().toInstant(), TTL, BITS, SIGNING)).exp());
    }

    @Test
    void encodeRefusesASignerNoVerifierCouldAnchor() {
        // M-11a's envelope refuses the chain, and encode maps it through refusal() into the one shape the service handles
        SigningContext noChain = StatusListTestKeys.context(DSC_KEYS, CertificateChain.EMPTY);
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> encode(SUB, IAT, EXP, TTL, BITS, noChain));
        assertTrue(refused.getMessage().startsWith("STATUS_SIGNER_NO_CHAIN: "), refused.getMessage());
        // the policy refuses it before the envelope is reached; the envelope's own refusals are mapped the same way
        // (StatusListSignerPolicyTest.anEnvelopeRefusalMapsLikeAPolicyRefusal holds that mapping directly)
    }

    // ---- decode refuses every other shape ----------------------------------------------------------------------

    @Test
    void decodeRefusesATag61Token() {
        byte[] token = encode(BITS);
        byte[] cwt = CBORObject.FromObjectAndTag(CBORObject.DecodeFromBytes(token), 61).EncodeToBytes();
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(cwt));
        assertTrue(refused.getMessage().contains("tag 61"), refused.getMessage());
    }

    @Test
    void decodeRefusesAnUntaggedToken() {
        byte[] untagged = CBORObject.DecodeFromBytes(encode(BITS)).UntagOne().EncodeToBytes();
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(untagged));
        assertTrue(refused.getMessage().contains("untagged"), refused.getMessage());
    }

    @Test
    void decodeRefusesANestedTag() {
        CBORObject untagged = CBORObject.DecodeFromBytes(encode(BITS)).UntagOne();
        for (int inner : new int[]{18, CwtEnvelopeTag.TAG_CWT}) {
            byte[] nested = CBORObject.FromObjectAndTag(CBORObject.FromObjectAndTag(untagged, inner), 18).EncodeToBytes();
            IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(nested));
            assertTrue(refused.getMessage().contains("more than one tag"), refused.getMessage());
        }
    }

    @Test
    void decodeRefusesATypInTheUnprotectedHeader() {
        byte[] token = mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) -> {
            CBORObject typ = protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_TYP));
            protectedHeader.Remove(CBORObject.FromObject(CoseEnvelope.LABEL_TYP));
            unprotectedHeader.Add(CBORObject.FromObject(CoseEnvelope.LABEL_TYP), typ);
        });
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(token));
        assertTrue(refused.getMessage().contains("no protected typ"), refused.getMessage());
    }

    @Test
    void decodeRefusesAnX5chainOnlyInTheUnprotectedHeader() {
        byte[] token = mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) -> {
            CBORObject chain = protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
            protectedHeader.Remove(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
            unprotectedHeader.Add(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN), chain);
        });
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(token));
        assertTrue(refused.getMessage().contains("no protected x5chain"), refused.getMessage());
    }

    @Test
    void decodeRefusesAMissingExp() {
        byte[] token = mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                payload.Remove(CBORObject.FromObject(TokenStatusListCwt.CLAIM_EXP)));
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(token));
        assertTrue(refused.getMessage().contains("no claim 4 (exp)"), refused.getMessage());
    }

    @Test
    void decodeRefusesBitsOtherThanOne() {
        byte[] token = mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                payload.get(CBORObject.FromObject(TokenStatusListCwt.CLAIM_STATUS_LIST))
                        .set(CBORObject.FromObject("bits"), CBORObject.FromObject(2)));
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> TokenStatusListCwt.decode(token));
        assertTrue(refused.getMessage().contains("status_list.bits is 2"), refused.getMessage());
    }

    @Test
    void decodeRefusesMalformedCose() {
        CBORObject[] parts = parts(encode(BITS));
        // a label in both header buckets (RFC 9052 section 3), typ included
        CBORObject[] both = cloneParts(parts);
        both[1] = CBORObject.NewMap().Add(CBORObject.FromObject(CoseEnvelope.LABEL_TYP),
                CBORObject.FromObject(TokenStatusListCwt.MEDIA_TYPE));
        // a non-map unprotected header
        CBORObject[] integerUnprotected = cloneParts(parts);
        integerUnprotected[1] = CBORObject.FromObject(1);
        // no protected alg
        CBORObject[] noAlg = cloneParts(parts);
        noAlg[0].Remove(CBORObject.FromObject(CoseEnvelope.LABEL_ALG));
        // a null signature and a payload that is not a bstr
        CBORObject[] nullSignature = cloneParts(parts);
        nullSignature[3] = CBORObject.Null;
        CBORObject[] textPayload = cloneParts(parts);
        textPayload[2] = CBORObject.FromObject("claims");
        // an unprotected header that is not empty and shares nothing is still a map: this one is accepted
        List<byte[]> refused = List.of(
                rebuild(both), rebuild(integerUnprotected), rebuild(noAlg), rebuild(nullSignature), rebuild(textPayload));
        for (byte[] candidate : refused) {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> TokenStatusListCwt.decode(candidate), HexFormat.of().formatHex(candidate));
            assertTrue(failure.getMessage().startsWith("Not a CWT Status List Token: "), failure.getMessage());
        }
    }

    @Test
    void decodeRefusesClaimsItCannotRepresent() {
        List<byte[]> refused = List.of(
                // exp is not after iat
                mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_EXP),
                                CBORObject.FromObject(IAT.getEpochSecond()))),
                // ttl is 0, and ttl is negative
                mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_TTL), CBORObject.FromObject(0))),
                mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_TTL), CBORObject.FromObject(-1))),
                // lst is not zlib data
                mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                        payload.get(CBORObject.FromObject(TokenStatusListCwt.CLAIM_STATUS_LIST))
                                .set(CBORObject.FromObject("lst"), CBORObject.FromObject(new byte[]{1, 2, 3}))),
                // iat is a uint64 above Long.MAX_VALUE
                mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_IAT),
                                CBORObject.DecodeFromBytes(HexFormat.of().parseHex("1bffffffffffffffff")))));
        for (byte[] candidate : refused) {
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> TokenStatusListCwt.decode(candidate), HexFormat.of().formatHex(candidate));
            assertTrue(failure.getMessage().startsWith("Not a CWT Status List Token: "), failure.getMessage());
        }
    }

    @Test
    void decodeRefusesAnLstThatInflatesPastTheCeiling() {
        // a decompression bomb: 1 MiB of zeros compresses to about a kilobyte, and a 16 KiB list is the largest a
        // 131072-bit list can be, so decode refuses it before allocating
        byte[] bomb = TokenStatusListService.zlib(new byte[1024 * 1024]);
        byte[] token = mutate(encode(BITS), (protectedHeader, unprotectedHeader, payload) ->
                payload.get(CBORObject.FromObject(TokenStatusListCwt.CLAIM_STATUS_LIST))
                        .set(CBORObject.FromObject("lst"), CBORObject.FromObject(bomb)));
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> TokenStatusListCwt.decode(token, 131072));
        assertTrue(refused.getMessage().contains("inflates to more than"), refused.getMessage());
        // the ceiling is the caller's: with room for it, the same token decodes
        assertEquals(1024 * 1024, TokenStatusListCwt.decode(token, 1024 * 1024 * 8).lst().length);
    }

    @Test
    void decodeRefusesEveryOtherShape() {
        byte[] token = encode(BITS);
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
                // a sub that is not text, and an iat that is not an integer (a floating-point NumericDate included)
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_SUB), CBORObject.FromObject(2))),
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_IAT), CBORObject.FromObject("now"))),
                mutate(token, (protectedHeader, unprotectedHeader, payload) ->
                        payload.set(CBORObject.FromObject(TokenStatusListCwt.CLAIM_IAT), CBORObject.FromObject(1.5))),
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

    /** The codec's ceiling must be positive and a multiple of 8. */
    @Test
    void decodeRefusesAnImpossibleCeiling() {
        byte[] token = encode(BITS);
        assertThrows(IllegalArgumentException.class, () -> TokenStatusListCwt.decode(token, 0));
        assertThrows(IllegalArgumentException.class, () -> TokenStatusListCwt.decode(token, 100));
    }

    private static byte[] encode(byte[] bits) {
        return encode(SUB, IAT, EXP, TTL, bits, SIGNING);
    }

    private static byte[] encode(String sub, Instant iat, Instant exp, Duration ttl, byte[] bits, SigningContext signing) {
        return TokenStatusListCwt.encode(sub, iat, exp, ttl, bits, signing, POLICY, NOW, MODE);
    }

    private static void refusedEncode(String rule, SigningContext signing, StatusListSignerPolicy policy) {
        IllegalStateException refused = assertThrows(IllegalStateException.class,
                () -> TokenStatusListCwt.encode(SUB, IAT, EXP, TTL, BITS, signing, policy, NOW, MODE), rule);
        assertTrue(refused.getMessage().startsWith(rule + ": "), "the refusal names " + rule + ": " + refused.getMessage());
    }

    /** A signing context whose signer counts invocations, so a refusal can be proved to reach no signer. */
    private static SigningContext counting(KeyPair keys, java.security.cert.X509Certificate... chain) {
        SigningContext base = StatusListTestKeys.context(keys, chain);
        return new SigningContext(base.config(), base.key(), new Signer() {
            @Override
            public byte[] signRaw(byte[] data, SigningKey key, SignatureAlgorithm algorithm) {
                SIGNED.incrementAndGet();
                return StatusListTestKeys.SIGNER.signRaw(data, key, algorithm);
            }
        });
    }

    private static TrustAnchorRegistry anchors(java.security.cert.X509Certificate... iacas) {
        return anchorsWithCrl(iacas[0], null);
    }

    private static TrustAnchorRegistry anchorsWithCrl(java.security.cert.X509Certificate iaca, X509CRL crl) {
        List<TrustAnchorRegistry.Anchor> anchors = new ArrayList<>();
        for (int index = 0; index < 1; index++) {
            anchors.add(new TrustAnchorRegistry.Anchor("iaca-" + index, TrustAnchorRegistry.MDOC_IACA, iaca));
        }
        return new TrustAnchorRegistry() {
            @Override
            public List<Anchor> entries(String purpose) {
                return TrustAnchorRegistry.MDOC_IACA.equals(purpose) ? List.copyOf(anchors) : List.of();
            }

            @Override
            public Optional<X509CRL> crl(String anchorId) {
                return crl == null ? Optional.empty() : Optional.of(crl);
            }
        };
    }

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

    /** A token's protected header, unprotected header, claim map and signature. */
    private static CBORObject[] parts(byte[] token) {
        CBORObject sign1 = sign1(token);
        return new CBORObject[]{CBORObject.DecodeFromBytes(sign1.get(0).GetByteString()), sign1.get(1),
                CBORObject.DecodeFromBytes(sign1.get(2).GetByteString()), sign1.get(3)};
    }

    /** A copy deep enough that mutating one case cannot affect another. */
    private static CBORObject[] cloneParts(CBORObject[] parts) {
        return new CBORObject[]{CBORObject.DecodeFromBytes(parts[0].EncodeToBytes()),
                CBORObject.DecodeFromBytes(parts[1].EncodeToBytes()),
                CBORObject.DecodeFromBytes(parts[2].EncodeToBytes()), parts[3]};
    }

    private static byte[] rebuild(CBORObject[] parts) {
        CBORObject sign1 = CBORObject.NewArray()
                .Add(CBORObject.FromObject(parts[0].EncodeToBytes()))
                .Add(parts[1])
                .Add(CBORObject.FromObject(parts[2].EncodeToBytes()))
                .Add(parts[3]);
        return CBORObject.FromObjectAndTag(sign1, CoseEnvelope.TAG_COSE_SIGN1).EncodeToBytes();
    }

    /** Changes a token's protected header, unprotected header and claim map in place. */
    @FunctionalInterface
    private interface Mutation {
        void accept(CBORObject protectedHeader, CBORObject unprotectedHeader, CBORObject claims);
    }

    /** Re-encodes a token with its protected header, unprotected header and claim map changed, without re-signing. */
    private static byte[] mutate(byte[] token, Mutation mutation) {
        CBORObject[] parts = parts(token);
        mutation.accept(parts[0], parts[1], parts[2]);
        return rebuild(parts);
    }

    /** The CWT tag, spelled here so the nested-tag case does not depend on the signing library's constant. */
    private static final class CwtEnvelopeTag {
        private static final int TAG_CWT = 61;
    }
}
