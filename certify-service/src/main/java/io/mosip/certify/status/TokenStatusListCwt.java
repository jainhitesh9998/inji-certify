package io.mosip.certify.status;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import io.mosip.certify.signing.CoseEnvelope;
import io.mosip.certify.signing.CoseHeaderPolicy;
import io.mosip.certify.signing.CwtEnvelope;
import io.mosip.certify.signing.SigningException;
import io.mosip.certify.spi.SigningContext;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

/**
 * The CWT form of a Token Status List (draft-ietf-oauth-status-list-21 section 5.2; ISO/IEC 18013-5 second edition
 * 12.3.6.3 requires it for an mDoc's MSO revocation list): a COSE_Sign1_Tagged (18, never the CWT tag 61) whose
 * protected header is {@code {1: alg, 16: "application/statuslist+cwt", 33: x5chain}} and whose claims are
 * {@code {2: sub, 4: exp, 6: iat, 65533: {lst, bits}, 65534: ttl}} in RFC 8949 section 4.2.1 bytewise order at both
 * levels.
 *
 * <p>The nested StatusList map is encoded {@code {"lst": <zlib bytes>, "bits": 1}} — {@code lst} first because
 * {@code 63 6c 73 74} sorts before {@code 64 62 69 74 73} bytewise ({@link CwtEnvelope#signOrdered} can only check the
 * top-level claim keys, so the nested order is this codec's job). The title of the map follows TSL section 4.3:
 * {@code bits} is 1 for mDocs (ISO2 12.3.6.5), the {@code lst} bytes are the same zlib stream the JWT form carries
 * base64url encoded, and index {@code i} is bit {@code i mod 8} of byte {@code i / 8}, least significant bit first
 * ({@link TokenStatusListService#get}).
 *
 * <p>{@link #decode} reads a token back without verifying its signature: it is the codec, not a verifier. What it does
 * refuse is anything that is not this profile — so a stored or served token cannot silently change shape — while a
 * verifier still has the last word on the signature, the trust path and the signer's authorisation
 * ({@code StatusListSignerPolicy} runs before either signing or re-signing).
 */
public final class TokenStatusListCwt {

    /** TSL section 8.2: the media type of a CWT Status List Token, and protected header 16 (RFC 9596). */
    public static final String MEDIA_TYPE = "application/statuslist+cwt";

    /** RFC 8392 claim keys and the TSL section 4.3 StatusList member. */
    public static final int CLAIM_SUB = 2;
    public static final int CLAIM_EXP = 4;
    public static final int CLAIM_IAT = 6;
    public static final int CLAIM_STATUS_LIST = 65533;
    public static final int CLAIM_TTL = 65534;

    /** ISO/IEC 18013-5 second edition 12.3.6.5: an mDoc status list carries one bit per index. */
    public static final int BITS = 1;

    private TokenStatusListCwt() {}

    /**
     * A token read back: the claims a status list carries and the signer chain its protected header names. {@code ttl}
     * is {@code null} when the token omits the recommended claim 65534, and the signature is not checked here.
     */
    public record Decoded(String sub, Instant iat, Instant exp, Long ttl, int bits, byte[] lst,
                          List<X509Certificate> x5chain) {

        public Decoded {
            Objects.requireNonNull(sub, "sub");
            Objects.requireNonNull(iat, "iat");
            Objects.requireNonNull(exp, "exp");
            Objects.requireNonNull(lst, "lst");
            x5chain = List.copyOf(x5chain);
        }
    }

    /**
     * Signs a status list as a CWT.
     *
     * @param sub     the {@code status_list.uri} of the Referenced Tokens this list answers for (claim 2, TSL section
     *                8.3 step 4a)
     * @param iat     the signing instant, in whole seconds (claim 6)
     * @param exp     when the token expires, in whole seconds and later than {@code iat}; never later than the signer's
     *                {@code notAfter} (claim 4 is REQUIRED for an mDoc list, ISO2 12.3.6.3)
     * @param ttl     how long a verifier may cache the list (claim 65534)
     * @param bits    the bit array, one bit per index, least significant bit first
     * @param signing the signer — {@code StatusListSignerPolicy} must have accepted it already
     * @throws IllegalArgumentException when a claim could not be represented faithfully, so no ambiguous token is signed
     * @throws SigningException         when the signer chain is one no verifier could anchor (M-11a's envelope refuses
     *                                  an empty chain, a self-signed leaf and an emitted chain carrying an anchor)
     */
    public static byte[] encode(String sub, Instant iat, Instant exp, Duration ttl, byte[] bits, SigningContext signing) {
        Objects.requireNonNull(signing, "signing");
        if (sub == null || sub.isBlank()) {
            throw new IllegalArgumentException("A status list names the uri of its Referenced Tokens (claim 2, TSL section 8.3)");
        }
        Objects.requireNonNull(iat, "iat");
        Objects.requireNonNull(exp, "exp");
        if (exp.getEpochSecond() <= iat.getEpochSecond()) {
            throw new IllegalArgumentException("exp " + exp + " must be later than iat " + iat
                    + ": a token is not signed already expired, and both claims are whole seconds (RFC 8392 section 2)");
        }
        if (ttl == null || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be a non-negative duration, got " + ttl);
        }
        Objects.requireNonNull(bits, "bits");

        LinkedHashMap<Integer, CBORObject> claims = new LinkedHashMap<>();
        claims.put(CLAIM_SUB, CBORObject.FromObject(sub));
        claims.put(CLAIM_EXP, CBORObject.FromObject(exp.getEpochSecond()));
        claims.put(CLAIM_IAT, CBORObject.FromObject(iat.getEpochSecond()));
        claims.put(CLAIM_STATUS_LIST, statusList(bits));
        claims.put(CLAIM_TTL, CBORObject.FromObject(ttl.getSeconds()));
        return CwtEnvelope.signOrdered(claims, CoseHeaderPolicy.statusListCwt(), signing.key(), signing.signer());
    }

    /**
     * TSL section 4.3's {@code StatusList = {bits: 1, lst: bstr}}: RFC 8949 section 4.2.1 order, {@code lst} first.
     */
    private static CBORObject statusList(byte[] bits) {
        return CBORObject.NewOrderedMap()
                .Add(CBORObject.FromObject("lst"), CBORObject.FromObject(TokenStatusListService.zlib(bits)))
                .Add(CBORObject.FromObject("bits"), CBORObject.FromObject(BITS));
    }

    /**
     * Reads a CWT Status List Token back, without verifying its signature (TSL section 5.2; ISO2 12.3.6.3).
     *
     * @throws IllegalStateException when the bytes are not this profile: not tag 18 around a four-element COSE_Sign1, no
     *                               protected {@code typ} 16 equal to {@value #MEDIA_TYPE}, no protected {@code x5chain}
     *                               33, a missing claim 2/6/4/65533, or {@code bits} other than 1
     */
    public static Decoded decode(byte[] token) {
        Objects.requireNonNull(token, "token");
        CBORObject outer = cbor(token);
        if (!outer.isTagged() || !String.valueOf(CoseEnvelope.TAG_COSE_SIGN1).equals(outer.getMostOuterTag().toString())) {
            // a CWT tag 61 around a COSE_Sign1 is the shape TSL section 5.2 forbids, and an untagged array is no
            // Status List Token at all
            throw refuse("not COSE_Sign1_Tagged (tag 18)" + (outer.isTagged()
                    ? ", it is tagged " + outer.getMostOuterTag() + " (a Status List Token is never tag 61, TSL section 5.2)"
                    : " and untagged"));
        }
        CBORObject sign1 = outer.UntagOne();
        if (sign1.getType() != CBORType.Array || sign1.size() != 4) {
            throw refuse("the tag wraps " + (sign1.getType() == CBORType.Array
                    ? "an array of " + sign1.size() : "a " + sign1.getType()) + ", not a four-element COSE_Sign1");
        }
        CBORObject protectedHeader = cbor(bytes(sign1.get(0), "the protected header"));
        if (protectedHeader.getType() != CBORType.Map) {
            throw refuse("the protected header is a " + protectedHeader.getType() + ", not a map");
        }
        CBORObject typ = protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_TYP));
        if (typ == null) {
            throw refuse("no protected typ (label 16); TSL section 5.2 requires " + MEDIA_TYPE
                    + ", and a typ in the unprotected header is not one");
        }
        if (typ.getType() != CBORType.TextString || !MEDIA_TYPE.equals(typ.AsString())) {
            throw refuse("protected typ " + typ + " is not the text string " + MEDIA_TYPE + " (TSL section 5.2)");
        }
        CBORObject chain = protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_X5CHAIN));
        if (chain == null) {
            throw refuse("no protected x5chain (label 33); ISO/IEC 18013-5 second edition 12.3.6.3 requires the chain"
                    + " used to verify the signature in the protected header, and a chain in the unprotected header is"
                    + " not one");
        }
        List<X509Certificate> x5chain = certificates(chain);

        CBORObject payload = cbor(bytes(sign1.get(2), "the payload"));
        if (payload.getType() != CBORType.Map) {
            throw refuse("the payload is a " + payload.getType() + ", not a claim map");
        }
        CBORObject sub = claim(payload, CLAIM_SUB, "sub");
        if (sub.getType() != CBORType.TextString) {
            throw refuse("claim 2 (sub) is a " + sub.getType() + ", not the uri text");
        }
        Instant iat = instant(claim(payload, CLAIM_IAT, "iat"), "iat");
        Instant exp = instant(claim(payload, CLAIM_EXP, "exp"), "exp");
        CBORObject ttlClaim = payload.get(CBORObject.FromObject(CLAIM_TTL));
        Long ttl = ttlClaim == null ? null : integer(ttlClaim, "ttl");
        CBORObject statusList = claim(payload, CLAIM_STATUS_LIST, "status list");
        if (statusList.getType() != CBORType.Map) {
            throw refuse("claim 65533 (status_list) is a " + statusList.getType() + ", not a StatusList map");
        }
        CBORObject bits = statusList.get(CBORObject.FromObject("bits"));
        if (bits == null) {
            throw refuse("claim 65533 (status_list) has no bits");
        }
        if (integer(bits, "bits") != BITS) {
            throw refuse("status_list.bits is " + bits + "; an mDoc status list carries one bit per index"
                    + " (ISO/IEC 18013-5 second edition 12.3.6.5)");
        }
        CBORObject lst = statusList.get(CBORObject.FromObject("lst"));
        if (lst == null) {
            throw refuse("claim 65533 (status_list) has no lst");
        }
        return new Decoded(sub.AsString(), iat, exp, ttl, BITS, bytes(lst, "status_list.lst"), x5chain);
    }

    private static CBORObject claim(CBORObject payload, int label, String name) {
        CBORObject value = payload.get(CBORObject.FromObject(label));
        if (value == null) {
            throw refuse("no claim " + label + " (" + name + "), which a Status List Token carries (TSL section 5.2)");
        }
        return value;
    }

    private static Instant instant(CBORObject value, String name) {
        return Instant.ofEpochSecond(integer(value, name));
    }

    private static long integer(CBORObject value, String name) {
        if (value.getType() != CBORType.Integer) {
            throw refuse(name + " is a " + value.getType() + ", not an integer (RFC 8392 section 3.1)");
        }
        return value.AsInt64();
    }

    private static byte[] bytes(CBORObject value, String what) {
        if (value == null || value.getType() != CBORType.ByteString) {
            throw refuse(what + " is " + (value == null ? "absent" : "a " + value.getType()) + ", not a bstr");
        }
        return value.GetByteString();
    }

    /** RFC 9360 section 2: one certificate as a single {@code bstr}, several as an array of {@code bstr}, end-entity first. */
    private static List<X509Certificate> certificates(CBORObject value) {
        List<byte[]> der = new ArrayList<>();
        if (value.getType() == CBORType.ByteString) {
            der.add(value.GetByteString());
        } else if (value.getType() == CBORType.Array) {
            for (int index = 0; index < value.size(); index++) {
                der.add(bytes(value.get(index), "an x5chain entry"));
            }
        } else {
            throw refuse("the protected x5chain (label 33) is a " + value.getType() + ", not a bstr or an array of bstr");
        }
        if (der.isEmpty()) {
            throw refuse("the protected x5chain (label 33) is empty; a Status List Token names its signer there"
                    + " (TSL section 11.3)");
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certificates = new ArrayList<>(der.size());
            for (byte[] encoded : der) {
                certificates.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encoded)));
            }
            return certificates;
        } catch (java.security.cert.CertificateException e) {
            throw refuse("an x5chain entry is not an X.509 certificate: " + e.getMessage());
        }
    }

    private static CBORObject cbor(byte[] encoded) {
        try {
            return CBORObject.DecodeFromBytes(encoded);
        } catch (RuntimeException e) {
            throw refuse("the bytes are not CBOR: " + e.getMessage());
        }
    }

    private static IllegalStateException refuse(String reason) {
        return new IllegalStateException("Not a CWT Status List Token: " + reason);
    }
}
