package io.mosip.certify.status;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import io.mosip.certify.signing.CertificateChain;
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
 * <p><b>{@link #encode} is the only way this code signs a status-list CWT, and it always runs
 * {@link StatusListSignerPolicy#check} first</b>: an expired, revoked, untrusted or wrongly-purposed signer is refused
 * before the envelope is built, and both the policy's {@link IllegalStateException} and M-11a's
 * {@link SigningException}s carrying a {@code STATUS_SIGNER_} prefix come out through
 * {@link StatusListSignerPolicy#refusal} in one shape. There is no public path around it.
 *
 * <p>{@link #decode} reads a token back without verifying its signature: it is the codec, not a verifier. It does
 * refuse anything that is not this profile — so a stored or served token cannot silently change shape — including
 * malformed COSE (extra or nested tags, a non-map unprotected header, a label in both header buckets, a missing
 * {@code alg}, a non-{@code bstr} payload or signature), a {@code ttl} that is not a positive integer, an
 * {@code exp} that is not after {@code iat}, and an {@code lst} that does not inflate as zlib within the size ceiling.
 * Floating-point NumericDates are refused too: RFC 8392 permits them, Certify never writes them, and a token that
 * carried one would not be one of ours.
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

    /**
     * The size ceiling {@link #decode(byte[])} applies to an inflated {@code lst}: eight times the largest configured
     * list ({@code certify.status.token-status-list.size-bits} defaults to 131072), i.e. 1 MiB of bits. A stream that
     * inflates past it is refused before it is allocated, so a decompression bomb in a stored or fetched token cannot
     * exhaust the heap; a caller that knows its configured size passes it to {@link #decode(byte[], int)}.
     */
    public static final int MAX_BITS = 1 << 23;

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
     * Signs a status list as a CWT, after holding the signer to {@link StatusListSignerPolicy}.
     *
     * @param sub     the {@code status_list.uri} of the Referenced Tokens this list answers for (claim 2, TSL section
     *                8.3 step 4a)
     * @param iat     the signing instant, in whole seconds (claim 6)
     * @param exp     when the token expires, in whole seconds, later than {@code iat} and never later than the signer
     *                certificate's {@code notAfter} (claim 4 is REQUIRED for an mDoc list, ISO2 12.3.6.3; section 4.1)
     * @param ttl     how long a verifier may cache the list (claim 65534); its whole seconds must be positive
     * @param bits    the bit array, one bit per index, least significant bit first
     * @param signing the signer
     * @param policy  the signer policy, with the configured IACA anchors, CRLs and stale-CRL grace
     * @param now     the instant the policy judges validity, revocation and CRL freshness at
     * @param mode    which extended key usage the signer needs (the mDL Document Signer's or a dedicated signer's)
     * @throws IllegalArgumentException when a claim could not be represented faithfully, so no ambiguous token is signed
     * @throws IllegalStateException    a policy refusal (the message starts with its rule), or a {@code STATUS_SIGNER_}
     *                                  refusal of M-11a's envelope mapped by {@link StatusListSignerPolicy#refusal}
     */
    public static byte[] encode(String sub, Instant iat, Instant exp, Duration ttl, byte[] bits,
                                SigningContext signing, StatusListSignerPolicy policy, Instant now,
                                StatusListSignerPolicy.Mode mode) {
        Objects.requireNonNull(signing, "signing");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(mode, "mode");
        if (sub == null || sub.isBlank()) {
            throw new IllegalArgumentException("A status list names the uri of its Referenced Tokens (claim 2, TSL section 8.3)");
        }
        Objects.requireNonNull(iat, "iat");
        Objects.requireNonNull(exp, "exp");
        if (exp.getEpochSecond() <= iat.getEpochSecond()) {
            throw new IllegalArgumentException("exp " + exp + " must be later than iat " + iat
                    + ": a token is not signed already expired, and both claims are whole seconds (RFC 8392 section 2)");
        }
        if (ttl == null || ttl.getSeconds() < 1) {
            throw new IllegalArgumentException("ttl must be at least one second, got " + ttl
                    + ": TSL section 5.2 makes the time to live a positive unsigned integer");
        }
        Objects.requireNonNull(bits, "bits");

        try {
            // mandatory, before anything is encoded or signed: no public path signs a status-list CWT without it
            policy.check(signing, now, mode);
            X509Certificate leaf = leaf(signing);
            Instant notAfter = leaf.getNotAfter().toInstant();
            if (exp.isAfter(notAfter)) {
                throw new IllegalArgumentException("exp " + exp + " is after the signer certificate's notAfter " + notAfter
                        + "; a list is not signed to outlive the certificate that signs it (section 4.1, D7)");
            }
            LinkedHashMap<Integer, CBORObject> claims = new LinkedHashMap<>();
            claims.put(CLAIM_SUB, CBORObject.FromObject(sub));
            claims.put(CLAIM_EXP, CBORObject.FromObject(exp.getEpochSecond()));
            claims.put(CLAIM_IAT, CBORObject.FromObject(iat.getEpochSecond()));
            claims.put(CLAIM_STATUS_LIST, statusList(bits));
            claims.put(CLAIM_TTL, CBORObject.FromObject(ttl.getSeconds()));
            return CwtEnvelope.signOrdered(claims, CoseHeaderPolicy.statusListCwt(), signing.key(), signing.signer());
        } catch (RuntimeException e) {
            // the policy's IllegalStateException and M-11a's STATUS_SIGNER_ SigningException become one shape; a
            // caller's own IllegalArgumentException keeps its type (refusal returns it unchanged)
            throw StatusListSignerPolicy.refusal(e);
        }
    }

    /**
     * TSL section 4.3's {@code StatusList = {bits: 1, lst: bstr}}: RFC 8949 section 4.2.1 order, {@code lst} first.
     */
    private static CBORObject statusList(byte[] bits) {
        return CBORObject.NewOrderedMap()
                .Add(CBORObject.FromObject("lst"), CBORObject.FromObject(TokenStatusListService.zlib(bits)))
                .Add(CBORObject.FromObject("bits"), CBORObject.FromObject(BITS));
    }

    private static X509Certificate leaf(SigningContext signing) {
        CertificateChain chain = signing.key().chain();
        if (chain == null || chain.isEmpty() || chain.leaf().isEmpty()) {
            throw new IllegalStateException(StatusListSignerPolicy.NO_CHAIN + ": the key " + signing.key().ref()
                    + " has no certificate");
        }
        return chain.leaf().orElseThrow();
    }

    /** As {@link #decode(byte[], int)} with the ceiling {@link #MAX_BITS}. */
    public static Decoded decode(byte[] token) {
        return decode(token, MAX_BITS);
    }

    /**
     * Reads a CWT Status List Token back, without verifying its signature (TSL section 5.2; ISO2 12.3.6.3).
     *
     * @param maxBits the largest list this caller accepts, in bits; the {@code lst} must inflate to at most
     *                {@code maxBits / 8} bytes (a multiple of 8, positive)
     * @throws IllegalStateException when the bytes are not this profile: not exactly one tag 18 around an untagged
     *                               four-element COSE_Sign1 with a {@code bstr} payload and signature, a non-map or
     *                               missing protected/unprotected header, a label in both headers (RFC 9052 section 3),
     *                               no protected {@code alg} 1, no protected {@code typ} 16 equal to
     *                               {@value #MEDIA_TYPE}, no protected {@code x5chain} 33, a missing claim 2/6/4/65533,
     *                               an {@code exp} not after {@code iat}, a {@code ttl} that is not a positive
     *                               unsigned integer, {@code bits} other than 1, or an {@code lst} that is not zlib
     *                               data within {@code maxBits}
     */
    public static Decoded decode(byte[] token, int maxBits) {
        Objects.requireNonNull(token, "token");
        if (maxBits <= 0 || maxBits % 8 != 0) {
            throw new IllegalArgumentException("maxBits must be a positive multiple of 8, got " + maxBits);
        }
        CBORObject outer = cbor(token);
        if (!outer.isTagged()) {
            throw refuse("untagged; a Status List Token is COSE_Sign1_Tagged (18) (TSL section 5.2)");
        }
        if (!String.valueOf(CoseEnvelope.TAG_COSE_SIGN1).equals(outer.getMostOuterTag().toString())) {
            // a CWT tag 61 around a COSE_Sign1 is the shape TSL section 5.2 forbids
            throw refuse("tagged " + outer.getMostOuterTag() + ", not 18 (a Status List Token is never tag 61,"
                    + " TSL section 5.2)");
        }
        CBORObject sign1 = outer.UntagOne();
        if (sign1.isTagged()) {
            // 18(18(…)) or 18(61(…)): exactly one tag 18 around an untagged COSE_Sign1 (RFC 9052 section 4.2)
            throw refuse("more than one tag; exactly one tag 18 wraps an untagged COSE_Sign1 (RFC 9052 section 4.2)");
        }
        if (sign1.getType() != CBORType.Array || sign1.size() != 4) {
            throw refuse("the tag wraps " + (sign1.getType() == CBORType.Array
                    ? "an array of " + sign1.size() : "a " + sign1.getType()) + ", not a four-element COSE_Sign1");
        }
        CBORObject protectedHeader = cbor(bytes(sign1.get(0), "the protected header"));
        if (protectedHeader.getType() != CBORType.Map) {
            throw refuse("the protected header is a " + protectedHeader.getType() + ", not a map");
        }
        CBORObject unprotectedHeader = sign1.get(1);
        if (unprotectedHeader == null || unprotectedHeader.getType() != CBORType.Map) {
            throw refuse("the unprotected header is " + (unprotectedHeader == null ? "absent" : "a "
                    + unprotectedHeader.getType()) + ", not a map");
        }
        for (CBORObject label : unprotectedHeader.getKeys()) {
            if (protectedHeader.ContainsKey(label)) {
                throw refuse("label " + label + " is in both the protected and the unprotected header, which RFC 9052"
                        + " section 3 forbids");
            }
        }
        CBORObject alg = protectedHeader.get(CBORObject.FromObject(CoseEnvelope.LABEL_ALG));
        if (alg == null || alg.getType() != CBORType.Integer) {
            throw refuse("no protected alg (label 1) as an integer; RFC 9052 section 3 requires the algorithm to be"
                    + " integrity protected");
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
        bytes(sign1.get(3), "the signature");

        CBORObject sub = claim(payload, CLAIM_SUB, "sub");
        if (sub.getType() != CBORType.TextString) {
            throw refuse("claim 2 (sub) is a " + sub.getType() + ", not the uri text");
        }
        Instant iat = instant(claim(payload, CLAIM_IAT, "iat"), "iat");
        Instant exp = instant(claim(payload, CLAIM_EXP, "exp"), "exp");
        if (!exp.isAfter(iat)) {
            throw refuse("exp " + exp + " is not after iat " + iat + "; a Status List Token is not issued already"
                    + " expired (RFC 8392 section 2)");
        }
        CBORObject ttlClaim = payload.get(CBORObject.FromObject(CLAIM_TTL));
        Long ttl = null;
        if (ttlClaim != null) {
            long seconds = unsigned(ttlClaim, "ttl");
            if (seconds < 1) {
                throw refuse("ttl is " + seconds + "; TSL section 5.2 makes the time to live a positive unsigned"
                        + " integer");
            }
            ttl = seconds;
        }
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
        byte[] bitArray;
        try {
            bitArray = TokenStatusListService.inflate(bytes(lst, "status_list.lst"), maxBits / 8);
        } catch (IllegalStateException e) {
            throw refuse("status_list.lst is not a usable zlib stream: " + e.getMessage(), e);
        }
        return new Decoded(sub.AsString(), iat, exp, ttl, BITS, bitArray, x5chain);
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

    /**
     * An integer claim. Floating-point NumericDates are refused: RFC 8392 section 2 permits them, but Certify never
     * writes one and a token carrying one is not one of its lists. A uint64 above {@code Long.MAX_VALUE} is refused as
     * an {@link IllegalStateException} too, never as an {@link ArithmeticException} escaping to the caller.
     */
    private static long integer(CBORObject value, String name) {
        if (value.getType() != CBORType.Integer) {
            throw refuse(name + " is a " + value.getType() + ", not an integer (RFC 8392 section 3.1)");
        }
        try {
            return value.AsInt64();
        } catch (ArithmeticException e) {
            throw refuse(name + " " + value + " is outside the signed 64-bit range Certify reads", e);
        }
    }

    /** An unsigned integer claim: a negative value is refused rather than reinterpreted. */
    private static long unsigned(CBORObject value, String name) {
        long number = integer(value, name);
        if (number < 0) {
            throw refuse(name + " is " + number + ", which is not an unsigned integer");
        }
        return number;
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

    private static IllegalStateException refuse(String reason, Throwable cause) {
        return new IllegalStateException("Not a CWT Status List Token: " + reason, cause);
    }
}
