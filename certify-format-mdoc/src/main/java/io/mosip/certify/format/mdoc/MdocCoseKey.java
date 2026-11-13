package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.ipfs.multibase.Multibase;
import io.mosip.certify.spi.FormatException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The {@code deviceKey} of the MSO: a COSE_Key (RFC 9052 section 7, RFC 9053) built from the holder key the proof
 * carried (docs/design/20-mdl-issuer.md D4, G6). Accepted forms:
 *
 * <ul>
 *   <li>{@code did:jwk:<base64url JWK>} — what {@code JwtProofValidatorAdapter} produces from a {@code jwk} header;</li>
 *   <li>{@code did:key:<multibase>} — the multicodec-prefixed public key of the did:key method (Ed25519 {@code 0xed01},
 *       NIST P-256/P-384/P-521 {@code 0x1200}/{@code 0x1201}/{@code 0x1202}, compressed or uncompressed);</li>
 *   <li>a raw public JWK as JSON, for callers that hand the key over directly.</li>
 * </ul>
 *
 * <p>EC2 maps kty 1:2, curve -1:1 (P-256) / 2 (P-384) / 3 (P-521) and the fixed-width coordinates -2 (x), -3 (y);
 * OKP maps kty 1:1 and curve -1:6 (Ed25519) with -2 (x). No {@code alg} label is written: the device key is not
 * bound to one JOSE algorithm (ISO/IEC 18013-5 9.1.2.4 allows the holder to choose among 9.1.5.2's curves).
 * A key that cannot be encoded is {@link MdocConstants#ERROR_HOLDER_KEY}, which the core answers as
 * OpenID4VCI {@code invalid_proof}.
 */
final class MdocCoseKey {

    static final int LABEL_KTY = 1;
    static final int LABEL_CURVE = -1;
    static final int LABEL_X = -2;
    static final int LABEL_Y = -3;

    static final int KTY_OKP = 1;
    static final int KTY_EC2 = 2;
    static final int CURVE_P256 = 1;
    static final int CURVE_P384 = 2;
    static final int CURVE_P521 = 3;
    static final int CURVE_ED25519 = 6;

    private static final int ED25519_KEY_LENGTH = 32;
    private static final byte[] ED25519_MULTICODEC = {(byte) 0xed, (byte) 0x01};
    private static final byte[][] NIST_MULTICODEC = {{(byte) 0x80, (byte) 0x24}, {(byte) 0x81, (byte) 0x24}, {(byte) 0x82, (byte) 0x24}};
    private static final String[] NIST_CURVE_NAME = {"secp256r1", "secp384r1", "secp521r1"};
    private static final int[] NIST_COORDINATE_LENGTH = {32, 48, 66};

    private MdocCoseKey() {}

    /** The COSE_Key for the holder the proof established, or {@link MdocConstants#ERROR_HOLDER_KEY}. */
    static Map<Object, Object> fromHolder(String holderValue, ObjectMapper objectMapper) {
        if (holderValue == null || holderValue.isBlank()) {
            throw holderKeyError("the mDoc MSO needs a holder device key but the proof established none");
        }
        String value = holderValue.trim();
        try {
            if (value.startsWith(MdocConstants.DID_JWK_PREFIX)) {
                return fromJwk(objectMapper.readTree(decodeDidJwk(value)));
            }
            if (value.startsWith(MdocConstants.DID_KEY_PREFIX)) {
                return fromMultibase(multibasePart(value));
            }
            if (value.startsWith("{")) {
                return fromJwk(objectMapper.readTree(value));
            }
        } catch (FormatException e) {
            throw e;
        } catch (IOException e) {
            // the JWK JSON could not be read: JsonParseException/JsonMappingException (the caller chose the key)
            throw holderKeyError("the holder key " + abbreviate(value) + " is not a readable JWK: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            // base64url/base58 decoding and BouncyCastle point decoding report malformed keys this way
            throw holderKeyError("the holder key " + abbreviate(value) + " could not be encoded as a COSE_Key: " + e.getMessage());
        }
        throw holderKeyError("the holder key " + abbreviate(value) + " is not a did:jwk, a did:key or a JWK");
    }

    /** The COSE_Key for a public JWK: EC2 over P-256/P-384/P-521, or OKP over Ed25519. */
    static Map<Object, Object> fromJwk(JsonNode jwk) {
        if (jwk == null || !jwk.isObject()) {
            throw holderKeyError("the holder key is not a JWK object");
        }
        String kty = text(jwk, "kty");
        Map<Object, Object> coseKey = new LinkedHashMap<>();
        if ("EC".equals(kty)) {
            int curve = switch (String.valueOf(text(jwk, "crv"))) {
                case "P-256" -> CURVE_P256;
                case "P-384" -> CURVE_P384;
                case "P-521" -> CURVE_P521;
                default -> throw holderKeyError("the holder's EC key is on curve " + text(jwk, "crv")
                        + "; an mDL device key is P-256, P-384 or P-521 (ISO/IEC 18013-5 9.1.5.2)");
            };
            int width = NIST_COORDINATE_LENGTH[curve - 1];
            byte[] x = fixedWidth(decodeCoordinate(text(jwk, "x"), "x"), width, "x");
            byte[] y = fixedWidth(decodeCoordinate(text(jwk, "y"), "y"), width, "y");
            requireOnCurve(curve, x, y);
            coseKey.put(LABEL_KTY, KTY_EC2);
            coseKey.put(LABEL_CURVE, curve);
            coseKey.put(LABEL_X, x);
            coseKey.put(LABEL_Y, y);
            return coseKey;
        }
        if ("OKP".equals(kty)) {
            if (!"Ed25519".equals(text(jwk, "crv"))) {
                throw holderKeyError("the holder's OKP key is on curve " + text(jwk, "crv")
                        + "; an mDL device key is Ed25519 (ISO/IEC 18013-5 9.1.5.2)");
            }
            byte[] x = decodeCoordinate(text(jwk, "x"), "x");
            if (x.length != ED25519_KEY_LENGTH) {
                // RFC 8032: an Ed25519 public key is exactly 32 bytes; zero-padding would invent a different key
                throw holderKeyError("the holder JWK Ed25519 x is " + x.length + " bytes, expected " + ED25519_KEY_LENGTH);
            }
            requireEd25519Point(x);
            coseKey.put(LABEL_KTY, KTY_OKP);
            coseKey.put(LABEL_CURVE, CURVE_ED25519);
            coseKey.put(LABEL_X, x);
            return coseKey;
        }
        throw holderKeyError("the holder key is a " + kty + " key; an mDL device key is EC2 (P-256/384/521) or OKP (Ed25519)");
    }

    /** The COSE_Key for a did:key multibase string: a multicodec prefix plus the raw public key. */
    static Map<Object, Object> fromMultibase(String multibase) {
        byte[] decoded;
        try {
            decoded = Multibase.decode(multibase);
        } catch (IllegalArgumentException | IllegalStateException | IndexOutOfBoundsException e) {
            throw holderKeyError("the did:key " + abbreviate(multibase) + " is not valid multibase: " + e.getMessage());
        }
        if (decoded.length > 2 && Arrays.equals(Arrays.copyOf(decoded, 2), ED25519_MULTICODEC)) {
            if (decoded.length != 2 + ED25519_KEY_LENGTH) {
                throw holderKeyError("the did:key Ed25519 key is " + (decoded.length - 2) + " bytes, expected " + ED25519_KEY_LENGTH);
            }
            byte[] x = Arrays.copyOfRange(decoded, 2, decoded.length);
            requireEd25519Point(x);
            Map<Object, Object> coseKey = new LinkedHashMap<>();
            coseKey.put(LABEL_KTY, KTY_OKP);
            coseKey.put(LABEL_CURVE, CURVE_ED25519);
            coseKey.put(LABEL_X, x);
            return coseKey;
        }
        for (int curve = CURVE_P256; curve <= CURVE_P521; curve++) {
            if (decoded.length > 2 && Arrays.equals(Arrays.copyOf(decoded, 2), NIST_MULTICODEC[curve - 1])) {
                return fromCompressedPoint(curve, Arrays.copyOfRange(decoded, 2, decoded.length));
            }
        }
        if (decoded.length >= 2 && decoded[0] == (byte) 0xe7 && decoded[1] == 0x01) {
            throw holderKeyError("the did:key is a secp256k1 key; an mDL device key is P-256, P-384, P-521 or Ed25519"
                    + " (ISO/IEC 18013-5 9.1.5.2)");
        }
        throw holderKeyError("the did:key " + abbreviate(multibase) + " carries no supported multicodec public key");
    }

    private static Map<Object, Object> fromCompressedPoint(int curve, byte[] point) {
        int width = NIST_COORDINATE_LENGTH[curve - 1];
        if (point.length != 1 + 2 * width && point.length != 1 + width) {
            throw holderKeyError("the did:key P-" + (curve == CURVE_P256 ? "256" : curve == CURVE_P384 ? "384" : "521")
                    + " point is " + point.length + " bytes; expected a compressed or uncompressed point");
        }
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec(NIST_CURVE_NAME[curve - 1]).getCurve();
        ECPoint decoded;
        try {
            decoded = ecCurve.decodePoint(point);
        } catch (IllegalArgumentException e) {
            throw holderKeyError("the did:key point is not on " + NIST_CURVE_NAME[curve - 1] + ": " + e.getMessage());
        }
        Map<Object, Object> coseKey = new LinkedHashMap<>();
        coseKey.put(LABEL_KTY, KTY_EC2);
        coseKey.put(LABEL_CURVE, curve);
        coseKey.put(LABEL_X, BigIntegers.asUnsignedByteArray(width, decoded.getAffineXCoord().toBigInteger()));
        coseKey.put(LABEL_Y, BigIntegers.asUnsignedByteArray(width, decoded.getAffineYCoord().toBigInteger()));
        return coseKey;
    }

    private static String decodeDidJwk(String didJwk) {
        String encoded = didJwk.substring(MdocConstants.DID_JWK_PREFIX.length());
        int fragment = encoded.indexOf('#');
        if (fragment > 0) {
            encoded = encoded.substring(0, fragment);
        }
        return new String(Base64.getUrlDecoder().decode(encoded), java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String multibasePart(String didKey) {
        String multibase = didKey.substring(MdocConstants.DID_KEY_PREFIX.length());
        int fragment = multibase.indexOf('#');
        return fragment > 0 ? multibase.substring(0, fragment) : multibase;
    }

    private static String text(JsonNode jwk, String field) {
        JsonNode node = jwk.get(field);
        return node == null || node.isNull() ? null : node.asText();
    }

    /** A JWK coordinate or key: base64url, unpadded (its length is checked by the caller). */
    private static byte[] decodeCoordinate(String encoded, String field) {
        if (encoded == null || encoded.isBlank()) {
            throw holderKeyError("the holder JWK has no " + field + " coordinate");
        }
        try {
            return Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException unpadded) {
            try {
                return Base64.getUrlDecoder().decode(encoded + "=".repeat((4 - encoded.length() % 4) % 4));
            } catch (IllegalArgumentException e) {
                throw holderKeyError("the holder JWK " + field + " is not base64url: " + e.getMessage());
            }
        }
    }

    /** A raw-JWK EC point must be a point of its curve; otherwise the COSE_Key is not a usable public key. */
    private static void requireOnCurve(int curve, byte[] x, byte[] y) {
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec(NIST_CURVE_NAME[curve - 1]).getCurve();
        ECPoint point;
        try {
            point = ecCurve.createPoint(new BigInteger(1, x), new BigInteger(1, y));
        } catch (IllegalArgumentException e) {
            point = null;
        }
        if (point == null || point.isInfinity() || !point.isValid()) {
            throw holderKeyError("the holder's P-" + (curve == CURVE_P256 ? "256" : curve == CURVE_P384 ? "384" : "521")
                    + " point is not on " + NIST_CURVE_NAME[curve - 1]);
        }
    }

    /**
     * RFC 7518 6.2.1.2/6.2.1.3: an EC coordinate MUST be the full width of the field, leading zeros included. A shorter
     * value is a malformed JWK and is refused, not padded: the issuer would otherwise sign a key the holder never stated.
     */
    private static byte[] fixedWidth(byte[] coordinate, int width, String field) {
        if (coordinate.length != width) {
            throw holderKeyError("the holder JWK " + field + " coordinate is " + coordinate.length + " bytes, expected exactly "
                    + width + " (RFC 7518 6.2.1.2)");
        }
        return coordinate;
    }

    /**
     * An Ed25519 public key must decode to a point of the prime-order subgroup (RFC 8032 5.1.3; BouncyCastle's full
     * validation also refuses non-canonical encodings and small-order points): otherwise no signature could ever verify
     * under the device key the MSO would carry.
     */
    private static void requireEd25519Point(byte[] x) {
        if (!org.bouncycastle.math.ec.rfc8032.Ed25519.validatePublicKeyFull(x, 0)) {
            throw holderKeyError("the holder's Ed25519 key is not a valid Ed25519 public key (RFC 8032 5.1.3)");
        }
    }

    private static FormatException holderKeyError(String message) {
        return new FormatException(MdocConstants.ERROR_HOLDER_KEY, message);
    }

    private static String abbreviate(String value) {
        return value.length() <= 48 ? value : value.substring(0, 24) + "..." + value.substring(value.length() - 12);
    }

    /** Exposed for the validator's message: the curve name of a COSE_Key, or {@code null} for a non-EC2 key. */
    static String curveName(Map<Object, Object> coseKey) {
        Object curve = coseKey.get(LABEL_CURVE);
        if (!(curve instanceof Integer id)) {
            return null;
        }
        return switch (id) {
            case CURVE_P256 -> "P-256";
            case CURVE_P384 -> "P-384";
            case CURVE_P521 -> "P-521";
            case CURVE_ED25519 -> "Ed25519";
            default -> null;
        };
    }
}
