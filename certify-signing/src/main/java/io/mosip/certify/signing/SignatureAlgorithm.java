package io.mosip.certify.signing;

import java.util.Arrays;
import java.util.Optional;

/**
 * Signature algorithms Certify can ask a {@link Signer} for, with every identifier the different
 * specifications use for the same primitive. {@link #joseName()} is the canonical identifier in
 * configuration; the others are looked up through {@link AlgorithmRegistry}.
 */
public enum SignatureAlgorithm {
    RS256("RS256", -257, "SHA256withRSA", null, SignatureFormat.PKCS1, 0),
    PS256("PS256", -37, "SHA256withRSAandMGF1", null, SignatureFormat.PSS, 0),
    ES256("ES256", -7, "SHA256withECDSA", "P-256", SignatureFormat.EC_CONCAT, 64),
    ES256K("ES256K", -47, "SHA256withECDSA", "secp256k1", SignatureFormat.EC_CONCAT, 64),
    ES384("ES384", -35, "SHA384withECDSA", "P-384", SignatureFormat.EC_CONCAT, 96),
    ES512("ES512", -36, "SHA512withECDSA", "P-521", SignatureFormat.EC_CONCAT, 132),
    EdDSA("EdDSA", -8, "Ed25519", "Ed25519", SignatureFormat.RAW, 64);

    /** How {@link Signer#signRaw} must encode the signature bytes: the JOSE/COSE wire form, never DER. */
    public enum SignatureFormat { PKCS1, PSS, EC_CONCAT, RAW }

    private final String joseName;
    private final int coseId;
    private final String jcaName;
    private final String curve;
    private final SignatureFormat format;
    private final int concatLength;

    SignatureAlgorithm(String joseName, int coseId, String jcaName, String curve, SignatureFormat format, int concatLength) {
        this.joseName = joseName;
        this.coseId = coseId;
        this.jcaName = jcaName;
        this.curve = curve;
        this.format = format;
        this.concatLength = concatLength;
    }

    /** RFC 7518 name, e.g. {@code ES256}. */
    public String joseName() { return joseName; }

    /** RFC 9053 COSE algorithm identifier, e.g. {@code -7}. */
    public int coseId() { return coseId; }

    /** {@link java.security.Signature} algorithm name. */
    public String jcaName() { return jcaName; }

    /** JOSE curve name for EC and OKP keys, {@code null} for RSA. */
    public String curve() { return curve; }

    public SignatureFormat format() { return format; }

    /** Length of the R||S concatenation for EC algorithms, 0 otherwise. */
    public int concatLength() { return concatLength; }

    public boolean isEc() { return format == SignatureFormat.EC_CONCAT; }

    public boolean isRsa() { return format == SignatureFormat.PKCS1 || format == SignatureFormat.PSS; }

    public static Optional<SignatureAlgorithm> fromJose(String joseName) {
        return Arrays.stream(values()).filter(a -> a.joseName.equalsIgnoreCase(joseName)).findFirst();
    }

    public static Optional<SignatureAlgorithm> fromCose(int coseId) {
        return Arrays.stream(values()).filter(a -> a.coseId == coseId).findFirst();
    }
}
