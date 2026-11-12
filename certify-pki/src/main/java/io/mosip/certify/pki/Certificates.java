package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * DER, extension, name and signature helpers shared by the Annex B builders, the CSR parser and the validator.
 * BouncyCastle is used as an explicit provider instance rather than installed in {@code java.security}, so the library
 * changes no global state.
 *
 * <p>The curve allowlist is a choice of this module, not the text of the standard: ISO/IEC 18013-5 also lists brainpool
 * curves, which this profile excludes for now (decision log, 2026-11-13). P-256, P-384 and P-521 are accepted; brainpool,
 * secp256k1 and explicit curve parameters are refused here rather than checked at each call site.
 */
final class Certificates {

    static final ASN1ObjectIdentifier ECDSA_WITH_SHA256 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.2");
    static final ASN1ObjectIdentifier ECDSA_WITH_SHA384 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.3");
    static final ASN1ObjectIdentifier ECDSA_WITH_SHA512 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.4");

    static final ASN1ObjectIdentifier P256 = SECObjectIdentifiers.secp256r1;
    static final ASN1ObjectIdentifier P384 = SECObjectIdentifiers.secp384r1;
    static final ASN1ObjectIdentifier P521 = SECObjectIdentifiers.secp521r1;

    /** The named curves this module allows (decision log, 2026-11-13), each with the {@code ecdsa-with-SHA*} signature algorithm it signs with. */
    static final Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> CURVES = curveTable();

    private static final Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> SIGNATURES = signatureTable();

    /** RFC 5322 dot-atom text: one atom of a local part. */
    private static final Pattern ATOM = Pattern.compile("[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+");

    /** RFC 1035/5321 letter-digit-hyphen label of at most 63 octets. */
    private static final Pattern LABEL = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?");

    private static final Provider BC = new BouncyCastleProvider();

    private Certificates() {}

    static Provider provider() {
        return BC;
    }

    // ---------------------------------------------------------------- names

    /** The DER encoding of a name, for byte-equality comparisons that must not depend on re-encoding. */
    static byte[] der(X500Name name) {
        try {
            return name.getEncoded();
        } catch (IOException e) {
            throw new PkiException("Cannot encode the name", e);
        }
    }

    /** Whether two names have the same DER encoding; a name that cannot be encoded equals nothing. */
    static boolean sameName(X500Name a, X500Name b) {
        try {
            return Arrays.equals(a.getEncoded(), b.getEncoded());
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /** Every attribute of the given type anywhere in the name: every RDN, every member of a multi-valued RDN. */
    static List<AttributeTypeAndValue> attributes(X500Name name, ASN1ObjectIdentifier type) {
        List<AttributeTypeAndValue> attributes = new ArrayList<>();
        for (RDN rdn : name.getRDNs()) {
            for (AttributeTypeAndValue value : rdn.getTypesAndValues()) {
                if (value.getType().equals(type)) {
                    attributes.add(value);
                }
            }
        }
        return attributes;
    }

    /** The first value of an attribute anywhere in the name, as its ASN.1 value, or {@code null} when there is none. */
    static ASN1Encodable value(X500Name name, ASN1ObjectIdentifier type) {
        List<AttributeTypeAndValue> attributes = attributes(name, type);
        return attributes.isEmpty() ? null : attributes.get(0).getValue();
    }

    /**
     * The decoded value of a directory string attribute, whatever its ASN.1 string type: never an escaped form. Returns
     * {@code null} when the value cannot be decoded (a UTF8String that is not UTF-8, for one), so a caller reports it
     * instead of throwing.
     */
    static String string(ASN1Encodable value) {
        try {
            return value instanceof ASN1String string ? string.getString() : value.toString();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The decoded first value of an attribute, or {@code null} when the name has none or it cannot be decoded. */
    static String attribute(X500Name name, ASN1ObjectIdentifier type) {
        ASN1Encodable value = value(name, type);
        return value == null ? null : string(value);
    }

    /**
     * Whether two attribute values are the same: equal decoded strings when both decode, equal DER otherwise, so an
     * undecodable value is never equal to a different one and never throws.
     */
    static boolean sameValue(ASN1Encodable a, ASN1Encodable b) {
        String left = string(a);
        String right = string(b);
        if (left != null && right != null) {
            return left.equals(right);
        }
        try {
            return Arrays.equals(a.toASN1Primitive().getEncoded(), b.toASN1Primitive().getEncoded());
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /** The subject of a certificate, read from its DER. */
    static X500Name subject(X509Certificate certificate) {
        return Parsed.certificate(certificate).subject();
    }

    /** The issuer of a certificate, read from its DER. */
    static X500Name issuer(X509Certificate certificate) {
        return Parsed.certificate(certificate).issuer();
    }

    // ----------------------------------------------------------- extensions

    /** The DER value inside an extension's OCTET STRING, or {@code null} when the certificate does not carry it. */
    static byte[] extension(Parsed.Cert certificate, ASN1ObjectIdentifier oid) {
        Extension extension = certificate.extension(oid);
        return extension == null ? null : extension.getExtnValue().getOctets();
    }

    static byte[] extension(X509Certificate certificate, ASN1ObjectIdentifier oid) {
        return extension(Parsed.certificate(certificate), oid);
    }

    /**
     * The SKI a certificate declares, and the RFC 5280 method 1 value of its key when it declares none. A declared SKI
     * that is not exactly one OCTET STRING is refused with {@link PkiException}.
     */
    static byte[] keyIdentifier(Parsed.Cert certificate) {
        byte[] declared = extension(certificate, Extension.subjectKeyIdentifier);
        if (declared == null) {
            return keyIdentifier(certificate.spki());
        }
        try {
            return ASN1OctetString.getInstance(Parsed.strict(declared)).getOctets();
        } catch (IOException | RuntimeException e) {
            throw new PkiException("the subject key identifier cannot be read: " + Parsed.describe(e), e);
        }
    }

    static byte[] keyIdentifier(X509Certificate certificate) {
        return keyIdentifier(Parsed.certificate(certificate));
    }

    /** The AuthorityKeyIdentifier keyIdentifier of a certificate, or {@code null} when absent. */
    static byte[] authorityKeyIdentifier(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.authorityKeyIdentifier);
        return extension == null ? null : AuthorityKeyIdentifier.getInstance(extension).getKeyIdentifier();
    }

    /** The subjectPublicKeyInfo a JCA key encodes to; a key that cannot be encoded is refused with {@code rule}. */
    static SubjectPublicKeyInfo spki(PublicKey key, String rule) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(key.getEncoded());
            if (spki == null) {
                throw new IllegalArgumentException("the key has no X.509 encoding");
            }
            return spki;
        } catch (RuntimeException e) {
            throw new PkiException(rule + ": the public key cannot be read: " + Parsed.describe(e), e);
        }
    }

    static SubjectPublicKeyInfo spki(PublicKey key) {
        return spki(key, "KEY_INVALID");
    }

    /** Whether a JCA public key encodes to exactly the given subjectPublicKeyInfo. */
    static boolean sameKey(SubjectPublicKeyInfo expected, PublicKey key) {
        try {
            return Arrays.equals(expected.getEncoded(ASN1Encoding.DER),
                    SubjectPublicKeyInfo.getInstance(key.getEncoded()).getEncoded(ASN1Encoding.DER));
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /** The RFC 5280 section 4.2.1.2 method 1 key identifier: SHA-1 over the subjectPublicKey BIT STRING contents. */
    static byte[] keyIdentifier(SubjectPublicKeyInfo spki) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(spki.getPublicKeyData().getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new PkiException("Cannot compute a key identifier", e);
        }
    }

    /** The RFC 5280 section 4.2.1.2 method 1 key identifier of a public key: SHA-1 over the subjectPublicKey bits. */
    static byte[] keyIdentifier(PublicKey publicKey) {
        try {
            return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey).getKeyIdentifier();
        } catch (NoSuchAlgorithmException e) {
            throw new PkiException("Cannot compute a key identifier", e);
        }
    }

    /** The issuerAltName values as {@code tag:value} pairs, so a URI never compares equal to an email of the same text. */
    static List<String> issuerAltNames(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.issuerAlternativeName);
        List<String> values = new ArrayList<>();
        if (extension != null) {
            for (GeneralName name : GeneralNames.getInstance(extension).getNames()) {
                values.add(name.getTagNo() + ":" + generalNameValue(name));
            }
        }
        return values;
    }

    /**
     * The text of a GeneralName: the IA5String of a URI, rfc822Name or dNSName, the RFC 4514 form of a directoryName.
     * Decoding a directoryName can fail on an undecodable string inside it; callers decode inside their own guard.
     */
    static String generalNameValue(GeneralName name) {
        ASN1Encodable value = name.getName();
        return value instanceof ASN1String string ? string.getString() : value.toString();
    }

    /**
     * An issuerAltName value with an optional URI and an optional rfc822 email, refusing what a verifier could not use:
     * the URI must pass {@link #isIssuerAltUri} and the email {@link #isMailbox} with a domain of at least two labels
     * and a non-numeric last one ({@link #isRoutableMailbox}). The validator applies the URI check and the plain
     * mailbox syntax.
     */
    static GeneralNames issuerAltNames(String uri, String email) {
        List<GeneralName> names = new ArrayList<>(2);
        if (uri != null) {
            if (!isIssuerAltUri(uri)) {
                throw new PkiException("IACA_ISSUER_ALT_NAME_INVALID: " + uri
                        + " is not an absolute https, http, mailto or urn URI");
            }
            names.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
        }
        if (email != null) {
            if (!isRoutableMailbox(email)) {
                throw new PkiException("IACA_ISSUER_ALT_NAME_INVALID: " + email + " is not an rfc822 mailbox with a"
                        + " dotted domain whose last label is not numeric");
            }
            names.add(new GeneralName(GeneralName.rfc822Name, email));
        }
        if (names.isEmpty()) {
            throw new PkiException("IACA_ISSUER_ALT_NAME_MISSING: an issuerAltName needs a URI or an email address");
        }
        return new GeneralNames(names.toArray(GeneralName[]::new));
    }

    /**
     * Whether the value is an absolute URI (RFC 3986 section 4.3: a scheme and a non-empty scheme-specific part) made
     * of printable ASCII, which is what an IA5String GeneralName can carry.
     */
    static boolean isAbsoluteUri(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= 0x20 || c >= 0x7f) {
                return false;
            }
        }
        try {
            URI uri = new URI(value);
            String specific = uri.getRawSchemeSpecificPart();
            return uri.isAbsolute() && specific != null && !specific.isEmpty();
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /**
     * Whether the value is an issuerAltName URI this module accepts (decision log, 2026-11-13): an {@code https} or
     * {@code http} URI that passes {@link #isHttpUri}, or an absolute {@code mailto} or {@code urn} URI. Builder and
     * validator apply the same check.
     */
    static boolean isIssuerAltUri(String value) {
        if (!isAbsoluteUri(value)) {
            return false;
        }
        String scheme = value.substring(0, value.indexOf(':')).toLowerCase(Locale.ROOT);
        return switch (scheme) {
            case "https", "http" -> isHttpUri(value);
            case "mailto", "urn" -> true;
            default -> false;
        };
    }

    /**
     * Whether the value is an absolute {@code http} or {@code https} URI with a host, no userinfo and a port, if any,
     * no greater than 65535: a location a verifier can fetch.
     */
    static boolean isHttpUri(String value) {
        if (!isAbsoluteUri(value)) {
            return false;
        }
        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme();
            return uri.getHost() != null && !uri.getHost().isEmpty()
                    && uri.getRawUserInfo() == null
                    && uri.getPort() <= 65_535
                    && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme));
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /**
     * Whether the value is an RFC 5280 rfc822Name mailbox (RFC 5321 section 4.1.2): a dot-atom local part of at most 64
     * octets, {@code @}, and a domain of letter-digit-hyphen labels of at most 255 octets. Quoted local parts and address
     * literals are not accepted (decision log, 2026-11-13). The validator applies this syntax only; the builders also
     * require {@link #isRoutableMailbox}.
     */
    static boolean isMailbox(String value) {
        if (value == null) {
            return false;
        }
        int at = value.indexOf('@');
        if (at <= 0 || at != value.lastIndexOf('@') || at == value.length() - 1) {
            return false;
        }
        String local = value.substring(0, at);
        String domain = value.substring(at + 1);
        if (local.length() > 64 || domain.length() > 255) {
            return false;
        }
        for (String atom : local.split("\\.", -1)) {
            if (!ATOM.matcher(atom).matches()) {
                return false;
            }
        }
        for (String label : domain.split("\\.", -1)) {
            if (!LABEL.matcher(label).matches()) {
                return false;
            }
        }
        return true;
    }

    /**
     * A {@link #isMailbox mailbox} whose domain has at least two labels and a last label that is not all digits, so
     * {@code pki@localhost} and {@code pki@123.456} are refused: what a builder writes must be deliverable.
     */
    static boolean isRoutableMailbox(String value) {
        if (!isMailbox(value)) {
            return false;
        }
        String domain = value.substring(value.indexOf('@') + 1);
        int dot = domain.lastIndexOf('.');
        return dot > 0 && !domain.substring(dot + 1).chars().allMatch(Character::isDigit);
    }

    // ------------------------------------------------------- distribution point

    /** A CRL distribution point extension with one http(s) URI, refusing anything a verifier could not fetch. */
    static CRLDistPoint crlDistributionPoint(String uri) {
        if (!isHttpUri(uri)) {
            throw new PkiException("IACA_CRL_DP_INVALID: " + uri + " is not an absolute http or https URI");
        }
        return new CRLDistPoint(new DistributionPoint[] {
                new DistributionPoint(
                        new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uri))),
                        null, null)});
    }

    /** The URI distribution points of the CRL distribution point extension, empty when absent. */
    static List<String> crlDistributionPointUris(Parsed.Cert certificate) {
        byte[] extension = extension(certificate, Extension.cRLDistributionPoints);
        List<String> uris = new ArrayList<>();
        if (extension == null) {
            return uris;
        }
        for (DistributionPoint point : CRLDistPoint.getInstance(extension).getDistributionPoints()) {
            DistributionPointName name = point.getDistributionPoint();
            if (name != null && name.getType() == DistributionPointName.FULL_NAME) {
                for (GeneralName generalName : GeneralNames.getInstance(name.getName()).getNames()) {
                    if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        uris.add(generalNameValue(generalName));
                    }
                }
            }
        }
        return uris;
    }

    static List<String> crlDistributionPointUris(X509Certificate certificate) {
        return crlDistributionPointUris(Parsed.certificate(certificate));
    }

    // ---------------------------------------------------------------- keys

    /**
     * Why the subjectPublicKeyInfo is outside the key profile of this module, or {@code null} when it conforms: EC only,
     * a named curve from {@link #CURVES}, no explicit parameters, an uncompressed point of the curve's size that decodes
     * to a finite point on that curve (infinity, off-curve points and coordinates outside the field are refused).
     */
    static String keyProblem(SubjectPublicKeyInfo spki) {
        ASN1ObjectIdentifier algorithm = spki.getAlgorithm().getAlgorithm();
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
            return "the key is not an EC key (" + algorithm.getId() + ")";
        }
        ASN1Encodable parameters = spki.getAlgorithm().getParameters();
        if (parameters == null) {
            return "the subjectPublicKeyInfo names no curve";
        }
        ASN1Primitive primitive = parameters.toASN1Primitive();
        if (!(primitive instanceof ASN1ObjectIdentifier curve)) {
            return "the subjectPublicKeyInfo carries explicit curve parameters, not a named curve OID";
        }
        if (!CURVES.containsKey(curve)) {
            return "the curve " + curve.getId() + " is not P-256, P-384 or P-521";
        }
        if (spki.getPublicKeyData().getPadBits() != 0) {
            return "the subjectPublicKey BIT STRING is not a whole number of octets";
        }
        byte[] point = spki.getPublicKeyData().getBytes();
        int fieldOctets = (curveBits(curve) + 7) / 8;
        if (point.length == 0 || point[0] != 0x04) {
            return "the public key is not an uncompressed point (first octet " + (point.length == 0 ? "none" : point[0]) + ")";
        }
        if (point.length != 1 + 2 * fieldOctets) {
            return "the public key is " + point.length + " octets, an uncompressed " + curveBits(curve)
                    + " bit point is " + (1 + 2 * fieldOctets);
        }
        try {
            ECPoint decoded = ECNamedCurveTable.getByOID(curve).getCurve().decodePoint(point);
            if (decoded.isInfinity() || !decoded.isValid()) {
                return "the public key is not a finite point on " + curveName(curve);
            }
        } catch (RuntimeException e) {
            return "the public key is not a point on " + curveName(curve) + ": " + e.getMessage();
        }
        return null;
    }

    /** The named-curve OID of the key, refusing anything outside the allowlist with {@code profile + "_KEY_INVALID"}. */
    static ASN1ObjectIdentifier curve(PublicKey key, String profile) {
        SubjectPublicKeyInfo spki = spki(key, profile + "_KEY_INVALID");
        String problem = keyProblem(spki);
        if (problem != null) {
            throw new PkiException(profile + "_KEY_INVALID: " + problem);
        }
        return (ASN1ObjectIdentifier) spki.getAlgorithm().getParameters().toASN1Primitive();
    }

    static String curveName(ASN1ObjectIdentifier curve) {
        return "P-" + curveBits(curve);
    }

    static int curveBits(ASN1ObjectIdentifier curve) {
        if (P256.equals(curve)) {
            return 256;
        }
        if (P384.equals(curve)) {
            return 384;
        }
        if (P521.equals(curve)) {
            return 521;
        }
        throw new PkiException("CURVE_UNSUPPORTED: " + curve.getId() + " is not P-256, P-384 or P-521");
    }

    /** The {@code ecdsa-with-SHA256/384/512} signature algorithm Annex B pairs with a P-256, P-384 or P-521 key. */
    static String signatureAlgorithm(PublicKey key, String profile) {
        return signatureAlgorithmName(curve(key, profile));
    }

    static String signatureAlgorithmName(ASN1ObjectIdentifier curve) {
        ASN1ObjectIdentifier signature = CURVES.get(curve);
        if (signature == null) {
            throw new PkiException("CURVE_UNSUPPORTED: " + curve.getId() + " is not P-256, P-384 or P-521");
        }
        return switch (signature.getId()) {
            case "1.2.840.10045.4.3.2" -> "SHA256withECDSA";
            case "1.2.840.10045.4.3.3" -> "SHA384withECDSA";
            default -> "SHA512withECDSA";
        };
    }

    /** The curve a signature algorithm requires, or {@code null} when it is not one of the three Annex B algorithms. */
    static ASN1ObjectIdentifier signatureCurve(ASN1ObjectIdentifier signatureAlgorithm) {
        return SIGNATURES.get(signatureAlgorithm);
    }

    static boolean isEcdsaSignature(ASN1ObjectIdentifier signatureAlgorithm) {
        return SIGNATURES.containsKey(signatureAlgorithm);
    }

    // ------------------------------------------------------------- validity

    /**
     * Refuses a validity shorter than {@link IsoMdocProfiles#MIN_VALIDITY} or longer than the profile cap, with a named
     * rule. The minimum keeps every builder output well clear of {@code notAfter <= notBefore}, which the validator
     * reports as {@code *_VALIDITY_REVERSED}.
     */
    static void checkValidity(Duration validity, Duration maximum, String profile) {
        if (validity == null || validity.compareTo(IsoMdocProfiles.MIN_VALIDITY) < 0) {
            throw new PkiException(profile + "_VALIDITY_INVALID: the validity " + validity
                    + " is shorter than the minimum of " + IsoMdocProfiles.MIN_VALIDITY);
        }
        if (validity.compareTo(maximum) > 0) {
            throw new PkiException(profile + "_VALIDITY_TOO_LONG: the validity " + validity + " exceeds " + maximum);
        }
    }

    /**
     * The end of a validity period. RFC 5280 section 4.1.2.5 makes {@code notAfter} inclusive, so a period of one day
     * runs from {@code notBefore} through {@code notBefore + 1 day - 1 s}.
     */
    static Instant end(Instant start, Duration validity) {
        return start.plus(validity).minusSeconds(1).truncatedTo(ChronoUnit.SECONDS);
    }

    /** Refuses a serial that is not positive, shorter than {@value Serials#MIN_BITS} bits or longer than 20 DER content octets. */
    static void checkSerial(BigInteger serial, String profile) {
        if (serial == null || serial.signum() <= 0) {
            throw new PkiException(profile + "_SERIAL_NOT_POSITIVE: the serial number must be a positive integer");
        }
        if (serial.bitLength() < Serials.MIN_BITS) {
            throw new PkiException(profile + "_SERIAL_TOO_SHORT: the serial number has " + serial.bitLength()
                    + " bits; the builders write at least " + Serials.MIN_BITS + " so that Annex B's 63 random bits fit");
        }
        if (Serials.octets(serial) > Serials.MAX_OCTETS) {
            throw new PkiException(profile + "_SERIAL_TOO_LONG: the serial number is " + Serials.octets(serial)
                    + " DER content octets, RFC 5280 allows " + Serials.MAX_OCTETS);
        }
    }

    // ------------------------------------------------------------ signing

    /**
     * A signer for the private key; a key the algorithm cannot sign with (an RSA key for {@code SHA256withECDSA}, for
     * one) is refused with {@code rule}, the builder's key-pair consistency rule.
     */
    static ContentSigner signer(PrivateKey key, String signatureAlgorithm, String rule) {
        try {
            return new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(key);
        } catch (OperatorCreationException | RuntimeException e) {
            throw new PkiException(rule + ": the private key cannot sign with " + signatureAlgorithm + ": "
                    + Parsed.describe(e), e);
        }
    }

    static X509Certificate certificate(X509CertificateHolder holder) {
        try {
            return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
        } catch (CertificateException e) {
            throw new PkiException("Cannot convert the certificate", e);
        }
    }

    static X509CRL crl(X509CRLHolder holder) {
        try {
            return new JcaX509CRLConverter().setProvider(BC).getCRL(holder);
        } catch (java.security.cert.CRLException e) {
            throw new PkiException("Cannot convert the CRL", e);
        }
    }

    /** Whether a certificate a builder just signed verifies under the expected public key. */
    static boolean verifies(X509CertificateHolder holder, SubjectPublicKeyInfo key) {
        try {
            return holder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(key));
        } catch (Exception e) {
            return false;
        }
    }

    /** Whether a CRL a builder just signed verifies under the expected public key. */
    static boolean verifies(X509CRLHolder holder, SubjectPublicKeyInfo key) {
        try {
            return holder.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(key));
        } catch (Exception e) {
            return false;
        }
    }

    private static Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> curveTable() {
        Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> curves = new LinkedHashMap<>();
        curves.put(P256, ECDSA_WITH_SHA256);
        curves.put(P384, ECDSA_WITH_SHA384);
        curves.put(P521, ECDSA_WITH_SHA512);
        return Map.copyOf(curves);
    }

    private static Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> signatureTable() {
        Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> signatures = new LinkedHashMap<>();
        signatures.put(ECDSA_WITH_SHA256, P256);
        signatures.put(ECDSA_WITH_SHA384, P384);
        signatures.put(ECDSA_WITH_SHA512, P521);
        return Map.copyOf(signatures);
    }
}
