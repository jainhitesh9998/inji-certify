package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1Encodable;
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
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
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

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.security.auth.x500.X500Principal;

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

    static X500Name name(X500Principal principal) {
        return X500Name.getInstance(principal.getEncoded());
    }

    static X500Name name(X509Certificate certificate) {
        return name(certificate.getSubjectX500Principal());
    }

    /** The DER encoding of a name, for byte-equality comparisons that must not depend on re-encoding. */
    static byte[] der(X500Name name) {
        try {
            return name.getEncoded();
        } catch (IOException e) {
            throw new PkiException("Cannot encode the name", e);
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

    static List<AttributeTypeAndValue> attributes(X500Principal principal, ASN1ObjectIdentifier type) {
        return attributes(name(principal), type);
    }

    /** The decoded value of a directory string attribute, whatever its ASN.1 string type: never an escaped form. */
    static String string(ASN1Encodable value) {
        return value instanceof ASN1String string ? string.getString() : value.toString();
    }

    /** The first value of a single-valued attribute, or {@code null} when the name has none. */
    static String attribute(X500Principal principal, ASN1ObjectIdentifier type) {
        List<AttributeTypeAndValue> attributes = attributes(principal, type);
        return attributes.isEmpty() ? null : string(attributes.get(0).getValue());
    }

    // ----------------------------------------------------------- extensions

    /** The DER value of an extension, or {@code null} when the certificate does not carry it. */
    static byte[] extension(X509Certificate certificate, ASN1ObjectIdentifier oid) {
        byte[] encoded = certificate.getExtensionValue(oid.getId());
        return encoded == null ? null : ASN1OctetString.getInstance(encoded).getOctets();
    }

    /** Whether the certificate carries the extension and marks it critical. */
    static boolean critical(X509Certificate certificate, ASN1ObjectIdentifier oid) {
        return certificate.getCriticalExtensionOIDs() != null
                && certificate.getCriticalExtensionOIDs().contains(oid.getId());
    }

    /** Whether the CRL carries the extension and marks it critical. */
    static boolean critical(X509CRL crl, ASN1ObjectIdentifier oid) {
        return crl.getCriticalExtensionOIDs() != null && crl.getCriticalExtensionOIDs().contains(oid.getId());
    }

    /** The SubjectKeyIdentifier extension value, or {@code null} when absent. */
    static byte[] subjectKeyIdentifier(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.subjectKeyIdentifier);
        return extension == null ? null : SubjectKeyIdentifier.getInstance(extension).getKeyIdentifier();
    }

    /** The AuthorityKeyIdentifier keyIdentifier of a certificate, or {@code null} when absent. */
    static byte[] authorityKeyIdentifier(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.authorityKeyIdentifier);
        return extension == null ? null : AuthorityKeyIdentifier.getInstance(extension).getKeyIdentifier();
    }

    /** The SKI of a certificate when it declares one, and the RFC 5280 method 1 value of its key otherwise. */
    static byte[] keyIdentifier(X509Certificate certificate) {
        byte[] declared = subjectKeyIdentifier(certificate);
        return declared != null ? declared : keyIdentifier(subjectPublicKeyInfo(certificate));
    }

    /** The subjectPublicKeyInfo a JCA key encodes to. */
    static SubjectPublicKeyInfo spki(PublicKey key) {
        return SubjectPublicKeyInfo.getInstance(key.getEncoded());
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

    /** The issuerAltName extension values with their GeneralName tags, empty when absent. */
    static List<GeneralName> issuerAltNameNames(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.issuerAlternativeName);
        return extension == null ? List.of() : List.of(GeneralNames.getInstance(extension).getNames());
    }

    /** The issuerAltName values as {@code tag:value} pairs, so a URI never compares equal to an email of the same text. */
    static List<String> issuerAltNames(X509Certificate certificate) {
        List<String> values = new ArrayList<>();
        for (GeneralName name : issuerAltNameNames(certificate)) {
            values.add(name.getTagNo() + ":" + generalNameValue(name));
        }
        return values;
    }

    static String generalNameValue(GeneralName name) {
        ASN1Encodable value = name.getName();
        return value instanceof ASN1String string ? string.getString() : value.toString();
    }

    /**
     * An issuerAltName value with an optional URI and an optional rfc822 email. The URI may use any scheme (an
     * {@code https:} page or a {@code mailto:} address) as long as it is absolute; the email must be a mailbox. The
     * validator applies the same two checks.
     */
    static GeneralNames issuerAltNames(String uri, String email) {
        List<GeneralName> names = new ArrayList<>(2);
        if (uri != null) {
            if (!isAbsoluteUri(uri)) {
                throw new PkiException("IACA_ISSUER_ALT_NAME_INVALID: " + uri + " is not an absolute URI");
            }
            names.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
        }
        if (email != null) {
            if (!isMailbox(email)) {
                throw new PkiException("IACA_ISSUER_ALT_NAME_INVALID: " + email + " is not an rfc822 mailbox");
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
     * of printable ASCII, which is what an IA5String GeneralName can carry. Any scheme is accepted; callers that need a
     * fetchable location use {@link #isHttpUri}.
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

    /** Whether the value is an absolute {@code http} or {@code https} URI with a host: a location a verifier can fetch. */
    static boolean isHttpUri(String value) {
        if (!isAbsoluteUri(value)) {
            return false;
        }
        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme();
            return uri.getHost() != null && !uri.getHost().isEmpty()
                    && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme));
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /**
     * Whether the value is an RFC 5280 rfc822Name mailbox (RFC 5321 section 4.1.2): a dot-atom local part of at most 64
     * octets, {@code @}, and a domain of letter-digit-hyphen labels of at most 255 octets. Quoted local parts and address
     * literals are not accepted (decision log, 2026-11-13).
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

    /** The distribution points of the CRL distribution point extension, empty when absent. */
    static List<DistributionPoint> distributionPoints(X509Certificate certificate) {
        byte[] extension = extension(certificate, Extension.cRLDistributionPoints);
        return extension == null ? List.of() : List.of(CRLDistPoint.getInstance(extension).getDistributionPoints());
    }

    /** The URI distribution points of the CRL distribution point extension, empty when absent. */
    static List<String> crlDistributionPointUris(X509Certificate certificate) {
        List<String> uris = new ArrayList<>();
        for (DistributionPoint point : distributionPoints(certificate)) {
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

    // ---------------------------------------------------------------- keys

    /** The subjectPublicKeyInfo of a certificate, read from its DER so an unusable key cannot fail the read. */
    static SubjectPublicKeyInfo subjectPublicKeyInfo(X509Certificate certificate) {
        try {
            return new X509CertificateHolder(certificate.getEncoded()).getSubjectPublicKeyInfo();
        } catch (Exception e) {
            throw new PkiException("Cannot read the certificate DER", e);
        }
    }

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
        SubjectPublicKeyInfo spki = spki(key);
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

    static ContentSigner signer(PrivateKey key, String signatureAlgorithm) {
        try {
            return new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC).build(key);
        } catch (OperatorCreationException e) {
            throw new PkiException("Cannot sign with " + signatureAlgorithm, e);
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

    /** Whether the certificate is signed by the given key. */
    static boolean signedBy(X509Certificate certificate, PublicKey key) {
        try {
            certificate.verify(key);
            return true;
        } catch (GeneralSecurityException e) {
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
