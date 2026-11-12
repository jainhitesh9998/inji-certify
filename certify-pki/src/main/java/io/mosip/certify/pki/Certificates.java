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
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
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
 * <p>The curve allowlist is deliberate: Annex B (2021 edition) signs with ECDSA over P-256, P-384 or P-521 and nothing
 * else, so brainpool, secp256k1 and explicit curve parameters are refused here rather than checked at each call site.
 */
final class Certificates {

    static final ASN1ObjectIdentifier ECDSA_WITH_SHA256 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.2");
    static final ASN1ObjectIdentifier ECDSA_WITH_SHA384 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.3");
    static final ASN1ObjectIdentifier ECDSA_WITH_SHA512 = new ASN1ObjectIdentifier("1.2.840.10045.4.3.4");

    static final ASN1ObjectIdentifier P256 = SECObjectIdentifiers.secp256r1;
    static final ASN1ObjectIdentifier P384 = SECObjectIdentifiers.secp384r1;
    static final ASN1ObjectIdentifier P521 = SECObjectIdentifiers.secp521r1;

    /** The named curves Annex B allows, each with the {@code ecdsa-with-SHA*} signature algorithm it signs with. */
    static final Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> CURVES = curveTable();

    private static final Map<ASN1ObjectIdentifier, ASN1ObjectIdentifier> SIGNATURES = signatureTable();

    private static final Pattern EMAIL = Pattern.compile("[^@\\s,;]+@[^@\\s,;]+\\.[A-Za-z]{2,}");

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

    /** The DER value of a CRL extension, or {@code null} when the CRL does not carry it. */
    static byte[] extension(X509CRL crl, ASN1ObjectIdentifier oid) {
        byte[] encoded = crl.getExtensionValue(oid.getId());
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

    /** The AuthorityKeyIdentifier keyIdentifier of a CRL, or {@code null} when absent. */
    static byte[] authorityKeyIdentifier(X509CRL crl) {
        byte[] extension = extension(crl, Extension.authorityKeyIdentifier);
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

    /** An issuerAltName value with an optional URI and an optional rfc822 email. */
    static GeneralNames issuerAltNames(String uri, String email) {
        List<GeneralName> names = new ArrayList<>(2);
        if (uri != null) {
            if (!isHttpUri(uri)) {
                throw new PkiException("IACA_ISSUER_ALT_NAME_INVALID: " + uri + " is not an http or https URI");
            }
            names.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
        }
        if (email != null) {
            if (!EMAIL.matcher(email).matches()) {
                throw new PkiException("IACA_ISSUER_ALT_NAME_INVALID: " + email + " is not an rfc822 mailbox");
            }
            names.add(new GeneralName(GeneralName.rfc822Name, email));
        }
        if (names.isEmpty()) {
            throw new PkiException("IACA_ISSUER_ALT_NAME_MISSING: an issuerAltName needs a URI or an email address");
        }
        return new GeneralNames(names.toArray(GeneralName[]::new));
    }

    /** Whether the value is an absolute http or https URI with a host, the only scheme Annex B CRL access allows. */
    static boolean isHttpUri(String value) {
        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme();
            return uri.isAbsolute() && uri.getHost() != null
                    && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme));
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------- distribution point

    /** A CRL distribution point extension with one URI, refusing anything a verifier could not fetch. */
    static CRLDistPoint crlDistributionPoint(String uri) {
        if (!isHttpUri(uri)) {
            throw new PkiException("IACA_CRL_DP_INVALID: " + uri + " is not an http or https URI");
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
     * Why the subjectPublicKeyInfo is outside the Annex B key profile, or {@code null} when it conforms: EC only, a
     * named curve from {@link #CURVES}, no explicit parameters, an uncompressed point.
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
        byte[] point = spki.getPublicKeyData().getBytes();
        int fieldOctets = (curveBits(curve) + 7) / 8;
        if (point.length == 0 || point[0] != 0x04) {
            return "the public key is not an uncompressed point (first octet " + (point.length == 0 ? "none" : point[0]) + ")";
        }
        if (point.length != 1 + 2 * fieldOctets) {
            return "the public key is " + point.length + " octets, an uncompressed " + curveBits(curve)
                    + " bit point is " + (1 + 2 * fieldOctets);
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

    /** Refuses a validity that is not positive or that exceeds the profile cap, with a named rule. */
    static void checkValidity(Duration validity, Duration maximum, String profile) {
        if (validity == null || validity.isZero() || validity.isNegative()) {
            throw new PkiException(profile + "_VALIDITY_INVALID: the validity " + validity
                    + " is not a positive duration");
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
        return start.plus(validity).minusSeconds(1);
    }

    /** Refuses a serial that is not positive, shorter than 64 bits or longer than 20 DER content octets. */
    static void checkSerial(BigInteger serial, String profile) {
        if (serial == null || serial.signum() <= 0) {
            throw new PkiException(profile + "_SERIAL_NOT_POSITIVE: the serial number must be a positive integer");
        }
        if (serial.bitLength() < Serials.MIN_BITS) {
            throw new PkiException(profile + "_SERIAL_TOO_SHORT: the serial number has " + serial.bitLength()
                    + " bits, Annex B requires at least " + Serials.MIN_BITS);
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
