package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * A certificate or CRL read once from its DER with BouncyCastle's ASN.1 structures ({@link Certificate},
 * {@link TBSCertificate}, {@link CertificateList}), never through the JCA getters.
 *
 * <p>A JCA object is not a promise that its fields can be read: the JDK keeps attribute values and extensions it does
 * not understand as raw octets, and BouncyCastle's provider decodes names, dates and extensions lazily, so a getter
 * can throw on first access. Reading the DER here, with every lazily decoded part (dates, CRL entries, entry
 * extensions) forced inside {@link #certificate} and {@link #crl}, turns any such object into one exception at one
 * place, which the validator reports as {@code *_ENCODING_INVALID} and the builders as a named refusal. What is not
 * decoded here (attribute string values, extension values) is decoded by the caller inside its own guard.
 *
 * <p>The encoding must be DER, as RFC 5280 requires, not merely BER: one that differs from its own DER re-encoding (a
 * BOOLEAN TRUE written {@code 01} instead of {@code FF}, an unsorted SET OF, non-zero BIT STRING padding, an
 * indefinite or non-minimal length) is refused by {@link #certificate}, {@link #crl} and {@link #der}. Without that
 * check the verdict would depend on the provider: the JDK keeps the octets it parsed, so a signature made over BER
 * would verify, while BouncyCastle's provider re-encodes the object to DER on construction and the same signature
 * fails. Strict verifiers (Go's {@code crypto/x509}) refuse such an encoding outright. The check is BouncyCastle's DER
 * re-encoding, which is syntactic: a DEFAULT value encoded explicitly (an extension's {@code critical FALSE}) and a
 * UTCTime without seconds re-encode to themselves and are not caught here; both providers keep those octets, so the
 * verdict is the same.
 */
final class Parsed {

    private Parsed() {}

    /**
     * The fields of a certificate the profiles read, from its DER, with the tbsCertificate octets exactly as the
     * encoding carries them and the signature value. The signature is verified over those octets with BouncyCastle's
     * verifier and the subjectPublicKeyInfo, never through a JCA public key conversion. Because the encoding must be
     * DER, the octets verified are the same whichever provider built the object.
     */
    record Cert(byte[] signed, byte[] signature, int version, BigInteger serial, X500Name issuer, X500Name subject,
                Instant notBefore, Instant notAfter, SubjectPublicKeyInfo spki, Extensions extensions,
                AlgorithmIdentifier outerAlgorithm, AlgorithmIdentifier innerAlgorithm) {

        /** Whether the signature verifies under the key over the tbsCertificate octets as encoded. */
        boolean signedBy(SubjectPublicKeyInfo key) {
            return verifies(signed, outerAlgorithm, signature, key);
        }

        Extension extension(ASN1ObjectIdentifier oid) {
            return extensions == null ? null : extensions.getExtension(oid);
        }

        boolean critical(ASN1ObjectIdentifier oid) {
            Extension extension = extension(oid);
            return extension != null && extension.isCritical();
        }

        /** The OIDs of the extensions marked critical, sorted. */
        Set<String> criticalExtensions() {
            Set<String> oids = new TreeSet<>();
            if (extensions != null) {
                for (ASN1ObjectIdentifier oid : extensions.getCriticalExtensionOIDs()) {
                    oids.add(oid.getId());
                }
            }
            return oids;
        }
    }

    /** One revoked entry: its serial, its revocation date and whether it carries entry extensions. */
    record Entry(BigInteger serial, Instant revokedAt, boolean hasExtensions) {}

    /** The fields of a CRL the profile reads, from its DER, with the tbsCertList octets as signed and the signature. */
    record Crl(byte[] signed, byte[] signature, int version, X500Name issuer, Instant thisUpdate, Instant nextUpdate,
               List<Entry> entries, Extensions extensions, AlgorithmIdentifier outerAlgorithm,
               AlgorithmIdentifier innerAlgorithm) {

        /** Whether the signature verifies under the key over the tbsCertList octets as encoded. */
        boolean signedBy(SubjectPublicKeyInfo key) {
            return verifies(signed, outerAlgorithm, signature, key);
        }

        Extension extension(ASN1ObjectIdentifier oid) {
            return extensions == null ? null : extensions.getExtension(oid);
        }

        boolean critical(ASN1ObjectIdentifier oid) {
            Extension extension = extension(oid);
            return extension != null && extension.isCritical();
        }

        /** Every extension OID, sorted. */
        Set<String> extensionOids() {
            Set<String> oids = new TreeSet<>();
            if (extensions != null) {
                for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                    oids.add(oid.getId());
                }
            }
            return oids;
        }
    }

    /**
     * The certificate read from its DER. Throws {@link PkiException} (with the cause) when the encoding cannot be read
     * as an X.509 Certificate, including a validity date that does not parse and an encoding that is BER but not DER.
     */
    static Cert certificate(X509Certificate certificate) {
        try {
            byte[] der = certificate.getEncoded();
            Certificate structure = Certificate.getInstance(strict(der));
            requireDer(der, structure.getEncoded(ASN1Encoding.DER));
            TBSCertificate tbs = structure.getTBSCertificate();
            return new Cert(firstElement(der), signature(BcCompat.signatureValue(structure)), tbs.getVersionNumber(),
                    tbs.getSerialNumber().getValue(), name(tbs.getIssuer()), name(tbs.getSubject()),
                    instant(tbs.getStartDate()), instant(tbs.getEndDate()),
                    tbs.getSubjectPublicKeyInfo(), tbs.getExtensions(), structure.getSignatureAlgorithm(),
                    tbs.getSignature());
        } catch (Exception e) {
            throw new PkiException("the certificate cannot be read as an X.509 Certificate: " + describe(e), e);
        }
    }

    /**
     * The CRL read from its DER, every entry included. Throws {@link PkiException} (with the cause) when the encoding
     * cannot be read as an X.509 CertificateList, including a date or an entry extension list that does not parse and
     * an encoding that is BER but not DER.
     */
    static Crl crl(X509CRL crl) {
        try {
            byte[] der = crl.getEncoded();
            CertificateList structure = CertificateList.getInstance(strict(der));
            requireDer(der, structure.getEncoded(ASN1Encoding.DER));
            TBSCertList tbs = structure.getTBSCertList();
            List<Entry> entries = new ArrayList<>();
            for (TBSCertList.CRLEntry entry : tbs.getRevokedCertificates()) {
                Extensions extensions = entry.getExtensions();
                entries.add(new Entry(entry.getUserCertificate().getValue(), instant(entry.getRevocationDate()),
                        extensions != null));
            }
            Time nextUpdate = tbs.getNextUpdate();
            return new Crl(firstElement(der), signature(BcCompat.signatureValue(structure)), tbs.getVersionNumber(),
                    name(tbs.getIssuer()), instant(tbs.getThisUpdate()),
                    nextUpdate == null ? null : instant(nextUpdate), List.copyOf(entries), tbs.getExtensions(),
                    structure.getSignatureAlgorithm(), tbs.getSignature());
        } catch (Exception e) {
            throw new PkiException("the CRL cannot be read as an X.509 CertificateList: " + describe(e), e);
        }
    }

    /** Exactly one DER object: an empty input and trailing octets are refused. */
    static ASN1Primitive strict(byte[] der) throws IOException {
        if (der == null || der.length == 0) {
            throw new IOException("no encoding");
        }
        try (ASN1InputStream in = new ASN1InputStream(der)) {
            ASN1Primitive primitive = in.readObject();
            if (primitive == null) {
                throw new IOException("no DER object");
            }
            if (in.available() != 0) {
                throw new IOException(in.available() + " octets after the DER object");
            }
            return primitive;
        }
    }

    /**
     * Exactly one object, encoded in DER: {@link #strict} and then equal, octet for octet, to its own DER re-encoding.
     * For an extension value, whose OCTET STRING hides it from the check on the enclosing certificate or CRL.
     */
    static ASN1Primitive der(byte[] encoding) throws IOException {
        ASN1Primitive primitive = strict(encoding);
        requireDer(encoding, primitive.getEncoded(ASN1Encoding.DER));
        return primitive;
    }

    /** Refuses an encoding that differs from its DER re-encoding: BER, which RFC 5280 does not allow. */
    private static void requireDer(byte[] encoding, byte[] reencoded) throws IOException {
        if (!Arrays.equals(encoding, reencoded)) {
            throw new IOException("the encoding is BER but not DER (it differs from its DER re-encoding at octet "
                    + Arrays.mismatch(encoding, reencoded) + "); RFC 5280 requires DER");
        }
    }

    /**
     * The octets of the first element of the outer SEQUENCE, tag and length included: the tbsCertificate or
     * tbsCertList exactly as the issuer signed it. Only definite lengths are read (DER has no other kind).
     */
    static byte[] firstElement(byte[] der) throws IOException {
        int[] outer = header(der, 0);
        int start = outer[0];
        int[] inner = header(der, start);
        long end = (long) start + inner[0] + inner[1];
        if (end > der.length) {
            throw new IOException("the signed part runs past the end of the encoding");
        }
        return Arrays.copyOfRange(der, start, (int) end);
    }

    /** {header length, content length} of the TLV at {@code offset}. */
    private static int[] header(byte[] der, int offset) throws IOException {
        if (offset + 2 > der.length) {
            throw new IOException("truncated encoding");
        }
        if ((der[offset] & 0x1f) == 0x1f) {
            throw new IOException("unexpected high tag number");
        }
        int first = der[offset + 1] & 0xff;
        if (first < 0x80) {
            return new int[] {2, first};
        }
        int octets = first & 0x7f;
        if (octets == 0) {
            throw new IOException("indefinite length, which DER does not allow");
        }
        if (octets > 4 || offset + 2 + octets > der.length) {
            throw new IOException("length of " + octets + " octets");
        }
        long length = 0;
        for (int i = 0; i < octets; i++) {
            length = (length << 8) | (der[offset + 2 + i] & 0xff);
        }
        if (length > Integer.MAX_VALUE) {
            throw new IOException("length " + length);
        }
        return new int[] {2 + octets, (int) length};
    }

    /** The signature BIT STRING's octets, or {@code null} when it is not a whole number of octets. */
    private static byte[] signature(ASN1BitString signature) {
        return signature.getPadBits() == 0 ? signature.getOctets() : null;
    }

    /**
     * Whether {@code signature} over {@code signed} verifies under the key with the algorithm named. Any failure, an
     * unknown algorithm or a key BouncyCastle cannot build included, is a no.
     */
    static boolean verifies(byte[] signed, AlgorithmIdentifier algorithm, byte[] signature, SubjectPublicKeyInfo key) {
        if (signature == null) {
            return false;
        }
        try {
            ContentVerifier verifier = new JcaContentVerifierProviderBuilder().setProvider(Certificates.provider())
                    .build(key).get(algorithm);
            try (OutputStream out = verifier.getOutputStream()) {
                out.write(signed);
            }
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * The name with every RDN's attributes parsed: BouncyCastle reads an RDN's {@code AttributeTypeAndValue}s only when
     * they are first asked for, so a malformed one would otherwise throw later, outside this guard.
     */
    private static X500Name name(X500Name name) {
        for (RDN rdn : name.getRDNs()) {
            for (AttributeTypeAndValue attribute : rdn.getTypesAndValues()) {
                Objects.requireNonNull(attribute.getType(), "attribute type");
                Objects.requireNonNull(attribute.getValue(), "attribute value");
            }
        }
        return name;
    }

    private static Instant instant(Time time) {
        return time.getDate().toInstant();
    }

    static String describe(Throwable e) {
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }
}
