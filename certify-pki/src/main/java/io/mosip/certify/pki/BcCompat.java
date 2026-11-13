package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * BouncyCastle calls that link the same way from 1.69 to 1.78 (decision log 2026-11-13, F-10).
 *
 * <p>Deployments put published plugin jars on {@code loader.path} that bundle unshaded BouncyCastle 1.69, and those
 * classes shadow the 1.78 the service ships. Between the two releases several methods changed their return type
 * ({@code SubjectPublicKeyInfo.getPublicKeyData()}, {@code Certificate.getSignature()},
 * {@code CertificateList.getSignature()} return {@code DERBitString} in 1.69 and {@code ASN1BitString} from 1.71;
 * {@code DERIA5String.getInstance} returns {@code ASN1IA5String} from 1.71), and some types are new in 1.71
 * ({@code ASN1PrintableString}, {@code ASN1UTF8String}, {@code ASN1IA5String}, the static
 * {@code ASN1BitString.getInstance}). Code compiled against 1.78 that calls them fails with {@code NoSuchMethodError} or
 * {@code NoClassDefFoundError} under 1.69. The forms here use only methods and types whose descriptors are identical in
 * both: the BIT STRINGs are read from the parsed SEQUENCE, and the string types are tested by their {@code DER} classes,
 * which are what both releases' parsers create. The {@code bc169} Maven profile runs the module tests on 1.69.
 */
public final class BcCompat {

    private BcCompat() {}

    /** The subjectPublicKey BIT STRING of a SubjectPublicKeyInfo (RFC 5280 4.1: element 1 of the SEQUENCE). */
    public static ASN1BitString subjectPublicKey(SubjectPublicKeyInfo spki) {
        return bitString(ASN1Sequence.getInstance(spki.toASN1Primitive()).getObjectAt(1));
    }

    /**
     * The signatureValue BIT STRING of a signed X.509 structure (Certificate or CertificateList, RFC 5280 4.1 and 5.1:
     * element 2 of the SEQUENCE).
     */
    public static ASN1BitString signatureValue(ASN1Encodable signed) {
        return bitString(ASN1Sequence.getInstance(signed.toASN1Primitive()).getObjectAt(2));
    }

    /** The value as a BIT STRING; {@link IllegalArgumentException} when it is something else, as {@code ASN1BitString.getInstance}. */
    public static ASN1BitString bitString(ASN1Encodable value) {
        ASN1Primitive primitive = value == null ? null : value.toASN1Primitive();
        if (primitive instanceof ASN1BitString bits) {
            return bits;
        }
        throw new IllegalArgumentException("not a BIT STRING: " + (primitive == null ? "null" : primitive.getClass().getSimpleName()));
    }

    /** Whether the value is a PrintableString (both releases parse one into {@link DERPrintableString}). */
    public static boolean isPrintableString(ASN1Encodable value) {
        return value instanceof DERPrintableString;
    }

    /** Whether the value is a UTF8String (both releases parse one into {@link DERUTF8String}). */
    public static boolean isUtf8String(ASN1Encodable value) {
        return value instanceof DERUTF8String;
    }

    /** The text of an IA5String (a GeneralName URI, rfc822Name or dNSName); {@link IllegalArgumentException} for anything else. */
    public static String ia5String(ASN1Encodable value) {
        if (value instanceof DERIA5String && value instanceof ASN1String text) {
            return text.getString();
        }
        throw new IllegalArgumentException("not an IA5String: " + (value == null ? "null" : value.getClass().getSimpleName()));
    }
}
