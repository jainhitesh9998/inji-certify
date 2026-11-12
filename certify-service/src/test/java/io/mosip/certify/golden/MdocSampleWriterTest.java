package io.mosip.certify.golden;

import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code .gaps} the service writes: G27's {@code x5chain.serialNumber:nonPositive} follows the leaf serial in the
 * received bytes (keymanager draws its sign at random), so the conformance gate is exact on every run; a zero or an
 * overlong serial is never declared and therefore fails there (certify-testkit-mdoc {@code MdocVerifierRulesTest}).
 */
class MdocSampleWriterTest {

    static final Pattern LINE = Pattern.compile("[A-Za-z0-9_.]+:[A-Za-z][A-Za-z0-9]*(:[A-Za-z0-9_.\\-/]+)? # \\S.*");

    @Test
    void aNegativeLeafSerialDeclaresG27() throws Exception {
        assertTrue(MdocSampleWriter.gapsFor(issuerSigned(BigInteger.valueOf(-5), false), MdocSampleWriter.CORE_GAPS)
                .contains(MdocSampleWriter.KEYMANAGER_NEGATIVE_SERIAL));
        assertTrue(MdocSampleWriter.gapsFor(issuerSigned(BigInteger.valueOf(-5), true), MdocSampleWriter.D13_GAPS)
                .contains(MdocSampleWriter.KEYMANAGER_NEGATIVE_SERIAL), "read through the draft-13 Document and tag 18");
    }

    @Test
    void aPositiveLeafSerialDeclaresNothing() throws Exception {
        assertEquals(MdocSampleWriter.CORE_GAPS,
                MdocSampleWriter.gapsFor(issuerSigned(BigInteger.valueOf(7), false), MdocSampleWriter.CORE_GAPS));
    }

    @Test
    void aZeroOrOverlongSerialIsNeverDeclaredUnderItsOwnCode() throws Exception {
        // zero is non-positive, so nonPositive is declared and the gate still fails on the undeclared :zero
        List<MdocSampleWriter.Gap> zero = MdocSampleWriter.gapsFor(issuerSigned(BigInteger.ZERO, false), List.of());
        assertEquals(List.of(MdocSampleWriter.KEYMANAGER_NEGATIVE_SERIAL), zero);
        assertEquals(List.of(), MdocSampleWriter.gapsFor(issuerSigned(BigInteger.TWO.pow(159), false), List.of()),
                "21 octets: tooLong is reported by the verifier and declared by nobody");
    }

    @Test
    void everyDeclaredGapIsOneProblemCodeWithAReason() {
        Stream.of(MdocSampleWriter.LEGACY_SERVICE_GAPS, MdocSampleWriter.CORE_GAPS, MdocSampleWriter.D13_GAPS,
                        List.of(MdocSampleWriter.KEYMANAGER_NEGATIVE_SERIAL))
                .flatMap(List::stream)
                .forEach(gap -> assertTrue(LINE.matcher(gap.line()).matches(), gap.line()));
        assertFalse(MdocSampleWriter.CORE_GAPS.contains(MdocSampleWriter.DOCUMENT_WRAPPER), "the shape is the d13 sample's alone");
        assertTrue(MdocSampleWriter.D13_GAPS.containsAll(List.of(MdocSampleWriter.DOCUMENT_WRAPPER, MdocSampleWriter.TAGGED_ISSUER_AUTH)));
        assertEquals(MdocSampleWriter.D13_GAPS.size(), MdocSampleWriter.D13_GAPS.stream().distinct().count());
    }

    /** {issuerAuth: [h'', {33: leaf}, h'', h''], nameSpaces: {}}, or the draft-13 Document around it with tag 18. */
    static byte[] issuerSigned(BigInteger serial, boolean draft13) throws Exception {
        CBORObject issuerAuth = CBORObject.NewArray().Add(new byte[0])
                .Add(CBORObject.NewMap().Add(33, certificate(serial).getEncoded())).Add(new byte[0]).Add(new byte[0]);
        CBORObject issuerSigned = CBORObject.NewMap()
                .Add("issuerAuth", draft13 ? CBORObject.FromObjectAndTag(issuerAuth, 18) : issuerAuth)
                .Add("nameSpaces", CBORObject.NewMap());
        return (draft13 ? CBORObject.NewMap().Add("docType", "org.iso.18013.5.1.mDL").Add("issuerSigned", issuerSigned)
                : issuerSigned).EncodeToBytes();
    }

    static X509Certificate certificate(BigInteger serial) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=serial " + serial);
        Instant now = Instant.now();
        return new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(name, serial,
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)), name, keys.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }
}
