package io.mosip.certify.golden;

import com.nimbusds.jose.jwk.JWK;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Writes what {@code certify-conformance-mdoc} and {@code docs/design/tools/verify_mdoc.py} re-verify after the service
 * tests: the credential exactly as a wallet received it (base64url-decoded), the holder public JWK, the docType the
 * configuration asked for, the problems the sample is known to have ({@code .gaps}) and, when the x5chain ends in a
 * self-signed anchor, that anchor as PEM. Files are named {@code <TestClass>-<surface>}, so a subclass such as
 * {@code IssuanceGoldenCoreTest} writes its own samples instead of overwriting its parent's. Raw CBOR plus sidecars keep
 * the samples readable by tools that know nothing about this code (docs/design/20-mdl-issuer.md M-01, gap G24).
 *
 * <p>This module deliberately has no dependency on {@code certify-testkit-mdoc}, not even in test scope: the verifier's
 * Kotlin runtime must stay off certify-service's classpath. The sidecar format is the testkit's {@code AcceptedGaps}:
 * one {@code <check>:<code> # <reason>} line per problem, the codes of {@code IndependentMdocVerifier.PROBLEM_CODES};
 * the conformance module refuses an unknown check or code, a bare check name and a line without a reason, and fails
 * on a reported problem not declared here as well as on a declared one no longer reported.
 */
final class MdocSampleWriter {

    static final Path DIRECTORY = Path.of("target", "mdoc-samples");

    /** Producers whose earlier samples this JVM already removed. */
    private static final Set<String> CLEANED = ConcurrentHashMap.newKeySet();

    /** One accepted problem: the verifier's check, one of its problem codes, why it is there and what fixes it. */
    record Gap(String check, String code, String reason) {

        String line() {
            return check + ":" + code + " # " + reason;
        }
    }

    // What the keymanager-signed mDoc of either issuance path cannot pass yet (docs/design/20-mdl-issuer.md gaps).
    private static final String G1_MILLISECONDS = "G1: the legacy utils.MDocProcessor writes signed/validFrom/validUntil with milliseconds"
            + " (UTC_DATETIME_PATTERN); the refactored formatter (M-02) does not, and the legacy path is retired with the compat-core flip";

    static final List<Gap> TDATE_MILLISECONDS = List.of(
            new Gap("mso.validityInfo.tdateTags", "fractionalSeconds:signed", G1_MILLISECONDS),
            new Gap("mso.validityInfo.tdateTags", "fractionalSeconds:validFrom", G1_MILLISECONDS),
            new Gap("mso.validityInfo.tdateTags", "fractionalSeconds:validUntil", G1_MILLISECONDS));
    /**
     * The legacy processor has no element typing: the Table 5 template's base64 portrait stays a tstr. Its dates and
     * {@code driving_privileges} pass through its date heuristic, so portrait is the only element problem it has.
     */
    static final Gap LEGACY_UNTYPED_PORTRAIT = new Gap("mdl.elementTypes", "untyped:portrait",
            "G2: the legacy utils.MDocProcessor has no element typing and writes the base64 portrait as a tstr; the refactored"
                    + " formatter (M-03) writes a bstr, and the legacy path is retired with the compat-core flip");
    static final Gap KEYMANAGER_NO_IACA = new Gap("x5chain.iaca", "noAnchorSupplied",
            "G13: the keymanager x5chain is the master-signed leaf alone, there is no IACA to anchor it; M-06");
    /** Declared by {@link #write} exactly when the received leaf serial is not positive; zero and overlong never are. */
    static final Gap KEYMANAGER_NEGATIVE_SERIAL = new Gap("x5chain.serialNumber", "nonPositive",
            "G27: keymanager drew this certificate's serial from SecureRandom.nextLong(), negative in about half the runs; M-06/keymanager provider");
    private static final String D13_COMPATIBILITY = "0.14.0 wire compatibility on the draft-13 surface (decision log 2026-09-19, "
            + "D13Mdoc): wallets built for 0.14.0 parse this shape; the /oid4vci and legacy surfaces return the bare untagged form";
    static final Gap DOCUMENT_WRAPPER = new Gap("credential.shape", "documentWrapper",
            "the draft-13 credential is the 0.14.0 Document {docType, issuerSigned}, not the bare IssuerSigned; " + D13_COMPATIBILITY);
    static final Gap TAGGED_ISSUER_AUTH = new Gap("issuerAuth.untagged", "tagged",
            "the draft-13 IssuerAuth carries COSE tag 18 as 0.14.0 did (ISO/IEC 18013-5 9.1.2.4 wants it untagged); " + D13_COMPATIBILITY);

    /**
     * The legacy service path ({@code CertifyIssuanceServiceImpl} + the unchanged {@code utils/MDocProcessor}), which
     * M-02/M-03 leave alone (rule 1: its wire bytes are the {@code legacy-develop} golden).
     */
    static final List<Gap> LEGACY_SERVICE_GAPS = concat(TDATE_MILLISECONDS, List.of(KEYMANAGER_NO_IACA, LEGACY_UNTYPED_PORTRAIT));
    /**
     * Every path through the core ({@code DefaultIssuanceService} + {@code certify-format-mdoc}): after M-02/M-03 only the
     * missing trust anchor is left (and G27 when keymanager drew a negative serial, see {@link #gapsFor}).
     */
    static final List<Gap> CORE_GAPS = List.of(KEYMANAGER_NO_IACA);
    /** The draft-13 surface: the core's gaps plus the two 0.14.0 shape deviations it keeps on purpose. */
    static final List<Gap> D13_GAPS = concat(CORE_GAPS, List.of(DOCUMENT_WRAPPER, TAGGED_ISSUER_AUTH));

    private MdocSampleWriter() {}

    @SafeVarargs
    private static List<Gap> concat(List<Gap>... lists) {
        return Stream.of(lists).flatMap(List::stream).toList();
    }

    /**
     * Writes the sample {@code <producer>-<surface>}. The first write of a producer in this JVM deletes that producer's
     * earlier samples, so a renamed or dropped sample cannot linger from an older build.
     */
    static void write(Class<?> producer, String surface, String credential, JWK holder, String docType, List<Gap> gaps)
            throws IOException, java.security.cert.CertificateEncodingException {
        String name = producer.getSimpleName() + "-" + surface;
        Files.createDirectories(DIRECTORY);
        if (CLEANED.add(producer.getName())) {
            try (Stream<Path> files = Files.list(DIRECTORY)) {
                for (Path stale : files.filter(p -> p.getFileName().toString().startsWith(producer.getSimpleName() + "-")).toList()) {
                    Files.delete(stale);
                }
            }
        }
        byte[] received = Base64.getUrlDecoder().decode(credential);
        Files.write(DIRECTORY.resolve(name + ".mdoc"), received);
        Files.writeString(DIRECTORY.resolve(name + ".holder.jwk"), holder.toPublicJWK().toJSONString());
        Files.writeString(DIRECTORY.resolve(name + ".doctype"), docType);
        StringBuilder sidecar = new StringBuilder("# Accepted gaps of the mDoc sample ").append(name)
                .append(" (docs/design/20-mdl-issuer.md M-01), written by ").append(producer.getName()).append(".\n")
                .append("# One problem per line, \"<check>:<code> # <reason>\" (IndependentMdocVerifier.PROBLEM_CODES).\n")
                .append("# certify-conformance-mdoc fails on a reported problem not listed here and on a listed one no longer reported.\n");
        gapsFor(received, gaps).forEach(gap -> sidecar.append(gap.line()).append('\n'));
        Files.writeString(DIRECTORY.resolve(name + ".gaps"), sidecar.toString());
        List<X509Certificate> chain = x5chain(received);
        X509Certificate anchor = chain.size() < 2 ? null : chain.get(chain.size() - 1); // a lone leaf is not an anchor
        if (anchor != null && anchor.getSubjectX500Principal().equals(anchor.getIssuerX500Principal())) {
            Files.writeString(DIRECTORY.resolve(name + ".iaca.pem"), "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(anchor.getEncoded())
                    + "\n-----END CERTIFICATE-----\n");
        }
    }

    /**
     * {@code gaps}, plus G27's {@code x5chain.serialNumber:nonPositive} exactly when the leaf certificate the credential
     * carries has a serial {@code <= 0}: keymanager draws the sign at random, so the sidecar follows the bytes and the
     * gate stays exact on every run. A zero or overlong serial is reported under its own code and never declared.
     */
    static List<Gap> gapsFor(byte[] received, List<Gap> gaps) {
        List<X509Certificate> chain = x5chain(received);
        if (chain.isEmpty() || chain.get(0).getSerialNumber().signum() > 0) {
            return gaps;
        }
        return concat(gaps, List.of(KEYMANAGER_NEGATIVE_SERIAL));
    }

    /** The x5chain certificates the credential carries, leaf first, or empty when they cannot be read. */
    static List<X509Certificate> x5chain(byte[] received) {
        try {
            CBORObject root = CBORObject.DecodeFromBytes(received);
            CBORObject issuerSigned = root.ContainsKey("issuerSigned") ? root.get("issuerSigned") : root; // draft-13 Document
            CBORObject issuerAuth = issuerSigned.get("issuerAuth");
            CBORObject chain = (issuerAuth.isTagged() ? issuerAuth.Untag() : issuerAuth).get(1).get(CBORObject.FromObject(33));
            if (chain == null) {
                return List.of();
            }
            List<byte[]> der = new ArrayList<>();
            if (chain.getType() == CBORType.Array) {
                chain.getValues().forEach(certificate -> der.add(certificate.GetByteString()));
            } else {
                der.add(chain.GetByteString());
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certificates = new ArrayList<>();
            for (byte[] certificate : der) {
                certificates.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificate)));
            }
            return certificates;
        } catch (Exception e) {
            return List.of(); // the conformance run reports an unreadable credential; the sample is written regardless
        }
    }
}
