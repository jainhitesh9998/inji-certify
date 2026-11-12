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
 * configuration asked for, the checks the sample is known not to pass yet ({@code .gaps}) and, when the x5chain ends in
 * a self-signed anchor, that anchor as PEM. Files are named {@code <TestClass>-<surface>}, so a subclass such as
 * {@code IssuanceGoldenCoreTest} writes its own samples instead of overwriting its parent's. Raw CBOR plus sidecars keep
 * the samples readable by tools that know nothing about this code (docs/design/20-mdl-issuer.md M-01, gap G24).
 *
 * <p>This module deliberately has no dependency on {@code certify-testkit-mdoc}, not even in test scope: the verifier's
 * Kotlin runtime must stay off certify-service's classpath. The sidecar format is the testkit's {@code AcceptedGaps}
 * ({@code <check>[?] # <reason>}); the conformance module refuses an unknown check name or a line without a reason.
 */
final class MdocSampleWriter {

    static final Path DIRECTORY = Path.of("target", "mdoc-samples");

    /** Producers whose earlier samples this JVM already removed. */
    private static final Set<String> CLEANED = ConcurrentHashMap.newKeySet();

    /** One accepted gap: the verifier's check name, why it cannot pass today and what fixes it. */
    record Gap(String check, String reason, boolean intermittent) {

        static Gap of(String check, String reason) {
            return new Gap(check, reason, false);
        }

        /** A gap whose failure depends on a value the product draws at random: the check may pass or fail. */
        static Gap intermittent(String check, String reason) {
            return new Gap(check, reason, true);
        }

        String line() {
            return check + (intermittent ? "?" : "") + " # " + reason;
        }
    }

    // What the keymanager-signed mDoc of either issuance path cannot pass yet (docs/design/20-mdl-issuer.md gaps).
    static final Gap TDATE_MILLISECONDS = Gap.of("mso.validityInfo.tdateTags",
            "G1: signed/validFrom/validUntil carry milliseconds (UTC_DATETIME_PATTERN); fixed by M-02");
    static final Gap TDATE_MILLISECONDS_UNTAGGED = Gap.of("mso.validityInfo.tdateTags",
            "G1: dates carry milliseconds, and validFrom/validUntil filled by the template engine are plain tstr without tag 0; fixed by M-02");
    static final Gap KEYMANAGER_NO_IACA = Gap.of("x5chain.iaca",
            "G13: the keymanager x5chain is the master-signed leaf alone, there is no IACA to anchor it; M-06");
    static final Gap KEYMANAGER_SERIAL = Gap.intermittent("x5chain.serialNumber",
            "G27: keymanager draws certificate serials from SecureRandom.nextLong(), negative in about half the runs; M-06/keymanager provider");
    static final Gap UNTYPED_ELEMENTS = Gap.of("mdl.elementTypes",
            "G2/G3: the golden template's elements are untyped strings and Table 5 mandatory elements are missing; fixed by M-03");
    static final Gap SIGNED_AFTER_VALID_FROM = Gap.of("mso.validityInfo",
            "G8: through the core validFrom is the request instant and signed the formatter's wall clock, milliseconds later; fixed by M-02/M-03");
    static final Gap MULTIPAZ_REFUSES_MSO = Gap.of("mso.parse",
            "G1: Multipaz's MobileSecurityObject parser refuses the untagged validFrom/validUntil, so a Multipaz wallet cannot read the MSO; fixed by M-02");

    /** The legacy service path ({@code CertifyIssuanceServiceImpl} + {@code utils/MDocProcessor}) signs at validFrom. */
    static final List<Gap> LEGACY_SERVICE_GAPS = List.of(TDATE_MILLISECONDS, KEYMANAGER_NO_IACA, KEYMANAGER_SERIAL, UNTYPED_ELEMENTS);
    /** Every path through the core ({@code DefaultIssuanceService} + {@code certify-format-mdoc}). */
    static final List<Gap> CORE_GAPS = List.of(MULTIPAZ_REFUSES_MSO, SIGNED_AFTER_VALID_FROM, TDATE_MILLISECONDS_UNTAGGED,
            KEYMANAGER_NO_IACA, KEYMANAGER_SERIAL, UNTYPED_ELEMENTS);

    private MdocSampleWriter() {}

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
                .append("# One check per line, \"<check>[?] # <reason>\"; '?' marks an intermittent gap.\n")
                .append("# certify-conformance-mdoc fails when an unlisted check does not pass, and when a listed one passes.\n");
        gaps.forEach(gap -> sidecar.append(gap.line()).append('\n'));
        Files.writeString(DIRECTORY.resolve(name + ".gaps"), sidecar.toString());
        X509Certificate anchor = selfSignedAnchor(received);
        if (anchor != null) {
            Files.writeString(DIRECTORY.resolve(name + ".iaca.pem"), "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(anchor.getEncoded())
                    + "\n-----END CERTIFICATE-----\n");
        }
    }

    /** The last x5chain certificate when the chain has more than the leaf and that one is self-issued, else null. */
    private static X509Certificate selfSignedAnchor(byte[] received) {
        try {
            CBORObject root = CBORObject.DecodeFromBytes(received);
            CBORObject issuerSigned = root.ContainsKey("issuerSigned") ? root.get("issuerSigned") : root; // draft-13 Document
            CBORObject issuerAuth = issuerSigned.get("issuerAuth");
            CBORObject chain = (issuerAuth.isTagged() ? issuerAuth.Untag() : issuerAuth).get(1).get(CBORObject.FromObject(33));
            if (chain == null) {
                return null;
            }
            List<byte[]> der = new ArrayList<>();
            if (chain.getType() == CBORType.Array) {
                chain.getValues().forEach(certificate -> der.add(certificate.GetByteString()));
            } else {
                der.add(chain.GetByteString());
            }
            if (der.size() < 2) {
                return null; // one certificate is the leaf, not an anchor to hand out
            }
            X509Certificate last = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der.get(der.size() - 1)));
            return last.getSubjectX500Principal().equals(last.getIssuerX500Principal()) ? last : null;
        } catch (Exception e) {
            return null; // the conformance run reports an unreadable credential; the sample is written regardless
        }
    }
}
