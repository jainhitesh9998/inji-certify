/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import com.nimbusds.jose.jwk.JWK;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.MajorType;
import org.multipaz.cose.CoseNumberLabel;
import org.multipaz.cose.CoseSign1;
import org.multipaz.crypto.X509Cert;
import org.multipaz.crypto.X509CertChain;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * A recorded mDoc credential plus everything an independent verifier needs to check it, written by the tests that
 * issue credentials and read back by the conformance suite and {@code docs/design/tools/verify_mdoc.py}.
 *
 * <p>Files, side by side in one directory, named {@code <TestClass>-<surface>}:
 * <ul>
 *     <li>{@code <name>.mdoc} — the credential exactly as issued, base64url-decoded: an {@code IssuerSigned}, or the
 *     draft-13 {@code Document} {@code {docType, issuerSigned}} the 0.14.0 surface returns;</li>
 *     <li>{@code <name>.holder.jwk} — the holder public JWK the proof carried, expected to equal the MSO deviceKey;</li>
 *     <li>{@code <name>.doctype} — the docType the credential configuration asked for;</li>
 *     <li>{@code <name>.gaps} — the problems this sample is known to have, one {@code <check>:<code>} each
 *     ({@link AcceptedGaps});</li>
 *     <li>{@code <name>.iaca.pem} — the IACA, present only when the chain carries one (M-06 completes this).</li>
 * </ul>
 *
 * <p>Raw CBOR plus sidecars keep the samples free of any Java-only knowledge: the Python verifier reads the same
 * directory. Production code never sees this class; it lives in the test-only {@code certify-testkit-mdoc}.
 */
public final class MdocSamples {

    public static final String MDOC = ".mdoc";
    public static final String HOLDER_JWK = ".holder.jwk";
    public static final String DOCTYPE = ".doctype";
    public static final String GAPS = ".gaps";
    public static final String IACA_PEM = ".iaca.pem";

    /** Producers whose earlier samples this JVM already removed. */
    private static final Set<String> CLEANED = ConcurrentHashMap.newKeySet();

    /**
     * One sample on disk.
     *
     * @param received      the credential bytes as issued
     * @param issuerSigned  the {@code IssuerSigned} inside them, sliced out of a {@code Document} without re-encoding
     * @param documentDocType the {@code Document.docType} when the credential is a draft-13 {@code Document}
     */
    public record Sample(String name, Path path, byte[] received, byte[] issuerSigned, Optional<String> documentDocType,
                         JWK holder, String docType, AcceptedGaps gaps, Optional<X509Certificate> iaca) {}

    private MdocSamples() {}

    /** The sample name for a producing test class and the surface that issued the credential. */
    public static String name(Class<?> producer, String surface) {
        return producer.getSimpleName() + "-" + surface;
    }

    /**
     * Writes the sample {@code <producer>-<surface>} and returns the path of its {@code .mdoc} file. The first write of
     * a producer in this JVM first deletes that producer's earlier samples, so a renamed or dropped sample cannot
     * linger from an older build.
     */
    public static Path write(Path directory, Class<?> producer, String surface, byte[] credential, JWK holder,
                             String docType, AcceptedGaps gaps) {
        String name = name(producer, surface);
        try {
            Files.createDirectories(directory);
            if (CLEANED.add(directory.toAbsolutePath().normalize() + "/" + producer.getName())) {
                try (Stream<Path> files = Files.list(directory)) {
                    for (Path stale : files.filter(p -> p.getFileName().toString().startsWith(producer.getSimpleName() + "-")).toList()) {
                        Files.delete(stale);
                    }
                }
            }
            Path mdoc = directory.resolve(name + MDOC);
            Files.write(mdoc, credential);
            Files.writeString(directory.resolve(name + HOLDER_JWK), holder.toPublicJWK().toJSONString(), StandardCharsets.UTF_8);
            Files.writeString(directory.resolve(name + DOCTYPE), docType, StandardCharsets.UTF_8);
            Files.writeString(directory.resolve(name + GAPS), gaps.format(name), StandardCharsets.UTF_8);
            Optional<X509Certificate> iaca = iacaOf(issuerSignedOf(credential));
            if (iaca.isPresent()) {
                Files.writeString(directory.resolve(name + IACA_PEM), pem(iaca.get()), StandardCharsets.UTF_8);
            }
            return mdoc;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write the mDoc sample " + name, e);
        }
    }

    /** Reads a sample back from its {@code .mdoc} file and the sidecars next to it; every sidecar but the IACA is required. */
    public static Sample read(Path mdoc) {
        String file = mdoc.getFileName().toString();
        if (!file.endsWith(MDOC)) {
            throw new IllegalArgumentException(mdoc + " is not a " + MDOC + " sample");
        }
        String name = file.substring(0, file.length() - MDOC.length());
        Path directory = mdoc.getParent();
        try {
            byte[] received = Files.readAllBytes(mdoc);
            byte[] issuerSigned = issuerSignedOf(received);
            Optional<String> documentDocType = issuerSigned == received ? Optional.empty()
                    : Optional.ofNullable(Cbor.INSTANCE.decode(received).getOrNull("docType")).map(DataItem::getAsTstr);
            JWK holder = JWK.parse(Files.readString(sidecar(directory, name, HOLDER_JWK)));
            String docType = Files.readString(sidecar(directory, name, DOCTYPE)).trim();
            Path gapsFile = sidecar(directory, name, GAPS);
            AcceptedGaps gaps = AcceptedGaps.parse(Files.readString(gapsFile), gapsFile.toString());
            Path iaca = directory.resolve(name + IACA_PEM);
            return new Sample(name, mdoc, received, issuerSigned, documentDocType, holder, docType, gaps,
                    Files.isRegularFile(iaca) ? Optional.of(readPem(iaca)) : Optional.empty());
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read the mDoc sample " + mdoc, e);
        } catch (ParseException e) {
            throw new IllegalArgumentException("cannot parse the holder JWK next to " + mdoc, e);
        }
    }

    /** Every file that belongs to the sample whose {@code .mdoc} is {@code mdoc}, the {@code .mdoc} first. */
    public static List<Path> files(Path mdoc) {
        String file = mdoc.getFileName().toString();
        String name = file.substring(0, file.length() - MDOC.length());
        return Stream.of(MDOC, HOLDER_JWK, DOCTYPE, GAPS, IACA_PEM)
                .map(suffix -> mdoc.resolveSibling(name + suffix))
                .filter(Files::isRegularFile)
                .toList();
    }

    private static Path sidecar(Path directory, String name, String suffix) {
        Path path = directory.resolve(name + suffix);
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("the mDoc sample " + name + " has no " + suffix + " sidecar: the producing "
                    + "test must write it" + (GAPS.equals(suffix) ? ", even when it accepts no gap" : ""));
        }
        return path;
    }

    /**
     * The {@code IssuerSigned} of a credential: the bytes themselves, or the {@code issuerSigned} value of a draft-13
     * {@code Document}, sliced out of the received bytes rather than re-encoded.
     */
    public static byte[] issuerSignedOf(byte[] credential) {
        DataItem top = Cbor.INSTANCE.decode(credential);
        if (top.getMajorType() == MajorType.MAP && top.getOrNull("issuerSigned") != null) {
            return WireIssuerSignedItems.valueOf(credential, "issuerSigned");
        }
        return credential;
    }

    /**
     * The IACA of a credential, when the x5chain carries one: the last certificate, and only when the chain has more
     * than one certificate and that last one is self-signed. A chain of one has no anchor to hand out, and writing
     * its self-signed leaf as an "IACA" would make the chain-to-anchor check unpassable by construction.
     */
    public static Optional<X509Certificate> iacaOf(byte[] issuerSignedCbor) {
        DataItem issuerSigned = Cbor.INSTANCE.decode(issuerSignedCbor);
        DataItem issuerAuthItem = issuerSigned.get("issuerAuth");
        if (issuerAuthItem.getMajorType() == MajorType.TAG) {
            issuerAuthItem = issuerAuthItem.getAsTagged();
        }
        CoseSign1 issuerAuth = CoseSign1.Companion.fromDataItem(issuerAuthItem);
        DataItem x5chain = issuerAuth.getUnprotectedHeaders().get(new CoseNumberLabel(33));
        if (x5chain == null) {
            x5chain = issuerAuth.getProtectedHeaders().get(new CoseNumberLabel(33));
        }
        if (x5chain == null) {
            return Optional.empty();
        }
        X509CertChain chain = X509CertChain.Companion.fromDataItem(x5chain);
        List<X509Cert> certificates = chain.getCertificates();
        if (certificates.size() < 2) {
            return Optional.empty();
        }
        X509Cert last = certificates.get(certificates.size() - 1);
        if (!last.getSubject().equals(last.getIssuer())) {
            return Optional.empty();
        }
        try {
            kotlinx.io.bytestring.ByteString encoded = last.getEncoded();
            return Optional.of(certificate(encoded.toByteArray(0, encoded.getSize())));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("cannot read the last x5chain certificate: " + e.getMessage(), e);
        }
    }

    public static String pem(X509Certificate certificate) {
        try {
            return "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (CertificateException e) {
            throw new IllegalArgumentException("cannot encode " + certificate.getSubjectX500Principal(), e);
        }
    }

    private static X509Certificate readPem(Path path) {
        try (var in = Files.newInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + path, e);
        } catch (CertificateException e) {
            throw new IllegalArgumentException("cannot parse the certificate in " + path, e);
        }
    }

    private static X509Certificate certificate(byte[] der) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(der));
    }
}
