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

/**
 * A recorded IssuerSigned credential plus everything an independent verifier needs to check it, written by the tests
 * that issue credentials and read back by the conformance suite and {@code docs/design/tools/verify_mdoc.py}.
 *
 * <p>Files, side by side in one directory:
 * <ul>
 *     <li>{@code <name>.mdoc} — the raw {@code IssuerSigned} CBOR exactly as issued (not base64);</li>
 *     <li>{@code <name>.holder.jwk} — the holder public JWK the proof carried, expected to equal the MSO deviceKey;</li>
 *     <li>{@code <name>.doctype} — the docType the credential configuration asked for;</li>
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
    public static final String IACA_PEM = ".iaca.pem";

    /** One sample on disk. The IACA is absent when the credential's chain does not carry one. */
    public record Sample(Path issuerSigned, JWK holder, String docType, Optional<X509Certificate> iaca) {}

    private MdocSamples() {}

    /** Writes the sample and returns the path of the {@code .mdoc} file. */
    public static Path write(Path directory, String name, byte[] issuerSignedCbor, JWK holder, String docType) {
        try {
            Files.createDirectories(directory);
            Path mdoc = directory.resolve(name + MDOC);
            Files.write(mdoc, issuerSignedCbor);
            Files.writeString(directory.resolve(name + HOLDER_JWK), holder.toPublicJWK().toJSONString(),
                    StandardCharsets.UTF_8);
            Files.writeString(directory.resolve(name + DOCTYPE), docType, StandardCharsets.UTF_8);
            Optional<X509Certificate> iaca = iacaOf(issuerSignedCbor);
            if (iaca.isPresent()) {
                Files.writeString(directory.resolve(name + IACA_PEM), pem(iaca.get()), StandardCharsets.UTF_8);
            }
            return mdoc;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write the mDoc sample " + name, e);
        }
    }

    /** Reads a sample back from its {@code .mdoc} file and the sidecars next to it. */
    public static Sample read(Path mdoc) {
        String name = mdoc.getFileName().toString();
        if (!name.endsWith(MDOC)) {
            throw new IllegalArgumentException(mdoc + " is not a " + MDOC + " sample");
        }
        Path directory = mdoc.getParent();
        try {
            JWK holder = JWK.parse(Files.readString(directory.resolve(name.substring(0, name.length() - MDOC.length()) + HOLDER_JWK)));
            String docType = Files.readString(directory.resolve(name.substring(0, name.length() - MDOC.length()) + DOCTYPE)).trim();
            Path iaca = directory.resolve(name.substring(0, name.length() - MDOC.length()) + IACA_PEM);
            return new Sample(mdoc, holder, docType, Files.isRegularFile(iaca) ? Optional.of(readPem(iaca)) : Optional.empty());
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read the mDoc sample " + mdoc, e);
        } catch (ParseException e) {
            throw new IllegalArgumentException("cannot parse the holder JWK next to " + mdoc, e);
        }
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
