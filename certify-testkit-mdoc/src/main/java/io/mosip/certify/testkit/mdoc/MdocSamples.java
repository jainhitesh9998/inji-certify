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
import org.multipaz.crypto.X509CertChainJvmKt;

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
 *     <li>{@code <name>.iaca.pem} — the IACA the verifier anchors to: the one the chain carries, or the configured
 *     trust anchor the producer hands over (M-06; HAIP keeps it out of the x5chain).</li>
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
    /** The status list the MSO's {@code status.status_list.uri} names, byte for byte as the endpoint answered it. */
    public static final String STATUSLIST_CWT = ".statuslist.cwt";
    /** The {@code Content-Type} the status list was served with (M-11b: both sidecars are required together). */
    public static final String STATUSLIST_CONTENT_TYPE = ".statuslist.ct";

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
                         JWK holder, String docType, AcceptedGaps gaps, Optional<X509Certificate> iaca,
                         Optional<StatusListToken> statusList, StatusListReference statusListReference,
                         List<X509Certificate> issuerAuthX5chain) {

        /** The MSO's {@code {uri, idx}} when it is present and well formed. */
        public Optional<StatusListInfo> statusListInfo() {
            return statusListReference.info();
        }

        /** Why the MSO's {@code status.status_list} cannot be used, when it is present but malformed. */
        public Optional<String> statusListMalformed() {
            return statusListReference.malformed();
        }
    }

    /**
     * A status list as the endpoint served it: the body as received and the {@code Content-Type}. M-11b's verifier
     * takes both, because a JWT body with the right media type and a CWT body with the wrong one are two different
     * defects (TSL 8.2).
     */
    public record StatusListToken(byte[] body, String contentType) {}

    /**
     * The MSO's {@code status.status_list}: {@code uri} and {@code idx} (ISO/IEC 18013-5 second edition 12.3.6,
     * TSL 6.3). A sample whose MSO carries one must also record the list itself, in the two sidecars above.
     */
    public record StatusListInfo(String uri, long idx) {}

    /**
     * What the MSO says about the status list: <b>absent</b> (no {@code status.status_list}), <b>present</b> as
     * {@code {uri: tstr, idx: uint}}, or <b>malformed</b> with the reason — present but not usable, for example
     * {@code idx} as text or negative, a missing {@code uri}, or {@code status_list} as an array. The distinction is
     * the point: a malformed reference must fail the sample rather than silently skip the list, because a wallet
     * cannot fetch a list it cannot address. An IssuerAuth or MSO that cannot be read at all is M-01's problem, and
     * answers absent here.
     */
    public record StatusListReference(Optional<StatusListInfo> info, Optional<String> malformed) {

        public StatusListReference {
            if (info.isPresent() && malformed.isPresent()) {
                throw new IllegalArgumentException("a status_list reference is either present or malformed, not both");
            }
        }

        public static StatusListReference absent() {
            return new StatusListReference(Optional.empty(), Optional.empty());
        }

        public static StatusListReference present(StatusListInfo info) {
            return new StatusListReference(Optional.of(info), Optional.empty());
        }

        public static StatusListReference malformed(String reason) {
            return new StatusListReference(Optional.empty(), Optional.of(reason));
        }

        public boolean isMalformed() {
            return malformed.isPresent();
        }
    }

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
        return write(directory, producer, surface, credential, holder, docType, gaps, null);
    }

    /**
     * As {@link #write(Path, Class, String, byte[], JWK, String, AcceptedGaps)}, with the IACA the verifier is given:
     * the issuer's configured trust anchor (M-06), which an x5chain without its anchor does not carry. {@code null}
     * writes the IACA only when the chain carries one.
     */
    public static Path write(Path directory, Class<?> producer, String surface, byte[] credential, JWK holder,
                             String docType, AcceptedGaps gaps, X509Certificate trustAnchor) {
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
            Optional<X509Certificate> iaca = trustAnchor != null ? Optional.of(trustAnchor) : iacaOf(issuerSignedOf(credential));
            if (iaca.isPresent()) {
                Files.writeString(directory.resolve(name + IACA_PEM), pem(iaca.get()), StandardCharsets.UTF_8);
            }
            return mdoc;
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write the mDoc sample " + name, e);
        }
    }

    /**
     * Writes the status list a sample's MSO points at, beside its {@code .mdoc}: the body exactly as the endpoint
     * answered it ({@code <name>.statuslist.cwt}) and its {@code Content-Type} ({@code <name>.statuslist.ct}). The
     * producer of a sample whose MSO carries {@code status.status_list} writes both; the conformance run requires
     * them together (M-11b).
     */
    public static void writeStatusList(Path mdoc, byte[] body, String contentType) {
        String file = mdoc.getFileName().toString();
        if (!file.endsWith(MDOC)) {
            throw new IllegalArgumentException(mdoc + " is not a " + MDOC + " sample");
        }
        String name = file.substring(0, file.length() - MDOC.length());
        try {
            Files.write(mdoc.resolveSibling(name + STATUSLIST_CWT), body);
            Files.writeString(mdoc.resolveSibling(name + STATUSLIST_CONTENT_TYPE), contentType, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write the status list of the mDoc sample " + name, e);
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
            Path statusListBody = directory.resolve(name + STATUSLIST_CWT);
            Path statusListType = directory.resolve(name + STATUSLIST_CONTENT_TYPE);
            Optional<StatusListToken> statusList = Optional.empty();
            if (Files.isRegularFile(statusListBody) || Files.isRegularFile(statusListType)) {
                if (!Files.isRegularFile(statusListBody) || !Files.isRegularFile(statusListType)) {
                    throw new IllegalStateException("the mDoc sample " + name + " records " + STATUSLIST_CWT + " and "
                            + STATUSLIST_CONTENT_TYPE + " together: the body without its Content-Type cannot be held to "
                            + "TSL 8.2, and a Content-Type without a body says nothing");
                }
                statusList = Optional.of(new StatusListToken(Files.readAllBytes(statusListBody),
                        Files.readString(statusListType).trim()));
            }
            return new Sample(name, mdoc, received, issuerSigned, documentDocType, holder, docType, gaps,
                    Files.isRegularFile(iaca) ? Optional.of(readPem(iaca)) : Optional.empty(),
                    statusList, statusListReferenceOf(issuerSigned), issuerAuthX5chainOf(issuerSigned));
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
        return Stream.of(MDOC, HOLDER_JWK, DOCTYPE, GAPS, IACA_PEM, STATUSLIST_CWT, STATUSLIST_CONTENT_TYPE)
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
     * The MSO's {@code status.status_list}, read from the bytes as received, in three outcomes: absent, present as
     * {@code {uri: tstr, idx: uint}}, or malformed with the reason ({@link StatusListReference}). An IssuerAuth or MSO
     * that cannot be read at all answers absent: that is M-01's check, not this one. Once the MSO map is read, a
     * {@code status} that is there but unusable is malformed, never absent — a gate that skipped those silently would
     * let a wallet-facing defect through.
     */
    public static StatusListReference statusListReferenceOf(byte[] issuerSignedCbor) {
        DataItem mso;
        try {
            DataItem issuerSigned = Cbor.INSTANCE.decode(issuerSignedCbor);
            DataItem issuerAuthItem = issuerSigned.get("issuerAuth");
            if (issuerAuthItem.getMajorType() == MajorType.TAG) {
                issuerAuthItem = issuerAuthItem.getAsTagged();
            }
            CoseSign1 issuerAuth = CoseSign1.Companion.fromDataItem(issuerAuthItem);
            byte[] payload = issuerAuth.getPayload();
            if (payload == null) {
                return StatusListReference.absent();
            }
            mso = Cbor.INSTANCE.decode(payload);
            if (mso.getMajorType() == MajorType.TAG) {
                mso = mso.getAsTaggedEncodedCbor();
            }
            if (mso.getMajorType() != MajorType.MAP) {
                return StatusListReference.absent();
            }
        } catch (Throwable e) {
            if (e instanceof VirtualMachineError fatal && !(e instanceof StackOverflowError)) {
                throw fatal;
            }
            return StatusListReference.absent();
        }
        try {
            DataItem status = mso.getOrNull("status");
            if (status == null) {
                return StatusListReference.absent();
            }
            if (status.getMajorType() != MajorType.MAP) {
                return StatusListReference.malformed("status is " + describe(status) + ", not the map ISO/IEC 18013-5 "
                        + "second edition 12.3.6 defines ({status_list: StatusListInfo})");
            }
            DataItem statusList = status.getOrNull("status_list");
            if (statusList == null) {
                // ISO/IEC 18013-5 second edition 12.3.6: Status = { ? "status_list", ? "identifier_list", * tstr => RFU },
                // so a status map without status_list (identifier_list only, or RFU keys) is valid and has no list.
                return StatusListReference.absent();
            }
            if (statusList.getMajorType() != MajorType.MAP) {
                return StatusListReference.malformed("status_list is " + describe(statusList) + ", not the map "
                        + "{uri: tstr, idx: uint} of ISO/IEC 18013-5 second edition 12.3.6");
            }
            DataItem uri = statusList.getOrNull("uri");
            if (uri == null) {
                return StatusListReference.malformed("status_list has no uri; it is the URL TSL 8.1 has the wallet GET");
            }
            if (uri.getMajorType() != MajorType.UNICODE_STRING) {
                return StatusListReference.malformed("status_list.uri is " + describe(uri) + ", not a tstr");
            }
            DataItem idx = statusList.getOrNull("idx");
            if (idx == null) {
                return StatusListReference.malformed("status_list has no idx; TSL 6.3 makes it the index of this "
                        + "credential in the list");
            }
            if (idx.getMajorType() != MajorType.UNSIGNED_INTEGER) {
                return StatusListReference.malformed("status_list.idx is " + describe(idx) + ", not the unsigned integer "
                        + "TSL 6.3 requires");
            }
            long number;
            try {
                number = idx.getAsNumber();
            } catch (RuntimeException e) {
                return StatusListReference.malformed("status_list.idx " + describe(idx) + " cannot be read as an index: "
                        + e.getMessage());
            }
            return StatusListReference.present(new StatusListInfo(uri.getAsTstr(), number));
        } catch (Throwable e) {
            if (e instanceof VirtualMachineError fatal && !(e instanceof StackOverflowError)) {
                throw fatal;
            }
            return StatusListReference.malformed("the MSO's status.status_list cannot be read: " + e.getMessage());
        }
    }

    /** A CBOR value as the malformed reasons spell it: its type and at most 60 characters of it. */
    private static String describe(DataItem value) {
        String text = value.getMajorType() + " " + value;
        return text.length() <= 60 ? text : text.substring(0, 57) + "...";
    }

    /**
     * The credential's IssuerAuth {@code x5chain} as received, leaf first: what the status list's own chain has to
     * equal for Credo and Paradym to accept it (M-11b {@code statusList.issuanceChain}).
     */
    public static List<X509Certificate> issuerAuthX5chainOf(byte[] issuerSignedCbor) {
        try {
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
                return List.of();
            }
            X509CertChain chain = X509CertChain.Companion.fromDataItem(x5chain);
            return X509CertChainJvmKt.getJavaX509Certificates(chain);
        } catch (Throwable e) {
            if (e instanceof VirtualMachineError fatal && !(e instanceof StackOverflowError)) {
                throw fatal;
            }
            return List.of();
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
