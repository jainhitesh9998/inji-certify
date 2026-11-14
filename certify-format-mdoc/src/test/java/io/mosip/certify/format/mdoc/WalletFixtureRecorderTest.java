package io.mosip.certify.format.mdoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import io.mosip.certify.spi.ClaimSet;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.IssuedCredential;
import io.mosip.certify.spi.UnsignedCredential;
import org.junit.jupiter.api.Test;

import java.io.UncheckedIOException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Records an IssuerSigned exactly as {@link MdocFormatter} signs it, for the demo wallet's browser harness (P5-03a;
 * plan section 4.12): {@code docs/design/tools/fixtures/wallet/mdl-a.issuersigned}, an {@code org.iso.18013.5.1.mDL}
 * carrying the 15 elements the demo issues to {@code mdl-demo-1}, and {@code mdl-a.holder.jwk}, the holder key it was
 * issued to, beside the two things a verifier of the wallet's presentation needs (P5-03b): {@code iaca.pem}, the IACA
 * the recording's DSC chains to, and {@code clock.txt}, an instant inside the fixture's validity. The wallet harness used to build its own fixtures, and so drifted from what Certify really writes - an
 * IssuerAuth whose payload is a byte string holding {@code #6.24(bstr .cbor MSO)}, and a DSC-only {@code x5chain} as a
 * single bstr (RFC 9360 section 2). This recorder is the answer: the bytes the page is tested on come from the issuer.
 *
 * <p>The elements are {@code mdl-demo-1}'s record in {@code docker-compose/docker-compose-injistack/config/mdl/
 * holders.json} with its portrait file, in the order {@code config/mdl/mdl.vm} writes them, so the fixture is the demo's
 * credential and follows it when the demo data changes (the test fails if the record stops having those 15 elements).</p>
 *
 * <p>Like the golden recorders ({@code -Dgoldens.record=true}), the committed copy is written only when asked:</p>
 * <pre>mvn -B -pl certify-format-mdoc test -Dtest=WalletFixtureRecorderTest -Dwallet.fixture.record=true</pre>
 * <p>Every run of the module's tests, recording or not, runs it (its name is a surefire test name, so its assertions are
 * a build gate) and writes a copy to {@code certify-format-mdoc/target/wallet-fixture/} with the real clock, which is
 * what a CI interop job can feed a verifier. The assertions below are the test: they read the produced bytes with a CBOR
 * library the page does not share and check the layout, the x5chain form, the elements and every digest.</p>
 */
class WalletFixtureRecorderTest {

    private static final String FIXTURE = "mdl-a";
    /** The demo subject whose credential the fixture is (plan 4.12). */
    private static final String DEMO_SUBJECT = "mdl-demo-1";
    private static final Path DEMO_DATA = Paths.get("docker-compose/docker-compose-injistack/config/mdl");
    /** The elements in the order config/mdl/mdl.vm writes them for a record that has every optional one. */
    private static final List<String> TEMPLATE_ORDER = List.of("family_name", "given_name", "birth_date", "issue_date",
            "expiry_date", "issuing_country", "issuing_authority", "document_number", "portrait", "driving_privileges",
            "sex", "age_over_18", "nationality", "resident_city", "un_distinguishing_sign");
    private static final String MDL_NAMESPACE = MdlFixtures.MDL_NAMESPACE;
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /**
     * The instant the fixtures are issued at: this run's clock, truncated to the seconds {@code tdate} carries. Every
     * run, recording or not, issues at its own instant on purpose - the dev DSC and IACA are valid from theirs, and the
     * committed {@code clock.txt} has to sit inside the certificates' validity as well as the MSO's, which a pinned
     * instant could not do on a later re-record.
     */
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    @Test
    void theFormatterWritesTheLayoutTheWalletReads() throws Exception {
        boolean record = Boolean.getBoolean("wallet.fixture.record");
        Instant now = NOW;

        KeyPair holder = holderKeyPair();
        Map<String, Object> publicJwk = jwk((ECPublicKey) holder.getPublic());
        Map<String, Object> privateJwk = new LinkedHashMap<>(publicJwk);
        privateJwk.put("d", coordinate(((ECPrivateKey) holder.getPrivate()).getS(), 32));
        privateJwk.put("comment", "TEST KEY - NOT SECRET");

        MdocFormatter formatter = new MdocFormatter(new ObjectMapper(), MdlFixtures.properties(Duration.ofDays(90)));
        CredentialConfiguration configuration = MdlFixtures.configuration(formatter,
                Map.of("docType", MdlFixtures.MDL_DOCTYPE), AnnexBFixtures.dsc());
        IssuanceContext context = MdlFixtures.context(now);
        HolderBinding binding = HolderBinding.did(MAPPER.writeValueAsString(publicJwk), "jwt");

        UnsignedCredential unsigned = formatter.build(ClaimSet.of(demoDocument()), configuration, context, binding);
        IssuedCredential issued = formatter.sign(unsigned, AnnexBFixtures.signing(), context);
        byte[] issuerSignedBytes = Base64.getUrlDecoder().decode((String) issued.credential());

        // the layout, read with a CBOR library the page does not share
        CBORObject issuerSigned = CBORObject.DecodeFromBytes(issuerSignedBytes);
        assertEquals(MDL_NAMESPACE, issuerSigned.get("nameSpaces").getKeys().iterator().next().AsString(),
                "the document is the mDL namespace");
        CBORObject issuerAuth = issuerSigned.get("issuerAuth");
        assertEquals(CBORType.Array, issuerAuth.getType());
        assertEquals(4, issuerAuth.size(), "a COSE_Sign1 is [protected, unprotected, payload, signature] (RFC 9052 4.2)");
        assertEquals(CBORType.ByteString, issuerAuth.get(2).getType(),
                "the payload is a bstr (ISO/IEC 18013-5 9.1.2.4); the MSO is not the array element itself");
        byte[] payload = issuerAuth.get(2).GetByteString();
        CBORObject taggedMso = CBORObject.DecodeFromBytes(payload);
        assertTrue(taggedMso.HasMostOuterTag(24), "the payload's content is #6.24(bstr .cbor MSO)");
        assertEquals(CBORType.ByteString, taggedMso.Untag().getType(), "and the tag wraps a byte string");
        CBORObject mso = CBORObject.DecodeFromBytes(taggedMso.Untag().GetByteString());
        assertEquals(MdlFixtures.MDL_DOCTYPE, mso.get("docType").AsString());
        assertEquals("1.0", mso.get("version").AsString());
        // the device key is the holder the proof named: the wallet only keeps a credential issued to its own key
        CBORObject deviceKey = mso.get("deviceKeyInfo").get("deviceKey");
        assertArrayEquals(Base64.getUrlDecoder().decode((String) publicJwk.get("x")),
                deviceKey.get(CBORObject.FromObject(-2)).GetByteString());
        assertArrayEquals(Base64.getUrlDecoder().decode((String) publicJwk.get("y")),
                deviceKey.get(CBORObject.FromObject(-3)).GetByteString());
        // one ES256 digest per issued item, over the item bytes exactly as the IssuerSigned carries them
        CBORObject items = issuerSigned.get("nameSpaces").get(MDL_NAMESPACE);
        CBORObject valueDigests = mso.get("valueDigests").get(MDL_NAMESPACE);
        assertEquals(items.size(), valueDigests.size());
        List<String> identifiers = new ArrayList<>();
        for (CBORObject item : items.getValues()) {
            identifiers.add(CBORObject.DecodeFromBytes(item.Untag().GetByteString()).get("elementIdentifier").AsString());
        }
        assertEquals(TEMPLATE_ORDER.stream().sorted().toList(), identifiers.stream().sorted().toList(),
                "the fixture carries the 15 elements the demo issues to " + DEMO_SUBJECT);
        for (CBORObject item : items.getValues()) {
            assertTrue(item.HasMostOuterTag(24), "an IssuerSignedItemBytes is a tag-24 item");
            int digestId = CBORObject.DecodeFromBytes(item.Untag().GetByteString()).get("digestID").AsInt32();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(item.EncodeToBytes());
            assertArrayEquals(valueDigests.get(CBORObject.FromObject(digestId)).GetByteString(), digest,
                    "the item re-encodes to the bytes the MSO's valueDigest covers");
        }
        // Certify signs a DSC-only chain (the IACA is not carried: HAIP forbids it), which RFC 9360 section 2 encodes as
        // a single bstr rather than a one-element array
        CBORObject chain = issuerAuth.get(1).get(CBORObject.FromObject(33));
        assertEquals(CBORType.ByteString, chain.getType(),
                "a DSC-only x5chain is a single bstr (RFC 9360 section 2), which the wallet has to normalise to one cert");
        assertTrue(chain.GetByteString().length > 300, "the DSC is a real certificate");
        assertFalse(issuerAuth.isTagged(), "the formatter writes an untagged COSE_Sign1; the page accepts #6.18 too");

        // the clock the committed fixture is valid at: inside its MSO validity window (plan 4.12's clock.txt)
        Instant clock = now.plus(Duration.ofHours(1));
        write(Paths.get("").toAbsolutePath().resolve("target/wallet-fixture"), issuerSignedBytes, privateJwk, clock);
        if (record) {
            write(repoRoot().resolve("docs/design/tools/fixtures/wallet"), issuerSignedBytes, privateJwk, clock);
        }
    }

    /**
     * The template JSON config/mdl/mdl.vm renders for {@code mdl-demo-1}: its holders.json values in the template's
     * element order, the portrait file's bytes as the file data source serves them (unpadded base64url, F-15).
     */
    private static Map<String, Object> demoDocument() throws IOException {
        Path data = repoRoot().resolve(DEMO_DATA);
        Map<?, ?> holders = new ObjectMapper().readValue(data.resolve("holders.json").toFile(), Map.class);
        Map<?, ?> record = (Map<?, ?>) holders.get(DEMO_SUBJECT);
        assertEquals(TEMPLATE_ORDER.stream().sorted().toList(),
                record.keySet().stream().map(String::valueOf).sorted().toList(),
                DEMO_SUBJECT + " has the 15 elements the fixture records (plan 4.12)");
        List<Map<String, Object>> items = new ArrayList<>();
        for (String identifier : TEMPLATE_ORDER) {
            Object value = record.get(identifier);
            if ("portrait".equals(identifier)) {
                value = BASE64URL.encodeToString(Files.readAllBytes(data.resolve(String.valueOf(value))));
            }
            items.add(MdlFixtures.item(identifier, value));
        }
        Map<String, Object> namespaces = new LinkedHashMap<>();
        namespaces.put(MDL_NAMESPACE, items);
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("docType", MdlFixtures.MDL_DOCTYPE);
        document.put("nameSpaces", namespaces);
        return document;
    }

    private static void write(Path directory, byte[] issuerSigned, Map<String, Object> privateJwk, Instant clock) {
        try {
            Files.createDirectories(directory);
            Path signed = directory.resolve(FIXTURE + ".issuersigned");
            Files.write(signed, issuerSigned);
            Files.writeString(directory.resolve(FIXTURE + ".holder.jwk"), MAPPER.writeValueAsString(privateJwk) + "\n",
                    StandardCharsets.UTF_8);
            // the trust anchor the wallet's DeviceResponse is verified against, and the instant the fixture is valid at
            // (P5-03b): the DSC chains to the IACA this run generated, so the two are written together or not at all
            Files.writeString(directory.resolve("iaca.pem"), pem(iaca()), StandardCharsets.US_ASCII);
            Files.writeString(directory.resolve("clock.txt"), clock.toString() + "\n", StandardCharsets.UTF_8);
            System.out.println("[wallet-fixture] wrote " + signed + " (" + issuerSigned.length + " bytes)");
        } catch (IOException | CertificateEncodingException e) {
            throw new UncheckedIOException("the wallet fixture cannot be written", new IOException(e));
        }
    }

    /**
     * The IACA the recorded DSC chains to: the Annex B IACA of {@link AnnexBFixtures}, built by {@code certify-pki} the
     * way an operator builds one (plan 4.12), with the subject key identifier a verifier matches trust points against.
     */
    private static X509Certificate iaca() {
        return AnnexBFixtures.IACA;
    }

    private static String pem(X509Certificate certificate) throws IOException, CertificateEncodingException {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    /** The repository root, whether the build runs in the module or at the top. */
    private static Path repoRoot() {
        Path directory = Paths.get("").toAbsolutePath();
        while (directory != null && !Files.exists(directory.resolve("certify-format-mdoc/pom.xml"))) {
            directory = directory.getParent();
        }
        if (directory == null) {
            throw new IllegalStateException("the repository root is not above " + Paths.get("").toAbsolutePath());
        }
        return directory;
    }

    private static KeyPair holderKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    /** The public JWK of a P-256 key, its coordinates fixed-width as RFC 7518 section 6.2.1.2 requires. */
    private static Map<String, Object> jwk(ECPublicKey key) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", coordinate(key.getW().getAffineX(), 32));
        jwk.put("y", coordinate(key.getW().getAffineY(), 32));
        return jwk;
    }

    private static String coordinate(BigInteger value, int width) {
        byte[] padded = new byte[width];
        byte[] magnitude = value.toByteArray();
        int length = Math.min(magnitude.length, width);
        System.arraycopy(magnitude, magnitude.length - length, padded, width - length, length);
        return BASE64URL.encodeToString(padded);
    }
}
