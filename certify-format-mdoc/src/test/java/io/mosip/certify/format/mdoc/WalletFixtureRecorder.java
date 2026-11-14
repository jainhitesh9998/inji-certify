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
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Records an IssuerSigned exactly as {@link MdocFormatter} signs it, for the demo wallet's browser harness (P5-03a;
 * plan section 4.12): {@code docs/design/tools/fixtures/wallet/certify-mdl.issuersigned} and the holder key it was
 * issued to. The wallet harness used to build its own fixtures, and so drifted from what Certify really writes - an
 * IssuerAuth whose payload is a byte string holding {@code #6.24(bstr .cbor MSO)}, and a DSC-only {@code x5chain} as a
 * single bstr (RFC 9360 section 2). This recorder is the answer: the bytes the page is tested on come from the issuer.
 *
 * <p>Like the golden recorders ({@code -Dgoldens.record=true}), the committed copy is written only when asked:</p>
 * <pre>mvn -B -pl certify-format-mdoc test -Dwallet.fixture.record=true</pre>
 * <p>and every run, recording or not, writes a copy to {@code certify-format-mdoc/target/wallet-fixture/} with the real
 * clock, which is what a CI interop job can feed a verifier. The assertions below are the test: they read the produced
 * bytes with a CBOR library the page does not share and check the layout, the x5chain form and one digest.</p>
 */
class WalletFixtureRecorder {

    private static final String FIXTURE = "certify-mdl";
    private static final String MDL_NAMESPACE = MdlFixtures.MDL_NAMESPACE;
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /** The instant the committed fixture is issued at, so a re-record only changes salts and the holder key. */
    private static final Instant FIXED_NOW = Instant.parse("2026-11-14T12:00:00Z");

    @Test
    void theFormatterWritesTheLayoutTheWalletReads() throws Exception {
        boolean record = Boolean.getBoolean("wallet.fixture.record");
        Instant now = record ? FIXED_NOW : Instant.now().truncatedTo(ChronoUnit.SECONDS);

        KeyPair holder = holderKeyPair();
        Map<String, Object> publicJwk = jwk((ECPublicKey) holder.getPublic());
        Map<String, Object> privateJwk = new LinkedHashMap<>(publicJwk);
        privateJwk.put("d", coordinate(((ECPrivateKey) holder.getPrivate()).getS(), 32));
        privateJwk.put("comment", "TEST KEY - NOT SECRET");

        MdocFormatter formatter = new MdocFormatter(new ObjectMapper(), MdlFixtures.properties(Duration.ofDays(90)));
        CredentialConfiguration configuration = MdlFixtures.configuration(formatter);
        IssuanceContext context = MdlFixtures.context(now);
        HolderBinding binding = HolderBinding.did(MAPPER.writeValueAsString(publicJwk), "jwt");

        UnsignedCredential unsigned = formatter.build(ClaimSet.of(MdlFixtures.mdl()), configuration, context, binding);
        IssuedCredential issued = formatter.sign(unsigned, MdlFixtures.signing(MdlFixtures.dsc()), context);
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

        write(Paths.get("").toAbsolutePath().resolve("target/wallet-fixture"), issuerSignedBytes, privateJwk);
        if (record) {
            write(repoRoot().resolve("docs/design/tools/fixtures/wallet"), issuerSignedBytes, privateJwk);
        }
    }

    private static void write(Path directory, byte[] issuerSigned, Map<String, Object> privateJwk) {
        try {
            Files.createDirectories(directory);
            Path signed = directory.resolve(FIXTURE + ".issuersigned");
            Files.write(signed, issuerSigned);
            Files.writeString(directory.resolve(FIXTURE + ".holder.jwk"), MAPPER.writeValueAsString(privateJwk) + "\n",
                    StandardCharsets.UTF_8);
            System.out.println("[wallet-fixture] wrote " + signed + " (" + issuerSigned.length + " bytes)");
        } catch (IOException e) {
            throw new UncheckedIOException("the wallet fixture cannot be written", e);
        }
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
