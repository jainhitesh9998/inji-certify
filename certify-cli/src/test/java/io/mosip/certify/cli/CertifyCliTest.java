package io.mosip.certify.cli;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Drives the commands in-process; every signature is checked with Nimbus or plain JCA. */
class CertifyCliTest {

    @TempDir Path dir;
    Path keystore;
    ByteArrayOutputStream out;

    @BeforeEach
    void setUp() {
        keystore = dir.resolve("keys.p12");
        out = new ByteArrayOutputStream();
    }

    int run(String... args) {
        PrintStream original = System.out;
        System.setOut(new PrintStream(out, true));
        try {
            return new CommandLine(new CertifyCli()).execute(args);
        } finally {
            System.setOut(original);
        }
    }

    String output() {
        String s = out.toString(StandardCharsets.UTF_8);
        out.reset();
        return s;
    }

    @Test
    void generateListJwksAndJwsRoundTrip() throws Exception {
        assertEquals(0, run("keys", "generate", "-k", keystore.toString(), "-p", "pw", "--alias", "issuer-es256", "--alg", "ES256"));
        assertTrue(output().startsWith("issuer-es256\tES256\tkid=issuer-es256"));
        assertEquals(0, run("keys", "generate", "-k", keystore.toString(), "-p", "pw", "--alias", "issuer-rsa", "--alg", "RS256"));
        output();
        assertEquals(2, run("keys", "generate", "-k", keystore.toString(), "-p", "pw", "--alias", "issuer-rsa", "--alg", "RS256"), "duplicate alias refused");

        assertEquals(0, run("keys", "list", "-k", keystore.toString(), "-p", "pw"));
        String listed = output();
        assertTrue(listed.contains("issuer-es256\tES256\tvc-signing") && listed.contains("issuer-rsa\tRS256"), listed);

        assertEquals(0, run("keys", "jwks", "-k", keystore.toString(), "-p", "pw"));
        JWKSet jwks = JWKSet.parse(output());
        assertEquals(2, jwks.getKeys().size());
        assertNotNull(jwks.getKeyByKeyId("issuer-es256").getX509CertChain(), "x5c published");

        Path claims = dir.resolve("claims.json");
        Files.writeString(claims, "{\"iss\":\"did:web:issuer.example\",\"vct\":\"FarmerCredential\"}");
        assertEquals(0, run("sign", "jws", "-k", keystore.toString(), "-p", "pw", "--key", "issuer-es256", "--typ", "dc+sd-jwt", "--x5c", "--x5t", "--in", claims.toString()));
        JWSObject jws = JWSObject.parse(output().trim());
        assertEquals("dc+sd-jwt", jws.getHeader().getType().getType());
        assertEquals("issuer-es256", jws.getHeader().getKeyID());
        assertNotNull(jws.getHeader().getX509CertChain());
        assertNotNull(jws.getHeader().getX509CertSHA256Thumbprint());
        ECDSAVerifier verifier = new ECDSAVerifier((ECKey) jwks.getKeyByKeyId("issuer-es256"));
        verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        assertTrue(jws.verify(verifier), "JWS verifies with the published JWK");
        assertEquals("FarmerCredential", jws.getPayload().toJSONObject().get("vct"));

        assertEquals(0, run("sign", "jws", "-k", keystore.toString(), "-p", "pw", "--key", "issuer-rsa", "--alg", "PS256", "--typ", "JWT", "--in", claims.toString()));
        JWSObject ps = JWSObject.parse(output().trim());
        assertEquals("PS256", ps.getHeader().getAlgorithm().getName());
        assertTrue(ps.verify(new RSASSAVerifier((RSAKey) jwks.getKeyByKeyId("issuer-rsa"))), "PS256 over the RSA key verifies");
    }

    @Test
    void coseSign1VerifiesWithJcaAgainstTheEmbeddedCertificate() throws Exception {
        assertEquals(0, run("keys", "generate", "-k", keystore.toString(), "-p", "pw", "--alias", "dsc", "--alg", "ES256", "--subject", "CN=mDL DSC"));
        output();
        Path payload = dir.resolve("mso.cbor");
        Files.write(payload, CBORObject.NewMap().Add("docType", "org.iso.18013.5.1.mDL").EncodeToBytes());
        Path signed = dir.resolve("issuer-auth.cbor");

        assertEquals(0, run("sign", "cose", "-k", keystore.toString(), "-p", "pw", "--key", "dsc", "--in", payload.toString(), "--out", signed.toString()));

        CBORObject sign1 = CBORObject.DecodeFromBytes(Files.readAllBytes(signed));
        assertFalse(sign1.isTagged());
        assertEquals(4, sign1.size());
        byte[] protectedBytes = sign1.get(0).GetByteString();
        assertEquals(-7, CBORObject.DecodeFromBytes(protectedBytes).get(CBORObject.FromObject(1)).AsInt32());
        byte[] leafDer = sign1.get(1).get(CBORObject.FromObject(33)).GetByteString();
        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(leafDer));
        assertEquals("CN=mDL DSC", leaf.getSubjectX500Principal().getName());
        byte[] sigStructure = CBORObject.NewArray().Add("Signature1").Add(protectedBytes).Add(new byte[0]).Add(sign1.get(2).GetByteString()).EncodeToBytes();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(leaf.getPublicKey());
        verifier.update(sigStructure);
        assertTrue(verifier.verify(com.nimbusds.jose.crypto.impl.ECDSA.transcodeSignatureToDER(sign1.get(3).GetByteString())), "COSE_Sign1 verifies with JCA");

        assertEquals(0, run("sign", "cose", "-k", keystore.toString(), "-p", "pw", "--key", "dsc", "--tagged", "--kid", "--in", payload.toString(), "--out", signed.toString()));
        CBORObject tagged = CBORObject.DecodeFromBytes(Files.readAllBytes(signed));
        assertTrue(tagged.HasMostOuterTag(18));
        assertTrue(tagged.Untag().get(1).ContainsKey(CBORObject.FromObject(4)), "kid label 4 present");
    }

    @Test
    void unknownKeyFailsWithAnError() {
        assertEquals(0, run("keys", "generate", "-k", keystore.toString(), "-p", "pw", "--alias", "a", "--alg", "EdDSA"));
        output();
        int code = run("sign", "jws", "-k", keystore.toString(), "-p", "pw", "--key", "missing", "--in", keystore.toString());
        assertTrue(code != 0);
    }
}
