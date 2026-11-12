package io.mosip.certify.pki;

import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Encrypted private keys: the offline IACA flow (D3) copies a password-protected key file around, so both PKCS#8
 * {@code ENCRYPTED PRIVATE KEY} (what the library writes) and the legacy OpenSSL {@code EC PRIVATE KEY} with DEK-Info
 * headers (what an operator may already have) must be readable, and reading one without a password must fail loudly.
 */
class PemTest {

    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

    @Test
    void anEncryptedPkcs8KeyRoundTrips() throws Exception {
        KeyPair keyPair = BadCerts.ec(256);
        String pem = Pem.writeEncryptedPrivateKey(keyPair.getPrivate(), PASSWORD);

        assertTrue(pem.contains("BEGIN ENCRYPTED PRIVATE KEY"), pem);
        assertFalse(pem.contains("-----BEGIN PRIVATE KEY-----"), "the plaintext PKCS#8 header must not appear");
        assertTrue(Pem.isEncryptedPrivateKey(pem), "the parser recognises an encrypted key");

        PrivateKey read = Pem.readPrivateKey(pem, PASSWORD);
        assertSigns(read, keyPair);

        PkiException withoutPassword = assertThrows(PkiException.class, () -> Pem.readPrivateKey(pem));
        assertTrue(withoutPassword.getMessage().startsWith("PEM_KEY_ENCRYPTED"), withoutPassword.getMessage());

        PkiException wrongPassword = assertThrows(PkiException.class,
                () -> Pem.readPrivateKey(pem, "wrong password".toCharArray()));
        assertTrue(wrongPassword.getMessage().startsWith("PEM_KEY_INVALID"), wrongPassword.getMessage());
    }

    @Test
    void anEncryptedPkcs8KeyIsReadableByAnIndependentImplementation() throws Exception {
        KeyPair keyPair = BadCerts.ec(256);
        String pem = Pem.writeEncryptedPrivateKey(keyPair.getPrivate(), PASSWORD);

        // the same file through BouncyCastle's own PKCS#8 reader, with no help from the library
        org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo encrypted =
                (org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) new org.bouncycastle.openssl.PEMParser(
                        new java.io.StringReader(pem)).readObject();
        var decryptor = new org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder()
                .setProvider(BadCerts.BC).build(PASSWORD);
        var info = encrypted.decryptPrivateKeyInfo(decryptor);
        PrivateKey independent = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider(BadCerts.BC)
                .getPrivateKey(info);
        assertSigns(independent, keyPair);
    }

    @Test
    void aLegacyOpenSslEncryptedEcKeyIsReadable() throws Exception {
        KeyPair keyPair = BadCerts.bcEc(256);
        String pem = legacyEncrypted(keyPair);

        assertTrue(pem.contains("Proc-Type: 4,ENCRYPTED"), pem);
        assertTrue(Pem.isEncryptedPrivateKey(pem));
        assertSigns(Pem.readPrivateKey(pem, PASSWORD), keyPair);

        PkiException withoutPassword = assertThrows(PkiException.class, () -> Pem.readPrivateKey(pem));
        assertTrue(withoutPassword.getMessage().startsWith("PEM_KEY_ENCRYPTED"), withoutPassword.getMessage());
    }

    @Test
    void aPlaintextKeyStillIgnoresAPassword() throws Exception {
        KeyPair keyPair = BadCerts.ec(256);
        String pem = Pem.writePrivateKey(keyPair.getPrivate());
        assertFalse(Pem.isEncryptedPrivateKey(pem));
        assertSigns(Pem.readPrivateKey(pem, PASSWORD), keyPair);
        assertSigns(Pem.readPrivateKey(pem), keyPair);
    }

    @Test
    void anEncryptedKeyIsNotMistakenForACertificate() {
        String pem = Pem.writeEncryptedPrivateKey(BadCerts.ec(256).getPrivate(), PASSWORD);
        PkiException exception = assertThrows(PkiException.class, () -> Pem.readCertificates(pem));
        assertTrue(exception.getMessage().startsWith("PEM_NOT_A_CERTIFICATE"), exception.getMessage());
    }

    private static String legacyEncrypted(KeyPair keyPair) throws Exception {
        var encryptor = new JcePEMEncryptorBuilder("AES-256-CBC").setProvider(BadCerts.BC).build(PASSWORD);
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(new JcaMiscPEMGenerator(keyPair, encryptor));
        }
        return out.toString();
    }

    private static void assertSigns(PrivateKey privateKey, KeyPair keyPair) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA", BadCerts.BC);
        signer.initSign(privateKey);
        signer.update("encrypted pem".getBytes());
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withECDSA", BadCerts.BC);
        verifier.initVerify(keyPair.getPublic());
        verifier.update("encrypted pem".getBytes());
        assertTrue(verifier.verify(signature), "the decrypted key signs for the same key pair");
    }
}
