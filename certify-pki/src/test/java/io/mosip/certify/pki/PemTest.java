package io.mosip.certify.pki;

import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Encrypted private keys: the offline IACA flow (D3) copies a password-protected key file around. The library writes
 * only PKCS#8 PBES2 AES-256-CBC/PBKDF2-HMAC-SHA256 and reads every scheme BouncyCastle can decrypt (PKCS#5 v1, PKCS#12
 * PBE, PBES2 with any PBKDF2 PRF, the traditional OpenSSL {@code Proc-Type: 4,ENCRYPTED} block), logging a weak one at
 * WARNING; scrypt and unknown schemes are refused by name, and reading an encrypted key without a password fails loudly.
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
    void aLegacyOpenSslEncryptedEcKeyIsReadableAndLoggedAsWeak() throws Exception {
        KeyPair keyPair = BadCerts.bcEc(256);
        String pem = legacyEncrypted(keyPair);

        assertTrue(pem.contains("Proc-Type: 4,ENCRYPTED"), pem);
        assertTrue(Pem.isEncryptedPrivateKey(pem));
        List<String> warnings = warnings(() -> assertSigns(Pem.readPrivateKey(pem, PASSWORD), keyPair));
        assertEquals(1, warnings.size(), warnings::toString);
        assertTrue(warnings.get(0).contains("traditional OpenSSL encryption")
                && warnings.get(0).contains("AES-256-CBC"), warnings.get(0));

        PkiException withoutPassword = assertThrows(PkiException.class, () -> Pem.readPrivateKey(pem));
        assertTrue(withoutPassword.getMessage().startsWith("PEM_KEY_ENCRYPTED"), withoutPassword.getMessage());
    }

    /** What the library writes is the one strong scheme: it is read without a warning. */
    @Test
    void theWrittenSchemeIsReadWithoutAWarning() throws Exception {
        KeyPair keyPair = BadCerts.ec(256);
        String pem = Pem.writeEncryptedPrivateKey(keyPair.getPrivate(), PASSWORD);
        var info = (org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) new org.bouncycastle.openssl.PEMParser(
                new java.io.StringReader(pem)).readObject();
        var parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters.getInstance(info.getEncryptionAlgorithm().getParameters());
        assertEquals(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes256_CBC,
                parameters.getEncryptionScheme().getAlgorithm());
        assertEquals(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_hmacWithSHA256,
                org.bouncycastle.asn1.pkcs.PBKDF2Params.getInstance(parameters.getKeyDerivationFunc().getParameters())
                        .getPrf().getAlgorithm());
        assertEquals(List.of(), warnings(() -> assertSigns(Pem.readPrivateKey(pem, PASSWORD), keyPair)));
    }

    /**
     * Legacy PKCS#8 schemes an operator may already hold are read, each logged at WARNING with its name: PKCS#5 v1
     * (written here by the JDK's own PBEWithMD5AndDES), PKCS#12 PBE with 3DES, and PBES2 with the default HMAC-SHA1 PRF.
     */
    @Test
    void legacyPkcs8SchemesAreReadAndLoggedAsWeak() throws Exception {
        KeyPair keyPair = BadCerts.ec(256);

        String pkcs5 = pkcs5v1(keyPair.getPrivate());
        List<String> pkcs5Warnings = warnings(() -> assertSigns(Pem.readPrivateKey(pkcs5, PASSWORD), keyPair));
        assertEquals(1, pkcs5Warnings.size(), pkcs5Warnings::toString);
        assertTrue(pkcs5Warnings.get(0).contains("PKCS#5 v1 pbeWithMD5AndDES-CBC"), pkcs5Warnings.get(0));

        String pkcs12 = bcEncrypted(keyPair.getPrivate(),
                new org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder(
                        org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC));
        List<String> pkcs12Warnings = warnings(() -> assertSigns(Pem.readPrivateKey(pkcs12, PASSWORD), keyPair));
        assertEquals(1, pkcs12Warnings.size(), pkcs12Warnings::toString);
        assertTrue(pkcs12Warnings.get(0).contains("PKCS#12 PBE 1.2.840.113549.1.12.1.3"), pkcs12Warnings.get(0));

        String sha1 = bcEncrypted(keyPair.getPrivate(), new org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder(
                org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes256_CBC).setIterationCount(2048));
        List<String> sha1Warnings = warnings(() -> assertSigns(Pem.readPrivateKey(sha1, PASSWORD), keyPair));
        assertEquals(1, sha1Warnings.size(), sha1Warnings::toString);
        assertTrue(sha1Warnings.get(0).contains("PBES2 with PBKDF2/HMAC-SHA1"), sha1Warnings.get(0));
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

    /**
     * PBES2 with scrypt (what {@code openssl pkcs8 -topk8 -scrypt} writes) and a scheme BouncyCastle does not know are
     * refused with a message that names the scheme, before any password is tried.
     */
    @Test
    void anUnsupportedPbeSchemeIsRefusedByName() throws Exception {
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        var scrypt = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_PBES2,
                new org.bouncycastle.asn1.pkcs.PBES2Parameters(
                        new org.bouncycastle.asn1.pkcs.KeyDerivationFunc(
                                org.bouncycastle.asn1.misc.MiscObjectIdentifiers.id_scrypt,
                                new org.bouncycastle.asn1.misc.ScryptParams(salt, 16384, 8, 1)),
                        new org.bouncycastle.asn1.pkcs.EncryptionScheme(
                                org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes256_CBC,
                                new org.bouncycastle.asn1.DEROctetString(iv))));
        PkiException exception = assertThrows(PkiException.class, () -> Pem.readPrivateKey(encryptedPem(scrypt), PASSWORD));
        assertTrue(exception.getMessage().startsWith("PEM_KEY_UNSUPPORTED: unsupported PBE scheme"), exception.getMessage());
        assertTrue(exception.getMessage().contains("scrypt"), exception.getMessage());

        var unknown = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.5"),
                new org.bouncycastle.asn1.pkcs.PBEParameter(new byte[8], 2048));
        PkiException other = assertThrows(PkiException.class, () -> Pem.readPrivateKey(encryptedPem(unknown), PASSWORD));
        assertTrue(other.getMessage().startsWith("PEM_KEY_UNSUPPORTED: unsupported PBE scheme 1.2.3.4.5"),
                other.getMessage());
    }

    /** The PKCS#5 v1 PBES1 encoding of a key, made by the JDK's own cipher so no BouncyCastle code wrote it. */
    private static String pkcs5v1(PrivateKey key) throws Exception {
        byte[] salt = {1, 2, 3, 4, 5, 6, 7, 8};
        int iterations = 2048;
        javax.crypto.SecretKey secret = javax.crypto.SecretKeyFactory.getInstance("PBEWithMD5AndDES")
                .generateSecret(new javax.crypto.spec.PBEKeySpec(PASSWORD));
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secret, new javax.crypto.spec.PBEParameterSpec(salt, iterations));
        byte[] encrypted = cipher.doFinal(key.getEncoded());
        return encryptedPem(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC,
                new org.bouncycastle.asn1.pkcs.PBEParameter(salt, iterations)), encrypted);
    }

    private static String bcEncrypted(PrivateKey key, org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder builder)
            throws Exception {
        var encryptor = builder.setProvider(BadCerts.BC).setPassword(PASSWORD).build();
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(key, encryptor));
        }
        return out.toString();
    }

    /** The WARNING records {@link Pem} logs while {@code action} runs (System.Logger routes to java.util.logging here). */
    private static List<String> warnings(ThrowingRunnable action) throws Exception {
        Logger logger = Logger.getLogger(Pem.class.getName());
        List<String> records = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                    records.add(record.getMessage());
                }
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        logger.addHandler(handler);
        try {
            action.run();
        } finally {
            logger.removeHandler(handler);
        }
        return records;
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static String encryptedPem(org.bouncycastle.asn1.x509.AlgorithmIdentifier scheme) throws Exception {
        return encryptedPem(scheme, new byte[48]);
    }

    private static String encryptedPem(org.bouncycastle.asn1.x509.AlgorithmIdentifier scheme, byte[] data) throws Exception {
        byte[] der = new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(scheme, data).getEncoded();
        StringWriter out = new StringWriter();
        try (org.bouncycastle.util.io.pem.PemWriter writer = new org.bouncycastle.util.io.pem.PemWriter(out)) {
            writer.writeObject(new org.bouncycastle.util.io.pem.PemObject("ENCRYPTED PRIVATE KEY", der));
        }
        return out.toString();
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
