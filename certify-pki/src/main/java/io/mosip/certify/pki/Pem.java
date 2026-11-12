package io.mosip.certify.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * PEM reading and writing for certificates, certificate chains, private and public keys, CSRs and CRLs.
 *
 * <p>Private keys may be written and read unencrypted (the PKCS#8 {@code PRIVATE KEY} block every JCA provider reads) or
 * encrypted: PKCS#8 with AES-256-CBC under PBKDF2/HMAC-SHA256 ({@code ENCRYPTED PRIVATE KEY}), and the legacy OpenSSL
 * {@code EC PRIVATE KEY} with DEK-Info headers ({@code PEMEncryptedKeyPair}), because an IACA key created offline (D3)
 * is a password-protected file an operator copies, not a plaintext one.
 *
 * <p>An encrypted PKCS#8 key is read when it uses PBES2 with PBKDF2 (what {@code openssl pkcs8 -topk8} writes, and
 * what {@link #writeEncryptedPrivateKey} writes) or one of the PKCS#12 PBE schemes older OpenSSL releases wrote. Any
 * other scheme, scrypt included, is refused with {@code PEM_KEY_UNSUPPORTED} before a password is tried.
 */
public final class Pem {

    /** PBKDF2 iteration count for a written encrypted key; high enough for an offline IACA key, fast enough to load. */
    public static final int PBKDF2_ITERATIONS = 200_000;


    private Pem() {}

    /** Every certificate block in the PEM text, in order. */
    public static List<X509Certificate> readCertificates(String pem) {
        List<X509Certificate> certificates = new ArrayList<>();
        for (Object object : read(pem)) {
            if (object instanceof X509CertificateHolder holder) {
                certificates.add(Certificates.certificate(holder));
            } else if (object instanceof X509CRLHolder || object instanceof PKCS10CertificationRequest
                    || object instanceof PrivateKeyInfo || object instanceof PEMKeyPair
                    || object instanceof PEMEncryptedKeyPair || object instanceof PKCS8EncryptedPrivateKeyInfo) {
                throw new PkiException("PEM_NOT_A_CERTIFICATE: the PEM text contains a " + object.getClass().getSimpleName());
            }
        }
        if (certificates.isEmpty()) {
            throw new PkiException("PEM_NOT_A_CERTIFICATE: the PEM text contains no certificate");
        }
        return certificates;
    }

    /** The first certificate block in the PEM text. */
    public static X509Certificate readCertificate(String pem) {
        return readCertificates(pem).get(0);
    }

    /** The certificate revocation list in the PEM text. */
    public static X509CRL readCrl(String pem) {
        for (Object object : read(pem)) {
            if (object instanceof X509CRLHolder holder) {
                return Certificates.crl(holder);
            }
        }
        throw new PkiException("PEM_NOT_A_CRL: the PEM text contains no CRL");
    }

    /** The PKCS#10 request in the PEM text, parsed and with its proof of possession verified. */
    public static Csr readCsr(String pem) {
        return Csr.parsePem(pem);
    }

    /** Whether the PEM text holds an encrypted private key rather than a plaintext one. */
    public static boolean isEncryptedPrivateKey(String pem) {
        return read(pem).stream()
                .anyMatch(object -> object instanceof PKCS8EncryptedPrivateKeyInfo || object instanceof PEMEncryptedKeyPair);
    }

    /** A private key from a PKCS#8 ({@code PRIVATE KEY}) or SEC1/RSA ({@code EC PRIVATE KEY}) PEM block. */
    public static PrivateKey readPrivateKey(String pem) {
        return readPrivateKey(pem, null);
    }

    /**
     * A private key, encrypted or not. An encrypted key needs the password it was written with; a plaintext key ignores
     * it. An encrypted key read without a password is refused rather than skipped.
     */
    public static PrivateKey readPrivateKey(String pem, char[] password) {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(Certificates.provider());
        for (Object object : read(pem)) {
            try {
                if (object instanceof PrivateKeyInfo info) {
                    return normalize(converter.getPrivateKey(info));
                }
                if (object instanceof PEMKeyPair pair) {
                    return normalize(converter.getPrivateKey(pair.getPrivateKeyInfo()));
                }
                if (object instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
                    checkPbeScheme(encrypted.getEncryptionAlgorithm());
                    PrivateKeyInfo info = encrypted.decryptPrivateKeyInfo(decryptor(password));
                    return normalize(converter.getPrivateKey(info));
                }
                if (object instanceof PEMEncryptedKeyPair encrypted) {
                    PEMKeyPair pair = encrypted.decryptKeyPair(new JcePEMDecryptorProviderBuilder()
                            .setProvider(Certificates.provider()).build(password(password)));
                    // a traditional EC key block need not carry the public key, so only the private key is read
                    return normalize(converter.getPrivateKey(pair.getPrivateKeyInfo()));
                }
            } catch (IOException | OperatorCreationException | PKCSException e) {
                throw new PkiException("PEM_KEY_INVALID: cannot read the private key: " + e.getMessage(), e);
            }
        }
        throw new PkiException("PEM_NOT_A_KEY: the PEM text contains no private key");
    }

    /**
     * Refuses a PKCS#8 encryption scheme the reader does not support with a message that names it, rather than the
     * provider's internal error (BouncyCastle fails a scrypt key with a {@code ClassCastException}).
     */
    private static void checkPbeScheme(AlgorithmIdentifier scheme) {
        ASN1ObjectIdentifier oid = scheme.getAlgorithm();
        if (PKCSObjectIdentifiers.id_PBES2.equals(oid)) {
            ASN1ObjectIdentifier kdf;
            try {
                kdf = PBES2Parameters.getInstance(scheme.getParameters()).getKeyDerivationFunc().getAlgorithm();
            } catch (RuntimeException e) {
                throw new PkiException("PEM_KEY_UNSUPPORTED: unsupported PBE scheme: PBES2 parameters cannot be read", e);
            }
            if (!PKCSObjectIdentifiers.id_PBKDF2.equals(kdf)) {
                String name = MiscObjectIdentifiers.id_scrypt.equals(kdf) ? "scrypt" : kdf.getId();
                throw new PkiException("PEM_KEY_UNSUPPORTED: unsupported PBE scheme: PBES2 with " + name
                        + " key derivation; only PBKDF2 is read. Re-encrypt the key with"
                        + " openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256");
            }
            return;
        }
        if (!oid.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
            throw new PkiException("PEM_KEY_UNSUPPORTED: unsupported PBE scheme " + oid.getId()
                    + "; re-encrypt the key with openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256");
        }
    }

    private static char[] password(char[] password) {
        if (password == null || password.length == 0) {
            throw new PkiException("PEM_KEY_ENCRYPTED: the private key is encrypted and needs a password");
        }
        return password;
    }

    private static InputDecryptorProvider decryptor(char[] password) throws OperatorCreationException {
        return new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(Certificates.provider())
                .build(password(password));
    }

    /** A public key from a {@code PUBLIC KEY} (SubjectPublicKeyInfo) PEM block. */
    public static PublicKey readPublicKey(String pem) {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(Certificates.provider());
        for (Object object : read(pem)) {
            if (object instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo info) {
                try {
                    return normalize(converter.getPublicKey(info));
                } catch (PEMException e) {
                    throw new PkiException("PEM_KEY_INVALID: cannot read the public key", e);
                }
            }
        }
        throw new PkiException("PEM_NOT_A_KEY: the PEM text contains no public key");
    }

    public static String writeCertificate(X509Certificate certificate) {
        return write(certificate);
    }

    /** A PEM certificate chain, leaf first. */
    public static String writeCertificates(List<X509Certificate> certificates) {
        StringBuilder out = new StringBuilder();
        for (X509Certificate certificate : certificates) {
            out.append(write(certificate));
        }
        return out.toString();
    }

    public static String writeCrl(X509CRL crl) {
        return write(crl);
    }

    /** A PKCS#8 {@code PRIVATE KEY} block, the form every JCA provider reads back. */
    public static String writePrivateKey(PrivateKey privateKey) {
        try {
            return write(new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(privateKey, null));
        } catch (org.bouncycastle.util.io.pem.PemGenerationException e) {
            throw new PkiException("PEM_KEY_INVALID: cannot write the private key", e);
        }
    }

    /**
     * An {@code ENCRYPTED PRIVATE KEY} block: PKCS#8 with AES-256-CBC under PBKDF2 with HMAC-SHA256. Read it back with
     * {@link #readPrivateKey(String, char[])}.
     */
    public static String writeEncryptedPrivateKey(PrivateKey privateKey, char[] password) {
        try {
            OutputEncryptor encryptor = new JceOpenSSLPKCS8EncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                    .setProvider(Certificates.provider())
                    .setIterationCount(PBKDF2_ITERATIONS)
                    .setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
                    .setPassword(password(password))
                    .build();
            return write(new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(privateKey, encryptor));
        } catch (OperatorCreationException | org.bouncycastle.util.io.pem.PemGenerationException e) {
            throw new PkiException("PEM_KEY_INVALID: cannot write the encrypted private key", e);
        }
    }

    /** A {@code PUBLIC KEY} block. */
    public static String writePublicKey(PublicKey publicKey) {
        return write(publicKey);
    }

    static String writeCsr(PKCS10CertificationRequest request) {
        return write(request);
    }

    /** BouncyCastle names an EC key {@code ECDSA}; a JDK signer looks for {@code EC}, so re-read it through the JDK. */
    private static PrivateKey normalize(PrivateKey key) {
        if (!"ECDSA".equals(key.getAlgorithm())) {
            return key;
        }
        try {
            return java.security.KeyFactory.getInstance("EC")
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(key.getEncoded()));
        } catch (java.security.GeneralSecurityException e) {
            throw new PkiException("PEM_KEY_INVALID: cannot convert the EC private key: " + e.getMessage(), e);
        }
    }

    private static PublicKey normalize(PublicKey key) {
        if (!"ECDSA".equals(key.getAlgorithm())) {
            return key;
        }
        try {
            return java.security.KeyFactory.getInstance("EC")
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(key.getEncoded()));
        } catch (java.security.GeneralSecurityException e) {
            throw new PkiException("PEM_KEY_INVALID: cannot convert the EC public key: " + e.getMessage(), e);
        }
    }

    private static String write(Object object) {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(object);
        } catch (IOException e) {
            throw new PkiException("Cannot write " + object.getClass().getSimpleName() + " as PEM", e);
        }
        return out.toString();
    }

    private static List<Object> read(String pem) {
        if (pem == null) {
            throw new PkiException("PEM_EMPTY: no PEM text");
        }
        List<Object> objects = new ArrayList<>();
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object object;
            while ((object = parser.readObject()) != null) {
                objects.add(object);
            }
        } catch (IOException e) {
            throw new PkiException("PEM_INVALID: cannot parse the PEM text", e);
        }
        return objects;
    }
}
