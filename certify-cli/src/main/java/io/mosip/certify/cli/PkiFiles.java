package io.mosip.certify.cli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Files and keys the {@code pki} commands share: a PKCS#12 keystore read and written entry by entry, EC key generation
 * for the three curves ISO/IEC 18013-5 Annex B allows, a PKCS#10 writer for an existing key, and the password rules.
 *
 * <p>Every password comes from the option ({@code -p}, {@code -P}, {@code --key-password}), or, when the option is
 * absent, from an environment variable: {@code CERTIFY_KEYSTORE_PASSWORD}, {@code CERTIFY_ISSUER_KEYSTORE_PASSWORD} or
 * {@code CERTIFY_KEY_PASSWORD}. A password is never printed, logged or echoed back; a missing one is a refusal that
 * names both ways to supply it.
 */
final class PkiFiles {

    /** {@code -p}: the keystore an IACA key and certificate live in, or the keystore a {@code keys} command reads. */
    static final String KEYSTORE_PASSWORD_ENV = "CERTIFY_KEYSTORE_PASSWORD";

    /** {@code -P}: the issuer keystore a Document Signer key is generated into ({@code pki dsc issue --generate}). */
    static final String ISSUER_PASSWORD_ENV = "CERTIFY_ISSUER_KEYSTORE_PASSWORD";

    /** {@code --key-password}: the PEM private key {@code keys import} reads. */
    static final String KEY_PASSWORD_ENV = "CERTIFY_KEY_PASSWORD";

    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    private PkiFiles() {}

    // ------------------------------------------------------------------ passwords

    /** The option value, else the environment variable, else a refusal that names both; never the value itself. */
    static char[] password(char[] option, String env, String flags) {
        if (option != null && option.length > 0) {
            return option;
        }
        String value = System.getenv(env);
        if (value != null && !value.isEmpty()) {
            return value.toCharArray();
        }
        throw new IllegalArgumentException("no password: pass " + flags + " or set " + env);
    }

    // ------------------------------------------------------------------ PKCS#12

    /** A PKCS#12 keystore read from disk; a wrong password or a damaged file is a refusal, not an empty store. */
    static KeyStore read(Path path, char[] password) {
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("no such keystore: " + path);
        }
        try (InputStream in = Files.newInputStream(path)) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(in, password);
            return store;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException("cannot read the PKCS#12 keystore " + path
                    + " (wrong password?): " + e.getMessage(), e);
        }
    }

    /** The keystore at {@code path}, or an empty one when the file does not exist yet. */
    static KeyStore readOrCreate(Path path, char[] password) {
        if (Files.exists(path)) {
            return read(path, password);
        }
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            return store;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot create a PKCS#12 keystore", e);
        }
    }

    static void write(KeyStore store, Path path, char[] password) {
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            try (OutputStream out = Files.newOutputStream(path)) {
                store.store(out, password);
            }
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot write the PKCS#12 keystore " + path + ": " + e.getMessage(), e);
        }
    }

    /** Whether the keystore holds a key entry under the alias. */
    static boolean contains(KeyStore store, String alias) {
        try {
            return store.containsAlias(alias);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("cannot read the keystore aliases: " + e.getMessage(), e);
        }
    }

    /** Adds a key with its chain, leaf first; an existing alias is refused so a keystore is never silently replaced. */
    static void add(KeyStore store, String alias, PrivateKey key, char[] password, List<X509Certificate> chain) {
        if (contains(store, alias)) {
            throw new IllegalArgumentException("alias already exists: " + alias);
        }
        try {
            store.setKeyEntry(alias, key, password, chain.toArray(Certificate[]::new));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot add " + alias + " to the keystore: " + e.getMessage(), e);
        }
    }

    static PrivateKey privateKey(KeyStore store, String alias, char[] password) {
        try {
            if (!store.isKeyEntry(alias)) {
                throw new IllegalArgumentException("no key entry '" + alias + "' in the keystore");
            }
            return (PrivateKey) store.getKey(alias, password);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("cannot read the key '" + alias + "': " + e.getMessage(), e);
        }
    }

    /** The certificate chain of a key entry, leaf first. */
    static List<X509Certificate> chain(KeyStore store, String alias) {
        try {
            Certificate[] chain = store.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                throw new IllegalArgumentException("the key entry '" + alias + "' has no certificate");
            }
            List<X509Certificate> certificates = new ArrayList<>();
            for (Certificate certificate : chain) {
                certificates.add((X509Certificate) certificate);
            }
            return certificates;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("cannot read the chain of '" + alias + "': " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------ keys

    /** The JCA curve name of an Annex B algorithm: ES256 P-256, ES384 P-384, ES512 P-521. */
    static String curve(String algorithm) {
        return switch (algorithm.toUpperCase(java.util.Locale.ROOT)) {
            case "ES256" -> "secp256r1";
            case "ES384" -> "secp384r1";
            case "ES512" -> "secp521r1";
            default -> throw new IllegalArgumentException("--alg must be ES256, ES384 or ES512, not " + algorithm);
        };
    }

    /** A fresh EC key pair on the curve of {@code algorithm}. */
    static KeyPair keyPair(String algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve(algorithm)));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot generate an " + algorithm + " key: " + e.getMessage(), e);
        }
    }

    /** The JCA signature algorithm of a key: the hash follows the P-256/384/521 curve. */
    static String signatureAlgorithm(PublicKey key) {
        if (!(key instanceof ECPublicKey ec)) {
            throw new IllegalArgumentException("an ECDSA key is required, not " + key.getAlgorithm());
        }
        int bits = ec.getParams().getCurve().getField().getFieldSize();
        return switch (bits) {
            case 256 -> "SHA256withECDSA";
            case 384 -> "SHA384withECDSA";
            case 521 -> "SHA512withECDSA";
            default -> throw new IllegalArgumentException("the key is on a " + bits + " bit curve; only P-256, P-384"
                    + " and P-521 are allowed");
        };
    }

    /** Whether the private key belongs to the public key: a probe signature over fixed bytes verifies or it does not. */
    static boolean matches(PrivateKey privateKey, PublicKey publicKey) {
        try {
            String algorithm = signatureAlgorithm(publicKey);
            byte[] probe = "certify-cli key pair probe".getBytes(StandardCharsets.US_ASCII);
            Signature signer = Signature.getInstance(algorithm, BC);
            signer.initSign(privateKey);
            signer.update(probe);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance(algorithm, BC);
            verifier.initVerify(publicKey);
            verifier.update(probe);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ PKCS#10

    /** A PEM {@code CERTIFICATE REQUEST} for an existing key; the signature algorithm follows the key's curve. */
    static String csrPem(PrivateKey privateKey, PublicKey publicKey, String subjectDn) {
        try {
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(publicKey)).setProvider(BC)
                    .build(privateKey);
            PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name(subjectDn), publicKey).build(signer);
            StringWriter out = new StringWriter();
            try (PemWriter writer = new PemWriter(out)) {
                writer.writeObject(new PemObject("CERTIFICATE REQUEST", request.getEncoded()));
            }
            return out.toString();
        } catch (OperatorCreationException | IOException e) {
            throw new IllegalStateException("cannot create the PKCS#10 request: " + e.getMessage(), e);
        }
    }

    /** The first CN of a subject, or {@code null} when it has none. */
    static String commonName(X500Principal principal) {
        try {
            for (Rdn rdn : new LdapName(principal.getName()).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return String.valueOf(rdn.getValue());
                }
            }
            return null;
        } catch (InvalidNameException e) {
            return null;
        }
    }

    // ------------------------------------------------------------------ output

    /** The SHA-256 fingerprint of a certificate, lowercase hex. */
    static String sha256(X509Certificate certificate) {
        try {
            return sha256(certificate.getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot encode the certificate", e);
        }
    }

    /** The SHA-256 fingerprint of an encoded object as lowercase hex, no separators, so a script can compare it. */
    static String sha256(byte[] encoded) {
        try {
            return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
