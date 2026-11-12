package io.mosip.certify.cli;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Files and keys the {@code pki} and {@code keys} commands share: PKCS#12 keystores read whole and written whole
 * (atomically, under PBKDF2 with 200,000 iterations), EC key generation and the key allowlist of ISO/IEC 18013-5 Annex B
 * (P-256, P-384, P-521), PKCS#10 requests, certificate chain checks, and the password rules.
 *
 * <p>Passwords. The IACA keystore's password comes only from {@code -p}/{@code --iaca-password} or
 * {@code CERTIFY_IACA_PASSWORD}; an issuer or {@code keys} keystore's only from its option or
 * {@code CERTIFY_KEYSTORE_PASSWORD}; a PEM key's only from {@code --key-password} or {@code CERTIFY_KEY_PASSWORD}. One
 * never falls back to another, so an IACA can never be opened with the deployment's keystore password. When neither the
 * option nor the variable is set and a console is attached, the password is prompted without echo. Every password is
 * returned as a fresh {@code char[]} that the caller clears ({@link #clear}); none is ever printed.
 */
final class PkiFiles {

    /** The offline IACA keystore (or encrypted PEM) every {@code pki} command signs with. */
    static final String IACA_PASSWORD_ENV = "CERTIFY_IACA_PASSWORD";

    /** The issuer keystore a Document Signer key is generated into, and the keystore a {@code keys} command reads. */
    static final String KEYSTORE_PASSWORD_ENV = "CERTIFY_KEYSTORE_PASSWORD";

    /** {@code --key-password}: the PEM private key {@code keys import} reads. */
    static final String KEY_PASSWORD_ENV = "CERTIFY_KEY_PASSWORD";

    /** PBKDF2 iterations for the key bags, the certificate bag and the MAC of every PKCS#12 file the CLI writes. */
    static final int PKCS12_ITERATIONS = 200_000;

    /** PBES2: PBKDF2 with HMAC-SHA256 and AES-256-CBC, for both the key bags and the certificate bag. */
    static final String PKCS12_PBE = "PBEWithHmacSHA256AndAES_256";

    /** The PKCS#12 MAC: HMAC-SHA256 with the PKCS#12 key derivation. */
    static final String PKCS12_MAC = "HmacPBESHA256";

    /** The curves Annex B and {@code certify-pki} allow: P-256, P-384, P-521, by name. */
    private static final Map<ASN1ObjectIdentifier, String> CURVES = Map.of(
            X9ObjectIdentifiers.prime256v1, "P-256",
            SECObjectIdentifiers.secp384r1, "P-384",
            SECObjectIdentifiers.secp521r1, "P-521");

    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    private PkiFiles() {}

    // ------------------------------------------------------------------ passwords

    /**
     * The option value, else the environment variable, else a no-echo console prompt, else a {@link UsageException}
     * naming the option and the variable. Always a fresh array: the caller clears it with {@link #clear}.
     */
    static char[] password(char[] option, String env, String what, String flag) {
        if (option != null && option.length > 0) {
            return option.clone();
        }
        String value = System.getenv(env);
        if (value != null && !value.isEmpty()) {
            return value.toCharArray();
        }
        Console console = System.console();
        if (console != null) {
            char[] typed = console.readPassword("%s: ", what);
            if (typed != null && typed.length > 0) {
                return typed;
            }
        }
        throw new UsageException("no " + what + ": set " + env + ", or pass " + flag
                + " without a value to be prompted (a password on the command line is visible to other users)");
    }

    /** Overwrites every array with zeros; {@code null} is ignored. */
    static void clear(char[]... secrets) {
        for (char[] secret : secrets) {
            if (secret != null) {
                Arrays.fill(secret, '\0');
            }
        }
    }

    // ------------------------------------------------------------------ PKCS#12

    /** A PKCS#12 keystore read from disk; a wrong password or a damaged (or empty) file is a refusal. */
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
                    + " (wrong password, or not a PKCS#12 file): " + e.getMessage(), e);
        }
    }

    /** The keystore at {@code path}, or an empty one when the file does not exist yet. */
    static KeyStore readOrCreate(Path path, char[] password) {
        return Files.exists(path) ? read(path, password) : empty();
    }

    static KeyStore empty() {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            return store;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot create a PKCS#12 keystore", e);
        }
    }

    /**
     * Writes the keystore atomically ({@link SecureFiles#write}, {@code rw-------}): replacing the file when
     * {@code replace}, else creating it and refusing an existing one.
     */
    static void write(KeyStore store, Path path, char[] password, boolean replace) throws IOException {
        SecureFiles.write(path, pkcs12(store, password), SecureFiles.Visibility.SECRET, replace);
    }

    /**
     * The PKCS#12 encoding of a keystore, every entry re-encrypted: key bags and the certificate bag under PBES2
     * (PBKDF2-HMAC-SHA256, AES-256-CBC) with {@value #PKCS12_ITERATIONS} iterations, the MAC HMAC-SHA256 with as many.
     * The entries are copied into a fresh keystore so that the iteration counts of a file read from disk (the JDK keeps
     * them) do not carry over.
     */
    static byte[] pkcs12(KeyStore source, char[] password) {
        try {
            // the JDK reads these when a key is added to a fresh keystore (key bags) and when it is stored
            // (certificate bag, MAC); KeyStore.PasswordProtection with PBEParameterSpec would do for the key bags, but
            // KeyStore.PrivateKeyEntry refuses an Ed25519 key whose certificate names its key "EdDSA"
            System.setProperty("keystore.pkcs12.keyProtectionAlgorithm", PKCS12_PBE);
            System.setProperty("keystore.pkcs12.keyPbeIterationCount", Integer.toString(PKCS12_ITERATIONS));
            System.setProperty("keystore.pkcs12.certProtectionAlgorithm", PKCS12_PBE);
            System.setProperty("keystore.pkcs12.certPbeIterationCount", Integer.toString(PKCS12_ITERATIONS));
            System.setProperty("keystore.pkcs12.macAlgorithm", PKCS12_MAC);
            System.setProperty("keystore.pkcs12.macIterationCount", Integer.toString(PKCS12_ITERATIONS));
            KeyStore target = empty();
            for (String alias : Collections.list(source.aliases())) {
                if (source.isKeyEntry(alias)) {
                    Key key = source.getKey(alias, password);
                    if (!(key instanceof PrivateKey privateKey)) {
                        throw new IllegalArgumentException("the keystore entry '" + alias + "' is not a private key");
                    }
                    target.setKeyEntry(alias, privateKey, password, source.getCertificateChain(alias));
                } else if (source.isCertificateEntry(alias)) {
                    target.setCertificateEntry(alias, source.getCertificate(alias));
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            target.store(out, password);
            return out.toByteArray();
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot encode the PKCS#12 keystore: " + e.getMessage(), e);
        }
    }

    /** Whether the keystore holds an entry under the alias. */
    static boolean contains(KeyStore store, String alias) {
        try {
            return store.containsAlias(alias);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("cannot read the keystore aliases: " + e.getMessage(), e);
        }
    }

    /** Every alias of the keystore. */
    static List<String> aliases(KeyStore store) {
        try {
            return Collections.list(store.aliases());
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("cannot read the keystore aliases: " + e.getMessage(), e);
        }
    }

    /** Adds a key with its chain, leaf first; an existing alias is refused so an entry is never silently replaced. */
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
        return switch (algorithm.toUpperCase(Locale.ROOT)) {
            case "ES256" -> "secp256r1";
            case "ES384" -> "secp384r1";
            case "ES512" -> "secp521r1";
            default -> throw new UsageException("--alg must be ES256, ES384 or ES512, not " + algorithm);
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

    /**
     * Refuses anything but an EC key on a named P-256, P-384 or P-521 curve, naming what it got: "only EC
     * P-256/384/521 is supported, not RSA".
     */
    static void requireSupportedKey(Key key, String what) {
        String algorithm = key.getAlgorithm();
        if (!"EC".equalsIgnoreCase(algorithm)) {
            throw new IllegalArgumentException(what + ": only EC P-256/384/521 is supported, not " + algorithm);
        }
        AlgorithmIdentifier identifier;
        try {
            identifier = key instanceof PublicKey
                    ? SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm()
                    : PrivateKeyInfo.getInstance(key.getEncoded()).getPrivateKeyAlgorithm();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(what + ": the EC key cannot be read: " + e.getMessage(), e);
        }
        if (!(identifier.getParameters() instanceof ASN1ObjectIdentifier curve) || !CURVES.containsKey(curve)) {
            throw new IllegalArgumentException(what + ": only EC P-256/384/521 is supported, not the curve "
                    + identifier.getParameters());
        }
    }

    /** The JCA signature algorithm of a key: the hash follows the P-256/384/521 curve. */
    static String signatureAlgorithm(PublicKey key) {
        requireSupportedKey(key, "the key");
        int bits = ((java.security.interfaces.ECPublicKey) key).getParams().getCurve().getField().getFieldSize();
        return switch (bits) {
            case 256 -> "SHA256withECDSA";
            case 384 -> "SHA384withECDSA";
            default -> "SHA512withECDSA";
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

    /** Whether two public keys are the same key, compared as encoded subjectPublicKeyInfo. */
    static boolean sameKey(PublicKey a, PublicKey b) {
        return Arrays.equals(a.getEncoded(), b.getEncoded());
    }

    // ------------------------------------------------------------------ chains

    /**
     * Refuses a chain that does not link: every certificate must be issued and signed by the next one, and the last
     * must be self-signed or issued and signed by {@code anchor} (or be the anchor itself). The chain is leaf first.
     */
    static void verifyChain(List<X509Certificate> chain, X509Certificate anchor) {
        for (int i = 0; i + 1 < chain.size(); i++) {
            if (!signedBy(chain.get(i), chain.get(i + 1))) {
                throw new IllegalArgumentException("certificate " + (i + 1) + " of the chain ("
                        + chain.get(i).getSubjectX500Principal().getName() + ") is not signed by certificate " + (i + 2)
                        + " (" + chain.get(i + 1).getSubjectX500Principal().getName() + "); the chain must be leaf"
                        + " first, each certificate followed by its issuer");
            }
        }
        X509Certificate last = chain.get(chain.size() - 1);
        if (anchor != null) {
            if (sameCertificate(last, anchor) || signedBy(last, anchor)) {
                return;
            }
            throw new IllegalArgumentException("the chain ends at " + last.getSubjectX500Principal().getName()
                    + ", which is not signed by the --anchor " + anchor.getSubjectX500Principal().getName());
        }
        if (!signedBy(last, last)) {
            throw new IllegalArgumentException("the chain ends at " + last.getSubjectX500Principal().getName()
                    + ", which is not self-signed; append its issuer to the chain or pass --anchor <issuer.pem>");
        }
    }

    /** Whether {@code certificate} names {@code issuer} as its issuer and its signature verifies under that key. */
    static boolean signedBy(X509Certificate certificate, X509Certificate issuer) {
        if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            return false;
        }
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    static boolean sameCertificate(X509Certificate a, X509Certificate b) {
        try {
            return Arrays.equals(a.getEncoded(), b.getEncoded());
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ PKCS#10

    /**
     * A subject with one CN attribute holding {@code commonName} verbatim: built attribute by attribute, never parsed
     * from a string, so {@code --cn "a,O=Other"} is a CN with a comma in it, not a second attribute.
     */
    static X500Name commonNameSubject(String commonName) {
        if (commonName == null || commonName.isBlank()) {
            throw new UsageException("--cn must not be empty");
        }
        return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build();
    }

    /** A certificate's subject as its DER, so the RDN order and the string types are preserved. */
    static X500Name subject(X509Certificate certificate) {
        return X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
    }

    /** A PEM {@code CERTIFICATE REQUEST} for an existing key; the signature algorithm follows the key's curve. */
    static String csrPem(PrivateKey privateKey, PublicKey publicKey, X500Name subject) {
        try {
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(publicKey)).setProvider(BC)
                    .build(privateKey);
            PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(subject, publicKey)
                    .build(signer);
            StringWriter out = new StringWriter();
            try (PemWriter writer = new PemWriter(out)) {
                writer.writeObject(new PemObject("CERTIFICATE REQUEST", request.getEncoded()));
            }
            return out.toString();
        } catch (OperatorCreationException | IOException e) {
            throw new IllegalStateException("cannot create the PKCS#10 request: " + e.getMessage(), e);
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
