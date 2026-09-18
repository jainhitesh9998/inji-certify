package io.mosip.certify.keyprovider.jca;

import io.mosip.certify.signing.SignatureAlgorithm;
import io.mosip.certify.signing.SigningException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/** Key-pair and self-signed certificate generation for dev mode; never for production keys. */
final class DevKeys {

    record Generated(PrivateKey privateKey, X509Certificate certificate) {}

    private DevKeys() {}

    static Generated generate(SignatureAlgorithm algorithm, String subjectDn) {
        try {
            KeyPair keyPair = keyPair(algorithm);
            Instant now = Instant.now();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Name(subjectDn), BigInteger.valueOf(now.toEpochMilli()),
                    Date.from(now.minus(1, ChronoUnit.MINUTES)), Date.from(now.plus(365, ChronoUnit.DAYS)),
                    new X500Name(subjectDn), keyPair.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            ContentSigner signer = new JcaContentSignerBuilder(certSigningAlgorithm(algorithm))
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
            return new Generated(keyPair.getPrivate(), certificate);
        } catch (GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException
                 | org.bouncycastle.cert.CertIOException e) {
            throw new SigningException("Cannot generate dev key for " + algorithm.joseName(), e);
        }
    }

    static KeyPair keyPair(SignatureAlgorithm algorithm) throws GeneralSecurityException {
        return switch (algorithm) {
            case RS256, PS256 -> {
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(2048, new SecureRandom());
                yield g.generateKeyPair();
            }
            case ES256, ES384, ES512 -> {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec(switch (algorithm) {
                    case ES384 -> "secp384r1";
                    case ES512 -> "secp521r1";
                    default -> "secp256r1";
                }), new SecureRandom());
                yield g.generateKeyPair();
            }
            case ES256K -> {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                g.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
                yield g.generateKeyPair();
            }
            case EdDSA -> KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        };
    }

    static String certSigningAlgorithm(SignatureAlgorithm algorithm) {
        return switch (algorithm) {
            case RS256, PS256 -> "SHA256withRSA";
            case ES256, ES256K -> "SHA256withECDSA";
            case ES384 -> "SHA384withECDSA";
            case ES512 -> "SHA512withECDSA";
            case EdDSA -> "Ed25519";
        };
    }

    static SignatureAlgorithm algorithmFor(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            return SignatureAlgorithm.RS256;
        }
        if (publicKey instanceof ECPublicKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            return switch (bits) {
                case 384 -> SignatureAlgorithm.ES384;
                case 521 -> SignatureAlgorithm.ES512;
                default -> SignatureAlgorithm.ES256;
            };
        }
        if ("Ed25519".equalsIgnoreCase(publicKey.getAlgorithm()) || "EdDSA".equalsIgnoreCase(publicKey.getAlgorithm())) {
            return SignatureAlgorithm.EdDSA;
        }
        throw new SigningException("Unsupported key type " + publicKey.getAlgorithm());
    }
}
