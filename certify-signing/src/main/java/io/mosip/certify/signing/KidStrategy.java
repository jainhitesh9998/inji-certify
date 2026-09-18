package io.mosip.certify.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Decides the {@code kid} placed in a JWS or COSE header for a key. */
@FunctionalInterface
public interface KidStrategy {

    String kidFor(SigningKey key);

    /** The provider's own identifier (keymanager's certificate thumbprint with its configured prefix). */
    KidStrategy PROVIDER = key -> key.descriptor().kid();

    /** RFC 7638 JWK thumbprint, what HAIP and {@code did:jwk} verifiers expect. */
    KidStrategy JWK_THUMBPRINT = key -> {
        try {
            return key.descriptor().toJwk().computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new SigningException("Cannot compute JWK thumbprint for " + key.ref(), e);
        }
    };

    /** SHA-256 thumbprint of the leaf certificate, base64url (the {@code x5t#S256} value). */
    KidStrategy X5T_S256 = key -> key.chain().leaf().map(cert -> {
        try {
            return Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())).toString();
        } catch (NoSuchAlgorithmException | java.security.cert.CertificateEncodingException e) {
            throw new SigningException("Cannot compute x5t#S256 for " + key.ref(), e);
        }
    }).orElseThrow(() -> new SigningException("Key " + key.ref() + " has no certificate for x5t#S256"));

    /** No {@code kid} header at all (the {@code x5c} chain identifies the key). */
    KidStrategy NONE = key -> null;

    static KidStrategy fixed(String kid) {
        return key -> kid;
    }
}
