package io.mosip.certify.signing;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Objects;

/**
 * What a key provider tells the world about one key: everything JWKS, DID documents, {@code x5c} and
 * {@code x5chain} need, and nothing a provider cannot supply.
 *
 * @param kid       the provider's key identifier (keymanager's certificate thumbprint today)
 * @param algorithm the algorithm this key signs with
 * @param publicKey the JCA public key
 * @param chain     certificate chain, leaf first, possibly empty
 * @param notBefore validity start, or {@code null}
 * @param notAfter  validity end, or {@code null}
 * @param purpose   free-form purpose tag such as {@code vc-signing}, {@code mdoc-dsc}, {@code access-token}
 */
public record PublicKeyDescriptor(String kid, SignatureAlgorithm algorithm, PublicKey publicKey, CertificateChain chain,
                                  Instant notBefore, Instant notAfter, String purpose) {

    public PublicKeyDescriptor {
        Objects.requireNonNull(kid, "kid");
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(publicKey, "publicKey");
        chain = chain == null ? CertificateChain.EMPTY : chain;
    }

    public boolean isValidAt(Instant instant) {
        return (notBefore == null || !instant.isBefore(notBefore)) && (notAfter == null || instant.isBefore(notAfter));
    }

    /** The public JWK for this key with {@code kid} and {@code alg} set, and {@code x5c} when a chain exists. */
    public JWK toJwk() {
        try {
            JWK jwk;
            if (publicKey instanceof RSAPublicKey rsa) {
                jwk = new RSAKey.Builder(rsa).keyID(kid).algorithm(new com.nimbusds.jose.JWSAlgorithm(algorithm.joseName()))
                        .x509CertChain(x5cBase64()).build();
            } else if (publicKey instanceof ECPublicKey ec) {
                Curve curve = Curve.forECParameterSpec(ec.getParams());
                if (curve == null) {
                    curve = Curve.parse(algorithm.curve());
                }
                jwk = new ECKey.Builder(curve, ec).keyID(kid).algorithm(new com.nimbusds.jose.JWSAlgorithm(algorithm.joseName()))
                        .x509CertChain(x5cBase64()).build();
            } else if ("Ed25519".equalsIgnoreCase(publicKey.getAlgorithm()) || "EdDSA".equalsIgnoreCase(publicKey.getAlgorithm())) {
                byte[] spki = publicKey.getEncoded();
                // Ed25519 SubjectPublicKeyInfo is 44 bytes: 12-byte header + 32-byte raw key (RFC 8410)
                if (spki.length != 44) {
                    throw new SigningException("Unexpected Ed25519 SPKI length " + spki.length);
                }
                byte[] raw = new byte[32];
                System.arraycopy(spki, 12, raw, 0, 32);
                jwk = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(raw)).keyID(kid)
                        .algorithm(com.nimbusds.jose.JWSAlgorithm.EdDSA).x509CertChain(x5cBase64()).build();
            } else {
                throw new SigningException("Unsupported public key type " + publicKey.getAlgorithm());
            }
            return jwk;
        } catch (RuntimeException e) {
            throw new SigningException("Cannot build JWK for key " + kid, e);
        }
    }

    private java.util.List<com.nimbusds.jose.util.Base64> x5cBase64() {
        if (chain.isEmpty()) {
            return null;
        }
        return chain.toX5c().stream().map(com.nimbusds.jose.util.Base64::new).toList();
    }
}
