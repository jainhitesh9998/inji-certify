package io.mosip.certify.signing;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds JWS envelopes (RFC 7515, RFC 7797) over any {@link Signer}. The provider's native
 * {@link Signer#signJws} is tried first so keymanager output stays byte-identical; otherwise the header is
 * built here and the signing input is signed with {@link Signer#signRaw}.
 */
public final class JwsEnvelope {

    private JwsEnvelope() {}

    /**
     * @return the compact serialization; with {@link JwsHeaderPolicy#detached()} the payload segment is empty
     */
    public static String sign(byte[] payload, JwsHeaderPolicy policy, SigningKey key, Signer signer) {
        return signer.signJws(new Signer.JwsInput(payload, policy), key)
                .orElseGet(() -> signLocally(payload, policy, key, signer));
    }

    /** Convenience for string payloads (JSON documents, JWT claim sets). */
    public static String sign(String payload, JwsHeaderPolicy policy, SigningKey key, Signer signer) {
        return sign(payload.getBytes(StandardCharsets.UTF_8), policy, key, signer);
    }

    static String signLocally(byte[] payload, JwsHeaderPolicy policy, SigningKey key, Signer signer) {
        JWSHeader header = header(policy, key);
        String encodedHeader = header.toBase64URL().toString();
        String payloadPart = policy.b64() ? Base64URL.encode(payload).toString() : new String(payload, StandardCharsets.UTF_8);
        byte[] signingInput = (encodedHeader + "." + payloadPart).getBytes(StandardCharsets.UTF_8);
        byte[] signature = signer.signRaw(signingInput, key, key.algorithm());
        String encodedSignature = Base64URL.encode(signature).toString();
        return encodedHeader + "." + (policy.detached() ? "" : payloadPart) + "." + encodedSignature;
    }

    public static JWSHeader header(JwsHeaderPolicy policy, SigningKey key) {
        JWSHeader.Builder builder = new JWSHeader.Builder(new JWSAlgorithm(key.algorithm().joseName()));
        if (policy.typ() != null) {
            builder.type(new JOSEObjectType(policy.typ()));
        }
        String kid = policy.kid().kidFor(key);
        if (kid != null) {
            builder.keyID(kid);
        }
        CertificateChain chain = key.chain();
        if (policy.x5c() != JwsHeaderPolicy.ChainInclusion.NONE && !chain.isEmpty()) {
            List<String> x5c = policy.x5c() == JwsHeaderPolicy.ChainInclusion.LEAF ? chain.toX5c().subList(0, 1) : chain.toX5c();
            builder.x509CertChain(x5c.stream().map(Base64::new).toList());
        }
        if (policy.x5tS256()) {
            builder.x509CertSHA256Thumbprint(new Base64URL(KidStrategy.X5T_S256.kidFor(key)));
        }
        Set<String> crit = new HashSet<>();
        if (!policy.b64()) {
            builder.base64URLEncodePayload(false);
            crit.add("b64");
        }
        if (!crit.isEmpty()) {
            builder.criticalParams(crit);
        }
        policy.extraHeaders().forEach(builder::customParam);
        return builder.build();
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new SigningException("SHA-256 unavailable", e);
        }
    }
}
