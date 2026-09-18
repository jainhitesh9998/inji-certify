package io.mosip.certify.services;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.signing.KeyFilter;
import io.mosip.certify.signing.KeyPublisher;
import io.mosip.certify.signing.PublicKeyDescriptor;
import io.mosip.certify.signing.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Publishes every key of every {@link io.mosip.certify.signing.KeyProvider} as a JWK (P1-04). The field set per key
 * is the one keymanager-backed publishing produced: kid, kty, use, exp, x5c, x5t#S256 and the public parameters.
 */
@Service
@Slf4j
public class JwksServiceImpl implements JwksService {

    @Autowired
    private KeyPublisher keyPublisher;

    /**
     * Internal method to fetch JWK set - cached for performance
     * Only successful responses are cached (method returns non-null Map)
     */
    @Cacheable(value = "jwks", key = "'oauth-jwks'")
    public Map<String, Object> getJwks() {
        List<Map<String, Object>> jwkList = new ArrayList<>();
        for (PublicKeyDescriptor descriptor : keyPublisher.descriptors(KeyFilter.validNow())) {
            try {
                jwkList.add(toJwk(descriptor));
                log.debug("Added JWK for keyId: {}", descriptor.kid());
            } catch (Exception e) {
                log.error("Failed to build the JWK for keyId: {}", descriptor.kid(), e);
            }
        }
        Map<String, Object> response = new HashMap<>();
        response.put("keys", jwkList);
        return response;
    }

    /** kid, kty, use, exp, x5c, x5t#S256 and the public parameters (e/n, x/y/crv, or crv/x for Ed25519). */
    static Map<String, Object> toJwk(PublicKeyDescriptor descriptor) throws Exception {
        JWK jwk = descriptor.toJwk();
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kid", descriptor.kid());
        map.put("kty", jwk.getKeyType().getValue());
        X509Certificate leaf = descriptor.chain().leaf().orElse(null);
        String use = descriptor.algorithm() == SignatureAlgorithm.EdDSA || leaf == null ? "sig" : keyUse(leaf);
        if (use != null) {
            map.put("use", use);
        }
        if (descriptor.notAfter() != null) {
            map.put("exp", descriptor.notAfter().getEpochSecond());
        }
        if (leaf != null) {
            map.put("x5c", descriptor.chain().toX5c());
            map.put("x5t#S256", Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded())).toString());
        }
        Map<String, ?> params = jwk.toPublicJWK().getRequiredParams();
        for (String name : List.of("e", "n", "x", "y", "crv")) {
            if (params.containsKey(name)) {
                map.put(name, params.get(name));
            }
        }
        return map;
    }

    private static String keyUse(X509Certificate certificate) {
        KeyUse use = KeyUse.from(certificate);
        return use == null ? null : use.getValue();
    }
}
