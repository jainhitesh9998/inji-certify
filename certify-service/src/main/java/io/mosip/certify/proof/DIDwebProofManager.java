package io.mosip.certify.proof;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Optional;

/**
 * Holder keys named by a {@code did:web} DID URL (W3C did:web method): {@code did:web:host[:path...]#fragment} resolves
 * to {@code https://host/[path/]did.json} ({@code /.well-known/did.json} without a path), and the verification method
 * whose {@code id} is the {@code kid} supplies the key as {@code publicKeyJwk} or {@code publicKeyMultibase}. Enabled by
 * {@code certify.protocol.oid4vci-v1.did-web-holders.enabled}; without it a {@code did:web} kid is rejected as before.
 */
@Slf4j
public class DIDwebProofManager implements JwtProofKeyManager {

    public static final String DID_WEB_PREFIX = "did:web:";

    private final DidDocumentFetcher fetcher;

    public DIDwebProofManager(DidDocumentFetcher fetcher) {
        this.fetcher = fetcher;
    }

    @Override
    public Optional<JWK> getKeyFromHeader(JWSHeader header) {
        if (header.getJWK() != null) {
            return Optional.of(header.getJWK());
        }
        String kid = header.getKeyID();
        if (kid == null || !kid.startsWith(DID_WEB_PREFIX)) {
            return Optional.empty();
        }
        int hash = kid.indexOf('#');
        String did = hash < 0 ? kid : kid.substring(0, hash);
        try {
            JSONObject document = new JSONObject(fetcher.fetch(documentUrl(did)));
            if (!did.equals(document.optString("id", did))) {
                log.error("DID document id {} does not match {}", document.optString("id"), did);
                return Optional.empty();
            }
            JSONArray methods = document.optJSONArray("verificationMethod");
            for (int i = 0; methods != null && i < methods.length(); i++) {
                JSONObject method = methods.getJSONObject(i);
                String id = method.optString("id");
                if (kid.equals(id) || (hash > 0 && id.equals(kid.substring(hash)))) {
                    return key(method, kid);
                }
            }
            log.error("No verification method {} in the DID document of {}", kid, did);
        } catch (IOException | RuntimeException e) {
            log.error("Could not resolve {}: {}", did, e.getMessage());
        }
        return Optional.empty();
    }

    @Override
    public Optional<String> getDID(JWSHeader header) {
        return header.getKeyID() != null && header.getKeyID().startsWith(DID_WEB_PREFIX) ? Optional.of(header.getKeyID()) : Optional.empty();
    }

    /** {@code did:web:example.com:users:alice} is {@code https://example.com/users/alice/did.json}; a port is percent-encoded in the DID. */
    static URI documentUrl(String did) {
        String[] parts = did.substring(DID_WEB_PREFIX.length()).split(":");
        String host = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
        if (host.isBlank()) {
            throw new IllegalArgumentException("did:web without a host: " + did);
        }
        StringBuilder path = new StringBuilder();
        for (int i = 1; i < parts.length; i++) {
            path.append('/').append(URLDecoder.decode(parts[i], StandardCharsets.UTF_8));
        }
        return URI.create("https://" + host + (path.isEmpty() ? "/.well-known" : path) + "/did.json");
    }

    private static Optional<JWK> key(JSONObject method, String kid) {
        try {
            if (method.has("publicKeyJwk")) {
                return Optional.of(DIDkeysProofManager.withKid(JWK.parse(method.getJSONObject("publicKeyJwk").toString()), kid));
            }
            if (method.has("publicKeyMultibase")) {
                return DIDkeysProofManager.fromMultibase(method.getString("publicKeyMultibase")).map(key -> DIDkeysProofManager.withKid(key, kid));
            }
        } catch (ParseException e) {
            log.error("Verification method {} carries an unparsable key: {}", kid, e.getMessage());
        }
        return Optional.empty();
    }
}
