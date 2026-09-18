package io.mosip.certify.spi;

import java.util.Map;

/**
 * The subject data a data source returned, plus provenance a listener may want (which source, when, request id).
 * Values are JSON-compatible: strings, numbers, booleans, lists and maps.
 */
public record ClaimSet(Map<String, Object> claims, Map<String, Object> provenance) {

    public ClaimSet {
        claims = claims == null ? Map.of() : Map.copyOf(claims);
        provenance = provenance == null ? Map.of() : Map.copyOf(provenance);
    }

    public static ClaimSet of(Map<String, Object> claims) {
        return new ClaimSet(claims, Map.of());
    }

    public Object get(String name) {
        return claims.get(name);
    }
}
