package io.mosip.certify.spi;

import java.util.List;
import java.util.Map;

/**
 * Wallet-facing metadata of a configuration: display objects, claim display order and per-claim display.
 * Kept as JSON-compatible maps because every protocol version renders them differently.
 */
public record DisplayConfig(List<Map<String, Object>> display, List<String> order, Map<String, Object> claims) {

    public static final DisplayConfig NONE = new DisplayConfig(List.of(), List.of(), Map.of());

    public DisplayConfig {
        display = display == null ? List.of() : List.copyOf(display);
        order = order == null ? List.of() : List.copyOf(order);
        claims = claims == null ? Map.of() : Map.copyOf(claims);
    }
}
