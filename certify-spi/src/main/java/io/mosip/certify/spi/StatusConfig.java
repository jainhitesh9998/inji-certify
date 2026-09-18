package io.mosip.certify.spi;

import java.util.List;

/** Which status mechanism a configuration uses, if any, and for which purposes. */
public record StatusConfig(String mechanism, List<String> purposes) {

    public static final StatusConfig NONE = new StatusConfig(null, List.of());

    public StatusConfig {
        purposes = purposes == null ? List.of() : List.copyOf(purposes);
    }

    public boolean isEnabled() {
        return mechanism != null && !purposes.isEmpty();
    }
}
