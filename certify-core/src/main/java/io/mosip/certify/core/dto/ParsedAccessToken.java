/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import lombok.Data;

import java.util.Map;

/**
 * Access-token view used by services and plugins since 0.9. Since 1.0.0 the bean of this type is
 * request-scoped underneath ({@code RequestScopedParsedAccessToken} in certify-service delegates to
 * {@link AuthorizationContext}), so two concurrent requests never see each other's claims. Plugins and
 * services keep injecting this class unchanged; new code should inject {@link AuthorizationContext}.
 *
 * @deprecated since 1.0.0, use {@link AuthorizationContext}; kept for plugin compatibility until 2.0.0.
 */
@Deprecated(since = "1.0.0")
@Data
public class ParsedAccessToken {

    private Map<String, Object> claims;
    private String accessTokenHash;
    private boolean isActive;
}
