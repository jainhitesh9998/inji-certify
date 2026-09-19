package io.mosip.certify.status;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Token Status List (draft-ietf-oauth-status-list) settings: the key that signs every list ({@code key-ref} as
 * {@code provider:alias}, e.g. {@code x509-file:sdjwt-es256}; keymanager's EC key when absent), its JOSE algorithm, how
 * much of its chain the list's {@code x5c} carries, the list size in bits, and how long a fetched list may be cached ({@code ttl}).
 */
@ConfigurationProperties(prefix = "certify.status.token-status-list")
public record TokenStatusListProperties(String keyRef, @DefaultValue("ES256") String alg, @DefaultValue("without-anchor") String x5c,
                                        @DefaultValue("131072") int sizeBits, @DefaultValue("PT1H") Duration ttl) {
}
