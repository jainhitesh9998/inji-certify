package io.mosip.certify.signing;

/** What a configuration needs from a provider at bootstrap: a key under this alias, for this algorithm and purpose. */
public record KeyRequirement(String alias, SignatureAlgorithm algorithm, String purpose) {}
