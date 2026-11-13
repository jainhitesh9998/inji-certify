package io.mosip.certify.oid4vci;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings of the OpenID4VCI 1.0 adapter (docs/design/14-configuration.md). {@code compat-core.enabled} routes the
 * compatibility path {@code POST /issuance/credential} through the new core instead of the legacy issuance service;
 * off until the v1 goldens prove both modes on CI, then the default flips and the legacy service is removed.
 */
@ConfigurationProperties(prefix = "certify.protocol.oid4vci-v1")
public record Oid4vciProperties(@DefaultValue CompatCore compatCore, @DefaultValue Notification notification,
                                  @DefaultValue Nonce nonce, @DefaultValue Batch batch, @DefaultValue KeyAttestation keyAttestation,
                               @DefaultValue DidWebHolders didWebHolders, @DefaultValue Offers offers) {

    public static final String COMPAT_CORE_PREFIX = "certify.protocol.oid4vci-v1.compat-core";

    public record CompatCore(@DefaultValue("false") boolean enabled) {}

    /**
     * How long an issuance transaction stays open for the wallet's notification ({@code retention}) and how often
     * expired rows are purged ({@code purge-interval}, read by the housekeeping schedule).
     */
    public record Notification(@DefaultValue("P1D") java.time.Duration retention,
                               @DefaultValue("PT1H") java.time.Duration purgeInterval) {}

    /** {@code single-use}: a c_nonce from the nonce endpoint is consumed by the credential request it authorised. */
    public record Nonce(@DefaultValue("true") boolean singleUse) {}

    /**
     * {@code size}: the largest {@code proofs} array a credential request may carry (one credential per proof),
     * advertised as {@code batch_credential_issuance.batch_size} when above 1.
     */
    public record Batch(@DefaultValue("10") int size) {}

    /**
     * Key attestations (OpenID4VCI 1.0 Appendix D) are trusted through {@code attesters.<id>}: a JWK Set ({@code jwks},
     * JSON) holding the attester's keys, or a PEM trust anchor ({@code trust-anchor}) the attestation's {@code x5c}
     * chains to; {@code clock-skew} is tolerated on {@code iat} and {@code exp}. Which configurations require an
     * attestation, and what they accept, is {@code proof_types_supported.<type>.key_attestations_required}.
     */
    public record KeyAttestation(@DefaultValue java.util.Map<String, Attester> attesters,
                                 @DefaultValue("PT60S") java.time.Duration clockSkew) {}

    public record Attester(String jwks, String trustAnchor) {}

    /**
     * {@code did-web-holders.enabled}: a proof whose {@code kid} is a {@code did:web} DID URL is resolved by fetching the
     * DID document over HTTPS ({@code timeout} per fetch); off by default, so such proofs are rejected as before.
     */
    public record DidWebHolders(@DefaultValue("false") boolean enabled, @DefaultValue("PT5S") java.time.Duration timeout) {}

    /**
     * {@code default-issuer}: the surface a pre-authorized offer targets when its request names none. Typed as the
     * {@link OfferSurface} enum (bound case-insensitively, like the request field), so a typo fails at startup rather
     * than at the first offer. {@code legacy} is the default, so an unchanged deployment's offers keep the compatibility
     * identifier (the mDL profile sets {@code oid4vci}; docs/design/20-mdl-issuer.md, decision D5).
     *
     * <p>{@code max-claims-bytes} and {@code max-claims-values} bound the {@code claims} an offer may carry: the offer is
     * cached until it is redeemed or lapses, and {@code POST /pre-authorized-data} is public on the mDL demo (D12), so
     * one caller must not be able to park unbounded data per offer (F-21 review round 2). The bytes are the claims as
     * JSON (UTF-8); the values are every JSON value inside them at any depth, containers included, because the heap a
     * parsed value costs is set by how many values it holds, not by its length (8 KiB of {@code [{},{},...]} is
     * ~180 KB of heap, the same 8 KiB in one string ~8 KB). Raise them for a data provider that takes large claims
     * ({@code PreAuthDataProviderPlugin} issues them as the credential's data); 0 refuses every non-empty
     * {@code claims}.
     *
     * <p>The built-in defaults (256 KiB, 1024 values) are generous on purpose: {@code POST /pre-authorized-data} shipped
     * in 0.14.0 with unbounded claims, which {@code PreAuthDataProviderPlugin} issues as the credential's data (a base64
     * portrait is often 10-50 KB), so an upgraded deployment keeps working with no new setting (non-negotiable 3). The
     * compose stacks set 8 KiB / 256 and the mDL demo 1 KiB / 32, where the endpoint is public (F-21 review round 3).
     */
    public record Offers(@DefaultValue("legacy") OfferSurface defaultIssuer,
                         @DefaultValue("262144") int maxClaimsBytes,
                         @DefaultValue("1024") int maxClaimsValues) {
        public Offers {
            if (maxClaimsBytes < 0 || maxClaimsValues < 0) {
                throw new IllegalArgumentException("certify.protocol.oid4vci-v1.offers.max-claims-bytes and max-claims-values "
                        + "must not be negative");
            }
        }
    }
}
