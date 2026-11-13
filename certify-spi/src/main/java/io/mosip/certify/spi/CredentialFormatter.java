package io.mosip.certify.spi;

import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * One credential format, end to end: configuration schema, metadata fragment, build and sign
 * (docs/design/05-target-architecture.md). Formats are discovered by {@link #formatId()} and {@link #aliases()};
 * nothing else in Certify switches on the format string.
 */
public interface CredentialFormatter {

    /** Canonical identifier advertised in metadata: {@code ldp_vc}, {@code dc+sd-jwt}, {@code mso_mdoc}, {@code jwt_vc_json}. */
    String formatId();

    /** Identifiers accepted on input for compatibility but never advertised, e.g. {@code vc+sd-jwt}. */
    default Set<String> aliases() {
        return Set.of();
    }

    default boolean handles(String format) {
        return formatId().equals(format) || aliases().contains(format);
    }

    /** Parses and validates the format-specific part of a configuration; throws {@link FormatException} on a bad one. */
    FormatConfig parseConfig(Map<String, Object> raw);

    /** The format-specific fields of this configuration's entry in issuer metadata for the given protocol version. */
    Map<String, Object> metadataFragment(CredentialConfiguration configuration, ProtocolVersion version);

    /** Builds the unsigned credential from rendered claims (or from a supplied document in {@code claims.provenance}). */
    UnsignedCredential build(ClaimSet claims, CredentialConfiguration configuration, IssuanceContext context, HolderBinding holder);

    /** Signs with the envelope builders of certify-signing; never calls a key provider directly. */
    IssuedCredential sign(UnsignedCredential credential, SigningContext signing, IssuanceContext context);

    /**
     * The checks {@link #sign} runs on the signing key, without signing anything: a configuration's dry run and preview
     * call it so that a key this format would refuse is named before a wallet asks for a credential. The supplier
     * resolves the key; a format with nothing to check never calls it, so a preview stays key-free for it. Throws
     * {@link FormatException} with the rule the key breaks. Default: nothing to check.
     */
    default void checkSigningKey(Supplier<SigningContext> signing, CredentialConfiguration configuration, IssuanceContext context) {
    }
}
