package io.mosip.certify.oid4vci;

/**
 * The {@code error_description} of an OpenID4VCI error response, made ASCII-safe (M-11e review round 1, minor 5).
 *
 * <p>OpenID4VCI 1.0 section 8.3.1.2 gives the member the ABNF of OAuth 2.0 (RFC 6749 appendix A.7), which the
 * {@code error_description} of RFC 6749 section 5.2 repeats:
 *
 * <pre>
 * error-description = 1*( %x20-21 / %x23-5B / %x5D-7E )
 * </pre>
 *
 * <p>That is printable US-ASCII except the double quote ({@code %x22}) and the backslash ({@code %x5C}), so a description
 * Certify derives from a certificate subject, a file path or an exception message may carry characters the grammar does
 * not allow: a Unicode common name, a quote, a backslash, a newline or a tab. Every other character becomes {@code ?}
 * (itself allowed), which keeps the response parseable by a strict client and keeps the position of the offending value
 * visible. A description that is already safe is returned unchanged, so nothing on the wire moves for the messages
 * Certify writes itself (CLAUDE.md rule 1).
 *
 * <p>This is the protocol boundary and the only place the rule applies: the compatibility surfaces answer the MOSIP error
 * envelope, whose {@code error_description} is not this grammar's.
 */
public final class Oid4vciErrorDescriptions {

    /** The replacement for a character RFC 6749 appendix A.7 does not allow in a description. */
    public static final char REPLACEMENT = '?';

    private Oid4vciErrorDescriptions() {}

    /**
     * @param description the message of a core or provider failure, possibly {@code null}
     * @return the same text with every character outside {@code %x20-21 / %x23-5B / %x5D-7E} replaced by {@code ?}
     */
    public static String safe(String description) {
        if (description == null) {
            return null;
        }
        StringBuilder safe = null;
        for (int i = 0; i < description.length(); i++) {
            char c = description.charAt(i);
            boolean allowed = (c >= 0x20 && c <= 0x21) || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E);
            if (allowed) {
                if (safe != null) {
                    safe.append(c);
                }
                continue;
            }
            if (safe == null) {
                safe = new StringBuilder(description.length());
                safe.append(description, 0, i);
            }
            safe.append(REPLACEMENT);
        }
        return safe == null ? description : safe.toString();
    }
}
