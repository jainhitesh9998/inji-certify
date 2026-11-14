package io.mosip.certify.status;

import java.util.List;
import java.util.Objects;

/**
 * A CWT status list whose update cannot be applied now, with the batch job's answer to it (M-11d review round 2, major
 * 2): {@link Kind#TRANSIENT} when time or a retry can clear it (the key provider or HSM unavailable, a stale IACA CRL, a
 * certificate not yet valid, a signing failure), {@link Kind#PERMANENT} when only an operator can (a revoked or
 * rotated-away Document Signer, a signer the IACA did not issue or not for this purpose, a stored token its pinned
 * signer did not sign). Neither drops the list's transactions: they stay pending, in order, until the list can be
 * updated again. A retired list is not this exception but {@link StatusListRetiredException}: its transactions are
 * closed, since every mDL on it has expired (D-M11-7).
 *
 * <p>The classification follows the rule each refusal names ({@link StatusListSignerPolicy}, {@link StatusListSigners}),
 * not the exception's type: a policy refusal is an {@link IllegalStateException} whatever its rule. A
 * {@value StatusListSigners#GONE} with a cause is the provider failing to resolve the pinned reference at all (an
 * outage, or a key an operator may restore); without one the reference now names another certificate, which no retry
 * changes. A failure no rule names is transient: retrying it is bounded by the back-off, while calling it permanent
 * would park a list on a guess.
 */
public class TokenStatusListUpdateException extends IllegalStateException {

    /** Whether a later attempt can succeed without an operator changing anything. */
    public enum Kind { TRANSIENT, PERMANENT }

    /** The stored document is not the section 4.4 envelope, or its token is not a CWT this build reads. */
    public static final String UNREADABLE = "STATUS_LIST_UNREADABLE";
    /** The stored token is not signed by the certificate its envelope pins (review round 1, major 1). */
    public static final String UNVERIFIABLE = "STATUS_LIST_UNVERIFIABLE";
    /** A transaction names an index outside the list's bits: no retry makes it fit. */
    public static final String INDEX_OUT_OF_RANGE = "STATUS_LIST_INDEX_OUT_OF_RANGE";
    /** The signer could not sign now: a provider, HSM or network failure without a rule of its own. */
    public static final String SIGNING_FAILED = "STATUS_LIST_SIGNING_FAILED";

    /** Refusals no retry clears: the certificate, its path or its purpose is wrong until an operator replaces it. */
    static final List<String> PERMANENT_RULES = List.of(StatusListSignerPolicy.REVOKED, StatusListSignerPolicy.PURPOSE,
            StatusListSignerPolicy.NO_TRUSTED_IACA, StatusListSignerPolicy.SELF_SIGNED,
            StatusListSignerPolicy.CARRIES_ANCHOR, StatusListSignerPolicy.ISSUER_NOT_CA,
            StatusListSignerPolicy.PATH_LENGTH, StatusListSignerPolicy.NO_CHAIN, StatusListSignerPolicy.EXPIRED,
            StatusListSignerPolicy.IACA_EXPIRED, StatusListSignerPolicy.CHAIN_LINK_INVALID);
    /** Refusals that clear by themselves or by routine operation: a new CRL, a certificate whose notBefore arrives. */
    static final List<String> TRANSIENT_RULES = List.of(StatusListSignerPolicy.CRL_STALE,
            StatusListSignerPolicy.NOT_YET_VALID, StatusListSignerPolicy.IACA_NOT_YET_VALID);

    private final String listId;
    private final Kind kind;
    private final String rule;

    public TokenStatusListUpdateException(String listId, Kind kind, String rule, RuntimeException cause) {
        super(String.valueOf(Objects.requireNonNull(cause, "cause").getMessage()), cause);
        this.listId = Objects.requireNonNull(listId, "listId");
        this.kind = Objects.requireNonNull(kind, "kind");
        this.rule = Objects.requireNonNull(rule, "rule");
    }

    /** A failure of re-signing a list (resolving its pinned signer, the policy, the signature), classified by its rule. */
    public static TokenStatusListUpdateException signing(String listId, RuntimeException failure) {
        String message = String.valueOf(failure.getMessage());
        if (startsWithRule(message, StatusListSigners.GONE)) {
            // with a cause the provider could not resolve the reference at all (an outage, a key that may be restored);
            // without one the reference resolved to another certificate, which no retry changes (section 4.3)
            return new TokenStatusListUpdateException(listId, failure.getCause() == null ? Kind.PERMANENT : Kind.TRANSIENT,
                    StatusListSigners.GONE, failure);
        }
        for (String rule : PERMANENT_RULES) {
            if (startsWithRule(message, rule)) {
                return new TokenStatusListUpdateException(listId, Kind.PERMANENT, rule, failure);
            }
        }
        for (String rule : TRANSIENT_RULES) {
            if (startsWithRule(message, rule)) {
                return new TokenStatusListUpdateException(listId, Kind.TRANSIENT, rule, failure);
            }
        }
        return new TokenStatusListUpdateException(listId, Kind.TRANSIENT, SIGNING_FAILED, failure);
    }

    /** A failure no retry clears that is not a signer rule: an unreadable or unverifiable row, an index outside it. */
    public static TokenStatusListUpdateException permanent(String listId, String rule, RuntimeException failure) {
        return new TokenStatusListUpdateException(listId, Kind.PERMANENT, rule, failure);
    }

    private static boolean startsWithRule(String message, String rule) {
        return message.startsWith(rule + ":");
    }

    public String listId() {
        return listId;
    }

    public Kind kind() {
        return kind;
    }

    public boolean permanent() {
        return kind == Kind.PERMANENT;
    }

    /** The rule that refused the update: a {@link StatusListSignerPolicy} rule, {@value StatusListSigners#GONE}, or one of this class's. */
    public String rule() {
        return rule;
    }
}
