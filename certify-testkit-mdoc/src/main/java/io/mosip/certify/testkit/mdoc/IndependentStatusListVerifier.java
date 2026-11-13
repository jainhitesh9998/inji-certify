/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORDecoderOptions;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function3;
import kotlinx.coroutines.BuildersKt;
import kotlinx.coroutines.CoroutineScope;
import kotlin.jvm.functions.Function2;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.MajorType;
import org.multipaz.cbor.Tagged;
import org.multipaz.cose.Cose;
import org.multipaz.cose.CoseLabel;
import org.multipaz.cose.CoseNumberLabel;
import org.multipaz.cose.CoseSign1;
import org.multipaz.crypto.Algorithm;
import org.multipaz.crypto.X509Cert;
import org.multipaz.crypto.X509CertChain;
import org.multipaz.crypto.X509CertChainJvmKt;
import org.multipaz.revocation.CompressedStatusList;
import org.multipaz.revocation.StatusList;
import org.multipaz.util.CompressionKt;
import org.multipaz.webtoken.ValidateJwtKt;
import org.multipaz.webtoken.WebTokenCheck;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An independent Token Status List verifier for the {@code mso_mdoc} status list of
 * ISO/IEC 18013-5 second edition 12.3.6 (M-11b in {@code docs/design/wp/M-11-status-list-under-iaca.md}).
 *
 * <p>It applies the rules to the bytes a wallet downloads, with libraries Certify does not maintain: OpenWallet
 * Foundation <b>Multipaz</b> parses the CBOR, checks the COSE_Sign1 signature, runs its own
 * {@code CompressedStatusList.fromCwt} (typ, sub, exp, maxValidity and the chain to the IACA, exactly as
 * {@code CachingRevocationChecker} calls it) and decides the chain's trust independently with
 * {@code trustedRootCertificateChainValidator}; <b>Authlete CBOR</b> parses and verifies the same COSE_Sign1 as a second
 * oracle; the JDK's X.509 API reads the signer's EKU and key usage. {@code @owf/mdoc} 0.9.1 (Paradym) and Credo's
 * {@code assertMdocStatusListChainsMatchIssuanceChain} are emulated, not imported: the list's {@code x5chain} must be
 * certificate-for-certificate equal to the mDL's IssuerAuth {@code x5chain}, and the CBOR envelope must be exactly one
 * tag, 18 — {@code @owf/cose} 0.6.0 refuses any other tag stack including the self-describe tag 55799 (M-11b review
 * round 1).
 *
 * <p>Each rule is a named check in a {@link VerificationReport}; a failed check carries <b>every</b> problem it found,
 * each under a stable code from {@link #PROBLEM_CODES}. The codes are the ones
 * {@code docs/design/tools/verify_status_list.py} reports in M-11f; this table is held to the M-11b table by
 * {@code ProblemCodeRegistryTest}.
 *
 * <table>
 *   <caption>Checks and clauses</caption>
 *   <tr><th>Check</th><th>Clause</th></tr>
 *   <tr><td>{@code statusList.mso}</td><td>ISO/IEC 18013-5 second edition 12.3.6 (the MSO {@code status.status_list}
 *       {uri: tstr, idx: uint} that points at the list)</td></tr>
 *   <tr><td>{@code statusList.http}</td><td>TSL 8.2 (content type)</td></tr>
 *   <tr><td>{@code statusList.envelope}</td><td>TSL 5.2, RFC 9052 4.2 (tag 18, never CWT tag 61; no MAC0; no
 *       detached payload); RFC 9052 3, RFC 8392 7.2 steps 1 and 7, RFC 8949 5.3.1 and 5.6.1 (no map of the headers
 *       or the claims carries a key twice)</td></tr>
 *   <tr><td>{@code statusList.typ}</td><td>TSL 5.2, RFC 9596 (protected {@code typ} =
 *       {@code application/statuslist+cwt})</td></tr>
 *   <tr><td>{@code statusList.x5chain}</td><td>ISO/IEC 18013-5 second edition 12.3.6.3 (protected {@code x5chain}),
 *       HAIP 6.1 analogue, RFC 5280 4.1.2.2 (serials)</td></tr>
 *   <tr><td>{@code statusList.signature}</td><td>TSL 5.2 rule 2; two independent oracles</td></tr>
 *   <tr><td>{@code statusList.chain}</td><td>ISO/IEC 18013-5 second edition 12.3.6.2 (trust point = IACA)</td></tr>
 *   <tr><td>{@code statusList.issuanceChain}</td><td>Credo {@code mdocUtil.ts:76-115}</td></tr>
 *   <tr><td>{@code statusList.claims}</td><td>TSL 5.2, 8.3 steps 4a/4c; ISO/IEC 18013-5 second edition 12.3.6.3
 *       ({@code exp} shall be present); RFC 8392 3.1.4 and RFC 7519 4.1.4 (the evaluation time must be before
 *       {@code exp})</td></tr>
 *   <tr><td>{@code statusList.list}</td><td>TSL 4.1, 8.3 step 6; ISO/IEC 18013-5 second edition 12.3.6.5
 *       ({@code bits} = 1)</td></tr>
 *   <tr><td>{@code statusList.signerPurpose}</td><td>Credo {@code assertStatusListSignerKeyPurpose.ts:14-25}</td></tr>
 * </table>
 *
 * <p>A check that did not run is {@link VerificationReport.State#SKIPPED} and is not a pass. Options that this
 * verifier cannot decide (no IACA supplied, no IssuerAuth chain supplied, a dedicated signer) are explicit in
 * {@link StatusListOptions} or are reported as skipped, never as passing.
 */
public final class IndependentStatusListVerifier {

    /** TSL 8.2: the media type of a CWT status list (the CoAP Content-Format id is still TBD, TSL 14.8). */
    public static final String MEDIA_TYPE = "application/statuslist+cwt";

    /** TSL 10, IANA "SMI Security for PKIX Extended Key Purpose" value 45 (assigned 2026-06-12). */
    public static final String STATUS_SIGNING_EKU = "1.3.6.1.5.5.7.3.45";

    /** ISO/IEC 18013-5 Annex B: the mDL Document Signer EKU. */
    public static final String DOCUMENT_SIGNER_EKU = "1.0.18013.5.1.2";

    /** The MSO's own {@code status.status_list}, before any token is fetched: present, absent, or malformed. */
    public static final String CHECK_MSO = "statusList.mso";
    public static final String CHECK_HTTP = "statusList.http";
    public static final String CHECK_ENVELOPE = "statusList.envelope";
    public static final String CHECK_TYP = "statusList.typ";
    public static final String CHECK_X5CHAIN = "statusList.x5chain";
    public static final String CHECK_SIGNATURE = "statusList.signature";
    public static final String CHECK_CHAIN = "statusList.chain";
    public static final String CHECK_ISSUANCE_CHAIN = "statusList.issuanceChain";
    public static final String CHECK_CLAIMS = "statusList.claims";
    public static final String CHECK_LIST = "statusList.list";
    public static final String CHECK_SIGNER_PURPOSE = "statusList.signerPurpose";

    /** Every check this class can report, in report order: the MSO's reference first, then the token's checks. */
    public static final List<String> CHECKS = List.of(CHECK_MSO, CHECK_HTTP, CHECK_ENVELOPE, CHECK_TYP, CHECK_X5CHAIN,
            CHECK_SIGNATURE, CHECK_CHAIN, CHECK_ISSUANCE_CHAIN, CHECK_CLAIMS, CHECK_LIST, CHECK_SIGNER_PURPOSE);

    /** The checks {@link #verify} runs on a token; {@link #mso} runs {@link #CHECK_MSO} beside them. */
    public static final List<String> TOKEN_CHECKS = List.of(CHECK_HTTP, CHECK_ENVELOPE, CHECK_TYP, CHECK_X5CHAIN,
            CHECK_SIGNATURE, CHECK_CHAIN, CHECK_ISSUANCE_CHAIN, CHECK_CLAIMS, CHECK_LIST, CHECK_SIGNER_PURPOSE);

    /**
     * The problem codes each check reports. A code ending in {@code :*} takes a parameter
     * ({@code statusMismatch:1}); every other code is spelled exactly as a mutation test and {@code .gaps} line names
     * it. {@code docs/design/tools/verify_status_list.py} carries the same table from M-11f.
     */
    public static final Map<String, List<String>> PROBLEM_CODES = problemCodes();

    /** Reported when a check throws unexpectedly; never an accepted gap. */
    public static final String ERROR = "error";
    /** Reported when the body did not parse or a check's subject is missing; never an accepted gap. */
    public static final String NOT_RUN = "notRun";

    /** RFC 8949 3.1 / RFC 8392 3.1 claim keys, as unsigned integers. */
    static final long CLAIM_SUB = 2;
    static final long CLAIM_EXP = 4;
    static final long CLAIM_IAT = 6;
    static final long CLAIM_STATUS_LIST = 65533;
    static final long CLAIM_TTL = 65534;
    /** COSE header labels (RFC 9596 2, RFC 9360 2) and RFC 9052 4.2 tags. */
    static final long LABEL_ALG = 1;
    static final long LABEL_TYP = 16;
    static final long LABEL_X5CHAIN = 33;
    static final long TAG_COSE_SIGN1 = 18;
    static final long TAG_CWT = 61;
    static final long TAG_COSE_MAC0 = 17;
    /**
     * The clock allowance for {@code iat}, the same five seconds Multipaz's {@code validateCwt} uses
     * ("Allow no more than 5 seconds clock mismatch"), so this verifier and the wallet stack agree on when a list is
     * "not yet issued".
     */
    static final long IAT_FUTURE_SKEW_SECONDS = 5;
    /** Multipaz's {@code fromCwt} default {@code maxValidity} (365 days), which {@code CachingRevocationChecker} uses. */
    static final long MAX_VALIDITY_SECONDS = 365L * 24 * 3600;
    /**
     * The {@code bits} values Multipaz's {@code CompressedStatusList} constructor accepts (ISO2 12.3.6.5 wants 1),
     * compared after {@code fromStatusListClaim}'s own narrowing of the {@code Uint} to an {@code int}
     * ({@code Uint.getValue}, then {@code l2i} in the 0.102.0 bytecode), so {@code 4294967297} reads as 1 there.
     */
    static final Set<Integer> FROM_CWT_BITS = Set.of(1, 2, 4, 8);
    static final int MAX_SERIAL_OCTETS = 20;

    private static final Pattern CODE = Pattern.compile("([A-Za-z][A-Za-z0-9]*)(?::([A-Za-z0-9_./-]+))?");

    private static Map<String, List<String>> problemCodes() {
        Map<String, List<String>> codes = new LinkedHashMap<>();
        codes.put(CHECK_MSO, List.of("malformed"));
        codes.put(CHECK_HTTP, List.of("contentType"));
        codes.put(CHECK_ENVELOPE, List.of("notTagged18", "cwtTag61", "mac0", "detachedPayload", "duplicateKey"));
        codes.put(CHECK_TYP, List.of("missing", "unprotected", "notText", "wrong"));
        codes.put(CHECK_X5CHAIN, List.of("missing", "unprotectedOnly", "carriesAnchor", "serialNumber"));
        codes.put(CHECK_SIGNATURE, List.of("invalid:multipaz", "invalid:authlete"));
        codes.put(CHECK_CHAIN, List.of("untrusted", "noAnchorSupplied"));
        codes.put(CHECK_ISSUANCE_CHAIN, List.of("differs"));
        codes.put(CHECK_CLAIMS, List.of("subMismatch", "iatMissing", "iatFuture", "iatAfterExp", "expMissing", "expired",
                "expAfterSigner", "ttlInvalid"));
        codes.put(CHECK_LIST, List.of("missing", "bitsNotOne", "lstNotZlib", "idxOutOfRange", "statusMismatch:*"));
        codes.put(CHECK_SIGNER_PURPOSE, List.of("ekuMissing", "kuMissing"));
        if (!List.copyOf(codes.keySet()).equals(CHECKS)) {
            throw new IllegalStateException("PROBLEM_CODES must list every check in report order");
        }
        return Collections.unmodifiableMap(codes);
    }

    /** True when {@code code} is one {@code check} reports: a listed code, or a parameterised one with its parameter. */
    public static boolean isProblemCode(String check, String code) {
        List<String> codes = PROBLEM_CODES.get(check);
        Matcher matcher = code == null ? null : CODE.matcher(code);
        if (codes == null || matcher == null || !matcher.matches()) {
            return false;
        }
        return codes.contains(code) || (matcher.group(2) != null && codes.contains(matcher.group(1) + ":*"));
    }

    /**
     * What the caller knows about the deployment and expects of the list.
     *
     * @param strict              the list is a production sample: a check that cannot run because an input is missing
     *                            ({@code statusList.chain} without an IACA) fails instead of being skipped
     * @param expectedStatus      the status the list must report at {@code idx}: {@code 0} VALID for a live mDL or
     *                            {@code 1} INVALID for a revoked one. ISO/IEC 18013-5 second edition 12.3.6.1 allows
     *                            "no other status besides 'revoked'", and {@code bits} is 1 (12.3.6.5), so 2
     *                            SUSPENDED and 3 are refused as expectations
     * @param requireIssuanceChain the token's {@code x5chain} must equal the mDL's IssuerAuth {@code x5chain} (Credo's
     *                            rule, the default signer of D-M11-1); {@code false} for a dedicated status signer
     */
    public record StatusListOptions(boolean strict, int expectedStatus, boolean requireIssuanceChain) {

        public StatusListOptions {
            if (expectedStatus != 0 && expectedStatus != 1) {
                throw new IllegalArgumentException("expectedStatus must be 0 (VALID) or 1 (INVALID): ISO/IEC 18013-5 "
                        + "second edition 12.3.6.1 allows no mdoc status besides revoked, and 12.3.6.5 makes bits 1; is "
                        + expectedStatus);
            }
        }

        /** A live mDL's list under Credo's equal-chain rule, every check running. */
        public static StatusListOptions strictMode() {
            return new StatusListOptions(true, 0, true);
        }
    }

    /**
     * Verifies a status list token as a wallet received it.
     *
     * @param body                the HTTP response body as received
     * @param contentType         the HTTP {@code Content-Type} as received, parameters included
     * @param uri                 the {@code status_list.uri} the mDL's MSO carries
     * @param idx                 the {@code status_list.idx} the mDL's MSO carries
     * @param issuerAuthX5chain   the mDL's IssuerAuth {@code x5chain} as received, leaf first; empty when unknown
     * @param iaca                the IACA the mDL's Document Signer chains to, or {@code null} when none is known
     * @param at                  the instant the wallet evaluates the list at
     * @param options             what the caller expects
     */
    public static VerificationReport verify(byte[] body, String contentType, String uri, long idx,
                                            List<X509Certificate> issuerAuthX5chain, X509Certificate iaca, Instant at,
                                            StatusListOptions options) {
        if (body == null || uri == null || at == null || options == null) {
            throw new IllegalArgumentException("body, uri, at and options are required");
        }
        Token token = Token.parse(body);
        List<X509Certificate> issuanceChain = issuerAuthX5chain == null ? List.of() : List.copyOf(issuerAuthX5chain);
        // The chain check reports fromCwt's refusal as "untrusted" only when no more specific check already failed, so
        // one mutation still fires one code: compute those checks first, then the chain, and keep the report order.
        VerificationReport.Check envelope = run(CHECK_ENVELOPE, token::envelope);
        VerificationReport.Check typ = run(CHECK_TYP, token::typ);
        VerificationReport.Check signature = run(CHECK_SIGNATURE,
                problems -> token.signature(problems, !envelope.passed()));
        VerificationReport.Check claims = run(CHECK_CLAIMS, problems -> token.claims(problems, uri, at));
        VerificationReport.Check list = run(CHECK_LIST, problems -> token.list(problems, idx, options.expectedStatus()));
        // Only a defect fromCwt itself refuses on can explain its refusal; the decision is taken from the token's
        // state (tags, payload, claims), not from check names, because several codes cover shapes fromCwt accepts.
        boolean fromCwtRefusalExplained = token.fromCwtRefusesOnAReportedDefect(uri, at, typ, signature);
        List<VerificationReport.Check> checks = new ArrayList<>();
        checks.add(run(CHECK_HTTP, problems -> http(problems, contentType)));
        checks.add(envelope);
        checks.add(typ);
        checks.add(run(CHECK_X5CHAIN, token::x5chain));
        checks.add(signature);
        checks.add(run(CHECK_CHAIN, problems -> token.chain(problems, iaca, at, uri, options, fromCwtRefusalExplained)));
        checks.add(run(CHECK_ISSUANCE_CHAIN, problems -> token.issuanceChain(problems, issuanceChain, options)));
        checks.add(claims);
        checks.add(list);
        checks.add(run(CHECK_SIGNER_PURPOSE, problems -> token.signerPurpose(problems, issuanceChain)));
        return new VerificationReport(checks);
    }

    /**
     * The sample-side check of the MSO's {@code status.status_list} itself (ISO/IEC 18013-5 second edition 12.3.6):
     * a present-but-malformed reference must fail the gate rather than silently skip the list, because a wallet that
     * cannot read {@code {uri, idx}} cannot fetch the list at all; only an unreadable IssuerAuth or MSO stays M-01's
     * (the reference cannot be read there either).
     *
     * @param malformed why the reference is malformed, or {@code null} when the MSO has no {@code status_list} or a
     *                  well-formed one
     */
    public static VerificationReport.Check mso(String malformed) {
        return run(CHECK_MSO, problems -> {
            if (malformed != null) {
                problems.add("malformed", malformed);
            }
            return "the MSO's status.status_list is " + (malformed == null ? "absent or {uri: tstr, idx: uint}"
                    : "malformed");
        });
    }

    /** Check 0: the response carries the CWT media type, whatever its parameters (TSL 8.2). */
    private static String http(Problems problems, String contentType) {
        String type = contentType == null ? "" : contentType.split(";", 2)[0].trim();
        if (!MEDIA_TYPE.equalsIgnoreCase(type)) {
            problems.add("contentType", "Content-Type is " + (contentType == null ? "absent" : "'" + contentType + "'")
                    + "; TSL 8.2 makes a CWT status list " + MEDIA_TYPE + " (ISO/IEC 18013-5 second edition 12.3.6.3 "
                    + "makes the mdoc list a CWT, so application/statuslist+jwt is the wrong format)");
        }
        return "served as " + MEDIA_TYPE;
    }

    /** A parsed status list token: the COSE structure read from the wire, never re-encoded. */
    private static final class Token {

        private final byte[] body;
        /** Non-null when the body is not a COSE_Sign1 CWT at all; every check that needs it reports notRun. */
        private String parseError;
        /**
         * Non-null when a map of the headers or the claims carries a key twice: the token is malformed (RFC 9052 3,
         * RFC 8392 7.2), so nothing is read from its maps and every check that needs them reports notRun.
         */
        private String duplicateKeys;
        /** Every tag the body carried, outermost first: {@code 18} alone is the only shape TSL 5.2 allows. */
        private List<Long> tags = List.of();
        private Map<CoseLabel, DataItem> protectedHeaders = new LinkedHashMap<>();
        private Map<CoseLabel, DataItem> unprotectedHeaders = new LinkedHashMap<>();
        private byte[] payload;
        private boolean detached;
        private byte[] signature;
        /** The unwrapped COSE_Sign1 array as received, for the Authlete oracle (whose decoder auto-parses tags). */
        private DataItem coseArray;
        private DataItem claims;
        /** The chain the token actually carries: the protected one ISO2 12.3.6.3 requires, else the unprotected one. */
        private List<X509Certificate> chain = List.of();
        private boolean chainInProtected;
        private boolean chainInUnprotected;

        private Token(byte[] body) {
            this.body = body;
        }

        static Token parse(byte[] body) {
            Token token = new Token(body);
            DataItem item;
            try {
                item = Cbor.INSTANCE.decode(body);
            } catch (Throwable e) {
                token.parseError = "the body is not CBOR: " + describe(e);
                return token;
            }
            try {
                List<Long> tags = new ArrayList<>();
                while (item.getMajorType() == MajorType.TAG) {
                    tags.add(((Tagged) item).getTagNumber());
                    item = item.getAsTagged();
                }
                token.tags = List.copyOf(tags);
                if (item.getMajorType() != MajorType.ARRAY || item.getAsArray().size() != 4) {
                    token.parseError = "the body is not a COSE_Sign1 array(4): it is " + item.getMajorType();
                    return token;
                }
                List<DataItem> array = item.getAsArray();
                token.coseArray = item;
                // Multipaz's decoder already kept one value per key (the last); the wire is read again, before any
                // header or claim is looked at, so a key sent twice is refused instead of resolved by that choice.
                String duplicates = DuplicateKeys.find(body);
                if (duplicates != null) {
                    token.duplicateKeys = duplicates;
                    token.detached = array.get(2).getMajorType() == MajorType.SPECIAL;
                    return token;
                }
                if (array.get(0).getMajorType() != MajorType.BYTE_STRING) {
                    token.parseError = "the COSE_Sign1 protected header is not a bstr";
                    return token;
                }
                DataItem protectedItem = Cbor.INSTANCE.decode(array.get(0).getAsBstr());
                if (protectedItem.getMajorType() != MajorType.MAP) {
                    token.parseError = "the COSE_Sign1 protected header is not a CBOR map";
                    return token;
                }
                token.protectedHeaders = coseLabels(protectedItem.getAsMap());
                if (array.get(1).getMajorType() != MajorType.MAP) {
                    token.parseError = "the COSE_Sign1 unprotected header is not a CBOR map";
                    return token;
                }
                token.unprotectedHeaders = coseLabels(array.get(1).getAsMap());
                DataItem payloadItem = array.get(2);
                if (payloadItem.getMajorType() == MajorType.SPECIAL) {
                    // RFC 9052 4.2: a nil payload carries the content out of band, which a downloaded list never does
                    token.detached = true;
                } else if (payloadItem.getMajorType() == MajorType.BYTE_STRING) {
                    token.payload = payloadItem.getAsBstr();
                } else {
                    token.parseError = "the COSE_Sign1 payload is neither a bstr nor null (detached)";
                    return token;
                }
                if (array.get(3).getMajorType() != MajorType.BYTE_STRING) {
                    token.parseError = "the COSE_Sign1 signature is not a bstr";
                    return token;
                }
                token.signature = array.get(3).getAsBstr();
                if (token.payload != null) {
                    DataItem decoded = Cbor.INSTANCE.decode(token.payload);
                    if (decoded.getMajorType() != MajorType.MAP) {
                        token.parseError = "the CWT payload is not a CBOR map (TSL 5.2)";
                        return token;
                    }
                    token.claims = decoded;
                }
                token.chainInProtected = token.protectedHeaders.containsKey(label(LABEL_X5CHAIN));
                token.chainInUnprotected = token.unprotectedHeaders.containsKey(label(LABEL_X5CHAIN));
                if (token.chainInProtected) {
                    token.chain = certificates(token.protectedHeaders.get(label(LABEL_X5CHAIN)));
                } else if (token.chainInUnprotected) {
                    token.chain = certificates(token.unprotectedHeaders.get(label(LABEL_X5CHAIN)));
                }
            } catch (Throwable e) {
                if (e instanceof VirtualMachineError fatal && !(e instanceof StackOverflowError)) {
                    throw fatal;
                }
                token.parseError = "the body is not a readable COSE status-list token: " + describe(e);
            }
            return token;
        }

        /** Check 1: tag 18 around a COSE_Sign1, never CWT tag 61, no MAC0, no detached payload (TSL 5.2). */
        String envelope(Problems problems) {
            if (parseError != null) {
                problems.add("notTagged18", "not a status-list CWT: " + parseError);
                return null;
            }
            if (duplicateKeys != null) {
                problems.add("duplicateKey", duplicateKeys + "; RFC 8949 5.3.1 makes a map with a key twice invalid "
                        + "CBOR whose decoders keep one value or the other (Multipaz keeps the last, Authlete both), "
                        + "RFC 9052 3: \"if a label appears multiple times, the message MUST be rejected as "
                        + "malformed\", and RFC 8392 7.2 steps 1 and 7 reject a CWT that is not valid CBOR or whose "
                        + "claims are not a valid CBOR map — so no claim or header of this token is read");
            }
            if (tags.isEmpty()) {
                problems.add("notTagged18", "the COSE_Sign1 is untagged; TSL 5.2 requires COSE_Sign1_Tagged (18) "
                        + "(RFC 9052 4.2), never the bare COSE_Sign1");
            } else if (tags.contains(TAG_CWT)) {
                problems.add("cwtTag61", "the token is tagged " + tags + "; TSL 5.2: \"The Status List Token MUST NOT be "
                        + "tagged with the CWT tag defined in Section 6 of [RFC8392]\" (the COSE message is tag 18)");
            } else if (tags.size() != 1) {
                problems.add("notTagged18", "the token carries the tag stack " + tags + "; exactly one tag, 18, wraps the "
                        + "COSE_Sign1 (RFC 9052 4.2). A second tag — the self-describe tag 55799 (RFC 8949 3.4.6) or a "
                        + "repeated 18 — is refused: @owf/cose 0.6.0's Cwt.decodeCoseStructure requires the decoded "
                        + "value to be the tag-18 Sign1 or tag-17 Mac0 itself, so Paradym/Credo refuse it too");
            } else if (tags.get(0) == TAG_COSE_MAC0) {
                problems.add("mac0", "the COSE message is tag 17 (COSE_Mac0_Tagged); the status list is signed, so TSL 5.2 "
                        + "requires COSE_Sign1_Tagged (18)");
            } else if (tags.get(0) != TAG_COSE_SIGN1) {
                problems.add("notTagged18", "the token is tagged " + tags.get(0) + ", not 18 (RFC 9052 4.2)");
            }
            if (detached) {
                problems.add("detachedPayload", "the COSE_Sign1 payload is detached (null); a status list is a CWT whose "
                        + "claims are integrity protected by the signature (TSL 5.2, RFC 9052 4.2), so a verifier that "
                        + "downloads the token has nothing to read");
            }
            return "tag 18 around a COSE_Sign1 with an attached payload";
        }

        /** Check 2: protected header 16 is a tstr equal to the media type (TSL 5.2, RFC 9596 2). */
        String typ(Problems problems) {
            if (notRun(problems)) {
                return null;
            }
            DataItem protectedTyp = protectedHeaders.get(label(LABEL_TYP));
            DataItem unprotectedTyp = unprotectedHeaders.get(label(LABEL_TYP));
            if (protectedTyp == null) {
                if (unprotectedTyp != null) {
                    problems.add("unprotected", "typ is in the unprotected header; TSL 5.2 makes the type a protected "
                            + "header, so a wallet cannot rely on it being signed");
                } else {
                    problems.add("missing", "the protected header has no typ (label 16); TSL 5.2: \"The type of the CWT "
                            + "MUST be application/statuslist+cwt\"");
                }
                return null;
            }
            if (protectedTyp.getMajorType() != MajorType.UNICODE_STRING) {
                problems.add("notText", "typ is " + shortly(protectedTyp) + ", not a tstr (RFC 9596 2 allows a tstr media "
                        + "type or a uint Content-Format; the CoAP id is still TBD, TSL 14.8)");
                return null;
            }
            if (!MEDIA_TYPE.equals(protectedTyp.getAsTstr())) {
                problems.add("wrong", "typ is \"" + protectedTyp.getAsTstr() + "\", not \"" + MEDIA_TYPE + "\" (TSL 5.2)");
            }
            return "protected typ is " + MEDIA_TYPE;
        }

        /**
         * Check 3: {@code x5chain} in the protected header, no self-signed certificate in it, every serial positive and
         * at most 20 octets (ISO/IEC 18013-5 second edition 12.3.6.3; HAIP 6.1 analogue; RFC 5280 4.1.2.2).
         */
        String x5chain(Problems problems) {
            if (notRun(problems)) {
                return null;
            }
            if (!chainInProtected) {
                if (chainInUnprotected) {
                    problems.add("unprotectedOnly", "x5chain is only in the unprotected header; ISO/IEC 18013-5 second "
                            + "edition 12.3.6.3: \"The CWT shall contain the x5chain in the protected header that "
                            + "contains the certificate or chain of certificates used to verify the signature\" "
                            + "(isomdl refuses it there; RFC 9360 makes an unprotected x5chain usable only behind a "
                            + "protected x5t/kid binding)");
                } else {
                    problems.add("missing", "the token carries no x5chain (COSE label 33); ISO/IEC 18013-5 second "
                            + "edition 12.3.6.3 requires it in the protected header");
                    return null;
                }
            }
            int index = 0;
            for (X509Certificate certificate : chain) {
                String at = "x5chain certificate " + index + " (" + certificate.getSubjectX500Principal() + ")";
                if (selfSigned(certificate)) {
                    problems.add("carriesAnchor", at + " is self-signed; the list's chain carries the signer, not the "
                            + "trust anchor (ISO/IEC 18013-5 second edition 12.3.6.2 trusts the IACA; HAIP 6.1: \"The "
                            + "X.509 certificate of the trust anchor MUST NOT be included\")");
                }
                BigInteger serial = certificate.getSerialNumber();
                int octets = serial.toByteArray().length;
                if (serial.signum() <= 0 || octets > MAX_SERIAL_OCTETS) {
                    problems.add("serialNumber", at + " has the serial " + serial + " (" + octets + " octets); RFC 5280 "
                            + "4.1.2.2 requires a positive serial of at most 20 octets");
                }
                index++;
            }
            return "protected x5chain of " + chain.size() + " certificate(s) without an anchor";
        }

        /** Check 4: the COSE_Sign1 signature, by Multipaz and by Authlete (TSL 5.2 rule 2). */
        String signature(Problems problems, boolean envelopeFailed) throws Exception {
            if (notRun(problems)) {
                return null;
            }
            if (detached) {
                skip("the payload is detached, so there is nothing to verify the signature over");
            }
            if (chain.isEmpty()) {
                problems.add(NOT_RUN, "not run: the token carries no x5chain, so there is no signer to verify against "
                        + "(reported by " + CHECK_X5CHAIN + ")");
                return null;
            }
            X509Certificate leaf = chain.get(0);
            signatureWithMultipaz(problems, leaf);
            signatureWithAuthlete(problems, leaf, envelopeFailed);
            return "verified with Multipaz and Authlete against " + leaf.getSubjectX500Principal();
        }

        private void signatureWithMultipaz(Problems problems, X509Certificate leaf) {
            DataItem algItem = protectedHeaders.get(label(LABEL_ALG));
            if (algItem == null || (algItem.getMajorType() != MajorType.UNSIGNED_INTEGER
                    && algItem.getMajorType() != MajorType.NEGATIVE_INTEGER)) {
                problems.add("invalid:multipaz", "the protected header has no integer alg (label 1), so Multipaz cannot "
                        + "check the signature");
                return;
            }
            Algorithm algorithm;
            try {
                algorithm = Algorithm.Companion.fromCoseAlgorithmIdentifier((int) algItem.getAsNumber());
            } catch (RuntimeException e) {
                algorithm = Algorithm.UNSET;
            }
            if (algorithm == Algorithm.UNSET) {
                problems.add("invalid:multipaz", "Multipaz does not support the COSE alg " + shortly(algItem));
                return;
            }
            CoseSign1 sign1 = new CoseSign1(protectedHeaders, unprotectedHeaders, signature, payload);
            Algorithm checked = algorithm;
            try {
                await(continuation -> Cose.INSTANCE.coseSign1Check(multipazCertificate(leaf).getPublicKey(), null, sign1,
                        checked, continuation));
            } catch (Throwable e) {
                rethrowIfFatal(e);
                problems.add("invalid:multipaz", "Multipaz coseSign1Check rejects the signature: " + describe(e));
            }
        }

        private void signatureWithAuthlete(Problems problems, X509Certificate leaf, boolean envelopeFailed)
                throws Exception {
            // The wire bytes are what Authlete gets: its decoder reads tag 18, tag 61(18) and 55799(18(...)) itself.
            // Only a tag stack whose envelope check already failed (18(18(...))) defeats that decoder, and only then
            // is the unwrapped array handed over instead — the signed protected/payload/signature bstr contents are
            // the received ones either way.
            CBORItem item;
            try {
                item = new CBORDecoder(body).next();
            } catch (Exception e) {
                if (!envelopeFailed) {
                    problems.add("invalid:authlete", "Authlete cannot decode the body: " + describe(e));
                    return;
                }
                try {
                    item = new CBORDecoder(Cbor.INSTANCE.encode(coseArray)).next();
                } catch (Exception fallback) {
                    problems.add("invalid:authlete", "Authlete cannot decode the COSE_Sign1 array: "
                            + describe(fallback));
                    return;
                }
            }
            while (item instanceof CBORTaggedItem tagged) {
                item = tagged.getTagContent();
            }
            COSESign1 coseSign1;
            try {
                coseSign1 = item instanceof COSESign1 parsed ? parsed : COSESign1.build(item);
            } catch (Exception e) {
                problems.add("invalid:authlete", "Authlete cannot read the body as COSE_Sign1: " + describe(e));
                return;
            }
            boolean valid;
            try {
                valid = new COSEVerifier(leaf.getPublicKey()).verify(coseSign1);
            } catch (Exception e) {
                problems.add("invalid:authlete", "Authlete COSEVerifier fails: " + describe(e));
                return;
            }
            if (!valid) {
                problems.add("invalid:authlete", "Authlete COSEVerifier rejects the signature");
            }
        }

        /**
         * Check 5: the token's chain reaches the IACA, decided by the very Multipaz validator
         * {@code CompressedStatusList.fromCwt} passes to {@code validateCwt} (ISO/IEC 18013-5 second edition 12.3.6.2).
         */
        String chain(Problems problems, X509Certificate iaca, Instant at, String uri, StatusListOptions options,
                     boolean fromCwtRefusalExplained) {
            if (notRun(problems)) {
                return null;
            }
            if (iaca == null) {
                if (!options.strict()) {
                    skip("no IACA supplied: the chain-to-anchor decision cannot be made");
                }
                problems.add("noAnchorSupplied", "no IACA supplied: ISO/IEC 18013-5 second edition 12.3.6.2 makes the "
                        + "IACA the trust point when the MSO names no status_list.certificate (D-M11-10)");
                return null;
            }
            if (chain.isEmpty()) {
                problems.add(NOT_RUN, "not run: the token carries no x5chain (" + CHECK_X5CHAIN + ")");
                return null;
            }
            X509Cert anchor = multipazCertificate(iaca);
            // The gate: Multipaz's own reader, as CachingRevocationChecker calls it (typ, sub, exp, maxValidity, the
            // chain to the IACA and the signature in one decision). It is the only check that refuses an exp more than
            // 365 days after `at`, so a chain-validator-only verifier would accept a list Multipaz's wallet refuses.
            Throwable fromCwtRefusal = null;
            try {
                MultipazFromCwt.read(body, anchor, uri, at);
            } catch (MultipazAdapterException e) {
                // a broken adapter or pinned jar is a harness defect, never the credential's: non-declarable, as ERROR
                problems.add(ERROR, e.getMessage());
                return null;
            } catch (LinkageError e) {
                problems.add(ERROR, "Multipaz cannot be linked for CompressedStatusList.fromCwt: " + describe(e));
                return null;
            } catch (Throwable e) {
                rethrowIfFatal(e);
                fromCwtRefusal = e;
            }
            // The trust decision on its own, so a fromCwt refusal caused by a field another check reports (typ, sub,
            // exp, iat) is not also charged to the chain.
            String chainRefusal = null;
            Function3<X509CertChain, kotlin.time.Instant, Continuation<? super Boolean>, Object> validator =
                    ValidateJwtKt.trustedRootCertificateChainValidator(anchor);
            try {
                await(continuation -> validator.invoke(multipazChain(chain), kotlinInstant(at), continuation));
            } catch (Throwable e) {
                rethrowIfFatal(e);
                chainRefusal = describe(e);
            }
            if (fromCwtRefusal == null) {
                return "CompressedStatusList.fromCwt accepts the token against " + iaca.getSubjectX500Principal() + " at "
                        + at + " (typ, sub, exp and maxValidity included)";
            }
            String fromCwtReason = "CompressedStatusList.fromCwt refuses the token: " + describe(fromCwtRefusal);
            if (chainRefusal != null) {
                problems.add("untrusted", fromCwtReason + "; and Multipaz's certificate-chain validator refuses the "
                        + "x5chain at " + at + ": " + chainRefusal);
                return null;
            }
            if (fromCwtRefusalExplained) {
                return "the x5chain validates to " + iaca.getSubjectX500Principal() + "; fromCwt refused for a reason one "
                        + "of the checks it also makes already reports (" + describe(fromCwtRefusal) + ")";
            }
            if (beyondMaxValidity(at)) {
                problems.add("untrusted", fromCwtReason + ": maxValidity — exp " + numericDate(numeric(claims, CLAIM_EXP))
                        + " is more than 365 days after " + at + ", the wallet default in CachingRevocationChecker, and "
                        + "validateCwt refuses that before it looks at typ, sub, the signature or the list, so this is "
                        + "the reason whatever else is reported; the chain itself validates to "
                        + iaca.getSubjectX500Principal());
                return null;
            }
            problems.add("untrusted", fromCwtReason + ", and no defect fromCwt refuses on is reported by another check: "
                    + "the refusal comes from a rule no check names; the chain itself validates to "
                    + iaca.getSubjectX500Principal());
            return null;
        }

        /**
         * Check 6: the token's {@code x5chain} equals the mDL's IssuerAuth {@code x5chain}, certificate for
         * certificate — Credo's {@code assertMdocStatusListChainsMatchIssuanceChain}, which Paradym applies because it
         * trusts the presented top certificate (Credo {@code mdocUtil.ts:76-115}).
         */
        String issuanceChain(Problems problems, List<X509Certificate> issuerAuthX5chain, StatusListOptions options) {
            if (notRun(problems)) {
                return null;
            }
            if (!options.requireIssuanceChain()) {
                skip("the caller does not require the list's chain to equal the mDL's issuance chain (dedicated status "
                        + "signer, D-M11-1 (b)/(c))");
            }
            if (!equalsCertificateForCertificate(chain, issuerAuthX5chain)) {
                problems.add("differs", "the list's x5chain " + describeChain(chain) + " is not the mDL's IssuerAuth x5chain "
                        + describeChain(issuerAuthX5chain) + "; Credo's assertMdocStatusListChainsMatchIssuanceChain refuses "
                        + "a list whose validated chain differs from the credential's issuance chain when no dedicated "
                        + "status certificate is configured, which is Paradym's configuration (mdocUtil.ts:76-115)");
            }
            return "the list's x5chain equals the mDL's IssuerAuth x5chain";
        }

        /** Check 7: {@code sub}, {@code iat}, {@code exp} and {@code ttl} (TSL 5.2, 8.3 steps 4a/4c; ISO2 12.3.6.3). */
        String claims(Problems problems, String uri, Instant at) {
            if (notRun(problems)) {
                return null;
            }
            if (claims == null) {
                problems.add(NOT_RUN, "not run: the payload is detached, so there are no claims to read");
                return null;
            }
            DataItem sub = claims.getOrNull(CLAIM_SUB);
            String subValue = sub != null && sub.getMajorType() == MajorType.UNICODE_STRING ? sub.getAsTstr() : null;
            if (subValue == null) {
                problems.add("subMismatch", "the CWT has no tstr sub (claim 2); TSL 5.2 makes it REQUIRED and TSL 8.3 "
                        + "step 4a compares it with the uri of the Referenced Token (expected \"" + uri + "\")");
            } else if (!subValue.equals(uri)) {
                problems.add("subMismatch", "sub is \"" + subValue + "\" but the mDL's status_list.uri is \"" + uri
                        + "\"; TSL 8.3 step 4a: \"The subject claim (sub or 2) ... MUST be equal to the uri claim\"");
            }
            Long iat = numeric(claims, CLAIM_IAT);
            if (iat == null) {
                problems.add("iatMissing", "the CWT has no integer iat (claim 6); TSL 5.2 makes it REQUIRED");
            } else if (iat > at.getEpochSecond() + IAT_FUTURE_SKEW_SECONDS) {
                problems.add("iatFuture", "iat is " + Instant.ofEpochSecond(iat) + ", more than "
                        + IAT_FUTURE_SKEW_SECONDS + "s after " + at + "; Multipaz's validateCwt and this verifier "
                        + "allow five seconds of clock mismatch, so the wallet reads the list as not yet issued");
            }
            Long exp = numeric(claims, CLAIM_EXP);
            if (exp == null) {
                problems.add("expMissing", "the CWT has no integer exp (claim 4); ISO/IEC 18013-5 second edition 12.3.6.3: "
                        + "\"The exp claim shall be present.\" (TSL 5.2 only RECOMMENDS it; an mdoc list always has one)");
            } else {
                // at >= exp at full precision: exp is whole seconds and getEpochSecond() floors, so for an exp of S
                // the token is expired from S.000000000 on, and at S - 1 ns it is not
                if (exp <= at.getEpochSecond()) {
                    problems.add("expired", "exp is " + numericDate(exp) + ", and " + at + " is not before it; TSL 5.2 "
                            + "takes exp from RFC 8392 3.1.4, whose RFC 7519 4.1.4 rule is that \"the current date/time "
                            + "MUST be before the expiration date/time\" (the token is not accepted on or after exp), and "
                            + "TSL 8.3 step 4c checks it. Multipaz 0.102.0's validateCwt refuses only exp < now, so exactly "
                            + "at exp this check alone refuses");
                }
                X509Certificate leaf = chain.isEmpty() ? null : chain.get(0);
                if (leaf != null && exp > leaf.getNotAfter().toInstant().getEpochSecond()) {
                    problems.add("expAfterSigner", "exp is " + Instant.ofEpochSecond(exp) + ", after the signer's notAfter "
                            + leaf.getNotAfter().toInstant() + "; a list must not outlive the certificate that signs it");
                }
                if (iat != null && iat > exp) {
                    problems.add("iatAfterExp", "iat is " + Instant.ofEpochSecond(iat) + ", after exp "
                            + Instant.ofEpochSecond(exp) + "; TSL 8.3 step 4c reads exp as the end of the list's validity, "
                            + "so a list issued after it expires was never valid");
                }
            }
            DataItem ttlItem = claims.getOrNull(CLAIM_TTL);
            if (ttlItem != null) {
                if (ttlItem.getMajorType() != MajorType.UNSIGNED_INTEGER || ttlItem.getAsNumber() <= 0) {
                    problems.add("ttlInvalid", "ttl (claim 65534) is " + shortly(ttlItem) + "; TSL 5.2 makes it an unsigned "
                            + "integer, and a zero or negative time to live makes the list stale on arrival");
                }
            }
            return "sub, iat, exp and ttl are the values the specifications require";
        }

        /** Check 8: {@code bits} = 1, a zlib {@code lst}, the index in range, the status the caller expects (TSL 4.1/8.3). */
        String list(Problems problems, long idx, int expectedStatus) {
            if (notRun(problems)) {
                return null;
            }
            if (claims == null) {
                problems.add(NOT_RUN, "not run: the payload is detached, so there is no status_list claim");
                return null;
            }
            DataItem statusListClaim = claims.getOrNull(CLAIM_STATUS_LIST);
            if (statusListClaim == null) {
                problems.add("missing", "the CWT has no status_list claim (65533); TSL 5.2 makes it REQUIRED, so the "
                        + "status of idx " + idx + " cannot be read");
                return null;
            }
            if (statusListClaim.getMajorType() != MajorType.MAP) {
                problems.add("missing", "status_list (65533) is " + shortly(statusListClaim) + ", not the map TSL 4.3 "
                        + "defines ({bits, lst}); the status of idx " + idx + " cannot be read");
                return null;
            }
            DataItem bitsItem = statusListClaim.getOrNull("bits");
            if (bitsItem == null || bitsItem.getMajorType() != MajorType.UNSIGNED_INTEGER || bitsItem.getAsNumber() != 1) {
                problems.add("bitsNotOne", "status_list.bits is " + (bitsItem == null ? "missing" : shortly(bitsItem))
                        + "; ISO/IEC 18013-5 second edition 12.3.6.5: \"bits shall be 1\" for an mdoc status list");
                return null;
            }
            DataItem lstItem = statusListClaim.getOrNull("lst");
            if (lstItem == null || lstItem.getMajorType() != MajorType.BYTE_STRING) {
                problems.add("lstNotZlib", "status_list.lst is " + (lstItem == null ? "missing" : shortly(lstItem))
                        + "; TSL 4.3 makes it a bstr holding the zlib-compressed status values");
                return null;
            }
            byte[] statuses;
            try {
                statuses = await(continuation -> CompressionKt.zlibInflate(lstItem.getAsBstr(), continuation));
            } catch (Throwable e) {
                rethrowIfFatal(e);
                problems.add("lstNotZlib", "status_list.lst does not zlib-inflate (TSL 4.3): " + describe(e));
                return null;
            }
            if (idx < 0 || idx / 8 >= statuses.length) {
                problems.add("idxOutOfRange", "idx " + idx + " is outside the list of " + statuses.length + " octets ("
                        + statuses.length * 8L + " statuses); TSL 8.3 step 6: \"If the index ... is out of bounds ... it "
                        + "MUST be rejected\"");
                return null;
            }
            // Multipaz's own reader, so the bit order is the reference implementation's (TSL 4.1: least significant
            // bit first). The range check above stays ours: StatusList.get answers 0 for an index past the end, which
            // TSL 8.3 step 6 requires to be rejected instead.
            int status = new StatusList(1, statuses).get((int) idx);
            if (status != expectedStatus) {
                problems.add("statusMismatch:" + status, "idx " + idx + " reports " + status + ", expected "
                        + expectedStatus + " (TSL 7.1: 0 VALID, 1 INVALID)");
            }
            return "bits 1, a zlib lst of " + statuses.length + " octets and status " + status + " at idx " + idx;
        }

        /**
         * Whether {@code CompressedStatusList.fromCwt} refuses this token for a defect one of our checks reports, read
         * from the token's own state rather than from check names, and in the order Multipaz itself decides. Verified
         * against the Multipaz 0.102.0 bytecode:
         * <ul>
         *     <li>{@code ValidateCwtKt.validateCwt-efNRYWU} first decodes the body, unwraps at most one tag 18 (an
         *     untagged COSE_Sign1 and exactly {@code [18]} are accepted; a second tag, or any other tag, fails
         *     {@code getAsCoseSign1}) and decodes the payload as a map — so a parse failure, a detached payload and
         *     such a tag stack explain a refusal, never an untagged token. A duplicate key is not one of its refusals
         *     (its decoder keeps the last value), but such a token never gets here: the chain check is notRun;</li>
         *     <li>it then reads {@code exp} ({@code WebTokenClaim.get}): a present non-integer {@code exp} refuses;
         *     {@code exp} present refuses when it is before now ({@code exp == now} is accepted, so {@code expired} at
         *     exactly {@code exp} explains nothing) and, <b>before typ, sub, the signature or the list are looked at</b>,
         *     when it is more than {@code maxValidity} (365 days) after now — no check of ours names that, so it is
         *     decided here, and a token past it is never explained by anything checked later; {@code exp} absent reads
         *     {@code iat} ({@code "either 'exp' or 'iat' is required"}, {@code "'iat' is in future"} beyond 5 s) and
         *     derives {@code exp} from it, which cannot exceed maxValidity;</li>
         *     <li>its {@code checks} map carries TYP and SUB, and it verifies the COSE signature — so any
         *     {@code statusList.typ}, {@code statusList.signature} or {@code subMismatch} failure explains one;</li>
         *     <li>{@code CompressedStatusList$Companion.fromCborMap} reads {@code ttl} only in its exp-absent branch
         *     ({@code ttl.asNumber}), so a non-integer {@code ttl} refuses only without {@code exp};</li>
         *     <li>{@code fromCborMap} requires the {@code status_list} key, {@code fromStatusListClaim} requires
         *     {@code lst} a {@code Bstr} (it never inflates it) and {@code bits} a {@code Uint} narrowed to an
         *     {@code int} ({@code l2i}), and the {@code CompressedStatusList} constructor requires that int in 1, 2, 4,
         *     8 — so {@code list:missing}, a missing/non-uint {@code bits} or one whose low 32 bits are not 1, 2, 4 or 8
         *     ({@code bitsNotOne} for 2, 4, 8 or 4294967297 is accepted) and a missing/non-bstr {@code lst}
         *     ({@code lstNotZlib} for a garbage bstr is not) explain one.</li>
         * </ul>
         * Times are compared as {@code fromCwt} receives them: {@code at} at millisecond precision.
         */
        boolean fromCwtRefusesOnAReportedDefect(String uri, Instant at, VerificationReport.Check typ,
                                                VerificationReport.Check signature) {
            if (parseError != null || duplicateKeys != null || detached) {
                return true; // duplicateKeys: unreachable from verify(), whose chain check is notRun for such a token
            }
            if (!tags.isEmpty() && !tags.equals(List.of(TAG_COSE_SIGN1))) {
                return true;
            }
            if (claims == null) {
                return false;
            }
            long now = at.toEpochMilli();
            DataItem expItem = claims.getOrNull(CLAIM_EXP);
            if (expItem != null) {
                if (!isInteger(expItem)) {
                    return true;
                }
                if (compareSecondsWithMillis(expItem.getAsNumber(), now) < 0) {
                    return true;
                }
                if (beyondMaxValidity(at)) {
                    // refused here, before every check below: whatever else is reported, maxValidity is the reason
                    return false;
                }
            } else {
                DataItem iatItem = claims.getOrNull(CLAIM_IAT);
                if (!isInteger(iatItem)
                        || compareSecondsWithMillis(iatItem.getAsNumber(), now + IAT_FUTURE_SKEW_SECONDS * 1000) > 0) {
                    return true;
                }
            }
            if (!typ.passed() || !signature.passed()) {
                return true;
            }
            DataItem sub = claims.getOrNull(CLAIM_SUB);
            if (sub == null || sub.getMajorType() != MajorType.UNICODE_STRING || !sub.getAsTstr().equals(uri)) {
                return true;
            }
            if (expItem == null) {
                DataItem ttlItem = claims.getOrNull(CLAIM_TTL);
                if (ttlItem != null && !isInteger(ttlItem)) {
                    return true;
                }
            }
            DataItem statusList = claims.getOrNull(CLAIM_STATUS_LIST);
            if (statusList == null || statusList.getMajorType() != MajorType.MAP) {
                return true;
            }
            DataItem lst = statusList.getOrNull("lst");
            if (lst == null || lst.getMajorType() != MajorType.BYTE_STRING) {
                return true;
            }
            DataItem bits = statusList.getOrNull("bits");
            return bits == null || bits.getMajorType() != MajorType.UNSIGNED_INTEGER
                    || !FROM_CWT_BITS.contains((int) bits.getAsNumber());
        }

        /**
         * {@code validateCwt}'s maxValidity refusal: an integer {@code exp} more than 365 days after {@code at}, the
         * {@code CachingRevocationChecker} default, compared as {@code fromCwt} receives {@code at} (milliseconds).
         */
        boolean beyondMaxValidity(Instant at) {
            DataItem expItem = claims == null ? null : claims.getOrNull(CLAIM_EXP);
            return isInteger(expItem)
                    && compareSecondsWithMillis(expItem.getAsNumber(), at.toEpochMilli() + MAX_VALIDITY_SECONDS * 1000) > 0;
        }

        /**
         * Check 9: a list signed by a key other than the mDL's Document Signer needs the status-signing EKU and key
         * usage digitalSignature (Credo {@code assertStatusListSignerKeyPurpose.ts:14-25}, off by default there).
         */
        String signerPurpose(Problems problems, List<X509Certificate> issuerAuthX5chain) {
            if (notRun(problems)) {
                return null;
            }
            if (issuerAuthX5chain.isEmpty()) {
                skip("no IssuerAuth x5chain supplied, so there is no credential key to compare the signer with");
            }
            if (chain.isEmpty()) {
                problems.add(NOT_RUN, "not run: the token carries no x5chain (" + CHECK_X5CHAIN + ")");
                return null;
            }
            X509Certificate leaf = chain.get(0);
            if (leaf.getPublicKey().equals(issuerAuthX5chain.get(0).getPublicKey())) {
                return "the list is signed with the mDL's own Document Signer key, which TSL 11.3 allows without a "
                        + "separate purpose";
            }
            List<String> eku;
            try {
                eku = leaf.getExtendedKeyUsage();
            } catch (CertificateException e) {
                problems.add("ekuMissing", "the signer's extendedKeyUsage cannot be read: " + describe(e));
                return null;
            }
            if (eku == null || !eku.contains(STATUS_SIGNING_EKU)) {
                problems.add("ekuMissing", "the signer " + leaf.getSubjectX500Principal() + " is not the mDL's Document "
                        + "Signer and its extendedKeyUsage " + (eku == null ? "is absent" : "is " + eku) + " does not contain "
                        + STATUS_SIGNING_EKU + " (id-kp-oauthStatusSigning, TSL 10; Credo requires it unless the list key "
                        + "is the credential key)");
            }
            boolean[] keyUsage = leaf.getKeyUsage();
            if (keyUsage == null || keyUsage.length == 0 || !keyUsage[0]) {
                problems.add("kuMissing", "the signer " + leaf.getSubjectX500Principal() + " is not the mDL's Document "
                        + "Signer and its keyUsage does not assert digitalSignature, which Credo requires of a dedicated "
                        + "status signer");
            }
            return "the dedicated signer carries " + STATUS_SIGNING_EKU + " and digitalSignature";
        }

        /**
         * Reports notRun when the body did not parse or a map in it carries a key twice, and answers true so the
         * caller returns.
         */
        private boolean notRun(Problems problems) {
            if (parseError == null && duplicateKeys == null) {
                return false;
            }
            problems.add(NOT_RUN, "not run: " + (parseError != null ? parseError
                    : duplicateKeys + ", so the token is malformed and none of its maps is read") + " (reported by "
                    + CHECK_ENVELOPE + ")");
            return true;
        }
    }

    // ---- Multipaz / Authlete plumbing ---------------------------------------------------------------------------

    /** The problems one check found, by code, in the order found; the same code twice keeps both messages. */
    private static final class Problems {

        private final String check;
        private final Map<String, String> found = new LinkedHashMap<>();

        Problems(String check) {
            this.check = check;
        }

        void add(String code, String message) {
            if (!IndependentStatusListVerifier.ERROR.equals(code)
                    && !IndependentStatusListVerifier.NOT_RUN.equals(code)
                    && !isProblemCode(check, code)) {
                throw new IllegalStateException("the harness reports the unregistered problem code " + check + ":" + code
                        + "; add it to IndependentStatusListVerifier.PROBLEM_CODES");
            }
            found.merge(code, message, (a, b) -> a.equals(b) ? a : a + "; " + b);
        }

        boolean isEmpty() {
            return found.isEmpty();
        }

        List<VerificationReport.Problem> list() {
            return found.entrySet().stream().map(e -> new VerificationReport.Problem(e.getKey(), e.getValue())).toList();
        }
    }

    @FunctionalInterface
    private interface Probe {
        /** Adds every problem it finds to {@code problems} and returns what it verified when there is none. */
        String run(Problems problems) throws Exception;
    }

    /** A check that was not run because an input the caller did not supply is needed; never a pass. */
    private static final class Skipped extends RuntimeException {
        Skipped(String message) {
            super(message, null, false, false);
        }
    }

    private static String skip(String message) {
        throw new Skipped(message);
    }

    /** Runs one check; anything it throws is that check's {@code error} problem, Errors included (StackOverflowError). */
    static VerificationReport.Check run(String name, Probe probe) {
        Problems problems = new Problems(name);
        String message = null;
        try {
            message = probe.run(problems);
        } catch (Skipped e) {
            return VerificationReport.Check.skipped(name, e.getMessage());
        } catch (Throwable e) {
            rethrowIfFatal(e);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            problems.add(ERROR, describe(e));
        }
        return problems.isEmpty() ? VerificationReport.Check.pass(name, message)
                : VerificationReport.Check.fail(name, problems.list());
    }

    /** {@code OutOfMemoryError}, {@code InternalError}, {@code UnknownError}: nothing sensible is left to report. */
    private static void rethrowIfFatal(Throwable e) {
        if (e instanceof VirtualMachineError fatal && !(e instanceof StackOverflowError)) {
            throw fatal;
        }
    }

    private static String describe(Throwable e) {
        return e.getMessage() == null ? e.getClass().getName() : e.getClass().getSimpleName() + ": " + e.getMessage();
    }

    private static CoseNumberLabel label(long number) {
        return new CoseNumberLabel(number);
    }

    private static Map<CoseLabel, DataItem> coseLabels(Map<DataItem, DataItem> headers) {
        Map<CoseLabel, DataItem> labels = new LinkedHashMap<>();
        for (Map.Entry<DataItem, DataItem> header : headers.entrySet()) {
            labels.put(header.getKey().getAsCoseLabel(), header.getValue());
        }
        return labels;
    }

    private static List<X509Certificate> certificates(DataItem x5chain) {
        X509CertChain chain = X509CertChain.Companion.fromDataItem(x5chain);
        return X509CertChainJvmKt.getJavaX509Certificates(chain);
    }

    private static X509CertChain multipazChain(List<X509Certificate> certificates) {
        return X509CertChainJvmKt.fromJavaX509Certificates(X509CertChain.Companion, certificates);
    }

    private static X509Cert multipazCertificate(X509Certificate certificate) {
        return multipazChain(List.of(certificate)).getCertificates().get(0);
    }

    private static boolean selfSigned(X509Certificate certificate) {
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean equalsCertificateForCertificate(List<X509Certificate> left, List<X509Certificate> right) {
        if (left.size() != right.size()) {
            return false;
        }
        for (int i = 0; i < left.size(); i++) {
            try {
                if (!java.util.Arrays.equals(left.get(i).getEncoded(), right.get(i).getEncoded())) {
                    return false;
                }
            } catch (CertificateException e) {
                return false;
            }
        }
        return true;
    }

    private static String describeChain(List<X509Certificate> chain) {
        if (chain.isEmpty()) {
            return "[]";
        }
        List<String> subjects = chain.stream().map(c -> c.getSubjectX500Principal().getName()).toList();
        return subjects.toString();
    }

    /** An integer claim read as a NumericDate from the unsigned (or, for a malformed token, signed) integer. */
    private static Long numeric(DataItem claims, long claim) {
        DataItem item = claims.getOrNull(claim);
        if (item == null || (item.getMajorType() != MajorType.UNSIGNED_INTEGER
                && item.getMajorType() != MajorType.NEGATIVE_INTEGER)) {
            return null;
        }
        try {
            return item.getAsNumber();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** A NumericDate for a message: the seconds, and the instant when {@link Instant} can hold it. */
    private static String numericDate(long seconds) {
        return seconds + (seconds >= Instant.MIN.getEpochSecond() && seconds <= Instant.MAX.getEpochSecond()
                ? " (" + Instant.ofEpochSecond(seconds) + ")" : "");
    }

    /**
     * A NumericDate in whole seconds against an instant in epoch milliseconds, as {@code kotlin.time.Instant} compares
     * them inside {@code fromCwt}; exact, and without overflow for any {@code long} of seconds.
     */
    static int compareSecondsWithMillis(long seconds, long millis) {
        long floor = Math.floorDiv(millis, 1000);
        if (seconds != floor) {
            return Long.compare(seconds, floor);
        }
        return Math.floorMod(millis, 1000) == 0 ? 0 : -1;
    }

    /**
     * Finds the keys a map of the token carries more than once (RFC 8949 5.3.1, 5.6), on the wire and before any
     * decoder has chosen between them. The maps are the unprotected header, the protected header and the CWT claims,
     * with every map nested in them ({@code status_list}).
     *
     * <p>The walk is Authlete's decoder, with no tag processor so the COSE structure arrives as plain items: a map
     * comes back as a {@code CBORPairList} holding every pair in wire order, never collapsed (Multipaz's decoder keeps
     * the last value of a key instead). Two keys are the same key when Authlete encodes the decoded keys to the same
     * bytes: that encoding is preferred serialization ({@code 18 02} and {@code 02} are both the integer 2; an
     * indefinite-length text is re-encoded definite), which is RFC 8949 5.6.1's data-model equivalence for the
     * integer and text labels COSE and CWT use. Nothing else is interpreted.
     */
    static final class DuplicateKeys {

        private DuplicateKeys() {}

        /** What carries a key twice, or {@code null}; throws when Authlete cannot read a part Multipaz could. */
        static String find(byte[] body) {
            CBORItem item = decode(body, "the body");
            while (item instanceof CBORTaggedItem tagged) {
                item = tagged.getTagContent();
            }
            if (!(item instanceof CBORItemList sign1) || sign1.getItems().size() != 4) {
                throw new IllegalStateException("Authlete does not read the body as the array(4) Multipaz read");
            }
            List<? extends CBORItem> array = sign1.getItems();
            List<String> found = new ArrayList<>();
            if (array.get(0) instanceof CBORByteArray protectedBytes) {
                walk(decode(protectedBytes.getValue(), "the protected header"), "the protected header", found);
            }
            walk(array.get(1), "the unprotected header", found);
            if (array.get(2) instanceof CBORByteArray payload) {
                walk(decode(payload.getValue(), "the CWT claims"), "the CWT claims", found);
            }
            return found.isEmpty() ? null : String.join("; ", found);
        }

        private static CBORItem decode(byte[] cbor, String what) {
            try {
                return new CBORDecoder(cbor, new CBORDecoderOptions()).next();
            } catch (Exception e) {
                throw new IllegalStateException("Authlete cannot decode " + what + " to check its map keys (RFC 8949 "
                        + "5.6): " + describe(e), e);
            }
        }

        private static void walk(CBORItem item, String where, List<String> found) {
            if (item instanceof CBORPairList map) {
                Map<String, Integer> counts = new LinkedHashMap<>();
                Map<String, CBORItem> keys = new HashMap<>();
                for (CBORPair pair : map.getPairs()) {
                    String key = pair.getKey().encodeToHex();
                    counts.merge(key, 1, Integer::sum);
                    keys.putIfAbsent(key, pair.getKey());
                }
                counts.forEach((key, count) -> {
                    if (count > 1) {
                        found.add(where + " carries the key " + keys.get(key) + (count == 2 ? " twice" : " " + count
                                + " times"));
                    }
                });
                for (CBORPair pair : map.getPairs()) {
                    walk(pair.getKey(), where + " (in a key)", found);
                    walk(pair.getValue(), where + " → " + pair.getKey(), found);
                }
            } else if (item instanceof CBORItemList list) {
                for (int i = 0; i < list.getItems().size(); i++) {
                    walk(list.getItems().get(i), where + "[" + i + "]", found);
                }
            } else if (item instanceof CBORTaggedItem tagged) {
                walk(tagged.getTagContent(), where, found);
            }
        }
    }

    private static boolean isInteger(DataItem value) {
        return value != null && (value.getMajorType() == MajorType.UNSIGNED_INTEGER
                || value.getMajorType() == MajorType.NEGATIVE_INTEGER);
    }

    private static String shortly(DataItem value) {
        String text = String.valueOf(value);
        return text.length() <= 80 ? text : text.substring(0, 77) + "...";
    }

    private static kotlin.time.Instant kotlinInstant(Instant instant) {
        return kotlin.time.Instant.Companion.fromEpochMilliseconds(instant.toEpochMilli());
    }

    /**
     * Multipaz's {@code CompressedStatusList.fromCwt(cwt, trustedRootCert, checks, atTime)} — the reader
     * {@code CachingRevocationChecker} uses on the wallet path, and the merge gate the plan's 4.9 names. It checks the
     * protected {@code typ}, {@code sub}, {@code exp}/{@code iat}, the 365-day {@code maxValidity} and the chain to the
     * IACA in one decision, so no hand-written reimplementation of those rules can drift from it.
     *
     * <p>Kotlin mangles the method name because {@code maxValidity: Duration} is a value class:
     * {@code fromCwt-myKFqkg}. Java cannot spell that identifier, so the synthetic {@code $default} bridge is resolved
     * once, lazily, and the call passes mask {@code 16} (bit 4, the {@code maxValidity} position) so Multipaz's own
     * default is used. Resolution never happens in a static initializer: a failure is kept as the descriptive message
     * of a {@link MultipazAdapterException}, which the chain check reports as the non-declarable {@code error} code —
     * never as {@code statusList.chain:untrusted}, which would blame the credential for a harness defect.
     */
    private static final class MultipazFromCwt {

        private static final String METHOD = "fromCwt-myKFqkg$default";
        private static final String DESCRIPTOR = "Multipaz 0.102.0 CompressedStatusList$Companion." + METHOD
                + "(byte[] cwt, X509Cert trustedRootCert, Map<WebTokenCheck,String> checks, kotlin.time.Instant atTime,"
                + " long maxValidity, Continuation, int mask, Object marker)";

        private static Method bridge;
        private static String failure;
        /** Test seam: makes resolution fail as if a Multipaz upgrade had changed fromCwt. */
        private static volatile String forcedFailure;

        static synchronized Method bridge() {
            if (forcedFailure != null) {
                throw new MultipazAdapterException(forcedFailure);
            }
            if (bridge == null && failure == null) {
                try {
                    bridge = resolve();
                } catch (Throwable e) {
                    rethrowIfFatal(e);
                    failure = DESCRIPTOR + " is gone: a Multipaz upgrade changed fromCwt, and the M-11b gate cannot run "
                            + "without it (" + describe(e) + ")";
                }
            }
            if (failure != null) {
                throw new MultipazAdapterException(failure);
            }
            return bridge;
        }

        private static Method resolve() throws ReflectiveOperationException {
            Class<?> type = Class.forName("org.multipaz.revocation.CompressedStatusList$Companion");
            Method method = type.getDeclaredMethod(METHOD, type, byte[].class, X509Cert.class, Map.class,
                    kotlin.time.Instant.class, long.class, Continuation.class, int.class, Object.class);
            method.setAccessible(true);
            return method;
        }

        /** @throws RuntimeException whatever Multipaz refused the token with, as {@code fromCwt} throws it */
        static void read(byte[] body, X509Cert anchor, String uri, Instant at) {
            Method bridge = bridge();
            Map<WebTokenCheck, String> checks = Map.of(WebTokenCheck.SUB, uri);
            await(continuation -> invoke(bridge, body, anchor, checks, at, continuation));
        }

        private static Object invoke(Method bridge, byte[] body, X509Cert anchor, Map<WebTokenCheck, String> checks,
                                     Instant at, Continuation<?> continuation) {
            try {
                return bridge.invoke(CompressedStatusList.Companion, CompressedStatusList.Companion, body, anchor, checks,
                        kotlinInstant(at), 0L, continuation, 16, null);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause instanceof RuntimeException runtime) {
                    throw runtime;
                }
                if (cause instanceof Error error) {
                    throw error;
                }
                throw new IllegalStateException("CompressedStatusList.fromCwt refused the token: " + describe(cause), cause);
            } catch (IllegalAccessException e) {
                throw new MultipazAdapterException(DESCRIPTOR + " is not callable: " + describe(e));
            }
        }
    }

    /** A harness defect in the {@code fromCwt} adapter: reported as {@code error}, never as a credential problem. */
    private static final class MultipazAdapterException extends RuntimeException {
        MultipazAdapterException(String message) {
            super(message, null, false, false);
        }
    }

    /**
     * The resolved Multipaz {@code fromCwt} bridge, for a test that proves it still matches the pinned jar. Package
     * private: the testkit is a test module, and the alternative is no test of the one reflective call in the gate.
     */
    static Method multipazFromCwtBridge() {
        return MultipazFromCwt.bridge();
    }

    /**
     * The {@code fromCwt} mirror on its own — whether {@code fromCwt} refuses this token for a defect a check reports —
     * so a test can hold it to {@code fromCwt} itself token by token. Package private, like the bridge above.
     */
    static boolean fromCwtRefusesOnAReportedDefect(byte[] body, String uri, Instant at) {
        Token token = Token.parse(body);
        VerificationReport.Check envelope = run(CHECK_ENVELOPE, token::envelope);
        VerificationReport.Check typ = run(CHECK_TYP, token::typ);
        VerificationReport.Check signature = run(CHECK_SIGNATURE,
                problems -> token.signature(problems, !envelope.passed()));
        return token.fromCwtRefusesOnAReportedDefect(uri, at, typ, signature);
    }

    /** Test seam for the adapter's failure path; {@code resetMultipazFromCwtAdapterForTest} clears it. */
    static void failMultipazFromCwtAdapterForTest(String message) {
        MultipazFromCwt.forcedFailure = message;
    }

    static void resetMultipazFromCwtAdapterForTest() {
        MultipazFromCwt.forcedFailure = null;
    }

    /** Multipaz's cryptographic entry points are suspend on the JVM without ever suspending; runBlocking keeps that here. */
    private static <T> T await(Function<Continuation<? super T>, Object> block) {
        Function2<CoroutineScope, Continuation<? super T>, Object> runner = new Function2<>() {
            @Override
            public Object invoke(CoroutineScope scope, Continuation<? super T> continuation) {
                return block.apply(continuation);
            }
        };
        try {
            @SuppressWarnings("unchecked")
            T result = (T) BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE, runner);
            return result;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while verifying the status list with Multipaz", e);
        }
    }
}
