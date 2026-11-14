package io.mosip.certify.status;

import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.spi.CredentialConfiguration;
import io.mosip.certify.spi.FormatException;
import io.mosip.certify.spi.IssuanceContext;
import io.mosip.certify.spi.SigningContext;
import io.mosip.certify.spi.StatusProvider;
import io.mosip.certify.spi.UnsignedCredential;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@code status_config.mechanism = TokenStatusList}: an SD-JWT VC payload or an mDoc MSO gains
 * {@code status.status_list = {idx, uri}} (draft-ietf-oauth-status-list sections 6.1 and 6.2), the list being served at
 * {@code uri} as {@code application/statuslist+jwt}.
 *
 * <p>M-11e: an {@code mso_mdoc} whose formatter asks for a {@code cwt} status list ({@link
 * io.mosip.certify.spi.CredentialFormatter#statusListTokenFormat()}, which is {@code MdocFormatter}'s answer because of
 * ISO/IEC 18013-5 second edition 12.3.6.3) gets a {@link TokenStatusListService#TYPE_CWT} row signed by the Document
 * Signer that signs the mDL itself, when {@code certify.status.token-status-list.mdoc.token-format=cwt} (the default,
 * D-M11-3). The list therefore carries exactly the {@code x5chain} of the mDL's IssuerAuth, which is the rule Credo
 * and Paradym apply, and a rotated Document Signer keeps its own lists (section 4.3). Everything else — an SD-JWT VC,
 * an {@code ldp_vc}, and an mDoc with {@code token-format=jwt} — keeps today's shared JWT list, byte for byte (I4).
 */
@Slf4j
@Component
public class TokenStatusListProvider implements StatusProvider {

    public static final String MECHANISM = "TokenStatusList";
    static final Set<String> FORMATS = Set.of("dc+sd-jwt", "vc+sd-jwt", "mso_mdoc");
    /** The only status purpose an mDoc list may carry (ISO/IEC 18013-5 second edition 12.3.6.1, D-M11-5). */
    static final List<String> MDOC_PURPOSES = List.of("revocation");
    /**
     * Providers that resolve a key alias to one <em>version</em> of it ({@code mdl-dsc@2026-11}), so a list pinned to a
     * version stays re-signable after a rotation. A provider absent here rotates inside one reference and the pinned
     * reference names whatever the current key is.
     */
    private static final Set<String> VERSIONED_PROVIDERS = Set.of("x509-file", "jca");

    private final TokenStatusListService lists;
    private final TokenStatusListProperties properties;
    /** The aliases this instance has already warned about, so the WARN is said once, not on every mDL. */
    private final Set<String> warnedUnversioned = ConcurrentHashMap.newKeySet();

    public TokenStatusListProvider(TokenStatusListService lists, TokenStatusListProperties properties) {
        this.lists = lists;
        this.properties = properties;
    }

    @Override
    public String mechanism() {
        return MECHANISM;
    }

    @Override
    public boolean supports(String format) {
        return FORMATS.contains(format);
    }

    @Override
    public UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
        if (configuration.status().purposes().isEmpty()) {
            return credential;
        }
        return withStatusList(credential, lists.allocate(configuration.status().purposes().get(0)));
    }

    /**
     * The M-11e path: a CWT list signed by the credential's own Document Signer when the format asks for CWT and the
     * deployment has not opted out (D-M11-3).
     *
     * <p>An mDoc list carries only {@code revocation} (ISO/IEC 18013-5 second edition 12.3.6.1, D-M11-5). A row saved
     * through the v1 configuration API — which does not apply that rule — is refused here, at issuance, rather than
     * producing an mDL whose list no verifier accepts for its purpose.
     *
     * @throws FormatException {@code status_list_unavailable} when the signer is refused (the DSC policy, M-11c) or the
     *                         purpose is not {@code revocation}; the index is allocated only after both hold, so a
     *                         refused mDL consumes none
     */
    @Override
    public UnsignedCredential attach(UnsignedCredential credential, CredentialConfiguration configuration,
                                     IssuanceContext context, StatusBinding binding) {
        java.util.Objects.requireNonNull(binding, "binding: the CWT path needs the credential's signing context and its"
                + " formatter's status-list token format");
        if (configuration.status().purposes().isEmpty()) {
            return credential;
        }
        // the mDoc purpose rule is decided by the formatter, not by this deployment's token-format setting: an mDL whose
        // list is a JWT is still an mDoc list, and a wallet reads it for revoked/valid only. Checked before the JWT/CWT
        // choice, so the escape hatch cannot carry a purpose the specification refuses (review round 1, major 3)
        boolean mdocStatusList = TokenStatusListProperties.Mdoc.FORMAT_CWT.equals(binding.statusListTokenFormat());
        if (mdocStatusList && !MDOC_PURPOSES.equals(configuration.status().purposes())) {
            throw new FormatException("status_list_unavailable", "ISO/IEC 18013-5 second edition 12.3.6.1: an mDoc"
                    + " status list carries only revoked/valid");
        }
        if (!mdocStatusList || !TokenStatusListProperties.Mdoc.FORMAT_CWT.equals(properties.mdoc().tokenFormat())) {
            return attach(credential, configuration, context);
        }
        warnAboutAnUnversionedSigner(binding.signing());
        TokenStatusListService.Entry entry;
        try {
            entry = lists.allocateCwt(MDOC_PURPOSES.get(0), binding.signing());
        } catch (StatusListRetiredException e) {
            throw new FormatException("status_list_unavailable", "The Document Signer of this mDL is past its validity:"
                    + " no status list signed by it could be valid either (D-M11-7)", e);
        } catch (RuntimeException e) {
            throw new FormatException("status_list_unavailable", "Could not assign a token status list entry: " + e.getMessage(), e);
        }
        return withStatusList(credential, entry);
    }

    /**
     * Gives back the index of an mDL that was never issued (M-11e, owner decision D-M11e-1): a listener that fails
     * before the credential is signed, a Document Signer the format refuses at signing time or a signature that does
     * not happen must not spend an entry of a CWT list.
     *
     * <p>Only a CWT list is touched ({@link TokenStatusListService#release} refuses a JWT row): the legacy JWT path of an
     * SD-JWT VC, an {@code ldp_vc} or an mDoc with the escape hatch keeps exactly its previous behaviour, and a
     * Bitstring list is not this provider's at all.
     */
    @Override
    public void release(UnsignedCredential credential, CredentialConfiguration configuration, IssuanceContext context) {
        if (credential == null) {
            return;
        }
        Object status = credential.asMap().get("status");
        Object statusList = status instanceof Map<?, ?> map ? map.get("status_list") : null;
        if (!(statusList instanceof Map<?, ?> entry) || !(entry.get("idx") instanceof Number idx)) {
            return;
        }
        lists.release(String.valueOf(entry.get("uri")), idx.longValue());
    }

    private static UnsignedCredential withStatusList(UnsignedCredential credential, TokenStatusListService.Entry entry) {
        Map<String, Object> document = new LinkedHashMap<>(credential.asMap());
        document.put("status", Map.of("status_list", Map.of("idx", entry.idx(), "uri", entry.uri())));
        return credential.withDocument(document);
    }

    /**
     * Section 4.3's limitation, said once per alias on the first mDL signed with it: a Document Signer reference that
     * keeps no version of itself cannot be resolved back after it rotates, so a list pinned to it can be re-signed by no
     * {@code KeyRef} and is answered {@code STATUS_SIGNER_GONE} (503). Document-signer mode should be configured with
     * {@code mdl-dsc@2026-11}, which {@link StatusListSigners#pin} records from the key's own {@code kid}. This is
     * advisory, not a refusal: D-M11e-2 decided the wording, and the WARN fires here, at attach, on the first mDL signed
     * with the alias, naming the key it resolved so the operator can see which alias to version.
     */
    private void warnAboutAnUnversionedSigner(SigningContext signing) {
        KeyRef ref = signing.config() == null ? null : signing.config().keyRef();
        if (ref == null || !VERSIONED_PROVIDERS.contains(ref.provider())) {
            return;
        }
        String kid = signing.key().kid();
        if (kid != null && kid.lastIndexOf('@') > 0) {
            return; // the provider already resolves mdl-dsc to mdl-dsc@2026-11: the pinned reference is versioned
        }
        if (warnedUnversioned.add(ref.toString())) {
            log.warn("CWT status lists are pinned to the Document Signer that signs their mDLs (D-M11-1), and {} names no"
                    + " version of its key: it resolved to {} (kid {}, certificate {}). If it rotates while its old"
                    + " certificate is still valid, its lists can be re-signed by no key reference and are answered 503"
                    + " STATUS_SIGNER_GONE (section 4.3). Configure a versioned alias such as {}@2026-11",
                    ref, signing.key().ref(), kid == null ? "none" : kid,
                    signing.key().chain() == null ? "none" : signing.key().chain().leaf()
                            .map(certificate -> certificate.getSubjectX500Principal().getName()).orElse("none"),
                    ref.alias());
        }
    }

    @Override
    public void update(StatusUpdate update) {
        throw new UnsupportedOperationException("Status updates go through /credentials/status and the batch job");
    }
}
