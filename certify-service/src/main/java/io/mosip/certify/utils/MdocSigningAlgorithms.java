package io.mosip.certify.utils;

import io.mosip.certify.signing.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The one COSE algorithm map for {@code mso_mdoc} metadata (OpenID4VCI 1.0 Appendix A.2.2): both metadata builders
 * (the compatibility document's {@code CredentialIssuerMetadataBuilder} and this surface's
 * {@code TenantIssuerMetadata}) publish {@code credential_signing_alg_values_supported} for an mDoc configuration as
 * COSE identifiers rather than the JOSE names the column holds.
 *
 * <p>ISO/IEC 18013-5 signing algorithms are ES256 (-7), ES384 (-35), ES512 (-36) and EdDSA (-8). ES256K and RS256 stay
 * in the map because deployments configured them before the ISO rules were applied and their documents must not
 * change; nothing new may use them. The identifiers come from {@link SignatureAlgorithm}, so the metadata and the signer
 * can never disagree.
 *
 * <p>An algorithm the map does not know is omitted with a warning: one unsupported value must not fail the whole
 * metadata document (it used to throw).
 */
@Slf4j
public final class MdocSigningAlgorithms {

    private static final Map<String, Integer> JOSE_TO_COSE = map();

    private MdocSigningAlgorithms() {}

    private static Map<String, Integer> map() {
        Map<String, Integer> byName = new LinkedHashMap<>();
        for (String jose : new String[] {"ES256", "ES384", "ES512", "EdDSA", "ES256K", "RS256"}) {
            SignatureAlgorithm.fromJose(jose).ifPresent(algorithm -> byName.put(jose, algorithm.coseId()));
        }
        return Map.copyOf(byName);
    }

    /** The COSE identifier for a JOSE algorithm name, or {@code null} (one warning) when mDoc has none. */
    public static Integer coseId(String joseName) {
        if (joseName == null) {
            return null;
        }
        Integer cose = JOSE_TO_COSE.get(joseName.trim());
        if (cose == null) {
            log.warn("No COSE identifier for signing algorithm '{}'; omitting it from mso_mdoc credential_signing_alg_values_supported", joseName);
        }
        return cose;
    }

    /** The COSE identifiers for a list of JOSE names, skipping the ones the map does not know; {@code null} when none survive. */
    public static java.util.List<Object> coseIds(java.util.Collection<String> joseNames) {
        java.util.List<Object> cose = new java.util.ArrayList<>();
        for (String joseName : joseNames) {
            Integer id = coseId(joseName);
            if (id != null) {
                cose.add(id);
            }
        }
        return cose.isEmpty() ? null : cose;
    }
}
