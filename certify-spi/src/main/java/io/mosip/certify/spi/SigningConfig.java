package io.mosip.certify.spi;

import io.mosip.certify.signing.CoseHeaderPolicy;
import io.mosip.certify.signing.JwsHeaderPolicy;
import io.mosip.certify.signing.KeyRef;
import io.mosip.certify.signing.SignatureAlgorithm;

import java.util.Objects;

/**
 * How a configuration signs: which key, which algorithm, which suite, which headers. Replaces
 * {@code key_manager_app_id}, {@code key_manager_ref_id}, {@code signature_algo}, {@code signature_crypto_suite}
 * and {@code did_url}; the keymanager provider maps {@code keyRef} back to the app and reference ids.
 *
 * @param keyRef        the key, e.g. {@code keymanager:CERTIFY_VC_SIGN_ED25519/ED25519_SIGN}
 * @param algorithm     JOSE algorithm the key signs with
 * @param cryptosuite   Data Integrity cryptosuite or legacy LD suite name for W3C credentials, else {@code null}
 * @param jwsHeaders    header policy for JWS-based formats, or {@code null} for the format's default
 * @param coseHeaders   header policy for COSE-based formats, or {@code null} for the format's default
 * @param issuerDid     the DID whose verification method the proof names, for W3C credentials
 */
public record SigningConfig(KeyRef keyRef, SignatureAlgorithm algorithm, String cryptosuite,
                            JwsHeaderPolicy jwsHeaders, CoseHeaderPolicy coseHeaders, String issuerDid) {

    public SigningConfig {
        Objects.requireNonNull(keyRef, "keyRef");
        Objects.requireNonNull(algorithm, "algorithm");
    }

    public static SigningConfig of(KeyRef keyRef, SignatureAlgorithm algorithm) {
        return new SigningConfig(keyRef, algorithm, null, null, null, null);
    }

    public SigningConfig withCryptosuite(String suite) {
        return new SigningConfig(keyRef, algorithm, suite, jwsHeaders, coseHeaders, issuerDid);
    }

    public SigningConfig withIssuerDid(String did) {
        return new SigningConfig(keyRef, algorithm, cryptosuite, jwsHeaders, coseHeaders, did);
    }
}
