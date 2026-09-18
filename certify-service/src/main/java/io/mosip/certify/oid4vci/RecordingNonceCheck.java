package io.mosip.certify.oid4vci;

import io.mosip.certify.spi.ProofValidationException;
import io.mosip.certify.spi.ProofValidator;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Wraps the request's nonce store and remembers every nonce a proof presented, so the adapter can consume them once
 * the credentials are issued: all proofs of a batch share one c_nonce, so consumption waits for the whole request.
 */
final class RecordingNonceCheck implements ProofValidator.NonceCheck {

    private final ProofValidator.NonceCheck delegate;
    private final Set<String> nonces = new LinkedHashSet<>();

    RecordingNonceCheck(ProofValidator.NonceCheck delegate) {
        this.delegate = delegate;
    }

    @Override
    public void check(String nonce) throws ProofValidationException {
        delegate.check(nonce);
        nonces.add(nonce);
    }

    Set<String> nonces() {
        return Set.copyOf(nonces);
    }
}
