package io.mosip.certify.issuance;

import io.mosip.certify.spi.IssuedCredential;

import java.util.List;

/** Outcome of {@link IssuanceService#issue}: credentials now, or a transaction to collect later. */
public sealed interface IssuanceResult permits IssuanceResult.Issued, IssuanceResult.Deferred {

    String transactionId();

    record Issued(List<IssuedCredential> credentials, String transactionId) implements IssuanceResult {
        public Issued {
            credentials = List.copyOf(credentials);
        }
    }

    record Deferred(String transactionId) implements IssuanceResult {}
}
