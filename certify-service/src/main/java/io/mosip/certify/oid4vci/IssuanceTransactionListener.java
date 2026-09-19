package io.mosip.certify.oid4vci;

import io.mosip.certify.entity.IssuanceTransaction;
import io.mosip.certify.repository.IssuanceTransactionRepository;
import io.mosip.certify.spi.HolderBinding;
import io.mosip.certify.spi.IssuanceListener;
import io.mosip.certify.spi.IssuedCredential;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Records every issuance the core completes as an {@code issuance_transaction} row (state ISSUED): the transaction id
 * doubles as the {@code notification_id} the wallet reports back with, and the row expires after the configured
 * retention. Failures carry no transaction id yet and are not recorded.
 */
@Component
public class IssuanceTransactionListener implements IssuanceListener {

    private final IssuanceTransactionRepository repository;
    private final Oid4vciProperties properties;

    public IssuanceTransactionListener(IssuanceTransactionRepository repository, Oid4vciProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    @Override
    public void onIssued(IssuanceEvent event) {
        IssuanceTransaction transaction = new IssuanceTransaction();
        transaction.setId(transactionId(event.transactionId()));
        transaction.setTenantId(event.context() == null || event.context().tenant() == null ? "default" : event.context().tenant().tenantId());
        transaction.setAccessTokenHash(event.context() == null || event.context().authorization() == null ? null : event.context().authorization().tokenHash());
        transaction.setCredentialConfigId(event.configuration() == null ? null : event.configuration().id());
        transaction.setProtocolVersion(event.context() == null || event.context().protocol() == null ? null : event.context().protocol().name());
        transaction.setState(IssuanceTransaction.STATE_ISSUED);
        transaction.setNotificationId(event.transactionId());
        List<Map<String, Object>> bindings = new ArrayList<>();
        if (event.context() != null && event.context().holders() != null) {
            for (HolderBinding holder : event.context().holders()) {
                Map<String, Object> binding = new LinkedHashMap<>();
                binding.put("kind", holder.kind() == null ? null : holder.kind().name());
                binding.put("value", holder.value());
                binding.put("kid", holder.kid());
                binding.put("proofType", holder.proofType());
                bindings.add(binding);
            }
        }
        transaction.setHolderBindings(bindings);
        List<String> ids = new ArrayList<>();
        for (IssuedCredential credential : event.credentials()) {
            if (credential.credentialId() != null) {
                ids.add(credential.credentialId());
            }
        }
        transaction.setCredentialIds(ids);
        LocalDateTime now = event.context() == null ? LocalDateTime.now(ZoneOffset.UTC) : LocalDateTime.ofInstant(event.context().now(), ZoneOffset.UTC);
        transaction.setCreatedTimes(now);
        transaction.setExpiresAt(now.plus(properties.notification().retention()));
        repository.save(transaction);
    }

    static UUID transactionId(String transactionId) {
        try {
            return UUID.fromString(transactionId);
        } catch (IllegalArgumentException | NullPointerException e) {
            return UUID.nameUUIDFromBytes(String.valueOf(transactionId).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}
