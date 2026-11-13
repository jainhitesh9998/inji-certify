package io.mosip.certify.services;

import io.mosip.certify.entity.CredentialStatusTransaction;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import org.springframework.data.domain.Pageable;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code credential_status_transaction} as the status-list batch job's queries see it, in memory: pending rows that name
 * a list, oldest first (creation time, then id), without the lists the job excludes, at most the page size; a row the
 * job marks processed leaves the selection. Shared by the batch-job tests of this package and of the CWT service.
 */
public final class InMemoryStatusTransactions {

    public final List<CredentialStatusTransaction> rows = new CopyOnWriteArrayList<>();
    /** Every exclusion set the job passed to the selection, in order. */
    public final List<Set<String>> excludedSelections = new CopyOnWriteArrayList<>();
    public final CredentialStatusTransactionRepository repository = mock(CredentialStatusTransactionRepository.class);
    private final AtomicLong ids = new AtomicLong();

    public InMemoryStatusTransactions() {
        when(repository.findPending(any(Pageable.class))).thenAnswer(inv -> select(Set.of(), inv.getArgument(0)));
        when(repository.findPendingExcluding(anyCollection(), any(Pageable.class))).thenAnswer(inv -> {
            Set<String> excluded = Set.copyOf(inv.<Collection<String>>getArgument(0));
            excludedSelections.add(excluded);
            return select(excluded, inv.getArgument(1));
        });
        // the selection before M-11d review round 2 (OFFSET paging over every pending row): kept so a negative control
        // can run these tests against the old job
        when(repository.findByIsProcessedFalseOrderByCreatedDtimesAsc(any(Pageable.class))).thenAnswer(inv -> {
            Pageable page = inv.getArgument(0);
            return rows.stream().filter(t -> !t.getIsProcessed())
                    .sorted(Comparator.comparing(CredentialStatusTransaction::getCreatedDtimes)
                            .thenComparing(CredentialStatusTransaction::getTransactionLogId))
                    .skip(page.getOffset()).limit(page.getPageSize()).toList();
        });
        when(repository.saveAll(anyList())).thenAnswer(inv -> inv.getArgument(0));
        when(repository.countPendingByList(anyCollection())).thenAnswer(inv -> {
            Collection<String> listIds = inv.getArgument(0);
            List<CredentialStatusTransactionRepository.PendingCount> counts = new ArrayList<>();
            for (String listId : listIds) {
                long pending = pending().stream().filter(t -> listId.equals(t.getStatusListCredentialId())).count();
                if (pending > 0) {
                    counts.add(new CredentialStatusTransactionRepository.PendingCount() {
                        @Override
                        public String getListId() {
                            return listId;
                        }

                        @Override
                        public long getPending() {
                            return pending;
                        }
                    });
                }
            }
            return counts;
        });
    }

    /** A pending transaction setting {@code index} of {@code listId} to {@code value}, created at {@code created}. */
    public CredentialStatusTransaction add(String listId, long index, boolean value, Instant created) {
        CredentialStatusTransaction txn = new CredentialStatusTransaction();
        txn.setTransactionLogId(ids.incrementAndGet());
        txn.setCredentialId("credential-" + txn.getTransactionLogId());
        txn.setStatusPurpose("revocation");
        txn.setStatusListCredentialId(listId);
        txn.setStatusListIndex(index);
        txn.setStatusValue(value);
        txn.setCreatedDtimes(LocalDateTime.ofInstant(created, ZoneOffset.UTC));
        txn.setIsProcessed(false);
        rows.add(txn);
        return txn;
    }

    public List<CredentialStatusTransaction> pending() {
        return rows.stream().filter(t -> !t.getIsProcessed()).toList();
    }

    private List<CredentialStatusTransaction> select(Set<String> excluded, Pageable page) {
        return rows.stream()
                .filter(t -> !t.getIsProcessed() && t.getStatusListCredentialId() != null)
                .filter(t -> !excluded.contains(t.getStatusListCredentialId()))
                .sorted(Comparator.comparing(CredentialStatusTransaction::getCreatedDtimes)
                        .thenComparing(CredentialStatusTransaction::getTransactionLogId))
                .limit(page.getPageSize())
                .toList();
    }
}
