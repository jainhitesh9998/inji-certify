package io.mosip.certify.entity;

import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.TableGenerator;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * M-11d review round 5, nit 3: the order the batch job applies a list's status transactions in is the order of
 * {@code transaction_log_id} (G42), which holds only because each insert draws its id from the database's {@code SERIAL}
 * sequence ({@code CACHE 1}) while it holds the list's row lock. A pooled {@code SEQUENCE} or table generator would hand
 * out blocks of ids in memory, before the lock, and two nodes' blocks would interleave against the commit order. This
 * test fails the build if the mapping moves away from {@code IDENTITY}; {@code StatusListPostgresTest} checks the
 * sequence's {@code CACHE 1} on the Flyway schema.
 */
class CredentialStatusTransactionIdOrderTest {

    @Test
    void transactionLogIdIsDrawnByTheDatabaseAtInsert() throws Exception {
        Field id = CredentialStatusTransaction.class.getDeclaredField("transactionLogId");
        assertNotNull(id.getAnnotation(Id.class), "transactionLogId is the id");
        GeneratedValue generated = id.getAnnotation(GeneratedValue.class);
        assertNotNull(generated, "the database generates transaction_log_id");
        assertEquals(GenerationType.IDENTITY, generated.strategy(),
                "IDENTITY: the id is drawn by the insert, under the list's row lock (G42); a pooled SEQUENCE would not be");
        assertEquals("", generated.generator(), "no named generator overrides the strategy");
        assertNull(id.getAnnotation(SequenceGenerator.class));
        assertNull(id.getAnnotation(TableGenerator.class));
        assertNull(CredentialStatusTransaction.class.getAnnotation(SequenceGenerator.class));
        assertNull(CredentialStatusTransaction.class.getAnnotation(TableGenerator.class));
    }
}
