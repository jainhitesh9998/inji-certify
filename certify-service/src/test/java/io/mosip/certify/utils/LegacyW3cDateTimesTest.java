package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * F-19: the {@code issuanceDate}/{@code validFrom} reader on the compatibility path accepts every form Certify writes
 * and nothing else, and reads the same instant the same way whichever form carries it.
 */
class LegacyW3cDateTimesTest {

    private static final DateTimeFormatter LEGACY_WRITER = DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN);

    /** The value parts, exactly as written, and the wall clock each one states. */
    @Test
    void readsTheDatePartOfEveryFormTheTwoWritersProduce() {
        Map<String, LocalDateTime> written = Map.of(
                // Constants.UTC_DATETIME_PATTERN, the issuance path and StatusListCredentialService's list writer
                "2026-11-13T15:00:23.000Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23),
                "2026-11-13T15:00:23.123Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23, 123_000_000),
                // Instant.toString(): no fraction at all when it is zero, and 3, 6 or 9 digits otherwise
                "2026-11-13T15:00:23Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23),
                "1970-01-01T00:00:01Z", LocalDateTime.of(1970, 1, 1, 0, 0, 1),
                "2026-11-13T15:00:23.100Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23, 100_000_000),
                "2026-11-13T15:00:23.123456Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23, 123_456_000),
                "2026-11-13T15:00:23.123456789Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23, 123_456_789));
        written.forEach((value, expected) -> assertEquals(expected, LegacyW3cDateTimes.localDateTime(value), value));
    }

    /** Every instant a status list writer can observe round-trips through {@code Instant.toString()}. */
    @Test
    void readsEveryInstantToStringForm() {
        for (int nanos : List.of(0, 1, 1_000, 999_999_000, 123_000_000, 123_456_000, 123_456_789)) {
            Instant instant = Instant.ofEpochSecond(1_791_990_023L, nanos);
            String written = instant.toString();
            LocalDateTime wallClock = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
            assertEquals(wallClock, LegacyW3cDateTimes.localDateTime(written), written);
            assertEquals(wallClockInJvmZone(wallClock).truncatedTo(ChronoUnit.MILLIS),
                    LegacyW3cDateTimes.proofCreated(written).toInstant(), written);
        }
    }

    private static Instant wallClockInJvmZone(LocalDateTime wallClock) {
        return wallClock.atZone(ZoneId.systemDefault()).toInstant();
    }

    /**
     * Byte compatibility, checked against the former implementation itself: for the form every existing status list
     * and every issued credential carries, {@code proofCreated} is the same {@code Date} the strict
     * {@code LocalDateTime.parse(...).atZone(ZoneId.systemDefault())} produced.
     */
    @Test
    void keepsTheFormerReadingOfTheFormEveryExistingDocumentCarries() {
        for (String value : List.of("2026-11-13T15:00:23.000Z", "2026-11-13T15:00:23.123Z",
                "2023-01-01T00:00:00.000Z", "1970-01-01T00:00:00.001Z")) {
            Date former = Date.from(LocalDateTime.parse(value, LEGACY_WRITER)
                    .atZone(ZoneId.systemDefault()).toInstant());
            assertEquals(former, LegacyW3cDateTimes.proofCreated(value), value);
        }
    }

    /**
     * A template or a plugin may supply an RFC 3339 value with an offset. It is accepted; the designator is validated
     * and then not applied, because this path has always read the wall clock and applying it would move
     * {@code proof.created} on every deployment not on UTC (see the class note).
     */
    @Test
    void acceptsAnOffsetDesignatorAndReadsTheWallClock() {
        LocalDateTime wallClock = LocalDateTime.of(2026, 11, 13, 15, 0, 23, 123_000_000);
        for (String value : List.of("2026-11-13T15:00:23.123Z", "2026-11-13T15:00:23.123+05:30",
                "2026-11-13T15:00:23.123-08:00", "2026-11-13T15:00:23.123")) {
            assertEquals(wallClock, LegacyW3cDateTimes.localDateTime(value), value);
        }
    }

    /** A validity field that cannot be read is refused, not guessed. */
    @Test
    void refusesWhatIsNotARfc3339DateTime() {
        for (String value : List.of("not-a-date", "2026-11-13", "2026-11-13T15:00", "2026-13-01T00:00:00Z",
                "2026-11-13T25:00:23Z", "2026-11-13T15:00:23.1234567890Z", "2026-11-13 15:00:23Z",
                "2026-11-13T15:00:23+0530", "")) {
            assertThrows(DateTimeParseException.class, () -> LegacyW3cDateTimes.localDateTime(value), value);
        }
        assertThrows(DateTimeParseException.class, () -> LegacyW3cDateTimes.localDateTime(null));
    }
}
