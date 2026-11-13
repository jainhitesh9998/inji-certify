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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F-19: the {@code issuanceDate}/{@code validFrom} reader on the compatibility path accepts every form Certify writes,
 * every value the former reader accepted that is a valid XML Schema {@code dateTimeStamp}, and nothing outside the
 * grammar {@link LegacyW3cDateTimes} documents; and it reads the same instant the same way whichever form carries it.
 */
class LegacyW3cDateTimesTest {

    private static final DateTimeFormatter LEGACY_WRITER = DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN);

    /** The former reader, verbatim: {@code W3CJsonLD.addProof} before F-19. */
    private static Date formerProofCreated(String value) {
        return Date.from(LocalDateTime.parse(value, LEGACY_WRITER).atZone(ZoneId.systemDefault()).toInstant());
    }

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
     * and every issued credential carries, {@code proofCreated} is the same {@code Date} the former SMART
     * {@code LocalDateTime.parse(...).atZone(ZoneId.systemDefault())} produced, at the edges of the range as well.
     */
    @Test
    void keepsTheFormerReadingOfTheFormEveryExistingDocumentCarries() {
        for (String value : List.of("2026-11-13T15:00:23.000Z", "2026-11-13T15:00:23.123Z",
                "2023-01-01T00:00:00.000Z", "1970-01-01T00:00:00.001Z", "0001-01-01T00:00:00.000Z",
                "9999-12-31T23:59:59.999Z", "2024-02-29T12:00:00.000Z", "2000-02-29T00:00:00.000Z")) {
            assertEquals(formerProofCreated(value), LegacyW3cDateTimes.proofCreated(value), value);
        }
    }

    /**
     * XML Schema {@code endOfDayFrag}: {@code 24:00:00} with no fraction or an all-zero one is the first instant of
     * the next day, in the value's own zone. The former SMART reader read {@code 24:00:00.000Z} the same way, so those
     * values keep their {@code proof.created}; the other spellings are newly accepted, as valid {@code dateTimeStamp}s.
     */
    @Test
    void readsTheEndOfDayAsTheFirstInstantOfTheNextDay() {
        Map<String, LocalDateTime> endOfDay = new LinkedHashMap<>();
        endOfDay.put("2026-11-13T24:00:00.000Z", LocalDateTime.of(2026, 11, 14, 0, 0));
        endOfDay.put("2026-12-31T24:00:00.000Z", LocalDateTime.of(2027, 1, 1, 0, 0));
        endOfDay.put("2024-02-28T24:00:00.000Z", LocalDateTime.of(2024, 2, 29, 0, 0));
        endOfDay.put("2024-02-29T24:00:00.000Z", LocalDateTime.of(2024, 3, 1, 0, 0));
        endOfDay.put("9999-12-31T24:00:00.000Z", LocalDateTime.of(10000, 1, 1, 0, 0));
        endOfDay.forEach((value, expected) -> {
            assertEquals(expected, LegacyW3cDateTimes.localDateTime(value), value);
            assertEquals(LocalDateTime.parse(value, LEGACY_WRITER), LegacyW3cDateTimes.localDateTime(value), value);
            assertEquals(formerProofCreated(value), LegacyW3cDateTimes.proofCreated(value), value);
        });

        LocalDateTime nextMidnight = LocalDateTime.of(2026, 11, 14, 0, 0);
        for (String value : List.of("2026-11-13T24:00:00Z", "2026-11-13T24:00:00.0Z",
                "2026-11-13T24:00:00.000000000Z", "2026-11-13T24:00:00+00:00", "2026-11-13T24:00:00-00:00")) {
            assertEquals(nextMidnight, LegacyW3cDateTimes.localDateTime(value), value);
        }
        // the next day in the value's own zone, then converted: 2026-11-14T00:00+05:30 is 2026-11-13T18:30Z
        assertEquals(LocalDateTime.of(2026, 11, 13, 18, 30), LegacyW3cDateTimes.localDateTime("2026-11-13T24:00:00+05:30"));
        assertEquals(LocalDateTime.of(2026, 11, 14, 14, 0), LegacyW3cDateTimes.localDateTime("2026-11-13T24:00:00.00-14:00"));
    }

    /** Hour 24 is the end of day and nothing else; an impossible date is not made possible by it. */
    @Test
    void refusesEveryOtherHour24Form() {
        for (String value : List.of("2026-11-13T24:00:01Z", "2026-11-13T24:01:00Z", "2026-11-13T24:00:00.001Z",
                "2026-11-13T24:00:00.000000001Z", "2026-11-13T24:00:00.100Z", "2026-11-13T24:59:59.999Z",
                "2026-11-13T24:00:00.0000000000Z", "2026-11-13T24:00Z", "2026-11-13T24:00:00",
                "2026-02-29T24:00:00Z", "2026-04-31T24:00:00.000Z", "2026-11-13T24:00:00+14:01")) {
            assertThrows(DateTimeParseException.class, () -> LegacyW3cDateTimes.localDateTime(value), value);
        }
    }

    /**
     * A template or a plugin may supply a value with an offset instead of {@code Z}. The same instant must read the
     * same whichever designator wrote it, because the value is normalised to UTC before the compatibility rule.
     */
    @Test
    void readsTheSameInstantTheSameWhicheverZoneDesignatorWroteIt() {
        LocalDateTime utcWallClock = LocalDateTime.of(2026, 11, 13, 15, 0, 23, 123_000_000);
        for (String value : List.of("2026-11-13T15:00:23.123Z", "2026-11-13T15:00:23.123+00:00",
                "2026-11-13T20:30:23.123+05:30", "2026-11-13T07:00:23.123-08:00",
                "2026-11-13T15:00:23.123-00:00", "2026-11-14T05:00:23.123+14:00", "2026-11-13T01:00:23.123-14:00",
                "2026-11-14T04:59:23.123+13:59", "2026-11-13T01:01:23.123-13:59")) {
            assertEquals(utcWallClock, LegacyW3cDateTimes.localDateTime(value), value);
            // ...and therefore the same proof created, on whatever zone this JVM runs in
            assertEquals(LegacyW3cDateTimes.proofCreated("2026-11-13T15:00:23.123Z"),
                    LegacyW3cDateTimes.proofCreated(value), value);
        }
    }

    /**
     * XML Schema {@code timezoneFrag} stops at {@code ±14:00}; {@code java.time} allows {@code ±18:00} and RFC 3339
     * {@code ±23:59}. A value outside the XML Schema range is refused before anything is signed.
     */
    @Test
    void refusesAnOffsetBeyondFourteenHours() {
        assertDoesNotThrow(() -> LegacyW3cDateTimes.localDateTime("2026-11-13T15:00:23Z".replace("Z", "+14:00")));
        assertDoesNotThrow(() -> LegacyW3cDateTimes.localDateTime("2026-11-13T15:00:23Z".replace("Z", "-14:00")));
        for (String offset : List.of("+14:01", "-14:01", "+14:59", "+15:00", "-15:00", "+18:00", "-18:00", "+23:59",
                "+05:60", "-00:60", "+99:00")) {
            String value = "2026-11-13T15:00:23.123" + offset;
            assertThrows(DateTimeParseException.class, () -> LegacyW3cDateTimes.localDateTime(value), value);
        }
    }

    /**
     * The zone designator is required: VC 2.0's {@code validFrom} is a {@code dateTimeStamp}; for VC 1.1's {@code
     * dateTime} it is Certify's compatibility policy (the former reader required {@code Z}), so a zone-less value is
     * refused before signing rather than read in some assumed zone.
     */
    @Test
    void refusesAValueWithoutAZoneDesignator() {
        for (String value : List.of("2026-11-13T15:00:23.123", "2026-11-13T15:00:23", "1970-01-01T00:00:00.001")) {
            assertThrows(DateTimeParseException.class, () -> LegacyW3cDateTimes.localDateTime(value), value);
        }
    }

    /** The accepted edges of the documented grammar. */
    @Test
    void acceptsTheEdgesOfTheDocumentedGrammar() {
        Map<String, LocalDateTime> edges = new LinkedHashMap<>();
        edges.put("0001-01-01T00:00:00Z", LocalDateTime.of(1, 1, 1, 0, 0));
        edges.put("9999-12-31T23:59:59.999999999Z", LocalDateTime.of(9999, 12, 31, 23, 59, 59, 999_999_999));
        edges.put("2026-11-13T15:00:23.1Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23, 100_000_000));
        edges.put("2026-11-13T15:00:23.000000001Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23, 1));
        edges.put("2024-02-29T00:00:00Z", LocalDateTime.of(2024, 2, 29, 0, 0));
        edges.put("2000-02-29T00:00:00Z", LocalDateTime.of(2000, 2, 29, 0, 0));
        edges.put("2026-11-13T23:59:59Z", LocalDateTime.of(2026, 11, 13, 23, 59, 59));
        edges.put("0001-01-01T00:00:00+14:00", LocalDateTime.of(0, 12, 31, 10, 0));
        edges.forEach((value, expected) -> assertEquals(expected, LegacyW3cDateTimes.localDateTime(value), value));
    }

    /**
     * Each boundary where RFC 3339, XML Schema and this reader differ, on the refusing side (see the class javadoc).
     * None of these was accepted by the former reader either.
     */
    @Test
    void refusesWhatIsOutsideTheDocumentedGrammar() {
        for (String value : List.of(
                // RFC 3339 allows these, XML Schema does not
                "2026-11-13t15:00:23Z", "2026-11-13T15:00:23z", "2026-11-13t15:00:23.123z", "2026-12-31T23:59:60Z",
                "2026-12-31T23:59:60.000Z",
                // XML Schema allows these, this reader does not (documented restrictions)
                "10000-01-01T00:00:00Z", "10000-01-01T00:00:00.000Z", "0000-01-01T00:00:00Z",
                "0000-01-01T00:00:00.000Z", "-0001-01-01T00:00:00Z", "2026-11-13T15:00:23.1234567890Z",
                // neither standard has a signed year
                "+10000-01-01T00:00:00Z", "+2026-11-13T15:00:23Z", "+02026-11-13T15:00:23Z",
                // not a date-time at all, or not this lexical form
                "not-a-date", "2026-11-13", "2026-11-13T15:00", "2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z",
                "2026-11-00T00:00:00Z", "2026-11-32T00:00:00Z", "2026-11-13T25:00:23Z", "2026-11-13T15:60:23Z",
                "2026-11-13T15:00:23.Z", "2026-11-13 15:00:23Z", "2026-11-13T15:00:23+0530",
                "2026-11-13T15:00:23+05:30:15", "2026-11-13T15:00:23+05", "2026-11-13T15:00:23+5:30", "",
                " 2026-11-13T15:00:23Z", "2026-11-13T15:00:23Z ", "2026-11-13T15:00:23Z\n", "2026-1-13T15:00:23Z",
                "２０２６-11-13T15:00:23Z", "٢٠٢٦-11-13T15:00:23Z",
                // an impossible date is refused, not moved to the nearest valid one as SMART did
                "2026-02-29T00:00:00Z", "2100-02-29T00:00:00Z", "2026-02-30T00:00:00Z", "2026-02-31T00:00:00Z",
                "2026-04-31T00:00:00Z", "2026-06-31T00:00:00.000Z")) {
            assertThrows(DateTimeParseException.class, () -> LegacyW3cDateTimes.localDateTime(value), value);
        }
        assertThrows(DateTimeParseException.class, () -> LegacyW3cDateTimes.localDateTime(null));
    }

    /**
     * The only two kinds of value the former reader accepted and this one refuses, both invalid in XML Schema: an
     * impossible date (SMART moved it to the month's last day) and a signed, expanded year. Asserted against the
     * former reader so that the list in the class javadoc stays true.
     */
    @Test
    void refusesOnlyInvalidValuesTheFormerReaderAccepted() {
        Map<String, LocalDateTime> formerlyAccepted = new LinkedHashMap<>();
        formerlyAccepted.put("2026-02-30T00:00:00.000Z", LocalDateTime.of(2026, 2, 28, 0, 0));
        formerlyAccepted.put("2026-04-31T10:00:00.000Z", LocalDateTime.of(2026, 4, 30, 10, 0));
        formerlyAccepted.put("+10000-01-01T00:00:00.000Z", LocalDateTime.of(10000, 1, 1, 0, 0));
        formerlyAccepted.put("+02026-11-13T15:00:23.123Z", LocalDateTime.of(2026, 11, 13, 15, 0, 23, 123_000_000));
        formerlyAccepted.forEach((value, former) -> {
            assertEquals(former, LocalDateTime.parse(value, LEGACY_WRITER), value);
            assertThrows(DateTimeParseException.class, () -> LegacyW3cDateTimes.localDateTime(value), value);
        });
    }

    /** A refusal says where and why, and does not echo an unbounded value into the logs. */
    @Test
    void aRefusalNamesTheIndexAndBoundsTheEchoedValue() {
        DateTimeParseException offset = assertThrows(DateTimeParseException.class,
                () -> LegacyW3cDateTimes.localDateTime("2026-11-13T15:00:23+14:01"));
        assertEquals(19, offset.getErrorIndex());
        DateTimeParseException date = assertThrows(DateTimeParseException.class,
                () -> LegacyW3cDateTimes.localDateTime("2026-02-30T00:00:00Z"));
        assertEquals(5, date.getErrorIndex());
        String longValue = "2026-11-13T15:00:23Z" + "x".repeat(1000);
        DateTimeParseException tooLong = assertThrows(DateTimeParseException.class,
                () -> LegacyW3cDateTimes.localDateTime(longValue));
        assertEquals(longValue, tooLong.getParsedString());
        assertTrue(tooLong.getMessage().length() < 200, tooLong.getMessage());
    }
}
