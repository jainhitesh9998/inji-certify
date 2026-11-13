/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.time.temporal.ChronoField;
import java.util.Date;

/**
 * Reads the date fields of a W3C credential on the compatibility path: {@code issuanceDate} (VC 1.1) and {@code
 * validFrom} (VC 2.0), which the proof's {@code created} is derived from.
 *
 * <p>Two writers in Certify produce these values and every one of their forms must be readable:
 * <ul>
 *   <li>{@link Constants#UTC_DATETIME_PATTERN} ({@code yyyy-MM-dd'T'HH:mm:ss.SSS'Z'}) — the issuance path and the
 *       Bitstring Status List writer always print three fraction digits;</li>
 *   <li>{@link java.time.Instant#toString()} — the status list re-sign writer writes a millisecond instant, so it
 *       <em>omits</em> the fraction when it is zero and otherwise prints three digits; on a finer clock it prints six
 *       or nine. ISO-8601 (and XML Schema dateTime, and RFC 3339) allow all of these, so a re-sign at an instant with
 *       no fraction used to be refused by the legacy strict pattern ("could not be parsed at index 19").</li>
 * </ul>
 *
 * <p>What is read is an RFC 3339 / XML Schema {@code dateTime}:
 * <ul>
 *   <li>{@code yyyy-MM-dd'T'HH:mm:ss}, seconds required (RFC 3339 section 5.6, {@code dateTimeStamp});</li>
 *   <li>an optional fraction of one to nine digits;</li>
 *   <li>a <strong>required</strong> zone designator, {@code Z} or {@code +HH:MM}/{@code -HH:MM} — no offset seconds, as
 *       RFC 3339 has none, and no zone-less value, which both VC 1.1 and VC 2.0 forbid (non-negotiable 2: refuse
 *       before signing, never guess a zone);</li>
 *   <li>resolved {@linkplain ResolverStyle#STRICT strictly}, so an impossible date ({@code 2026-02-30}, {@code
 *       2026-04-31}) or {@code 24:00:00} is refused instead of being moved to the nearest valid day as the SMART
 *       default would.</li>
 * </ul>
 * Anything else is a {@link DateTimeParseException}, as it was before.
 *
 * <p>The value is normalised to UTC first ({@code withOffsetSameInstant(ZoneOffset.UTC)}), so the same instant reads
 * the same whichever offset wrote it; every {@code Z} value is unchanged by that step. The caller then applies the
 * compatibility rule — the UTC wall clock is read in the JVM's default zone, which is exactly what the legacy reader
 * did ({@code LocalDateTime.parse(value, UTC_DATETIME_PATTERN).atZone(ZoneId.systemDefault())}) — so {@code
 * proof.created} stays byte-identical to what every earlier release wrote for a {@code Z} value.
 *
 * <p><strong>Open owner question (G38):</strong> that last rule means a UTC {@code validFrom} becomes {@code created =
 * validFrom - the JVM's offset} (Asia/Kolkata: 5h30 earlier; America/Los_Angeles: 8h later, i.e. in the future at
 * signing time). Data Integrity defines {@code created} as the proof's creation time, and {@code
 * LdpVcFormatter.createdFrom} — the new formatter module — applies the designator correctly. Applying it here as well
 * would change {@code proof.created} on every deployment not on UTC, a wire change on the compatibility surface, so it
 * waits for the owner's decision (CLAUDE.md rule 8) rather than being assumed either way.
 */
public final class LegacyW3cDateTimes {

    /**
     * {@code yyyy-MM-dd'T'HH:mm:ss}, an optional fraction of one to nine digits and a required offset. The date is
     * {@link DateTimeFormatter#ISO_LOCAL_DATE} (proleptic year, so {@link ResolverStyle#STRICT} needs no era), the
     * offset is {@code "+HH:MM"} with {@code Z} for UTC, and no field is lenient.
     */
    private static final DateTimeFormatter DATE_TIME = new DateTimeFormatterBuilder()
            .append(DateTimeFormatter.ISO_LOCAL_DATE)
            .appendLiteral('T')
            .appendValue(ChronoField.HOUR_OF_DAY, 2)
            .appendLiteral(':')
            .appendValue(ChronoField.MINUTE_OF_HOUR, 2)
            .appendLiteral(':')
            .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
            .optionalStart()
            .appendFraction(ChronoField.NANO_OF_SECOND, 1, 9, true)
            .optionalEnd()
            .appendOffset("+HH:MM", "Z")
            .toFormatter()
            .withResolverStyle(ResolverStyle.STRICT);

    private LegacyW3cDateTimes() {
    }

    /**
     * The date-time part of an {@code issuanceDate}/{@code validFrom} value, normalised to UTC, with the zone
     * designator applied.
     *
     * @throws DateTimeParseException if the value is not an RFC 3339 / XML Schema dateTime, has no zone designator, or
     *                                states an impossible date
     */
    public static LocalDateTime localDateTime(String value) {
        if (value == null) {
            throw new DateTimeParseException("No date-time value", "null", 0);
        }
        return OffsetDateTime.parse(value, DATE_TIME).withOffsetSameInstant(ZoneOffset.UTC).toLocalDateTime();
    }

    /**
     * The proof's {@code created} for a credential: its {@code issuanceDate}/{@code validFrom} normalised to UTC and
     * then read as a wall clock in the JVM's default zone, as the compatibility path has always read it (G38).
     * {@link Date} holds milliseconds, so a finer fraction is truncated, exactly as it was before.
     *
     * @throws DateTimeParseException if the value is not an RFC 3339 / XML Schema dateTime, has no zone designator, or
     *                                states an impossible date
     */
    public static Date proofCreated(String value) {
        return Date.from(localDateTime(value).atZone(ZoneId.systemDefault()).toInstant());
    }
}
