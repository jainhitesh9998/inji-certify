/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
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
 * A Velocity template or a plugin may also supply any RFC 3339 / XML Schema dateTime, so fractional seconds of one
 * to nine digits and an offset designator ({@code Z}, {@code +hh:mm}) are read as well. Anything else — a malformed
 * date, a missing time, more than nine fraction digits — is still a {@link DateTimeParseException}, because a
 * credential's validity field that cannot be read is a refusal, not a guess.
 *
 * <p><strong>The designator is validated but not applied.</strong> The wall clock is read in the JVM's default zone,
 * which is exactly what the legacy reader did ({@code LocalDateTime.parse(value, UTC_DATETIME_PATTERN)
 * .atZone(ZoneId.systemDefault())}) for every {@code ...SSS'Z'} value Certify has ever written. Applying the designator
 * instead would move {@code proof.created} — and therefore the signature — for every deployment whose JVM is not on
 * UTC, which is a wire change on the compatibility surface and a decision for the owner (rule 1 and rule 3 of
 * {@code CLAUDE.md}); {@code LdpVcFormatter.createdFrom}, the new formatter module, already reads the designator as
 * UTC, and the two paths agree on a UTC JVM. Reading the wall clock also keeps a credential's {@code created} equal
 * whichever of the two writer forms its validity field happens to carry, which is what F-19 fixes.
 */
public final class LegacyW3cDateTimes {

    /**
     * {@code yyyy-MM-dd'T'HH:mm:ss}, an <em>optional</em> fraction of a second of 1 to 9 digits, and an optional offset.
     * RFC 3339 and XML Schema dateTime both require the seconds, so a bare {@code HH:mm} is refused; the offset is
     * parsed so that a malformed or unknown designator is refused too, and then dropped (see the class note).
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
            .optionalStart()
            .appendOffsetId()
            .optionalEnd()
            .toFormatter();

    private LegacyW3cDateTimes() {
    }

    /**
     * The date-time part of an {@code issuanceDate}/{@code validFrom} value, as the credential states it.
     *
     * @throws DateTimeParseException if the value is not an RFC 3339 / XML Schema dateTime
     */
    public static LocalDateTime localDateTime(String value) {
        if (value == null) {
            throw new DateTimeParseException("No date-time value", "null", 0);
        }
        return LocalDateTime.parse(value, DATE_TIME);
    }

    /**
     * The proof's {@code created} for a credential: its {@code issuanceDate}/{@code validFrom} read as a wall clock in
     * the JVM's default zone, as the compatibility path has always read it. {@link Date} holds milliseconds, so a
     * fraction finer than that is truncated, exactly as it was before.
     *
     * @throws DateTimeParseException if the value is not an RFC 3339 / XML Schema dateTime
     */
    public static Date proofCreated(String value) {
        return Date.from(localDateTime(value).atZone(ZoneId.systemDefault()).toInstant());
    }
}
