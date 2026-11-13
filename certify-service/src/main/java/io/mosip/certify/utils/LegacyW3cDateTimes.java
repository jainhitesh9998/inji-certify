/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;

import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the date fields of a W3C credential on the compatibility path: {@code issuanceDate} (VC 1.1) and {@code
 * validFrom} (VC 2.0), which the proof's {@code created} is derived from.
 *
 * <p>Two writers in Certify produce these values and every one of their forms must be readable:
 * <ul>
 *   <li>{@link Constants#UTC_DATETIME_PATTERN} ({@code yyyy-MM-dd'T'HH:mm:ss.SSS'Z'}) — the issuance path and the
 *       Bitstring Status List writer always print three fraction digits;</li>
 *   <li>{@link java.time.Instant#toString()} — the status list re-sign writer writes a millisecond instant, so it
 *       <em>omits</em> the fraction when it is zero and otherwise prints three digits (six or nine on a finer clock).
 *       The former reader ({@code LocalDateTime.parse(value, UTC_DATETIME_PATTERN)}, SMART) refused the form without a
 *       fraction ("could not be parsed at index 19"), which is the bug F-19 fixes.</li>
 * </ul>
 * Both always end in {@code Z}, and so does every value in the goldens and the shipped templates
 * ({@code ${validFrom}} is the first writer's value).
 *
 * <h2>Accepted grammar</h2>
 * The XML Schema 1.1 Part 2 {@code dateTimeStamp} lexical space (section 3.4.28: {@code dateTime} with a required
 * time zone), restricted as stated below; nothing else is read. Every restriction is a form the former reader refused
 * as well, so nothing it accepted is lost except values that are invalid in XML Schema (see "Compared with the former
 * reader").
 * <pre>
 * value    = year "-" month "-" day "T" ( time / end-of-day ) zone
 * year     = 4DIGIT                     ; 0001-9999, no sign
 * month    = 2DIGIT                     ; 01-12
 * day      = 2DIGIT                     ; 01-28/29/30/31 for that month and year (an impossible date is refused)
 * time     = hour ":" minute ":" second [ "." 1*9DIGIT ]
 * hour     = 2DIGIT                     ; 00-23
 * minute   = 2DIGIT                     ; 00-59
 * second   = 2DIGIT                     ; 00-59, no leap second
 * end-of-day = "24:00:00" [ "." 1*9"0" ] ; the first instant of the next day
 * zone     = "Z" / ( "+" / "-" ) hh ":" mm   ; hh:mm from 00:00 to 14:00, "-00:00" = "Z"
 * </pre>
 * Upper-case {@code T} and {@code Z} only; ASCII digits only; no surrounding white space.
 *
 * <p>Where this differs from the two standards the validity fields are defined by:
 * <ul>
 *   <li><b>XML Schema {@code dateTime}/{@code dateTimeStamp}</b> (VC 1.1 types {@code issuanceDate} as {@code
 *       dateTime}; VC 2.0 section 4.9 requires {@code validFrom} to be a {@code dateTimeStamp}). Refused here although
 *       XML Schema allows them: a year of five or more digits ({@code 10000-01-01T00:00:00Z}) — Certify's writers and
 *       goldens never produce one; the year {@code 0000} and negative years — the former reader refused them (its
 *       {@code yyyy} is a year-of-era, at least 1); a fraction of more than nine digits — {@code java.time} holds
 *       nanoseconds and the value is not silently cut before it is read. A missing time zone is allowed by {@code
 *       dateTime} but refused here: for VC 2.0 that is the {@code dateTimeStamp} rule, for VC 1.1 it is Certify's
 *       compatibility policy (the former reader required {@code Z}; a value without a zone names no instant, and
 *       non-negotiable 2 refuses it before signing rather than guessing one), not a {@code dateTime} requirement.</li>
 *   <li><b>RFC 3339 section 5.6</b>. Refused here although RFC 3339 allows them, because XML Schema does not: a
 *       lower-case {@code t} or {@code z}; a leap second {@code :60}; an offset beyond {@code ±14:00} (RFC 3339 allows
 *       up to {@code ±23:59}). Accepted here although RFC 3339 does not allow it: {@code 24:00:00}, which RFC 3339's
 *       {@code time-hour} (00-23) excludes; every other accepted value is also an RFC 3339 {@code date-time}. RFC 3339
 *       gives {@code -00:00} the meaning "offset unknown"; XML Schema, and this reader, read it as UTC.</li>
 *   <li>An expanded year with a sign ({@code +10000-...}, {@code +02026-...}) is neither: XML Schema has no {@code +}
 *       and RFC 3339 has four-digit years only. The former reader accepted it ({@code yyyy} parses a {@code +} with five
 *       or more digits); it is refused here.</li>
 * </ul>
 *
 * <h2>Compared with the former reader</h2>
 * The former reader accepted exactly {@code yyyy-MM-dd'T'HH:mm:ss.SSS'Z'} under {@link
 * java.time.format.ResolverStyle#SMART}. Every such value reads to the same {@code LocalDateTime} here, including
 * the end of day {@code 24:00:00.000Z} (the next day's {@code 00:00}, which SMART and XML Schema agree on), except:
 * <ul>
 *   <li>an impossible date ({@code 2026-02-30}, {@code 2026-04-31}), which SMART moved to the last day of the month and
 *       which is not a date at all — refused;</li>
 *   <li>a signed, expanded year ({@code +10000}, {@code +02026}), invalid in XML Schema and RFC 3339 — refused.</li>
 * </ul>
 * Newly accepted, as valid {@code dateTimeStamp} values: no fraction, or one to nine fraction digits; a numeric offset
 * from {@code -14:00} to {@code +14:00}; {@code 24:00:00} without a fraction or with any number (up to nine) of zeros.
 * A refused value is a {@link DateTimeParseException}, as it was before.
 *
 * <h2>Zones</h2>
 * {@link #localDateTime} applies the value's own zone designator — it returns the UTC wall clock of the instant the
 * value names ({@code withOffsetSameInstant(ZoneOffset.UTC)}), so the same instant reads the same whichever offset
 * wrote it, and every {@code Z} value is unchanged by that step. It applies no JVM zone. The ledger stores exactly
 * that zone-less UTC wall clock ({@code CertifyIssuanceServiceImpl}, {@code ledger.issuance_date}).
 *
 * <p>{@link #proofCreated} — and only it — then applies the legacy rule of {@code W3CJsonLD.addProof}: that UTC wall
 * clock is read in the JVM's default zone ({@code .atZone(ZoneId.systemDefault())}), exactly what the former {@code
 * LocalDateTime.parse(value, UTC_DATETIME_PATTERN).atZone(ZoneId.systemDefault())} did, so {@code proof.created} stays
 * what every earlier release wrote for a {@code Z} value on any JVM zone.
 *
 * <p><strong>Open owner question (G38):</strong> that rule makes the proof's {@code created} = {@code validFrom} - the
 * JVM's offset (Asia/Kolkata: 5h30 earlier; America/Los_Angeles: 8h later, i.e. in the future at signing time). Data
 * Integrity defines {@code created} as the proof's creation time, and {@code LdpVcFormatter.createdFrom} — the new
 * formatter module — applies the designator correctly. On a UTC JVM the two agree. On any other JVM zone, applying the
 * designator here would change {@code created}, and with it the signed proof options and the signature bytes, of
 * every credential and status list those deployments sign on the compatibility path; it waits for the owner's decision
 * (CLAUDE.md rule 8) rather than being assumed either way.
 */
public final class LegacyW3cDateTimes {

    /**
     * The grammar above, before range checks. Groups: 1 year, 2 month, 3 day, 4 hour, 5 minute, 6 second, 7 fraction
     * (absent if none), 8 {@code Z} (absent for a numeric offset), 9 offset sign, 10 offset hours, 11 offset minutes.
     * {@code \d} is ASCII {@code [0-9]} ({@code UNICODE_CHARACTER_CLASS} is not set).
     */
    private static final Pattern DATE_TIME_STAMP = Pattern.compile(
            "(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:\\.(\\d{1,9}))?(?:(Z)|([+-])(\\d{2}):(\\d{2}))");

    /** XML Schema {@code timezoneFrag}: {@code -14:00} to {@code +14:00}. */
    private static final int MAX_OFFSET_MINUTES = 14 * 60;

    private LegacyW3cDateTimes() {
    }

    /**
     * The UTC wall clock of the instant an {@code issuanceDate}/{@code validFrom} value names: its own zone designator
     * applied, no JVM zone applied.
     *
     * @throws DateTimeParseException if the value is not in the grammar of this class: not a {@code dateTimeStamp},
     *                                no zone designator, an impossible date or time, an offset beyond {@code ±14:00},
     *                                or one of the restrictions listed above
     */
    public static LocalDateTime localDateTime(String value) {
        if (value == null) {
            throw new DateTimeParseException("No date-time value", "null", 0);
        }
        Matcher m = DATE_TIME_STAMP.matcher(value);
        if (!m.matches()) {
            throw refused(value, 0, "not yyyy-MM-ddTHH:mm:ss[.1-9 digits] followed by Z or ±hh:mm", null);
        }
        int year = Integer.parseInt(m.group(1));
        if (year == 0) {
            throw refused(value, m.start(1), "year 0000 is outside 0001-9999", null);
        }
        LocalDate date;
        try {
            date = LocalDate.of(year, Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)));
        } catch (DateTimeException e) {
            throw refused(value, m.start(2), e.getMessage(), e);
        }
        int hour = Integer.parseInt(m.group(4));
        int minute = Integer.parseInt(m.group(5));
        int second = Integer.parseInt(m.group(6));
        String fraction = m.group(7);
        int nano = fraction == null ? 0 : Integer.parseInt((fraction + "00000000").substring(0, 9));
        LocalDateTime local;
        if (hour == 24 && minute == 0 && second == 0 && nano == 0) {
            // XML Schema endOfDayFrag "24:00:00" ('.' '0'+)?: the first instant of the next day, in the value's own
            // zone. The former SMART reader read 24:00:00.000Z the same way; STRICT alone would refuse it.
            local = date.plusDays(1).atStartOfDay();
        } else {
            try {
                local = LocalDateTime.of(date, LocalTime.of(hour, minute, second, nano));
            } catch (DateTimeException e) {
                throw refused(value, m.start(4), e.getMessage(), e);
            }
        }
        return OffsetDateTime.of(local, offset(value, m)).withOffsetSameInstant(ZoneOffset.UTC).toLocalDateTime();
    }

    /**
     * The proof's {@code created} for a credential on the compatibility path: {@link #localDateTime} read as a wall
     * clock in the JVM's default zone, as {@code W3CJsonLD.addProof} has always read it (G38). {@link Date} holds
     * milliseconds, so a finer fraction is truncated, exactly as before.
     *
     * @throws DateTimeParseException as {@link #localDateTime}
     */
    public static Date proofCreated(String value) {
        return Date.from(localDateTime(value).atZone(ZoneId.systemDefault()).toInstant());
    }

    private static ZoneOffset offset(String value, Matcher m) {
        if (m.group(8) != null) {
            return ZoneOffset.UTC;
        }
        int hours = Integer.parseInt(m.group(10));
        int minutes = Integer.parseInt(m.group(11));
        if (minutes > 59 || hours * 60 + minutes > MAX_OFFSET_MINUTES) {
            throw refused(value, m.start(9), "zone offset outside -14:00..+14:00", null);
        }
        int sign = "-".equals(m.group(9)) ? -1 : 1;
        return ZoneOffset.ofHoursMinutes(sign * hours, sign * minutes);
    }

    private static DateTimeParseException refused(String value, int index, String reason, Throwable cause) {
        String shown = value.length() > 64 ? value.substring(0, 64) + "..." : value;
        return new DateTimeParseException("Text '" + shown + "' could not be parsed at index " + index + ": " + reason,
                value, index, cause);
    }
}
