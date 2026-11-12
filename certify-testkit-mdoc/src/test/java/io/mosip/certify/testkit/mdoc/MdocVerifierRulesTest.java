/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.multipaz.cbor.Bstr;
import org.multipaz.cbor.Cbor;
import org.multipaz.cbor.CborArray;
import org.multipaz.cbor.CborMap;
import org.multipaz.cbor.DataItem;
import org.multipaz.cbor.Tagged;
import org.multipaz.cbor.Tstr;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The rules the harness applies itself, each with the value that must pass and the mutations that must fail:
 * ISO/IEC 18013-5 element dates (Table 5, 7.2.4), RFC 5280 serial numbers, the check runner's error handling and the
 * {@code .gaps} sidecar.
 */
class MdocVerifierRulesTest {

    // ---- dates ---------------------------------------------------------------------------------------------------

    @Test
    void tdateIsTagZeroOverAWholeSecondRfc3339InstantInUtc() {
        assertNull(IndependentMdocVerifier.tdateProblem(tdate("2026-11-13T10:15:30Z")));
        assertNotNull(IndependentMdocVerifier.tdateProblem(tdate("2026-11-13T10:15:30.123Z")), "fractional seconds");
        assertNotNull(IndependentMdocVerifier.tdateProblem(tdate("2026-11-13T10:15:30+05:30")), "an offset other than Z");
        assertNotNull(IndependentMdocVerifier.tdateProblem(tdate("2026-02-30T10:15:30Z")), "no 30 February");
        assertNotNull(IndependentMdocVerifier.tdateProblem(tdate("2026-11-13T25:15:30Z")), "no hour 25");
        assertNotNull(IndependentMdocVerifier.tdateProblem(new Tstr("2026-11-13T10:15:30Z")), "untagged");
        assertNotNull(IndependentMdocVerifier.tdateProblem(fullDate("2026-11-13")), "tag 1004 is not a tdate");
    }

    @Test
    void fullDateIsTag1004OverAStrictCalendarDate() {
        assertNull(IndependentMdocVerifier.fullDateProblem(fullDate("2026-01-31")));
        assertNotNull(IndependentMdocVerifier.fullDateProblem(fullDate("2026-99-99")), "month 99");
        assertNotNull(IndependentMdocVerifier.fullDateProblem(fullDate("2026-02-30")), "no 30 February");
        assertNotNull(IndependentMdocVerifier.fullDateProblem(fullDate("26-01-31")), "two-digit year");
        assertNotNull(IndependentMdocVerifier.fullDateProblem(new Tstr("2026-01-31")), "untagged");
        assertNotNull(IndependentMdocVerifier.fullDateProblem(tdate("2026-01-31T00:00:00Z")), "a tdate is not a full-date");
    }

    @Test
    void aCompleteMdlPassesWithIssueAndExpiryDateAsEitherDateType() {
        Map<String, DataItem> mdl = mdl();
        assertEquals(List.of(), IndependentMdocVerifier.mdlElementProblems(mdl), "full-date issue/expiry dates");
        mdl.put("issue_date", tdate("2026-01-01T09:00:00Z"));
        mdl.put("expiry_date", tdate("2031-01-01T09:00:00Z"));
        assertEquals(List.of(), IndependentMdocVerifier.mdlElementProblems(mdl), "Table 5: issue_date and expiry_date may be tdate");
    }

    @Test
    void elementDateMutationsFail() {
        assertProblem("expiry_date", fullDate("2026-99-99"), "expiry_date must be full-date or tdate");
        assertProblem("issue_date", tdate("2026-01-01T09:00:00.5Z"), "issue_date must be full-date or tdate");
        assertProblem("issue_date", new Tstr("2026-01-01"), "issue_date must be full-date or tdate");
        assertProblem("birth_date", tdate("1990-01-01T00:00:00Z"), "birth_date must be full-date");
        assertProblem("birth_date", fullDate("1990-13-01"), "birth_date must be full-date");
        assertProblem("portrait_capture_date", fullDate("2026-01-01"), "portrait_capture_date must be tdate");
        assertProblem("portrait_capture_date", tdate("2026-01-01T10:00:00.000Z"), "portrait_capture_date must be tdate");
    }

    @Test
    void portraitCaptureDateIsATdate() {
        Map<String, DataItem> mdl = mdl();
        mdl.put("portrait_capture_date", tdate("2026-01-01T10:00:00Z"));
        assertEquals(List.of(), IndependentMdocVerifier.mdlElementProblems(mdl));
    }

    @Test
    void drivingPrivilegesFollow724() {
        assertProblem("driving_privileges", privileges(Map.of("vehicle_category_code", new Tstr("B"),
                "issue_date", tdate("2026-01-01T00:00:00Z"))), "driving_privileges[0].issue_date must be full-date");
        assertProblem("driving_privileges", privileges(Map.of("issue_date", fullDate("2026-01-01"))),
                "driving_privileges[0].vehicle_category_code is missing");
        assertProblem("driving_privileges", privileges(Map.of("vehicle_category_code", new Tstr("B"),
                "codes", new CborArray(List.of(map(Map.of("sign", new Tstr("=")))), false))), "codes[0].code is missing");
        assertProblem("driving_privileges", new CborArray(List.of(), false), "non-empty array");
    }

    @Test
    void everyProblemIsReportedNotTheFirst() {
        Map<String, DataItem> mdl = mdl();
        mdl.remove("portrait");
        mdl.put("birth_date", new Tstr("1990-01-01"));
        mdl.put("not_an_mdl_element", new Tstr("x"));
        List<String> problems = IndependentMdocVerifier.mdlElementProblems(mdl);
        assertEquals(3, problems.size(), problems.toString());
        assertTrue(problems.stream().anyMatch(p -> p.contains("mandatory mDL element portrait is missing")), problems.toString());
        assertTrue(problems.stream().anyMatch(p -> p.contains("birth_date must be full-date")), problems.toString());
        assertTrue(problems.stream().anyMatch(p -> p.contains("not_an_mdl_element is not in")), problems.toString());
    }

    // ---- RFC 5280 serial numbers ---------------------------------------------------------------------------------

    @Test
    void serialNumbersArePositiveAndAtMostTwentyOctets() throws Exception {
        assertEquals(List.of(), IndependentMdocVerifier.serialNumberProblems(List.of(certificate(BigInteger.ONE),
                certificate(BigInteger.TWO.pow(158)))), "2^158 takes 20 octets");
        assertTrue(IndependentMdocVerifier.serialNumberProblems(List.of(certificate(BigInteger.valueOf(-5)))).get(0)
                .contains("non-positive serial -5"));
        assertTrue(IndependentMdocVerifier.serialNumberProblems(List.of(certificate(BigInteger.TWO.pow(159)))).get(0)
                .contains("21 octets"), "2^159 needs a sign octet: 21");
    }

    // ---- the check runner ----------------------------------------------------------------------------------------

    @Test
    void anErrorInACheckIsThatChecksFailure() {
        VerificationReport.Check kotlinTodo = IndependentMdocVerifier.run("x", () -> {
            throw new kotlin.NotImplementedError("An operation is not implemented.");
        });
        assertEquals(VerificationReport.State.FAIL, kotlinTodo.state());
        assertTrue(kotlinTodo.message().contains("NotImplementedError"));
        VerificationReport.Check overflow = IndependentMdocVerifier.run("x", () -> {
            throw new StackOverflowError();
        });
        assertEquals(VerificationReport.State.FAIL, overflow.state());
        assertThrows(OutOfMemoryError.class, () -> IndependentMdocVerifier.run("x", () -> {
            throw new OutOfMemoryError("no heap left");
        }), "a VM failure leaves nothing to report on and propagates");
    }

    // ---- the .gaps sidecar ---------------------------------------------------------------------------------------

    @Test
    void gapsRoundTripAndRefuseLinesWithoutAReasonOrAKnownCheck() {
        AcceptedGaps gaps = AcceptedGaps.none()
                .gap(IndependentMdocVerifier.CHECK_TDATE_TAGS, "G1: milliseconds; M-02")
                .intermittent(IndependentMdocVerifier.CHECK_SERIAL_NUMBER, "G27: random serial sign; M-06");
        AcceptedGaps parsed = AcceptedGaps.parse(gaps.format("s"), "s.gaps");
        assertEquals(gaps.gaps(), parsed.gaps());
        assertTrue(parsed.gaps().get(IndependentMdocVerifier.CHECK_SERIAL_NUMBER).intermittent());
        assertThrows(IllegalArgumentException.class, () -> AcceptedGaps.parse("mso.validityInfo\n", "s.gaps"), "no reason");
        assertThrows(IllegalArgumentException.class, () -> AcceptedGaps.parse("mso.validityInfo #   \n", "s.gaps"), "blank reason");
        assertThrows(IllegalArgumentException.class, () -> AcceptedGaps.parse("mso.noSuchCheck # x\n", "s.gaps"), "unknown check");
        assertThrows(IllegalArgumentException.class, () -> AcceptedGaps.parse("mso.docType # a\nmso.docType # b\n", "s.gaps"), "twice");
    }

    @Test
    void theReportMustMatchTheDeclaredGapsExactly() {
        VerificationReport report = new VerificationReport(List.of(
                VerificationReport.Check.pass(IndependentMdocVerifier.CHECK_DOC_TYPE, "ok"),
                VerificationReport.Check.fail(IndependentMdocVerifier.CHECK_TDATE_TAGS, "milliseconds"),
                VerificationReport.Check.pass(IndependentMdocVerifier.CHECK_SERIAL_NUMBER, "positive this run")));
        AcceptedGaps exact = AcceptedGaps.none().gap(IndependentMdocVerifier.CHECK_TDATE_TAGS, "G1")
                .intermittent(IndependentMdocVerifier.CHECK_SERIAL_NUMBER, "G27");
        exact.assertMatches(report, "s");

        AssertionError stale = assertThrows(AssertionError.class, () -> exact.gap(IndependentMdocVerifier.CHECK_DOC_TYPE, "old")
                .assertMatches(report, "s"));
        assertTrue(stale.getMessage().contains("gap no longer present, remove it from s.gaps: mso.docType"), stale.getMessage());

        AssertionError unlisted = assertThrows(AssertionError.class, () -> AcceptedGaps.none().assertMatches(report, "s"));
        assertTrue(unlisted.getMessage().contains("not an accepted gap of s: FAIL mso.validityInfo.tdateTags"), unlisted.getMessage());
    }

    // ---- fixtures ------------------------------------------------------------------------------------------------

    static void assertProblem(String identifier, DataItem value, String expected) {
        Map<String, DataItem> mdl = mdl();
        mdl.put(identifier, value);
        List<String> problems = IndependentMdocVerifier.mdlElementProblems(mdl);
        assertEquals(1, problems.size(), identifier + " -> " + problems);
        assertTrue(problems.get(0).contains(expected), "expected \"" + expected + "\" in " + problems);
    }

    /** Every Table 5 mandatory element of org.iso.18013.5.1, correctly typed. */
    static Map<String, DataItem> mdl() {
        Map<String, DataItem> mdl = new LinkedHashMap<>();
        mdl.put("family_name", new Tstr("Demo"));
        mdl.put("given_name", new Tstr("Test"));
        mdl.put("birth_date", fullDate("1990-01-01"));
        mdl.put("issue_date", fullDate("2026-01-01"));
        mdl.put("expiry_date", fullDate("2031-01-01"));
        mdl.put("issuing_country", new Tstr("IN"));
        mdl.put("issuing_authority", new Tstr("Lorem Ipsum Demo Issuing Authority"));
        mdl.put("document_number", new Tstr("DL-0001"));
        mdl.put("portrait", new Bstr(new byte[] {(byte) 0xff, (byte) 0xd8, (byte) 0xff}));
        mdl.put("driving_privileges", privileges(Map.of("vehicle_category_code", new Tstr("B"),
                "issue_date", fullDate("2026-01-01"), "expiry_date", fullDate("2031-01-01"),
                "codes", new CborArray(List.of(map(Map.of("code", new Tstr("B1"), "sign", new Tstr("="), "value", new Tstr("1")))), false))));
        mdl.put("un_distinguishing_sign", new Tstr("IND"));
        mdl.put("age_over_18", Cbor.INSTANCE.decode(new byte[] {(byte) 0xf5}));
        mdl.put("age_in_years", Cbor.INSTANCE.decode(new byte[] {0x18, 0x24}));
        return mdl;
    }

    static DataItem privileges(Map<String, DataItem> privilege) {
        return new CborArray(List.of(map(privilege)), false);
    }

    static DataItem map(Map<String, DataItem> entries) {
        Map<DataItem, DataItem> map = new LinkedHashMap<>();
        entries.forEach((key, value) -> map.put(new Tstr(key), value));
        return new CborMap(map, false);
    }

    static DataItem tdate(String text) {
        return new Tagged(Tagged.DATE_TIME_STRING, new Tstr(text));
    }

    static DataItem fullDate(String text) {
        return new Tagged(Tagged.FULL_DATE_STRING, new Tstr(text));
    }

    static X509Certificate certificate(BigInteger serial) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=serial " + serial.bitLength());
        Instant now = Instant.now();
        return new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(name, serial,
                Date.from(now.minusSeconds(60)), Date.from(now.plusSeconds(3600)), name, keys.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }
}
