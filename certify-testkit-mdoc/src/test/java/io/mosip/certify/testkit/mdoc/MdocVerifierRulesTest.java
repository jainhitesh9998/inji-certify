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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The rules the harness applies itself, each with the value that must pass and the mutations that must fail:
 * ISO/IEC 18013-5 element dates (Table 5, 7.2.4), RFC 5280 serial numbers, the check runner's error handling and the
 * {@code .gaps} sidecar with its problem codes.
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
    void everyWayADateMissesTdateIsItsOwnCode() {
        assertEquals(List.of(), codes(tdate("2026-11-13T10:15:30Z")));
        assertEquals(List.of("fractionalSeconds"), codes(tdate("2026-11-13T10:15:30.123Z")));
        assertEquals(List.of("untagged", "fractionalSeconds"), codes(new Tstr("2026-11-13T10:15:30.123Z")),
                "untagged and milliseconds are two defects: fixing one must not hide the other");
        assertEquals(List.of("fractionalSeconds", "notZulu"), codes(tdate("2026-11-13T10:15:30.5+05:30")));
        assertEquals(List.of("notCalendar"), codes(tdate("2026-02-30T10:15:30Z")));
        assertEquals(List.of("notRfc3339"), codes(tdate("2026-11-13 10:15:30Z")));
        assertEquals(List.of("notTdate", "notRfc3339"), codes(fullDate("2026-11-13")));
        assertEquals(List.of("notTdate"), codes(new Bstr(new byte[] {1})));
    }

    static List<String> codes(DataItem value) {
        return IndependentMdocVerifier.tdateProblems(value).stream().map(VerificationReport.Problem::code).toList();
    }

    @Test
    void multipazValidityFindingsMapOntoTheWireCodes() {
        assertEquals("signedAfterValidFrom", IndependentMdocVerifier.multipazValidityCode(
                "MSO validFrom (2026-01-01T00:00:00Z) must be equal to or later than signed (2026-01-01T00:00:01Z)"));
        assertEquals("expired", IndependentMdocVerifier.multipazValidityCode(
                "MSO is expired (validUntil: 2021-01-01T00:00:00Z, current time: 2026-11-13T00:00:00Z)"));
        assertEquals("notYetValid", IndependentMdocVerifier.multipazValidityCode(
                "MSO is not yet valid (validFrom: 2030-01-01T00:00:00Z, current time: 2026-11-13T00:00:00Z)"));
        assertEquals("expectedUpdateNotBeforeValidUntil", IndependentMdocVerifier.multipazValidityCode(
                "MSO expectedUpdate (2031-01-01T00:00:00Z) is later than validUntil (2030-01-01T00:00:00Z)"));
        assertEquals("validFromNotBeforeValidUntil", IndependentMdocVerifier.multipazValidityCode(
                "MSO validUntil (2020-01-01T00:00:00Z) must be later than validFrom (2021-01-01T00:00:00Z)"));
        assertNull(IndependentMdocVerifier.multipazValidityCode("MSO signed timestamp must not have fractional seconds"));
        assertEquals("multipazRejects", IndependentMdocVerifier.multipazValidityCode("MSO version cannot be empty"));
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
    void everyProblemIsReportedNotTheFirstEachUnderItsOwnCode() {
        Map<String, DataItem> mdl = mdl();
        mdl.remove("portrait");
        mdl.put("birth_date", new Tstr("1990-01-01"));
        mdl.put("not_an_mdl_element", new Tstr("x"));
        List<VerificationReport.Problem> problems = IndependentMdocVerifier.mdlElementProblems(mdl);
        // in the order of Multipaz's DrivingLicense table, then the elements it does not know
        assertEquals(List.of("untyped:birth_date", "missing:portrait", "notInDocType:not_an_mdl_element"),
                problems.stream().map(VerificationReport.Problem::code).toList(), problems.toString());
        assertTrue(problems.get(0).message().contains("birth_date must be full-date"), problems.toString());
        assertTrue(problems.get(1).message().contains("mandatory mDL element portrait is missing"), problems.toString());
        assertTrue(problems.get(2).message().contains("not_an_mdl_element is not in"), problems.toString());
    }

    // ---- RFC 5280 serial numbers ---------------------------------------------------------------------------------

    @Test
    void serialNumbersArePositiveAndAtMostTwentyOctets() throws Exception {
        assertEquals(List.of(), IndependentMdocVerifier.serialNumberProblems(List.of(certificate(BigInteger.ONE),
                certificate(BigInteger.TWO.pow(158)))), "2^158 takes 20 octets");
        assertEquals(List.of("nonPositive"), serialCodes(BigInteger.valueOf(-5)));
        assertEquals(List.of("nonPositive", "zero"), serialCodes(BigInteger.ZERO));
        assertEquals(List.of("tooLong"), serialCodes(BigInteger.TWO.pow(159)), "2^159 needs a sign octet: 21");
        assertTrue(IndependentMdocVerifier.serialNumberProblems(List.of(certificate(BigInteger.valueOf(-5)))).get(0)
                .message().contains("non-positive serial -5"));
    }

    @Test
    void theKeymanagerSerialGapCoversANegativeSerialAndNothingElse() throws Exception {
        // G27: a .gaps file declares x5chain.serialNumber:nonPositive exactly when the received leaf serial is <= 0
        AcceptedGaps g27 = AcceptedGaps.none().gap(IndependentMdocVerifier.CHECK_SERIAL_NUMBER, "nonPositive",
                "G27: keymanager draws negative serials; M-06");
        g27.assertMatches(serialReport(BigInteger.valueOf(-5)), "negative");

        AssertionError zero = assertThrows(AssertionError.class, () -> g27.assertMatches(serialReport(BigInteger.ZERO), "zero"));
        assertTrue(zero.getMessage().contains("not an accepted gap of zero: x5chain.serialNumber:zero"), zero.getMessage());

        AssertionError tooLong = assertThrows(AssertionError.class,
                () -> g27.assertMatches(serialReport(BigInteger.TWO.pow(159)), "long"));
        assertTrue(tooLong.getMessage().contains("not an accepted gap of long: x5chain.serialNumber:tooLong"), tooLong.getMessage());
        assertTrue(tooLong.getMessage().contains("gap no longer present, remove x5chain.serialNumber:nonPositive"),
                tooLong.getMessage());

        AssertionError positive = assertThrows(AssertionError.class,
                () -> g27.assertMatches(serialReport(BigInteger.valueOf(7)), "positive"));
        assertTrue(positive.getMessage().contains("gap no longer present, remove x5chain.serialNumber:nonPositive from "
                + "positive.gaps: x5chain.serialNumber passes now"), positive.getMessage());
    }

    static List<String> serialCodes(BigInteger serial) throws Exception {
        return IndependentMdocVerifier.serialNumberProblems(List.of(certificate(serial))).stream()
                .map(VerificationReport.Problem::code).toList();
    }

    static VerificationReport serialReport(BigInteger serial) throws Exception {
        List<VerificationReport.Problem> problems = IndependentMdocVerifier.serialNumberProblems(List.of(certificate(serial)));
        return new VerificationReport(List.of(problems.isEmpty()
                ? VerificationReport.Check.pass(IndependentMdocVerifier.CHECK_SERIAL_NUMBER, "positive")
                : VerificationReport.Check.fail(IndependentMdocVerifier.CHECK_SERIAL_NUMBER, problems)));
    }

    // ---- the check runner ----------------------------------------------------------------------------------------

    @Test
    void anErrorInACheckIsThatChecksFailure() {
        VerificationReport.Check kotlinTodo = IndependentMdocVerifier.run("x", problems -> {
            throw new kotlin.NotImplementedError("An operation is not implemented.");
        });
        assertEquals(VerificationReport.State.FAIL, kotlinTodo.state());
        assertTrue(kotlinTodo.message().contains("NotImplementedError"));
        assertEquals(List.of(IndependentMdocVerifier.ERROR), kotlinTodo.codes());
        VerificationReport.Check overflow = IndependentMdocVerifier.run("x", problems -> {
            throw new StackOverflowError();
        });
        assertEquals(VerificationReport.State.FAIL, overflow.state());
        assertThrows(OutOfMemoryError.class, () -> IndependentMdocVerifier.run("x", problems -> {
            throw new OutOfMemoryError("no heap left");
        }), "a VM failure leaves nothing to report on and propagates");
    }

    @Test
    void aCheckKeepsWhatItFoundBeforeItThrew() {
        VerificationReport.Check check = IndependentMdocVerifier.run(IndependentMdocVerifier.CHECK_VALIDITY_INFO, problems -> {
            problems.add("expired", "validUntil has passed");
            throw new IllegalStateException("then something broke");
        });
        assertEquals(List.of("expired", IndependentMdocVerifier.ERROR), check.codes());
    }

    @Test
    void aCheckCannotReportAnUnregisteredCode() {
        VerificationReport.Check check = IndependentMdocVerifier.run(IndependentMdocVerifier.CHECK_VALIDITY_INFO, problems -> {
            problems.add("tooLate", "not a registered code");
            return "unreachable";
        });
        assertEquals(List.of(IndependentMdocVerifier.ERROR), check.codes());
        assertTrue(check.message().contains("unregistered problem code mso.validityInfo:tooLate"), check.message());
    }

    // ---- the .gaps sidecar ---------------------------------------------------------------------------------------

    @Test
    void gapsRoundTripAndRefuseLinesWithoutAReasonACodeOrAKnownCheck() {
        AcceptedGaps gaps = AcceptedGaps.none()
                .gap(IndependentMdocVerifier.CHECK_TDATE_TAGS, "fractionalSeconds:signed", "G1: milliseconds; M-02")
                .gap(IndependentMdocVerifier.CHECK_ELEMENT_TYPES, "untyped:birth_date", "G2: untyped; M-03")
                .gap(IndependentMdocVerifier.CHECK_SERIAL_NUMBER, "nonPositive", "G27: random serial sign; M-06");
        AcceptedGaps parsed = AcceptedGaps.parse(gaps.format("s"), "s.gaps");
        assertEquals(gaps.gaps(), parsed.gaps());
        assertTrue(parsed.gaps().containsKey("mdl.elementTypes:untyped:birth_date"));
        assertRefused("mso.validityInfo:expired\n", "no reason");
        assertRefused("mso.validityInfo:expired #   \n", "blank reason");
        assertRefused("mso.noSuchCheck:expired # x\n", "unknown check");
        assertRefused("mso.validityInfo:tooLate # x\n", "unknown code");
        assertRefused("mso.validityInfo:expired:now # x\n", "a code that takes no parameter");
        assertRefused("mdl.elementTypes:untyped # x\n", "a parameterised code without its parameter");
        assertRefused("mso.validityInfo:error # x\n", "an unexpected error is never an accepted gap");
        assertRefused("mso.validityInfo:notRun # x\n", "a check that did not run is never an accepted gap");
        assertRefused("mso.docType:mismatch # a\nmso.docType:mismatch # b\n", "twice");
        IllegalArgumentException bare = assertThrows(IllegalArgumentException.class,
                () -> AcceptedGaps.parse("mso.validityInfo # G8\n", "s.gaps"));
        assertTrue(bare.getMessage().contains("names a whole check"), bare.getMessage());
        IllegalArgumentException optional = assertThrows(IllegalArgumentException.class,
                () -> AcceptedGaps.parse("x5chain.serialNumber? # G27\n", "s.gaps"));
        assertTrue(optional.getMessage().contains("'?' is gone"), optional.getMessage());
    }

    static void assertRefused(String text, String why) {
        assertThrows(IllegalArgumentException.class, () -> AcceptedGaps.parse(text, "s.gaps"), why);
    }

    @Test
    void theReportMustMatchTheDeclaredCodesExactly() {
        VerificationReport report = new VerificationReport(List.of(
                VerificationReport.Check.pass(IndependentMdocVerifier.CHECK_DOC_TYPE, "ok"),
                VerificationReport.Check.fail(IndependentMdocVerifier.CHECK_TDATE_TAGS, "fractionalSeconds:signed", "milliseconds")));
        AcceptedGaps exact = AcceptedGaps.none().gap(IndependentMdocVerifier.CHECK_TDATE_TAGS, "fractionalSeconds:signed", "G1");
        exact.assertMatches(report, "s");

        AssertionError stale = assertThrows(AssertionError.class, () -> exact
                .gap(IndependentMdocVerifier.CHECK_DOC_TYPE, "mismatch", "old").assertMatches(report, "s"));
        assertTrue(stale.getMessage().contains("gap no longer present, remove mso.docType:mismatch from s.gaps: "
                + "mso.docType passes now"), stale.getMessage());

        AssertionError unlisted = assertThrows(AssertionError.class, () -> AcceptedGaps.none().assertMatches(report, "s"));
        assertTrue(unlisted.getMessage().contains("not an accepted gap of s: mso.validityInfo.tdateTags:fractionalSeconds:signed"),
                unlisted.getMessage());
    }

    @Test
    void aDeclaredCodeCannotHideAnotherProblemOfTheSameCheck() {
        // the review's finding: with "mso.validityInfo" accepted as a whole, an expired re-signed credential passed
        VerificationReport report = new VerificationReport(List.of(VerificationReport.Check.fail(
                IndependentMdocVerifier.CHECK_VALIDITY_INFO, List.of(
                        new VerificationReport.Problem("signedAfterValidFrom", "signed after validFrom"),
                        new VerificationReport.Problem("expired", "validUntil has passed")))));
        AcceptedGaps g8 = AcceptedGaps.none().gap(IndependentMdocVerifier.CHECK_VALIDITY_INFO, "signedAfterValidFrom", "G8");
        AssertionError expired = assertThrows(AssertionError.class, () -> g8.assertMatches(report, "s"));
        assertTrue(expired.getMessage().contains("not an accepted gap of s: mso.validityInfo:expired"), expired.getMessage());

        AssertionError other = assertThrows(AssertionError.class, () -> AcceptedGaps.none()
                .gap(IndependentMdocVerifier.CHECK_VALIDITY_INFO, "expired", "x")
                .gap(IndependentMdocVerifier.CHECK_VALIDITY_INFO, "notYetValid", "y").assertMatches(report, "s"));
        assertTrue(other.getMessage().contains("gap no longer present, remove mso.validityInfo:notYetValid from s.gaps: "
                + "mso.validityInfo reports [signedAfterValidFrom, expired]"), other.getMessage());
    }

    @Test
    void aSkippedCheckIsNeverCoveredByAGap() {
        VerificationReport report = new VerificationReport(List.of(
                VerificationReport.Check.skipped(IndependentMdocVerifier.CHECK_ELEMENT_TYPES, "not an mDL")));
        AssertionError skipped = assertThrows(AssertionError.class, () -> AcceptedGaps.none().assertMatches(report, "s"));
        assertTrue(skipped.getMessage().contains("a gap cannot cover a check that did not run"), skipped.getMessage());
    }

    @Test
    void everyRegisteredCodeIsAValidGapAndEveryCheckHasCodes() {
        assertEquals(IndependentMdocVerifier.CHECKS, List.copyOf(IndependentMdocVerifier.PROBLEM_CODES.keySet()));
        IndependentMdocVerifier.PROBLEM_CODES.forEach((check, codes) -> {
            assertFalse(codes.isEmpty(), check);
            for (String code : codes) {
                String example = code.endsWith(":*") ? code.substring(0, code.length() - 1) + "x" : code;
                assertTrue(IndependentMdocVerifier.isProblemCode(check, example), check + ":" + example);
            }
        });
        assertEquals("org.iso.18013.5.1/family_name", IndependentMdocVerifier.parameter("org.iso.18013.5.1/family_name"));
        assertEquals("a_b_", IndependentMdocVerifier.parameter("a b\u00e9"));
    }

    // ---- fixtures ------------------------------------------------------------------------------------------------

    static void assertProblem(String identifier, DataItem value, String expected) {
        Map<String, DataItem> mdl = mdl();
        mdl.put(identifier, value);
        List<VerificationReport.Problem> problems = IndependentMdocVerifier.mdlElementProblems(mdl);
        assertEquals(1, problems.size(), identifier + " -> " + problems);
        assertEquals("untyped:" + identifier, problems.get(0).code(), problems.toString());
        assertTrue(problems.get(0).message().contains(expected), "expected \"" + expected + "\" in " + problems);
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
