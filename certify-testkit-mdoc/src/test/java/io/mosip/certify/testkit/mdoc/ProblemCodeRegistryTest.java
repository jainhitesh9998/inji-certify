/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.testkit.mdoc;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One {@code .gaps} sidecar serves both verifiers, so both must know the same check names and problem codes:
 * {@code docs/design/tools/verify_mdoc.py} carries the table between its {@code BEGIN/END PROBLEM CODES} markers as a
 * JSON-compatible literal, and this test holds it to {@link IndependentMdocVerifier#PROBLEM_CODES}, order included.
 */
class ProblemCodeRegistryTest {

    static final Path VERIFY_MDOC = Path.of("..", "docs", "design", "tools", "verify_mdoc.py");
    static final Pattern BLOCK = Pattern.compile("# BEGIN PROBLEM CODES[^\\n]*\\nPROBLEM_CODES = (\\{.*?\\n})\\n# END PROBLEM CODES",
            Pattern.DOTALL);
    static final Pattern KEY = Pattern.compile("^\\s*\"([^\"]+)\":", Pattern.MULTILINE);

    /**
     * The M-11b table (docs/design/wp/M-11-status-list-under-iaca.md, "Checks and problem codes"), transcribed: the
     * status-list verifier's registry must be exactly this, in this order, so a code added or dropped without the
     * table (and, from M-11f, {@code verify_status_list.py}) changing fails here. This is separate from the mDoc
     * registry above on purpose: those codes belong to {@code .gaps}, these to the status list a sample carries.
     */
    @Test
    void theStatusListVerifierListsTheM11bTable() {
        Map<String, List<String>> expected = new LinkedHashMap<>();
        expected.put("statusList.mso", List.of("malformed"));
        expected.put("statusList.http", List.of("contentType"));
        expected.put("statusList.envelope", List.of("notTagged18", "cwtTag61", "mac0", "detachedPayload"));
        expected.put("statusList.typ", List.of("missing", "unprotected", "notText", "wrong"));
        expected.put("statusList.x5chain", List.of("missing", "unprotectedOnly", "carriesAnchor", "serialNumber"));
        expected.put("statusList.signature", List.of("invalid:multipaz", "invalid:authlete"));
        expected.put("statusList.chain", List.of("untrusted", "noAnchorSupplied"));
        expected.put("statusList.issuanceChain", List.of("differs"));
        expected.put("statusList.claims", List.of("subMismatch", "iatMissing", "iatFuture", "iatAfterExp", "expMissing",
                "expired", "expAfterSigner", "ttlInvalid"));
        expected.put("statusList.list", List.of("missing", "bitsNotOne", "lstNotZlib", "idxOutOfRange",
                "statusMismatch:*"));
        expected.put("statusList.signerPurpose", List.of("ekuMissing", "kuMissing"));

        assertEquals(expected, IndependentStatusListVerifier.PROBLEM_CODES,
                "IndependentStatusListVerifier.PROBLEM_CODES must be the M-11b table");
        assertEquals(List.copyOf(expected.keySet()), IndependentStatusListVerifier.CHECKS,
                "CHECKS lists the status-list checks in the same report order as PROBLEM_CODES");
        assertEquals(IndependentStatusListVerifier.CHECKS.get(0), "statusList.mso",
                "the MSO's own reference is checked before the token it points at");
        assertEquals(IndependentStatusListVerifier.CHECKS.subList(1, IndependentStatusListVerifier.CHECKS.size()),
                IndependentStatusListVerifier.TOKEN_CHECKS, "verify() runs TOKEN_CHECKS, mso() runs statusList.mso");
        assertTrue(IndependentStatusListVerifier.CHECKS.stream().noneMatch(IndependentMdocVerifier.CHECKS::contains),
                "the two registries name disjoint checks, so a .gaps line always has exactly one owner");
        assertTrue(IndependentStatusListVerifier.isProblemCode("statusList.list", "statusMismatch:1"));
        assertTrue(IndependentStatusListVerifier.isProblemCode("statusList.signature", "invalid:multipaz"));
        assertTrue(!IndependentStatusListVerifier.isProblemCode("statusList.list", "statusMismatch:"));
        assertTrue(!IndependentStatusListVerifier.isProblemCode("statusList.signature", "invalid:other"));
    }

    @Test
    void thePythonVerifierCarriesTheSameProblemCodes() throws Exception {
        String source = Files.readString(VERIFY_MDOC);
        Matcher block = BLOCK.matcher(source);
        assertTrue(block.find(), VERIFY_MDOC + " has no BEGIN/END PROBLEM CODES block");
        Map<String, Object> parsed = JSONObjectUtils.parse(block.group(1));
        Map<String, List<String>> python = new LinkedHashMap<>();
        Matcher key = KEY.matcher(block.group(1));
        while (key.find()) {
            List<String> codes = new ArrayList<>();
            ((List<?>) parsed.get(key.group(1))).forEach(code -> codes.add((String) code));
            python.put(key.group(1), codes);
        }
        assertEquals(IndependentMdocVerifier.PROBLEM_CODES, python, "verify_mdoc.py PROBLEM_CODES");
        assertEquals(List.copyOf(IndependentMdocVerifier.PROBLEM_CODES.keySet()), List.copyOf(python.keySet()),
                "verify_mdoc.py lists the checks in the Java report order");
    }
}
