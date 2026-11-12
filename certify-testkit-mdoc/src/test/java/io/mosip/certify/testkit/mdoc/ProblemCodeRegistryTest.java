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
