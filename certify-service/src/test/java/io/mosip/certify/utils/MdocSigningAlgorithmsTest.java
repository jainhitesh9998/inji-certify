package io.mosip.certify.utils;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The one COSE map for {@code mso_mdoc} metadata (OpenID4VCI 1.0 A.2.2; M-09, gap G20). */
class MdocSigningAlgorithmsTest {

    @Test
    void theIsoAlgorithmsMapToTheirCoseIdentifiers() {
        assertEquals(-7, MdocSigningAlgorithms.coseId("ES256"));
        assertEquals(-35, MdocSigningAlgorithms.coseId("ES384"));
        assertEquals(-36, MdocSigningAlgorithms.coseId("ES512"));
        assertEquals(-8, MdocSigningAlgorithms.coseId("EdDSA"));
    }

    @Test
    void legacyRowsKeepTheIdentifiersTheyPublishedBefore() {
        // existing mDoc rows that list these must publish the same integers as on design/extensibility (CLAUDE.md rule 1)
        assertEquals(-47, MdocSigningAlgorithms.coseId("ES256K"));
        assertEquals(-257, MdocSigningAlgorithms.coseId("RS256"));
    }

    @Test
    void anUnknownAlgorithmIsOmittedWithAWarningInsteadOfFailingTheDocument() {
        assertNull(MdocSigningAlgorithms.coseId("HS256"));
        assertNull(MdocSigningAlgorithms.coseId(null));
        assertEquals(List.of(-7, -8), MdocSigningAlgorithms.coseIds(List.of("ES256", "HS256", "EdDSA")),
                "the known ones survive, in order; the unknown one is dropped");
        assertNull(MdocSigningAlgorithms.coseIds(List.of("HS256")), "nothing known leaves the field out entirely");
    }
}
