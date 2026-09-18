package io.mosip.certify.oid4vci.d13;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class D13BodyBufferFilterTest {

    final D13BodyBufferFilter filter = new D13BodyBufferFilter(new ObjectMapper());

    @Test
    void draft13BodiesAreRecognised() {
        assertTrue(filter.isDraft13("{\"format\":\"ldp_vc\",\"proof\":{}}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(filter.isDraft13("{\"credential_configuration_id\":\"x\",\"proofs\":{}}".getBytes(StandardCharsets.UTF_8)));
        assertFalse(filter.isDraft13("{\"format\":\"ldp_vc\",\"credential_configuration_id\":\"x\"}".getBytes(StandardCharsets.UTF_8)), "a 1.0 body naming a format stays with the 1.0 handler");
        assertFalse(filter.isDraft13("not json".getBytes(StandardCharsets.UTF_8)));
        assertFalse(filter.isDraft13("[1]".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void onlyCredentialPostsAreBufferedAndTheBodyIsServedAgain() throws Exception {
        MockHttpServletRequest get = new MockHttpServletRequest("GET", "/v1/certify/issuance/credential");
        assertTrue(filter.shouldNotFilter(get));
        MockHttpServletRequest nonce = new MockHttpServletRequest("POST", "/v1/certify/nonce");
        assertTrue(filter.shouldNotFilter(nonce));
        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/v1/certify/issuance/credential");
        assertFalse(filter.shouldNotFilter(post));

        post.setContent("{\"format\":\"mso_mdoc\"}".getBytes(StandardCharsets.UTF_8));
        String[] seen = new String[2];
        FilterChain chain = (request, response) -> {
            seen[0] = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            seen[1] = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8); // twice: the body is re-served
        };
        filter.doFilter(post, new MockHttpServletResponse(), chain);
        assertEquals("{\"format\":\"mso_mdoc\"}", seen[0]);
        assertEquals(seen[0], seen[1]);
        assertEquals(Boolean.TRUE, post.getAttribute(D13BodyBufferFilter.ATTRIBUTE_DRAFT13_BODY));

        MockHttpServletRequest v1 = new MockHttpServletRequest("POST", "/issuance/credential");
        v1.setContent("{\"credential_configuration_id\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        filter.doFilter(v1, new MockHttpServletResponse(), (request, response) -> {});
        assertEquals(Boolean.FALSE, v1.getAttribute(D13BodyBufferFilter.ATTRIBUTE_DRAFT13_BODY));
        assertNull(get.getAttribute(D13BodyBufferFilter.ATTRIBUTE_DRAFT13_BODY));
    }
}
