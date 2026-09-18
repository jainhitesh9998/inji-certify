package io.mosip.certify.oid4vci.d13;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.servlet.mvc.condition.RequestCondition;

/**
 * Matches when {@link D13BodyBufferFilter} found a draft-13 body. A handler carrying this condition sorts before the
 * unconditioned handler on the same path (Spring MVC ranks a present custom condition above an absent one), and drops
 * out entirely for OpenID4VCI 1.0 bodies, so the compatibility controller keeps serving those untouched.
 */
final class D13BodyCondition implements RequestCondition<D13BodyCondition> {

    static final D13BodyCondition INSTANCE = new D13BodyCondition();

    private D13BodyCondition() {}

    @Override
    public D13BodyCondition combine(D13BodyCondition other) {
        return other;
    }

    @Override
    public D13BodyCondition getMatchingCondition(HttpServletRequest request) {
        return Boolean.TRUE.equals(request.getAttribute(D13BodyBufferFilter.ATTRIBUTE_DRAFT13_BODY)) ? this : null;
    }

    @Override
    public int compareTo(D13BodyCondition other, HttpServletRequest request) {
        return 0;
    }
}
