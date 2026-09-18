package io.mosip.certify.oid4vci.d13;

import org.springframework.web.servlet.mvc.condition.RequestCondition;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.reflect.Method;

/** The application's request mapping with {@link D13BodyCondition} attached to every {@link D13Body} handler. */
public class D13RequestMappingHandlerMapping extends RequestMappingHandlerMapping {

    @Override
    protected RequestCondition<?> getCustomMethodCondition(Method method) {
        return method.isAnnotationPresent(D13Body.class) ? D13BodyCondition.INSTANCE : null;
    }
}
